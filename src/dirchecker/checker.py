"""Concurrent HTTP probing engine.

:class:`DirectoryChecker` owns the HTTP session, request strategy and thread
pool. It returns plain :class:`~dirchecker.models.CheckResult` objects and
never writes to the console — presentation lives in
:mod:`dirchecker.reporter`.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import detector, urls
from .__about__ import __version__
from .models import CheckerConfig, CheckResult, ScanStats
from .patterns import CONNECTION_ERRORS, ERROR_SIMPLIFICATIONS, SKIP_CONTENT_TYPES

logger = logging.getLogger("dirchecker")

# Type alias for the optional per-result progress callback.
ProgressCallback = Callable[[CheckResult], None]

_MAX_HTML_BYTES = 10_000_000  # Skip listings larger than ~10 MB.


class DirectoryChecker:
    """Probe URLs for directory-listing exposure."""

    def __init__(self, config: CheckerConfig | None = None) -> None:
        self.config = config or CheckerConfig()
        self.user_agent = self.config.user_agent or f"dirChecker/{__version__}"
        self.stats = ScanStats()
        self.session = self._build_session()

    # -- Session setup ----------------------------------------------------

    def _build_session(self) -> requests.Session:
        session = requests.Session()

        retry = Retry(
            total=2,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=0.5,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=self.config.max_threads,
            pool_maxsize=self.config.max_threads * 2,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        if self.config.custom_headers:
            session.headers.update(self.config.custom_headers)

        return session

    def close(self) -> None:
        """Release pooled connections."""
        self.session.close()

    def __enter__(self) -> DirectoryChecker:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- Single URL -------------------------------------------------------

    def check_url(self, url: str) -> CheckResult:
        """Probe one URL and return a populated :class:`CheckResult`."""
        result = CheckResult(url=url, depth=urls.url_depth(url))

        # Skip direct requests to binary files (directories are always tested).
        if (
            urls.is_binary_file(url)
            and not self.config.verbose
            and not url.endswith("/")
        ):
            result.skipped = "Binary file extension"
            return result

        timeout = self._effective_timeout(url)

        try:
            # A cheap HEAD lets us bail out of large/binary payloads early.
            try:
                head = self.session.head(
                    url, verify=self.config.verify_ssl, timeout=timeout, allow_redirects=True
                )
                if self._should_skip(head.headers):
                    result.response = head
                    result.skipped_content = True
                    self.stats.successful_requests += 1
                    return result
            except requests.RequestException:
                pass  # Fall through to GET.

            start = time.time()
            response = self._get(url, timeout)
            result.response = response
            result.elapsed_time = time.time() - start
            result.is_listing = detector.is_directory_listing(response)

            if result.is_listing:
                self.stats.vulnerable_urls += 1
            self.stats.successful_requests += 1
            return result

        except requests.RequestException as exc:
            self._record_request_error(result, str(exc), url)
            return result
        except Exception as exc:  # noqa: BLE001 - surface unexpected failures
            self.stats.failed_requests += 1
            result.error = f"Unexpected error: {exc}"
            return result

    def _record_request_error(self, result: CheckResult, message: str, url: str) -> None:
        self.stats.failed_requests += 1
        if any(err in message for err in CONNECTION_ERRORS):
            self.stats.connection_errors += 1
            if urls.has_double_slash(url) and "closed connection" in message:
                result.error = "Server closed connection (double slash vulnerability test)"
            else:
                result.error = f"Connection error: {self._simplify_error(message)}"
        else:
            result.error = f"Request failed: {self._simplify_error(message)}"

    @staticmethod
    def _simplify_error(message: str) -> str:
        for pattern, replacement in ERROR_SIMPLIFICATIONS.items():
            if pattern in message:
                return replacement
        return message[:100] + "..." if len(message) > 100 else message

    def _effective_timeout(self, url: str) -> int:
        if urls.is_binary_file(url):
            return min(self.config.timeout, 3)
        if urls.has_double_slash(url):
            return min(self.config.timeout, self.config.reduced_timeout)
        return self.config.timeout

    def _get(self, url: str, timeout: int) -> requests.Response:
        """Streamed GET that caps how much body we download for analysis."""
        response = self.session.get(
            url,
            verify=self.config.verify_ssl,
            timeout=timeout,
            stream=True,
            allow_redirects=True,
        )

        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= self.config.max_content_size:
                    break
            raw = b"".join(chunks)
            try:
                text = raw.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                text = raw.decode("latin-1", errors="replace")
            response._content = text.encode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            logger.debug("Error reading content from %s: %s", url, exc)
            response._content = b""

        return response

    @staticmethod
    def _should_skip(headers: dict[str, str]) -> bool:
        content_type = headers.get("Content-Type", "").lower()
        content_length = headers.get("Content-Length", "0")
        content_encoding = headers.get("Content-Encoding", "").lower()

        if any(ct in content_type for ct in SKIP_CONTENT_TYPES):
            return True
        if content_length.isdigit() and int(content_length) > _MAX_HTML_BYTES:
            return True
        if content_encoding in ("compress", "x-compress") and "text/html" not in content_type:
            return True
        return False

    # -- Bulk scan --------------------------------------------------------

    def scan(
        self,
        seed_urls: list[str],
        double_slash: bool = False,
        on_result: ProgressCallback | None = None,
    ) -> list[CheckResult]:
        """Expand and concurrently probe *seed_urls*.

        ``on_result`` is invoked from the worker thread as each URL finishes,
        enabling live progress display without coupling to a UI library.
        """
        self.stats.reset()
        targets = urls.expand_urls(seed_urls, double_slash)
        self.stats.total_urls = len(targets)

        results: list[CheckResult] = []
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            future_to_url = {executor.submit(self.check_url, url): url for url in targets}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Error scanning %s: %s", url, exc)
                    result = CheckResult(url=url, depth=urls.url_depth(url), error=str(exc))
                results.append(result)
                if on_result is not None:
                    on_result(result)

        return results
