"""Concurrent HTTP probing engine.

:class:`DirectoryChecker` owns the HTTP session, request strategy and thread
pool. It returns plain :class:`~dirchecker.models.CheckResult` objects and
never writes to the console — presentation lives in
:mod:`dirchecker.reporter`.
"""

from __future__ import annotations

import logging
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urljoin, urlparse

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

        if self.config.proxy:
            session.proxies = {"http": self.config.proxy, "https": self.config.proxy}

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

        if self.config.delay > 0:
            time.sleep(self.config.delay)

        try:
            # A cheap HEAD lets us bail out of large/binary payloads early.
            if self.config.use_head:
                try:
                    head = self.session.head(
                        url,
                        verify=self.config.verify_ssl,
                        timeout=timeout,
                        allow_redirects=self.config.follow_redirects,
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
        """Streamed GET that caps the downloaded body and follows redirects.

        Redirects are resolved manually so we can enforce ``same_host_redirects``
        (never leaving the original host) and cap the hop count ourselves.
        """
        origin_host = urlparse(url).netloc
        history: list[requests.Response] = []
        current = url
        response = None

        for _ in range(self.config.max_redirects + 1):
            response = self.session.get(
                current,
                verify=self.config.verify_ssl,
                timeout=timeout,
                stream=True,
                allow_redirects=False,
            )

            if not (self.config.follow_redirects and response.is_redirect):
                break
            location = response.headers.get("Location")
            if not location:
                break

            next_url = urljoin(current, location)
            if (
                self.config.same_host_redirects
                and urlparse(next_url).netloc != origin_host
            ):
                logger.debug("Not following off-host redirect %s -> %s", current, next_url)
                break  # Report the redirect itself rather than leave scope.

            history.append(response)
            response.close()
            current = next_url

        self._read_body(response)
        if history:
            response.history = history
        return response

    def _read_body(self, response: requests.Response) -> None:
        """Stream *response* into ``_content``, capping the download size."""
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
            logger.debug("Error reading content from %s: %s", response.url, exc)
            response._content = b""

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
        bypass: bool = False,
        on_result: ProgressCallback | None = None,
    ) -> list[CheckResult]:
        """Expand and concurrently probe *seed_urls*.

        ``on_result`` is invoked from the worker thread as each URL finishes,
        enabling live progress display without coupling to a UI library.
        """
        self.stats.reset()
        targets = urls.expand_urls(seed_urls, double_slash, bypass)
        self.stats.total_urls = len(targets)

        catch_all_hosts = self._catch_all_hosts(targets)

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
                self._apply_baseline(result, catch_all_hosts)
                results.append(result)
                if on_result is not None:
                    on_result(result)

        return results

    # -- Baseline / catch-all detection -----------------------------------

    def _catch_all_hosts(self, targets: list[str]) -> set[str]:
        """Return hosts that flag a random, non-existent path as a listing.

        Such a host answers ``200`` (and looks browsable) for *anything*, so
        its per-URL "listing" verdicts are almost certainly false positives.
        """
        if not self.config.baseline_check:
            return set()

        hosts: dict[str, str] = {}
        for target in targets:
            parsed = urlparse(target)
            hosts.setdefault(parsed.netloc, f"{parsed.scheme}://{parsed.netloc}")

        catch_all: set[str] = set()
        for netloc, base in hosts.items():
            probe = f"{base}/dirchecker-baseline-{secrets.token_hex(8)}/"
            try:
                response = self._get(probe, self._effective_timeout(probe))
                if response.status_code == 200 and detector.is_directory_listing(response):
                    catch_all.add(netloc)
                    logger.debug("Host %s looks like a catch-all; suppressing listings", netloc)
            except requests.RequestException as exc:
                logger.debug("Baseline probe failed for %s: %s", netloc, exc)
        return catch_all

    def _apply_baseline(self, result: CheckResult, catch_all_hosts: set[str]) -> None:
        if not result.is_listing:
            return
        if urlparse(result.url).netloc in catch_all_hosts:
            result.is_listing = False
            result.note = "suppressed: host flags a random baseline path too (likely catch-all)"
            self.stats.vulnerable_urls -= 1
