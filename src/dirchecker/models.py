"""Typed data structures shared across the package."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

import requests


@dataclass
class CheckerConfig:
    """Tunable settings for a :class:`~dirchecker.checker.DirectoryChecker`."""

    # Hard ceiling on worker threads for stability.
    THREAD_LIMIT: ClassVar[int] = 50

    timeout: int = 5
    reduced_timeout: int = 2
    verify_ssl: bool = False
    user_agent: str | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)
    max_threads: int = 10
    max_content_size: int = 100_000
    verbose: bool = False

    # Route all traffic through an HTTP/HTTPS proxy (e.g. "http://127.0.0.1:8080").
    proxy: str | None = None
    # Seconds to sleep before each request (per worker) to throttle scanning.
    delay: float = 0.0
    # Send a cheap HEAD before GET to bail out of large/binary payloads early.
    use_head: bool = True
    # Follow HTTP redirects; when off, a redirect is reported as-is.
    follow_redirects: bool = True
    # When following redirects, refuse to leave the original host (scope safety).
    same_host_redirects: bool = False
    # Upper bound on redirect hops we will follow for a single URL.
    max_redirects: int = 10
    # Probe a random path per host first; suppress listings on catch-all servers.
    baseline_check: bool = True

    def __post_init__(self) -> None:
        self.max_threads = max(1, min(self.max_threads, self.THREAD_LIMIT))


@dataclass
class CheckResult:
    """Outcome of probing a single URL."""

    url: str
    depth: int
    is_listing: bool = False
    error: str | None = None
    skipped: str | None = None
    skipped_content: bool = False
    elapsed_time: float = 0.0
    response: requests.Response | None = None
    # Free-form annotation, e.g. why a listing was suppressed as a false positive.
    note: str | None = None

    @property
    def status_code(self) -> int | None:
        return self.response.status_code if self.response is not None else None

    @property
    def content_type(self) -> str:
        if self.response is None:
            return "Unknown"
        return self.response.headers.get("Content-Type", "Unknown")


@dataclass
class ScanStats:
    """Aggregate counters for a scan run."""

    total_urls: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    connection_errors: int = 0
    vulnerable_urls: int = 0

    def reset(self) -> None:
        self.total_urls = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.connection_errors = 0
        self.vulnerable_urls = 0
