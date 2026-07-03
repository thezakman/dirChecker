"""URL normalisation and variant-generation helpers.

These functions are pure (no I/O) so they can be unit-tested in isolation
and reused by both the scanner and external callers.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .patterns import BINARY_EXTENSIONS


def normalize_url(url: str) -> str:
    """Ensure a URL carries an explicit scheme, defaulting to http://."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url


def url_depth(url: str) -> int:
    """Return the number of path segments in a URL."""
    path = urlparse(url).path.strip("/")
    return len(path.split("/")) if path else 0


def is_binary_file(url: str) -> bool:
    """True when the URL path ends with a known binary file extension."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in BINARY_EXTENSIONS)


def has_file_extension(url: str) -> bool:
    """True when the last path segment looks like ``name.ext``."""
    path_parts = urlparse(url).path.strip("/").split("/")
    last = path_parts[-1] if path_parts else ""
    return "." in last and not last.endswith(".")


def _directory_variants(url: str, double_slash: bool) -> list[str]:
    """Trailing-slash and bypass variants for directory-like URLs."""
    variants: list[str] = []
    if has_file_extension(url):
        return variants

    if not url.endswith("/"):
        variants.append(f"{url}/")

    if double_slash:
        variants.append(f"{url}/" if url.endswith("/") else f"{url}//")

    return variants


def _bypass_variants(url: str) -> list[str]:
    """Path-normalisation tricks that sometimes re-expose a disabled autoindex.

    These target servers/proxies that normalise the request path differently
    from the auth/routing layer (Apache, Nginx, Tomcat, various WAFs). Only
    generated for directory-like URLs and only when the user opts in, since
    they multiply the request count.
    """
    if has_file_extension(url):
        return []
    stem = url.rstrip("/")
    return [
        f"{stem}/.",       # trailing dot segment
        f"{stem}/%2e/",    # URL-encoded dot
        f"{stem};/",       # path parameter separator
        f"{stem}/..;/",    # Tomcat-style path traversal artefact
    ]


def _parent_directories(url: str, double_slash: bool) -> list[str]:
    """Every ancestor directory of ``url`` up to (and including) the root."""
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]

    # Drop a trailing filename so we only walk directories.
    if path_parts and "." in path_parts[-1] and not path_parts[-1].startswith("."):
        path_parts.pop()

    variants: list[str] = []
    for i in range(len(path_parts)):
        parent_url = f"{base_url}/{'/'.join(path_parts[: i + 1])}/"
        variants.append(parent_url)
        if double_slash:
            variants.append(f"{parent_url}/")

    root_url = f"{base_url}/"
    variants.append(root_url)
    if double_slash:
        variants.append(f"{root_url}/")

    return variants


def expand_urls(
    urls: list[str], double_slash: bool = False, bypass: bool = False
) -> list[str]:
    """Expand seed URLs into the full ordered set of paths to probe.

    For each input we add the URL itself, directory variants, and the whole
    chain of parent directories. When ``bypass`` is set we also add path
    normalisation tricks for each directory. Results are de-duplicated and
    ordered with the deepest paths first for a more intuitive scan progression.
    """
    seen: set[str] = set()
    ordered: list[str] = []

    def add(candidate: str) -> None:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)

    for raw in urls:
        normalized = normalize_url(raw)
        add(normalized)
        for variant in _directory_variants(normalized, double_slash):
            add(variant)
        for variant in _parent_directories(normalized, double_slash):
            add(variant)
        if bypass:
            for variant in _bypass_variants(normalized):
                add(variant)
            for parent in _parent_directories(normalized, False):
                for variant in _bypass_variants(parent):
                    add(variant)

    return sorted(ordered, key=lambda u: (-url_depth(u), u))


def has_double_slash(url: str) -> bool:
    """True when the path component contains a ``//`` sequence."""
    return "//" in url.replace("://", "", 1)
