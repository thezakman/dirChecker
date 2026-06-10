"""Static signatures and heuristics used to detect directory listings.

Keeping these tables in one place makes the detection logic easy to audit
and extend without touching the request/scan machinery.
"""

from __future__ import annotations

# File extensions that almost never represent a browsable directory.
# Direct requests to these are skipped unless verbose mode is on.
BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mp3", ".wav", ".ogg",
    ".zip", ".rar", ".tar", ".gz", ".bz2", ".7z", ".iso",
    ".exe", ".dmg", ".pkg", ".deb", ".rpm",
})

# Substrings that, when present in a response body, hint at a directory
# listing. Matched case-insensitively and combined with a scoring heuristic.
LISTING_PATTERNS: tuple[str, ...] = (
    # Apache
    "<title>index of", "index of /", "parent directory", "directory listing for",
    "[to parent directory]", "<h1>index of /", "directory: /",
    'alt="[dir]"', "last modified</a>",
    # Nginx
    "<h1>index of", "<title>directory listing for", "<h2>directory listing of",
    # IIS
    "directory listing denied", "the directory browsing", "systemadmin</title>",
    # Cloud storage (AWS S3, GCS, Azure)
    "<listbucketresult", "bucket-listing", "object listing", "storageexplorer",
    '<table class="listing', '<td class="name">', "<prefix>", "<contents>",
    "<enumerationresults", "blobprefix", "<blobs>",
    # Generic auto-index artefacts
    "folder.gif", "file.gif", "back.gif", "[ico]", "[   ]", "[txt]",
    "?c=n;o=d", "?c=m;o=a", "?c=s;o=a", "?c=d;o=a",
    # Misc server-generated indexes
    "autoindex", "fancy indexing", "server-generated page",
)

# Strong, unambiguous indicators that short-circuit the scoring heuristic.
OBVIOUS_PATTERNS: tuple[str, ...] = (
    "index of /", "directory listing", "parent directory",
    "[to parent directory]", 'alt="[dir]"',
)

# Content-Type prefixes we never want to analyse as HTML listings.
SKIP_CONTENT_TYPES: tuple[str, ...] = (
    "image/", "video/", "audio/", "application/pdf",
    "application/zip", "application/octet-stream",
    "application/x-executable", "application/x-msdownload",
)

# Substrings found in network errors that indicate a connectivity failure
# rather than an application-level response.
CONNECTION_ERRORS: tuple[str, ...] = (
    "Connection aborted", "Connection reset by peer",
    "Remote end closed connection", "Connection refused",
    "Connection timed out", "Name or service not known",
    "No route to host", "Network is unreachable",
    "SSL: CERTIFICATE_VERIFY_FAILED", "Max retries exceeded",
)

# Human-friendly rewrites for noisy urllib3/requests exception text.
ERROR_SIMPLIFICATIONS: dict[str, str] = {
    "HTTPSConnectionPool": "HTTPS connection failed",
    "HTTPConnectionPool": "HTTP connection failed",
    "NewConnectionError": "Cannot establish connection",
    "ConnectTimeoutError": "Connection timeout",
    "ReadTimeoutError": "Read timeout",
    "SSLError": "SSL/TLS error",
}
