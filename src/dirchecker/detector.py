"""Heuristics that decide whether an HTTP response is a directory listing.

The detector is intentionally free of any network code so it can be tested
against captured responses and reasoned about independently.
"""

from __future__ import annotations

import requests

from .patterns import (
    LISTING_PATTERNS,
    OBVIOUS_PATTERNS,
    SKIP_CONTENT_TYPES,
)

# A response needs at least this score from the weighted heuristic to be
# flagged when no obvious/cloud/JSON signal is present.
SCORE_THRESHOLD = 2


def is_directory_listing(response: requests.Response) -> bool:
    """Return True when *response* appears to expose a directory listing."""
    if response is None or not response.text:
        return False

    content_type = response.headers.get("Content-Type", "").lower()
    if any(ct in content_type for ct in SKIP_CONTENT_TYPES):
        return False

    body = response.text.lower()

    if _has_obvious_pattern(body):
        return True
    if _is_cloud_storage_listing(response, body):
        return True
    if _is_json_listing(response):
        return True

    return _score(body) >= SCORE_THRESHOLD


def _has_obvious_pattern(body: str) -> bool:
    return any(pattern in body for pattern in OBVIOUS_PATTERNS)


def _is_cloud_storage_listing(response: requests.Response, body: str) -> bool:
    """Detect AWS S3 / GCS / Azure Blob bucket listings."""
    url = response.url
    status = response.status_code

    if "amazonaws.com" in url and status == 200 and "<listbucketresult" in body:
        return "<contents>" in body or "<commonprefixes>" in body

    if "storage.googleapis.com" in url and status == 200:
        content_type = response.headers.get("Content-Type", "").lower()
        if ("xml" in content_type) and "<listbucketresult" in body:
            has_contents = "<contents>" in body
            has_prefixes = "<commonprefixes>" in body
            has_keys = "<key>" in body and len(response.text) > 500
            return has_contents or has_prefixes or has_keys

    if "blob.core.windows.net" in url and status == 200 and "<enumerationresults" in body:
        return "<blobs>" in body or "<blobprefix>" in body

    # A 403 that is not an explicit access-denied page may still leak a listing.
    if status == 403:
        denied = ("access denied", "invalidaccesskeyid", "forbidden")
        return not any(token in body for token in denied)

    return False


def _is_json_listing(response: requests.Response) -> bool:
    """Detect JSON APIs that enumerate objects/files."""
    if "application/json" not in response.headers.get("Content-Type", ""):
        return False
    try:
        data = response.json()
    except (ValueError, TypeError):
        return False
    if isinstance(data, dict):
        return any(key in data for key in ("objects", "contents", "files", "entries"))
    return False


def _score(body: str) -> int:
    """Weighted heuristic score for ambiguous responses."""
    score = sum(1 for pattern in LISTING_PATTERNS if pattern in body)

    link_count = body.count("<a href=")
    if link_count > 10:
        score += 2
    elif link_count > 5:
        score += 1

    if "<table" in body and "<td" in body:
        score += 1

    if "<key>" in body and "<size>" in body:
        score += 2

    return score
