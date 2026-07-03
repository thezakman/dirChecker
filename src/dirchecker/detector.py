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
    """Detect object-storage bucket listings by their XML signature.

    ``<ListBucketResult>`` and ``<EnumerationResults>`` are unambiguous root
    elements, so we key off the payload rather than the host. This covers AWS
    S3, Google Cloud Storage, DigitalOcean Spaces, Backblaze B2, Alibaba OSS,
    self-hosted MinIO/Ceph and Azure Blob without an allow-list of domains.
    """
    if response.status_code != 200:
        return False

    # S3-compatible object storage (AWS and every S3 API clone).
    if "<listbucketresult" in body:
        has_contents = "<contents>" in body
        has_prefixes = "<commonprefixes>" in body
        has_keys = "<key>" in body and len(response.text) > 500
        return has_contents or has_prefixes or has_keys

    # Azure Blob storage.
    if "<enumerationresults" in body:
        return "<blobs>" in body or "<blobprefix>" in body

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
    pattern_hits = sum(1 for pattern in LISTING_PATTERNS if pattern in body)
    score = pattern_hits

    # Structural cues (lots of links, a file table) are normal furniture on
    # ordinary web pages, so they only reinforce an existing listing signal —
    # on their own they must never push a plain page over the threshold.
    if pattern_hits:
        link_count = body.count("<a href=")
        if link_count > 10:
            score += 2
        elif link_count > 5:
            score += 1

        if "<table" in body and "<td" in body:
            score += 1

    # Cloud object rows (<Key>…<Size>) are a strong standalone signal.
    if "<key>" in body and "<size>" in body:
        score += 2

    return score
