"""Machine-readable serialisation of scan results (JSON / JSONL / CSV).

Kept separate from the human-facing :mod:`dirchecker.reporter` so structured
output stays stable and easy to consume from pipelines and other tools.
"""

from __future__ import annotations

import csv
import io
import json

from .models import CheckResult

# Column order for CSV and the key order callers can rely on.
FIELDS: tuple[str, ...] = (
    "url",
    "status_code",
    "is_listing",
    "content_type",
    "content_length",
    "server",
    "depth",
    "elapsed_time",
    "note",
    "error",
    "skipped",
)


def result_to_dict(result: CheckResult) -> dict:
    """Flatten a :class:`CheckResult` into JSON/CSV-friendly primitives."""
    response = result.response
    return {
        "url": result.url,
        "status_code": result.status_code,
        "is_listing": result.is_listing,
        "content_type": response.headers.get("Content-Type") if response is not None else None,
        "content_length": response.headers.get("Content-Length") if response is not None else None,
        "server": response.headers.get("Server") if response is not None else None,
        "depth": result.depth,
        "elapsed_time": round(result.elapsed_time, 3),
        "note": result.note,
        "error": result.error,
        "skipped": result.skipped,
    }


def _selected(results: list[CheckResult], only_listings: bool) -> list[CheckResult]:
    return [r for r in results if r.is_listing] if only_listings else list(results)


def to_json(results: list[CheckResult], only_listings: bool = False) -> str:
    rows = [result_to_dict(r) for r in _selected(results, only_listings)]
    return json.dumps(rows, indent=2)


def to_jsonl(results: list[CheckResult], only_listings: bool = False) -> str:
    return "\n".join(json.dumps(result_to_dict(r)) for r in _selected(results, only_listings))


def to_csv(results: list[CheckResult], only_listings: bool = False) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELDS)
    writer.writeheader()
    for result in _selected(results, only_listings):
        writer.writerow(result_to_dict(result))
    return buffer.getvalue().rstrip("\r\n")


def serialize(results: list[CheckResult], fmt: str, only_listings: bool = False) -> str:
    """Serialise *results* to ``fmt`` (``json`` | ``jsonl`` | ``csv``)."""
    serialisers = {"json": to_json, "jsonl": to_jsonl, "csv": to_csv}
    try:
        return serialisers[fmt](results, only_listings)
    except KeyError:
        raise ValueError(f"Unknown output format: {fmt!r}") from None
