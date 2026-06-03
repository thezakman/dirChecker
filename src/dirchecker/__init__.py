"""dirChecker — detect directory-listing vulnerabilities.

Public API::

    from dirchecker import DirectoryChecker, CheckerConfig
    from dirchecker.detector import is_directory_listing

    with DirectoryChecker(CheckerConfig(timeout=10)) as checker:
        results = checker.scan(["https://example.com/files/"])
"""

from __future__ import annotations

from .__about__ import __author__, __license__, __url__, __version__
from .checker import DirectoryChecker
from .detector import is_directory_listing
from .models import CheckerConfig, CheckResult, ScanStats

__all__ = [
    "DirectoryChecker",
    "CheckerConfig",
    "CheckResult",
    "ScanStats",
    "is_directory_listing",
    "__version__",
    "__author__",
    "__license__",
    "__url__",
]
