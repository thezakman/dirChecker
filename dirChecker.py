#!/usr/bin/env python3
"""Backward-compatible launcher for dirChecker.

The project is now a proper Python package under ``src/dirchecker``. The
recommended way to use it is::

    pip install .
    dirchecker https://example.com/path/

This shim lets you keep running ``python dirChecker.py ...`` from a clone
without installing first.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from dirchecker.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
