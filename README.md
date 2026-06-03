# dirChecker

```
     _ _       ___ _               _
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_|  v3
              - why check manually?
```

![version](https://img.shields.io/badge/version-3.0.0-brightgreen)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Recursive scanner that identifies **directory-listing vulnerabilities** on web
servers and cloud storage buckets. Give it any URL and it walks every parent
directory, fingerprints the response, and reports which paths leak a browsable
index.

## What's new in v3

- Rewritten as a **modular, pip-installable package** (`src/` layout)
- Importable **Python library API** in addition to the CLI
- Cleaner detection engine split into pure heuristics, HTTP engine and
  presentation layers
- Test suite (pytest) and linting (ruff)
- `dirchecker` / `dircheck` console commands and `python -m dirchecker`
- Backward-compatible: `python dirChecker.py ...` still works

## Features

- Recursive checking of every parent directory of a target URL
- Detection across HTML (Apache / Nginx / IIS), XML and JSON listings
- Cloud bucket detection for AWS S3, Google Cloud Storage and Azure Blob
- Weighted scoring heuristic to reduce false positives
- Multi-threaded scanning with a streamed, size-capped HTTP client
- Double-slash (`//`) bypass testing
- Silent mode for piping into other tools
- Response preview, security-header inspection and summary statistics
- Usable as a **CLI** *and* as an importable **Python library**

## Installation

```bash
# Directly from GitHub
pip install git+https://github.com/thezakman/dirChecker.git

# From a clone
git clone https://github.com/thezakman/dirChecker.git
cd dirChecker
pip install .

# For development (tests + linter)
pip install -e ".[dev]"
```

This installs two equivalent console commands: `dirchecker` and `dircheck`.

You can also run it without installing:

```bash
python -m dirchecker https://example.com/path/   # if on PYTHONPATH
python dirChecker.py https://example.com/path/    # backward-compatible launcher
```

## CLI usage

```
dirchecker [-h] [--version] [-u URL] [-l LIST] [-to TIMEOUT] [-vs]
           [-ua USER_AGENT] [-H HEADERS] [-t THREADS] [-ds]
           [-slt] [-v] [-p] [-s] [--debug] [url]
```

### Input options
| Flag | Description |
|------|-------------|
| `url` | URL to check (positional) |
| `-u, --url-flag` | URL to check (alternative to positional) |
| `-l, --list` | File containing a list of URLs |

### Request options
| Flag | Description |
|------|-------------|
| `-to, --timeout` | Request timeout in seconds (default: 5) |
| `-vs, --verify-ssl` | Verify SSL certificates |
| `-ua, --user-agent` | Custom User-Agent |
| `-H, --headers` | Custom headers (`Header1:Value1,Header2:Value2`) |
| `-t, --threads` | Concurrent threads (default: 10, max: 50) |
| `-ds, --double-slash` | Test `//` bypass variants |

### Output options
| Flag | Description |
|------|-------------|
| `-slt, --silent` | Print only vulnerable URLs |
| `-v, --verbose` | Detailed output for every URL |
| `-p, --preview` | Show a response body preview |
| `-s, --status` | Show summary statistics |
| `--debug` | Enable debug logging |

## Examples

```bash
# Single URL
dirchecker https://example.com/path/

# List of URLs
dirchecker -l urls.txt

# Double-slash bypass testing
dirchecker https://example.com/path/ -ds

# Silent mode (vulnerable URLs only) — great for pipelines
dirchecker https://example.com/path/ -slt

# Full detail with preview and stats
dirchecker https://example.com/path/ -v -p -s

# Custom headers
dirchecker https://example.com/ -H "Authorization:Bearer token,X-Custom:Value"
```

## Library usage

```python
from dirchecker import DirectoryChecker, CheckerConfig

config = CheckerConfig(timeout=10, max_threads=20)
with DirectoryChecker(config) as checker:
    results = checker.scan(["https://example.com/files/"], double_slash=True)

for r in results:
    if r.is_listing:
        print("VULNERABLE:", r.url)
```

The detector can also be used on its own against any `requests.Response`:

```python
from dirchecker.detector import is_directory_listing
```

## Project layout

```
src/dirchecker/
├── __about__.py    # version & metadata
├── cli.py          # argument parsing + entry point
├── checker.py      # concurrent HTTP probing engine
├── detector.py     # listing-detection heuristics (no I/O)
├── reporter.py     # console presentation layer
├── urls.py         # URL normalisation & variant generation
├── patterns.py     # detection signatures
└── models.py       # typed config / result / stats
tests/              # pytest suite
```

## Development

```bash
pip install -e ".[dev]"
pytest          # run the test suite
ruff check src tests
```

## License

MIT — see [LICENSE](LICENSE).
