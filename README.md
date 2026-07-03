# dirChecker

```
     _ _       ___ _               _
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_|  v3
              - why check manually?
```

![version](https://img.shields.io/badge/version-3.1.0-brightgreen)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Recursive scanner that identifies **directory-listing vulnerabilities** on web
servers and cloud storage buckets. Give it any URL and it walks every parent
directory, fingerprints the response, and reports which paths leak a browsable
index.

## What's new in v3.1

- **Structured output**: `--format json|jsonl|csv` and `-o/--output` for pipelines
- **Meaningful exit codes**: `2` when a listing is found (CI/pipeline friendly)
- **Stdin input**: `cat urls.txt | dirchecker -`
- **Proxy support** (`-x/--proxy`) and **request throttling** (`-d/--delay`)
- **Scope safety**: `--same-host` refuses redirects that leave the target host;
  `--no-redirects` to disable following entirely
- **Catch-all / soft-200 detection**: a per-host baseline probe suppresses
  listings on servers that answer `200` for any path (`--no-baseline` to opt out)
- **Broader bucket coverage**: signature-based detection now catches DigitalOcean
  Spaces, Backblaze B2, Alibaba OSS and self-hosted MinIO/Ceph, not just AWS/GCS/Azure
- **More bypass variants** (`-bp/--bypass`): `/.`, `/%2e/`, `;/`, `/..;/`
- **`--no-head`** to skip the pre-flight HEAD request

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

Both `url` and `-l/--list` accept `-` to read newline-separated targets from stdin.

### Request options
| Flag | Description |
|------|-------------|
| `-to, --timeout` | Request timeout in seconds (default: 5) |
| `-vs, --verify-ssl` | Verify SSL certificates |
| `-ua, --user-agent` | Custom User-Agent |
| `-H, --headers` | Custom headers (`Header1:Value1,Header2:Value2`) |
| `-t, --threads` | Concurrent threads (default: 10, max: 50) |
| `-ds, --double-slash` | Test `//` bypass variants |
| `-bp, --bypass` | Test path-normalisation autoindex bypass variants (`/.`, `/%2e/`, `;/`, `/..;/`) |
| `-x, --proxy` | Route traffic through a proxy (e.g. `http://127.0.0.1:8080`) |
| `-d, --delay` | Seconds to sleep before each request (throttle) |
| `--no-head` | Skip the pre-flight HEAD request |
| `--no-redirects` | Do not follow HTTP redirects |
| `--same-host` | Follow redirects only while they stay on the original host |
| `--no-baseline` | Disable catch-all / soft-200 baseline probing |

### Output options
| Flag | Description |
|------|-------------|
| `-f, --format` | Output format: `text` (default), `json`, `jsonl`, `csv` |
| `-o, --output` | Write structured output to a file (requires `-f json\|jsonl\|csv`) |
| `-slt, --silent` | Only vulnerable URLs (also filters structured output) |
| `-v, --verbose` | Detailed output for every URL |
| `-p, --preview` | Show a response body preview |
| `-s, --status` | Show summary statistics |
| `--debug` | Enable debug logging |

### Exit codes
| Code | Meaning |
|------|---------|
| `0` | Scan completed, no directory listing found |
| `2` | At least one directory listing was found |
| `1` | Unexpected error |
| `130` | Interrupted (Ctrl-C) |

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

# Read targets from stdin, emit JSON Lines, only listings
cat urls.txt | dirchecker - -f jsonl -slt

# Machine-readable report to a file
dirchecker -l urls.txt -f json -o results.json

# Autoindex bypass attempts, throttled, through Burp
dirchecker https://example.com/admin/ -bp -d 0.3 -x http://127.0.0.1:8080

# Stay in scope: never follow a redirect off the original host
dirchecker https://example.com/ --same-host

# Gate a pipeline on the exit code (2 == found)
dirchecker https://example.com/ -slt && echo "clean" || echo "listing found"
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
├── output.py       # json / jsonl / csv serialisation
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
