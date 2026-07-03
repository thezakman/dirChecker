"""Command-line interface for dirChecker."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

import requests
from colorama import Fore, Style
from colorama import init as colorama_init
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from . import output
from .__about__ import __version__
from .checker import DirectoryChecker
from .models import CheckerConfig
from .reporter import Reporter

logger = logging.getLogger("dirchecker")

# Exit codes: 0 clean, 2 vulnerable listing(s) found, 1 unexpected error.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_VULNERABLE = 2


def parse_headers(header_string: str | None) -> dict[str, str]:
    """Parse a ``Header1:Value1,Header2:Value2`` string into a dict."""
    headers: dict[str, str] = {}
    if not header_string:
        return headers
    for pair in header_string.split(","):
        if ":" in pair:
            key, value = pair.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def _read_stdin() -> list[str]:
    return [line.strip() for line in sys.stdin if line.strip()]


def load_urls(args: argparse.Namespace) -> list[str]:
    """Collect seed URLs from positional, flag, list-file, or stdin (``-``)."""
    if "-" in (args.url, args.url_flag, args.list):
        return _read_stdin()
    if args.url:
        return [args.url]
    if args.url_flag:
        return [args.url_flag]
    if args.list:
        try:
            with open(args.list, encoding="utf-8") as handle:
                return [line.strip() for line in handle if line.strip()]
        except OSError as exc:
            print(f"{Fore.RED}[ERROR] Cannot read URL list '{args.list}': {exc}{Style.RESET_ALL}")
            sys.exit(1)
    return []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dirchecker",
        description="Detect directory-listing vulnerabilities on web servers and cloud buckets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"dirChecker {__version__}")

    input_group = parser.add_argument_group("Input Options")
    input_group.add_argument("url", nargs="?", help="URL to check ('-' reads from stdin)")
    input_group.add_argument("-u", "--url-flag", help="URL to check (alternative to positional URL)")
    input_group.add_argument("-l", "--list", help="File containing a list of URLs ('-' reads from stdin)")

    request_group = parser.add_argument_group("Request Options")
    request_group.add_argument("-to", "--timeout", type=int, default=5, help="Request timeout in seconds")
    request_group.add_argument("-vs", "--verify-ssl", action="store_true", help="Verify SSL certificates")
    request_group.add_argument("-ua", "--user-agent", help=f"Custom User-Agent (default: dirChecker/{__version__})")
    request_group.add_argument("-H", "--headers", help="Custom headers ('Header1:Value1,Header2:Value2')")
    request_group.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    request_group.add_argument("-ds", "--double-slash", action="store_true", help="Test URLs with double slashes for bypass")
    request_group.add_argument("-bp", "--bypass", action="store_true", help="Test path-normalisation autoindex bypass variants")
    request_group.add_argument("-x", "--proxy", help="Route traffic through a proxy (e.g. http://127.0.0.1:8080)")
    request_group.add_argument("-d", "--delay", type=float, default=0.0, help="Seconds to sleep before each request (throttle)")
    request_group.add_argument("--no-head", action="store_true", help="Skip the pre-flight HEAD request")
    request_group.add_argument("--no-redirects", action="store_true", help="Do not follow HTTP redirects")
    request_group.add_argument("--same-host", action="store_true", help="Do not follow redirects that leave the original host")
    request_group.add_argument("--no-baseline", action="store_true", help="Disable catch-all/soft-200 baseline probing")

    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-f", "--format", choices=["text", "json", "jsonl", "csv"], default="text", help="Output format")
    output_group.add_argument("-o", "--output", help="Write structured output to a file instead of stdout")
    output_group.add_argument("-slt", "--silent", action="store_true", help="Output only vulnerable URLs")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Show detailed information for all URLs")
    output_group.add_argument("-p", "--preview", action="store_true", help="Show response body preview")
    output_group.add_argument("-s", "--status", action="store_true", help="Show summary statistics")
    output_group.add_argument("--debug", action="store_true", help="Enable debug logging")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``dirchecker`` console script."""
    colorama_init(autoreset=True)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if not any([args.url, args.url_flag, args.list]):
        parser.error("No URL provided. Use a positional argument, -u/--url or -l/--list.")

    if args.output and args.format == "text":
        parser.error("-o/--output requires a structured format (-f json|jsonl|csv).")

    seed_urls = load_urls(args)
    if not seed_urls:
        parser.error("No URLs to scan.")

    config = CheckerConfig(
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        user_agent=args.user_agent,
        custom_headers=parse_headers(args.headers),
        max_threads=args.threads,
        verbose=args.verbose,
        proxy=args.proxy,
        delay=args.delay,
        use_head=not args.no_head,
        follow_redirects=not args.no_redirects,
        same_host_redirects=args.same_host,
        baseline_check=not args.no_baseline,
    )

    try:
        results = _scan(args, config, seed_urls)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"\n{Fore.RED}[ERROR] An unexpected error occurred: {exc}{Style.RESET_ALL}")
        if logger.isEnabledFor(logging.DEBUG):
            import traceback
            traceback.print_exc()
        return EXIT_ERROR

    return EXIT_VULNERABLE if any(r.is_listing for r in results) else EXIT_OK


def _scan(args: argparse.Namespace, config: CheckerConfig, seed_urls: list[str]) -> list:
    """Run the scan and emit output in the requested format."""
    if args.format == "text":
        reporter = Reporter(
            verbose=args.verbose,
            preview=args.preview,
            silent=args.silent,
            show_status=args.status,
        )
        reporter.banner()
        with DirectoryChecker(config) as checker:
            return reporter.run(
                checker, seed_urls, double_slash=args.double_slash, bypass=args.bypass
            )

    # Structured output: no banner/progress on stdout so the payload stays clean.
    with DirectoryChecker(config) as checker:
        results = checker.scan(
            seed_urls, double_slash=args.double_slash, bypass=args.bypass
        )
    payload = output.serialize(results, args.format, only_listings=args.silent)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
    else:
        print(payload)
    return results


if __name__ == "__main__":
    sys.exit(main())
