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

from .__about__ import __version__
from .checker import DirectoryChecker
from .models import CheckerConfig
from .reporter import Reporter

logger = logging.getLogger("dirchecker")


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


def load_urls(args: argparse.Namespace) -> list[str]:
    """Collect seed URLs from positional, flag, or list-file arguments."""
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
    input_group.add_argument("url", nargs="?", help="URL to check")
    input_group.add_argument("-u", "--url-flag", help="URL to check (alternative to positional URL)")
    input_group.add_argument("-l", "--list", help="File containing a list of URLs to check")

    request_group = parser.add_argument_group("Request Options")
    request_group.add_argument("-to", "--timeout", type=int, default=5, help="Request timeout in seconds")
    request_group.add_argument("-vs", "--verify-ssl", action="store_true", help="Verify SSL certificates")
    request_group.add_argument("-ua", "--user-agent", help=f"Custom User-Agent (default: dirChecker/{__version__})")
    request_group.add_argument("-H", "--headers", help="Custom headers ('Header1:Value1,Header2:Value2')")
    request_group.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    request_group.add_argument("-ds", "--double-slash", action="store_true", help="Test URLs with double slashes for bypass")

    output_group = parser.add_argument_group("Output Options")
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

    urls = load_urls(args)
    if not urls:
        parser.error("No URLs to scan.")

    config = CheckerConfig(
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        user_agent=args.user_agent,
        custom_headers=parse_headers(args.headers),
        max_threads=args.threads,
        verbose=args.verbose,
    )
    reporter = Reporter(
        verbose=args.verbose,
        preview=args.preview,
        silent=args.silent,
        show_status=args.status,
    )

    try:
        reporter.banner()
        with DirectoryChecker(config) as checker:
            reporter.run(checker, urls, double_slash=args.double_slash)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"\n{Fore.RED}[ERROR] An unexpected error occurred: {exc}{Style.RESET_ALL}")
        if logger.isEnabledFor(logging.DEBUG):
            import traceback
            traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
