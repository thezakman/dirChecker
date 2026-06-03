"""Console presentation layer.

All user-facing output lives here so the scanning engine stays headless and
testable. Rich powers the progress bar and summary; colorama drives the
per-result detail lines for a compact, scriptable look.
"""

from __future__ import annotations

from urllib.parse import urlparse

from colorama import Fore, Style
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

from . import urls
from .__about__ import __version__
from .checker import DirectoryChecker
from .models import CheckResult, ScanStats

_BANNER = rf"""
     _ _       ___ _               _   {Fore.LIGHTGREEN_EX}@thezakman{Fore.GREEN}
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| {Fore.LIGHTGREEN_EX}v{__version__}"""

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "🛡️ [Content-Type-Options]",
    "X-XSS-Protection": "🛡️ [XSS-Protection]",
    "X-Frame-Options": "🛡️ [Frame-Options]",
    "Content-Security-Policy": "🛡️ [CSP]",
    "Strict-Transport-Security": "🛡️ [HSTS]",
}


class Reporter:
    """Render scan progress and results to a terminal."""

    def __init__(
        self,
        verbose: bool = False,
        preview: bool = False,
        silent: bool = False,
        show_status: bool = False,
        console: Console | None = None,
    ) -> None:
        self.verbose = verbose
        self.preview = preview
        self.silent = silent
        self.show_status = show_status
        self.console = console or Console()

    # -- Banner -----------------------------------------------------------

    def banner(self) -> None:
        if self.silent:
            return
        print(f"{Fore.GREEN}{_BANNER}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}\t    - why check manually?{Style.RESET_ALL}\n")

    # -- Orchestration ----------------------------------------------------

    def run(
        self,
        checker: DirectoryChecker,
        seed_urls: list[str],
        double_slash: bool = False,
    ) -> list[CheckResult]:
        """Run a scan, showing a progress bar unless in silent mode."""
        if self.silent:
            results = checker.scan(seed_urls, double_slash=double_slash)
        else:
            total = len(urls.expand_urls(seed_urls, double_slash))
            with Progress(
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                TextColumn("• {task.fields[url]}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("[cyan]Running...", total=total, url="")

                def advance(result: CheckResult) -> None:
                    progress.update(task, advance=1, url=result.url)

                results = checker.scan(seed_urls, double_slash=double_slash, on_result=advance)

        self.report(results, checker.stats)
        return results

    # -- Result rendering -------------------------------------------------

    def report(self, results: list[CheckResult], stats: ScanStats) -> None:
        if self.silent:
            for result in results:
                if result.is_listing:
                    print(result.url)
            return

        for result in self._organize(results):
            if result.error and self.verbose:
                self._print_error(result)
            elif result.is_listing or self.verbose:
                self._print_result(result)

        if self.show_status:
            self._print_stats(stats)

        self.console.print("[bold green]☑️ SCAN COMPLETE![/bold green]")

    @staticmethod
    def _organize(results: list[CheckResult]) -> list[CheckResult]:
        """Order results deepest-first, keeping the base URL last."""
        if not results:
            return []

        deepest = max(r.depth for r in results)
        original_url = next((r.url for r in results if r.depth == deepest), "")

        original = None
        base = None
        middle: list[CheckResult] = []
        for result in results:
            parsed = urlparse(result.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}/"
            if result.url == original_url:
                original = result
            elif result.url == base_url:
                base = result
            else:
                middle.append(result)

        middle.sort(key=lambda r: r.depth, reverse=True)
        ordered = ([original] if original else []) + middle + ([base] if base else [])
        return ordered

    def _print_error(self, result: CheckResult) -> None:
        print(f"{Fore.CYAN}[Testing]{Style.RESET_ALL}: {Fore.YELLOW}{result.url}{Style.RESET_ALL}")
        print(f"{Fore.RED}❌ Error: {result.error}{Style.RESET_ALL}\n")

    def _print_result(self, result: CheckResult) -> None:
        if result.skipped:
            if self.verbose:
                print(f"{Fore.CYAN}[Testing]{Style.RESET_ALL}: {Fore.YELLOW}{result.url}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}⏩ Skipped: {result.skipped}{Style.RESET_ALL}\n")
            return
        if result.response is None:
            return

        response = result.response
        print(f"{Fore.LIGHTYELLOW_EX}   [Testing]{Style.RESET_ALL}: {Fore.YELLOW}{result.url}{Style.RESET_ALL}")

        emoji, color = self._status_style(response.status_code)
        print(f"{emoji} {Fore.CYAN}[Status Code]{Style.RESET_ALL}: {color}{response.status_code}{Style.RESET_ALL}")

        if result.is_listing:
            listing = f"🚨 {Fore.CYAN}[Directory Listing]{Style.RESET_ALL}: {Fore.RED}(VULNERABLE){Style.RESET_ALL}"
        else:
            listing = f"🔒 {Fore.CYAN}[Directory Listing]{Style.RESET_ALL}: {Fore.GREEN}(DISABLED){Style.RESET_ALL}"
        print(listing)
        print(f"📄 {Fore.CYAN}[Content-Type]{Style.RESET_ALL}: {Fore.WHITE}{result.content_type}{Style.RESET_ALL}")

        if self.verbose:
            self._print_verbose(result)
        if self.preview:
            self._print_preview(response)
        print("\n")

    @staticmethod
    def _status_style(status_code: int) -> tuple[str, str]:
        if status_code == 200:
            return "✅", Fore.GREEN
        if status_code in (301, 302, 307, 308):
            return "⚠️", Fore.YELLOW
        return "❌", Fore.RED

    def _print_verbose(self, result: CheckResult) -> None:
        response = result.response
        server = response.headers.get("Server")
        if server:
            print(f"🖥️ {Fore.CYAN}[Server]{Style.RESET_ALL}: {Fore.WHITE}{server}{Style.RESET_ALL}")
        print(f"📦 {Fore.CYAN}[Content-Length]{Style.RESET_ALL}: {Fore.WHITE}{response.headers.get('Content-Length', 'Unknown')}{Style.RESET_ALL}")
        print(f"⏱️ {Fore.CYAN}[Elapsed Time]{Style.RESET_ALL}: {Fore.WHITE}{result.elapsed_time:.2f} seconds{Style.RESET_ALL}")

        for header, label in _SECURITY_HEADERS.items():
            if header in response.headers:
                print(f"{Fore.CYAN}{label}{Style.RESET_ALL}: {Fore.WHITE}{response.headers[header]}{Style.RESET_ALL}")

        if response.history:
            print(f"🔄 {Fore.CYAN}[Redirects]{Style.RESET_ALL}:")
            for resp in response.history:
                color = Fore.YELLOW if resp.status_code in (301, 302, 307, 308) else Fore.RED
                print(f"   ↳ {color}{resp.status_code}{Style.RESET_ALL} → {resp.url}")

    def _print_preview(self, response) -> None:
        print(f"👀 {Fore.CYAN}[Body Preview]{Style.RESET_ALL}:")
        preview_text = response.text[:200].replace("\n", " ").strip()
        print(f"{Fore.WHITE}{preview_text}{Style.RESET_ALL}")

    def _print_stats(self, stats: ScanStats) -> None:
        self.console.print("[bold cyan]📊 [Summary]:[/bold cyan]")
        self.console.print(f"   [white][Directories Tested]:[/white] [yellow]{stats.total_urls}[/yellow]")
        self.console.print(f"   [white][Successful Requests]:[/white] [green]{stats.successful_requests}[/green]")
        self.console.print(f"   [white][Failed Requests]:[/white] [red]{stats.failed_requests}[/red]")
        if stats.connection_errors > 0:
            self.console.print(f"   [white][Connection Errors]:[/white] [red]{stats.connection_errors}[/red]")
        self.console.print(f"   [white][Vulnerable]:[/white] [bold red]{stats.vulnerable_urls}[/bold red]\n")
