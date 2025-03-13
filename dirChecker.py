#!/usr/bin/env python3.11
import requests
import argparse
import time
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from typing import List, Dict, Tuple, Optional, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger('dirchecker')

# Suppress InsecureRequestWarning for SSL connections
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Rich console
console = Console()

# Version control
VERSION = "2.1"


class DirectoryChecker:
    """Class for checking directory listing vulnerabilities"""
    
    # Common binary file extensions to skip
    BINARY_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.mp4', '.zip', '.rar', 
        '.mp3', '.avi', '.mov', '.wmv', '.flv', '.doc', '.docx', '.xls', 
        '.xlsx', '.ppt', '.pptx', '.svg', '.webp', '.ico', '.exe'
    }
    
    # Directory listing detection patterns
    LISTING_PATTERNS = [
        "<ListBucketResult", "Index of", "Parent Directory",
        "Directory Listing For", "<title>Index of", "Directory listing for",
        "[To Parent Directory]", "<h1>Index of /", "Directory: /",
        "alt=\"\[DIR\]\"", "alt=\"[DIR]\"", "Last modified</a>",
        "<h2>Directory listing of", "bucket-listing",
        "<table class=\"listing", "<td class=\"name\">",
        "Object Listing", "StorageExplorer"
    ]
    
    # Content types to skip
    SKIP_CONTENT_TYPES = [
        'image/', 'video/', 'audio/', 'application/pdf', 
        'application/zip', 'application/octet-stream'
    ]
    
    def __init__(self, timeout=5, verify_ssl=False, user_agent="dirChecker/2.1", 
                 custom_headers=None, max_threads=10):
        """Initialize the directory checker with configurable parameters"""
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.custom_headers = custom_headers or {}
        self.max_threads = max_threads
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """Create and configure a requests session with proper settings"""
        session = requests.Session()
        
        # Configure adapter with stricter timeouts and fewer retries
        adapter = requests.adapters.HTTPAdapter(
            max_retries=1,
            pool_connections=self.max_threads,
            pool_maxsize=self.max_threads
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # Set headers
        session.headers.update({'User-Agent': self.user_agent})
        if self.custom_headers:
            session.headers.update(self.custom_headers)
            
        return session

    def is_directory_listing(self, response) -> bool:
        """
        Determine if a response contains a directory listing
        
        Args:
            response: Requests Response object
            
        Returns:
            bool: True if the response is a directory listing, False otherwise
        """
        # Skip content check if Content-Type is a binary file
        content_type = response.headers.get('Content-Type', '').lower()
        if any(binary_type in content_type for binary_type in self.SKIP_CONTENT_TYPES):
            return False
        
        # Check for S3 bucket listings
        if "amazonaws.com" in response.url and response.status_code == 200:
            if "<ListBucketResult" in response.text:
                if all(marker in response.text for marker in ["<Contents>", "<Key>"]):
                    return True  # S3 bucket with public listing
        
        # 403 responses from S3 buckets are not vulnerability listings
        if response.status_code == 403 and "<Error>" in response.text:
            if any(marker in response.text for marker in [
                "<Message>Access Denied</Message>", "InvalidAccessKeyId"
            ]):
                return False
        
        # Check for JSON directory listings
        try:
            json_data = response.json()
            if isinstance(json_data, dict) and any(key in json_data for key in ['objects', 'contents']):
                return True
        except:
            pass
        
        # Count positive directory listing markers
        positive_counts = sum(1 for pattern in self.LISTING_PATTERNS if pattern in response.text)
        
        # If we have multiple positive patterns, it's likely a directory listing
        if positive_counts >= 2:
            return True
        
        # Check for high link count combined with directory-related terms
        if (response.text.count('<a href=') > 10 and 
            any(term in response.text.lower() for term in ['directory', 'listing', 'index of', 'parent'])):
            return True
        
        return False

    def check_url(self, url: str, verbose=False, preview=False) -> Dict[str, Any]:
        """
        Check a URL for directory listing vulnerability
        
        Args:
            url: URL to check
            verbose: Whether to collect verbose information
            preview: Whether to collect content preview
            
        Returns:
            Dict: Result information
        """
        result = {
            'url': url,
            'is_listing': False,
            'depth': self._get_url_depth(url),
            'error': None
        }
        
        try:
            # Check if it's a binary file by extension
            if self._is_binary_file(url) and not verbose:
                result['skipped'] = "Binary file extension"
                return result
            
            # Adjust timeout based on file type
            effective_timeout = min(self.timeout, 3 if self._is_binary_file(url) else self.timeout)
            
            # Try HEAD request first to quickly filter out large files
            try:
                head_response = self._make_head_request(url, effective_timeout)
                
                # Check content headers to determine if we should skip
                if self._should_skip_from_headers(head_response.headers):
                    result['response'] = head_response
                    result['elapsed_time'] = 0
                    result['skipped_content'] = True
                    return result
                    
            except Exception:
                # If HEAD fails, continue with GET
                pass
            
            # Make GET request with streaming to limit data transfer
            start_time = time.time()
            response = self._make_get_request(url, effective_timeout)
            elapsed_time = time.time() - start_time
            
            # Analyze the response
            result['response'] = response
            result['elapsed_time'] = elapsed_time
            result['is_listing'] = self.is_directory_listing(response)
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            return result

    def _make_head_request(self, url: str, timeout: int) -> requests.Response:
        """Make a HEAD request to check content type and size"""
        return self.session.head(
            url, 
            verify=self.verify_ssl,
            timeout=timeout,
            allow_redirects=True
        )
    
    def _make_get_request(self, url: str, timeout: int, max_content_size: int = 20000) -> requests.Response:
        """Make a GET request and download limited content for analysis"""
        response = self.session.get(
            url, 
            verify=self.verify_ssl,
            timeout=timeout,
            stream=True
        )
        
        # Download just enough to analyze
        content = ""
        content_size = 0
        
        for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
            if chunk:
                content += chunk if isinstance(chunk, str) else chunk.decode('utf-8', errors='ignore')
                content_size += len(chunk)
                if content_size >= max_content_size:
                    break
        
        # Store partial content for analysis
        response._content = content.encode('utf-8')
        return response
    
    def _should_skip_from_headers(self, headers: Dict[str, str]) -> bool:
        """Determine if we should skip full content download based on headers"""
        content_type = headers.get('Content-Type', '').lower()
        content_length = headers.get('Content-Length', '0')
        
        # Skip certain content types
        if any(ct in content_type for ct in self.SKIP_CONTENT_TYPES):
            return True
            
        # Skip large files
        if content_length.isdigit() and int(content_length) > 1000000:  # 1MB
            return True
            
        return False
    
    def _is_binary_file(self, url: str) -> bool:
        """Check if URL points to a binary file based on extension"""
        parsed_url = urlparse(url)
        file_path = parsed_url.path.lower()
        return any(file_path.endswith(ext) for ext in self.BINARY_EXTENSIONS)
    
    def _get_url_depth(self, url: str) -> int:
        """Calculate the directory depth of a URL"""
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip('/').split('/')
        return len(path_parts)
    
    def scan_urls(self, urls: List[str], verbose=False, silent=False, preview=False, status=False) -> List[Dict[str, Any]]:
        """
        Scan a list of URLs for directory listing vulnerabilities
        
        Args:
            urls: List of URLs to scan
            verbose: Whether to show verbose output
            silent: Whether to suppress output
            preview: Whether to show response preview
            status: Whether to show scan status
            
        Returns:
            List[Dict]: Scan results
        """
        # Process URLs to include parent directories
        all_urls = self._prepare_urls_to_test(urls)
        total_urls = len(all_urls)
        
        # Perform the scan based on mode
        if silent:
            results = self._scan_silently(all_urls)
        else:
            results = self._scan_with_progress(all_urls, verbose, preview)
        
        # Display results
        self._display_results(results, verbose, silent, preview, status, total_urls)
        
        return results
    
    def _prepare_urls_to_test(self, urls: List[str]) -> List[str]:
        """Prepare URLs for testing including parent directories"""
        all_urls_to_test = []
        tested_urls = set()
        
        for url in urls:
            # Add the URL and all its parent directories
            self._add_url_and_parents(url, all_urls_to_test, tested_urls)
            
        return all_urls_to_test
    
    def _add_url_and_parents(self, url: str, all_urls: List[str], tested_urls: Set[str]) -> None:
        """Add a URL and all its parent directories to the test list"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        path_parts = parsed_url.path.strip('/').split('/')
        
        # Add original URL if not already added
        if url not in tested_urls:
            all_urls.append(url)
            tested_urls.add(url)
        
        # Add parent directories
        current_path = ""
        for part in path_parts:
            current_path = f"{current_path}/{part}"
            test_url = urljoin(base_url, current_path + "/")
            if test_url not in tested_urls:
                all_urls.append(test_url)
                tested_urls.add(test_url)
        
        # Add base URL if not already added
        if base_url not in tested_urls:
            all_urls.append(base_url)
            tested_urls.add(base_url)
    
    def _scan_with_progress(self, urls: List[str], verbose: bool, preview: bool) -> List[Dict[str, Any]]:
        """Scan URLs with progress bar"""
        results = []
        
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("• {task.fields[url]}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Running...", total=len(urls), url="")
            
            # Use ThreadPoolExecutor for parallel processing
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_url = {
                    executor.submit(self.check_url, url, verbose, preview): url 
                    for url in urls
                }
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    progress.update(task, advance=1, url=url)
                    
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        results.append({
                            'url': url,
                            'error': str(e),
                            'depth': self._get_url_depth(url)
                        })
        
        return results
    
    def _scan_silently(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan URLs without showing progress"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {
                executor.submit(self.check_url, url, False, False): url 
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.debug(f"Error scanning {url}: {str(e)}")
        
        return results
    
    def _display_results(self, results: List[Dict[str, Any]], verbose: bool, silent: bool, 
                         preview: bool, status: bool, total_urls: int) -> None:
        """Display scan results"""
        if silent:
            # In silent mode, print only vulnerable URLs
            for result in results:
                if result.get('is_listing'):
                    print(result['url'])
            return
            
        # Sort results by depth (most specific to most general) for verbose mode
        if verbose:
            results.sort(key=lambda x: (-x.get('depth', 0)))
        
        # Display detailed results
        for result in results:
            if 'error' in result and result['error']:
                if verbose:  # Show errors only in verbose mode
                    self._print_error_result(result)
            elif result.get('is_listing') or verbose:
                self._print_url_result(result, verbose, preview)
        
        # Show summary if requested
        if status:
            vulnerable_count = sum(1 for r in results if r.get('is_listing'))
            self._print_summary(total_urls, vulnerable_count)
        
        console.print("[bold green]☑️ SCAN COMPLETE![/bold green]")
    
    def _print_error_result(self, result: Dict[str, Any]) -> None:
        """Print error results"""
        print(f"{Fore.CYAN}[Testing]{Style.RESET_ALL}: {Fore.YELLOW}{result['url']}{Style.RESET_ALL}")
        print(f"{Fore.RED}❌ Error: {result['error']}{Style.RESET_ALL}\n")
    
    def _print_url_result(self, result: Dict[str, Any], verbose: bool, preview: bool) -> None:
        """Print URL scan results"""
        if 'skipped' in result:
            if verbose:
                print(f"{Fore.CYAN}[Testing]{Style.RESET_ALL}: {Fore.YELLOW}{result['url']}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}⏩ Skipped: {result['skipped']}{Style.RESET_ALL}\n")
            return
            
        if 'response' not in result:
            return
            
        response = result['response']
        is_listing = result.get('is_listing', False)
        
        print(f"{Fore.LIGHTYELLOW_EX}   [Testing]{Style.RESET_ALL}: {Fore.YELLOW}{result['url']}{Style.RESET_ALL}")
        
        # Status code with emoji
        status_info = self._get_status_display(response.status_code)
        print(f"{status_info['emoji']} {Fore.CYAN}[Status Code]{Style.RESET_ALL}: {status_info['color']}{response.status_code}{Style.RESET_ALL}")
        
        # Directory Listing status with emoji
        listing_info = self._get_listing_display(is_listing)
        print(f"{listing_info['emoji']} {Fore.CYAN}[Directory Listing]{Style.RESET_ALL}: {listing_info['status']}")
        print(f"📄 {Fore.CYAN}[Content-Type]{Style.RESET_ALL}: {Fore.WHITE}{response.headers.get('Content-Type', 'Unknown')}{Style.RESET_ALL}")
        
        # Additional details for verbose mode
        if verbose:
            self._print_verbose_details(result)
            
        if preview:
            self._print_preview(response)
        
        print("\n")
    
    def _get_status_display(self, status_code: int) -> Dict[str, str]:
        """Get display information for HTTP status code"""
        if status_code == 200:
            return {'color': Fore.GREEN, 'emoji': "✅"}
        elif status_code in [301, 302, 307, 308]:
            return {'color': Fore.YELLOW, 'emoji': "⚠️"}
        else:
            return {'color': Fore.RED, 'emoji': "❌"}
    
    def _get_listing_display(self, is_listing: bool) -> Dict[str, str]:
        """Get display information for directory listing status"""
        if is_listing:
            return {
                'emoji': "🚨",
                'status': f"{Fore.RED}(VULNERABLE){Style.RESET_ALL}"
            }
        else:
            return {
                'emoji': "🔒",
                'status': f"{Fore.GREEN}(DISABLED){Style.RESET_ALL}"
            }
    
    def _print_verbose_details(self, result: Dict[str, Any]) -> None:
        """Print verbose details for a result"""
        response = result['response']
        elapsed_time = result.get('elapsed_time', 0)
        
        print(f"📦 {Fore.CYAN}[Content-Length]{Style.RESET_ALL}: {Fore.WHITE}{response.headers.get('Content-Length', 'Unknown')}{Style.RESET_ALL}")
        print(f"⏱️ {Fore.CYAN}[Elapsed Time]{Style.RESET_ALL}: {Fore.WHITE}{elapsed_time:.2f} seconds{Style.RESET_ALL}")
        
        if response.history:
            print(f"🔄 {Fore.CYAN}[Redirects]{Style.RESET_ALL}:")
            for resp in response.history:
                redirect_color = Fore.YELLOW if resp.status_code in [301, 302, 307, 308] else Fore.RED
                print(f"   ↳ {redirect_color}{resp.status_code}{Style.RESET_ALL} → {resp.url}")
    
    def _print_preview(self, response) -> None:
        """Print preview of response body"""
        print(f"👀 {Fore.CYAN}[Body Preview]{Style.RESET_ALL}:")
        preview_text = response.text[:200].replace('\n', ' ').strip()
        print(f"{Fore.WHITE}{preview_text}{Style.RESET_ALL}")
    
    def _print_summary(self, total_urls: int, vulnerable_count: int) -> None:
        """Print scan summary"""
        console.print(f"[bold cyan]📊 [Summary]:[/bold cyan]")
        console.print(f"   [white][Directories]:[/white] [yellow]{total_urls}[/yellow]")
        console.print(f"   [white][Vulnerable]:[/white] [bold red]{vulnerable_count}[/bold red]\n")


def print_banner():
    """Display the application banner"""
    banner = fr'''
     _ _       ___ _               _   {Fore.LIGHTGREEN_EX}@thezakman{Fore.GREEN}
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| {Fore.LIGHTGREEN_EX}v{VERSION}'''
    sub_banner = "\t    - why checking manually?"
    print(f"{Fore.GREEN}{banner}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{sub_banner}{Style.RESET_ALL}\n")


def parse_custom_headers(header_string: Optional[str]) -> Dict[str, str]:
    """Parse custom headers from string format to dictionary"""
    headers = {}
    if header_string:
        header_pairs = header_string.split(',')
        for pair in header_pairs:
            if ':' in pair:
                key, value = pair.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Check directories for directory listing vulnerabilities.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # URL input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument('url', nargs='?', help='URL to check')
    input_group.add_argument('-u', '--url-flag', type=str, help='URL to check (alternative to positional URL)')
    input_group.add_argument('-l', '--list', type=str, help='File containing list of URLs to check')
    
    # Request options
    request_group = parser.add_argument_group('Request Options')
    request_group.add_argument("-to", "--timeout", type=int, default=5, help="Request timeout in seconds")
    request_group.add_argument("-vs", "--verify-ssl", action='store_true', help="Verify SSL certificates")
    request_group.add_argument("-ua", "--user-agent", default="dirChecker/2.1", help="Custom User-Agent")
    request_group.add_argument("-H", "--headers", type=str, help="Custom headers (format: 'Header1:Value1,Header2:Value2')")
    request_group.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("-slt", "--silent", action='store_true', help="Output only vulnerable URLs")
    output_group.add_argument("-v", "--verbose", action='store_true', help="Show detailed information for all URLs")
    output_group.add_argument("-p", "--preview", action='store_true', help="Show response body preview")
    output_group.add_argument("-s", "--status", action='store_true', help="Show summary statistics")
    output_group.add_argument("--debug", action='store_true', help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Validate arguments
    if not any([args.url, args.url_flag, args.list]):
        parser.error("No URL provided. Use positional argument, -u/--url or -l/--list")
        
    return args


def get_urls_from_args(args) -> List[str]:
    """Get URLs from command line arguments"""
    urls = []
    
    if args.url:
        urls.append(args.url)
    elif args.url_flag:
        urls.append(args.url_flag)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f.readlines() if line.strip()]
        except (IOError, FileNotFoundError) as e:
            console.print(f"[bold red]Error opening URL list file: {e}[/bold red]")
            exit(1)
            
    return urls


def main():
    """Main function"""
    args = parse_arguments()
    
    custom_headers = parse_custom_headers(args.headers)
    urls = get_urls_from_args(args)
    
    # Display banner in non-silent mode
    if not args.silent:
        print_banner()
    
    # Create and configure the directory checker
    checker = DirectoryChecker(
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        user_agent=args.user_agent,
        custom_headers=custom_headers,
        max_threads=args.threads
    )
    
    # Scan URLs
    checker.scan_urls(
        urls=urls,
        verbose=args.verbose,
        silent=args.silent,
        preview=args.preview,
        status=args.status
    )


if __name__ == "__main__":
    main()