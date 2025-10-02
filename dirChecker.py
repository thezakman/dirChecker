#!/usr/bin/env python3
import requests
import argparse
import time
import sys
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from typing import List, Dict, Set, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configure logging and suppress warnings
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger('dirchecker')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama and Rich console
init(autoreset=True)
console = Console()

VERSION = "2.5"

class DirectoryChecker:
    """Class for checking directory listing vulnerabilities"""
    
    BINARY_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico', '.svg',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mp3', '.wav', '.ogg',
        '.zip', '.rar', '.tar', '.gz', '.bz2', '.7z', '.iso',
        '.exe', '.dmg', '.pkg', '.deb', '.rpm'
    }
    
    LISTING_PATTERNS = [
        # Apache patterns
        "<title>Index of", "Index of /", "Parent Directory", "Directory Listing For",
        "Directory listing for", "[To Parent Directory]", "<h1>Index of /",
        "Directory: /", "alt=\"[DIR]\"", "alt=\"\\[DIR\\]\"", "Last modified</a>",

        # Nginx patterns
        "<h1>Index of", "<title>Directory listing for", "<h2>Directory listing of",

        # IIS patterns
        "Directory Listing Denied", "The Directory Browsing", "SystemAdmin</title>",

        # Cloud storage patterns (AWS S3, Google Cloud Storage, Azure)
        "<ListBucketResult", "bucket-listing", "Object Listing", "StorageExplorer",
        "<table class=\"listing", "<td class=\"name\">", "<Prefix>", "<Contents>",
        "<EnumerationResults", "BlobPrefix", "<Blobs>", "<Name>",

        # Generic patterns
        "folder.gif", "file.gif", "back.gif", "[ICO]", "[   ]", "[TXT]",
        "?C=N;O=D", "?C=M;O=A", "?C=S;O=A", "?C=D;O=A",

        # Custom server patterns
        "autoindex", "fancy indexing", "server-generated page"
    ]
    
    SKIP_CONTENT_TYPES = [
        'image/', 'video/', 'audio/', 'application/pdf', 
        'application/zip', 'application/octet-stream',
        'application/x-executable', 'application/x-msdownload'
    ]
    
    # Common error codes that indicate server connection closure
    CONNECTION_ERRORS = [
        "Connection aborted", "Connection reset by peer", 
        "Remote end closed connection", "Connection refused",
        "Connection timed out", "Name or service not known",
        "No route to host", "Network is unreachable",
        "SSL: CERTIFICATE_VERIFY_FAILED", "Max retries exceeded"
    ]

    def __init__(self, timeout: int = 5, verify_ssl: bool = False,
                 user_agent: str = None, custom_headers: Dict[str, str] = None,
                 max_threads: int = 10, verbose: bool = False,
                 reduced_timeout: int = 2):
        """
        Initialize the directory checker

        Args:
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates
            user_agent: Custom User-Agent
            custom_headers: Custom HTTP headers
            max_threads: Maximum number of concurrent threads
            verbose: Verbose mode
            reduced_timeout: Reduced timeout for potentially problematic URLs
        """
        self.timeout = timeout
        self.reduced_timeout = reduced_timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or f"dirChecker/{VERSION}"
        self.custom_headers = custom_headers or {}
        self.max_threads = min(max_threads, 50)  # Cap max threads at 50 for stability
        self.verbose = verbose
        self.session = self._create_session()
        self.connection_errors = 0
        self.stats = {
            'total_urls': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'connection_errors': 0,
            'vulnerable_urls': 0
        }
        
    def _create_session(self) -> requests.Session:
        """Creates a configured HTTP session with optimal settings"""
        session = requests.Session()

        # Configure retry strategy
        from urllib3.util.retry import Retry
        retry_strategy = Retry(
            total=2,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=0.5
        )

        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.max_threads,
            pool_maxsize=self.max_threads * 2
        )

        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # Set default headers
        default_headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        session.headers.update(default_headers)

        if self.custom_headers:
            session.headers.update(self.custom_headers)

        return session

    def is_directory_listing(self, response: requests.Response) -> bool:
        """
        Analyzes response to determine if it contains directory listing

        Args:
            response: HTTP response object

        Returns:
            bool: True if directory listing detected, False otherwise
        """
        if not response or not response.text:
            return False

        # Skip binary content types
        content_type = response.headers.get('Content-Type', '').lower()
        if any(ct in content_type for ct in self.SKIP_CONTENT_TYPES):
            return False

        response_text = response.text.lower()

        # Fast check for obvious directory listing indicators
        if self._check_obvious_patterns(response_text):
            return True

        # Check cloud storage specific patterns
        if self._check_cloud_storage_listing(response):
            return True

        # Check for JSON/API directory listings
        if self._check_json_listing(response):
            return True

        # Comprehensive pattern matching with scoring
        return self._score_directory_patterns(response_text) >= 2

    def _check_obvious_patterns(self, text: str) -> bool:
        """Check for obvious directory listing patterns"""
        obvious_patterns = [
            'index of /', 'directory listing', 'parent directory',
            '[to parent directory]', 'alt="[dir]"'
        ]
        return any(pattern in text for pattern in obvious_patterns)

    def _check_cloud_storage_listing(self, response: requests.Response) -> bool:
        """Check for cloud storage directory listings"""
        response_text_lower = response.text.lower()

        # AWS S3
        if "amazonaws.com" in response.url and response.status_code == 200:
            if "<listbucketresult" in response_text_lower:
                return "<contents>" in response_text_lower or "<commonprefixes>" in response_text_lower

        # Google Cloud Storage
        if "storage.googleapis.com" in response.url and response.status_code == 200:
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/xml' in content_type or 'text/xml' in content_type:
                # Check for GCS bucket listing XML structure
                if "<listbucketresult" in response_text_lower:
                    # Valid listing has either items or prefixes
                    has_contents = "<contents>" in response_text_lower
                    has_prefixes = "<commonprefixes>" in response_text_lower
                    has_keys = "<key>" in response_text_lower
                    is_substantial = len(response.text) > 500

                    return has_contents or has_prefixes or (has_keys and is_substantial)

        # Azure Blob Storage
        if "blob.core.windows.net" in response.url and response.status_code == 200:
            if "<enumerationresults" in response_text_lower:
                return "<blobs>" in response_text_lower or "<blobprefix>" in response_text_lower

        # Skip access denied responses
        if response.status_code == 403:
            denied_patterns = ["access denied", "invalidaccesskeyid", "forbidden"]
            return not any(pattern in response_text_lower for pattern in denied_patterns)

        return False

    def _check_json_listing(self, response: requests.Response) -> bool:
        """Check for JSON-based directory listings"""
        try:
            if 'application/json' in response.headers.get('Content-Type', ''):
                data = response.json()
                if isinstance(data, dict):
                    return any(key in data for key in ['objects', 'contents', 'files', 'entries'])
        except (ValueError, TypeError):
            pass
        return False

    def _score_directory_patterns(self, text: str) -> int:
        """Score text based on directory listing patterns"""
        score = 0

        # Pattern matching with weights
        for pattern in self.LISTING_PATTERNS:
            if pattern.lower() in text:
                score += 1

        # High link count bonus (likely a file listing)
        link_count = text.count('<a href=')
        if link_count > 10:
            score += 2
        elif link_count > 5:
            score += 1

        # Table structure bonus
        if '<table' in text and '<td' in text:
            score += 1

        # XML listing structure (for APIs and cloud storage)
        if '<key>' in text and '<size>' in text:
            score += 2

        return score

    def check_url(self, url: str, verbose: bool = False, preview: bool = False) -> Dict[str, Any]:
        """
        Checks if a specific URL is vulnerable to directory listing

        Args:
            url: URL to check
            verbose: Verbose mode
            preview: Show response body preview

        Returns:
            Dict: Result of the check with detailed information
        """
        result = {
            'url': url,
            'is_listing': False,
            'depth': self._get_url_depth(url),
            'error': None
        }

        # Increment total URLs counter
        self.stats['total_urls'] += 1

        try:
            # Skip binary files in non-verbose mode ONLY if it's a direct file request
            # Always test directories even if they contain binary extensions in path
            if self._is_binary_file(url) and not verbose and not url.endswith('/'):
                result['skipped'] = "Binary file extension"
                return result
            
            # Adjust timeout based on file type and if URL has double slash
            effective_timeout = self._determine_effective_timeout(url)
            
            # Try HEAD request first to quickly filter out large files
            try:
                head_response = self._make_head_request(url, effective_timeout)
                if self._should_skip_from_headers(head_response.headers):
                    result['response'] = head_response
                    result['elapsed_time'] = 0
                    result['skipped_content'] = True
                    self.stats['successful_requests'] += 1
                    return result
            except requests.RequestException:
                pass  # Continue with GET if HEAD fails
            
            # Make GET request with streaming
            start_time = time.time()
            response = self._make_get_request(url, effective_timeout)
            result['response'] = response
            result['elapsed_time'] = time.time() - start_time
            result['is_listing'] = self.is_directory_listing(response)
            
            if result['is_listing']:
                self.stats['vulnerable_urls'] += 1
                
            self.stats['successful_requests'] += 1
            return result
            
        except requests.exceptions.RequestException as e:
            error_message = str(e)
            self.stats['failed_requests'] += 1

            # Categorize and handle different error types
            if any(err in error_message for err in self.CONNECTION_ERRORS):
                self.stats['connection_errors'] += 1
                if '//' in url.replace('://', '') and 'closed connection' in error_message:
                    result['error'] = "Server closed connection (double slash vulnerability test)"
                else:
                    result['error'] = f"Connection error: {self._simplify_error_message(error_message)}"
            else:
                result['error'] = f"Request failed: {self._simplify_error_message(error_message)}"

            return result
        except Exception as e:
            # Capture other non-request related errors
            self.stats['failed_requests'] += 1
            result['error'] = f"Unexpected error: {str(e)}"
            return result

    def _simplify_error_message(self, error_msg: str) -> str:
        """Simplify error messages for better readability"""
        simplifications = {
            'HTTPSConnectionPool': 'HTTPS connection failed',
            'HTTPConnectionPool': 'HTTP connection failed',
            'NewConnectionError': 'Cannot establish connection',
            'ConnectTimeoutError': 'Connection timeout',
            'ReadTimeoutError': 'Read timeout',
            'SSLError': 'SSL/TLS error'
        }

        for pattern, replacement in simplifications.items():
            if pattern in error_msg:
                return replacement

        # Truncate very long error messages
        return error_msg[:100] + '...' if len(error_msg) > 100 else error_msg

    def _determine_effective_timeout(self, url: str) -> int:
        """Determines effective timeout based on URL"""
        # Binary file URLs get shorter timeout
        if self._is_binary_file(url):
            return min(self.timeout, 3)
        
        # URLs with double slash (potentially problematic) get even shorter timeout
        if '//' in url.replace('://', ''):
            return min(self.timeout, self.reduced_timeout)
            
        return self.timeout
            
    def _make_head_request(self, url: str, timeout: int) -> requests.Response:
        """Makes a HEAD request"""
        return self.session.head(url, verify=self.verify_ssl, timeout=timeout, allow_redirects=True)
    
    def _make_get_request(self, url: str, timeout: int, max_content_size: int = 100000) -> requests.Response:
        """
        Makes optimized GET request with intelligent content streaming

        Args:
            url: URL to request
            timeout: Timeout in seconds
            max_content_size: Maximum content size to download in bytes (default 100KB)

        Returns:
            Response: HTTP response object with limited content
        """
        response = self.session.get(
            url,
            verify=self.verify_ssl,
            timeout=timeout,
            stream=True,
            allow_redirects=True
        )

        # Efficiently read and decode content
        content_chunks = []
        total_size = 0

        try:
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                if not chunk:
                    continue

                content_chunks.append(chunk)
                total_size += len(chunk)

                # Stop if we've read enough for analysis
                if total_size >= max_content_size:
                    break

            # Efficiently join and decode content
            raw_content = b''.join(content_chunks)
            try:
                content = raw_content.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                # Fallback to latin-1 if UTF-8 fails
                content = raw_content.decode('latin-1', errors='replace')

            response._content = content.encode('utf-8', errors='replace')

        except Exception as e:
            logger.debug(f"Error reading content from {url}: {str(e)}")
            response._content = b''

        return response
    
    def _should_skip_from_headers(self, headers: Dict[str, str]) -> bool:
        """Determines if content should be skipped based on response headers"""
        content_type = headers.get('Content-Type', '').lower()
        content_length = headers.get('Content-Length', '0')
        content_encoding = headers.get('Content-Encoding', '').lower()

        # Skip binary content types
        if any(ct in content_type for ct in self.SKIP_CONTENT_TYPES):
            return True

        # Skip very large files (> 10MB)
        if content_length.isdigit() and int(content_length) > 10_000_000:
            return True

        # Skip compressed archives that are likely not directory listings
        if content_encoding in ['compress', 'x-compress'] and 'text/html' not in content_type:
            return True

        return False
    
    def _is_binary_file(self, url: str) -> bool:
        """Checks if URL points to a binary file"""
        parsed_url = urlparse(url)
        file_path = parsed_url.path.lower()
        return any(file_path.endswith(ext) for ext in self.BINARY_EXTENSIONS)
    
    def _get_url_depth(self, url: str) -> int:
        """Gets URL depth (number of directories)"""
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip('/').split('/')
        return len(path_parts)
    
    def scan_urls(self, urls: List[str], verbose: bool = False, silent: bool = False, 
                preview: bool = False, status: bool = False, double_slash: bool = False) -> List[Dict[str, Any]]:
        """
        Scans a list of URLs for vulnerabilities
        
        Args:
            urls: List of URLs to check
            verbose: Verbose mode
            silent: Silent mode (only vulnerable URLs)
            preview: Show body preview
            status: Show statistics
            double_slash: Test URLs with double slashes for bypass
            
        Returns:
            List[Dict]: Scan results
        """
        self.verbose = verbose
        
        # Reset statistics
        self.stats = {
            'total_urls': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'connection_errors': 0,
            'vulnerable_urls': 0
        }
        
        # For debug
        if verbose and double_slash and not silent:
            print(f"\n{Fore.CYAN}[DEBUG] Double slash testing is ENABLED{Style.RESET_ALL}\n")
        
        all_urls = self._prepare_urls_to_test(urls, double_slash)
        
        # For debug
        if double_slash and verbose and not silent:
            print(f"\n{Fore.CYAN}[DEBUG] URLs to test:{Style.RESET_ALL}")
            for url in all_urls:
                if '//' in url.replace('://', ''):
                    print(f"  - {Fore.GREEN}{url}{Style.RESET_ALL}")
        
        total_urls = len(all_urls)
        self.stats['total_urls'] = total_urls
        
        results = self._scan_silently(all_urls) if silent else self._scan_with_progress(all_urls, verbose, preview)
        self._display_results(results, verbose, silent, preview, status, total_urls)
        
        return results
    
    def _prepare_urls_to_test(self, urls: List[str], double_slash: bool = False) -> List[str]:
        """
        Intelligently prepares comprehensive URL list for testing

        Args:
            urls: List of original URLs
            double_slash: Flag to add double slash bypass variants

        Returns:
            List[str]: Optimized list of URLs to test
        """
        url_set = set()
        final_urls = []

        for url in urls:
            normalized_url = self._normalize_url(url)

            # Add original URL
            if normalized_url not in url_set:
                final_urls.append(normalized_url)
                url_set.add(normalized_url)

            # Generate URL variants and parent directories
            variants = self._generate_url_variants(normalized_url, double_slash)

            for variant in variants:
                if variant not in url_set:
                    final_urls.append(variant)
                    url_set.add(variant)

        # Optimize URL order for efficient scanning
        return self._optimize_url_order(final_urls)

    def _generate_url_variants(self, url: str, double_slash: bool) -> List[str]:
        """Generate all URL variants for comprehensive testing"""
        variants = []
        parsed_url = urlparse(url)

        # Generate directory variants
        variants.extend(self._get_directory_variants(url, double_slash))

        # Generate parent directory chain
        variants.extend(self._get_parent_directories(url, double_slash))

        return variants

    def _get_directory_variants(self, url: str, double_slash: bool) -> List[str]:
        """Get directory path variants"""
        variants = []

        if not self._has_file_extension(url):
            # Add trailing slash variant
            if not url.endswith('/'):
                variants.append(f"{url}/")

            # Add double slash variants for bypass testing
            if double_slash:
                if url.endswith('/'):
                    variants.append(f"{url}/")
                else:
                    variants.append(f"{url}//")

        return variants

    def _get_parent_directories(self, url: str, double_slash: bool) -> List[str]:
        """Extract all parent directories for testing"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path_parts = [p for p in parsed_url.path.strip('/').split('/') if p]

        # Remove filename if present
        if path_parts and '.' in path_parts[-1] and not path_parts[-1].startswith('.'):
            path_parts.pop()

        variants = []

        # Build parent directory hierarchy
        for i in range(len(path_parts)):
            parent_path = '/'.join(path_parts[:i+1])
            parent_url = f"{base_url}/{parent_path}/"
            variants.append(parent_url)

            if double_slash:
                variants.append(f"{parent_url}/")

        # Add root directory
        root_url = f"{base_url}/"
        variants.append(root_url)
        if double_slash:
            variants.append(f"{root_url}/")

        return variants

    def _optimize_url_order(self, urls: List[str]) -> List[str]:
        """Optimize URL scanning order for efficiency"""
        # Sort by depth (deeper first) then alphabetically for consistency
        return sorted(urls, key=lambda x: (-self._get_url_depth(x), x))
    
    def _normalize_url(self, url: str) -> str:
        """Normalizes a URL ensuring correct protocol"""
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        return url
    
    def _has_file_extension(self, url: str) -> bool:
        """Checks if URL ends with a file extension"""
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip('/').split('/')
        last_part = path_parts[-1] if path_parts else ""
        
        # Check if the last component has a file extension
        return '.' in last_part and not last_part.endswith('.')
    
    
                    
    
    def _scan_with_progress(self, urls: List[str], verbose: bool, preview: bool) -> List[Dict[str, Any]]:
        """
        Scans URLs showing a progress bar
        
        Args:
            urls: List of URLs to scan
            verbose: Verbose mode
            preview: Show body preview
            
        Returns:
            List[Dict]: Scan results
        """
        results = []
        
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("• {task.fields[url]}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Running...", total=len(urls), url="")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_url = {executor.submit(self.check_url, url, verbose, preview): url for url in urls}
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    progress.update(task, advance=1, url=url)
                    
                    try:
                        results.append(future.result())
                    except Exception as e:
                        results.append({
                            'url': url, 
                            'error': str(e), 
                            'depth': self._get_url_depth(url)
                        })
            
        return results
    
    def _scan_silently(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Scans URLs silently (without progress bar)
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List[Dict]: Scan results
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {executor.submit(self.check_url, url, False, False): url for url in urls}
            
            for future in as_completed(future_to_url):
                try:
                    results.append(future.result())
                except Exception as e:
                    url = future_to_url[future]
                    logger.debug(f"Error scanning {url}: {str(e)}")
                    results.append({
                        'url': url, 
                        'error': str(e),
                        'depth': self._get_url_depth(url)
                    })
        
        return results
    
    def _display_results(self, results: List[Dict[str, Any]], verbose: bool, silent: bool,
                      preview: bool, status: bool, total_urls: int) -> None:
        """
        Displays scan results

        Args:
            results: Scan results
            verbose: Verbose mode
            silent: Silent mode
            preview: Show body preview
            status: Show statistics
            total_urls: Total URLs scanned
        """
        if silent:
            # Print only vulnerable URLs in silent mode
            for result in results:
                if result.get('is_listing'):
                    print(result['url'])
            return

        # Sort results by category and depth
        ordered_results = self._organize_results(results)

        # Display the ordered results
        for result in ordered_results:
            if 'error' in result and result['error'] and verbose:
                self._print_error_result(result)
            elif result.get('is_listing'):
                # Always show vulnerable listings
                self._print_url_result(result, verbose, preview)
            elif verbose:
                # In verbose mode, show all results
                self._print_url_result(result, verbose, preview)
        
        # Show statistics if requested
        if status:
            self._print_statistics(total_urls)
        
        console.print("[bold green]☑️ SCAN COMPLETE![/bold green]")
        
    def _organize_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Organizes results in a logical order
        
        Args:
            results: Raw scan results
            
        Returns:
            List[Dict]: Organized results
        """
        # Find the original URL (usually the deepest)
        original_url = self._find_most_likely_original_url(results)
        
        # Classify results by categories
        original_result = None
        intermediate_results = []
        base_result = None
        
        for result in results:
            url = result['url']
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
            
            if url == original_url:
                original_result = result
            elif url == base_url:
                base_result = result
            else:
                intermediate_results.append(result)
        
        # Sort intermediate results by depth (from deepest to shallowest)
        intermediate_results.sort(key=lambda x: self._get_url_depth(x['url']), reverse=True)
        
        # Build results in order: original -> intermediate -> base
        ordered_results = []
        if original_result:
            ordered_results.append(original_result)
        ordered_results.extend(intermediate_results)
        if base_result:
            ordered_results.append(base_result)
        
        return ordered_results
        
    def _find_most_likely_original_url(self, results: List[Dict[str, Any]]) -> str:
        """
        Finds URL that was likely the original one provided by the user
        based on depth and position in the results list
        """
        if not results:
            return ""
            
        # Get the deepest URL
        most_deep_url = max(results, key=lambda x: x['depth'])
        
        # If several URLs have the same maximum depth, take the first
        deepest_urls = [r for r in results if r['depth'] == most_deep_url['depth']]
        if deepest_urls:
            return deepest_urls[0]['url']
            
        return ""
    
    def _print_error_result(self, result: Dict[str, Any]) -> None:
        """Displays result with error"""
        print(f"{Fore.CYAN}[Testing]{Style.RESET_ALL}: {Fore.YELLOW}{result['url']}{Style.RESET_ALL}")
        print(f"{Fore.RED}❌ Error: {result['error']}{Style.RESET_ALL}\n")
    
    def _print_url_result(self, result: Dict[str, Any], verbose: bool, preview: bool) -> None:
        """Displays result for a URL"""
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
        """Gets emoji and color for HTTP status code"""
        if status_code == 200:
            return {'color': Fore.GREEN, 'emoji': "✅"}
        elif status_code in [301, 302, 307, 308]:
            return {'color': Fore.YELLOW, 'emoji': "⚠️"}
        else:
            return {'color': Fore.RED, 'emoji': "❌"}
    
    def _get_listing_display(self, is_listing: bool) -> Dict[str, str]:
        """Gets emoji and text for directory listing status"""
        if is_listing:
            return {'emoji': "🚨", 'status': f"{Fore.RED}(VULNERABLE){Style.RESET_ALL}"}
        else:
            return {'emoji': "🔒", 'status': f"{Fore.GREEN}(DISABLED){Style.RESET_ALL}"}
    
    def _print_verbose_details(self, result: Dict[str, Any]) -> None:
        """Displays additional details in verbose mode"""
        response = result['response']
        elapsed_time = result.get('elapsed_time', 0)
        
        # Print server header if available
        server = response.headers.get('Server')
        if server:
            print(f"🖥️ {Fore.CYAN}[Server]{Style.RESET_ALL}: {Fore.WHITE}{server}{Style.RESET_ALL}")
        
        print(f"📦 {Fore.CYAN}[Content-Length]{Style.RESET_ALL}: {Fore.WHITE}{response.headers.get('Content-Length', 'Unknown')}{Style.RESET_ALL}")
        print(f"⏱️ {Fore.CYAN}[Elapsed Time]{Style.RESET_ALL}: {Fore.WHITE}{elapsed_time:.2f} seconds{Style.RESET_ALL}")
        
        # Print security headers if available
        security_headers = {
            'X-Content-Type-Options': '🛡️ [Content-Type-Options]',
            'X-XSS-Protection': '🛡️ [XSS-Protection]',
            'X-Frame-Options': '🛡️ [Frame-Options]',
            'Content-Security-Policy': '🛡️ [CSP]',
            'Strict-Transport-Security': '🛡️ [HSTS]'
        }
        
        for header, label in security_headers.items():
            if header in response.headers:
                print(f"{Fore.CYAN}{label}{Style.RESET_ALL}: {Fore.WHITE}{response.headers[header]}{Style.RESET_ALL}")
        
        if response.history:
            print(f"🔄 {Fore.CYAN}[Redirects]{Style.RESET_ALL}:")
            for resp in response.history:
                redirect_color = Fore.YELLOW if resp.status_code in [301, 302, 307, 308] else Fore.RED
                print(f"   ↳ {redirect_color}{resp.status_code}{Style.RESET_ALL} → {resp.url}")
    
    def _print_preview(self, response: requests.Response) -> None:
        """Displays preview of response body"""
        print(f"👀 {Fore.CYAN}[Body Preview]{Style.RESET_ALL}:")
        preview_text = response.text[:200].replace('\n', ' ').strip()
        print(f"{Fore.WHITE}{preview_text}{Style.RESET_ALL}")
    
    def _print_statistics(self, total_urls: int) -> None:
        """Displays scan statistics"""
        console.print(f"[bold cyan]📊 [Summary]:[/bold cyan]")
        console.print(f"   [white][Directories Tested]:[/white] [yellow]{total_urls}[/yellow]")
        console.print(f"   [white][Successful Requests]:[/white] [green]{self.stats['successful_requests']}[/green]")
        console.print(f"   [white][Failed Requests]:[/white] [red]{self.stats['failed_requests']}[/red]")
        if self.stats['connection_errors'] > 0:
            console.print(f"   [white][Connection Errors]:[/white] [red]{self.stats['connection_errors']}[/red]")
        console.print(f"   [white][Vulnerable]:[/white] [bold red]{self.stats['vulnerable_urls']}[/bold red]\n")


def print_banner():
    """Displays program banner"""
    banner = fr'''
     _ _       ___ _               _   {Fore.LIGHTGREEN_EX}@thezakman{Fore.GREEN}
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| {Fore.LIGHTGREEN_EX}v{VERSION}'''
    sub_banner = "\t    - why check manually?"
    print(f"{Fore.GREEN}{banner}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{sub_banner}{Style.RESET_ALL}\n")


def parse_custom_headers(header_string: Optional[str]) -> Dict[str, str]:
    """Parses custom headers from a string"""
    headers = {}
    if header_string:
        for pair in header_string.split(','):
            if ':' in pair:
                key, value = pair.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers


def parse_arguments():
    """Parses command line arguments"""
    parser = argparse.ArgumentParser(
        description="Check directories for directory listing vulnerabilities.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # URL input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument('url', nargs='?', help='URL to check')
    input_group.add_argument('-u', '--url-flag', help='URL to check (alternative to positional URL)')
    input_group.add_argument('-l', '--list', help='File containing list of URLs to check')
    
    # Request options
    request_group = parser.add_argument_group('Request Options')
    request_group.add_argument("-to", "--timeout", type=int, default=5, help="Request timeout in seconds")
    request_group.add_argument("-vs", "--verify-ssl", action='store_true', help="Verify SSL certificates")
    request_group.add_argument("-ua", "--user-agent", help=f"Custom User-Agent (default: dirChecker/{VERSION})")
    request_group.add_argument("-H", "--headers", help="Custom headers (format: 'Header1:Value1,Header2:Value2')")
    request_group.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    request_group.add_argument("-ds", "--double-slash", action='store_true', help="Test URLs with double slashes for bypass")
    
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
    """Gets URLs from passed arguments"""
    urls = []
    
    if args.url:
        urls.append(args.url)
    elif args.url_flag:
        urls.append(args.url_flag)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            console.print(f"[bold red]Error opening URL list file: {e}[/bold red]")
            exit(1)
            
    return urls


def main():
    """Main function"""
    try:
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
            max_threads=args.threads,
            verbose=args.verbose
        )
        
        # Scan URLs
        checker.scan_urls(
            urls=urls,
            verbose=args.verbose,
            silent=args.silent,
            preview=args.preview,
            status=args.status,
            double_slash=args.double_slash
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
        if logger.level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()