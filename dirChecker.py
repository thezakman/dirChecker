#!/usr/bin/env python3
import requests
import argparse
import time
import sys
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from typing import List, Dict, Set, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import re

# Configure logging and suppress warnings
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger('dirchecker')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama and Rich console
init(autoreset=True)
console = Console()

# Version control
VERSION = "2.3"  # Incremented to reflect improvements

class DirectoryChecker:
    """Class for checking directory listing vulnerabilities"""
    
    BINARY_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.mp4', '.zip', '.rar', 
        '.mp3', '.avi', '.mov', '.wmv', '.flv', '.doc', '.docx', '.xls', 
        '.xlsx', '.ppt', '.pptx', '.svg', '.webp', '.ico', '.exe', '.dmg',
        '.pkg', '.deb', '.rpm', '.tar', '.gz', '.bz2', '.7z', '.iso'
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
        
        # Cloud storage patterns
        "<ListBucketResult", "bucket-listing", "Object Listing", "StorageExplorer",
        "<table class=\"listing", "<td class=\"name\">", 
        
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
        "No route to host", "Network is unreachable"
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
        self.max_threads = max_threads
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
        """Creates a configured HTTP session"""
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            max_retries=1,  # Limit to 1 to avoid overloading the server
            pool_connections=self.max_threads,
            pool_maxsize=self.max_threads
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({'User-Agent': self.user_agent})
        if self.custom_headers:
            session.headers.update(self.custom_headers)
        return session

    def is_directory_listing(self, response: requests.Response) -> bool:
        """
        Checks if the response contains directory listing
        
        Args:
            response: HTTP response object
            
        Returns:
            bool: True if it's a directory listing, False otherwise
        """
        # Skip binary content types
        content_type = response.headers.get('Content-Type', '').lower()
        if any(binary_type in content_type for binary_type in self.SKIP_CONTENT_TYPES):
            return False
        
        # Check for S3 bucket listings
        if "amazonaws.com" in response.url and response.status_code == 200:
            if "<ListBucketResult" in response.text and all(marker in response.text for marker in ["<Contents>", "<Key>"]):
                return True
        
        # Skip S3 access denied responses
        if response.status_code == 403 and "<e>" in response.text:
            if any(marker in response.text for marker in ["<Message>Access Denied</Message>", "InvalidAccessKeyId"]):
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
        if positive_counts >= 2:
            return True
        
        # Check for high link count combined with directory-related terms
        if (response.text.count('<a href=') > 10 and 
            any(term in response.text.lower() for term in ['directory', 'listing', 'index of', 'parent'])):
            return True
        
        return False

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
            # Skip binary files unless verbose mode
            if self._is_binary_file(url) and not verbose:
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
            # Better handling of connection errors
            error_message = str(e)
            self.stats['failed_requests'] += 1
            
            # Check if it's a known connection error
            is_connection_error = any(err in error_message for err in self.CONNECTION_ERRORS)
            if is_connection_error:
                self.stats['connection_errors'] += 1
                # More friendly error for double slashes that commonly cause problems
                if '//' in url.replace('://', '') and 'closed connection' in error_message:
                    result['error'] = f"Server closed connection (common in double slash tests)"
                else:
                    result['error'] = f"Connection error: {error_message}"
            else:
                result['error'] = f"Error: {error_message}"
                
            return result
        except Exception as e:
            # Capture other non-request related errors
            self.stats['failed_requests'] += 1
            result['error'] = f"Unexpected error: {str(e)}"
            return result

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
    
    def _make_get_request(self, url: str, timeout: int, max_content_size: int = 20000) -> requests.Response:
        """
        Makes a GET request with streaming to limit download size
        
        Args:
            url: URL to request
            timeout: Timeout in seconds
            max_content_size: Maximum content size to download in bytes
            
        Returns:
            Response: HTTP response object
        """
        response = self.session.get(url, verify=self.verify_ssl, timeout=timeout, stream=True)
        
        # Download just enough to analyze
        content = ""
        content_size = 0
        try:
            for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
                if chunk:
                    content += chunk if isinstance(chunk, str) else chunk.decode('utf-8', errors='ignore')
                    content_size += len(chunk)
                    if content_size >= max_content_size:
                        break
            
            response._content = content.encode('utf-8')
        except Exception as e:
            # If there's an error reading content, save what we have already
            logger.debug(f"Error reading full content: {str(e)}")
            response._content = content.encode('utf-8')
        
        return response
    
    def _should_skip_from_headers(self, headers: Dict[str, str]) -> bool:
        """Checks if download should be skipped based on headers"""
        content_type = headers.get('Content-Type', '').lower()
        content_length = headers.get('Content-Length', '0')
        
        return (any(ct in content_type for ct in self.SKIP_CONTENT_TYPES) or 
                (content_length.isdigit() and int(content_length) > 1000000))
    
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
        Prepares list of URLs to test, including parent directories and variants
        
        Args:
            urls: List of original URLs
            double_slash: Flag to add double slash variants
            
        Returns:
            List[str]: Complete list of URLs to test
        """
        all_urls_to_test = []
        tested_urls = set()
        
        for url in urls:
            # Normalize and sanitize URL
            url = self._normalize_url(url)
            
            # For the original URL, we always add it
            if url not in tested_urls:
                all_urls_to_test.append(url)
                tested_urls.add(url)
            
            # Check if it's a file with extension
            has_extension = self._has_file_extension(url)
            
            # Add variants based on URL (with / at the end or double slash)
            self._add_url_variants(url, all_urls_to_test, tested_urls, has_extension, double_slash)
            
            # Add parent directories
            self._add_parent_directories(url, all_urls_to_test, tested_urls, double_slash)
            
        # Sort URLs by depth (deepest first)
        all_urls_to_test.sort(key=lambda x: self._get_url_depth(x), reverse=True)
        
        return all_urls_to_test
    
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
    
    def _add_url_variants(self, url: str, all_urls: List[str], tested_urls: Set[str], 
                        has_extension: bool, double_slash: bool) -> None:
        """Adds URL variants (with / at the end or double slash)"""
        # Never add slash to URLs that look like files
        if not has_extension and not url.endswith('/'):
            # Add version with / if it doesn't look like a file
            dir_url = f"{url}/"
            if dir_url not in tested_urls:
                all_urls.append(dir_url)
                tested_urls.add(dir_url)
                
                # If double_slash option is enabled, add double slash version
                if double_slash:
                    double_slash_url = f"{url}//"
                    if double_slash_url not in tested_urls:
                        all_urls.append(double_slash_url)
                        tested_urls.add(double_slash_url)
                        
        # If double_slash is enabled and URL already ends with slash
        elif double_slash and not has_extension and url.endswith('/'):
            double_slash_url = f"{url}/"  # This adds an extra slash -> url//
            if double_slash_url not in tested_urls:
                all_urls.append(double_slash_url)
                tested_urls.add(double_slash_url)
    
    def _add_parent_directories(self, url: str, all_urls: List[str], tested_urls: Set[str], double_slash: bool = False) -> None:
        """
        Adds parent directories of the URL for testing
        
        Args:
            url: Original URL
            all_urls: List of URLs to add to
            tested_urls: Set of already tested URLs
            double_slash: Flag to add double slash variants
        """
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path.strip('/')  # Remove extra slashes at beginning/end

        # If the original URL ends with a file extension, we remove it
        # before starting to build parent directories
        parts = []
        if path:
            parts = [p for p in path.split('/') if p]
            # If the last component looks like a file, remove it
            if parts and '.' in parts[-1]:
                parts.pop()

        # Build each directory level, from most specific to most general
        current_parts = parts.copy()

        while current_parts:
            # Build the current URL
            current_path = '/'.join(current_parts)
            parent_url = f"{base_url}/{current_path}/"

            # Normalize URL to avoid unintended double slashes
            parent_url = self._fix_url_protocol(parent_url)

            if parent_url not in tested_urls:
                all_urls.append(parent_url)
                tested_urls.add(parent_url)
                
                # If double_slash is enabled, add double slash version for parent directories too
                if double_slash:
                    double_slash_url = f"{parent_url}/"  # Adds an extra slash
                    if double_slash_url not in tested_urls:
                        all_urls.append(double_slash_url)
                        tested_urls.add(double_slash_url)

            # Remove the deepest component for next iteration
            current_parts.pop()

        # Add the base URL if not already added
        base_url_with_slash = f"{base_url}/"
        if base_url_with_slash not in tested_urls:
            all_urls.append(base_url_with_slash)
            tested_urls.add(base_url_with_slash)
            
            # Double slash for base URL
            if double_slash:
                double_slash_base = f"{base_url_with_slash}/"
                if double_slash_base not in tested_urls:
                    all_urls.append(double_slash_base)
                    tested_urls.add(double_slash_base)
                    
    def _fix_url_protocol(self, url: str) -> str:
        """Fixes URLs that might have damaged protocol due to replacements"""
        url = url.replace('//', '/')  # Fix unintended double slashes in path
        url = url.replace('https:/', 'https://')  # Restore correct protocol
        url = url.replace('http:/', 'http://')    # Restore correct protocol
        return url
    
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
            elif result.get('is_listing') or verbose:
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
    sub_banner = "\t    - why checking manually?"
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