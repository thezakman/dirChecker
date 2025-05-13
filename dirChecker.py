#!/usr/bin/env python3
import requests
import argparse
import time
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from typing import List, Dict, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configure logging and suppress warnings
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger('dirchecker')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama and Rich console
init(autoreset=True)
console = Console()

# Version control
VERSION = "2.2"

class DirectoryChecker:
    """Class for checking directory listing vulnerabilities"""
    
    BINARY_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.mp4', '.zip', '.rar', 
                         '.mp3', '.avi', '.mov', '.wmv', '.flv', '.doc', '.docx', '.xls', 
                         '.xlsx', '.ppt', '.pptx', '.svg', '.webp', '.ico', '.exe'}
    
    LISTING_PATTERNS = ["<ListBucketResult", "Index of", "Parent Directory", "Directory Listing For", 
                        "<title>Index of", "Directory listing for", "[To Parent Directory]", 
                        "<h1>Index of /", "Directory: /", "alt=\"\[DIR\]\"", "alt=\"[DIR]\"", 
                        "Last modified</a>", "<h2>Directory listing of", "bucket-listing",
                        "<table class=\"listing", "<td class=\"name\">", "Object Listing", "StorageExplorer"]
    
    SKIP_CONTENT_TYPES = ['image/', 'video/', 'audio/', 'application/pdf', 
                           'application/zip', 'application/octet-stream']
    
    # Códigos de erro comuns que indicam fechamento de conexão pelo servidor
    CONNECTION_ERRORS = [
        "Connection aborted",
        "Connection reset by peer",
        "Remote end closed connection",
        "Connection refused",
        "Connection timed out"
    ]
    
    def __init__(self, timeout=5, verify_ssl=False, user_agent="dirChecker/2.2", 
                 custom_headers=None, max_threads=10, verbose=False, reduced_timeout=2):
        self.timeout = timeout
        self.reduced_timeout = reduced_timeout  # Timeout reduzido para URLs potencialmente problemáticas
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.custom_headers = custom_headers or {}
        self.max_threads = max_threads
        self.verbose = verbose
        self.session = self._create_session()
        self.connection_errors = 0  # Contador para rastrear erros de conexão
        
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            max_retries=1,
            pool_connections=self.max_threads,
            pool_maxsize=self.max_threads
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({'User-Agent': self.user_agent})
        if self.custom_headers:
            session.headers.update(self.custom_headers)
        return session

    def is_directory_listing(self, response) -> bool:
        # Skip binary content types
        content_type = response.headers.get('Content-Type', '').lower()
        if any(binary_type in content_type for binary_type in self.SKIP_CONTENT_TYPES):
            return False
        
        # Check for S3 bucket listings
        if "amazonaws.com" in response.url and response.status_code == 200:
            if "<ListBucketResult" in response.text and all(marker in response.text for marker in ["<Contents>", "<Key>"]):
                return True
        
        # Skip S3 access denied responses
        if response.status_code == 403 and "<Error>" in response.text:
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

    def check_url(self, url: str, verbose=False, preview=False) -> Dict[str, Any]:
        result = {
            'url': url,
            'is_listing': False,
            'depth': self._get_url_depth(url),
            'error': None
        }
        
        try:
            # Skip binary files unless verbose mode
            if self._is_binary_file(url) and not verbose:
                result['skipped'] = "Binary file extension"
                return result
            
            # Adjust timeout based on file type
            effective_timeout = min(self.timeout, 3) if self._is_binary_file(url) else self.timeout
            
            # Try HEAD request first to quickly filter out large files
            try:
                head_response = self._make_head_request(url, effective_timeout)
                if self._should_skip_from_headers(head_response.headers):
                    result['response'] = head_response
                    result['elapsed_time'] = 0
                    result['skipped_content'] = True
                    return result
            except:
                pass  # Continue with GET if HEAD fails
            
            # Make GET request with streaming
            start_time = time.time()
            response = self._make_get_request(url, effective_timeout)
            result['response'] = response
            result['elapsed_time'] = time.time() - start_time
            result['is_listing'] = self.is_directory_listing(response)
            
            return result
        except Exception as e:
            result['error'] = str(e)
            return result

    def _make_head_request(self, url: str, timeout: int) -> requests.Response:
        return self.session.head(url, verify=self.verify_ssl, timeout=timeout, allow_redirects=True)
    
    def _make_get_request(self, url: str, timeout: int, max_content_size: int = 20000) -> requests.Response:
        response = self.session.get(url, verify=self.verify_ssl, timeout=timeout, stream=True)
        
        # Download just enough to analyze
        content = ""
        content_size = 0
        for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
            if chunk:
                content += chunk if isinstance(chunk, str) else chunk.decode('utf-8', errors='ignore')
                content_size += len(chunk)
                if content_size >= max_content_size:
                    break
        
        response._content = content.encode('utf-8')
        return response
    
    def _should_skip_from_headers(self, headers: Dict[str, str]) -> bool:
        content_type = headers.get('Content-Type', '').lower()
        content_length = headers.get('Content-Length', '0')
        
        return (any(ct in content_type for ct in self.SKIP_CONTENT_TYPES) or 
                (content_length.isdigit() and int(content_length) > 1000000))
    
    def _is_binary_file(self, url: str) -> bool:
        parsed_url = urlparse(url)
        file_path = parsed_url.path.lower()
        return any(file_path.endswith(ext) for ext in self.BINARY_EXTENSIONS)
    
    def _get_url_depth(self, url: str) -> int:
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip('/').split('/')
        return len(path_parts)
    
    def scan_urls(self, urls: List[str], verbose=False, silent=False, preview=False, status=False, double_slash=False) -> List[Dict[str, Any]]:
        self.verbose = verbose

        # Para debug
        if verbose and double_slash and not silent:
            print(f"\n{Fore.CYAN}[DEBUG] Double slash testing is ENABLED{Style.RESET_ALL}\n")
        
        all_urls = self._prepare_urls_to_test(urls, double_slash)
        
        # Para debug
        if double_slash and verbose and not silent:
            print(f"\n{Fore.CYAN}[DEBUG] URLs to test:{Style.RESET_ALL}")
            for url in all_urls:
                if '//' in url.replace('://', ''):
                    print(f"  - {Fore.GREEN}{url}{Style.RESET_ALL}")
        
        total_urls = len(all_urls)
        
        results = self._scan_silently(all_urls) if silent else self._scan_with_progress(all_urls, verbose, preview)
        self._display_results(results, verbose, silent, preview, status, total_urls)
        
        return results
    
    def _prepare_urls_to_test(self, urls: List[str], double_slash=False) -> List[str]:
        all_urls_to_test = []
        tested_urls = set()
        
        for url in urls:
            # Verificar primeiro se o URL é válido
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            # Para a URL original, sempre adicionamos
            if url not in tested_urls:
                all_urls_to_test.append(url)
                tested_urls.add(url)
            
            # Verificar se é um arquivo com extensão
            parsed_url = urlparse(url)
            path_parts = parsed_url.path.strip('/').split('/')
            last_part = path_parts[-1] if path_parts else ""
            
            # Verifica se o último componente tem uma extensão de arquivo
            has_extension = '.' in last_part and not last_part.endswith('.')
            
            # Nunca adicione barra ao final de URLs que parecem ser arquivos
            if not has_extension and not url.endswith('/'):
                # Só adiciona a versão com / se não parece ser um arquivo
                dir_url = f"{url}/"
                if dir_url not in tested_urls:
                    all_urls_to_test.append(dir_url)
                    tested_urls.add(dir_url)
                    
                    # Se a opção double_slash estiver ativada, adiciona versão com barra dupla
                    if double_slash:
                        double_slash_url = f"{url}//"
                        if double_slash_url not in tested_urls:
                            all_urls_to_test.append(double_slash_url)
                            tested_urls.add(double_slash_url)
                            
            # Se a opção double_slash estiver ativada e URL já termina com barra
            elif double_slash and not has_extension and url.endswith('/'):
                double_slash_url = f"{url}/"  # Isso só adiciona mais uma barra -> url//
                if double_slash_url not in tested_urls:
                    all_urls_to_test.append(double_slash_url)
                    tested_urls.add(double_slash_url)
                    
                    # Adicione também para os diretórios que estão sendo testados
                    if url in all_urls_to_test and url not in tested_urls:
                        tested_urls.add(url)
            
            # Adicionar diretórios pais
            self._add_parent_directories(url, all_urls_to_test, tested_urls, double_slash)
            
        # Ordenar URLs por profundidade (mais profundo primeiro)
        all_urls_to_test.sort(key=lambda x: self._get_url_depth(x), reverse=True)
        
        return all_urls_to_test
    
    def _add_parent_directories(self, url: str, all_urls: List[str], tested_urls: Set[str], double_slash=False) -> None:
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path.strip('/')  # Removemos barras extras no início/fim

        # Se a URL original termina com uma extensão de arquivo, nós a removemos
        # antes de começar a construir diretórios pai
        parts = []
        if path:
            parts = [p for p in path.split('/') if p]
            # Se o último componente parece ser um arquivo, remove-o
            if parts and '.' in parts[-1]:
                parts.pop()

        # Construir cada nível de diretório, do mais específico para o mais geral
        current_parts = parts.copy()

        while current_parts:
            # Construir a URL atual
            current_path = '/'.join(current_parts)
            parent_url = f"{base_url}/{current_path}/"

            # Normalizar a URL para evitar barras duplas
            parent_url = parent_url.replace('//', '/')  # Corrigir barras duplas na path
            parent_url = parent_url.replace('https:/', 'https://')  # Restaurar protocolo correto
            parent_url = parent_url.replace('http:/', 'http://')    # Restaurar protocolo correto

            if parent_url not in tested_urls:
                all_urls.append(parent_url)
                tested_urls.add(parent_url)
                
                # Se double_slash está ativado, adicionar versão com barra dupla para os diretórios pai também
                if double_slash:
                    double_slash_url = f"{parent_url}/"  # Adiciona uma barra extra
                    if double_slash_url not in tested_urls:
                        all_urls.append(double_slash_url)
                        tested_urls.add(double_slash_url)

            # Remover o componente mais profundo para a próxima iteração
            current_parts.pop()

        # Adicionar a URL base se ainda não foi adicionada
        base_url = f"{base_url}/"
        if base_url not in tested_urls:
            all_urls.append(base_url)
            tested_urls.add(base_url)
            
            # Se double_slash está ativado, adicionar versão com barra dupla para a URL base
            if double_slash:
                double_slash_base = f"{base_url}/"
                if double_slash_base not in tested_urls:
                    all_urls.append(double_slash_base)
                    tested_urls.add(double_slash_base)
    
    def _scan_with_progress(self, urls: List[str], verbose: bool, preview: bool) -> List[Dict[str, Any]]:
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
                        results.append({'url': url, 'error': str(e), 'depth': self._get_url_depth(url)})
            
        return results
    
    def _scan_silently(self, urls: List[str]) -> List[Dict[str, Any]]:
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {executor.submit(self.check_url, url, False, False): url for url in urls}
            
            for future in as_completed(future_to_url):
                try:
                    results.append(future.result())
                except Exception as e:
                    logger.debug(f"Error scanning {future_to_url[future]}: {str(e)}")
        
        return results
    
    def _display_results(self, results: List[Dict[str, Any]], verbose: bool, silent: bool, 
                     preview: bool, status: bool, total_urls: int) -> None:
        if silent:
            # Print only vulnerable URLs in silent mode
            for result in results:
                if result.get('is_listing'):
                    print(result['url'])
            return
        
        # Encontrar a URL original (primeiro argumento)
        original_url = None
        for result in results:
            # A URL original é normalmente a mais profunda e a primeira na lista original
            if not original_url or self._get_url_depth(result['url']) > self._get_url_depth(original_url):
                original_url = result['url']
        
        # Se não encontrou a URL original, usa uma string vazia
        if not original_url:
            original_url = ""
        
        # Classificar os resultados em categorias:
        # 1. URL original
        # 2. URLs intermediárias (diretórios pais da URL original, ordenados do mais profundo para o menos profundo)
        # 3. URL base (raiz)
        
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
        
        # Ordenar resultados intermediários por profundidade (do mais profundo para o menos profundo)
        intermediate_results.sort(key=lambda x: self._get_url_depth(x['url']), reverse=True)
        
        # Mostrar resultados na ordem: original -> intermediários -> base
        ordered_results = []
        if original_result:
            ordered_results.append(original_result)
        ordered_results.extend(intermediate_results)
        if base_result:
            ordered_results.append(base_result)
        
        # Exibir os resultados ordenados
        for result in ordered_results:
            if 'error' in result and result['error'] and verbose:
                self._print_error_result(result)
            elif result.get('is_listing') or verbose:
                self._print_url_result(result, verbose, preview)
        
        # Show summary if requested
        if status:
            vulnerable_count = sum(1 for r in results if r.get('is_listing'))
            self._print_summary(total_urls, vulnerable_count)
        
        console.print("[bold green]☑️ SCAN COMPLETE![/bold green]")
    
    def _print_error_result(self, result: Dict[str, Any]) -> None:
        print(f"{Fore.CYAN}[Testing]{Style.RESET_ALL}: {Fore.YELLOW}{result['url']}{Style.RESET_ALL}")
        print(f"{Fore.RED}❌ Error: {result['error']}{Style.RESET_ALL}\n")
    
    def _print_url_result(self, result: Dict[str, Any], verbose: bool, preview: bool) -> None:
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
        if status_code == 200:
            return {'color': Fore.GREEN, 'emoji': "✅"}
        elif status_code in [301, 302, 307, 308]:
            return {'color': Fore.YELLOW, 'emoji': "⚠️"}
        else:
            return {'color': Fore.RED, 'emoji': "❌"}
    
    def _get_listing_display(self, is_listing: bool) -> Dict[str, str]:
        if is_listing:
            return {'emoji': "🚨", 'status': f"{Fore.RED}(VULNERABLE){Style.RESET_ALL}"}
        else:
            return {'emoji': "🔒", 'status': f"{Fore.GREEN}(DISABLED){Style.RESET_ALL}"}
    
    def _print_verbose_details(self, result: Dict[str, Any]) -> None:
        """Print additional details in verbose mode"""
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
    

    def _print_preview(self, response) -> None:
        print(f"👀 {Fore.CYAN}[Body Preview]{Style.RESET_ALL}:")
        preview_text = response.text[:200].replace('\n', ' ').strip()
        print(f"{Fore.WHITE}{preview_text}{Style.RESET_ALL}")
    
    def _print_summary(self, total_urls: int, vulnerable_count: int) -> None:
        console.print(f"[bold cyan]📊 [Summary]:[/bold cyan]")
        console.print(f"   [white][Directories]:[/white] [yellow]{total_urls}[/yellow]")
        console.print(f"   [white][Vulnerable]:[/white] [bold red]{vulnerable_count}[/bold red]\n")


def print_banner():
    banner = fr'''
     _ _       ___ _               _   {Fore.LIGHTGREEN_EX}@thezakman{Fore.GREEN}
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| {Fore.LIGHTGREEN_EX}v{VERSION}'''
    sub_banner = "\t    - why checking manually?"
    print(f"{Fore.GREEN}{banner}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{sub_banner}{Style.RESET_ALL}\n")


def parse_custom_headers(header_string) -> Dict[str, str]:
    headers = {}
    if header_string:
        for pair in header_string.split(','):
            if ':' in pair:
                key, value = pair.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers


def parse_arguments():
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
    request_group.add_argument("-ua", "--user-agent", default="dirChecker/2.2", help="Custom User-Agent")
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


if __name__ == "__main__":
    main()