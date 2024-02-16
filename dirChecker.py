#!/usr/bin/env python3

import requests
import argparse
import random
from halo import Halo
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning for SSL connections
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def banner():
    print('''
     _ _       ___ _               _   @thezakman
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| v1.3
            - why checking manually?
''')

spinner_styles = [
    'dots', 'dots2', 'dots3', 'dots4', 'dots5', 'dots6', 'dots7', 'dots8', 'dots9', 'dots10',
    'dots11', 'dots12', 'line', 'line2', 'pipe', 'simpleDots', 'simpleDotsScrolling', 'star',
    'star2', 'flip', 'hamburger', 'growVertical', 'growHorizontal', 'balloon', 'balloon2',
    'noise', 'bounce', 'boxBounce', 'boxBounce2', 'triangle', 'arc', 'circle', 'squareCorners',
    'circleQuarters', 'circleHalves', 'squish', 'toggle', 'toggle2', 'toggle3', 'toggle4',
    'toggle5', 'toggle6', 'toggle7', 'toggle8', 'toggle9', 'toggle10', 'toggle11'
]

def parse_custom_headers(header_string):
    headers = {}
    if header_string:
        header_pairs = header_string.split(',')
        for pair in header_pairs:
            key, value = pair.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers

def is_directory_listing(response):
    patterns = [
        "<ListBucketResult",
        "Index of",
        "Parent Directory",
        "Directory Listing For",
        "<title>Index of"
    ]
    
    for pattern in patterns:
        if pattern in response.text:
            return True
    if response.text.count('<a href=') > 5:
        return True

    return False

def print_response_details(url, response, verbose, is_listing):
    if verbose or is_listing:
        print('\n[Testing]:', url)
        if verbose:
            print(f"[Status Code]: {response.status_code}")
            if custom_headers:
                print(f"[Headers]: {custom_headers}")
            print(f"[Content-Length]: {response.headers.get('Content-Length', 'Unknown')}")
            print(f"[Content-Type]: {response.headers.get('Content-Type', 'Unknown')}")
        if is_listing:
            print("[Directory Listing]: Yes")
        else:
            if verbose:
                print("[Directory Listing]: No")

def check_directory_listing(url, session, verify_ssl, verbose, timeout, spinner):
    """
    Adiciona um parâmetro spinner para controlar seu estado de dentro desta função.
    """
    try:
        response = session.get(url, verify=verify_ssl, timeout=timeout)
        is_listing = is_directory_listing(response)

        spinner.stop()  # Para o spinner antes de imprimir os detalhes
        print_response_details(url, response, verbose, is_listing)

        spinner.start()  # Reinicia o spinner após imprimir os detalhes, se necessário

        if response.status_code == 200 and is_listing:
            return True
    except requests.RequestException as e:
        spinner.stop()  # Também para o spinner em caso de exceção antes de imprimir
        if verbose:
            print(f"Error accessing {url}: {e}")
        spinner.start()
    return False

def main(url, timeout, verify_ssl, user_agent, silent, verbose, custom_headers):
    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})
    if custom_headers:
        session.headers.update(custom_headers)

    if not silent:
        banner()

    selected_spinner = random.choice(spinner_styles)
    spinner = Halo(text='[>] Running...', spinner=selected_spinner)
    spinner.start()

    try:
        # Passa o spinner como argumento para a função check_directory_listing
        check_directory_listing(url, session, verify_ssl, verbose, timeout, spinner)

        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip('/').split('/')
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"

        start_index = len(path_parts) - (1 if '.' in path_parts[-1] else 0)

        for i in range(start_index, 0, -1):
            test_url = urljoin(base_url, '/'.join(path_parts[:i]) + '/')
            if test_url not in [url]:
                check_directory_listing(test_url, session, verify_ssl, verbose, timeout, spinner)

        if base_url not in [url]:
            check_directory_listing(base_url, session, verify_ssl, verbose, timeout, spinner)

    finally:
        spinner.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check directories for listings.")
    parser.add_argument('-u', '--url', type=str, required=True, help='URL to check')
    parser.add_argument("-to","--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-vs","--verify-ssl", action='store_true', help="Verify SSL certificates")
    parser.add_argument("-ua","--user-agent", default="dirChecker/1.3", help="Custom User-Agent")
    parser.add_argument("-H","--headers", type=str, help="Custom headers to use in the request, formatted as 'Header1:Value1,Header2:Value2'")
    parser.add_argument("-S","--silent", action='store_true', help="Suppress banner and other output")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose output")

    args = parser.parse_args()
    custom_headers = parse_custom_headers(args.headers) if args.headers else {}
    main(args.url, args.timeout, args.verify_ssl, args.user_agent, args.silent, args.verbose, custom_headers)
