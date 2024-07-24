#!/usr/bin/env python3.11

import requests
import argparse
import random
import time
from halo import Halo
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning for SSL connections
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# version control
version = "1.6"

def banner():
    print(f'''
     _ _       ___ _               _   @thezakman
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| v{version}
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

def print_response_details(url, response, verbose, is_listing, silent, elapsed_time, preview):
    if silent and response.status_code != 200:
        return

    print('\n[Testing]:', url)
    if is_listing:
        print("[Directory Listing]: (ENABLED)")
    else:
        print("[Directory Listing]: (DISABLED)")

    print(f"[Status Code]: {response.status_code}")
    print(f"[Content-Length]: {response.headers.get('Content-Length', 'Unknown')}")
    print(f"[Content-Type]: {response.headers.get('Content-Type', 'Unknown')}")
    if verbose:
        #print(f"[Headers]: {response.headers}")
        print(f"[Elapsed Time]: {elapsed_time:.2f} seconds")
        
        if response.history:
            print("[Redirects]:")
            for resp in response.history:
                print(f"  [Status Code]: {resp.status_code} [URL]: {resp.url}")
    if preview:
            print(f"_________________________\n[Body (first 200 chars)]: {response.text[:200]}")

def check_directory_listing(url, session, verify_ssl, verbose, timeout, spinner, silent, preview):
    try:
        start_time = time.time()
        response = session.get(url, verify=verify_ssl, timeout=timeout)
        elapsed_time = time.time() - start_time
        is_listing = is_directory_listing(response)

        spinner.stop()
        print_response_details(url, response, verbose, is_listing, silent, elapsed_time, preview)
        spinner.start()

        if response.status_code == 200 and is_listing:
            return True
    except requests.RequestException as e:
        spinner.stop()
        if verbose:
            print(f"Error accessing {url}: {e}")
        spinner.start()
    return False

def main(urls, timeout, verify_ssl, user_agent, silent, verbose, custom_headers, preview):
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
        for url in urls:
            check_directory_listing(url, session, verify_ssl, verbose, timeout, spinner, silent, preview)

            parsed_url = urlparse(url)
            path_parts = parsed_url.path.strip('/').split('/')
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"

            start_index = len(path_parts) - (1 if '.' in path_parts[-1] else 0)

            for i in range(start_index, 0, -1):
                test_url = urljoin(base_url, '/'.join(path_parts[:i]) + '/')
                if test_url not in urls:
                    check_directory_listing(test_url, session, verify_ssl, verbose, timeout, spinner, silent, preview)

            if base_url not in urls:
                check_directory_listing(base_url, session, verify_ssl, verbose, timeout, spinner, silent, preview)

    finally:
        spinner.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check directories for listings.")
    parser.add_argument('url', nargs='?', help='URL to check')
    parser.add_argument('-u', '--url-flag', type=str, help='URL to check (alternative to positional URL)')
    parser.add_argument('-l', '--list', type=str, help='File containing list of URLs to check')
    parser.add_argument("-to", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-vs", "--verify-ssl", action='store_true', help="Verify SSL certificates")
    parser.add_argument("-ua", "--user-agent", default="dirChecker/1.3", help="Custom User-Agent")
    parser.add_argument("-H", "--headers", type=str, help="Custom headers to use in the request, formatted as 'Header1:Value1,Header2:Value2'")
    parser.add_argument("-S", "--silent", action='store_true', help="Suppress non-200 output")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose output")
    parser.add_argument("-p", "--preview", action='store_true', help="Show first 200 characters of the response body")

    args = parser.parse_args()
    custom_headers = parse_custom_headers(args.headers) if args.headers else {}
    urls = []

    if args.url:
        urls.append(args.url)
    elif args.url_flag:
        urls.append(args.url_flag)
    elif args.list:
        with open(args.list, 'r') as f:
            urls = [line.strip() for line in f.readlines()]
    else:
        parser.error("No URL provided. Use positional argument, -u/--url or -l/--list")

    main(urls, args.timeout, args.verify_ssl, args.user_agent, args.silent, args.verbose, custom_headers, args.preview)
