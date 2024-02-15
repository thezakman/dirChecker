#!/usr/bin/env python3

import requests
import argparse
from urllib.parse import urljoin, urlparse, urlunparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suprimir InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def banner():
    title = '''
     _ _       ___ _               _   @thezakman          
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __ 
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |   
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| v1.2  
            - why checking manually?
'''
    print(title)

def is_directory_listing(response):
    if "<ListBucketResult" in response.text or "Index of" in response.text:
        return True
    return False

def print_response_details(url, response, verbose, is_listing):
    if verbose or is_listing:
        print(f"[Testing]: {url}")
        if verbose:
            print(f"[Status Code]: {response.status_code}")
            print(f"[Content-Length]: {response.headers.get('Content-Length', 'Unknown')}")
            print(f"[Content-Type]: {response.headers.get('Content-Type', 'Unknown')}")
        if is_listing:
            print("[Directory Listing]: Yes")
        else:
            if verbose:
                print("[Directory Listing]: No")
        print("\n")

def check_directory_listing(url, session, verify_ssl, verbose):
    try:
        response = session.get(url, verify=verify_ssl)
        is_listing = is_directory_listing(response)
        # Sempre imprime se encontrar uma listagem de diretórios, independentemente do modo verboso
        print_response_details(url, response, verbose, is_listing)  
        if response.status_code == 200 and is_listing:
            return True
    except requests.RequestException as e:
        if verbose:
            print(f"Error accessing {url}: {e}")
    return False

def main(url, timeout, verify_ssl, user_agent, silent, verbose):
    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})

    if not silent:
        banner()

    parsed_url = urlparse(url)
    base_url = urlunparse(parsed_url._replace(query=""))
    
    check_directory_listing(url, session, verify_ssl, verbose)

    if '.' in parsed_url.path.split('/')[-1]:
        check_directory_listing(base_url, session, verify_ssl, verbose)
    
    path_parts = parsed_url.path.strip('/').split('/')
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for i in range(len(path_parts), -1, -1):
        test_url = urljoin(base_url, '/'.join(path_parts[:i]) + '/')
        if test_url != url:  # Evita testar a mesma URL duas vezes
            check_directory_listing(test_url, session, verify_ssl, verbose)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check directories for listings.")
    parser.add_argument('-u', '--url', type=str, required=True, help='URL to check')
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--verify-ssl", action='store_true', help="Verify SSL certificates")
    parser.add_argument("--user-agent", default="dirChecker/1.2", help="Custom User-Agent")
    parser.add_argument("--silent", action='store_true', help="Suppress banner and other output")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose output")
    
    args = parser.parse_args()
    main(args.url, args.timeout, args.verify_ssl, args.user_agent, args.silent, args.verbose)
