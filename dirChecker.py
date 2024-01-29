#!/usr/bin/env python3

import requests
import argparse
from urllib.parse import urljoin, urlparse

def banner():
    title = '''
     _ _       ___ _               _   @thezakman          
  __| (_)_ __ / __\ |__   ___  ___| | _____ _ __ 
 / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
| (_| | | | / /___| | | |  __/ (__|   <  __/ |   
 \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| v1  
            - why checking manually?
'''
    print(title)

def is_directory_listing(response):
    if "<ListBucketResult" in response.text or "Index of" in response.text:
        return True
    return False

def check_directory_listing(url, session, verify_ssl):
    try:
        response = session.get(url, verify=verify_ssl)
        if response.status_code == 200 and is_directory_listing(response):
            return True
    except requests.RequestException as e:
        print(f"Erro ao acessar {url}: {e}")
    return False

def main(url, timeout, verify_ssl, user_agent, silent):
    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})

    parsed_url = urlparse(url)
    paths = parsed_url.path.split('/')[1:]  

    for i in range(len(paths), -1, -1):
        path_url = urljoin(parsed_url.scheme + '://' + parsed_url.netloc, '/'.join(paths[:i]) + '/')
        if not silent:
            print(f"[Testing]: {path_url}")
        if check_directory_listing(path_url, session, verify_ssl):
            print(f"\n[Directory List]\n" + "-"*len(path_url) + f"\n{path_url}\n" + "-"*len(path_url))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Verifica listagem de diretório em URLs.')
    parser.add_argument('-u', '--url', type=str, required=True, help='URL para verificar')
    parser.add_argument('-to', '--timeout', type=int, default=10, help='Timeout para requisições HTTP (em segundos)')
    parser.add_argument('-nvs', '--no-verify-ssl', action='store_false', help='Desabilita verificação de SSL')
    parser.add_argument('-ua', '--user-agent', type=str, default='YourDefaultUserAgent', help='Define o User-Agent para as requisições HTTP')
    parser.add_argument('-s', '--silent', action='store_true', help='Executa em modo silencioso')
    args = parser.parse_args()

    banner()
    main(args.url, args.timeout, args.no_verify_ssl, args.user_agent, args.silent)
