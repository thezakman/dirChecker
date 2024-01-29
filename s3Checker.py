#!/usr/bin/env python3

import requests
import argparse
from urllib.parse import urljoin, urlparse

def banner():
    title = '''
 __ _____   ___ _   @TheZakMan  _            
/ _\___ /  / __\ |__   ___  ___| | _____ _ __ 
\ \  |_ \ / /  | '_ \ / _ \/ __| |/ / _ \ '__|
_\ \___) / /___| | | |  __/ (__|   <  __/ |   
\__/____/\____/|_| |_|\___|\___|_|\_\___|_| v1  
            - why checking manually?
'''
    print(title)

def is_directory_listing(response):
    if "<ListBucketResult" in response.text:
        return True
    return False

def check_directory_listing(url, timeout, verify_ssl):
    try:
        response = requests.get(url, timeout=timeout, verify=verify_ssl)
        if response.status_code == 200 and is_directory_listing(response):
            return True
    except requests.RequestException as e:
        print(f"Erro ao acessar {url}: {e}")
    return False

def main(url, timeout, verify_ssl):
    parsed_url = urlparse(url)
    paths = parsed_url.path.split('/')[1:]  

    for i in range(len(paths), -1, -1):
        path_url = urljoin(parsed_url.scheme + '://' + parsed_url.netloc, '/'.join(paths[:i]) + '/')
        if check_directory_listing(path_url, timeout, verify_ssl):
            print(f"\n[Directory List]\n" + "-"*len(path_url) + f"\n{path_url}\n" + "-"*len(path_url)) 
        else:
            print(f"[Testing]: {path_url}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Verifica listagem de diretório em URLs.')
    parser.add_argument('-u', '--url', type=str, required=True, help='URL para verificar')
    parser.add_argument('-to','--timeout', type=int, default=10, help='Timeout para requisições HTTP (em segundos)')
    parser.add_argument('-nvs','--no-verify-ssl', action='store_false', help='Desabilita verificação de SSL')
    args = parser.parse_args()

    banner()
    main(args.url, args.timeout, args.no_verify_ssl)
