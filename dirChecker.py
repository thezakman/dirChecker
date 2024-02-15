#!/usr/bin/env python3

import requests
import argparse
import random
from halo import Halo
from urllib.parse import urljoin, urlparse, urlunparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suprimir InsecureRequestWarning
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

def is_directory_listing(response):
    # Lista de padrões para verificar na resposta
    patterns = [
        "<ListBucketResult",      # S3 Buckets
        "Index of",               # Apache
        "Parent Directory",       # IIS
        "Directory Listing For",  # Vários servidores
        "<title>Index of"         # Alguns servidores configurados para mostrar o título "Index of" na listagem
    ]
    
    # Verifica cada padrão na resposta
    for pattern in patterns:
        if pattern in response.text:
            return True
    
    # Verificar por uma quantidade significativa de links, sugerindo uma listagem de diretório (NGINX e outros)
    # Isso é um pouco mais genérico e pode gerar falsos positivos, então use com cautela
    if response.text.count('<a href=') > 5:  # Exemplo de threshold, ajuste conforme necessário
        return True

    return False


def print_response_details(url, response, verbose, is_listing):
    if verbose or is_listing:
        print('\n')
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
       

def check_directory_listing(url, session, verify_ssl, verbose, timeout):
    try:
        # Adiciona o timeout à chamada get
        response = session.get(url, verify=verify_ssl, timeout=timeout)
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

    selected_spinner = random.choice(spinner_styles)
    spinner = Halo(text='[>] Running...', spinner=selected_spinner)
    
    if not verbose:
        spinner.start()

    try:
        # Verifica a URL fornecida diretamente, sem alterações
        check_directory_listing(url, session, verify_ssl, verbose, timeout)

        # Extrai os componentes da URL para verificar diretórios superiores
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip('/').split('/')
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"

        # Se a URL aponta para um arquivo (tem um ponto no último segmento), ajusta o índice para não incluir o arquivo na verificação dos diretórios superiores
        start_index = len(path_parts) - (1 if '.' in path_parts[-1] else 0)

        for i in range(start_index, 0, -1):
            # Constrói a URL de teste para cada diretório superior
            test_url = urljoin(base_url, '/'.join(path_parts[:i]) + '/')
            if test_url not in [url]:  # Evita testar a mesma URL fornecida
                check_directory_listing(test_url, session, verify_ssl, verbose, timeout)

        # Adicionalmente, verifica a raiz do domínio se ainda não foi feito
        if base_url not in [url]:
            check_directory_listing(base_url, session, verify_ssl, verbose, timeout)

    finally:
        if not verbose:
            spinner.stop()




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
