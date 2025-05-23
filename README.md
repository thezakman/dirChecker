# dirChecker

```
          _ _       ___ _               _           
       __| (_)_ __ / __\ |__   ___  ___| | _____ _ __ 
      / _` | | '__/ /  | '_ \ / _ \/ __| |/ / _ \ '__|
     | (_| | | | / /___| | | |  __/ (__|   <  __/ |   
      \__,_|_|_| \____/|_| |_|\___|\___|_|\_\___|_| v2.3
                 - why checking manually?
```
----
Recursive directory checker that identifies directory listing vulnerabilities in web servers and cloud storage buckets.

## Features

- Recursive checking of all parent directories
- Automatic detection of directory listing in different formats
- AWS S3 bucket vulnerability scanning
- Multi-threading support for fast scanning
- Support for different listing formats (HTML, XML, JSON)
- Double slash bypass to circumvent protections (//)
- Silent mode for integration with other tools
- Preview of response content
- Scan statistics

## Usage

```
python dirChecker.py [-h] [-u URL] [-l LIST] [-to TIMEOUT] [-vs] [-ua USER_AGENT]
                     [-H HEADERS] [-t THREADS] [-ds] [-slt] [-v] [-p] [-s] [--debug]
                     [url]
```

## Options

### Input Options:
```
  url                   URL to check
  -u, --url-flag        URL to check (alternative to positional URL)
  -l, --list            File containing list of URLs to check
```

### Request Options:
```
  -to, --timeout TIMEOUT
                        Request timeout in seconds (default: 5)
  -vs, --verify-ssl     Verify SSL certificates
  -ua, --user-agent USER_AGENT
                        Custom User-Agent (default: dirChecker/2.2)
  -H, --headers HEADERS
                        Custom headers (format: 'Header1:Value1,Header2:Value2')
  -t, --threads THREADS
                        Number of concurrent threads (default: 10)
  -ds, --double-slash   Test URLs with double slashes for bypass
```

### Output Options:
```
  -slt, --silent        Output only vulnerable URLs
  -v, --verbose         Show detailed information for all URLs
  -p, --preview         Show response body preview
  -s, --status          Show summary statistics
  --debug               Enable debug logging
```

## Examples

Check a single URL:
```
python dirChecker.py https://example.com/path/
```

Check a list of URLs:
```
python dirChecker.py -l urls.txt
```

Check with double slashes (bypass):
```
python dirChecker.py https://example.com/path/ -ds
```

Silent mode (vulnerable URLs only):
```
python dirChecker.py https://example.com/path/ -slt
```

Detailed scanning:
```
python dirChecker.py https://example.com/path/ -v -p -s
```

Custom headers:
```
python dirChecker.py https://example.com/path/ -H "Authorization:Bearer token,X-Custom:Value"
```
