#!/usr/bin/env python3
"""
Advanced Parameter Discovery Tool - XSSniper Module
Professional Security Testing Framework
Developed by H4mzaX

Open Source Tool - Free for everyone to use
"""

import hashlib
import hmac
import time
import base64
import os
import sys
import platform
import uuid
import asyncio
import aiohttp
import json
import re
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import warnings
warnings.filterwarnings("ignore")

# Initialize colorama
init(autoreset=True)

# License system removed - Open source tool for everyone

class AdvancedParamDiscovery:
    """Advanced parameter discovery with modern techniques"""
    
    def __init__(self, target_url, **kwargs):
        self.target_url = target_url
        self.timeout = kwargs.get('timeout', 15)
        self.max_concurrent = kwargs.get('threads', 20)
        self.delay = kwargs.get('delay', 0)
        self.verbose = kwargs.get('verbose', False)
        self.session = None
        self.discovered_params = set()
        
        # Headers
        self.headers = {
            'User-Agent': kwargs.get('user_agent') or 
                         'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        # Modern parameter wordlists
        self.parameter_wordlists = self._load_parameter_wordlists()

    def _load_parameter_wordlists(self):
        """Load comprehensive parameter wordlists"""
        return {
            # Common web parameters
            'common': [
                'id', 'page', 'search', 'q', 'query', 'name', 'user', 'email',
                'password', 'pass', 'pwd', 'username', 'login', 'auth', 'token',
                'key', 'api_key', 'access_token', 'session', 'sessid', 'sid',
                'cat', 'category', 'type', 'action', 'method', 'function', 'cmd',
                'view', 'show', 'display', 'render', 'output', 'format', 'mode',
                'file', 'filename', 'path', 'dir', 'folder', 'location', 'url',
                'link', 'href', 'src', 'img', 'image', 'pic', 'photo', 'avatar'
            ],
            
            # API parameters
            'api': [
                'callback', 'jsonp', 'format', 'output', 'response_type',
                'api_key', 'access_token', 'oauth_token', 'client_id', 'client_secret',
                'grant_type', 'scope', 'state', 'code', 'redirect_uri',
                'version', 'v', 'api_version', 'endpoint', 'method', 'action'
            ],
            
            # Navigation & filtering
            'navigation': [
                'next', 'prev', 'previous', 'page', 'offset', 'limit', 'per_page',
                'size', 'count', 'start', 'end', 'from', 'to', 'begin', 'finish',
                'filter', 'sort', 'order', 'orderby', 'sortby', 'direction',
                'asc', 'desc', 'ascending', 'descending', 'reverse'
            ],
            
            # Modern framework parameters
            'framework': [
                # React/Next.js
                'props', 'state', 'ref', 'key', 'children', 'component',
                # Vue.js
                'data', 'methods', 'computed', 'watch', 'model',
                # Angular
                'input', 'output', 'model', 'binding', 'directive',
                # Express.js
                'req', 'res', 'body', 'params', 'query', 'headers'
            ],
            
            # Security-related parameters
            'security': [
                'csrf_token', 'xsrf_token', 'authenticity_token', 'nonce',
                'hash', 'signature', 'hmac', 'checksum', 'verify', 'validate',
                'captcha', 'recaptcha', 'challenge', 'response', 'solution'
            ],
            
            # Database & content parameters
            'database': [
                'table', 'column', 'field', 'record', 'row', 'data', 'value',
                'content', 'text', 'description', 'title', 'subject', 'message',
                'comment', 'note', 'memo', 'tag', 'label', 'meta'
            ],
            
            # File & upload parameters
            'file_upload': [
                'upload', 'file_upload', 'attachment', 'document', 'media',
                'binary', 'data', 'content', 'payload', 'blob', 'stream'
            ],
            
            # Time & date parameters
            'temporal': [
                'date', 'time', 'datetime', 'timestamp', 'created', 'updated',
                'modified', 'year', 'month', 'day', 'hour', 'minute', 'second',
                'timezone', 'tz', 'locale', 'lang', 'language'
            ]
        }

    async def init_session(self):
        """Initialize async HTTP session"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=timeout,
            connector=aiohttp.TCPConnector(limit=100, limit_per_host=30)
        )

    async def close_session(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()

    def log(self, message, level="INFO"):
        """Enhanced logging function"""
        timestamp = time.strftime("%H:%M:%S")
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "FOUND": Fore.GREEN
        }
        
        color = colors.get(level, Fore.WHITE)
        if self.verbose or level in ["SUCCESS", "FOUND", "ERROR"]:
            print(f"{color}[{timestamp}] [{level}] {message}")

    async def test_parameter_reflection(self, url, param_name, test_value="test123"):
        """Test if parameter value is reflected in response"""
        try:
            test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={test_value}"
            
            async with self.session.get(test_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check for various reflection indicators
                    reflection_indicators = [
                        test_value in content,
                        param_name in content,
                        f'name="{param_name}"' in content,
                        f'id="{param_name}"' in content,
                        f'class="{param_name}"' in content,
                        f'data-{param_name}' in content
                    ]
                    
                    if any(reflection_indicators):
                        return True, content, response.status
                    
                    # Check for error messages that might reveal parameter processing
                    error_patterns = [
                        f"invalid {param_name}",
                        f"missing {param_name}",
                        f"required {param_name}",
                        f"{param_name} not found",
                        f"undefined {param_name}",
                        f"unknown {param_name}"
                    ]
                    
                    content_lower = content.lower()
                    for pattern in error_patterns:
                        if pattern.lower() in content_lower:
                            return True, content, response.status
            
            return False, "", 0
            
        except Exception as e:
            self.log(f"Error testing parameter {param_name}: {str(e)}", "ERROR")
            return False, "", 0

    async def discover_from_wordlist(self, url, wordlist_name):
        """Discover parameters using wordlist"""
        self.log(f"Testing {wordlist_name} parameters...", "INFO")
        
        if wordlist_name not in self.parameter_wordlists:
            return
        
        wordlist = self.parameter_wordlists[wordlist_name]
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def test_param(param):
            async with semaphore:
                is_valid, content, status = await self.test_parameter_reflection(url, param)
                
                if is_valid:
                    self.discovered_params.add(param)
                    self.log(f"Found parameter: {param} (wordlist: {wordlist_name})", "FOUND")
                
                if self.delay:
                    await asyncio.sleep(self.delay)
        
        # Test all parameters concurrently
        tasks = [test_param(param) for param in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def discover_from_html_analysis(self, url):
        """Discover parameters from HTML form analysis"""
        self.log("Analyzing HTML forms and JavaScript...", "INFO")
        
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return
                
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract form parameters
                forms = soup.find_all('form')
                for form in forms:
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for input_tag in inputs:
                        name = input_tag.get('name')
                        if name and name not in self.discovered_params:
                            self.discovered_params.add(name)
                            self.log(f"Found form parameter: {name}", "FOUND")
                
                # Extract from JavaScript
                js_patterns = [
                    r'\.get\(["\'](\w+)["\']',
                    r'\.post\(["\'](\w+)["\']',
                    r'getParameter\(["\'](\w+)["\']',
                    r'URLSearchParams.*get\(["\'](\w+)["\']',
                    r'location\.search.*[?&](\w+)=',
                    r'window\.location.*[?&](\w+)=',
                    r'fetch\([^)]*[?&](\w+)=',
                    r'ajax\([^)]*[?&](\w+)=',
                    r'var\s+(\w+)\s*=.*getParameter',
                    r'let\s+(\w+)\s*=.*getParameter',
                    r'const\s+(\w+)\s*=.*getParameter'
                ]
                
                for pattern in js_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        param = match.group(1)
                        if param and len(param) > 1 and param not in self.discovered_params:
                            self.discovered_params.add(param)
                            self.log(f"Found JS parameter: {param}", "FOUND")
                
                # Extract from data attributes
                data_attrs = soup.find_all(attrs={"data-param": True})
                for element in data_attrs:
                    param = element.get('data-param')
                    if param and param not in self.discovered_params:
                        self.discovered_params.add(param)
                        self.log(f"Found data attribute parameter: {param}", "FOUND")
                
        except Exception as e:
            self.log(f"Error analyzing HTML: {str(e)}", "ERROR")

    async def discover_from_api_endpoints(self, url):
        """Discover parameters from common API endpoints"""
        self.log("Checking common API endpoints...", "INFO")
        
        api_endpoints = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger.json', '/openapi.json', '/api-docs',
            '/docs', '/documentation'
        ]
        
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        for endpoint in api_endpoints:
            try:
                api_url = urljoin(base_url, endpoint)
                async with self.session.get(api_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Look for parameter definitions in API docs
                        param_patterns = [
                            r'"(\w+)"\s*:\s*{\s*"type"',
                            r'"parameters".*?"(\w+)"',
                            r'"query".*?"(\w+)"',
                            r'"path".*?"(\w+)"',
                            r'@RequestParam.*?"(\w+)"',
                            r'@PathVariable.*?"(\w+)"'
                        ]
                        
                        for pattern in param_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                param = match.group(1)
                                if param and len(param) > 1 and param not in self.discovered_params:
                                    self.discovered_params.add(param)
                                    self.log(f"Found API parameter: {param} (from {endpoint})", "FOUND")
                
                if self.delay:
                    await asyncio.sleep(self.delay * 0.5)
                    
            except:
                continue

    async def discover_from_error_analysis(self, url):
        """Discover parameters by analyzing error responses"""
        self.log("Analyzing error responses for parameter hints...", "INFO")
        
        # Common parameter values that might trigger informative errors
        error_probes = [
            'invalid_value_12345',
            '../../../etc/passwd',
            '<script>alert(1)</script>',
            '${7*7}',
            'null',
            'undefined',
            ''
        ]
        
        for probe in error_probes:
            try:
                # Test with a likely parameter name
                test_url = f"{url}{'&' if '?' in url else '?'}test={quote(probe)}"
                
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    
                    # Look for parameter names in error messages
                    error_patterns = [
                        r'parameter ["\'](\w+)["\'] is required',
                        r'missing required parameter ["\'](\w+)["\']',
                        r'invalid parameter ["\'](\w+)["\']',
                        r'unknown parameter ["\'](\w+)["\']',
                        r'parameter ["\'](\w+)["\'] not found',
                        r'(\w+) parameter is missing',
                        r'(\w+) is required',
                        r'expected parameter (\w+)',
                        r'(\w+) must be provided'
                    ]
                    
                    for pattern in error_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            param = match.group(1)
                            if param and len(param) > 1 and param not in self.discovered_params:
                                self.discovered_params.add(param)
                                self.log(f"Found parameter from error: {param}", "FOUND")
                
                if self.delay:
                    await asyncio.sleep(self.delay * 0.2)
                    
            except:
                continue

    async def discover_from_headers_analysis(self, url):
        """Discover parameters from HTTP headers"""
        self.log("Analyzing HTTP headers for parameter hints...", "INFO")
        
        try:
            async with self.session.get(url) as response:
                headers = response.headers
                
                # Look for parameter hints in various headers
                header_patterns = [
                    ('Link', r'[?&](\w+)='),
                    ('Location', r'[?&](\w+)='),
                    ('Refresh', r'[?&](\w+)='),
                    ('X-*', r'(\w+)'),
                    ('Access-Control-Allow-Headers', r'(\w+)'),
                    ('Content-Security-Policy', r'(\w+)'),
                ]
                
                for header_name, pattern in header_patterns:
                    for header, value in headers.items():
                        if header_name == 'X-*' and header.lower().startswith('x-'):
                            # Extract custom header names as potential parameters
                            param = header[2:].replace('-', '_').lower()
                            if param and param not in self.discovered_params:
                                self.discovered_params.add(param)
                                self.log(f"Found header-based parameter: {param}", "FOUND")
                        else:
                            matches = re.finditer(pattern, value, re.IGNORECASE)
                            for match in matches:
                                param = match.group(1)
                                if param and len(param) > 1 and param not in self.discovered_params:
                                    self.discovered_params.add(param)
                                    self.log(f"Found header parameter: {param} (from {header})", "FOUND")
                
        except Exception as e:
            self.log(f"Error analyzing headers: {str(e)}", "ERROR")

    async def run_discovery(self):
        """Run comprehensive parameter discovery"""
        self.log(f"Starting parameter discovery for: {self.target_url}", "INFO")
        
        await self.init_session()
        
        try:
            # Run all discovery methods
            await asyncio.gather(
                self.discover_from_html_analysis(self.target_url),
                self.discover_from_api_endpoints(self.target_url),
                self.discover_from_headers_analysis(self.target_url),
                self.discover_from_error_analysis(self.target_url),
                return_exceptions=True
            )
            
            # Run wordlist-based discovery
            for wordlist_name in self.parameter_wordlists.keys():
                await self.discover_from_wordlist(self.target_url, wordlist_name)
            
            self.generate_report()
            
        finally:
            await self.close_session()

    def generate_report(self):
        """Generate discovery report"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}PARAMETER DISCOVERY REPORT")
        print(f"{Fore.CYAN}{'='*70}")
        
        if not self.discovered_params:
            print(f"{Fore.YELLOW}No parameters discovered.")
        else:
            print(f"{Fore.GREEN}Discovered {len(self.discovered_params)} potential parameters:")
            print()
            
            # Sort parameters for better readability
            sorted_params = sorted(self.discovered_params)
            
            for i, param in enumerate(sorted_params, 1):
                print(f"{Fore.WHITE}{i:2d}. {param}")
            
            # Save to file
            output_file = f'discovered_params_{int(time.time())}.txt'
            with open(output_file, 'w') as f:
                for param in sorted_params:
                    f.write(f"{param}\n")
            
            print(f"\n{Fore.CYAN}Parameters saved to: {output_file}")
        
        print(f"{Fore.CYAN}{'='*70}")

def show_banner():
    """Display banner"""
    banner = f"""
{Fore.CYAN}    ╔══════════════════════════════════════════════════════╗
{Fore.CYAN}    ║      🔍 Advanced Parameter Discovery Tool            ║
{Fore.CYAN}    ║              XSSniper Security Module                ║
{Fore.CYAN}    ║                Enhanced for 2025                     ║
{Fore.CYAN}    ╚══════════════════════════════════════════════════════╝
{Fore.MAGENTA}                     Developed by H4mzaX
{Style.RESET_ALL}
"""
    print(banner)

async def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description='Advanced Parameter Discovery Tool')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of concurrent threads (default: 20)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--license', help='License key for operation')
    
    args = parser.parse_args()
    
    try:
        discoverer = AdvancedParamDiscovery(
            target_url=args.url,
            user_agent=args.user_agent,
            timeout=args.timeout,
            threads=args.threads,
            delay=args.delay,
            verbose=args.verbose
        )
        
        await discoverer.run_discovery()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Discovery interrupted by user.")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        show_banner()
        print(f"{Fore.YELLOW}Use --help for usage information")
        sys.exit(0)
    
    asyncio.run(main())
