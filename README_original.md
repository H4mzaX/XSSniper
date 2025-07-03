# XSS Tool by H4mzaX

An advanced XSS vulnerability scanner with automatic WAF detection and browser verification capabilities.

## 🚀 Features

- **ASCII Art Banner**: Beautiful figlet and lolcat powered banner
- **Auto WAF Detection**: Automatically detects and adapts to 9+ popular WAFs
- **WAF Bypass Payloads**: Specialized payloads for each detected WAF
- **Browser Verification**: Uses Selenium to verify XSS execution in real browsers
- **Comprehensive Payloads**: 80+ XSS payloads including modern attack vectors
- **Multiple Encodings**: Tests URL, Double URL, HTML, and Unicode encodings
- **False Positive Reduction**: Advanced reflection detection to minimize false positives
- **Professional Reporting**: Saves only vulnerable results with detailed information
- **Multi-threading**: Fast scanning with configurable thread count
- **Crawling Support**: Automatic discovery of additional URLs to test

## 🛠️ Installation

```bash
# Clone or download the tool
cd XssTool

# Install requirements
pip3 install -r requirements.txt

# Ensure figlet and lolcat are installed (for macOS)
brew install figlet lolcat
```

## 💻 Usage

### Basic Usage

```bash
# Scan a single URL
python3 xss_scanner.py -u "https://example.com/search?q=test" -v

# Scan with browser verification disabled (faster)
python3 xss_scanner.py -u "https://example.com" --no-browser-verify

# Scan multiple URLs from file
python3 xss_scanner.py -l urls.txt -v

# Scan with crawling for additional URLs
python3 xss_scanner.py -u "https://example.com" -c --max-depth 3
```

### Advanced Options

```bash
# Custom threading and delays
python3 xss_scanner.py -u "https://example.com" -t 20 -d 0.5

# Custom output file
python3 xss_scanner.py -u "https://example.com" -o my_scan_results.json

# Custom User-Agent
python3 xss_scanner.py -u "https://example.com" --user-agent "Custom Agent 1.0"
```

## 🔍 WAF Detection & Bypass

The tool automatically detects these WAFs and applies specialized bypass payloads:

- **Cloudflare**: SVG onload, iframe srcdoc, math element attacks
- **Akamai**: Details ontoggle, marquee onstart, object data attacks  
- **ModSecurity**: Base64 eval, Function constructor, entity encoding
- **AWS WAF**: Template literals, array methods, constructor chains
- **Imperva (Incapsula)**: String methods, regex sources, template literals
- **F5 BIG-IP**: Detected via headers and response patterns
- **Sucuri**: Identified through security headers
- **Barracuda**: Recognition through server signatures
- **Fortinet**: Detection via response characteristics

## 📊 Output

The tool generates comprehensive JSON reports containing:

```json
{
  "scan_info": {
    "target_url": "https://example.com",
    "timestamp": "2024-01-01 12:00:00",
    "total_vulnerabilities": 2,
    "waf_details": "Cloudflare",
    "scan_settings": {
      "threads": 10,
      "delay": 0,
      "total_payloads_tested": 84
    }
  },
  "vulnerabilities": [
    {
      "type": "Reflected XSS",
      "url": "https://example.com/search?q=<script>alert(1)</script>",
      "parameter": "q",
      "payload": "<script>alert(\"XSS\")</script>",
      "encoded_payload": "%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E",
      "encoding": "url",
      "method": "GET",
      "verified_in_browser": true
    }
  ]
}
```

## 🎯 Key Improvements

1. **Browser Verification**: Eliminates false positives by actually executing payloads in a real browser
2. **WAF-Aware Scanning**: Automatically adapts payload selection based on detected WAF
3. **Enhanced Payload Library**: 80+ carefully crafted payloads for maximum coverage
4. **Smart Encoding**: Tests multiple encoding schemes automatically
5. **Professional Output**: Clean, organized results with only genuine vulnerabilities
6. **Performance Optimized**: Multi-threaded scanning with intelligent parameter discovery

## ⚙️ Configuration

### Browser Verification
- Enabled by default for maximum accuracy
- Use `--no-browser-verify` to disable for faster scanning
- Requires Chrome/Chromium to be installed

### Threading
- Default: 10 threads
- Adjust with `-t` flag based on target capacity
- Higher values = faster scanning but more resource usage

### Delay
- Default: No delay between requests
- Use `-d` flag to add delays for rate-limited targets
- Recommended: 0.5-1.0 seconds for production targets

## 🔬 Technical Details

- **Payload Categories**: Basic, Advanced, Filter Bypass, Context-Specific, DOM-based, Event Handlers, Unicode, HTML5, CSS Injection, Meta Tags, Modern Attacks, XML/XHTML, Polyglot
- **Encoding Methods**: None, URL, Double URL, HTML Entity, Base64, Hex, Unicode
- **Detection Methods**: Response analysis, content-type checking, dangerous context identification
- **WAF Fingerprinting**: Header analysis, content inspection, response pattern matching

## 📝 Created by H4mzaX

This tool represents a significant advancement in XSS detection capabilities, combining traditional vulnerability scanning with modern evasion techniques and browser-based verification for unparalleled accuracy.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Only use on systems you own or have explicit permission to test.