# XSSniper - Advanced XSS Scanner
**Professional Security Testing Framework Enhanced for 2025**

![Version](https://img.shields.io/badge/version-3.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Open_Source-green)

## 🚀 Quick Installation

```bash
# Clone the repository
git clone https://github.com/H4mzaX/XSSniper.git
cd XSSniper

# Install dependencies
pip install -r requirements.txt

# Add to PATH (optional for global access)
echo 'export PATH="$PATH:/path/to/XSSniper"' >> ~/.bashrc
source ~/.bashrc

# Run XSSniper
python3 XSSniper.py -u "https://example.com" -v
```

**Repository URL**: `https://github.com/H4mzaX/XSSniper`

## 🚀 What's New in 2025

The XSSniper framework has been completely modernized with cutting-edge security testing capabilities:

### ⚡ Performance Enhancements
- **Async/Await Architecture**: Up to 5x faster scanning with concurrent request handling
- **Smart Rate Limiting**: Intelligent delay management to avoid overwhelming targets
- **Memory Optimization**: Reduced memory footprint for large-scale testing
- **Parallel Processing**: Multi-threaded parameter discovery and payload testing

### 🛡️ Advanced Security Features
- **License Protection System**: Advanced anti-tampering and copy protection
- **Runtime Integrity Checks**: Continuous verification during execution
- **Encrypted Configuration**: Secure storage of sensitive scanning parameters
- **Machine Fingerprinting**: Hardware-based license validation

### 🎯 Modern XSS Detection
- **CVE-2025 Coverage**: Latest vulnerability patterns and bypass techniques
- **Framework-Specific Payloads**: React, Vue.js, Angular XSS vectors
- **Template Literal Injection**: Modern JavaScript ES6+ exploitation
- **Mutation XSS (mXSS)**: Advanced DOM manipulation detection
- **CSP Bypass Techniques**: Content Security Policy evasion methods

### 🔍 Enhanced Discovery
- **AI-Powered Parameter Detection**: Smart parameter discovery algorithms
- **API Endpoint Analysis**: Automatic API documentation parsing
- **Error-Based Discovery**: Parameter extraction from error messages
- **Header Analysis**: Security header inspection and parameter hints

## 📋 Features

### Core Capabilities
- **Multi-Vector XSS Testing**: DOM, Reflected, Stored XSS detection
- **WAF Bypass**: Automated firewall evasion techniques
- **Context-Aware Detection**: Intelligent payload context analysis
- **Real-time Reporting**: Live vulnerability discovery feedback
- **Export Capabilities**: JSON, HTML, and CSV report formats

### Advanced Modules
1. **XSSniper.py**: Main scanner with async architecture
2. **param_discovery.py**: Enhanced parameter discovery engine
3. **payload_tester.py**: Comprehensive payload testing framework

### Payload Categories
- **DOM-based XSS** (CVE-2025-24017)
- **Template Literal Injection** (CVE-2025-26791)
- **Mutation XSS** (mXSS)
- **Framework Bypasses** (React, Vue, Angular)
- **CSP Bypass Techniques**
- **Modern HTML5 Vectors**
- **WebAssembly & Modern APIs**
- **Unicode & Encoding Bypasses**
- **Filter Bypass Techniques**

## � Installation

### Prerequisites
- Python 3.8 or higher
- Valid license key (contact developer)

### Quick Install
```bash
# Clone the repository
git clone <repository-url>
cd xssniper

# Install dependencies
pip install -r requirements.txt

# Verify installation
python XSSniper.py --help
```

### Dependencies
```
aiohttp>=3.9.0
beautifulsoup4>=4.12.2
colorama>=0.4.6
lxml>=4.9.3
urllib3>=2.0.0
```

## � Usage

### Basic Scanning
```bash
# Single URL scan
python XSSniper.py -u https://example.com

# Multiple URLs from file
python XSSniper.py -l urls.txt

# Verbose mode with custom threads
python XSSniper.py -u https://example.com -v -t 30
```

### Advanced Options
```bash
# Custom delay and crawling
python XSSniper.py -u https://example.com -d 0.5 -c --max-depth 3

# Custom User-Agent and output
python XSSniper.py -u https://example.com --user-agent "Custom Bot" -o results.json

# Disable browser verification
python XSSniper.py -u https://example.com --no-browser-verify
```

### Parameter Discovery
```bash
# Discover parameters
python param_discovery.py -u https://example.com

# With custom settings
python param_discovery.py -u https://example.com -t 25 -d 0.2 -v
```

### Payload Testing
```bash
# Test specific parameters
python payload_tester.py -u https://example.com -p id page search

# Test custom payloads
python payload_tester.py -u https://example.com --payloads "<script>alert(1)</script>" "${alert(1)}"
```

## 🔒 License System

### License Verification
The tool requires a valid license key for operation. License verification includes:
- Hardware fingerprinting
- Expiration date checking
- HMAC signature validation
- Runtime integrity verification

### License File
Create a `.xss_license` file in the tool directory:
```
eyJ1c2VyIjoiZXhhbXBsZSIsImV4cGlyZXMiOjE3NDA3NzQ0MDAsInNpZ25hdHVyZSI6IjEyMzQ1In0=
```

## 🎯 CVE Coverage

### Recently Added CVEs
- **CVE-2025-24017**: DOM-based XSS in modern frameworks
- **CVE-2025-26791**: Template literal injection vulnerabilities
- **CVE-2024-49646**: Framework-specific bypass techniques

### WAF Bypass Support
- Cloudflare
- AWS WAF
- Akamai
- ModSecurity
- Imperva (Incapsula)
- F5 BIG-IP
- Barracuda
- Fortinet

## 📊 Output Examples

### Console Output
```
[12:34:56] [INFO] Starting advanced XSS scan...
[12:34:57] [WARNING] WAF Detected: Cloudflare
[12:34:58] [VULN] VULNERABILITY FOUND! Parameter: search, Type: Template Literal Injection
[12:35:00] [SUCCESS] Scan completed. 3 vulnerabilities found.
```

### JSON Report Structure
```json
{
  "scan_info": {
    "target_url": "https://example.com",
    "timestamp": "2025-01-15 12:34:56",
    "total_vulnerabilities": 3,
    "detected_waf": "Cloudflare"
  },
  "vulnerabilities": [
    {
      "type": "Reflected XSS",
      "url": "https://example.com?search=<payload>",
      "parameter": "search",
      "severity": "High",
      "cve_related": ["CVE-2025-26791"]
    }
  ]
}
```

## 🚨 Important Notes

### Legal Usage
- **Authorized Testing Only**: Only use on systems you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities responsibly to affected parties
- **Compliance**: Ensure testing complies with local laws and regulations

### Performance Considerations
- Default thread count: 20 (adjust based on target capacity)
- Rate limiting recommended for production systems
- Monitor resource usage during large scans

### Protection Features
- Anti-tampering mechanisms active
- License verification required
- Runtime integrity checks
- Code obfuscation for IP protection

## 🤝 Support & Contact

For licensing inquiries, technical support, or feature requests:
- **Developer**: H4mzaX
- **Email**: [Contact for licensing]
- **License Type**: Professional/Commercial

## 📝 Changelog

### Version 3.0 (2025)
- Complete rewrite with async architecture
- Added CVE-2025 vulnerability patterns
- Enhanced WAF bypass capabilities
- Improved performance (5x faster)
- Advanced license protection system
- Modern framework-specific payloads

### Previous Versions
- Version 2.x: Basic XSS scanning
- Version 1.x: Initial release

## ⚠️ Disclaimer

This tool is for authorized security testing purposes only. The developers are not responsible for any misuse or damage caused by this tool. Users must ensure they have proper authorization before testing any systems.

---

**Professional Security Testing Framework - Enhanced for 2025**
*Developed by H4mzaX*
