#!/bin/bash

# XSS Tool Development Workflow Script
# This script handles the obfuscation and packaging of the XSS tool

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 XSS Tool Development Workflow${NC}"
echo "=================================="

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 is not installed or not in PATH${NC}"
    exit 1
fi

# Check if required tools are available
echo -e "${YELLOW}📋 Checking dependencies...${NC}"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for base64 (should be available on most systems)
if ! command_exists base64; then
    echo -e "${RED}❌ base64 command not found${NC}"
    exit 1
fi

# Set up directories
SOURCE_DIR="./src"
BUILD_DIR="./build"
DIST_DIR="./dist"

echo -e "${YELLOW}📁 Setting up directories...${NC}"
mkdir -p "$BUILD_DIR"
mkdir -p "$DIST_DIR"

# Function to obfuscate Python files
obfuscate_file() {
    local input_file="$1"
    local output_file="$2"
    
    echo -e "${YELLOW}🔒 Obfuscating $(basename "$input_file")...${NC}"
    
    # Read the original file and encode it
    if [ -f "$input_file" ]; then
        # Create obfuscated version
        cat > "$output_file" << 'EOF'
#!/usr/bin/env python3
# Obfuscated with custom obfuscator
import base64
exec(base64.b64decode('EOF
        
        # Add the base64 encoded content
        base64 -w 0 "$input_file" >> "$output_file"
        
        # Close the obfuscation wrapper
        cat >> "$output_file" << 'EOF'
').decode('utf-8'))
EOF
        
        # Make executable
        chmod +x "$output_file"
        echo -e "${GREEN}✅ Successfully obfuscated $(basename "$input_file")${NC}"
    else
        echo -e "${RED}❌ Source file $input_file not found${NC}"
        return 1
    fi
}

# Function to create requirements.txt
create_requirements() {
    echo -e "${YELLOW}📦 Creating requirements.txt...${NC}"
    cat > "$DIST_DIR/requirements.txt" << 'EOF'
requests>=2.28.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
selenium>=4.15.0
lxml>=4.9.0
urllib3>=1.26.0
EOF
    echo -e "${GREEN}✅ Requirements file created${NC}"
}

# Function to create README
create_readme() {
    echo -e "${YELLOW}📝 Creating README.md...${NC}"
    cat > "$DIST_DIR/README.md" << 'EOF'
# XSS Tool by H4mzaX

An advanced XSS vulnerability scanner with automatic WAF detection and browser verification capabilities.

## 🚀 Features

- **Auto WAF Detection**: Automatically detects and adapts to 9+ popular WAFs
- **WAF Bypass Payloads**: Specialized payloads for each detected WAF
- **Browser Verification**: Uses Selenium to verify XSS execution in real browsers
- **Comprehensive Payloads**: 80+ XSS payloads including modern attack vectors
- **Multiple Encodings**: Tests URL, Double URL, HTML, and Unicode encodings
- **False Positive Reduction**: Advanced reflection detection to minimize false positives
- **Professional Reporting**: Saves only vulnerable results with detailed information

## Installation

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
python3 XSSniper.py -u "https://example.com" -v
```

## Disclaimer

This tool is for educational and authorized testing purposes only.
EOF
    echo -e "${GREEN}✅ README created${NC}"
}

# Main obfuscation process
echo -e "${BLUE}🔄 Starting obfuscation process...${NC}"

# Obfuscate main files
if [ -f "XSSniper_clean.py" ]; then
    obfuscate_file "XSSniper_clean.py" "$DIST_DIR/XSSniper.py"
else
    echo -e "${RED}❌ XSSniper_clean.py not found${NC}"
fi

if [ -f "param_discovery_clean.py" ]; then
    obfuscate_file "param_discovery_clean.py" "$DIST_DIR/param_discovery.py"
else
    echo -e "${RED}❌ param_discovery_clean.py not found${NC}"
fi

if [ -f "payload_tester_clean.py" ]; then
    obfuscate_file "payload_tester_clean.py" "$DIST_DIR/payload_tester.py"
else
    echo -e "${RED}❌ payload_tester_clean.py not found${NC}"
fi

# Create additional files
create_requirements
create_readme

# Create version info
echo -e "${YELLOW}🏷️  Creating version info...${NC}"
cat > "$DIST_DIR/version.txt" << EOF
XSS Tool v2.0
Build Date: $(date)
Developer: H4mzaX
EOF

# Final package
echo -e "${BLUE}📦 Creating final package...${NC}"
cd "$DIST_DIR"
tar -czf "../xss_tool_v2.tar.gz" .
cd ..

echo -e "${GREEN}🎉 Build completed successfully!${NC}"
echo -e "${GREEN}📋 Package created: xss_tool_v2.tar.gz${NC}"
echo ""
echo -e "${YELLOW}📁 Distribution files:${NC}"
ls -la "$DIST_DIR"

# Cleanup build artifacts
echo -e "${YELLOW}🧹 Cleaning up build artifacts...${NC}"
rm -rf "$BUILD_DIR"

echo -e "${GREEN}✨ Development workflow completed!${NC}"