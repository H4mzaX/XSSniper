#!/bin/bash

# XSS Tool Setup Script
# This script sets up the environment and installs dependencies

echo "============================================"
echo "🔥 Advanced XSS Scanner Tool Setup"
echo "============================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if Python 3 is installed
echo -e "${CYAN}Checking Python installation...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    echo -e "${GREEN}✓ Python 3 found: ${PYTHON_VERSION}${NC}"
else
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.6 or higher.${NC}"
    exit 1
fi

# Check if pip is installed
echo -e "${CYAN}Checking pip installation...${NC}"
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓ pip3 found${NC}"
else
    echo -e "${RED}✗ pip3 not found. Please install pip for Python 3.${NC}"
    exit 1
fi

# Install Python dependencies
echo -e "${CYAN}Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Dependencies installed successfully${NC}"
else
    echo -e "${RED}✗ Failed to install dependencies${NC}"
    exit 1
fi

# Make scripts executable
echo -e "${CYAN}Setting executable permissions...${NC}"
chmod +x xss_scanner.py
chmod +x payload_tester.py
chmod +x example_usage.py

echo -e "${GREEN}✓ Scripts are now executable${NC}"

# Create symlinks for easier access (optional)
echo -e "${CYAN}Creating convenient aliases...${NC}"
TOOL_DIR=$(pwd)

# Add to bash/zsh profile if user wants
read -p "Do you want to add XSS tools to your PATH? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Detect shell
    if [[ $SHELL == *"zsh"* ]]; then
        PROFILE_FILE="$HOME/.zshrc"
    elif [[ $SHELL == *"bash"* ]]; then
        PROFILE_FILE="$HOME/.bashrc"
    else
        PROFILE_FILE="$HOME/.profile"
    fi
    
    echo "" >> $PROFILE_FILE
    echo "# XSS Scanner Tool aliases" >> $PROFILE_FILE
    echo "alias xss-scan='python3 $TOOL_DIR/xss_scanner.py'" >> $PROFILE_FILE
    echo "alias xss-test='python3 $TOOL_DIR/payload_tester.py'" >> $PROFILE_FILE
    echo "export PATH=\"$TOOL_DIR:\$PATH\"" >> $PROFILE_FILE
    
    echo -e "${GREEN}✓ Aliases added to $PROFILE_FILE${NC}"
    echo -e "${YELLOW}Run 'source $PROFILE_FILE' or restart your terminal to use aliases${NC}"
fi

# Test installation
echo -e "${CYAN}Testing installation...${NC}"
python3 xss_scanner.py --help > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ XSS Scanner is working correctly${NC}"
else
    echo -e "${RED}✗ XSS Scanner test failed${NC}"
    exit 1
fi

# Display usage information
echo ""
echo "============================================"
echo -e "${GREEN}🎉 Setup completed successfully!${NC}"
echo "============================================"
echo ""
echo -e "${CYAN}Quick Start Guide:${NC}"
echo ""
echo -e "${YELLOW}1. Basic XSS scan:${NC}"
echo "   python3 xss_scanner.py -u http://target.com/page.php?id=1"
echo ""
echo -e "${YELLOW}2. Advanced scan with crawling:${NC}"
echo "   python3 xss_scanner.py -u http://target.com -v -c"
echo ""
echo -e "${YELLOW}3. Interactive payload testing:${NC}"
echo "   python3 payload_tester.py -u http://target.com/search.php"
echo ""
echo -e "${YELLOW}4. View examples:${NC}"
echo "   python3 example_usage.py"
echo ""
echo -e "${RED}⚠️  Legal Notice:${NC}"
echo -e "${YELLOW}This tool is for educational and authorized testing only!${NC}"
echo -e "${YELLOW}Always ensure you have permission before testing any systems.${NC}"
echo ""
echo -e "${CYAN}For detailed documentation, see README.md${NC}"
echo "============================================"
