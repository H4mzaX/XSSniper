# 📦 Installation Guide

## Quick Installation

### Option 1: Clone from GitHub (Recommended)
```bash
# Clone the repository
git clone https://github.com/H4mzaX/XSSniper.git
cd XSSniper

# Run the setup script
./setup.sh
```

### Option 2: Download ZIP
1. Go to [https://github.com/H4mzaX/XSSniper](https://github.com/H4mzaX/XSSniper)
2. Click the green "Code" button
3. Select "Download ZIP"
4. Extract the ZIP file
5. Open terminal and navigate to the extracted folder
6. Run: `./setup.sh`

## Manual Installation

### Prerequisites
- Python 3.6 or higher
- pip3 (Python package manager)
- figlet and lolcat (for banner display)

### Step-by-Step
```bash
# 1. Install Python dependencies
pip3 install -r requirements.txt

# 2. Install banner dependencies (macOS)
brew install figlet lolcat

# 3. Make scripts executable
chmod +x xss_scanner.py
chmod +x payload_tester.py
chmod +x param_discovery.py
chmod +x setup.sh
```

## Verification

Test the installation:
```bash
python3 xss_scanner.py --help
```

If you see the help output, the installation was successful!

## Troubleshooting

### Common Issues

**Permission Denied:**
```bash
chmod +x *.py
```

**Module Not Found:**
```bash
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

**macOS figlet/lolcat Issues:**
```bash
# Install Homebrew first if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Then install figlet and lolcat
brew install figlet lolcat
```

**Linux figlet/lolcat Installation:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install figlet
gem install lolcat

# CentOS/RHEL
sudo yum install figlet
gem install lolcat
```

## Next Steps

After installation, check out:
- [README.md](README.md) for usage instructions
- [Examples](#usage-examples) for common scanning scenarios

## Usage Examples

### Basic Scan
```bash
python3 xss_scanner.py -u "https://example.com/search?q=test" -v
```

### Advanced Scan with Crawling
```bash
python3 xss_scanner.py -u "https://example.com" -c --max-depth 2 -v
```

### Multiple URLs
```bash
python3 xss_scanner.py -l urls.txt -v
```

## Support

If you encounter any issues:
1. Check the [troubleshooting section](#troubleshooting)
2. Make sure all prerequisites are installed
3. Verify Python version: `python3 --version`
4. Check pip version: `pip3 --version`

---
**Created by H4mzaX** | [GitHub](https://github.com/H4mzaX/XSSniper)
