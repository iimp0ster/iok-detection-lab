#!/bin/bash
# IOK PoC Lab Setup Script

set -e

echo "[+] IOK Detection Pipeline Setup"
echo "=================================="

# Update system
echo "[+] Updating packages..."
sudo apt-get update -qq

# Install Python
echo "[+] Installing Python3..."
sudo apt-get install -y python3 python3-pip python3-venv git wget unzip

# Install Chrome
echo "[+] Installing Google Chrome..."
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list'
sudo apt-get update -qq
sudo apt-get install -y google-chrome-stable

# Install ChromeDriver (simplified)
echo "[+] Installing ChromeDriver..."
sudo apt-get install -y chromium-chromedriver || true
sudo ln -sf /usr/bin/chromedriver /usr/local/bin/chromedriver || true

# Create venv
echo "[+] Setting up Python environment..."
python3 -m venv venv
source venv/bin/activate

# Install packages
pip install -q --upgrade pip
pip install -q selenium requests PyYAML urllib3

# Clone IOK rules
echo "[+] Cloning IOK repository..."
if [ ! -d "IOK" ]; then
    git clone -q https://github.com/phish-report/IOK.git
fi

# Make executable
chmod +x scripts/iok_collector.py scripts/iok_detector.py scripts/iok_batch.py
chmod +x siem-integration/iok_api.py siem-integration/splunk_iok_action.py siem-integration/elastic_iok_enrich.py

echo ""
echo "[✓] Setup complete!"
echo ""
echo "Quick Start:"
echo "  source venv/bin/activate"
echo "  python3 scripts/iok_collector.py https://example.com"
echo "  python3 scripts/iok_detector.py iok_event.json IOK/indicators/"
