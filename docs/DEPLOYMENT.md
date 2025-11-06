# IOK Lab Deployment Guide

Complete walkthrough for setting up the IOK detection pipeline in your home lab.

## Lab Architecture

```
┌─────────────────────────────────────┐
│    Analysis VM (Ubuntu 22.04)      │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  IOK Detection Pipeline      │  │
│  │  - Headless Chrome           │  │
│  │  - Python collectors         │  │
│  │  - Sigma rule engine         │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  Storage                     │  │
│  │  - Event JSONs               │  │
│  │  - Detection results         │  │
│  │  - IOK rules repository      │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

## Step 1: VM Setup

**Create Ubuntu VM:**
- OS: Ubuntu 22.04 LTS Server/Desktop
- RAM: 4GB minimum (8GB recommended)
- Disk: 20GB minimum
- Network: Bridged or NAT (needs internet)

**Initial VM config:**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget
```

## Step 2: Deploy IOK Pipeline

**Download the files to your VM:**
```bash
# Create project directory
mkdir -p ~/iok-lab
cd ~/iok-lab

# Download files (use these commands on your VM after transferring files)
# For now, manually copy these files to your VM:
#   - iok_collector.py
#   - iok_detector.py
#   - iok_batch.py
#   - setup.sh
#   - urls.txt
```

**Run setup:**
```bash
chmod +x setup.sh
./setup.sh
```

This installs:
- Python 3 + dependencies
- Google Chrome
- ChromeDriver
- Selenium, PyYAML, requests
- IOK rules repository

## Step 3: Test Installation

**Activate environment:**
```bash
cd ~/iok-lab
source venv/bin/activate
```

**Test with safe site:**
```bash
# Collect event data
python3 iok_collector.py https://example.com test.json

# Verify JSON was created
ls -lh test.json

# Run detection
python3 iok_detector.py test.json IOK/indicators/

# Should output: "No threats detected" for example.com
```

## Step 4: Test with Known Phishing

**Use URLScan.io to find test samples:**
1. Visit https://urlscan.io
2. Search for "phishing" with recent date filter
3. Find confirmed phishing URLs (look for "Malicious" or "Phishing" verdicts)
4. Copy a URL

**Scan it:**
```bash
python3 iok_collector.py https://[phishing-url] phish1.json
python3 iok_detector.py phish1.json IOK/indicators/
```

If detections trigger, you'll see output like:
```
[!] DETECTED 3 MATCHES:
================================================================================

Title: Generic Phishing Kit Detection
Level: HIGH
...
```

## Step 5: Batch Scanning

**Create URL list:**
```bash
nano urls.txt
```

Add URLs (one per line):
```
https://suspected-phish1.com
https://suspected-phish2.com
https://suspected-phish3.com
```

**Run batch scan:**
```bash
python3 iok_batch.py urls.txt
```

Results saved in `batch_results/` directory.

## Step 6: Analyze Results

**View collected events:**
```bash
# Pretty print JSON
cat phish1.json | python3 -m json.tool | less

# Check what JavaScript was captured
cat phish1.json | jq '.js[] | length'

# Check captured requests
cat phish1.json | jq '.requests[]'
```

**Review detections:**
```bash
# View detection summary
cat phish1_detections.json | python3 -m json.tool

# Count detections by level
cat phish1_detections.json | jq -r '.[] | .level' | sort | uniq -c
```

## Step 7: Write Custom Rules

**Scenario:** You found a phishing kit that IOK doesn't detect.

**Create custom rule:**
```bash
mkdir -p IOK/indicators/custom
nano IOK/indicators/custom/my-detection.yml
```

**Example rule structure:**
```yaml
title: Custom Phishing Kit Detection
id: 12345678-abcd-1234-abcd-123456789012
status: experimental
description: Detects custom kit by unique JavaScript function
author: Tyler
date: 2024-10-31
tags:
  - phishing-kit
  - credential-harvesting
detection:
  selection:
    js|contains:
      - 'submitCredentials'
      - 'sendToC2'
  condition: selection
level: high
```

**Test your rule:**
```bash
python3 iok_detector.py phish1.json IOK/indicators/
```

## Step 8: Automation Ideas

**Scheduled scanning:**
```bash
# Add to crontab
crontab -e

# Run batch scan daily at 2 AM
0 2 * * * cd ~/iok-lab && source venv/bin/activate && python3 iok_batch.py urls.txt >> scan.log 2>&1
```

**Integration with URLScan.io:**
```python
# Future enhancement: Auto-fetch from URLScan API
# Check their API docs: https://urlscan.io/docs/api/
```

## Troubleshooting

**Problem: ChromeDriver version mismatch**
```bash
# Check versions
google-chrome --version
chromedriver --version

# They should match major version (e.g., both 119.x)
```

**Problem: Selenium timeout errors**
```bash
# Edit iok_collector.py, increase timeout
# Line ~15: collect_iok_data(url, timeout=30)
```

**Problem: Out of memory**
```bash
# Check RAM usage
free -h

# Increase VM RAM or close other processes
```

**Problem: Network access denied**
```bash
# Chrome blocks some sites
# Edit iok_collector.py, add:
chrome_options.add_argument('--ignore-certificate-errors')
```

## Workflow for Detection Engineering

**Your typical workflow:**

1. **Collect URLs**
   - From phishing reports
   - URLScan.io submissions
   - Threat intel feeds
   - OSINT sources

2. **Batch scan**
   - Run iok_batch.py on URL list
   - Review detection summary

3. **Analyze undetected**
   - Open event JSON files
   - Look for patterns in JS/CSS/HTML
   - Identify unique indicators

4. **Write Sigma rules**
   - Create rule in IOK/indicators/custom/
   - Test against collected events
   - Refine until working

5. **Validate**
   - Test on known-good sites (false positive check)
   - Test on known-bad sites (true positive check)
   - Document findings

6. **Share**
   - Submit to IOK repository via GitHub PR
   - Share with team
   - Update internal detection stack

## Next Steps

**Expand the pipeline:**
- Add database storage (SQLite/PostgreSQL)
- Build web dashboard (Flask/Django)
- Integrate with SIEM (Splunk/ELK)
- Create API endpoint (FastAPI)
- Add screenshot capture
- Implement detonation sandbox

**Learning resources:**
- Study existing IOK rules: `IOK/indicators/`
- Read Sigma docs: https://github.com/SigmaHQ/sigma
- Check phish.report blog for analysis examples
- Practice on URLScan.io samples

## Lab Maintenance

**Update IOK rules:**
```bash
cd ~/iok-lab/IOK
git pull
cd ..
```

**Update Python packages:**
```bash
source venv/bin/activate
pip install --upgrade selenium requests PyYAML
```

**Clean old results:**
```bash
# Archive old batch results
tar -czf batch_results_$(date +%Y%m%d).tar.gz batch_results/
rm -rf batch_results/*.json
```

## Security Notes

- Run this in an isolated lab VM
- Don't visit phishing URLs from your host machine
- Consider using VPN when scanning live threats
- Don't store credentials in event files
- Sanitize data before sharing
