# IOK Lab - Quick Reference Card

## Essential Commands

### Setup (One Time)
```bash
chmod +x setup.sh && ./setup.sh
source venv/bin/activate
```

### Single URL Scan
```bash
# Collect + detect in 2 steps
python3 iok_collector.py https://phishing-site.com phish.json
python3 iok_detector.py phish.json IOK/indicators/

# Quick scan (uses default filenames)
python3 iok_collector.py https://phishing-site.com
python3 iok_detector.py iok_event.json IOK/indicators/
```

### Batch Scanning
```bash
# Create URL list
nano urls.txt

# Run batch scan
python3 iok_batch.py urls.txt

# View results
ls -lh batch_results/
cat batch_results/batch_report_*.json | python3 -m json.tool
```

### Analyzing Results
```bash
# View event data
cat event.json | python3 -m json.tool | less

# Count JavaScript files captured
cat event.json | jq '.js | length'

# List all network requests
cat event.json | jq -r '.requests[]'

# View detection summary
cat event_detections.json | python3 -m json.tool

# Count detections by severity
cat event_detections.json | jq -r '.[] | .level' | sort | uniq -c
```

### Writing Custom Rules
```bash
# Create custom rule directory
mkdir -p IOK/indicators/custom

# Create rule file
nano IOK/indicators/custom/my-rule.yml

# Test your rule
python3 iok_detector.py test_event.json IOK/indicators/
```

### Maintenance
```bash
# Update IOK rules
cd IOK && git pull && cd ..

# Update Python packages
pip install --upgrade selenium requests PyYAML

# Clean old results
rm -f *.json
rm -rf batch_results/*.json
```

## File Locations

```
~/iok-lab/
├── venv/                      # Python virtual environment
├── IOK/                       # Rules repository
│   └── indicators/            # Sigma rule files
│       ├── *.yml             # Built-in rules
│       └── custom/           # Your custom rules
├── batch_results/            # Batch scan outputs
├── iok_collector.py          # Data collector
├── iok_detector.py           # Detection engine
├── iok_batch.py              # Batch processor
└── urls.txt                  # URL list for batch scans
```

## Common Patterns

### URLScan.io Workflow
```bash
# 1. Find phishing on URLScan
# 2. Copy URL
# 3. Scan it
python3 iok_collector.py https://suspected-phish.com
python3 iok_detector.py iok_event.json IOK/indicators/
```

### Daily Batch Scan (Cron)
```bash
# Add to crontab
crontab -e

# Add this line (runs at 2 AM daily)
0 2 * * * cd ~/iok-lab && source venv/bin/activate && python3 iok_batch.py urls.txt
```

### Custom Rule Template
```yaml
title: Your Detection Name
id: generate-uuid-here
status: experimental
description: What this detects
author: Tyler
date: 2024-10-31
tags:
  - phishing-kit
detection:
  selection:
    js|contains: 'unique_string'
  condition: selection
level: high
```

## Troubleshooting Quick Fixes

### ChromeDriver Issues
```bash
sudo apt-get install chromium-chromedriver
```

### Timeout Errors
Edit `iok_collector.py`, line ~15:
```python
event = collect_iok_data(url, timeout=30)  # Increase from 10
```

### Python Environment
```bash
# Reactivate if needed
source venv/bin/activate

# Check if active (should show venv path)
which python3
```

## Detection Levels

- **critical**: Active C2, malware distribution
- **high**: Credential harvesting, brand impersonation  
- **medium**: Phishing kit, suspicious patterns
- **low**: Generic indicators, needs context

## Tips

- Test rules on known-good sites first (false positive check)
- Use specific patterns over broad ones
- Tag your custom rules consistently
- Document why you created each rule
- Version control your custom rules directory
- Share good rules with the community (PR to IOK repo)

## Getting Help

- IOK issues: https://github.com/phish-report/IOK/issues
- Sigma docs: https://github.com/SigmaHQ/sigma
- This lab: Check DEPLOYMENT.md for detailed guide
