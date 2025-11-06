# IOK Detection Lab

> Automated phishing detection pipeline using IOK (Indicator of Kit) rules with SIEM integration

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/)

Proof-of-concept detection pipeline for analyzing phishing sites using [IOK rules](https://github.com/phish-report/IOK) with automated SIEM enrichment for Splunk and Elastic Stack.

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git
cd iok-detection-lab

# Run setup
chmod +x setup.sh
./setup.sh

# Activate environment
source venv/bin/activate

# Test with example URL
python3 scripts/iok_collector.py https://example.com
python3 scripts/iok_detector.py iok_event.json IOK/indicators/
```

## 📋 What This Does

**Automated Phishing Detection:**
- Collects full web page data (HTML, JavaScript, CSS, cookies, requests)
- Runs 500+ IOK/Sigma rules against collected data
- Returns threat intelligence in structured JSON format
- Integrates with Splunk and Elastic Stack for automated enrichment

**Use Cases:**
- Security Operations Centers (SOC) - Automated phishing triage
- Detection Engineering - Write and test custom Sigma rules
- Threat Research - Analyze phishing campaigns at scale
- Incident Response - Quick phishing site analysis

## 🏗️ Architecture

### Phase 1: Standalone Analysis
```
URL → IOK Collector → IOK Detector → Detection Results
      (Headless Chrome)  (Sigma Rules)    (JSON)
```

### Phase 2: SIEM Integration
```
SIEM → API Server → Worker Pool → IOK Analysis → Enhanced Alert
     Suspicious URL   (Flask)      (Collector+Detector)    (Enriched)
```

## 📦 Components

### Core Scripts (`scripts/`)
- **iok_collector.py** - Headless browser data collector (captures all 9 IOK fields)
- **iok_detector.py** - Sigma rule matching engine (runs IOK rules)
- **iok_batch.py** - Batch URL processor with reporting

### SIEM Integration (`siem-integration/`)
- **iok_api.py** - Flask REST API server for automated analysis
- **splunk_iok_action.py** - Splunk alert action for enrichment
- **elastic_iok_enrich.py** - Elasticsearch enrichment script
- **elastic_watcher_iok.json** - Elastic Watcher configuration

### Documentation (`docs/`)
- Complete deployment guides
- SIEM integration instructions
- Detection engineering workflow
- Troubleshooting guides

## 💻 Installation

### Prerequisites
- Ubuntu/Debian Linux (or VM)
- Python 3.8+
- 2GB RAM minimum
- Internet connection

### Setup
```bash
# Clone and setup
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git
cd iok-detection-lab
./setup.sh

# Activate environment
source venv/bin/activate
```

This installs:
- Python dependencies (Selenium, PyYAML, requests)
- Google Chrome + ChromeDriver
- IOK rules repository (500+ rules)

## 🎯 Usage

### Analyze Single URL
```bash
python3 scripts/iok_collector.py https://suspicious-site.com output.json
python3 scripts/iok_detector.py output.json IOK/indicators/
```

### Batch Analysis
```bash
# Create URL list
echo "https://site1.com" > urls.txt
echo "https://site2.com" >> urls.txt

# Run batch scan
python3 scripts/iok_batch.py urls.txt
```

### SIEM Integration

**Deploy API Server:**
```bash
# Install Flask
pip install flask

# Start API server
python3 siem-integration/iok_api.py
```

**Test API:**
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Integrate with Splunk:**
```bash
sudo cp siem-integration/splunk_iok_action.py $SPLUNK_HOME/bin/scripts/
# See docs/SIEM_INTEGRATION.md for details
```

**Integrate with Elastic:**
```bash
sudo cp siem-integration/elastic_iok_enrich.py /usr/local/bin/
curl -X PUT "localhost:9200/_watcher/watch/iok" -d @siem-integration/elastic_watcher_iok.json
# See docs/SIEM_INTEGRATION.md for details
```

## 📊 IOK Event Schema

The collector captures these 9 fields for detection:

| Field | Type | Description |
|-------|------|-------------|
| `title` | Array | Page title(s) - static and JS-set |
| `hostname` | String | Domain name |
| `html` | String | Raw server HTML response |
| `dom` | String | HTML after JavaScript execution |
| `js` | Array | All JavaScript code (inline + external) |
| `css` | Array | All CSS code (inline + external) |
| `cookies` | Array | Cookies in `name=value` format |
| `headers` | Array | HTTP headers in `Header: value` format |
| `requests` | Array | All URLs requested by the page |

## 🔍 Example Detection

**Input:** Phishing URL
```bash
python3 scripts/iok_collector.py https://microsoft-verify-2024.xyz
python3 scripts/iok_detector.py iok_event.json IOK/indicators/
```

**Output:**
```
[!] DETECTED 3 MATCHES:
================================================================================

Title: Generic Phishing Kit Detection
Level: HIGH
Description: Detects common phishing kit patterns
Tags: phishing-kit, credential-harvesting

Title: Microsoft Brand Impersonation
Level: MEDIUM
Description: Page impersonates Microsoft branding
Tags: brand-impersonation, microsoft

Title: Credential Harvesting Page
Level: HIGH
Description: Page contains credential submission forms
Tags: credential-harvesting
```

## ✍️ Writing Custom Rules

Create custom IOK/Sigma rules for your environment:

```yaml
# IOK/indicators/custom/my-rule.yml
title: Custom Phishing Kit Detection
id: 12345678-abcd-1234-abcd-123456789012
status: experimental
description: Detects specific phishing kit in my environment
author: Your Name
date: 2024-10-31
tags:
  - phishing-kit
  - credential-harvesting
detection:
  selection:
    js|contains: 'unique_malicious_function()'
  condition: selection
level: high
```

Test your rule:
```bash
python3 scripts/iok_detector.py collected_event.json IOK/indicators/
```

## 📈 Performance

**Analysis Time:**
- Simple page: 5-10 seconds
- Complex page: 10-30 seconds
- Batch (10 URLs): 1-3 minutes

**Throughput (API Server):**
- 3 workers: 6-18 URLs/minute
- 5 workers: 10-30 URLs/minute

**Resource Usage:**
- RAM: ~500MB per Chrome instance
- CPU: Moderate during analysis
- Disk: Minimal (temp files)

## 🛠️ Configuration

### API Server Environment Variables
```bash
export IOK_COLLECTOR=/path/to/scripts/iok_collector.py
export IOK_DETECTOR=/path/to/scripts/iok_detector.py
export IOK_RULES=/path/to/IOK/indicators/
export IOK_MAX_WORKERS=3
export IOK_TIMEOUT=60
```

### Production Deployment
```bash
# Run API as systemd service
sudo cp siem-integration/iok-api.service /etc/systemd/system/
sudo systemctl enable iok-api
sudo systemctl start iok-api
```

## 📚 Documentation

- **[Getting Started](docs/SETUP_INSTRUCTIONS.md)** - Complete setup walkthrough
- **[SIEM Integration](docs/SIEM_INTEGRATION.md)** - Splunk & Elastic integration guide
- **[Deployment Checklist](docs/DEPLOYMENT_CHECKLIST.md)** - Step-by-step deployment tracking
- **[Quick Reference](docs/QUICK_REFERENCE.md)** - Command cheat sheet
- **[Full Documentation](docs/)** - All guides and references

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Contribute IOK rules to the upstream project:**
- Repository: https://github.com/phish-report/IOK
- Rule reference: https://phish.report/docs/iok-rule-reference

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

IOK rules are licensed under [ODbL](https://opendatacommons.org/licenses/odbl/) by the [phish-report/IOK](https://github.com/phish-report/IOK) project.

## 🙏 Acknowledgments

- **IOK Project** - https://github.com/phish-report/IOK - Rule repository
- **Sigma** - https://github.com/SigmaHQ/sigma - Detection rule format
- **phish.report** - https://phish.report - Phishing research platform

## 🔗 Resources

- [IOK Project](https://github.com/phish-report/IOK)
- [IOK Live Detections](https://phish.report/IOK)
- [IOK Rule Reference](https://phish.report/docs/iok-rule-reference)
- [Sigma Documentation](https://github.com/SigmaHQ/sigma)
- [Selenium Python](https://selenium-python.readthedocs.io/)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/iok-detection-lab/issues)
- **Documentation**: [docs/](docs/)
- **IOK Community**: [phish-report/IOK](https://github.com/phish-report/IOK)

## ⚠️ Disclaimer

This tool is for security research and detection engineering purposes. Use responsibly:
- Only analyze URLs you have permission to investigate
- Run in isolated lab environment
- Be aware that visiting phishing sites may expose you to malicious content
- Follow your organization's security policies

---

**Built for detection engineers, by detection engineers.**

If this helps your security operations, please ⭐ star the repository!
