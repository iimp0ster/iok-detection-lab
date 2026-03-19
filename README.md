# IOK Detection Lab

> Automated phishing detection pipeline using IOK (Indicator of Kit) rules with a browser-based hunt panel, batch scanning, VPN rotation, and SIEM integration

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/)

Proof-of-concept detection pipeline for analyzing phishing sites using [IOK rules](https://github.com/phish-report/IOK) with a built-in web UI, concurrent batch scanning, ProtonVPN SOCKS5 opsec, and automated SIEM enrichment for Splunk and Elastic Stack.

## Quick Start

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git
cd iok-detection-lab

# Run setup
chmod +x setup.sh
./setup.sh

# Activate environment
source venv/bin/activate

# Start the web UI
./start.sh
# Open http://localhost:5000
```

Or use the CLI directly:

```bash
python3 scripts/iok_collector.py https://suspicious-site.com output.json
python3 scripts/iok_detector.py output.json IOK/indicators/
```

## What This Does

**Automated Phishing Detection:**
- Collects full web page data (HTML, JavaScript, CSS, cookies, network requests, forms)
- Runs 500+ IOK/Sigma rules against collected data
- Returns threat intelligence in structured JSON format
- Integrates with Splunk and Elastic Stack for automated enrichment

**Use Cases:**
- Security Operations Centers (SOC) - Automated phishing triage
- Detection Engineering - Write and test custom Sigma rules
- Threat Research - Analyze phishing campaigns at scale
- Incident Response - Quick phishing site analysis

## Architecture

### Phase 1: Standalone CLI
```
URL → IOK Collector → IOK Detector → Detection Results
      (Headless Chrome)  (Sigma Rules)    (JSON)
```

### Phase 2: Web UI + Batch Engine
```
Browser → Hunt Panel (Flask) → BatchEngine → IOK Collector → IOK Detector → SSE Results
                                 (concurrent)   (per URL)      (Sigma rules)   (live stream)
```

### Phase 3: SIEM Integration
```
SIEM → API Server → Worker Pool → IOK Analysis → Enhanced Alert
     Suspicious URL   (Flask)      (Collector+Detector)    (Enriched)
```

## Components

### Core Library (`core/`)
- **opsec.py** — `OpsecManager`: VPN rotation with ProtonVPN, nmcli, or openvpn backends; SOCKS5 proxy helpers; exit-IP verification via ipapi.co
- **batch.py** — `BatchEngine`: concurrent URL scanning with SSE streaming, VPN rotation modes, jitter, and SQLite persistence
- **ua_pool.py** — `UAPool`: thread-safe rotating User-Agent pool

### Scripts (`scripts/`)
- **iok_collector.py** — Headless Chrome collector (captures all IOK fields + forms); supports proxy injection and UA override
- **iok_detector.py** — Sigma rule matching engine (runs IOK rules)
- **iok_batch.py** — Standalone batch URL processor with reporting

### Web UI (`web/`)
- **app.py** — Flask server: single scan, batch hunt with SSE, history, opsec API, rules stats
- **static/index.html** — Hunt panel UI (Single Scan / Batch Hunt / History tabs)
- **static/style.css** — Amber terminal aesthetic
- **static/app.js** — SSE batch streaming, live results, export (JSON/CSV)

### SIEM Integration (`siem-integration/`)
- **iok_api.py** — Flask REST API for SIEM-initiated analysis
- **splunk_iok_action.py** — Splunk alert action for enrichment
- **elastic_iok_enrich.py** — Elasticsearch enrichment script
- **elastic_watcher_iok.json** — Elastic Watcher configuration

### Documentation (`docs/`)
- Complete deployment guides
- SIEM integration instructions
- Detection engineering workflow
- Troubleshooting guides

## Installation

### Prerequisites
- Ubuntu/Debian Linux (or VM)
- Python 3.8+
- 2GB RAM minimum
- Internet connection
- ProtonVPN CLI (optional, for VPN rotation): https://protonvpn.com/support/linux-vpn-tool/

### Setup
```bash
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git
cd iok-detection-lab
./setup.sh
source venv/bin/activate
```

This installs:
- Python dependencies (Flask, Flask-CORS, Selenium, PyYAML, requests)
- Google Chrome + ChromeDriver
- IOK rules repository (500+ rules)

## Usage

### Web UI (recommended)

```bash
./start.sh
```

Open `http://localhost:5000`. The hunt panel has three tabs:

- **Single Scan** — paste a URL, click scan, see verdict + matched rules + network surface
- **Batch Hunt** — paste URLs or import a `.txt` file; configure concurrency, delay, VPN rotation; watch live SSE results
- **History** — searchable table of all completed scans; export to JSON

### CLI — Single URL

```bash
python3 scripts/iok_collector.py https://suspicious-site.com output.json
python3 scripts/iok_detector.py output.json IOK/indicators/
```

### CLI — Batch

```bash
python3 scripts/iok_batch.py urls.txt
```

### API

```bash
# Single scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Start batch
curl -X POST http://localhost:5000/api/batch \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://site1.com", "https://site2.com"],
    "concurrency": 3,
    "delay_ms": 1500,
    "use_vpn": false,
    "rotate_mode": "none"
  }'

# Stream batch results (SSE)
curl http://localhost:5000/api/batch/<batch_id>/stream

# VPN status / rotate
curl http://localhost:5000/api/opsec/status
curl -X POST http://localhost:5000/api/opsec/rotate -d '{"country":"NL"}'
```

## Opsec / VPN

`OpsecManager` supports multiple VPN backends:

| Backend | Description |
|---|---|
| `protonvpn` | ProtonVPN CLI with SOCKS5 on `127.0.0.1:1080`; routes both Chrome and requests through the tunnel |
| `nmcli` | NetworkManager VPN profiles (openvpn/wireguard) |
| `openvpn` | Direct `openvpn` CLI with config files |
| `stub` | Log-only mode (default when no profiles configured) |

Configure via environment or instantiation:

```python
from core.opsec import OpsecManager

# ProtonVPN (country list auto-detected from protonvpn-cli)
opsec = OpsecManager(vpn_profiles=["NL", "CH", "US"], backend="protonvpn")

# nmcli profiles
opsec = OpsecManager(vpn_profiles=["nl-vpn", "ch-vpn"], backend="nmcli")
```

Batch VPN rotation modes (set in the UI or API):

| Mode | Behaviour |
|---|---|
| `none` | No rotation |
| `per_scan` | Rotate before every URL |
| `every_n` | Rotate every N scans |
| `per_batch` | Rotate once at batch start |

## IOK Event Schema

The collector captures these fields for detection:

| Field | Type | Description |
|-------|------|-------------|
| `title` | Array | Page title(s) — static and JS-set |
| `hostname` | String | Domain name |
| `html` | String | Raw server HTML response |
| `dom` | String | HTML after JavaScript execution |
| `js` | Array | All JavaScript code (inline + external) |
| `css` | Array | All CSS code (inline + external) |
| `cookies` | Array | Cookies in `name=value` format |
| `headers` | Array | HTTP headers in `Header: value` format |
| `requests` | Array | All URLs requested by the page (deduplicated) |
| `forms` | Array | Form endpoints with field names and input types |

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Hunt panel UI |
| `POST` | `/api/scan` | Single synchronous scan |
| `POST` | `/api/batch` | Start async batch; returns `batch_id` |
| `GET` | `/api/batch/<id>/stream` | SSE stream of batch events |
| `GET` | `/api/batch/<id>` | Batch status + per-scan summary |
| `GET` | `/api/history` | Last 200 completed scans |
| `GET` | `/api/rules/stats` | IOK rule count |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/opsec/status` | VPN status |
| `POST` | `/api/opsec/rotate` | Rotate VPN server `{ country? }` |
| `POST` | `/api/opsec/connect` | Connect to country `{ country }` |
| `POST` | `/api/opsec/disconnect` | Disconnect VPN |
| `GET` | `/api/opsec/countries` | Available ProtonVPN country codes |

## Configuration

### Environment Variables

```bash
export IOK_DB=/path/to/scans.db          # SQLite database (default: ./scans.db)
export IOK_RULES=/path/to/IOK/indicators # Rules directory
export IOK_COLLECTOR=/path/to/collector  # Collector script path
export IOK_DETECTOR=/path/to/detector    # Detector script path
export IOK_WORK_DIR=/tmp/iok_web         # Temp directory for scan artifacts
export IOK_MAX_WORKERS=3                 # Default batch concurrency
export IOK_TIMEOUT=60                    # Per-URL timeout (seconds)
export PORT=5000                         # HTTP port
```

### Production Deployment

```bash
# Run as systemd service
sudo cp siem-integration/iok-api.service /etc/systemd/system/
sudo systemctl enable iok-api
sudo systemctl start iok-api
```

## Writing Custom Rules

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

## Performance

**Analysis Time (per URL):**
- Simple page: 5-10 seconds
- Complex page: 10-30 seconds

**Batch Throughput:**
- 3 workers: 6-18 URLs/minute
- 5 workers: 10-30 URLs/minute

**Resource Usage:**
- RAM: ~500MB per Chrome instance
- CPU: Moderate during analysis
- Disk: Minimal (SQLite + temp files)

## Documentation

- **[Getting Started](docs/SETUP_INSTRUCTIONS.md)** - Complete setup walkthrough
- **[SIEM Integration](docs/SIEM_INTEGRATION.md)** - Splunk & Elastic integration guide
- **[Deployment Checklist](docs/DEPLOYMENT_CHECKLIST.md)** - Step-by-step deployment tracking
- **[Quick Reference](docs/QUICK_REFERENCE.md)** - Command cheat sheet

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Contribute IOK rules to the upstream project:**
- Repository: https://github.com/phish-report/IOK
- Rule reference: https://phish.report/docs/iok-rule-reference

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

IOK rules are licensed under [ODbL](https://opendatacommons.org/licenses/odbl/) by the [phish-report/IOK](https://github.com/phish-report/IOK) project.

## Acknowledgments

- **IOK Project** - https://github.com/phish-report/IOK - Rule repository
- **Sigma** - https://github.com/SigmaHQ/sigma - Detection rule format
- **phish.report** - https://phish.report - Phishing research platform

## Resources

- [IOK Project](https://github.com/phish-report/IOK)
- [IOK Live Detections](https://phish.report/IOK)
- [IOK Rule Reference](https://phish.report/docs/iok-rule-reference)
- [Sigma Documentation](https://github.com/SigmaHQ/sigma)
- [Selenium Python](https://selenium-python.readthedocs.io/)

## Disclaimer

This tool is for security research and detection engineering purposes. Use responsibly:
- Only analyze URLs you have permission to investigate
- Run in isolated lab environment
- Be aware that visiting phishing sites may expose you to malicious content
- Follow your organization's security policies
