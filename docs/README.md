# IOK Detection Pipeline - Lab PoC

Proof of concept for detecting phishing sites using IOK (Indicator of Kit) rules.

## Quick Start

```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
python3 iok_collector.py https://example.com
python3 iok_detector.py iok_event.json IOK/indicators/
```

## Components

**iok_collector.py**: Visits URLs with headless Chrome, extracts IOK event data
**iok_detector.py**: Runs Sigma rules against collected events
**IOK/indicators/**: Rule repository (cloned during setup)

## Usage

### Collect Event Data
```bash
python3 iok_collector.py <URL> [output.json]
```

Example:
```bash
python3 iok_collector.py https://phishing-site.com phish1.json
```

### Run Detections
```bash
python3 iok_detector.py <event.json> IOK/indicators/
```

Example:
```bash
python3 iok_detector.py phish1.json IOK/indicators/
```

## IOK Event Schema

```json
{
  "title": ["Page Title"],
  "hostname": "domain.com",
  "html": "raw server HTML",
  "dom": "post-JavaScript HTML",
  "js": ["all JavaScript code"],
  "css": ["all CSS code"],
  "cookies": ["name=value"],
  "headers": ["Header: value"],
  "requests": ["https://..."]
}
```

## Detection Output

```
[!] DETECTED 2 MATCHES:
================================================================================

Title: Cazanova Phishing Kit Detection
Level: HIGH
Description: Detects Cazanova phishing kit by unique cookie name
Tags: phishing-kit, credential-harvesting, cazanova
Rule: IOK/indicators/cazanova-cookie.yml
--------------------------------------------------------------------------------
```

## Writing Custom Rules

Create `IOK/indicators/custom/my-rule.yml`:

```yaml
title: My Custom Detection
id: 12345678-1234-1234-1234-123456789012
description: Detects malicious JavaScript pattern
tags:
  - phishing-kit
detection:
  selection:
    js|contains:
      - 'eval(atob('
      - 'document.location.href'
  condition: selection
level: medium
```

## Detection Engineering Workflow

1. Collect URLs from phishing reports
2. Run collector on each URL
3. Analyze what IOK rules trigger
4. Identify patterns in undetected phishing sites
5. Write new Sigma rules for those patterns
6. Test against your collected events

## Integration Ideas

- **Batch scanning**: Process URL lists
- **SIEM forwarding**: Send detections to Splunk/ELK
- **URLScan.io**: Auto-fetch recent submissions
- **Database**: Store events in PostgreSQL
- **REST API**: Expose as web service

## Troubleshooting

**Chrome errors**: 
```bash
sudo apt-get install chromium-chromedriver
```

**Timeout issues**: Edit `iok_collector.py`, increase timeout value

**Memory**: Chrome needs ~500MB RAM per instance

## Resources

- IOK Repo: https://github.com/phish-report/IOK
- Rule Docs: https://phish.report/docs/iok-rule-reference
- Sigma: https://github.com/SigmaHQ/sigma
