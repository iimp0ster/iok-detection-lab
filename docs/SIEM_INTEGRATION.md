# IOK SIEM Integration Guide

Complete guide for integrating IOK detection with Splunk and Elastic Stack.

## Architecture

```
SIEM (Splunk/Elastic)
    ↓ Suspicious URL detected
    ↓ HTTP POST
IOK API Server (Flask)
    ↓ Queue request
    ↓ Process with workers
IOK Collector + Detector (Your PoC)
    ↓ Return enriched results
Back to SIEM (Enhanced alert)
```

## What You Get

**Before Integration:**
- SIEM alert: "Suspicious URL detected: https://phishing-site.com"
- Investigation required: Is it actually phishing?

**After Integration:**
- SIEM alert: "PHISHING DETECTED: https://phishing-site.com"
  - IOK Detections: 3
  - Threat Level: HIGH
  - Phishing Kit: Cazanova v2
  - Tags: credential-harvesting, microsoft-impersonation
- Investigation automated: IOK already analyzed it

## Components

**iok_api.py** - Flask REST API server
- Exposes `/analyze` endpoint
- Manages worker queue
- Returns enriched results

**splunk_iok_action.py** - Splunk integration
- Alert action script
- Calls API and enriches events

**elastic_iok_enrich.py** - Elastic integration
- Enrichment script for ES
- Can run from Watcher or standalone

**elastic_watcher_iok.json** - Watcher config
- Automated detection workflow

## Installation

### Step 1: Deploy API Server

**On your IOK lab VM:**

```bash
cd ~/iok-lab
source venv/bin/activate

# Install Flask
pip install flask

# Test API
python3 iok_api.py
```

**Test it:**
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Step 2A: Splunk Integration

```bash
# Copy script
sudo cp splunk_iok_action.py $SPLUNK_HOME/bin/scripts/iok_enrich.py
sudo chmod +x $SPLUNK_HOME/bin/scripts/iok_enrich.py

# Edit to set your API URL
sudo nano $SPLUNK_HOME/bin/scripts/iok_enrich.py
# Change: IOK_API_URL = "http://your-iok-server:5000"
```

**Create Splunk search:**
```spl
index=proxy status=200 reputation="suspicious"
| script iok_enrich.py url=$url$
| where iok_detection_count > 0
```

### Step 2B: Elastic Integration

```bash
# Install script
sudo cp elastic_iok_enrich.py /usr/local/bin/
sudo chmod +x /usr/local/bin/elastic_iok_enrich.py
pip3 install elasticsearch requests

# Edit configuration
sudo nano /usr/local/bin/elastic_iok_enrich.py
```

**Create Watcher:**
```bash
curl -X PUT "localhost:9200/_watcher/watch/iok_detection" \
  -H "Content-Type: application/json" \
  -d @elastic_watcher_iok.json
```

## Usage

### API Endpoints

**Analyze single URL (sync):**
```bash
curl -X POST http://localhost:5000/analyze \
  -d '{"url": "https://site.com"}'
```

**Analyze async:**
```bash
curl -X POST http://localhost:5000/analyze \
  -d '{"url": "https://site.com", "async": true}'
  
# Returns job_id, check status:
curl http://localhost:5000/status/{job_id}
```

**Batch analyze:**
```bash
curl -X POST http://localhost:5000/batch \
  -d '{"urls": ["https://site1.com", "https://site2.com"]}'
```

**Health check:**
```bash
curl http://localhost:5000/health
```

### Splunk Examples

**View enriched events:**
```spl
index=proxy iok_analyzed="true"
| stats count by iok_threat_level
```

**Find detections:**
```spl
index=proxy iok_detection_count>0
| table _time, url, iok_threat_level, iok_detections
```

### Elastic Examples

**Query detections:**
```json
GET /iok-detections/_search
{
  "query": {
    "range": {"iok.detection_count": {"gt": 0}}
  }
}
```

## Production Deployment

**Run as systemd service:**

Create `/etc/systemd/system/iok-api.service`:
```ini
[Unit]
Description=IOK API Server
After=network.target

[Service]
Type=simple
User=iok
WorkingDirectory=/opt/iok-lab
Environment="PATH=/opt/iok-lab/venv/bin"
ExecStart=/opt/iok-lab/venv/bin/python3 iok_api.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable iok-api
sudo systemctl start iok-api
```

## Detection Engineering Workflow

**Daily routine:**

1. **Morning: Check overnight detections**
```spl
index=proxy earliest=-24h iok_detection_count>0
| stats count by iok_detections
```

2. **Investigate new patterns**
```bash
# Find undetected phishing
# Manually analyze
curl -X POST http://localhost:5000/analyze -d '{"url":"..."}'
```

3. **Write custom rules**
```bash
nano IOK/indicators/custom/new-campaign.yml
# Restart API to load new rules
sudo systemctl restart iok-api
```

4. **Validate against backlog**
```bash
curl -X POST http://localhost:5000/batch -d '{"urls":[...]}'
```

## Troubleshooting

**API not responding:**
```bash
curl http://localhost:5000/health
sudo systemctl status iok-api
sudo journalctl -u iok-api -f
```

**Timeouts:**
```bash
# Increase timeout in iok_api.py
export IOK_TIMEOUT=120
```

**Queue backup:**
```bash
# Increase workers
export IOK_MAX_WORKERS=5
```

## Performance

**Typical analysis:** 5-30 seconds per URL
**Throughput:** 6-18 URLs/minute (3 workers)
**Resources:** ~500MB RAM per Chrome instance

**Scaling:**
- Increase workers for more throughput
- Run multiple API servers (load balance)
- Cache results for duplicate URLs

## Security

**API Security:**
- Runs localhost by default
- Add auth for external access
- Use HTTPS via reverse proxy

**Isolation:**
- IOK visits malicious sites
- Run in isolated network
- Monitor for compromise

**Data retention:**
- Event files contain full page content
- Set retention policy
- Sanitize before sharing

## Next Steps

1. **Test:** Submit URL through SIEM, verify enrichment
2. **Tune:** Adjust queries to reduce false positives
3. **Customize:** Write rules for your environment
4. **Monitor:** Watch performance and queue
5. **Scale:** Add workers or servers as needed
