# IOK SIEM Integration - Complete Package

Tyler, here's your complete SIEM integration for the IOK detection pipeline. This takes your PoC to production by connecting it to your SIEM.

## What's New

**SIEM Integration Components:**
1. **iok_api_server.py** - Flask REST API that SIEMs can call
2. **splunk_integration.py** - Splunk alert action for automated analysis
3. **elastic_integration.py** - Elastic watcher integration
4. **siem_forwarder.py** - Generic CEF/Syslog forwarder (ArcSight, QRadar, etc.)
5. **test_siem_integration.py** - End-to-end test suite
6. **SIEM_INTEGRATION.md** - Complete deployment guide
7. **requirements_siem.txt** - Additional dependencies

## How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│    SIEM     │────────▶│   IOK API    │────────▶│ IOK PoC     │
│             │  POST   │   (Flask)    │  calls  │ Components  │
│ Detects     │  /api/  │              │         │             │
│ Suspicious  │  analyze│ Orchestrates │         │ collector + │
│ URL         │         │ Analysis     │         │ detector    │
└─────────────┘         └──────────────┘         └─────────────┘
                               │
                               │ Returns
                               ▼
                    ┌────────────────────┐
                    │ IOK Detections     │
                    │ (Enriched Event)   │
                    └────────────────────┘
                               │
                               │ Forward
                               ▼
                    ┌────────────────────┐
                    │ Back to SIEM       │
                    │ (HEC/CEF/Syslog)   │
                    └────────────────────┘
```

## Quick Start (5 Minutes)

### Step 1: Install Dependencies

```bash
cd ~/iok-lab
source venv/bin/activate
pip install -r requirements_siem.txt
```

### Step 2: Start API Server

```bash
# Update paths in iok_api_server.py (lines 15-17)
nano iok_api_server.py

# Set these to your actual paths:
IOK_COLLECTOR = "/home/youruser/iok-lab/iok_collector.py"
IOK_DETECTOR = "/home/youruser/iok-lab/iok_detector.py"
IOK_RULES_DIR = "/home/youruser/iok-lab/IOK/indicators/"

# Start server
python3 iok_api_server.py &
```

### Step 3: Test It Works

```bash
# Run test suite
python3 test_siem_integration.py

# Should show all tests passing:
# ✓ IOK Collector
# ✓ IOK Detector
# ✓ API Server
# ✓ API Analysis
# ✓ Splunk Integration
# ✓ SIEM Forwarder
```

### Step 4: Integrate with Your SIEM

Pick your SIEM and follow the guide:

**Splunk:**
```bash
# Copy alert action to Splunk
cp splunk_integration.py /opt/splunk/bin/scripts/

# Edit config (API URL, HEC token)
nano /opt/splunk/bin/scripts/splunk_integration.py

# Create alert in Splunk UI that calls this script
```

**Elastic:**
```bash
# Test integration
python3 elastic_integration.py https://example.com

# Create watcher (see SIEM_INTEGRATION.md)
```

**Other SIEMs (ArcSight, QRadar, etc.):**
```bash
# Forward via CEF or Syslog
python3 siem_forwarder.py https://phishing.com \
  --siem-host your-siem.com \
  --format cef
```

## API Endpoints

### POST /api/analyze
Analyze a URL and return IOK detections.

**Request:**
```json
{
  "url": "https://suspicious-site.com",
  "request_id": "optional-tracking-id"
}
```

**Response:**
```json
{
  "status": "success",
  "url": "https://suspicious-site.com",
  "detection_count": 2,
  "max_severity": "high",
  "rule_titles": ["Phishing Kit A", "Generic Credential Harvester"],
  "detections": [
    {
      "rule_id": "abc123",
      "title": "Phishing Kit A",
      "level": "high",
      "description": "Detects Phishing Kit A by JS signature",
      "tags": ["phishing-kit", "credential-harvesting"]
    }
  ],
  "event_metadata": {
    "hostname": "suspicious-site.com",
    "title": ["Fake Login Page"],
    "js_count": 3,
    "css_count": 2,
    "request_count": 15
  },
  "collection_time": 3.2,
  "detection_time": 0.8
}
```

### GET /api/health
Health check endpoint.

### GET /api/stats  
Get API statistics.

## Integration Patterns

### Pattern 1: SIEM Alert → API → Enrichment

**Use Case:** SIEM detects suspicious URL in logs, triggers IOK analysis, gets enriched event back.

**Flow:**
1. SIEM correlation rule fires on suspicious URL
2. SIEM calls IOK API
3. API runs collector + detector
4. API returns detections
5. SIEM creates incident with IOK context

**Best For:** Splunk, Elastic with webhooks

### Pattern 2: Batch Analysis → Forward

**Use Case:** Queue of suspicious URLs analyzed periodically, results sent to SIEM.

**Flow:**
1. URLs collected in queue (from threat feeds, reports, etc.)
2. Batch processor analyzes via API
3. Results forwarded to SIEM in CEF/Syslog
4. SIEM ingests as new events

**Best For:** ArcSight, QRadar, LogRhythm

### Pattern 3: Real-Time Stream

**Use Case:** Network tap/proxy streams URLs, immediate analysis, blocking.

**Flow:**
1. Proxy forwards suspicious URLs to API
2. Real-time analysis
3. High-severity detections trigger block
4. All results logged to SIEM

**Best For:** Network security tools + SIEM

## Detection Engineering Workflow

**With SIEM integration, your workflow becomes:**

1. **Automated Detection**
   - SIEM detects suspicious URLs from logs
   - Automatically triggers IOK analysis
   - No manual URL submission needed

2. **Enriched Alerts**
   - SIEM alerts include full IOK context
   - Detection names, severity, indicators
   - Faster triage and response

3. **Pattern Discovery**
   - Review SIEM dashboards for IOK trends
   - Identify phishing campaigns
   - Write custom rules for gaps

4. **Continuous Improvement**
   - Test rules against SIEM data
   - Tune thresholds to reduce FPs
   - Scale detection coverage

## Example SIEM Queries

### Splunk

```spl
# Show all IOK detections
index=main sourcetype="iok:detection"
| stats count by max_severity
| sort -count

# High severity phishing
index=main sourcetype="iok:detection" iok_status="detected" max_severity="high"
| table _time url detection_count rule_titles
| sort -_time

# Detection frequency by rule
index=main sourcetype="iok:detection"
| mvexpand rule_titles
| stats count by rule_titles
| sort -count
```

### Elastic

```json
GET iok-detections-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"match": {"iok.status": "success"}},
        {"range": {"iok.detection_count": {"gt": 0}}}
      ]
    }
  },
  "aggs": {
    "by_severity": {
      "terms": {"field": "iok.max_severity"}
    }
  }
}
```

## Performance Tuning

### Increase Timeout
```python
# In iok_api_server.py, line 16
TIMEOUT = 60  # Increase from 30 for slow sites
```

### Concurrent Analyses
```python
# Add to iok_api_server.py
from threading import Semaphore
analysis_semaphore = Semaphore(3)  # Max 3 concurrent analyses

def analyze_url(url, request_id):
    with analysis_semaphore:
        # ... existing code
```

### Rate Limiting
```python
# Add to iok_api_server.py
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")  # Limit requests
def api_analyze():
    # ... existing code
```

## Troubleshooting

### API Server Won't Start
```bash
# Check if port 5000 is in use
sudo lsof -i :5000

# Use different port
python3 iok_api_server.py --port 5001
```

### ChromeDriver Crashes
```bash
# Increase VM memory
# Or reduce concurrent analyses (see Performance Tuning)
```

### SIEM Not Receiving Events
```bash
# Test network connectivity
telnet siem.company.com 514

# Check firewall
sudo iptables -L -n | grep 514

# Verify SIEM logs for dropped events
```

### Timeout Errors
```bash
# Increase timeout (see Performance Tuning)
# Or investigate slow phishing sites
```

## Production Deployment

### Run as Systemd Service

```bash
sudo nano /etc/systemd/system/iok-api.service

[Unit]
Description=IOK Phishing Detection API
After=network.target

[Service]
Type=simple
User=iok
WorkingDirectory=/opt/iok
ExecStart=/opt/iok/venv/bin/python3 /opt/iok/iok_api_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

sudo systemctl enable iok-api
sudo systemctl start iok-api
```

### Behind Nginx (HTTPS)

```nginx
server {
    listen 443 ssl;
    server_name iok-api.company.com;
    
    ssl_certificate /etc/ssl/certs/iok.crt;
    ssl_certificate_key /etc/ssl/private/iok.key;
    
    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Add Authentication

```python
# In iok_api_server.py
from functools import wraps

API_KEY = "your-secret-key-here"

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if key != API_KEY:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/analyze', methods=['POST'])
@require_api_key
def api_analyze():
    # ... existing code
```

## Next Steps

1. **Deploy API server** - Run test_siem_integration.py
2. **Choose SIEM integration** - Splunk, Elastic, or generic
3. **Configure SIEM rules** - Detect suspicious URLs
4. **Test end-to-end** - Trigger analysis from SIEM
5. **Monitor and tune** - Watch for detections, adjust rules
6. **Scale up** - Add more workers, monitoring, alerting

## Files Summary

| File | Purpose | Lines |
|------|---------|-------|
| iok_api_server.py | REST API server | 180 |
| splunk_integration.py | Splunk alert action | 160 |
| elastic_integration.py | Elastic watcher | 180 |
| siem_forwarder.py | CEF/Syslog forwarder | 260 |
| test_siem_integration.py | Test suite | 260 |

**Total: ~1,040 lines of production-ready integration code**

## Learning Opportunities

This code teaches:
- **REST APIs** - Flask web framework
- **SIEM integration** - CEF, Syslog, HEC formats
- **Error handling** - Timeouts, retries, validation
- **Production patterns** - Logging, monitoring, security
- **Async operations** - Webhooks, callbacks

As you mentioned wanting to learn coding - this is real production code. Read through it, modify it, break it, fix it. That's how you learn.

---

**You now have a complete SIEM-integrated phishing detection pipeline!**
