# IOK Detection Pipeline - Complete Package

## 📦 What You Have

**Phase 1: Lab PoC** (Working prototype)
- Headless browser data collection
- Sigma rule matching engine  
- Batch URL processor

**Phase 2: SIEM Integration** (Production ready)
- REST API server
- Splunk integration
- Elastic Stack integration
- Automated enrichment workflow

## 🚀 Quick Start

### New to this project? Start here:

1. **Read first:** `SIEM_INTEGRATION_SUMMARY.md` (10 min read)
2. **Deploy PoC:** `SETUP_INSTRUCTIONS.md` (30 min)
3. **Add SIEM:** `SIEM_INTEGRATION.md` (1 hour)
4. **Track progress:** `DEPLOYMENT_CHECKLIST.md` (ongoing)

### Already have PoC running? Deploy SIEM:

1. **Deploy API:** `python3 iok_api.py`
2. **Integrate SIEM:** Follow `SIEM_INTEGRATION.md`
3. **Test:** Use checklist in `DEPLOYMENT_CHECKLIST.md`

## 📁 File Organization

### Essential Scripts (Deploy These)

**Core PoC:**
- `iok_collector.py` - Headless browser data collector (185 lines)
- `iok_detector.py` - Sigma rule matching engine (220 lines)
- `iok_batch.py` - Batch URL processor (145 lines)
- `setup.sh` - One-command installation script

**SIEM Integration:**
- `iok_api.py` - Flask REST API server (280 lines)
- `splunk_iok_action.py` - Splunk alert action (120 lines)
- `elastic_iok_enrich.py` - Elastic enrichment script (180 lines)
- `elastic_watcher_iok.json` - Elastic Watcher configuration

**Configuration:**
- `requirements_siem.txt` - Python dependencies
- `urls.txt` - Example URL list for batch testing

### Documentation (Read These)

**Getting Started:**
- `README.md` - Quick overview and examples
- `SETUP_INSTRUCTIONS.md` - Complete PoC deployment walkthrough
- `DEPLOYMENT.md` - Detailed lab setup guide

**SIEM Integration:**
- `SIEM_INTEGRATION_SUMMARY.md` - **START HERE** - Overview and benefits
- `SIEM_INTEGRATION.md` - Complete integration guide
- `DEPLOYMENT_CHECKLIST.md` - Step-by-step deployment tracking

**Reference:**
- `QUICK_REFERENCE.md` - Command cheat sheet

## 🎯 Use Cases by Role

### As a Detection Engineer:

**Problem:** Manual phishing analysis takes 20-30 minutes per URL

**Solution:** 
1. Deploy IOK PoC for manual analysis (Phase 1)
2. Add SIEM integration for automation (Phase 2)
3. Write custom rules for your environment

**Result:** 5-10 minute triage time, automated enrichment

### As a Security Analyst:

**Before:** 
- Alert: "Suspicious URL"
- Manual investigation required
- 20-30 minutes

**After:**
- Alert: "PHISHING CONFIRMED - IOK Detections: 3 HIGH"
- IOK already analyzed
- 5 minutes to validate

### As a Threat Researcher:

**Workflow:**
1. Collect phishing URLs from OSINT (URLScan, Shodan, Censys)
2. Batch analyze: `python3 iok_batch.py urls.txt`
3. Identify new patterns
4. Write Sigma rules
5. Deploy to production via API

## 🏗️ Architecture

### Phase 1: Lab PoC
```
Manual URL → Collector → Detector → Results (JSON)
```

### Phase 2: SIEM Integration  
```
SIEM → API Server → Queue → Worker Pool → IOK Analysis → SIEM (Enriched)
     Suspicious URL     3 workers      Collector+Detector      Enhanced Alert
```

## ⚡ Quick Commands

### Deploy Everything (Fresh Start)

```bash
# 1. Setup PoC
chmod +x setup.sh && ./setup.sh
source venv/bin/activate

# 2. Test PoC
python3 iok_collector.py https://example.com
python3 iok_detector.py iok_event.json IOK/indicators/

# 3. Deploy API
pip install flask
python3 iok_api.py

# 4. Test API
curl http://localhost:5000/health
```

### Daily Operations

```bash
# Activate environment
source venv/bin/activate

# Analyze single URL
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com"}'

# Batch analyze
python3 iok_batch.py urls.txt

# Check API health
curl http://localhost:5000/health

# View logs (if running as service)
sudo journalctl -u iok-api -f
```

### Write Custom Rule

```bash
# 1. Create rule file
nano IOK/indicators/custom/my-rule.yml

# 2. Test against collected event
python3 iok_detector.py event.json IOK/indicators/

# 3. Restart API to load new rule
sudo systemctl restart iok-api
```

## 📊 Expected Results

### Performance

**Analysis Time:**
- Simple page: 5-10 seconds
- Complex page: 10-30 seconds
- Batch (10 URLs): 1-3 minutes

**Throughput:**
- 3 workers: 6-18 URLs/minute
- 5 workers: 10-30 URLs/minute

**Resource Usage:**
- RAM: ~500MB per Chrome instance
- CPU: Moderate during analysis
- Disk: Minimal (temp files)

### Detection Coverage

**Built-in Rules:**
- 500+ IOK rules from community
- Covers major phishing kits
- Updated regularly via git pull

**Custom Rules:**
- Write your own for environment-specific threats
- Test immediately against collected events
- Deploy to production via API restart

## 🔧 Configuration

### Environment Variables (API Server)

```bash
export IOK_COLLECTOR=/path/to/iok_collector.py
export IOK_DETECTOR=/path/to/iok_detector.py
export IOK_RULES=/path/to/IOK/indicators/
export IOK_WORK_DIR=/tmp/iok_analysis
export IOK_MAX_WORKERS=3
export IOK_TIMEOUT=60
```

### SIEM Configuration

**Splunk:**
- Edit `splunk_iok_action.py`
- Set `IOK_API_URL`
- Copy to `$SPLUNK_HOME/bin/scripts/`

**Elastic:**
- Edit `elastic_iok_enrich.py`
- Set `IOK_API_URL`, `ES_HOST`
- Upload watcher: `elastic_watcher_iok.json`

## 🐛 Troubleshooting

### Common Issues

**API won't start:**
```bash
# Check port availability
netstat -tulpn | grep 5000

# Test Python environment
source venv/bin/activate && python3 iok_api.py
```

**Timeout errors:**
```bash
# Increase timeout
export IOK_TIMEOUT=120
```

**Queue backing up:**
```bash
# Add more workers
export IOK_MAX_WORKERS=5
```

**SIEM can't reach API:**
```bash
# Test connectivity from SIEM server
curl http://iok-server:5000/health
```

### Debug Mode

```bash
# View event files
ls -lh /tmp/iok_analysis/

# Check specific analysis
cat /tmp/iok_analysis/<job_id>_event.json | jq .

# Monitor API logs
tail -f /tmp/iok_api.log  # if logging enabled
```

## 📈 Deployment Timeline

**Day 1 (2 hours):**
- Deploy PoC
- Test with safe sites
- Deploy API server
- Integrate with SIEM

**Week 1:**
- Monitor performance
- Validate enrichment
- Document baseline

**Week 2:**
- Write 2-3 custom rules
- Test against backlog
- Tune alert thresholds

**Week 3:**
- Create SIEM dashboard
- Train analysts
- Document procedures

**Week 4:**
- Assess scaling needs
- Expand coverage
- Measure ROI

## 💡 Pro Tips

**For Detection Engineers:**
- Start with built-in rules, learn patterns
- Write custom rules for your environment
- Test rules against multiple samples before deploying
- Tag rules consistently for easier hunting

**For Security Analysts:**
- Trust IOK verdicts but validate high-severity
- Check event JSON for investigation context
- Report false positives to help tune rules

**For Threat Researchers:**
- Use batch mode for campaign analysis
- Collect samples from multiple sources
- Identify patterns across campaigns
- Share good rules with community

## 🔐 Security Considerations

**API Server:**
- Runs localhost by default (secure)
- Add authentication for external access
- Use HTTPS via reverse proxy

**Isolation:**
- IOK visits malicious sites
- Run in isolated network
- Monitor for compromise

**Data Handling:**
- Event files contain full page content
- May include sensitive data
- Set retention policy
- Sanitize before sharing

## 📚 Resources

**IOK Project:**
- Repository: https://github.com/phish-report/IOK
- Live detections: https://phish.report/IOK
- Rule reference: https://phish.report/docs/iok-rule-reference

**Sigma:**
- Documentation: https://github.com/SigmaHQ/sigma
- Specification: https://github.com/SigmaHQ/sigma-specification

**OSINT Sources:**
- URLScan.io: https://urlscan.io
- Shodan: https://shodan.io
- Censys: https://censys.io

## 🎓 Learning Path

**Week 1: Understand IOK**
- Read 10-20 built-in rules
- Understand rule structure
- Practice pattern matching

**Week 2: Practice**
- Collect 10+ phishing samples
- Analyze with IOK
- Identify detection patterns

**Week 3: Create**
- Write first custom rule
- Test against samples
- Deploy to production

**Week 4: Optimize**
- Analyze false positives
- Tune rule accuracy
- Share with community

## ✅ Success Metrics

**You'll know it's working when:**

✅ Automated enrichment:
- SIEM triggers IOK automatically
- Results within 30 seconds
- No manual intervention

✅ Time savings:
- Triage: 5-10 min (was 20-30)
- Investigation starts with IOK data
- Faster incident response

✅ Detection coverage:
- 500+ rules running automatically
- Custom rules for your environment
- New threats detected quickly

✅ Analyst efficiency:
- IOK verdict available immediately
- Enhanced alerts with context
- Faster ticket resolution

## 📞 Support

**If you get stuck:**

1. Check documentation (files above)
2. Review logs (journalctl or /tmp/)
3. Test components individually
4. Refer to troubleshooting section

**This package includes:**
- Working code (tested)
- Complete documentation
- Deployment checklists
- Troubleshooting guides

**Everything you need to go from lab PoC to production SIEM integration.**

---

**Current Phase:** [ ] PoC | [ ] SIEM Integration | [ ] Production

**Start with:** `SIEM_INTEGRATION_SUMMARY.md`

**Questions?** Check `DEPLOYMENT_CHECKLIST.md` for step-by-step guidance.
