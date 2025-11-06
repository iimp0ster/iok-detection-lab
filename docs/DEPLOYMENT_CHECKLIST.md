# IOK SIEM Integration - Deployment Checklist

Tyler, here's your complete deployment checklist. Use this to track your progress from lab PoC to production SIEM integration.

## Phase 1: Lab PoC ✓ (You've completed this)

- [x] IOK collector built
- [x] IOK detector built  
- [x] Batch processor created
- [x] Tested on safe sites
- [x] Understanding of IOK schema
- [x] Comfortable with Sigma rules

**Time invested:** ~1-2 hours
**Status:** Complete

## Phase 2: SIEM Integration (Deploy this now)

### Step 1: Deploy API Server (15 minutes)

**Pre-flight checks:**
- [ ] IOK PoC is working (can analyze URLs)
- [ ] Python 3.8+ available
- [ ] Network access from SIEM to lab VM
- [ ] Port 5000 available

**Deployment:**
```bash
cd ~/iok-lab
source venv/bin/activate
pip install flask
python3 iok_api.py
```

**Verification:**
```bash
# In another terminal
curl http://localhost:5000/health
# Should return: {"status": "healthy", ...}

curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
# Should return IOK analysis JSON
```

- [ ] API server starts without errors
- [ ] Health endpoint responds
- [ ] Test analysis completes successfully

### Step 2A: Splunk Integration (10 minutes)

**If you use Splunk:**

```bash
# 1. Copy alert action
sudo cp splunk_iok_action.py $SPLUNK_HOME/bin/scripts/iok_enrich.py
sudo chmod +x $SPLUNK_HOME/bin/scripts/iok_enrich.py
sudo chown splunk:splunk $SPLUNK_HOME/bin/scripts/iok_enrich.py

# 2. Edit configuration
sudo nano $SPLUNK_HOME/bin/scripts/iok_enrich.py
# Change: IOK_API_URL = "http://your-iok-server:5000"

# 3. Test from Splunk
# Run this search:
index=_internal | head 1 | eval url="https://example.com" | script iok_enrich.py url=$url$
```

**Verification:**
- [ ] Script copied to Splunk
- [ ] API URL configured
- [ ] Test search returns iok_analyzed field
- [ ] No errors in splunkd.log

### Step 2B: Elastic Integration (10 minutes)

**If you use Elastic:**

```bash
# 1. Install enrichment script
sudo cp elastic_iok_enrich.py /usr/local/bin/
sudo chmod +x /usr/local/bin/elastic_iok_enrich.py

# 2. Install dependencies
pip3 install elasticsearch requests

# 3. Configure
sudo nano /usr/local/bin/elastic_iok_enrich.py
# Set: IOK_API_URL, ES_HOST

# 4. Test
/usr/local/bin/elastic_iok_enrich.py --url https://example.com --json

# 5. Deploy watcher
curl -X PUT "localhost:9200/_watcher/watch/iok_phishing_detection" \
  -H "Content-Type: application/json" \
  -d @elastic_watcher_iok.json
```

**Verification:**
- [ ] Script runs successfully
- [ ] Can connect to Elasticsearch
- [ ] Watcher created (check Kibana)
- [ ] Test URL analysis works

### Step 3: Production Deployment (20 minutes)

**Make API server persistent:**

```bash
# Create systemd service
sudo nano /etc/systemd/system/iok-api.service
# Copy content from SIEM_INTEGRATION.md

sudo systemctl daemon-reload
sudo systemctl enable iok-api
sudo systemctl start iok-api
sudo systemctl status iok-api
```

**Verification:**
- [ ] Service starts on boot
- [ ] No errors in journal: `sudo journalctl -u iok-api -f`
- [ ] API responds after reboot

### Step 4: Integration Testing (15 minutes)

**End-to-end test:**

1. **Generate test event in SIEM:**
```bash
# Splunk: Manually create event with suspicious URL
# Elastic: POST test document to proxy index
```

2. **Verify SIEM triggers IOK:**
```bash
# Watch API logs
sudo journalctl -u iok-api -f
# Should see analysis request
```

3. **Check enriched data in SIEM:**
```bash
# Splunk: Search for iok_analyzed=true
# Elastic: Query iok-detections index
```

**Verification checklist:**
- [ ] SIEM sends URL to API
- [ ] API logs show analysis request
- [ ] Analysis completes (check /tmp/iok_analysis/)
- [ ] SIEM receives enriched data
- [ ] Alert/event shows IOK fields

## Phase 3: Tuning & Optimization (Ongoing)

### Week 1: Baseline

- [ ] Monitor API performance (queue size, response time)
- [ ] Check for errors in API logs
- [ ] Verify all suspicious URLs are analyzed
- [ ] Document baseline metrics

**Metrics to track:**
- URLs analyzed per day: _____
- Average analysis time: _____
- Detection rate: _____% 
- False positive rate: _____% (if known)

### Week 2: Custom Rules

- [ ] Review undetected phishing samples
- [ ] Identify common patterns
- [ ] Write 2-3 custom IOK rules
- [ ] Test rules against collected events
- [ ] Validate no false positives

**Custom rules written:**
1. _____________________
2. _____________________
3. _____________________

### Week 3: SIEM Optimization

- [ ] Create dashboard for IOK detections
- [ ] Set up alerting on high-severity matches
- [ ] Configure notification rules
- [ ] Document investigation procedures

**SIEM artifacts created:**
- [ ] Dashboard showing daily detection counts
- [ ] Alert for critical-level detections
- [ ] Report of top phishing kits detected
- [ ] Runbook for analysts

### Week 4: Scaling Assessment

- [ ] Review API performance under load
- [ ] Identify bottlenecks
- [ ] Plan scaling if needed (more workers/servers)
- [ ] Document lessons learned

**Performance evaluation:**
- Current throughput: _____ URLs/min
- Peak queue size: _____
- 95th percentile analysis time: _____ seconds
- Scaling needed? Yes / No

## Troubleshooting Checklist

**API not responding:**
- [ ] Check if service is running: `systemctl status iok-api`
- [ ] Check logs: `journalctl -u iok-api -f`
- [ ] Test health endpoint: `curl http://localhost:5000/health`
- [ ] Verify port is open: `netstat -tulpn | grep 5000`

**SIEM can't reach API:**
- [ ] Test connectivity: `curl http://iok-server:5000/health`
- [ ] Check firewall rules
- [ ] Verify API URL in integration scripts
- [ ] Check network routing

**Slow analysis times:**
- [ ] Check Chrome/ChromeDriver version
- [ ] Increase timeout: `export IOK_TIMEOUT=120`
- [ ] Add more workers: `export IOK_MAX_WORKERS=5`
- [ ] Review complex pages (lots of JS/requests)

**No detections triggering:**
- [ ] Verify IOK rules loaded: `curl http://localhost:5000/rules/stats`
- [ ] Test manually: `python3 iok_detector.py event.json IOK/indicators/`
- [ ] Check rule syntax in custom rules
- [ ] Review event JSON for expected fields

## Success Criteria

**You'll know it's working when:**

✅ **Automated Analysis**
- SIEM automatically triggers IOK on suspicious URLs
- No manual intervention required
- Results appear in SIEM within 30 seconds

✅ **Enriched Alerts**
- Alerts include IOK detection count
- Threat level is visible
- Phishing kit identification present
- Full IOK context available for investigation

✅ **Time Savings**
- Initial triage: 5-10 minutes (was 20-30)
- Analyst can see IOK verdict immediately
- Investigation starts with IOK data, not from scratch

✅ **Detection Coverage**
- 500+ IOK rules running automatically
- Custom rules for your environment
- New phishing kits detected quickly

## Files Reference

**Core Integration (Deploy these):**
- `iok_api.py` - API server
- `splunk_iok_action.py` - Splunk script
- `elastic_iok_enrich.py` - Elastic script
- `elastic_watcher_iok.json` - Watcher config
- `requirements_siem.txt` - Dependencies

**Documentation (Read these):**
- `SIEM_INTEGRATION_SUMMARY.md` - Overview (start here)
- `SIEM_INTEGRATION.md` - Detailed guide
- `QUICK_REFERENCE.md` - Command reference

**Original PoC (Already deployed):**
- `iok_collector.py`
- `iok_detector.py`
- `iok_batch.py`
- `setup.sh`

## Timeline Estimate

**Total deployment time: ~1-2 hours**

- API server setup: 15 min
- SIEM integration: 10-20 min (depends on which SIEM)
- Production hardening: 20 min
- Testing: 15 min
- Documentation: 15 min

**To production-ready: 2-3 weeks**

- Week 1: Deploy and validate
- Week 2: Custom rules and tuning
- Week 3: SIEM optimization
- Week 4: Scale and expand

## Next Actions (In Order)

**Right now (30 minutes):**
1. [ ] Read SIEM_INTEGRATION_SUMMARY.md
2. [ ] Deploy API server: `python3 iok_api.py`
3. [ ] Test health endpoint
4. [ ] Test single URL analysis

**Today (1 hour):**
5. [ ] Deploy SIEM integration (Splunk OR Elastic)
6. [ ] End-to-end test
7. [ ] Verify enrichment works
8. [ ] Check logs for errors

**This week:**
9. [ ] Make API service persistent (systemd)
10. [ ] Monitor for 24-48 hours
11. [ ] Create first custom IOK rule
12. [ ] Document your environment specifics

**This month:**
13. [ ] Write 5+ custom rules
14. [ ] Build SIEM dashboard
15. [ ] Train analysts on new workflow
16. [ ] Measure time savings

## Support

**If you get stuck:**

1. **Check the docs:**
   - SIEM_INTEGRATION.md (detailed guide)
   - QUICK_REFERENCE.md (common commands)

2. **Review logs:**
   - API: `journalctl -u iok-api -f`
   - Event files: `/tmp/iok_analysis/`
   - SIEM logs (depends on your SIEM)

3. **Test components individually:**
   - IOK collector: `python3 iok_collector.py https://example.com`
   - IOK detector: `python3 iok_detector.py event.json IOK/indicators/`
   - API: `curl http://localhost:5000/health`

4. **Common issues documented in:**
   - SIEM_INTEGRATION.md (Troubleshooting section)

## Final Validation

**Before marking complete, verify:**

- [ ] API server running persistently
- [ ] SIEM can reach API
- [ ] Test URL analyzed successfully
- [ ] Enriched data appears in SIEM
- [ ] Logs show no errors
- [ ] Documentation updated for your environment
- [ ] Analysts trained on new workflow

## You're Ready When...

✅ User reports phishing → SIEM enriches with IOK → Alert shows detections
✅ You can write custom rule → Restart API → See it trigger
✅ Analyst opens alert → IOK analysis already done → Quick validation

**That's the goal. Let's get there!**

---

**Current Status:** [ ] Not Started | [ ] In Progress | [ ] Complete
**Date Started:** ___________
**Date Completed:** ___________
**Notes:**
