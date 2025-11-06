# IOK Detection Lab - Complete Setup Package

Tyler, here's your complete IOK detection pipeline for your home lab. This is a working proof of concept that you can deploy and start using immediately.

## What You're Getting

**Core Components:**
1. **iok_collector.py** - Headless browser that visits URLs and captures all IOK event fields
2. **iok_detector.py** - Sigma rule engine that runs IOK rules against collected events  
3. **iok_batch.py** - Batch processor for scanning multiple URLs at once
4. **setup.sh** - Automated installation script
5. **urls.txt** - Example URL list for batch scanning
6. **README.md** - Quick reference guide
7. **DEPLOYMENT.md** - Complete deployment walkthrough

## Installation (5 minutes)

**On your Ubuntu VM:**

```bash
# 1. Download all files to ~/iok-lab directory
mkdir ~/iok-lab && cd ~/iok-lab

# 2. Make setup script executable
chmod +x setup.sh

# 3. Run setup (installs everything)
./setup.sh

# 4. Activate Python environment
source venv/bin/activate
```

Done! You now have a working IOK detection pipeline.

## Quick Test

```bash
# Test with a safe site
python3 iok_collector.py https://example.com test.json
python3 iok_detector.py test.json IOK/indicators/

# Should output: "No threats detected"
```

## Real World Usage

**Single URL scan:**
```bash
python3 iok_collector.py https://suspicious-site.com
python3 iok_detector.py iok_event.json IOK/indicators/
```

**Batch scanning:**
```bash
# Edit urls.txt with your URLs
nano urls.txt

# Run batch scan
python3 iok_batch.py urls.txt

# Results in batch_results/ directory
```

## What This Does for You

**Data Collection (iok_collector.py):**
- Visits URL with headless Chrome
- Captures raw HTML (before JavaScript)
- Captures DOM (after JavaScript executes)
- Extracts all JavaScript files (inline + external)
- Extracts all CSS files (inline + external)
- Records cookies, headers, network requests
- Saves everything in IOK-compatible JSON format

**Detection (iok_detector.py):**
- Loads IOK/Sigma rules from repository
- Scans collected event against all rules
- Reports matches with severity levels
- Saves detections to JSON for further analysis

**Batch Processing (iok_batch.py):**
- Processes multiple URLs from a list
- Auto-generates timestamped result files
- Creates summary report with statistics
- Shows top detection rules across all scans

## Event Schema

Every scan produces a JSON file with this structure:

```json
{
  "title": ["Page Title"],           // Page title(s)
  "hostname": "evil.com",             // Domain
  "html": "<html>raw...</html>",      // Server response
  "dom": "<html>post-js...</html>",   // After JavaScript
  "js": ["script1", "script2"],       // All JavaScript code
  "css": ["style1", "style2"],        // All CSS code  
  "cookies": ["session=abc"],         // Cookies (name=value)
  "headers": ["Server: nginx"],       // HTTP headers
  "requests": ["https://cdn..."]      // All URLs requested
}
```

## Detection Engineering Workflow

**Your typical workflow as a detection engineer:**

1. **Gather URLs**
   - Phishing reports from users
   - URLScan.io submissions  
   - Threat intel feeds
   - Your OSINT sources (URLScan, Shodan, Censys)

2. **Batch Scan**
   ```bash
   python3 iok_batch.py suspicious_urls.txt
   ```

3. **Analyze Results**
   - Review which rules triggered
   - Examine undetected samples
   - Look for patterns in the JSON events

4. **Write Custom Rules**
   - Create Sigma rule in `IOK/indicators/custom/`
   - Test against your collected events
   - Refine until accurate

5. **Deploy Detections**
   - Convert to your production format (you mentioned Sigma primarily)
   - Test in your environment
   - Monitor for false positives

## Example: Writing a Custom Rule

Let's say you found a phishing kit that uses a unique JavaScript function called `harvestCreds()`.

**Create rule:**
```bash
nano IOK/indicators/custom/harvest-creds-kit.yml
```

**Rule content:**
```yaml
title: Phishing Kit with harvestCreds Function
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects phishing kit that uses harvestCreds() JavaScript function
author: Tyler
date: 2024-10-31
tags:
  - phishing-kit
  - credential-harvesting
detection:
  selection:
    js|contains: 'harvestCreds()'
  condition: selection
level: high
```

**Test it:**
```bash
python3 iok_detector.py suspicious_phish.json IOK/indicators/
```

If your rule triggers, you'll see it in the detection output!

## Integration with Your Current Workflow

**URLScan.io Integration:**
- Find phishing submissions on URLScan
- Copy the URL
- Run through your IOK pipeline
- Compare IOK detections with URLScan's verdict

**Sigma Rule Development:**
- IOK rules ARE Sigma rules
- Study the patterns in `IOK/indicators/`
- Apply same logic to your endpoint Sigma rules
- Many phishing techniques translate to host-based TTPs

**Yara Learning:**
- IOK's string matching is similar to Yara
- Practice pattern matching with IOK first
- Transfer skills to Yara for malware analysis

## Files Explained

**iok_collector.py (185 lines)**
- Main data collection engine
- Uses Selenium WebDriver with headless Chrome
- Captures all 9 IOK schema fields
- Handles timeouts and errors gracefully
- You don't need to modify this unless you want longer timeouts

**iok_detector.py (220 lines)**
- Sigma rule matching engine
- Loads YAML rules from directory
- Supports AND/OR logic, wildcards, contains operators
- Outputs detailed detection reports
- Extensible if you want to add more Sigma features

**iok_batch.py (145 lines)**
- Batch processing wrapper
- Calls collector and detector for each URL
- Generates summary statistics
- Creates timestamped result directories
- Good starting point if you want to build automation

**setup.sh (50 lines)**
- Installs system dependencies
- Sets up Python virtual environment
- Clones IOK rules repository
- One-time setup, then you're good to go

## Troubleshooting

**"ChromeDriver not found"**
```bash
sudo apt-get install chromium-chromedriver
sudo ln -s /usr/bin/chromedriver /usr/local/bin/
```

**Timeout errors:**
Edit `iok_collector.py`, line ~15, increase timeout from 10 to 30 seconds.

**Memory issues:**
Chrome needs ~500MB per instance. Close other VMs or increase RAM.

## Next Steps

1. **Deploy to your lab VM** - Run setup.sh
2. **Test with safe sites** - example.com, httpbin.org
3. **Scan real phishing** - Use URLScan.io to find samples
4. **Study the rules** - Read IOK/indicators/ to understand patterns
5. **Write your first rule** - Detect something unique you find
6. **Integrate with your stack** - Export to Splunk/ELK/your SIEM

## Learning Path (Since You Want to Learn Coding)

**This project teaches you:**
- **Python basics** - Functions, loops, file I/O
- **Web automation** - Selenium, browser automation
- **Data processing** - JSON parsing, data structures
- **Pattern matching** - Regex, string operations
- **Sigma rules** - Detection logic, boolean operators

**How to learn from this code:**
1. Read through iok_collector.py line by line
2. Add print statements to see what each variable contains
3. Modify timeouts, user agents, see what changes
4. Write comments explaining what each function does
5. Try adding a new field to the IOK schema

**Suggested exercises:**
- Add screenshot capture to iok_collector.py
- Modify iok_detector.py to support more Sigma operators
- Build a simple Flask web UI for the pipeline
- Add SQLite database storage for results
- Create a cron job for automated scanning

## Support Resources

- **IOK Documentation**: https://phish.report/docs/iok-rule-reference
- **Sigma Docs**: https://github.com/SigmaHQ/sigma
- **Selenium Docs**: https://selenium-python.readthedocs.io/
- **Python Basics**: https://docs.python.org/3/tutorial/

## Detection Engineering Tips (From One DE to Another)

- **Start broad, refine narrow** - Initial rules can be loose, tighten based on FPs
- **Tag everything** - Good tags make hunting easier later
- **Document your logic** - Future you will thank you
- **Test on known goods** - False positive validation is critical
- **Version control your rules** - Git is your friend
- **Share with community** - IOK accepts PRs, help other DEs

## What Makes This Different from Other Tools

**vs URLScan.io:**
- You control the environment
- Access to raw event data
- Write custom detections immediately
- No rate limits

**vs Sigma CLI:**
- Purpose-built for phishing
- Captures browser-executed content
- Pre-built rule library for phishing kits
- Simpler for web-based threats

**vs Manual Analysis:**
- Automated data collection
- Consistent event schema
- Batch processing capability
- Repeatable methodology

## Final Thoughts

This is a **working proof of concept** that you can deploy today. It's designed to:
- Be easy to understand (you said you don't know coding well)
- Teach you Python through practical examples
- Integrate with your existing Sigma workflow
- Scale from single URLs to batch scanning

Start simple: scan a few URLs, look at the JSON output, run the detections. Then gradually expand: write custom rules, build automation, integrate with your tools.

The code is heavily commented and follows a clear structure. When you get stuck, the DEPLOYMENT.md file has detailed troubleshooting.

**You got this! Time to build some detections.**

-- Your AI Assistant

P.S. - Once you get comfortable with this, the next evolution is adding Binary Ninja integration for analyzing any malware dropped by phishing sites. But that's phase 2. Get this working first.
