#!/usr/bin/env python3
"""
IOK Data Collector - Visits URLs and extracts IOK event schema fields
"""

import json
import sys
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time
import requests
from urllib.parse import urlparse

def collect_iok_data(url, timeout=10):
    """
    Visit a URL and collect all IOK schema fields
    """
    
    # Configure headless Chrome
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
    
    # Enable network logging
    chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
    
    driver = None
    
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(timeout)
        
        # Get raw HTML from server first
        raw_html = ""
        server_headers = []
        try:
            response = requests.get(url, timeout=timeout, verify=False, 
                                   headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            raw_html = response.text
            server_headers = [f"{k}: {v}" for k, v in response.headers.items()]
        except:
            pass
        
        # Visit page with Selenium
        driver.get(url)
        time.sleep(3)  # Wait for JS
        
        # IOK Event Schema
        iok_event = {
            "title": [],
            "hostname": "",
            "html": "",
            "dom": "",
            "js": [],
            "css": [],
            "cookies": [],
            "headers": [],
            "requests": [],
            "forms": []
        }
        
        # 1. Title
        try:
            iok_event["title"].append(driver.title)
        except:
            pass
        
        # 2. Hostname
        iok_event["hostname"] = urlparse(url).netloc
        
        # 3. HTML (raw)
        iok_event["html"] = raw_html
        
        # 4. DOM (post-JS)
        try:
            iok_event["dom"] = driver.page_source
        except:
            pass
        
        # 5. JavaScript
        try:
            scripts = driver.find_elements(By.TAG_NAME, "script")
            for script in scripts:
                inline_js = script.get_attribute("innerHTML")
                if inline_js and inline_js.strip():
                    iok_event["js"].append(inline_js)
                
                src = script.get_attribute("src")
                if src:
                    try:
                        ext_js = requests.get(src, timeout=5, verify=False).text
                        iok_event["js"].append(ext_js)
                    except:
                        pass
        except:
            pass
        
        # 6. CSS
        try:
            styles = driver.find_elements(By.TAG_NAME, "style")
            for style in styles:
                css = style.get_attribute("innerHTML")
                if css and css.strip():
                    iok_event["css"].append(css)
            
            links = driver.find_elements(By.CSS_SELECTOR, "link[rel='stylesheet']")
            for link in links:
                href = link.get_attribute("href")
                if href:
                    try:
                        ext_css = requests.get(href, timeout=5, verify=False).text
                        iok_event["css"].append(ext_css)
                    except:
                        pass
        except:
            pass
        
        # 7. Cookies
        try:
            cookies = driver.get_cookies()
            for cookie in cookies:
                iok_event["cookies"].append(f"{cookie['name']}={cookie['value']}")
        except:
            pass
        
        # 8. Headers
        iok_event["headers"] = server_headers
        
        # 9. Requests (structured as dicts)
        try:
            logs = driver.get_log('performance')
            seen_urls = set()
            for log in logs:
                message = json.loads(log['message'])
                msg_method = message.get('message', {}).get('method', '')

                if msg_method == 'Network.requestWillBeSent':
                    params = message['message']['params']
                    req = params.get('request', {})
                    request_url = req.get('url', '')
                    http_method = req.get('method', 'GET')
                    if request_url and request_url not in seen_urls:
                        seen_urls.add(request_url)
                        try:
                            parsed = urlparse(request_url)
                            iok_event["requests"].append({
                                "url": request_url,
                                "method": http_method,
                                "host": parsed.netloc,
                                "path": parsed.path
                            })
                        except Exception:
                            iok_event["requests"].append({
                                "url": request_url,
                                "method": http_method,
                                "host": "",
                                "path": ""
                            })
        except:
            pass

        # 10. Forms
        try:
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                action = form.get_attribute("action") or ""
                method = (form.get_attribute("method") or "GET").upper()
                inputs = form.find_elements(By.TAG_NAME, "input")
                fields = []
                for inp in inputs:
                    name = inp.get_attribute("name")
                    if name:
                        fields.append(name)
                iok_event["forms"].append({
                    "action": action,
                    "method": method,
                    "fields": fields
                })
        except:
            pass

        return iok_event
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return None
        
    finally:
        if driver:
            driver.quit()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 iok_collector.py <URL> [output.json]")
        sys.exit(1)
    
    url = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "iok_event.json"
    
    print(f"[+] Collecting IOK data from: {url}")
    
    event = collect_iok_data(url)
    
    if event:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(event, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Saved to: {output_file}")
        print(f"[+] JS files: {len(event['js'])}, CSS files: {len(event['css'])}")
        print(f"[+] Requests: {len(event['requests'])}, Cookies: {len(event['cookies'])}")
    else:
        print("[-] Failed to collect data")
        sys.exit(1)


if __name__ == "__main__":
    main()
