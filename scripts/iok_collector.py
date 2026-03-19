#!/usr/bin/env python3
"""
IOK Data Collector - Visits URLs and extracts IOK event schema fields.

Integrates with OpsecManager for proxy routing, UA rotation, and
anti-fingerprinting.  Returns a structured dict on every code path —
callers never receive None.
"""

import json
import socket
import sys
import time
from urllib.parse import urlparse

import requests
import requests.exceptions
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

from core.ua_pool import get_random_ua as _get_random_ua

_SOCKS5_PROXY = "socks5h://127.0.0.1:1080"


def _empty_event(url: str) -> dict:
    """Return a zeroed-out IOK event dict for the given URL."""
    return {
        "title": [],
        "hostname": urlparse(url).netloc,
        "html": "",
        "dom": "",
        "js": [],
        "css": [],
        "cookies": [],
        "headers": [],
        "requests": [],
        "forms": [],
    }


def _error_event(url: str, error_type: str, message: str) -> dict:
    """Return a structured failure dict with error metadata."""
    event = _empty_event(url)
    event.update({"url": url, "error": True, "error_type": error_type, "error_message": message})
    return event


def collect_iok_data(url, proxy_args=None, ua=None, delay_ms=0, timeout=10) -> dict:
    """
    Visit a URL and collect all IOK schema fields.

    Args:
        url:        Target URL to collect data from.
        proxy_args: List of Chrome argument strings (e.g. from
                    OpsecManager.get_chromium_args()).  None = no proxy.
        ua:         User-Agent string override.  None = random UA from pool.
        delay_ms:   Milliseconds to wait after page load for JS execution.
                    0 = no extra wait.
        timeout:    Selenium page-load and requests timeout in seconds.

    Returns:
        IOK event dict.  Always a dict — never None.
        On failure the dict contains "error": True, "error_type": str,
        "error_message": str alongside zeroed-out schema fields.
        error_type values: "timeout" | "connection" | "blocked"
    """

    # Resolve UA once so both Chrome and requests use the same string
    resolved_ua = ua or _get_random_ua()

    # Determine proxies for requests library (mirrors Chrome proxy state)
    _proxies = {"http": _SOCKS5_PROXY, "https": _SOCKS5_PROXY} if proxy_args else {}

    # ------------------------------------------------------------------
    # Configure headless Chrome
    # ------------------------------------------------------------------
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument(f"--user-agent={resolved_ua}")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")

    # Inject caller-supplied proxy/fingerprint args (e.g. from OpsecManager)
    for arg in (proxy_args or []):
        chrome_options.add_argument(arg)

    # Enable network logging for request capture
    chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    driver = None

    try:
        # ------------------------------------------------------------------
        # 1. Fetch raw server HTML via requests (before browser launch)
        # ------------------------------------------------------------------
        raw_html = ""
        server_headers = []
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                headers={"User-Agent": resolved_ua},
                proxies=_proxies,
            )
            if response.status_code in (403, 429, 503):
                return _error_event(
                    url,
                    "blocked",
                    f"HTTP {response.status_code} from server",
                )
            raw_html = response.text
            server_headers = [f"{k}: {v}" for k, v in response.headers.items()]
        except requests.exceptions.Timeout:
            return _error_event(url, "timeout", "Initial HTTP request timed out")
        except requests.exceptions.ConnectionError as exc:
            return _error_event(url, "connection", str(exc))
        except Exception:
            # Non-fatal: continue to browser-based collection
            pass

        # ------------------------------------------------------------------
        # 2. Launch headless Chrome
        # ------------------------------------------------------------------
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(timeout)

        # Remove navigator.webdriver fingerprint before any page is loaded
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {
                "source": (
                    "Object.defineProperty(navigator, 'webdriver', "
                    "{get: () => undefined})"
                )
            },
        )

        # ------------------------------------------------------------------
        # 3. Navigate
        # ------------------------------------------------------------------
        try:
            driver.get(url)
        except TimeoutException as exc:
            return _error_event(url, "timeout", str(exc))
        except WebDriverException as exc:
            return _error_event(url, "connection", str(exc))

        # Wait for JS execution
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)

        # ------------------------------------------------------------------
        # 4. Build IOK event
        # ------------------------------------------------------------------
        iok_event = _empty_event(url)
        iok_event["html"] = raw_html
        iok_event["headers"] = server_headers

        # 1. Title
        try:
            iok_event["title"].append(driver.title)
        except Exception:
            pass

        # 2. Hostname already set by _empty_event

        # 4. DOM (post-JS)
        try:
            iok_event["dom"] = driver.page_source
        except Exception:
            pass

        # 5. JavaScript (inline + external)
        try:
            for script in driver.find_elements(By.TAG_NAME, "script"):
                inline_js = script.get_attribute("innerHTML")
                if inline_js and inline_js.strip():
                    iok_event["js"].append(inline_js)

                src = script.get_attribute("src")
                if src:
                    try:
                        ext_js = requests.get(
                            src, timeout=5, verify=False,
                            headers={"User-Agent": resolved_ua},
                            proxies=_proxies,
                        ).text
                        iok_event["js"].append(ext_js)
                    except Exception:
                        pass
        except Exception:
            pass

        # 6. CSS (inline + external)
        try:
            for style in driver.find_elements(By.TAG_NAME, "style"):
                css = style.get_attribute("innerHTML")
                if css and css.strip():
                    iok_event["css"].append(css)

            for link in driver.find_elements(By.CSS_SELECTOR, "link[rel='stylesheet']"):
                href = link.get_attribute("href")
                if href:
                    try:
                        ext_css = requests.get(
                            href, timeout=5, verify=False,
                            headers={"User-Agent": resolved_ua},
                            proxies=_proxies,
                        ).text
                        iok_event["css"].append(ext_css)
                    except Exception:
                        pass
        except Exception:
            pass

        # 7. Cookies
        try:
            for cookie in driver.get_cookies():
                iok_event["cookies"].append(f"{cookie['name']}={cookie['value']}")
        except Exception:
            pass

        # 8. Headers already set above

        # 9. Network requests (from Chrome performance log)
        try:
            seen_urls: set = set()
            for entry in driver.get_log("performance"):
                message = json.loads(entry["message"])
                if message.get("message", {}).get("method") == "Network.requestWillBeSent":
                    req_url = message["message"]["params"]["request"]["url"]
                    if req_url and req_url not in seen_urls:
                        seen_urls.add(req_url)
                        iok_event["requests"].append(req_url)
        except Exception:
            pass

        # 10. Forms: POST action endpoints + input field names
        try:
            for form in driver.find_elements(By.TAG_NAME, "form"):
                action = form.get_attribute("action") or ""
                method = (form.get_attribute("method") or "GET").upper()
                fields = []
                for inp in form.find_elements(By.CSS_SELECTOR, "input, select, textarea"):
                    name = inp.get_attribute("name") or ""
                    ftype = inp.get_attribute("type") or inp.tag_name
                    if name:
                        fields.append({"name": name, "type": ftype})
                iok_event["forms"].append({"action": action, "method": method, "fields": fields})
        except Exception:
            pass

        return iok_event

    except TimeoutException as exc:
        return _error_event(url, "timeout", str(exc))
    except (socket.error, OSError) as exc:
        return _error_event(url, "connection", str(exc))
    except Exception as exc:
        return _error_event(url, "connection", str(exc))

    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 iok_collector.py <URL> [output.json]")
        sys.exit(1)

    url = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "iok_event.json"

    print(f"[+] Collecting IOK data from: {url}")

    event = collect_iok_data(url)

    if event.get("error"):
        print(f"[-] Collection failed ({event['error_type']}): {event['error_message']}")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(event, f, indent=2, ensure_ascii=False)
        print(f"[+] Error event saved to: {output_file}")
        sys.exit(1)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(event, f, indent=2, ensure_ascii=False)

    print(f"[+] Saved to: {output_file}")
    print(f"[+] JS files: {len(event['js'])}, CSS files: {len(event['css'])}")
    print(f"[+] Requests: {len(event['requests'])}, Cookies: {len(event['cookies'])}")
    print(f"[+] Forms: {len(event['forms'])}")


if __name__ == "__main__":
    main()
