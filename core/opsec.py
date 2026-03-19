"""
OpsecManager — ProtonVPN SOCKS5 integration, UA rotation, and proxy helpers
for the IOK Detection Lab.

ProtonVPN CLI must be installed and authenticated before use.
Install: https://protonvpn.com/support/linux-vpn-tool/
"""

import re
import socket
import subprocess
import time

import requests

from core.ua_pool import get_random_ua as _get_random_ua


class OpsecManager:
    SOCKS5_PORT = 1080

    # Country list cache
    _countries_cache: list = []
    _cache_time: float = 0.0
    CACHE_TTL = 300  # seconds

    # ------------------------------------------------------------------ #
    #  Status                                                              #
    # ------------------------------------------------------------------ #

    @classmethod
    def get_status(cls) -> dict:
        """
        Return current VPN + SOCKS5 status.

        Returns:
            {
              "connected": bool,
              "exit_ip": str,
              "country": str,
              "country_code": str,
              "server": str,
              "socks5_available": bool,
              "available_countries": list[str],
            }
        """
        status = {
            "connected": False,
            "exit_ip": "",
            "country": "",
            "country_code": "",
            "server": "",
            "socks5_available": cls._check_socks5(),
            "available_countries": cls.get_available_countries(),
        }

        try:
            result = subprocess.run(
                ["protonvpn-cli", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr

            # Detect connected state
            if re.search(r"Status\s*[:\-]\s*Connected", output, re.IGNORECASE):
                status["connected"] = True

            # IP address
            ip_match = re.search(r"IP\s*[:\-]\s*([\d.]+)", output, re.IGNORECASE)
            if ip_match:
                status["exit_ip"] = ip_match.group(1)

            # Country name
            country_match = re.search(r"Country\s*[:\-]\s*(.+)", output, re.IGNORECASE)
            if country_match:
                status["country"] = country_match.group(1).strip()

            # Country code (2-letter, e.g. "US")
            cc_match = re.search(r"\b([A-Z]{2})-\w+#\d+", output)
            if cc_match:
                status["country_code"] = cc_match.group(1)
            elif status["country"]:
                status["country_code"] = status["country"][:2].upper()

            # Server name (e.g. "US-FREE#1" or "NL#42")
            server_match = re.search(r"Server\s*[:\-]\s*(\S+)", output, re.IGNORECASE)
            if server_match:
                status["server"] = server_match.group(1)

        except FileNotFoundError:
            # protonvpn-cli not installed; return defaults
            pass
        except subprocess.TimeoutExpired:
            pass

        return status

    # ------------------------------------------------------------------ #
    #  Connection management                                               #
    # ------------------------------------------------------------------ #

    @classmethod
    def rotate_server(cls, country: str = None) -> dict:
        """
        Disconnect from current server and reconnect to the fastest available,
        optionally filtered by country code.

        Args:
            country: ISO 3166-1 alpha-2 country code (e.g. "NL", "US").

        Returns:
            New status dict.
        """
        cmd = ["protonvpn-cli", "connect", "--fastest"]
        if country:
            cmd += ["--cc", country.upper()]

        subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        # Poll for connected state, up to 10 s
        for _ in range(10):
            time.sleep(1)
            if cls.get_status()["connected"]:
                break

        return cls.get_status()

    @classmethod
    def connect(cls, country: str) -> dict:
        """
        Connect to the fastest server in the given country.

        Args:
            country: ISO 3166-1 alpha-2 country code.

        Returns:
            Status dict after connection attempt.
        """
        return cls.rotate_server(country=country)

    @classmethod
    def disconnect(cls) -> dict:
        """
        Disconnect from ProtonVPN.

        Returns:
            Status dict after disconnection.
        """
        try:
            subprocess.run(
                ["protonvpn-cli", "disconnect"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return cls.get_status()

    # ------------------------------------------------------------------ #
    #  IP verification                                                     #
    # ------------------------------------------------------------------ #

    @classmethod
    def verify_exit_ip(cls) -> dict:
        """
        Confirm the real exit IP by fetching ifconfig.me through the SOCKS5 proxy.
        Uses socks5h to ensure DNS resolution happens on the remote side.

        Returns:
            {"exit_ip": str, "proxied": bool}
        """
        try:
            resp = requests.get(
                "https://ifconfig.me/all.json",
                proxies=cls.get_requests_proxies(),
                timeout=10,
                headers={"User-Agent": cls.get_random_ua()},
            )
            data = resp.json()
            return {"exit_ip": data.get("ip_addr", ""), "proxied": True}
        except Exception:
            return {"exit_ip": "", "proxied": False}

    # ------------------------------------------------------------------ #
    #  Country enumeration                                                 #
    # ------------------------------------------------------------------ #

    @classmethod
    def get_available_countries(cls) -> list:
        """
        Return a sorted list of country codes available via ProtonVPN.
        Result is cached for CACHE_TTL seconds (default 5 minutes).

        Returns:
            List of ISO 3166-1 alpha-2 country code strings, e.g. ["CH", "DE", "NL", "US"].
        """
        now = time.monotonic()
        if cls._countries_cache and (now - cls._cache_time) < cls.CACHE_TTL:
            return cls._countries_cache

        countries: set = set()
        try:
            result = subprocess.run(
                ["protonvpn-cli", "servers", "--list"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout + result.stderr

            # Try to extract 2-letter country codes from server names like "US-FREE#1" or "NL#5"
            for match in re.finditer(r"\b([A-Z]{2})(?:-\w+)?#\d+", output):
                countries.add(match.group(1))

            # Fallback: look for explicit "Country" labels
            if not countries:
                for match in re.finditer(r"\b([A-Z]{2})\b", output):
                    if len(match.group(1)) == 2:
                        countries.add(match.group(1))

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        cls._countries_cache = sorted(countries)
        cls._cache_time = now
        return cls._countries_cache

    # ------------------------------------------------------------------ #
    #  Proxy / browser helpers                                             #
    # ------------------------------------------------------------------ #

    @classmethod
    def get_chromium_args(cls) -> list:
        """
        Return Chrome/Chromium launch arguments that route traffic through the
        local SOCKS5 proxy and harden against automation fingerprinting.

        Returns:
            List of argument strings suitable for selenium ChromeOptions.add_argument().
        """
        return [
            f"--proxy-server=socks5://127.0.0.1:{cls.SOCKS5_PORT}",
            "--dns-over-https-templates=https://1.1.1.1/dns-query",
            "--disable-blink-features=AutomationControlled",
        ]

    @classmethod
    def get_requests_proxies(cls) -> dict:
        """
        Return a proxies dict for use with the requests library.
        Uses socks5h:// so that DNS resolution happens on the VPN exit node,
        preventing DNS leaks.

        Returns:
            {"http": "socks5h://...", "https": "socks5h://..."}
        """
        proxy_url = f"socks5h://127.0.0.1:{cls.SOCKS5_PORT}"
        return {"http": proxy_url, "https": proxy_url}

    @classmethod
    def get_random_ua(cls) -> str:
        """Return a randomly selected, market-share-weighted User-Agent string."""
        return _get_random_ua()

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    @classmethod
    def _check_socks5(cls) -> bool:
        """Return True if the SOCKS5 proxy port is accepting connections."""
        try:
            with socket.create_connection(("127.0.0.1", cls.SOCKS5_PORT), timeout=1):
                return True
        except OSError:
            return False
