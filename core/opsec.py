#!/usr/bin/env python3
"""
OpsecManager — VPN rotation, exit-IP verification, and SOCKS5 proxy helpers.

Rotation back-ends (in priority order):
  1. protonvpn — ProtonVPN CLI with SOCKS5 proxy (preferred for this lab)
  2. nmcli     — NetworkManager VPN connections (openvpn/wireguard profiles)
  3. openvpn   — direct openvpn CLI
  4. stub      — logs rotation intent; no actual VPN change (dev/test mode)

ProtonVPN CLI: https://protonvpn.com/support/linux-vpn-tool/
verify_exit_ip() uses ipapi.co to confirm the new exit node.
"""

import logging
import re
import socket
import subprocess
import time

import requests

from core.ua_pool import UAPool as _UAPool

log = logging.getLogger(__name__)

# Public IP-info endpoint (no API key required, rate-limited to ~1k/day)
IP_API_URL      = "https://ipapi.co/json/"
IP_API_TIMEOUT  = 8  # seconds
IP_FALLBACK_URL = "https://api.ipify.org?format=json"

SOCKS5_PORT = 1080

_ua_pool = _UAPool()


class OpsecManager:
    """
    Manages VPN / proxy rotation and exit-IP verification.

    Parameters
    ----------
    vpn_profiles : list[str] | None
        List of VPN connection names (nmcli) or config-file paths (openvpn).
        For the ``protonvpn`` backend, pass ISO country codes (e.g. ["NL", "CH"]).
        When None the manager operates in stub/log-only mode.
    backend : str
        One of ``"protonvpn"``, ``"nmcli"``, ``"openvpn"``, ``"stub"``.
    """

    def __init__(self, vpn_profiles=None, backend="stub"):
        self.vpn_profiles = vpn_profiles or []
        self.backend = backend if self.vpn_profiles else "stub"
        self._profile_index = 0
        self._last_exit: dict = {}
        # Country list cache (ProtonVPN backend)
        self._countries_cache: list = []
        self._cache_time: float = 0.0
        self._CACHE_TTL = 300  # seconds

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def rotate_server(self, country: str = None) -> bool:
        """
        Rotate to the next VPN server.

        Args:
            country: ISO 3166-1 alpha-2 country code (ProtonVPN backend only).

        Returns:
            True on success, False if rotation could not be confirmed.
        """
        if not self.vpn_profiles or self.backend == "stub":
            log.info("[opsec] stub rotate — no VPN profiles configured")
            return True

        try:
            if self.backend == "protonvpn":
                return self._rotate_protonvpn(country)
            elif self.backend == "nmcli":
                return self._rotate_nmcli(self._next_profile())
            elif self.backend == "openvpn":
                return self._rotate_openvpn(self._next_profile())
        except Exception as exc:
            log.warning("[opsec] rotation error: %s", exc)

        return False

    def connect(self, country: str) -> bool:
        """Connect to the given country (ProtonVPN backend)."""
        return self.rotate_server(country=country)

    def disconnect(self) -> bool:
        """Disconnect from VPN."""
        if self.backend == "protonvpn":
            try:
                subprocess.run(
                    ["protonvpn-cli", "disconnect"],
                    capture_output=True, text=True, timeout=30,
                )
                return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False
        return True

    def get_status(self) -> dict:
        """
        Return current VPN status dict.

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
        if self.backend == "protonvpn":
            return self._protonvpn_status()

        return {
            "connected":           False,
            "exit_ip":             self._last_exit.get("ip", ""),
            "country":             self._last_exit.get("country_name", ""),
            "country_code":        self._last_exit.get("country_code", ""),
            "server":              "",
            "socks5_available":    self._check_socks5(),
            "available_countries": self.get_available_countries(),
        }

    def verify_exit_ip(self, retries: int = 3, backoff: float = 2.0) -> dict:
        """
        Query current exit IP and geo-location.

        Returns a dict::

            {
                "ip": "185.107.x.x",
                "country_code": "NL",
                "country_name": "Netherlands",
                "city": "Amsterdam",
                "org": "AS12345 Example ISP",
            }

        Retries up to *retries* times with exponential back-off.
        """
        for attempt in range(retries):
            try:
                r = requests.get(IP_API_URL, timeout=IP_API_TIMEOUT)
                if r.status_code == 200:
                    data = r.json()
                    info = {
                        "ip":           data.get("ip", ""),
                        "country_code": data.get("country_code", ""),
                        "country_name": data.get("country_name", ""),
                        "city":         data.get("city", ""),
                        "org":          data.get("org", ""),
                    }
                    self._last_exit = info
                    log.info("[opsec] exit IP: %s (%s)", info["ip"], info["country_code"])
                    return info
            except Exception as exc:
                log.debug("[opsec] verify_exit_ip attempt %d failed: %s", attempt + 1, exc)
                if attempt < retries - 1:
                    time.sleep(backoff * (attempt + 1))

        # Fallback: get bare IP only
        try:
            r = requests.get(IP_FALLBACK_URL, timeout=IP_API_TIMEOUT)
            ip = r.json().get("ip", "unknown")
            info = {"ip": ip, "country_code": "", "country_name": "", "city": "", "org": ""}
            self._last_exit = info
            return info
        except Exception:
            return {"ip": "unknown", "country_code": "", "country_name": "", "city": "", "org": ""}

    def get_current_exit(self) -> dict:
        """Return the most recently verified exit-IP info (no network call)."""
        return dict(self._last_exit)

    def get_available_countries(self) -> list:
        """Return sorted list of available country codes."""
        if self.backend == "protonvpn":
            return self._protonvpn_countries()
        return []

    def get_random_ua(self) -> str:
        """Return a randomly selected User-Agent string."""
        return _ua_pool.get()

    def get_chromium_args(self) -> list:
        """
        Return Chromium launch args for SOCKS5 proxy and fingerprint hardening.

        Returns:
            List of argument strings for selenium ChromeOptions.add_argument().
        """
        return [
            f"--proxy-server=socks5://127.0.0.1:{SOCKS5_PORT}",
            "--dns-over-https-templates=https://1.1.1.1/dns-query",
            "--disable-blink-features=AutomationControlled",
        ]

    def get_requests_proxies(self) -> dict:
        """
        Return a proxies dict for use with the requests library.
        Uses socks5h:// so DNS resolution happens on the VPN exit node.

        Returns:
            {"http": "socks5h://...", "https": "socks5h://..."}
        """
        proxy_url = f"socks5h://127.0.0.1:{SOCKS5_PORT}"
        return {"http": proxy_url, "https": proxy_url}

    # ------------------------------------------------------------------ #
    #  ProtonVPN backend                                                   #
    # ------------------------------------------------------------------ #

    def _rotate_protonvpn(self, country: str = None) -> bool:
        cmd = ["protonvpn-cli", "connect", "--fastest"]
        if country:
            cmd += ["--cc", country.upper()]

        subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        # Poll for connected state, up to 10 s
        for _ in range(10):
            time.sleep(1)
            if self._protonvpn_status().get("connected"):
                return True
        return False

    def _protonvpn_status(self) -> dict:
        status = {
            "connected":           False,
            "exit_ip":             "",
            "country":             "",
            "country_code":        "",
            "server":              "",
            "socks5_available":    self._check_socks5(),
            "available_countries": self.get_available_countries(),
        }
        try:
            result = subprocess.run(
                ["protonvpn-cli", "status"],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout + result.stderr

            if re.search(r"Status\s*[:\-]\s*Connected", output, re.IGNORECASE):
                status["connected"] = True

            ip_match = re.search(r"IP\s*[:\-]\s*([\d.]+)", output, re.IGNORECASE)
            if ip_match:
                status["exit_ip"] = ip_match.group(1)

            country_match = re.search(r"Country\s*[:\-]\s*(.+)", output, re.IGNORECASE)
            if country_match:
                status["country"] = country_match.group(1).strip()

            cc_match = re.search(r"\b([A-Z]{2})-\w+#\d+", output)
            if cc_match:
                status["country_code"] = cc_match.group(1)
            elif status["country"]:
                status["country_code"] = status["country"][:2].upper()

            server_match = re.search(r"Server\s*[:\-]\s*(\S+)", output, re.IGNORECASE)
            if server_match:
                status["server"] = server_match.group(1)

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return status

    def _protonvpn_countries(self) -> list:
        now = time.monotonic()
        if self._countries_cache and (now - self._cache_time) < self._CACHE_TTL:
            return self._countries_cache

        countries: set = set()
        try:
            result = subprocess.run(
                ["protonvpn-cli", "servers", "--list"],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr

            for match in re.finditer(r"\b([A-Z]{2})(?:-\w+)?#\d+", output):
                countries.add(match.group(1))

            if not countries:
                for match in re.finditer(r"\b([A-Z]{2})\b", output):
                    countries.add(match.group(1))

        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        self._countries_cache = sorted(countries)
        self._cache_time = now
        return self._countries_cache

    # ------------------------------------------------------------------ #
    #  nmcli / openvpn backends                                           #
    # ------------------------------------------------------------------ #

    def _next_profile(self) -> str:
        profile = self.vpn_profiles[self._profile_index % len(self.vpn_profiles)]
        self._profile_index += 1
        return profile

    def _rotate_nmcli(self, profile: str) -> bool:
        subprocess.run(
            ["nmcli", "connection", "down", "type", "vpn"],
            capture_output=True, timeout=15,
        )
        result = subprocess.run(
            ["nmcli", "connection", "up", profile],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            log.warning("[opsec] nmcli up failed: %s", result.stderr.strip())
            return False
        time.sleep(2)
        return True

    def _rotate_openvpn(self, config_path: str) -> bool:
        subprocess.run(["pkill", "-f", "openvpn"], capture_output=True, timeout=5)
        time.sleep(1)
        subprocess.Popen(
            ["openvpn", "--config", config_path, "--daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(5)
        return True

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check_socks5() -> bool:
        """Return True if the SOCKS5 proxy port is accepting connections."""
        try:
            with socket.create_connection(("127.0.0.1", SOCKS5_PORT), timeout=1):
                return True
        except OSError:
            return False
