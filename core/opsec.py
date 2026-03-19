#!/usr/bin/env python3
"""
OpsecManager — VPN rotation and exit-IP verification.

Rotation back-ends (in priority order):
  1. nmcli  — NetworkManager VPN connections (openvpn/wireguard profiles)
  2. openvpn — direct openvpn CLI
  3. stub    — logs rotation intent; no actual VPN change (dev/test mode)

verify_exit_ip() uses ipapi.co to confirm the new exit node.
"""

import logging
import random
import subprocess
import time

import requests

log = logging.getLogger(__name__)

# Public IP-info endpoint (no API key required, rate-limited to ~1k/day)
IP_API_URL = "https://ipapi.co/json/"
IP_API_TIMEOUT = 8  # seconds

# Fallback simple IP endpoint
IP_FALLBACK_URL = "https://api.ipify.org?format=json"


class OpsecManager:
    """
    Manages VPN / proxy rotation and exit-IP verification.

    Parameters
    ----------
    vpn_profiles : list[str] | None
        List of VPN connection names (nmcli) or config-file paths (openvpn).
        When None the manager operates in stub/log-only mode.
    backend : str
        One of ``"nmcli"``, ``"openvpn"``, ``"stub"``.
    """

    def __init__(self, vpn_profiles=None, backend="stub"):
        self.vpn_profiles = vpn_profiles or []
        self.backend = backend if self.vpn_profiles else "stub"
        self._profile_index = 0
        self._last_exit: dict = {}

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def rotate_server(self) -> bool:
        """
        Rotate to the next VPN server.

        Returns True on success, False if rotation could not be confirmed.
        """
        if not self.vpn_profiles or self.backend == "stub":
            log.info("[opsec] stub rotate — no VPN profiles configured")
            return True

        next_profile = self._next_profile()
        log.info("[opsec] rotating to VPN profile: %s", next_profile)

        try:
            if self.backend == "nmcli":
                return self._rotate_nmcli(next_profile)
            elif self.backend == "openvpn":
                return self._rotate_openvpn(next_profile)
        except Exception as exc:
            log.warning("[opsec] rotation error: %s", exc)

        return False

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

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _next_profile(self) -> str:
        profile = self.vpn_profiles[self._profile_index % len(self.vpn_profiles)]
        self._profile_index += 1
        return profile

    def _rotate_nmcli(self, profile: str) -> bool:
        # Disconnect any active VPN, then connect new profile
        subprocess.run(["nmcli", "connection", "down", "type", "vpn"],
                       capture_output=True, timeout=15)
        result = subprocess.run(
            ["nmcli", "connection", "up", profile],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            log.warning("[opsec] nmcli up failed: %s", result.stderr.strip())
            return False
        time.sleep(2)   # allow routes to settle
        return True

    def _rotate_openvpn(self, config_path: str) -> bool:
        # Kill existing openvpn, start new one
        subprocess.run(["pkill", "-f", "openvpn"], capture_output=True, timeout=5)
        time.sleep(1)
        result = subprocess.Popen(
            ["openvpn", "--config", config_path, "--daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(5)   # wait for tunnel establishment
        return True
