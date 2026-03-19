#!/usr/bin/env python3
"""
BatchEngine — concurrent URL scanning with VPN rotation, jitter, and SSE streaming.

Usage
-----
    from core.batch import BatchEngine
    from core.opsec import OpsecManager
    from core.ua_pool import UAPool

    engine = BatchEngine(
        db_path="scans.db",
        opsec=OpsecManager(vpn_profiles=["nl-01", "ch-01"]),
        ua_pool=UAPool(),
    )
    engine.run_batch(
        batch_id="abc123",
        urls=["https://site1.com", "https://site2.net"],
        config={
            "concurrency":    3,
            "delay_ms":       1500,
            "use_vpn":        True,
            "rotate_mode":    "every_n",   # none | per_scan | every_n | per_batch
            "rotate_every_n": 5,
        },
    )

    # In the Flask SSE route:
    q = engine.get_sse_queue("abc123")

SSE event schema
----------------
    {
        "scan_id":        "abc123",
        "url":            "https://...",
        "status":         "complete" | "error",
        "verdict":        "HIGH" | "MED" | "LOW" | "NONE",
        "detection_count": 3,
        "exit_country":   "NL",
        "exit_ip":        "185.107.x.x",
        "elapsed_ms":     14200,
        "ua_label":       "Chr",
        "progress":       {"complete": 12, "total": 30, "failed": 0}
    }

    Sentinel when batch is done:
        {"done": True, "total": 30, "failed": 0}
"""

import hashlib
import json
import logging
import os
import queue
import random
import sqlite3
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# Module-level SSE queue registry: batch_id -> Queue
_sse_queues: dict[str, queue.Queue] = {}
_sse_lock = threading.Lock()

# Detect script root (two levels up from this file)
_PKG_ROOT = Path(__file__).resolve().parent.parent


class BatchEngine:
    """
    Concurrent IOK batch scanner.

    Parameters
    ----------
    db_path : str
        Path to the SQLite database file (created if absent).
    opsec : OpsecManager | None
        Handles VPN rotation.  Pass ``None`` to disable VPN.
    ua_pool : UAPool | None
        User-agent rotation pool.
    collector_path : str
        Path to ``iok_collector.py``.
    detector_path : str
        Path to ``iok_detector.py``.
    rules_path : str
        Directory containing Sigma/IOK YAML rules.
    work_dir : str
        Temp directory for intermediate JSON files.
    analysis_timeout : int
        Seconds before a collector subprocess is killed.
    """

    def __init__(
        self,
        db_path: str = "scans.db",
        opsec=None,
        ua_pool=None,
        collector_path: Optional[str] = None,
        detector_path: Optional[str] = None,
        rules_path: Optional[str] = None,
        work_dir: Optional[str] = None,
        analysis_timeout: int = 60,
    ):
        self.db_path = db_path
        self.opsec = opsec
        self.ua_pool = ua_pool
        self.collector_path = collector_path or str(_PKG_ROOT / "scripts" / "iok_collector.py")
        self.detector_path = detector_path or str(_PKG_ROOT / "scripts" / "iok_detector.py")
        self.rules_path = rules_path or str(_PKG_ROOT / "IOK" / "indicators")
        self.work_dir = work_dir or tempfile.mkdtemp(prefix="iok_batch_")
        self.analysis_timeout = analysis_timeout

        Path(self.work_dir).mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def run_batch(self, batch_id: str, urls: list[str], config: dict) -> None:
        """
        Start a batch in a background thread; returns immediately.

        *config* keys (all optional):

        ============== ======= ===============================================
        concurrency    int     Max parallel scans (default 3)
        delay_ms       int     Base inter-scan delay in ms (default 1500)
        use_vpn        bool    Enable VPN rotation (default False)
        rotate_mode    str     ``none`` | ``per_scan`` | ``every_n``
                               | ``per_batch`` (default ``none``)
        rotate_every_n int     Rotation interval for ``every_n`` (default 5)
        ============== ======= ===============================================
        """
        # Register SSE queue before spawning thread so callers can subscribe
        with _sse_lock:
            _sse_queues[batch_id] = queue.Queue()

        self._db_insert_batch(batch_id, len(urls), config)

        t = threading.Thread(
            target=self._run,
            args=(batch_id, list(urls), config),
            daemon=True,
            name=f"batch-{batch_id[:8]}",
        )
        t.start()
        log.info("[batch:%s] started — %d URLs, concurrency=%d",
                 batch_id[:8], len(urls), config.get("concurrency", 3))

    def get_sse_queue(self, batch_id: str) -> Optional[queue.Queue]:
        """Return the SSE event queue for *batch_id*, or None if not found."""
        return _sse_queues.get(batch_id)

    # ------------------------------------------------------------------ #
    # Internal orchestrator                                                #
    # ------------------------------------------------------------------ #

    def _run(self, batch_id: str, urls: list[str], config: dict) -> None:
        concurrency    = int(config.get("concurrency", 3))
        delay_ms       = int(config.get("delay_ms", 1500))
        use_vpn        = bool(config.get("use_vpn", False))
        rotate_mode    = config.get("rotate_mode", "none")
        rotate_every_n = int(config.get("rotate_every_n", 5))
        total          = len(urls)
        completed      = 0
        failed         = 0

        # Per-batch: rotate once before any scans begin
        if use_vpn and self.opsec and rotate_mode == "per_batch":
            self._do_rotate(batch_id)

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="scan") as pool:
            futures = {}

            for i, url in enumerate(urls):
                # Rotation before submission (per_scan / every_n)
                if use_vpn and self.opsec:
                    if rotate_mode == "per_scan":
                        self._do_rotate(batch_id)
                    elif rotate_mode == "every_n" and i > 0 and i % rotate_every_n == 0:
                        self._do_rotate(batch_id)

                # Get current exit info (may be stale if no VPN)
                exit_info = self.opsec.get_current_exit() if self.opsec else {}

                # Pick UA for this scan
                ua = self.ua_pool.get() if self.ua_pool else None
                ua_label = self.ua_pool.label(ua) if (self.ua_pool and ua) else "Chr"

                scan_id = _make_id(f"{batch_id}:{url}:{i}")
                self._db_insert_scan(scan_id, batch_id, url)

                future = pool.submit(
                    self._scan_url,
                    url, batch_id, scan_id, ua, exit_info
                )
                futures[future] = (scan_id, url, ua_label, exit_info)

                # Inter-scan jitter delay (skip for first URL)
                if i < total - 1 and delay_ms > 0:
                    jitter = random.uniform(0.8, 1.2)
                    time.sleep((delay_ms * jitter) / 1000.0)

            # Collect results as they complete
            for future in as_completed(futures):
                scan_id, url, ua_label, exit_info = futures[future]
                try:
                    result = future.result()
                    completed += 1
                except Exception as exc:
                    failed += 1
                    result = {"url": url, "error": str(exc)}
                    log.warning("[batch:%s] scan error for %s: %s", batch_id[:8], url, exc)

                self._db_update_batch_progress(batch_id, completed, failed)

                verdict = (result.get("threat_level", "none") or "none").upper()
                if verdict in ("MEDIUM",):
                    verdict = "MED"

                event = {
                    "scan_id":         scan_id,
                    "url":             result.get("url", url),
                    "status":          "error" if "error" in result else "complete",
                    "verdict":         verdict,
                    "detection_count": result.get("detection_count", 0),
                    "exit_country":    exit_info.get("country_code", "N/A"),
                    "exit_ip":         exit_info.get("ip", "N/A"),
                    "elapsed_ms":      result.get("elapsed_ms", 0),
                    "ua_label":        ua_label,
                    "progress": {
                        "complete": completed,
                        "total":    total,
                        "failed":   failed,
                    },
                }
                if "error" in result:
                    event["error"] = result["error"]

                self._emit_sse(batch_id, event)

        self._db_complete_batch(batch_id)
        self._emit_sse(batch_id, {"done": True, "total": total, "failed": failed})
        log.info("[batch:%s] done — %d/%d completed, %d failed",
                 batch_id[:8], completed, total, failed)

    # ------------------------------------------------------------------ #
    # Per-URL scanner                                                      #
    # ------------------------------------------------------------------ #

    def _scan_url(
        self,
        url: str,
        batch_id: str,
        scan_id: str,
        ua: Optional[str],
        exit_info: dict,
    ) -> dict:
        """Run collector + detector for a single URL; update DB on completion."""
        start = time.time()
        event_file = os.path.join(self.work_dir, f"{scan_id}_event.json")
        det_file   = os.path.join(self.work_dir, f"{scan_id}_event_detections.json")

        # ── Step 1: collect ──────────────────────────────────────────── #
        collector_cmd = ["python3", self.collector_path, url, event_file]
        try:
            proc = subprocess.run(
                collector_cmd,
                capture_output=True,
                text=True,
                timeout=self.analysis_timeout,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"collector exited {proc.returncode}: {proc.stderr[:200]}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("collector timeout")

        # ── Step 2: detect ───────────────────────────────────────────── #
        try:
            subprocess.run(
                ["python3", self.detector_path, event_file, self.rules_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("detector timeout")

        # ── Step 3: parse results ────────────────────────────────────── #
        detections: list = []
        if os.path.exists(det_file):
            with open(det_file) as f:
                detections = json.load(f)

        event_data: dict = {}
        if os.path.exists(event_file):
            with open(event_file) as f:
                event_data = json.load(f)

        elapsed_ms = int((time.time() - start) * 1000)
        threat_level = _top_level(detections)

        result = {
            "url":             url,
            "hostname":        event_data.get("hostname", ""),
            "title":           event_data.get("title", []),
            "detections":      detections,
            "detection_count": len(detections),
            "threat_level":    threat_level,
            "js_count":        len(event_data.get("js", [])),
            "css_count":       len(event_data.get("css", [])),
            "cookies_count":   len(event_data.get("cookies", [])),
            "forms_count":     len(event_data.get("forms", [])),
            "forms":           event_data.get("forms", []),
            "requests_count":  len(event_data.get("requests", [])),
            "requests_detail": event_data.get("requests", []),
            "exit_ip":         exit_info.get("ip", ""),
            "exit_country":    exit_info.get("country_code", ""),
            "elapsed_ms":      elapsed_ms,
            "timestamp":       datetime.utcnow().isoformat(),
        }

        self._db_complete_scan(scan_id, result)
        return result

    # ------------------------------------------------------------------ #
    # VPN helpers                                                          #
    # ------------------------------------------------------------------ #

    def _do_rotate(self, batch_id: str) -> None:
        """Rotate VPN server and verify the new exit IP."""
        log.info("[batch:%s] rotating VPN server…", batch_id[:8])
        if self.opsec.rotate_server():
            info = self.opsec.verify_exit_ip()
            log.info("[batch:%s] new exit: %s (%s)",
                     batch_id[:8], info.get("ip"), info.get("country_code"))
        else:
            log.warning("[batch:%s] VPN rotation failed", batch_id[:8])

    # ------------------------------------------------------------------ #
    # SSE helpers                                                          #
    # ------------------------------------------------------------------ #

    def _emit_sse(self, batch_id: str, event: dict) -> None:
        q = _sse_queues.get(batch_id)
        if q is not None:
            q.put(event)

    # ------------------------------------------------------------------ #
    # SQLite persistence                                                   #
    # ------------------------------------------------------------------ #

    def _init_db(self) -> None:
        with self._db() as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS batches (
                    id          TEXT PRIMARY KEY,
                    status      TEXT    NOT NULL DEFAULT 'running',
                    total       INTEGER NOT NULL,
                    complete    INTEGER NOT NULL DEFAULT 0,
                    failed      INTEGER NOT NULL DEFAULT 0,
                    config      TEXT,
                    created_at  TEXT    NOT NULL,
                    finished_at TEXT
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id              TEXT PRIMARY KEY,
                    batch_id        TEXT NOT NULL,
                    url             TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    verdict         TEXT,
                    detection_count INTEGER DEFAULT 0,
                    detections      TEXT,
                    hostname        TEXT,
                    js_count        INTEGER DEFAULT 0,
                    css_count       INTEGER DEFAULT 0,
                    requests_count  INTEGER DEFAULT 0,
                    forms_count     INTEGER DEFAULT 0,
                    cookies_count   INTEGER DEFAULT 0,
                    exit_ip         TEXT,
                    exit_country    TEXT,
                    elapsed_ms      INTEGER,
                    timestamp       TEXT,
                    FOREIGN KEY (batch_id) REFERENCES batches(id)
                );

                CREATE INDEX IF NOT EXISTS idx_scans_batch
                    ON scans (batch_id);
            """)

    @contextmanager
    def _db(self):
        con = sqlite3.connect(self.db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _db_insert_batch(self, batch_id: str, total: int, config: dict) -> None:
        with self._db() as con:
            con.execute(
                "INSERT OR IGNORE INTO batches (id, total, config, created_at) VALUES (?,?,?,?)",
                (batch_id, total, json.dumps(config), datetime.utcnow().isoformat()),
            )

    def _db_insert_scan(self, scan_id: str, batch_id: str, url: str) -> None:
        with self._db() as con:
            con.execute(
                "INSERT OR IGNORE INTO scans (id, batch_id, url) VALUES (?,?,?)",
                (scan_id, batch_id, url),
            )

    def _db_update_batch_progress(self, batch_id: str, complete: int, failed: int) -> None:
        with self._db() as con:
            con.execute(
                "UPDATE batches SET complete=?, failed=? WHERE id=?",
                (complete, failed, batch_id),
            )

    def _db_complete_scan(self, scan_id: str, result: dict) -> None:
        with self._db() as con:
            con.execute(
                """UPDATE scans SET
                    status='complete',
                    verdict=?,
                    detection_count=?,
                    detections=?,
                    hostname=?,
                    js_count=?,
                    css_count=?,
                    requests_count=?,
                    forms_count=?,
                    cookies_count=?,
                    exit_ip=?,
                    exit_country=?,
                    elapsed_ms=?,
                    timestamp=?
                WHERE id=?""",
                (
                    result.get("threat_level", "none"),
                    result.get("detection_count", 0),
                    json.dumps(result.get("detections", [])),
                    result.get("hostname", ""),
                    result.get("js_count", 0),
                    result.get("css_count", 0),
                    result.get("requests_count", 0),
                    result.get("forms_count", 0),
                    result.get("cookies_count", 0),
                    result.get("exit_ip", ""),
                    result.get("exit_country", ""),
                    result.get("elapsed_ms", 0),
                    result.get("timestamp", ""),
                    scan_id,
                ),
            )

    def _db_complete_batch(self, batch_id: str) -> None:
        with self._db() as con:
            con.execute(
                "UPDATE batches SET status='done', finished_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), batch_id),
            )


# ────────────────────────────────────────────────────────────────────────── #
# Helpers                                                                     #
# ────────────────────────────────────────────────────────────────────────── #

_LEVEL_ORDER = {"high": 3, "medium": 2, "med": 2, "low": 1, "none": 0}


def _top_level(detections: list) -> str:
    best = "none"
    for d in detections:
        lvl = (d.get("level") or "low").lower()
        if _LEVEL_ORDER.get(lvl, 0) > _LEVEL_ORDER.get(best, 0):
            best = lvl
    return best


def _make_id(seed: str) -> str:
    return hashlib.sha256(f"{seed}{time.time()}".encode()).hexdigest()[:32]
