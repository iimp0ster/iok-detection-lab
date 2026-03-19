#!/usr/bin/env python3
"""
IOK Detection Lab — Flask API
Provides scan submission, batch management, SSE streaming, opsec control,
and scan history backed by SQLite.

Run from repo root:
    PYTHONPATH=. python3 web/app.py
    PYTHONPATH=. flask --app web.app run --host 0.0.0.0 --port 5000
"""

import concurrent.futures
import json
import os
import queue
import sqlite3
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, request, stream_with_context

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.opsec import OpsecManager
from scripts.iok_collector import collect_iok_data
from scripts.iok_detector import IOKDetectionEngine

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IOK_RULES    = os.getenv("IOK_RULES",        "./IOK/indicators/")
DB_PATH      = os.getenv("IOK_DB",           "./iok.db")
MAX_WORKERS  = int(os.getenv("IOK_MAX_WORKERS",  "3"))
SCAN_TIMEOUT = int(os.getenv("IOK_SCAN_TIMEOUT", "60"))

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)

# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

_db_lock = threading.Lock()


def _db_conn() -> sqlite3.Connection:
    """Open a new SQLite connection with row_factory for dict-like rows."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they do not exist."""
    with _db_lock:
        conn = _db_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id               TEXT PRIMARY KEY,
                url              TEXT,
                timestamp        TEXT,
                status           TEXT,
                detection_count  INTEGER,
                highest_severity TEXT,
                vpn_country      TEXT,
                exit_ip          TEXT,
                ua_used          TEXT,
                result_json      TEXT
            );

            CREATE TABLE IF NOT EXISTS batches (
                id          TEXT PRIMARY KEY,
                total       INTEGER,
                complete    INTEGER,
                failed      INTEGER,
                created_at  TEXT,
                config_json TEXT
            );

            CREATE TABLE IF NOT EXISTS batch_scans (
                batch_id TEXT,
                scan_id  TEXT,
                position INTEGER
            );
        """)
        conn.commit()
        conn.close()


def _db_insert_scan(scan_id: str, url: str, status: str = "pending") -> None:
    with _db_lock:
        conn = _db_conn()
        conn.execute(
            "INSERT OR IGNORE INTO scans (id, url, timestamp, status) VALUES (?,?,?,?)",
            (scan_id, url, datetime.utcnow().isoformat(), status),
        )
        conn.commit()
        conn.close()


def _db_update_scan(scan_id: str, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    vals = list(fields.values()) + [scan_id]
    with _db_lock:
        conn = _db_conn()
        conn.execute(f"UPDATE scans SET {cols} WHERE id = ?", vals)
        conn.commit()
        conn.close()


def _db_get_scan(scan_id: str) -> dict | None:
    conn = _db_conn()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def _db_insert_batch(batch_id: str, total: int, config: dict) -> None:
    with _db_lock:
        conn = _db_conn()
        conn.execute(
            "INSERT INTO batches (id, total, complete, failed, created_at, config_json) "
            "VALUES (?,?,0,0,?,?)",
            (batch_id, total, datetime.utcnow().isoformat(), json.dumps(config)),
        )
        conn.commit()
        conn.close()


def _db_link_batch_scan(batch_id: str, scan_id: str, position: int) -> None:
    with _db_lock:
        conn = _db_conn()
        conn.execute(
            "INSERT INTO batch_scans (batch_id, scan_id, position) VALUES (?,?,?)",
            (batch_id, scan_id, position),
        )
        conn.commit()
        conn.close()


def _db_increment_batch(batch_id: str, complete_delta: int = 0, failed_delta: int = 0) -> None:
    with _db_lock:
        conn = _db_conn()
        conn.execute(
            "UPDATE batches SET complete = complete + ?, failed = failed + ? WHERE id = ?",
            (complete_delta, failed_delta, batch_id),
        )
        conn.commit()
        conn.close()


def _db_get_batch(batch_id: str) -> dict | None:
    conn = _db_conn()
    row = conn.execute("SELECT * FROM batches WHERE id = ?", (batch_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def _db_get_batch_scans(batch_id: str) -> list[dict]:
    conn = _db_conn()
    rows = conn.execute(
        "SELECT s.* FROM scans s "
        "JOIN batch_scans bs ON s.id = bs.scan_id "
        "WHERE bs.batch_id = ? "
        "ORDER BY bs.position",
        (batch_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Detection engine singleton (lazy-loaded)
# ---------------------------------------------------------------------------

_engine: IOKDetectionEngine | None = None
_engine_lock = threading.Lock()


def _get_engine() -> IOKDetectionEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = IOKDetectionEngine(IOK_RULES)
    return _engine


# ---------------------------------------------------------------------------
# SSE batch queue registry
# ---------------------------------------------------------------------------

_batch_queues: dict[str, queue.Queue] = {}
_batch_queues_lock = threading.Lock()


def _get_batch_queue(batch_id: str) -> queue.Queue:
    with _batch_queues_lock:
        if batch_id not in _batch_queues:
            _batch_queues[batch_id] = queue.Queue()
        return _batch_queues[batch_id]


def _push_sse(batch_id: str, event: str, data: dict) -> None:
    q = _get_batch_queue(batch_id)
    payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    q.put(payload)


# ---------------------------------------------------------------------------
# Core scan execution
# ---------------------------------------------------------------------------

def _execute_scan(
    scan_id: str,
    url: str,
    use_vpn: bool = False,
    ua: str | None = None,
    delay_ms: int = 0,
) -> dict:
    """
    Run collect → detect for one URL.  Persists status to DB throughout.
    Returns a result dict regardless of success/failure.
    """
    _db_update_scan(scan_id, status="running")

    proxy_args = OpsecManager.get_chromium_args() if use_vpn else None
    resolved_ua = ua or OpsecManager.get_random_ua()

    vpn_country = ""
    exit_ip = ""
    if use_vpn:
        vpn_status = OpsecManager.get_status()
        vpn_country = vpn_status.get("country_code", "")
        exit_ip = vpn_status.get("exit_ip", "")

    # Collect
    event = collect_iok_data(
        url,
        proxy_args=proxy_args,
        ua=resolved_ua,
        delay_ms=delay_ms,
    )

    if event.get("error"):
        _db_update_scan(
            scan_id,
            status="failed",
            ua_used=resolved_ua,
            vpn_country=vpn_country,
            exit_ip=exit_ip,
            result_json=json.dumps(event),
        )
        return {"scan_id": scan_id, "url": url, "status": "failed",
                "error_type": event.get("error_type"), "error_message": event.get("error_message")}

    # Detect
    try:
        detections = _get_engine().scan(event)
    except Exception as exc:
        detections = []
        event["engine_error"] = str(exc)

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "none": -1}
    highest = max(
        (d.get("level", "low") for d in detections),
        key=lambda lvl: severity_order.get(lvl, 0),
        default="none",
    )

    result = {
        "scan_id": scan_id,
        "url": url,
        "status": "complete",
        "detection_count": len(detections),
        "highest_severity": highest,
        "detections": detections,
        "hostname": event.get("hostname", ""),
        "title": event.get("title", []),
        "js_count": len(event.get("js", [])),
        "css_count": len(event.get("css", [])),
        "requests_count": len(event.get("requests", [])),
        "forms_count": len(event.get("forms", [])),
        "timestamp": datetime.utcnow().isoformat(),
    }

    _db_update_scan(
        scan_id,
        status="complete",
        detection_count=len(detections),
        highest_severity=highest,
        vpn_country=vpn_country,
        exit_ip=exit_ip,
        ua_used=resolved_ua,
        result_json=json.dumps(result),
    )
    return result


# ---------------------------------------------------------------------------
# Batch execution (runs in background thread)
# ---------------------------------------------------------------------------

def _execute_batch(batch_id: str, scan_ids: list[str], urls: list[str], config: dict) -> None:
    """
    Execute a batch of scans.  Handles VPN rotation and concurrency.
    Pushes SSE events to the per-batch queue as scans complete.
    """
    use_vpn        = config.get("use_vpn", False)
    target_country = config.get("target_country") or None
    delay_ms       = config.get("delay_ms", 0)
    rotate_per_scan = config.get("rotate_per_scan", False)
    rotate_every_n  = int(config.get("rotate_every_n", 0))
    concurrency     = max(1, int(config.get("concurrency", 1)))

    total = len(urls)
    complete = 0
    failed   = 0
    scan_counter = 0

    def _maybe_rotate():
        try:
            OpsecManager.rotate_server(target_country)
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_scan = {}

        for idx, (scan_id, url) in enumerate(zip(scan_ids, urls)):
            # VPN rotation before submission
            if use_vpn:
                if rotate_per_scan:
                    _maybe_rotate()
                elif rotate_every_n > 0 and idx > 0 and idx % rotate_every_n == 0:
                    _maybe_rotate()

            future = executor.submit(
                _execute_scan, scan_id, url, use_vpn, None, delay_ms
            )
            future_to_scan[future] = scan_id

        for future in concurrent.futures.as_completed(future_to_scan):
            scan_id = future_to_scan[future]
            try:
                result = future.result()
                scan_counter += 1
                if result.get("status") == "failed":
                    failed += 1
                    _db_increment_batch(batch_id, failed_delta=1)
                else:
                    complete += 1
                    _db_increment_batch(batch_id, complete_delta=1)

                _push_sse(batch_id, "scan_complete", {
                    "scan_id": scan_id,
                    "url": result.get("url", ""),
                    "status": result.get("status"),
                    "detection_count": result.get("detection_count", 0),
                    "highest_severity": result.get("highest_severity", "none"),
                })
            except Exception as exc:
                failed += 1
                _db_increment_batch(batch_id, failed_delta=1)
                _db_update_scan(scan_id, status="failed",
                                result_json=json.dumps({"error": str(exc)}))
                _push_sse(batch_id, "scan_complete", {
                    "scan_id": scan_id,
                    "status": "failed",
                    "error": str(exc),
                })

    # Batch complete sentinel
    _push_sse(batch_id, "batch_complete", {
        "batch_id": batch_id,
        "total": total,
        "complete": complete,
        "failed": failed,
    })


# ---------------------------------------------------------------------------
# Background thread pool for single scans
# ---------------------------------------------------------------------------

_scan_executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def scan_submit():
    """
    POST /api/scan
    Body: { url, use_vpn?, target_country?, delay_ms? }
    Returns: { scan_id }
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    scan_id      = str(uuid.uuid4())
    use_vpn      = bool(data.get("use_vpn", False))
    delay_ms     = int(data.get("delay_ms", 0))
    target_country = data.get("target_country") or None

    if use_vpn and target_country:
        try:
            OpsecManager.connect(target_country)
        except Exception:
            pass

    _db_insert_scan(scan_id, url, status="pending")
    _scan_executor.submit(_execute_scan, scan_id, url, use_vpn, None, delay_ms)

    return jsonify({"scan_id": scan_id}), 202


@app.route("/api/scan/<scan_id>", methods=["GET"])
def scan_status(scan_id: str):
    """
    GET /api/scan/<id>
    Returns: { status, result, error }
    """
    row = _db_get_scan(scan_id)
    if row is None:
        return jsonify({"error": "scan not found"}), 404

    result = None
    error  = None
    if row["result_json"]:
        try:
            result = json.loads(row["result_json"])
        except ValueError:
            pass

    if row["status"] == "failed" and result:
        error = result.get("error_message") or result.get("error")

    return jsonify({"status": row["status"], "result": result, "error": error})


@app.route("/api/scan/batch", methods=["POST"])
def batch_submit():
    """
    POST /api/scan/batch
    Body: { urls[], use_vpn?, target_country?, rotate_per_scan?,
            rotate_every_n?, concurrency?, delay_ms? }
    Returns: { batch_id }
    """
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])
    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "urls must be a non-empty array"}), 400

    batch_id = str(uuid.uuid4())
    config   = {
        "use_vpn":         bool(data.get("use_vpn", False)),
        "target_country":  data.get("target_country") or None,
        "rotate_per_scan": bool(data.get("rotate_per_scan", False)),
        "rotate_every_n":  int(data.get("rotate_every_n", 0)),
        "concurrency":     max(1, int(data.get("concurrency", 1))),
        "delay_ms":        int(data.get("delay_ms", 0)),
    }

    # Pre-create all scan rows and the batch row
    scan_ids = []
    for idx, url in enumerate(urls):
        scan_id = str(uuid.uuid4())
        scan_ids.append(scan_id)
        _db_insert_scan(scan_id, url, status="pending")
        _db_link_batch_scan(batch_id, scan_id, idx)

    _db_insert_batch(batch_id, len(urls), config)
    _get_batch_queue(batch_id)  # ensure queue exists before thread starts

    threading.Thread(
        target=_execute_batch,
        args=(batch_id, scan_ids, urls, config),
        daemon=True,
    ).start()

    return jsonify({"batch_id": batch_id}), 202


@app.route("/api/batch/<batch_id>", methods=["GET"])
def batch_status(batch_id: str):
    """
    GET /api/batch/<id>
    Returns: { total, complete, pending, failed, results[] }
    """
    row = _db_get_batch(batch_id)
    if row is None:
        return jsonify({"error": "batch not found"}), 404

    scan_rows = _db_get_batch_scans(batch_id)
    results = []
    for sr in scan_rows:
        entry = {k: sr[k] for k in ("id", "url", "timestamp", "status",
                                     "detection_count", "highest_severity",
                                     "vpn_country", "exit_ip", "ua_used")}
        if sr.get("result_json"):
            try:
                entry["result"] = json.loads(sr["result_json"])
            except ValueError:
                entry["result"] = None
        results.append(entry)

    pending = row["total"] - row["complete"] - row["failed"]
    return jsonify({
        "total":    row["total"],
        "complete": row["complete"],
        "pending":  max(0, pending),
        "failed":   row["failed"],
        "results":  results,
    })


@app.route("/api/batch/<batch_id>/stream", methods=["GET"])
def batch_stream(batch_id: str):
    """
    GET /api/batch/<id>/stream
    SSE stream — emits scan_complete events and a final batch_complete event.
    """
    if _db_get_batch(batch_id) is None:
        return jsonify({"error": "batch not found"}), 404

    q = _get_batch_queue(batch_id)

    def generate():
        while True:
            try:
                msg = q.get(timeout=30)
                yield msg
                if "batch_complete" in msg:
                    break
            except queue.Empty:
                # Send a keepalive comment to prevent client timeout
                yield ": keepalive\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/history", methods=["GET"])
def history():
    """
    GET /api/history
    Returns last 100 scans with verdict summary.
    """
    conn = _db_conn()
    rows = conn.execute(
        "SELECT id, url, timestamp, status, detection_count, highest_severity, "
        "vpn_country, exit_ip, ua_used FROM scans "
        "ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/opsec/status", methods=["GET"])
def opsec_status():
    """
    GET /api/opsec/status
    Returns full OpsecManager status.  Called every 10s by UI — must be fast.
    """
    return jsonify(OpsecManager.get_status())


@app.route("/api/opsec/rotate", methods=["POST"])
def opsec_rotate():
    """
    POST /api/opsec/rotate
    Body: { country? }
    Returns: { success, new_server, new_exit_ip, country }
    """
    data    = request.get_json(silent=True) or {}
    country = data.get("country") or None
    try:
        status = OpsecManager.rotate_server(country)
        return jsonify({
            "success":     status.get("connected", False),
            "new_server":  status.get("server", ""),
            "new_exit_ip": status.get("exit_ip", ""),
            "country":     status.get("country_code", ""),
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/opsec/connect", methods=["POST"])
def opsec_connect():
    """
    POST /api/opsec/connect
    Body: { country }
    """
    data    = request.get_json(silent=True) or {}
    country = data.get("country", "").strip()
    if not country:
        return jsonify({"error": "country is required"}), 400
    try:
        return jsonify(OpsecManager.connect(country))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/opsec/disconnect", methods=["POST"])
def opsec_disconnect():
    """POST /api/opsec/disconnect"""
    try:
        return jsonify(OpsecManager.disconnect())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/rules", methods=["GET"])
def rules_info():
    """
    GET /api/rules
    Returns: { count, rules_dir, last_updated }
    """
    rules_path = Path(IOK_RULES)
    count = 0
    last_updated = None
    if rules_path.exists():
        yml_files = list(rules_path.rglob("*.yml"))
        count = len(yml_files)
        if yml_files:
            newest = max(f.stat().st_mtime for f in yml_files)
            last_updated = datetime.utcfromtimestamp(newest).isoformat()
    return jsonify({
        "count":        count,
        "rules_dir":    IOK_RULES,
        "last_updated": last_updated,
    })


@app.route("/api/opsec/countries", methods=["GET"])
def opsec_countries():
    """
    GET /api/opsec/countries
    Returns: { countries: [...] }  — cached 5 min in OpsecManager
    """
    return jsonify({"countries": OpsecManager.get_available_countries()})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    print(f"[+] IOK Detection Lab API")
    print(f"[+] Rules:      {IOK_RULES}")
    print(f"[+] DB:         {DB_PATH}")
    print(f"[+] Workers:    {MAX_WORKERS}")
    app.run(host="0.0.0.0", port=5000, debug=False)
