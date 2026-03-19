#!/usr/bin/env python3
"""
IOK Detection Lab — web server (web/app.py)

Endpoints
---------
  GET  /                            → Hunt Panel UI (static)
  GET  /static/<path>               → Static assets

  POST /api/scan                    → Single synchronous scan
  POST /api/batch                   → Start async batch; returns batch_id
  GET  /api/batch/<id>/stream       → SSE stream of batch events
  GET  /api/batch/<id>              → Batch status + per-scan summary
  GET  /api/history                 → Recent completed scans (from SQLite)
  GET  /api/rules/stats             → IOK rule count
  GET  /api/health                  → Health / queue depth

Environment variables
---------------------
  IOK_DB           Path to SQLite DB   (default: scans.db next to this file)
  IOK_RULES        Path to rules dir   (default: ../IOK/indicators/)
  IOK_COLLECTOR    Path to collector   (default: ../scripts/iok_collector.py)
  IOK_DETECTOR     Path to detector    (default: ../scripts/iok_detector.py)
  IOK_WORK_DIR     Temp work dir       (default: /tmp/iok_web)
  IOK_MAX_WORKERS  Worker threads      (default: 3)
  IOK_TIMEOUT      Collector timeout s (default: 60)
  PORT             HTTP port           (default: 5000)
"""

import json
import logging
import os
import sys
import time
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context
from flask_cors import CORS

# ── path setup so imports work regardless of cwd ─────────────────────────── #
_HERE  = Path(__file__).resolve().parent          # web/
_ROOT  = _HERE.parent                             # iok-detection-lab/
sys.path.insert(0, str(_ROOT))

from core.batch import BatchEngine                # noqa: E402
from core.opsec import OpsecManager              # noqa: E402
from core.ua_pool import UAPool                  # noqa: E402

# ── configuration ─────────────────────────────────────────────────────────── #
DB_PATH     = os.getenv("IOK_DB",         str(_ROOT / "scans.db"))
RULES_PATH  = os.getenv("IOK_RULES",      str(_ROOT / "IOK" / "indicators"))
COLLECTOR   = os.getenv("IOK_COLLECTOR",  str(_ROOT / "scripts" / "iok_collector.py"))
DETECTOR    = os.getenv("IOK_DETECTOR",   str(_ROOT / "scripts" / "iok_detector.py"))
WORK_DIR    = os.getenv("IOK_WORK_DIR",   "/tmp/iok_web")
MAX_WORKERS = int(os.getenv("IOK_MAX_WORKERS", "3"))
TIMEOUT     = int(os.getenv("IOK_TIMEOUT", "60"))
STATIC_DIR  = str(_HERE / "static")
PORT        = int(os.getenv("PORT", "5000"))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("web.app")

# ── Flask app ──────────────────────────────────────────────────────────────── #
app = Flask(__name__, static_folder=None)
CORS(app)

# ── core services ─────────────────────────────────────────────────────────── #
opsec  = OpsecManager()    # stub mode by default (no VPN profiles configured)
ua_pool = UAPool()
engine  = BatchEngine(
    db_path=DB_PATH,
    opsec=opsec,
    ua_pool=ua_pool,
    collector_path=COLLECTOR,
    detector_path=DETECTOR,
    rules_path=RULES_PATH,
    work_dir=WORK_DIR,
    analysis_timeout=TIMEOUT,
)

# ── static UI ─────────────────────────────────────────────────────────────── #

@app.route("/")
def ui_index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/static/<path:filename>")
def ui_static(filename):
    return send_from_directory(STATIC_DIR, filename)


# ── health ────────────────────────────────────────────────────────────────── #

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "db": DB_PATH})


# ── single scan ───────────────────────────────────────────────────────────── #

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    POST /api/scan
    { "url": "https://..." }
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    # Re-use BatchEngine's single-URL scanner directly
    import hashlib
    scan_id = hashlib.sha256(f"{url}{time.time()}".encode()).hexdigest()[:32]
    exit_info = opsec.get_current_exit()
    ua        = ua_pool.get()

    try:
        result = engine._scan_url(url, "single", scan_id, ua, exit_info)
        result["ua_label"] = ua_pool.label(ua)
        return jsonify(result)
    except Exception as exc:
        log.exception("scan error for %s", url)
        return jsonify({"error": str(exc), "url": url, "success": False}), 500


# ── batch ─────────────────────────────────────────────────────────────────── #

@app.route("/api/batch", methods=["POST"])
def api_batch():
    """
    POST /api/batch
    {
        "urls": ["https://..."],
        "concurrency": 3,
        "delay_ms": 1500,
        "use_vpn": false,
        "rotate_mode": "none",
        "rotate_every_n": 5
    }
    """
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])

    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "urls must be a non-empty list"}), 400
    if len(urls) > 100:
        return jsonify({"error": "Maximum 100 URLs per batch"}), 400

    import hashlib
    batch_id = hashlib.sha256(f"batch{time.time()}".encode()).hexdigest()[:32]

    config = {
        "concurrency":    int(data.get("concurrency", MAX_WORKERS)),
        "delay_ms":       int(data.get("delay_ms", 1500)),
        "use_vpn":        bool(data.get("use_vpn", False)),
        "rotate_mode":    data.get("rotate_mode", "none"),
        "rotate_every_n": int(data.get("rotate_every_n", 5)),
    }

    engine.run_batch(batch_id, urls, config)

    return jsonify({
        "batch_id": batch_id,
        "total":    len(urls),
        "message":  "Batch started",
    }), 202


@app.route("/api/batch/<batch_id>/stream")
def api_batch_stream(batch_id):
    """
    GET /api/batch/<id>/stream
    Server-Sent Events: one event per completed scan + done sentinel.
    """
    q = engine.get_sse_queue(batch_id)
    if q is None:
        return jsonify({"error": "batch not found"}), 404

    def generate():
        while True:
            try:
                event = q.get(timeout=15)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("done"):
                    break
            except Exception:
                # keepalive comment so the connection doesn't drop
                yield ": keepalive\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/batch/<batch_id>")
def api_batch_status(batch_id):
    """GET /api/batch/<id> — summary from SQLite."""
    import sqlite3
    try:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        batch = con.execute("SELECT * FROM batches WHERE id=?", (batch_id,)).fetchone()
        if not batch:
            return jsonify({"error": "not found"}), 404
        scans = con.execute(
            "SELECT id,url,status,verdict,detection_count,exit_country,elapsed_ms,timestamp "
            "FROM scans WHERE batch_id=?", (batch_id,)
        ).fetchall()
        con.close()
        return jsonify({
            "batch":  dict(batch),
            "scans":  [dict(s) for s in scans],
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── history ───────────────────────────────────────────────────────────────── #

@app.route("/api/history")
def api_history():
    """GET /api/history — last 200 completed scans, newest first."""
    import sqlite3
    try:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """SELECT s.id, s.batch_id, s.url, s.verdict, s.detection_count,
                      s.hostname, s.exit_ip, s.exit_country, s.elapsed_ms, s.timestamp
               FROM   scans s
               WHERE  s.status = 'complete'
               ORDER  BY s.timestamp DESC
               LIMIT  200"""
        ).fetchall()
        con.close()
        return jsonify([dict(r) for r in rows])
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── rules stats ───────────────────────────────────────────────────────────── #

@app.route("/api/rules/stats")
def api_rules_stats():
    try:
        count = len(list(Path(RULES_PATH).rglob("*.yml")))
        return jsonify({"rules_directory": RULES_PATH, "rule_count": count})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── entry point ───────────────────────────────────────────────────────────── #

if __name__ == "__main__":
    log.info("IOK Detection Lab starting on port %d", PORT)
    log.info("DB:        %s", DB_PATH)
    log.info("Rules:     %s", RULES_PATH)
    log.info("Static UI: %s", STATIC_DIR)
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
