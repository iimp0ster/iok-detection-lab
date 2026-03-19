#!/usr/bin/env bash
# IOK Detection Lab — start the web server
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── defaults ─────────────────────────────────────────────────────────── #
export IOK_DB="${IOK_DB:-$SCRIPT_DIR/scans.db}"
export IOK_RULES="${IOK_RULES:-$SCRIPT_DIR/IOK/indicators}"
export IOK_COLLECTOR="${IOK_COLLECTOR:-$SCRIPT_DIR/scripts/iok_collector.py}"
export IOK_DETECTOR="${IOK_DETECTOR:-$SCRIPT_DIR/scripts/iok_detector.py}"
export IOK_WORK_DIR="${IOK_WORK_DIR:-/tmp/iok_web}"
export IOK_MAX_WORKERS="${IOK_MAX_WORKERS:-3}"
export IOK_TIMEOUT="${IOK_TIMEOUT:-60}"
export PORT="${PORT:-5000}"

echo "[iok] starting on http://0.0.0.0:${PORT}"
echo "[iok] db:      ${IOK_DB}"
echo "[iok] rules:   ${IOK_RULES}"

exec python3 web/app.py
