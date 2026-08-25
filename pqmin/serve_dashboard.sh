#!/bin/sh
set -eu

PQMIN_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOG_DIR="$PQMIN_DIR/logs"
PID_FILE="$LOG_DIR/dashboard.pid"
LOG_FILE="$LOG_DIR/dashboard.log"
HOST=${PQMIN_DASHBOARD_HOST:-127.0.0.1}
PORT=${PQMIN_DASHBOARD_PORT:-8765}

mkdir -p "$LOG_DIR"

if [ -f "$PID_FILE" ]; then
    existing_pid=$(sed -n '1p' "$PID_FILE" 2>/dev/null || true)
    if [ -n "$existing_pid" ] && kill -0 "$existing_pid" 2>/dev/null; then
        printf 'Dashboard already running: http://%s:%s\n' "$HOST" "$PORT"
        exit 0
    fi
    rm -f "$PID_FILE"
fi

nohup setsid python3 -u "$PQMIN_DIR/dashboard.py" --host "$HOST" --port "$PORT" >>"$LOG_FILE" 2>&1 &
dashboard_pid=$!
printf '%s\n' "$dashboard_pid" >"$PID_FILE"

attempt=0
while [ "$attempt" -lt 30 ]; do
    if ! kill -0 "$dashboard_pid" 2>/dev/null; then
        rm -f "$PID_FILE"
        printf 'Dashboard failed to start; see %s\n' "$LOG_FILE" >&2
        exit 1
    fi
    if python3 - "$HOST" "$PORT" <<'PY' >/dev/null 2>&1
import sys
import urllib.request

with urllib.request.urlopen(f"http://{sys.argv[1]}:{sys.argv[2]}/api/health", timeout=0.2) as response:
    if response.status != 200:
        raise SystemExit(1)
PY
    then
        printf 'Dashboard: http://%s:%s\n' "$HOST" "$PORT"
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

kill "$dashboard_pid" 2>/dev/null || true
rm -f "$PID_FILE"
printf 'Dashboard did not become ready; see %s\n' "$LOG_FILE" >&2
exit 1
