#!/bin/sh
set -eu
PQ=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_FILE="$PQ/orchestrator.pid"
LOG="$PQ/logs/orchestrator.log"
if [ -f "$PID_FILE" ]; then
    pid=$(sed -n '1p' "$PID_FILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        printf 'Autoresearch is already running (PID %s).\n' "$pid"
        exit 0
    fi
fi
mkdir -p "$PQ/logs"
rm -f "$PQ/STOP"
nohup setsid uv run --with pyarrow --with duckdb python -u "$PQ/orchestrator.py" >>"$LOG" 2>&1 &
pid=$!
printf '%s\n' "$pid" >"$PID_FILE"
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
    printf 'Autoresearch failed to start; see %s\n' "$LOG" >&2
    exit 1
fi
printf 'Autoresearch started (PID %s).\n' "$pid"
