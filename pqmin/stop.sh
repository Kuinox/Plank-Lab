#!/bin/sh
set -eu
PQ=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_FILE="$PQ/orchestrator.pid"
: >"$PQ/STOP"
if [ ! -f "$PID_FILE" ]; then
    printf 'Stop sentinel created; no orchestrator PID is recorded.\n'
    exit 0
fi
pid=$(sed -n '1p' "$PID_FILE" 2>/dev/null || true)
case "$pid" in ''|*[!0-9]*) printf 'Invalid orchestrator PID file.\n' >&2; exit 1;; esac
args=$(ps -p "$pid" -o args= 2>/dev/null || true)
case "$args" in *"$PQ/orchestrator.py"*) ;; *) printf 'PID %s is not this orchestrator; refusing to stop it.\n' "$pid" >&2; exit 1;; esac
kill -TERM "$pid" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
done
if kill -0 "$pid" 2>/dev/null; then
    printf 'Orchestrator is still stopping; workers have a bounded cleanup period.\n'
else
    printf 'Autoresearch stopped.\n'
fi
