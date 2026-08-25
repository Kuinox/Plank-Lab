#!/bin/sh
set -eu

PQMIN_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_FILE="$PQMIN_DIR/logs/dashboard.pid"

if [ ! -f "$PID_FILE" ]; then
    printf 'Dashboard is not running.\n'
    exit 0
fi

dashboard_pid=$(sed -n '1p' "$PID_FILE" 2>/dev/null || true)
case "$dashboard_pid" in
    ''|*[!0-9]*)
        printf 'Ignoring invalid dashboard PID file.\n' >&2
        rm -f "$PID_FILE"
        exit 1
        ;;
esac

if ! kill -0 "$dashboard_pid" 2>/dev/null; then
    rm -f "$PID_FILE"
    printf 'Dashboard is not running.\n'
    exit 0
fi

process_args=$(ps -p "$dashboard_pid" -o args= 2>/dev/null || true)
case "$process_args" in
    *"$PQMIN_DIR/dashboard.py"*) ;;
    *)
        printf 'PID %s is not this dashboard; refusing to stop it.\n' "$dashboard_pid" >&2
        exit 1
        ;;
esac

kill "$dashboard_pid"
attempt=0
while kill -0 "$dashboard_pid" 2>/dev/null && [ "$attempt" -lt 30 ]; do
    attempt=$((attempt + 1))
    sleep 0.1
done
if kill -0 "$dashboard_pid" 2>/dev/null; then
    printf 'Dashboard did not stop cleanly (PID %s).\n' "$dashboard_pid" >&2
    exit 1
fi
rm -f "$PID_FILE"
printf 'Dashboard stopped.\n'
