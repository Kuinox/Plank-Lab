#!/usr/bin/env bash
# Stop the run-fleet.sh worker whose AFL_TMPDIR is fuzz/.tmp/<name> (default main):
# kill its respawn loop first, then SIGINT afl-fuzz so it saves its state.
# Walks the process tree rather than pkill -f, whose pattern can match the shell
# that runs it.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${1:-main}"
for pid in $(pgrep -x afl-fuzz); do
  env_tmp=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep '^AFL_TMPDIR=' | cut -d= -f2-)
  [ "$env_tmp" = "$ROOT/fuzz/.tmp/$NAME" ] || continue
  p=$pid
  while p=$(ps -o ppid= -p "$p" | tr -d ' ') && [ -n "$p" ] && [ "$p" -gt 1 ]; do
    if ps -o args= -p "$p" | grep -q '^bash -c'; then kill "$p"; break; fi
  done
  kill -INT "$pid"
done
# afl-fuzz saves its state on SIGINT before exiting; wait for that, since the
# output directory stays locked until it is gone.
for _ in $(seq 60); do
  running=0
  for pid in $(pgrep -x afl-fuzz); do
    tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -q "^AFL_TMPDIR=$ROOT/fuzz/.tmp/$NAME\$" && running=1
  done
  [ "$running" -eq 0 ] && break
  sleep 1
done
echo "afl-fuzz still running for $NAME: $(for pid in $(pgrep -x afl-fuzz); do tr '\0' '\n' < /proc/$pid/environ 2>/dev/null | grep -c "^AFL_TMPDIR=$ROOT/fuzz/.tmp/$NAME\$"; done | grep -c 1)"
