#!/usr/bin/env bash
# Append one row per AFL instance to fuzz/<target>-coverage.csv every INTERVAL
# seconds, keyed by wall-clock time.
#
# AFL's own plot_data restarts its clock whenever a worker respawns, so it
# cannot show a campaign that survived restarts as one curve. This can.
#
# Usage: coverage-history.sh <reader|writer> [interval_seconds]
set -euo pipefail

TARGET="${1:-reader}"
INTERVAL="${2:-30}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/fuzz/$TARGET-findings"
CSV="$ROOT/fuzz/$TARGET-coverage.csv"
BUCKETS="$ROOT/fuzz/disagreements"

[ -f "$CSV" ] || echo "unix_time,instance,edges_found,corpus_count,execs_done,execs_per_sec,buckets" >"$CSV"

while true; do
  now=$(date +%s)
  buckets=$(find "$BUCKETS" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
  for stats in "$OUT"/*/fuzzer_stats; do
    [ -f "$stats" ] || continue
    awk -v t="$now" -v n="$(basename "$(dirname "$stats")")" -v b="$buckets" -F' *: *' '
      { v[$1] = $2 }
      END {
        if (v["edges_found"] != "")
          print t "," n "," v["edges_found"] "," v["corpus_count"] "," v["execs_done"] "," v["execs_per_sec"] "," b
      }' "$stats" >>"$CSV"
  done
  sleep "$INTERVAL"
done
