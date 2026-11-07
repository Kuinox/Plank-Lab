#!/usr/bin/env bash
# Time-share one pinned core between the reader and the writer targets.
#
# With a single worker the campaign only ever ran the reader, so the writer target
# (write, then read back with Plank and Arrow) went unfuzzed for days. run-fleet.sh
# stops every running worker before it starts, so alternating calls is enough.
# The ISA rotation restarts at the native tier on every call, so the tier length must
# divide the window: 30 min tiers give the reader all four tiers twice in 4 h and the
# writer all four once in 2 h.
#
# Usage: setsid nohup fuzz/rotate-targets.sh >fuzz/logs/rotate.log 2>&1 &
# Stop:  kill the rotate-targets.sh process, then fuzz/stop-worker.sh main
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="${PLANK_FUZZ_FIRST_CORE:-23}"
READER_SECONDS="${READER_SECONDS:-14400}"
WRITER_SECONDS="${WRITER_SECONDS:-7200}"
TIER_SECONDS="${TIER_SECONDS:-1800}"
cd "$ROOT"
while true; do
  for slot in "reader $READER_SECONDS" "writer $WRITER_SECONDS"; do
    set -- $slot
    echo "$(date -Is) ==> $1 for $2 s"
    PLANK_FUZZ_FIRST_CORE=$CORE PLANK_FUZZ_ROTATE_ISA=$TIER_SECONDS bash fuzz/run-fleet.sh "$1" 1
    sleep "$2"
  done
done
