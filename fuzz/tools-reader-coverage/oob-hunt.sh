#!/usr/bin/env bash
# Replays structure-aware mutants of the reader seeds under an exact-fit, guard-byte pool (PLANK_FUZZ_POOL=1|2) and a 1 GiB heap cap,
# keeping every input that faults, mismatches or kills the process. Restart-safe per chunk. Usage: oob-hunt.sh <replay-dir> <out-dir> <chunks> <chunk-size> <seed-base>
set -u
RP="$1"; OUT="$2"; CHUNKS="$3"; SIZE="$4"; BASE="$5"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; F="$ROOT/fuzz"
SEEDS="${OOB_SEEDS:-$F/reader-gap-generated $F/reader-corpus $F/reader-pyarrow-seeds $F/reader-pqt-seeds $F/reader-focused-seeds $F/reader-gap-seeds}"
mkdir -p "$OUT"
for c in $(seq 0 $((CHUNKS - 1))); do
  [ -f "$OUT/chunk-$c.done" ] && continue
  D=$(mktemp -d); python3 -I "$F/mutate-decoder-seeds.py" "$D" "$SIZE" $((BASE + c)) $SEEDS
  for pool in 1 2 0; do
    LOG="$OUT/chunk-$c-pool$pool.log"
    DOTNET_GCHeapHardLimit=0x40000000 PLANK_FUZZ_POOL=$pool PLANK_FUZZ_CONTINUE_ON_CRASH=1 nice "$RP/Plank.Fuzzing.Replay" reader "$D" > "$LOG" 2>&1
    rc=$?
    if [ $rc -ne 0 ] && ! grep -q '^done' "$LOG"; then mkdir -p "$OUT/died-$c-pool$pool"; cp -r "$D" "$OUT/died-$c-pool$pool/inputs"; fi
    for f in $(grep -E '^(FAULT|CRASH|MISMATCH)' "$LOG" | cut -f2 | sort -u); do cp "$f" "$OUT/hit-c$c-p$pool-$(basename "$f")" 2>/dev/null; done
  done
  rm -rf "$D"; touch "$OUT/chunk-$c.done"
done
