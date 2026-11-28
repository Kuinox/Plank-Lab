#!/usr/bin/env bash
# Proves each guard layer fires: every case but "ok" must kill the replay driver. Usage: guard-selftest.sh <replay-dir>
RP="$1"; fail=0
for mode in end start; do
  for c in ok pool pool-write shim input uar borrow; do
    out=$(PLANK_FUZZ_GUARD=$mode "$RP/Plank.Fuzzing.Replay" guard-selftest $c 2>&1); rc=$?
    if [ $c = ok ]; then [ $rc -eq 0 ] && r=PASS || r=FAIL; else
      echo "$out" | grep -qE "AccessViolation|GUARD-VIOLATION" && [ $rc -ne 0 ] && r=PASS || r=FAIL; fi
    [ $r = FAIL ] && fail=1
    echo "$r $mode $c rc=$rc $(echo "$out" | grep -E 'AccessViolation|GUARD-VIOLATION|SURVIVED|^ok' | head -1)"
  done
done
exit $fail
