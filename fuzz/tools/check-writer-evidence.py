#!/usr/bin/env python3
"""Check that every Temporal branch of the WTM1 route ran, from a replay log made with PLANK_ORACLE_COUNTERS=1.

Usage:
  # inputs pinned to kind 11 (Temporal): marker 0xC8 'WTM1' + little-endian kind + random bytes
  PLANK_ORACLE_COUNTERS=1 Plank.Fuzzing.Replay writer <dir> 2> log
  python3 fuzz/tools/check-writer-evidence.py log
Exit status 1 and the list of missing cells when a branch never ran.
"""
import itertools, re, sys

evidence = {}
for line in open(sys.argv[1], errors="ignore"):
    m = re.match(r"EVIDENCE (\S+) (\d+)", line)
    if m:
        evidence[m.group(1)] = int(m.group(2))

units = ["Millis", "Micros", "Nanos"]
need = [f"temporal.date.opt={o}.roundtrip" for o in (True, False)]
for u, a, o in itertools.product(units, (True, False), (True, False)):
    need += [
        f"temporal.time.{u}.adj={a}.opt={o}.roundtrip",
        f"temporal.timestamp.{u}.adj={a}.opt={o}.roundtrip",
        f"temporal.timestamp-wrongkind.{u}.adj={a}.opt={o}.rejected",
        f"temporal.offset.{u}.adj={a}.opt={o}." + ("roundtrip" if a else "rejected"),
    ]
need += [f"variant{v}.DateTimeOffset.verified" for v in (1, 2, 3)] + ["temporal.offset.nonzero-offset-values"]
missing = [n for n in need if n not in evidence]
print(f"{len(need) - len(missing)}/{len(need)} Temporal branches ran")
for n in missing:
    print("MISSING", n)
sys.exit(1 if missing else 0)
