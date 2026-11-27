#!/usr/bin/env python3
"""Check that every Temporal / decimal / converter / append-merge branch of the WTM1 route ran, from a replay log made with PLANK_ORACLE_COUNTERS=1.

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
# decimals: every mode on every physical form (modes 6 and 7 are asserted rejections), converters, variants
for mode in range(9):
    if mode == 6:
        need.append("decimal.mode6.lossy-fraction.rejected")
    elif mode == 7:
        need.append("decimal.mode7.overflow.rejected")
    else:
        need += [f"decimal.mode{mode}.{ph}.roundtrip" for ph in ("Int32", "Int64", "FixedLenByteArray", "ByteArray")]
for u, o in itertools.product(("NotInt", "NotLong"), ("optional", "required")):
    need += [f"converter.{u}.unsigned={a}.{o}.roundtrip" for a in (True, False)]
need += [f"converter-unsigned-physical.{t}.annotated={a}.{o}.roundtrip"
         for t in ("uint", "ulong") for a in (True, False) for o in ("optional", "required")]
need += [f"converter-guid.{o}.roundtrip" for o in ("optional", "required")]
need += [f"variant{v}.{t}.verified" for v in (1, 3) for t in ("Int32", "Int64", "Decimal", "Double", "Byte[]", "FlipGuid", "NotInt", "NotLong")]
need += [f"variant{v}.DateTimeOffset.verified" for v in (1, 2, 3)] + ["temporal.offset.nonzero-offset-values"]
missing = [n for n in need if n not in evidence]
print(f"{len(need) - len(missing)}/{len(need)} WTM1 branches ran")
for n in missing:
    print("MISSING", n)
sys.exit(1 if missing else 0)
