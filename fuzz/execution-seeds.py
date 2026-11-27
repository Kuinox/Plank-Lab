#!/usr/bin/env python3
"""Seeds for the buffer-pool / execution route: 0xDD "EXEC" <mode> <fuzzer choices...>.
usage: execution-seeds.py <outdir> [per-mode-count] [rng-seed]
Modes: 0 pool sequence, 1 pool concurrent, 2 schedule round trip, 3 reader lifecycle."""
import os, random, sys
out = sys.argv[1]; n = int(sys.argv[2]) if len(sys.argv) > 2 else 6
rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
os.makedirs(out, exist_ok=True)
for mode in range(4):
    for i in range(n):
        body = bytes(rng.randrange(256) for _ in range(rng.choice([32, 96, 256, 600])))
        with open(os.path.join(out, f"exec-m{mode}-{i}.bin"), "wb") as f:
            f.write(b"\xddEXEC" + bytes([mode]) + body)
