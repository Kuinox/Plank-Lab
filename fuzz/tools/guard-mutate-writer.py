#!/usr/bin/env python3
"""Mutants of writer-target programs for guard replays. Usage: guard-mutate-writer.py <out-dir> <count> <seed> <file>...

Keeps the route header (marker byte + 4-byte magic when present) and mutates the parameter bytes the routes draw
counts, sizes and values from: boundary values (0, 1, 0x7F, 0x80, 0xFF, powers of two +-1), bit flips, inserted and
appended random runs (more parameters = more rows/pages/columns), deletions. Page sizes, batch sizes and buffer chunk
sizes the routes draw from these bytes then land on odd lengths.
"""
import os, random, sys
out, count, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
files = [f for f in sys.argv[4:] if os.path.isfile(f) and 0 < os.path.getsize(f) <= 65536]
rnd = random.Random(seed)
os.makedirs(out, exist_ok=True)
EDGE = [0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255]
for n in range(count):
    data = bytearray(open(rnd.choice(files), "rb").read())
    head = 5 if len(data) >= 5 and data[1:5].isascii() and bytes(data[1:5]).isalnum() else (1 if data else 0)
    for _ in range(rnd.choice([1, 1, 2, 3, 4, 8])):
        k = rnd.random()
        if len(data) <= head or k < 0.15:
            data += bytes(rnd.randrange(256) for _ in range(rnd.choice([1, 4, 16, 64, 256])))
            continue
        i = rnd.randrange(head, len(data))
        if k < 0.45:
            data[i] = rnd.choice(EDGE + [rnd.randrange(256), 0xFE, 0xFF])
        elif k < 0.6:
            data[i] ^= 1 << rnd.randrange(8)
        elif k < 0.75:
            w = rnd.choice([2, 4])
            v = rnd.choice([0, 1, 0x7FFF, 0xFFFF, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF, rnd.randrange(1 << 16)])
            data[i:i + w] = (v & ((1 << 8 * w) - 1)).to_bytes(w, "little")[:len(data[i:i + w])]
        elif k < 0.9:
            data[i:i] = bytes(rnd.randrange(256) for _ in range(rnd.choice([1, 2, 8, 32])))
        else:
            del data[i:min(len(data), i + rnd.randrange(1, 16))]
    with open(os.path.join(out, f"w{seed}-{n}.bin"), "wb") as f:
        f.write(data)
