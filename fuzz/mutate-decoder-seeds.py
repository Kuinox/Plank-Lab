#!/usr/bin/env python3
"""Structure-aware byte mutations of valid reader seeds, aimed at the decoders' length/count/width fields.

Usage: mutate-decoder-seeds.py <out-dir> <count> <seed> <seed-dir-or-file>...

The route byte (first byte) is kept. Mutations touch the page region (first ~60% of the file) far more than the footer, and write
the values that break arithmetic: 0, 1, 0x7f, 0x80, 0xff, 2^31-1, 2^32-1, length+-1, bit widths 0/1/32/33/63/64/65, run headers with a huge count.
"""
import os, random, struct, sys
out, count, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
files = []
for p in sys.argv[4:]:
    if os.path.isdir(p):
        files += [os.path.join(p, f) for f in sorted(os.listdir(p)) if os.path.getsize(os.path.join(p, f)) <= int(os.environ.get("MUT_MAXSIZE", "6000"))]
    else:
        files.append(p)
rnd = random.Random(seed)
os.makedirs(out, exist_ok=True)
INTS = [0, 1, 2, 7, 8, 9, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 0x7FFF, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
for n in range(count):
    data = bytearray(open(rnd.choice(files), 'rb').read())
    if len(data) < 16:
        continue
    for _ in range(rnd.choice([1, 1, 2, 3, 5])):
        region = int(len(data) * 0.6) if rnd.random() < 0.8 else len(data)
        i = rnd.randrange(1, max(2, region))
        kind = rnd.random()
        if kind < 0.35:
            data[i] = rnd.choice([0, 1, 2, 0x3F, 0x7F, 0x80, 0xFE, 0xFF, rnd.randrange(256)])
        elif kind < 0.5:
            data[i] ^= 1 << rnd.randrange(8)
        elif kind < 0.8:
            v = rnd.choice(INTS + [len(data), len(data) - 1, len(data) + 1, i, region])
            w = rnd.choice([2, 4, 4, 8])
            data[i:i + w] = (v & ((1 << 8 * w) - 1)).to_bytes(w, 'little')[: len(data[i:i + w])]
        elif kind < 0.9:
            # varint-ish: a long continuation run (Thrift / RLE headers)
            data[i:i + 5] = bytes([0xFF, 0xFF, 0xFF, 0xFF, rnd.choice([0x07, 0x0F, 0x7F])])[: len(data[i:i + 5])]
        elif kind < 0.95:
            j = rnd.randrange(i, len(data))
            del data[i:j]
        else:
            j = min(len(data), i + rnd.randrange(1, 64))
            data[i:i] = data[i:j]
    with open(os.path.join(out, f"m{seed}-{n}.bin"), 'wb') as f:
        f.write(data)
