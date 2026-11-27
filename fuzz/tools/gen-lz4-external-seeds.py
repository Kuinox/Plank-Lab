#!/usr/bin/env python3
"""Seeds for WCD1 mode 6: LZ4 payloads produced by an EXTERNAL implementation (python `lz4`, liblz4 1.9.x).

  cd /tmp && uv run --no-project --with lz4 python <repo>/fuzz/tools/gen-lz4-external-seeds.py <repo>/fuzz/corpus

Writes fuzz/corpus/writer-codec-lz4ext-*.bin. Layout (see WriterCodecLz4Cases.Lz4ExternalPayload):
0xDB 'WCD1' | LE int 6 | u32 original length | u32 payload length | u32 CRC-32(payload) | SHA-256(original) | payload
"""
import hashlib, os, random, struct, sys, zlib
import lz4.block, lz4.frame

out = sys.argv[1]
rng = random.Random(20261127)


def make(kind, size):
    if kind == "zeros":
        return bytes(size)
    if kind == "random":
        return bytes(rng.randrange(256) for _ in range(size))
    if kind == "text":
        words = [b"parquet ", b"plank ", b"column ", b"row ", b"group ", b"page ", b"null ", b"value "]
        buf = bytearray()
        while len(buf) < size:
            buf += rng.choice(words)
        return bytes(buf[:size])
    if kind == "repeat":
        unit = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300)))
        return (unit * (size // len(unit) + 1))[:size]
    if kind == "window":  # matches at the edge of the 64 KiB window
        buf = bytearray(rng.randbytes(70000))
        while len(buf) < size:
            d = rng.choice([1, 255, 256, 4096, 65535])
            n = rng.randrange(4, 600)
            start = len(buf) - min(d, len(buf))
            buf += bytes(buf[start + i % d] if d <= len(buf) else 0 for i in range(n))
        return bytes(buf[:size])
    raise ValueError(kind)


def hadoop(data, piece, level):
    out = bytearray()
    for i in range(0, len(data), piece):
        chunk = data[i:i + piece]
        block = lz4.block.compress(chunk, mode="high_compression" if level >= 3 else "default",
                                   compression=max(level, 1), store_size=False)
        out += struct.pack(">II", len(chunk), len(block)) + block
    return bytes(out)


def seed(name, original, payload):
    body = (struct.pack("<iIII", 6, len(original), len(payload), zlib.crc32(payload) & 0xFFFFFFFF)
            + hashlib.sha256(original).digest() + payload)
    with open(os.path.join(out, f"writer-codec-lz4ext-{name}.bin"), "wb") as f:
        f.write(b"\xdbWCD1" + body)


n = 0
BS = {64: lz4.frame.BLOCKSIZE_MAX64KB, 256: lz4.frame.BLOCKSIZE_MAX256KB,
      1024: lz4.frame.BLOCKSIZE_MAX1MB, 4096: lz4.frame.BLOCKSIZE_MAX4MB}
# frames: every option combination class, several levels, block sizes and data kinds
for kind, size in [("text", 100), ("repeat", 5000), ("random", 3000), ("zeros", 70000), ("window", 150000),
                   ("text", 300000), ("repeat", 1), ("random", 66000)]:
    data = make(kind, size)
    for linked in (False, True):
        for bsz in rng.sample(list(BS), 2):
            level = rng.choice([0, 3, 9, 12, 16])
            opts = dict(block_size=BS[bsz], block_linked=linked, compression_level=level,
                        content_checksum=rng.random() < .5, block_checksum=rng.random() < .5,
                        store_size=rng.random() < .5)
            seed(f"frame-{kind}-{size}-{'linked' if linked else 'indep'}-{bsz}k-l{level}-{n}", data,
                 lz4.frame.compress(data, **opts))
            n += 1
# multi-frame stream and skippable frames
a, b = make("text", 40000), make("repeat", 90000)
fa, fb = lz4.frame.compress(a), lz4.frame.compress(b, block_linked=True, content_checksum=True)
skippable = struct.pack("<II", 0x184D2A53, 5) + b"hello"
seed("two-frames", a + b, fa + fb)
seed("skippable-frames", a + b, skippable + fa + skippable + fb)
# Hadoop records and bare blocks
for kind, size in [("text", 200000), ("random", 1000), ("repeat", 65536), ("window", 120000)]:
    data = make(kind, size)
    for piece in (1000, 65536, 262144):
        seed(f"hadoop-{kind}-{size}-{piece}", data, hadoop(data, piece, rng.choice([1, 9, 12])))
    seed(f"block-{kind}-{size}", data, lz4.block.compress(data, mode="high_compression", compression=12, store_size=False))
print("wrote", len([f for f in os.listdir(out) if f.startswith("writer-codec-lz4ext-")]), "seeds")
