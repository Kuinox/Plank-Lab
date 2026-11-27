#!/usr/bin/env python3
"""Generate fuzz/decompressor-seeds/: inputs for the reader target's bit-7 decompressor route
(PlankDecompressorFuzzTarget). Layout: [0]=selector byte with bit 7 set (0x80; the reader harness strips it),
[1]=codec (byte % 6 picks the codec:
0 Snappy 1 Gzip 2 Zstd 3 Lz4 4 Brotli 5 Lz4Legacy), [2..4]=destination length BE, rest = payload.
Seeds cover raw LZ4 blocks and every Lz4Legacy framing (Hadoop blocks, LZ4 frames with/without
content size, block and content checksums, dependent blocks, uncompressed blocks, skippable frames).
Usage: decompressor-seeds.py [outdir]"""
import gzip, os, struct, sys
out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'decompressor-seeds')
os.makedirs(out, exist_ok=True)
M = 0xFFFFFFFF
def rotl(x, r): return ((x << r) | (x >> (32 - r))) & M
P1, P2, P3, P4, P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
def xxh32(b, seed=0):
    n = len(b); i = 0
    if n >= 16:
        v = [(seed + P1 + P2) & M, (seed + P2) & M, seed, (seed - P1) & M]
        while i <= n - 16:
            for k in range(4):
                v[k] = (rotl((v[k] + struct.unpack_from('<I', b, i)[0] * P2) & M, 13) * P1) & M; i += 4
        h = (rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18)) & M
    else:
        h = (seed + P5) & M
    h = (h + n) & M
    while i + 4 <= n:
        h = (rotl((h + struct.unpack_from('<I', b, i)[0] * P3) & M, 17) * P4) & M; i += 4
    while i < n:
        h = (rotl((h + b[i] * P5) & M, 11) * P1) & M; i += 1
    h ^= h >> 15; h = (h * P2) & M; h ^= h >> 13; h = (h * P3) & M; h ^= h >> 16
    return h
def sel(codec): return codec
def seed(name, codec, dest, payload):
    open(os.path.join(out, name), 'wb').write(bytes([0x80, sel(codec)]) + struct.pack('>H', dest) + payload)
def lz4_lit(d):  # literal-only block
    n = len(d)
    if n < 15: return bytes([n << 4]) + d
    r = n - 15; ext = b'\xff' * (r // 255) + bytes([r % 255])
    return bytes([0xF0]) + ext + d
def lz4_run(d, rep):  # d literals then match offset len(d), repeated `rep` extra bytes; last 5 literal rule: add tail
    tail = b'ZZZZZZ'
    m = rep - 4
    tok_m = min(m, 15)
    blk = bytes([(min(len(d), 15) << 4) | tok_m]) + d + struct.pack('<H', len(d))
    if m >= 15:
        r = m - 15; blk += b'\xff' * (r // 255) + bytes([r % 255])
    return blk + bytes([len(tail) << 4]) + tail, d + (d * (rep // len(d) + 1))[:rep] + tail
raw = bytes(range(32)) * 3
blk = lz4_lit(raw)
rb, rexp = lz4_run(b'abcd', 300)
seed('lz4-raw-literal.bin', 3, len(raw), blk)
seed('lz4-raw-match.bin', 3, len(rexp), rb)
seed('lz4-raw-dest-too-small.bin', 3, 10, blk)
seed('snappy-literal.bin', 0, 5, bytes([5, 0x10]) + b'hello')
seed('snappy-copy.bin', 0, 10, bytes([10, 0x10]) + b'hello' + bytes([((5 - 4) << 2) | 1 | 0, 5]))
seed('gzip.bin', 1, 100, gzip.compress(b'x' * 100))
# Hadoop-framed blocks (big-endian uncompressed/stored lengths, may repeat)
seed('lz4legacy-hadoop-1.bin', 5, len(raw), struct.pack('>II', len(raw), len(blk)) + blk)
seed('lz4legacy-hadoop-2.bin', 5, len(raw) * 2, (struct.pack('>II', len(raw), len(blk)) + blk) * 2)
seed('lz4legacy-hadoop-badlen.bin', 5, len(raw), struct.pack('>II', len(raw), len(blk) + 9) + blk)
seed('lz4legacy-rawblock.bin', 5, len(raw), blk)
def frame(blocks, flags=0x60, bd=0x40, content=None, bchk=False, cchk=None, ccs=None, magic=0x184D2204):
    desc = bytes([flags, bd]) + (struct.pack('<Q', ccs) if ccs is not None else b'')
    f = struct.pack('<I', magic) + desc + bytes([(xxh32(desc) >> 8) & 0xFF])
    for stored, un in blocks:
        h = len(stored) | (0x80000000 if un else 0)
        f += struct.pack('<I', h) + stored
        if flags & 0x10: f += struct.pack('<I', xxh32(stored) ^ (1 if bchk else 0))
    f += struct.pack('<I', 0)
    if flags & 0x04: f += struct.pack('<I', xxh32(content) ^ (1 if cchk else 0))
    return f
seed('lz4legacy-frame-basic.bin', 5, len(raw), frame([(blk, False)]))
seed('lz4legacy-frame-contentsize.bin', 5, len(raw), frame([(blk, False)], flags=0x68, ccs=len(raw)))
seed('lz4legacy-frame-contentsize-mismatch.bin', 5, len(raw), frame([(blk, False)], flags=0x68, ccs=len(raw) + 1))
seed('lz4legacy-frame-blockchecksum.bin', 5, len(raw), frame([(blk, False)], flags=0x70))
seed('lz4legacy-frame-blockchecksum-bad.bin', 5, len(raw), frame([(blk, False)], flags=0x70, bchk=True))
seed('lz4legacy-frame-contentchecksum.bin', 5, len(raw), frame([(blk, False)], flags=0x64, content=raw))
seed('lz4legacy-frame-contentchecksum-bad.bin', 5, len(raw), frame([(blk, False)], flags=0x64, content=raw, cchk=True))
seed('lz4legacy-frame-uncompressed-block.bin', 5, len(raw), frame([(raw, True)]))
seed('lz4legacy-frame-dependent-blocks.bin', 5, len(raw) + len(rexp), frame([(blk, False), (rb, False)], flags=0x40))
seed('lz4legacy-frame-independent-blocks.bin', 5, len(raw) + len(rexp), frame([(blk, False), (rb, False)], flags=0x60))
seed('lz4legacy-frame-two-frames.bin', 5, len(raw) * 2, frame([(blk, False)]) + frame([(blk, False)]))
seed('lz4legacy-frame-skippable.bin', 5, len(raw), struct.pack('<II', 0x184D2A53, 4) + b'skip' + frame([(blk, False)]))
seed('lz4legacy-frame-block-5.bin', 5, len(raw), frame([(blk, False)], bd=0x50))
seed('lz4legacy-frame-block-7.bin', 5, len(raw), frame([(blk, False)], bd=0x70))
seed('lz4legacy-frame-dictid.bin', 5, len(raw), frame([(blk, False)], flags=0x61))
seed('lz4legacy-frame-truncated.bin', 5, len(raw), frame([(blk, False)])[:20])
seed('lz4legacy-frame-badmagic-second.bin', 5, len(raw) * 2, frame([(blk, False)]) + b'\x01\x02\x03\x04')

# --- zstd / brotli / gzip variants (need `zstandard` and `brotli` Python modules; seeds are committed,
# so these only run when someone regenerates: uv pip install --target /tmp/pyc zstandard brotli; PYTHONPATH=/tmp/pyc) ---
try:
    import zstandard, brotli
except ImportError:
    zstandard = brotli = None
if zstandard:
    text = (b'the quick brown fox jumps over the lazy dog ' * 40) + bytes(range(256))
    n = len(text)
    z = zstandard.ZstdCompressor(level=3)
    zf = z.compress(text)
    seed('zstd-frame.bin', 2, n, zf)
    seed('zstd-frame-no-contentsize.bin', 2, n, zstandard.ZstdCompressor(level=3, write_content_size=False).compress(text))
    seed('zstd-two-frames.bin', 2, n * 2, zf + zf)
    seed('zstd-level19.bin', 2, n, zstandard.ZstdCompressor(level=19).compress(text))
    seed('zstd-checksum.bin', 2, n, zstandard.ZstdCompressor(level=3, write_checksum=True).compress(text))
    seed('zstd-incompressible.bin', 2, 300, zstandard.ZstdCompressor().compress(bytes((i * 167 + 13) & 0xFF for i in range(300))))
    seed('zstd-dest-too-small.bin', 2, 50, zf)
    seed('zstd-truncated.bin', 2, n, zf[:len(zf) // 2])
    seed('zstd-corrupt-checksum.bin', 2, n, bytearray(zstandard.ZstdCompressor(write_checksum=True).compress(text))[:-1] + b'\x00')
    seed('zstd-dest-zero.bin', 2, 0, zf)
if brotli:
    text = (b'abcabcabc hello hello hello ' * 50)
    n = len(text)
    bf = brotli.compress(text, quality=5)
    seed('brotli-q5.bin', 4, n, bf)
    seed('brotli-q0.bin', 4, n, brotli.compress(text, quality=0))
    seed('brotli-q11.bin', 4, n, brotli.compress(text, quality=11))
    seed('brotli-empty.bin', 4, 0, brotli.compress(b''))
    seed('brotli-dest-too-small.bin', 4, 20, bf)
    seed('brotli-truncated.bin', 4, n, bf[:len(bf) // 2])
    seed('brotli-trailing-garbage.bin', 4, n, bf + b'\x00garbage')
gz = gzip.compress(b'multi member one ' * 20)
gz2 = gzip.compress(b'second member ' * 20)
seed('gzip-two-members.bin', 1, len(b'multi member one ' * 20) + len(b'second member ' * 20), gz + gz2)
seed('gzip-truncated.bin', 1, 340, gz[:len(gz) - 6])
seed('gzip-bad-crc.bin', 1, 340, gz[:-8] + b'\xde\xad\xbe\xef' + gz[-4:])
seed('gzip-dest-too-small.bin', 1, 10, gz)
seed('gzip-trailing-garbage.bin', 1, 340, gz + b'junk')
seed('gzip-empty-dest.bin', 1, 0, gzip.compress(b''))
