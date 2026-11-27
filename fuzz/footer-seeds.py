#!/usr/bin/env python3
"""Hand-crafted footer variants of small pyarrow files, for reader paths no ordinary writer reaches.

Usage: uv run --with pyarrow python fuzz/footer-seeds.py <output-dir> [max-bytes=8192]

The footer (Thrift compact protocol) is decoded into a tree, mutated, and re-serialised; the file body is untouched
apart from the footer length. Mutations:
  unknown-*      unknown fields of every Thrift type (list/set/map/struct/double/binary/bool/byte/i16/i64, nested)
                 injected at FileMetaData, RowGroup, ColumnChunk, ColumnMetaData and SchemaElement level: the
                 CompactStructLength.SkipValue/SkipElements skippers and the reader's tolerance for newer writers.
  nolength       bloom_filter_length removed (BloomFilterReader.OpenWithoutLength)
  gap-*          column/offset index offsets and data/dictionary page offsets shifted so the pages no longer abut
                 (PageMetadataReader.ValidateLocationGap)
  geo-*          geospatial statistics (bbox with and without z/m, geospatial_types) and GEOMETRY/GEOGRAPHY logical types
  legacy-*       logicalType dropped (converted type only), converted type dropped (logical only)
  pageheader-*   unknown fields inside PAGE headers (and their nested DataPageHeader structs), with every later
                 offset fixed up: PageHeaderProbe/CompactStructLength skip nested lists, sets, maps and structs while
                 growing a header window, and the fragmented-stream route (0x64) makes it ask for more bytes.
Route bytes 0x00 and 0x04 (and 0x64 for page headers) are prepended. Plank's writer cannot produce any of these shapes.
"""
import io
import os
import struct
import sys

import pyarrow as pa
import pyarrow.parquet as pq

out = sys.argv[1]
max_bytes = int(sys.argv[2]) if len(sys.argv) > 2 else 8192
os.makedirs(out, exist_ok=True)

# ---- compact protocol ------------------------------------------------------
T_TRUE, T_FALSE, T_BYTE, T_I16, T_I32, T_I64, T_DOUBLE, T_BINARY, T_LIST, T_SET, T_MAP, T_STRUCT = range(1, 13)


class R:
    def __init__(self, b): self.b, self.i = b, 0
    def byte(self):
        v = self.b[self.i]; self.i += 1; return v
    def varint(self):
        s = r = 0
        while True:
            c = self.byte(); r |= (c & 0x7F) << s; s += 7
            if not c & 0x80: return r
    def zz(self):
        n = self.varint(); return (n >> 1) ^ -(n & 1)


def read_value(r, t):
    if t in (T_TRUE, T_FALSE): return t == T_TRUE
    if t == T_BYTE: return r.byte()
    if t in (T_I16, T_I32, T_I64): return r.zz()
    if t == T_DOUBLE:
        v = r.b[r.i:r.i + 8]; r.i += 8; return v
    if t == T_BINARY:
        n = r.varint(); v = r.b[r.i:r.i + n]; r.i += n; return v
    if t in (T_LIST, T_SET):
        h = r.byte(); n = h >> 4; et = h & 15
        if n == 15: n = r.varint()
        # collection elements use 1/2 for bool bytes
        return ("L", t, et, [read_bool_elem(r) if et in (T_TRUE, T_FALSE) else read_value(r, et) for _ in range(n)])
    if t == T_MAP:
        n = r.varint()
        if n == 0: return ("M", 0, 0, [])
        kv = r.byte()
        return ("M", kv >> 4, kv & 15, [(read_value(r, kv >> 4), read_value(r, kv & 15)) for _ in range(n)])
    if t == T_STRUCT: return read_struct(r)
    raise ValueError(t)


def read_bool_elem(r): return r.byte() == 1


def read_struct(r):
    fields, last = [], 0
    while True:
        h = r.byte()
        if h == 0: return fields
        t = h & 15; d = h >> 4
        fid = last + d if d else r.zz()
        last = fid
        fields.append([fid, t, read_value(r, t)])


def wv(o, n):
    while n > 0x7F: o.append((n & 0x7F) | 0x80); n >>= 7
    o.append(n)


def wzz(o, n, bits=64): wv(o, ((n << 1) ^ (n >> 63)) & 0xFFFFFFFFFFFFFFFF)


def write_value(o, t, v):
    if t in (T_TRUE, T_FALSE): return
    if t == T_BYTE: o.append(v)
    elif t in (T_I16, T_I32, T_I64): wzz(o, v)
    elif t == T_DOUBLE: o += v
    elif t == T_BINARY: wv(o, len(v)); o += v
    elif t in (T_LIST, T_SET):
        _, _, et, items = v
        if len(items) < 15: o.append(len(items) << 4 | et)
        else: o.append(0xF0 | et); wv(o, len(items))
        for x in items:
            if et in (T_TRUE, T_FALSE): o.append(1 if x else 2)
            else: write_value(o, et, x)
    elif t == T_MAP:
        _, kt, vt, items = v
        wv(o, len(items))
        if items:
            o.append(kt << 4 | vt)
            for k, x in items: write_value(o, kt, k); write_value(o, vt, x)
    elif t == T_STRUCT: write_struct(o, v)


def write_struct(o, fields):
    last = 0
    for fid, t, v in sorted(fields, key=lambda f: f[0]):
        tt = (T_TRUE if v else T_FALSE) if t in (T_TRUE, T_FALSE) else t
        d = fid - last
        if 0 < d <= 15: o.append(d << 4 | tt)
        else: o.append(tt); wzz(o, fid)
        last = fid
        write_value(o, t, v)
    o.append(0)


def get(fields, fid):
    for f in fields:
        if f[0] == fid: return f
    return None


def put(fields, fid, t, v):
    f = get(fields, fid)
    if f: f[1], f[2] = t, v
    else: fields.append([fid, t, v])


def drop(fields, fid): fields[:] = [f for f in fields if f[0] != fid]


def dbl(x): return struct.pack("<d", x)


# ---- file plumbing -----------------------------------------------------------
def split(data):
    n = struct.unpack("<I", data[-8:-4])[0]
    return data[:-8 - n], read_struct(R(data[-8 - n:-8]))


def join(body, meta):
    o = bytearray(); write_struct(o, meta)
    return body + bytes(o) + struct.pack("<I", len(o)) + b"PAR1"


written = 0


def emit(name, body, meta, routes=(0x00, 0x04)):
    global written
    data = join(body, meta)
    if len(data) > max_bytes: return
    for r in routes:
        with open(os.path.join(out, f"footer-{name}-r{r:02x}.bin"), "wb") as f: f.write(bytes([r]) + data)
    written += 1


def pa_file(table, **kw):
    b = io.BytesIO(); pq.write_table(table, b, **kw); return b.getvalue()


def row_groups(meta): return get(meta, 4)[2][3]
def col_chunks(rg): return get(rg, 1)[2][3]
def schema(meta): return get(meta, 2)[2][3]


def clone(meta):
    o = bytearray(); write_struct(o, meta); return read_struct(R(bytes(o)))


base = pa_file(pa.table({"a": pa.array(range(40), pa.int32()), "s": pa.array([f"v{i % 5}" for i in range(40)]),
                         "d": pa.array([i / 4 for i in range(40)], pa.float64())}),
               compression="none", write_page_index=True)
bloom = pa_file(pa.table({"a": pa.array(range(40), pa.int64())}), compression="none",
                bloom_filter_options={"a": True}, write_page_index=True)
tsfile = pa_file(pa.table({"t": pa.array([1_600_000_000_000 + i for i in range(30)], pa.timestamp("ms")),
                           "dec": pa.array([i for i in range(30)], pa.decimal128(9, 0)),
                           "dt": pa.array([18000 + i for i in range(30)], pa.date32())}),
                 compression="none", version="2.6")

# ---- unknown fields at each level -------------------------------------------
UNKNOWN = {
    "i16": (T_I16, 77), "i64": (T_I64, -5), "byte": (T_BYTE, 9), "true": (T_TRUE, True), "false": (T_FALSE, False),
    "double": (T_DOUBLE, dbl(1.5)), "binary": (T_BINARY, b"hello"), "empty-binary": (T_BINARY, b""),
    "list-i32": (T_LIST, ("L", T_LIST, T_I32, [1, 2, 3])),
    "list-bool": (T_LIST, ("L", T_LIST, T_TRUE, [True, False, True])),
    "list-bin": (T_LIST, ("L", T_LIST, T_BINARY, [b"a", b"bc"])),
    "list-big": (T_LIST, ("L", T_LIST, T_I32, list(range(20)))),
    "set-i64": (T_SET, ("L", T_SET, T_I64, [1, 2])),
    "empty-list": (T_LIST, ("L", T_LIST, T_I32, [])),
    "list-struct": (T_LIST, ("L", T_LIST, T_STRUCT, [[[1, T_I32, 4], [2, T_BINARY, b"x"]], []])),
    "map": (T_MAP, ("M", T_BINARY, T_I32, [(b"k", 1), (b"j", 2)])),
    "map-empty": (T_MAP, ("M", 0, 0, [])),
    "map-struct": (T_MAP, ("M", T_I32, T_STRUCT, [(1, [[1, T_I32, 2]])])),
    "struct": (T_STRUCT, [[1, T_I32, 3], [2, T_LIST, ("L", T_LIST, T_I32, [1])], [3, T_STRUCT, [[1, T_BYTE, 1]]]]),
    "deep": (T_LIST, ("L", T_LIST, T_LIST, [("L", T_LIST, T_LIST, [("L", T_LIST, T_I32, [1])])])),
}
LEVELS = {
    "file": lambda m: m,
    "rowgroup": lambda m: row_groups(m)[0],
    "chunk": lambda m: col_chunks(row_groups(m)[0])[0],
    "colmeta": lambda m: get(col_chunks(row_groups(m)[0])[0], 3)[2],
    "schema": lambda m: schema(m)[1],
}
_, meta0 = split(base)
body0 = split(base)[0]
for lname, pick in LEVELS.items():
    for uname, (t, v) in UNKNOWN.items():
        m = clone(meta0)
        put(pick(m), 99, t, v)
        emit(f"unknown-{lname}-{uname}", body0, m)
    m = clone(meta0)
    for i, (uname, (t, v)) in enumerate(UNKNOWN.items()):  # many at once, interleaved with known ids
        put(pick(m), 30 + i, t, v)
    emit(f"unknown-{lname}-all", body0, m)
# unknown field where the reader expects a known id with another type (type confusion)
m = clone(meta0); put(m, 3, T_BINARY, b"notanumber"); emit("confused-numrows", body0, m)
m = clone(meta0); put(m, 1, T_BINARY, b"x"); emit("confused-version", body0, m)

# ---- bloom length missing -----------------------------------------------------
bbody, bmeta = split(bloom)
m = clone(bmeta)
cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]
drop(cm, 15)
emit("bloom-nolength", bbody, m)
m = clone(bmeta); cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]; put(cm, 15, T_I32, 0); emit("bloom-zerolength", bbody, m)
m = clone(bmeta); cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]; put(cm, 15, T_I32, 3); emit("bloom-shortlength", bbody, m)
m = clone(bmeta); cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]; put(cm, 15, T_I32, 1 << 30); emit("bloom-hugelength", bbody, m)
m = clone(bmeta); cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]; drop(cm, 15); put(cm, 14, T_I64, len(bbody) + 5)
emit("bloom-nolength-badoffset", bbody, m)

# ---- location gaps --------------------------------------------------------------
for k in (1, 7, 64):
    for fid, label in ((4, "offsetindex"), (6, "columnindex")):
        m = clone(bmeta if False else meta0)
        cc = col_chunks(row_groups(m)[0])[0]
        f = get(cc, fid)
        if f: f[2] += k; emit(f"gap-{label}-plus{k}", body0, m)
    # pad the body between the column data and the indexes: shift every offset beyond data
    m = clone(meta0)
    cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]
    put(cm, 9, T_I64, get(cm, 9)[2] + k)
    emit(f"gap-datapage-plus{k}", body0, m)
    m = clone(meta0)
    cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]
    put(cm, 7, T_I64, get(cm, 7)[2] + k)  # total_compressed_size too long
    emit(f"gap-compressed-plus{k}", body0, m)
    m = clone(meta0)
    cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]
    put(cm, 7, T_I64, max(1, get(cm, 7)[2] - k))
    emit(f"gap-compressed-minus{k}", body0, m)
# padding inserted between row-group data and the index regions, offsets fixed up consistently (a real gap)
pad_at = min(get(col_chunks(row_groups(meta0)[0])[0], fid)[2] for fid in (4, 6) if get(col_chunks(row_groups(meta0)[0])[0], fid))
for pad in (1, 13):
    m = clone(meta0)
    for rg in row_groups(m):
        for cc in col_chunks(rg):
            for fid in (4, 6):
                f = get(cc, fid)
                if f and f[2] >= pad_at: f[2] += pad
    emit(f"gap-indexpadding-{pad}", body0[:pad_at] + b"\0" * pad + body0[pad_at:], m)

# ---- geospatial statistics and logical types -------------------------------------
def bbox(z=False, m=False):
    f = [[1, T_DOUBLE, dbl(-10.0)], [2, T_DOUBLE, dbl(10.0)], [3, T_DOUBLE, dbl(-5.0)], [4, T_DOUBLE, dbl(5.0)]]
    if z: f += [[5, T_DOUBLE, dbl(0.0)], [6, T_DOUBLE, dbl(100.0)]]
    if m: f += [[7, T_DOUBLE, dbl(1.0)], [8, T_DOUBLE, dbl(2.0)]]
    return f


for label, geo in {
    "bbox": [[1, T_STRUCT, bbox()]],
    "bbox-z": [[1, T_STRUCT, bbox(z=True)]],
    "bbox-m": [[1, T_STRUCT, bbox(m=True)]],
    "bbox-zm": [[1, T_STRUCT, bbox(True, True)]],
    "types": [[2, T_LIST, ("L", T_LIST, T_I32, [1, 2, 1001, 3001])]],
    "bbox-types": [[1, T_STRUCT, bbox(True, True)], [2, T_LIST, ("L", T_LIST, T_I32, [1, 2, 3, 4, 5, 6, 7])]],
    "empty": [],
    "bbox-nan": [[1, T_STRUCT, [[1, T_DOUBLE, struct.pack("<d", float("nan"))], [2, T_DOUBLE, dbl(1.0)],
                                [3, T_DOUBLE, dbl(0.0)], [4, T_DOUBLE, dbl(1.0)]]]],
    "bbox-partial": [[1, T_STRUCT, [[1, T_DOUBLE, dbl(1.0)]]]],
    "bbox-confused": [[1, T_STRUCT, [[1, T_BINARY, b"x"]]]],
}.items():
    m = clone(meta0)
    cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]
    put(cm, 17, T_STRUCT, [list(f) for f in geo])
    emit(f"geo-stats-{label}", body0, m)

for label, lt in {
    "geometry": [[17, T_STRUCT, [[1, T_BINARY, b"OGC:CRS84"]]]],
    "geometry-nocrs": [[17, T_STRUCT, []]],
    "geography": [[18, T_STRUCT, [[1, T_BINARY, b"OGC:CRS84"], [2, T_I32, 0]]]],
    "geography-alg": [[18, T_STRUCT, [[2, T_I32, 3]]]],
    "geography-badalg": [[18, T_STRUCT, [[2, T_I32, 99]]]],
    "geometry-longcrs": [[17, T_STRUCT, [[1, T_BINARY, b"srid:" + b"1" * 300]]]],
    "variant": [[16, T_STRUCT, []]],
    "unknown": [[99, T_STRUCT, []]],
}.items():
    for col in (1, 2):
        m = clone(meta0)
        el = schema(m)[col]
        put(el, 10, T_STRUCT, [list(f) for f in lt])
        drop(el, 6)
        emit(f"geo-logical-{label}-col{col}", body0, m)

# ---- legacy converted types only -----------------------------------------------------
tbody, tmeta = split(tsfile)
for label, edit in {
    "logical-dropped": lambda el: drop(el, 10),
    "converted-dropped": lambda el: drop(el, 6),
    "both-dropped": lambda el: (drop(el, 6), drop(el, 10)),
}.items():
    m = clone(tmeta)
    for el in schema(m)[1:]: edit(el)
    emit(f"legacy-{label}", tbody, m)
for ct in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 99):
    m = clone(tmeta)
    el = schema(m)[2]
    drop(el, 10); put(el, 6, T_I32, ct)
    emit(f"legacy-converted-{ct}", tbody, m)
    m = clone(tmeta)
    el = schema(m)[1]
    drop(el, 10); put(el, 6, T_I32, ct)
    emit(f"legacy-converted-ts-{ct}", tbody, m)


# ---- unknown fields inside page headers -----------------------------------------------------
def shift_offsets(meta, at, delta):
    for rg in row_groups(meta):
        f = get(rg, 5)
        if f and f[2] >= at: f[2] += delta
        for cc in col_chunks(rg):
            for fid in (2, 4, 6):
                f = get(cc, fid)
                if f and f[2] >= at: f[2] += delta
            cm = get(cc, 3)[2]
            for fid in (9, 10, 11, 14):
                f = get(cm, fid)
                if f and f[2] >= at: f[2] += delta


def header_edit(body, meta, edit, columns=None):
    """Rewrite the page header at each chunk's first page (last chunk first, so earlier offsets stay valid)."""
    m = clone(meta)
    starts = []
    for rg in row_groups(m):
        for ci, cc in enumerate(col_chunks(rg)):
            cm = get(cc, 3)[2]
            starts.append(min(get(cm, fid)[2] for fid in (9, 11) if get(cm, fid) and get(cm, fid)[2] > 0))
    body = bytearray(body)
    for ci in sorted(range(len(starts)), key=lambda i: -starts[i]):
        if columns is not None and ci not in columns: continue
        r = R(bytes(body)); r.i = starts[ci]
        header = read_struct(r)
        old_len = r.i - starts[ci]
        edit(header)
        o = bytearray(); write_struct(o, header)
        body[starts[ci]:starts[ci] + old_len] = o
        shift_offsets(m, starts[ci] + 1, len(o) - old_len)
    return bytes(body), m


nodict = {}
for dpv in ("1.0", "2.0"):
    nodict[dpv] = split(pa_file(pa.table({"a": pa.array(range(40), pa.int32()),
                                          "s": pa.array([f"v{i % 5}" for i in range(40)]),
                                          "d": pa.array([i / 4 for i in range(40)], pa.float64())}),
                                compression="none", use_dictionary=False, data_page_version=dpv))
    wd = split(pa_file(pa.table({"s": pa.array([f"v{i % 5}" for i in range(80)])}), compression="none",
                       data_page_version=dpv))
    nodict[dpv + "-dict"] = wd
for dpv, (pbody, pmeta) in nodict.items():
    sub = 5 if dpv.startswith("1.0") else 8
    for uname, (t, v) in UNKNOWN.items():
        for where in ("page", "sub"):
            def edit(h, t=t, v=v, where=where, sub=sub):
                target = h if where == "page" else (get(h, sub) or get(h, 7))[2]
                put(target, 60, t, v)
            body2, m2 = header_edit(pbody, pmeta, edit)
            emit(f"pageheader-{dpv}-{where}-{uname}", body2, m2, routes=(0x00, 0x04, 0x64, 0x42))
    def edit_all(h, sub=sub):
        for i, (t, v) in enumerate(UNKNOWN.values()):
            put(h, 30 + i, t, v)
    body2, m2 = header_edit(pbody, pmeta, edit_all)
    emit(f"pageheader-{dpv}-all", body2, m2, routes=(0x00, 0x04, 0x64, 0x42))
    # a crc field (page checksum) that is wrong / present on every page
    def edit_crc(h): put(h, 4, T_I32, 12345)
    body2, m2 = header_edit(pbody, pmeta, edit_crc)
    emit(f"pageheader-{dpv}-badcrc", body2, m2, routes=(0x10, 0x14, 0x00))

print(f"wrote {written} files to {out}")
