#!/usr/bin/env python3
"""Seeds whose footer / page headers *declare* huge sizes, counts and lengths over a tiny real payload.

Usage: uv run --with pyarrow python fuzz/resource-seeds.py <output-dir> [max-bytes=8192]

Reuses the Thrift tree codec of fuzz/footer-seeds.py. A reader must reject these quickly and without allocating what the
declaration claims (ResourceBudget in the reader target turns an over-allocation, a huge single buffer request or a slow read
into a finding): num_rows / num_values / sizes / offsets at 2^31, 2^40, 2^62, -1, schema num_children and type_length at int max,
lists whose header claims 2^28..2^31-1 elements but carry a few bytes, binaries claiming 2^30 bytes, page headers declaring
uncompressed_page_size 2^28..2^31-1 (the decompression-bomb shape, per codec), V1/V2/dictionary page value counts, null counts, level lengths.
"""
import os
import sys

out_dir = sys.argv[1]
max_bytes_arg = sys.argv[2] if len(sys.argv) > 2 else "8192"
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "footer-seeds.py")).read()
src = src.replace("""        _, _, et, items = v
        if len(items) < 15: o.append(len(items) << 4 | et)
        else: o.append(0xF0 | et); wv(o, len(items))""", """        _, _, et, items = v[:4]
        n = v[4] if len(v) > 4 else len(items)
        if n < 15: o.append(n << 4 | et)
        else: o.append(0xF0 | et); wv(o, n)""")
src = src.replace("    elif t == T_BINARY: wv(o, len(v)); o += v", """    elif t == T_BINARY:
        if isinstance(v, tuple): wv(o, v[1]); o += v[2]
        else: wv(o, len(v)); o += v""")
# do not run footer-seeds' own seed generation into the real directory
sys.argv = [sys.argv[0], "/tmp/_resource_seeds_discard", max_bytes_arg]
src = src.split("# ---- unknown fields at each level")[0] + "\n" + src.split("# ---- unknown fields inside page headers")[1].split("nodict = {}")[0].replace("-----------------------------------------------------", "", 1) if False else src
exec(compile(src, "footer-seeds.py", "exec"))
import shutil
shutil.rmtree("/tmp/_resource_seeds_discard", ignore_errors=True)
out = out_dir
os.makedirs(out, exist_ok=True)
written = 0

I32MAX, I64MAX = 2**31 - 1, 2**63 - 1
BIG32 = (I32MAX, 2**30, 2**28)
BIG64 = (I64MAX, 2**62, 2**40, 2**32, -1)


def fake_list(et, items, n): return ("L", T_LIST, et, items, n)


def emit_r(name, body, meta, routes=(0x00, 0x04)):
    emit("res-" + name, body, meta, routes)


# ---- base files, one per codec, with dictionary/optional/list columns --------------------------------
tbl = pa.table({"i": pa.array(range(30), pa.int32()),
                "s": pa.array([None if i % 4 == 1 else f"v{i % 6}" for i in range(30)]),
                "l": pa.array([[i, i + 1] if i % 3 else None for i in range(30)], pa.list_(pa.int32()))})
bases = {}
for codec in ("none", "snappy", "zstd", "gzip", "brotli", "lz4"):
    for dpv in ("1.0", "2.0"):
        bases[f"{codec}-dp{dpv}"] = split(pa_file(tbl, compression=codec, data_page_version=dpv, write_page_index=True))
bases["bloom"] = split(pa_file(pa.table({"a": pa.array(range(30), pa.int64())}), compression="none",
                               bloom_filter_options={"a": True}))
bases["nodict"] = split(pa_file(tbl, compression="none", use_dictionary=False))


def cc0(m, i=0): return col_chunks(row_groups(m)[0])[i]
def cm0(m, i=0): return get(cc0(m, i), 3)[2]


for bname in ("none-dp1.0", "snappy-dp2.0", "zstd-dp2.0"):
    body, meta = bases[bname]
    # file / row-group / column-metadata numbers
    for v in BIG64:
        m = clone(meta); put(m, 3, T_I64, v); emit_r(f"{bname}-filerows-{v}", body, m)
        m = clone(meta); put(row_groups(m)[0], 3, T_I64, v); emit_r(f"{bname}-rgrows-{v}", body, m)
        m = clone(meta); put(row_groups(m)[0], 2, T_I64, v); emit_r(f"{bname}-rgbytes-{v}", body, m)
        for fid, label in ((5, "numvalues"), (6, "uncompressed"), (7, "compressed"), (9, "datapageoffset"), (11, "dictoffset")):
            m = clone(meta); put(cm0(m, 0), fid, T_I64, v); emit_r(f"{bname}-cm-{label}-{v}", body, m)
            m = clone(meta); put(cm0(m, 1), fid, T_I64, v); emit_r(f"{bname}-cm1-{label}-{v}", body, m)
    # schema counts
    for v in BIG32:
        m = clone(meta); put(schema(m)[0], 5, T_I32, v); emit_r(f"{bname}-rootchildren-{v}", body, m)
        m = clone(meta); put(schema(m)[2], 5, T_I32, v); emit_r(f"{bname}-childchildren-{v}", body, m)
        m = clone(meta); put(schema(m)[1], 2, T_I32, v); emit_r(f"{bname}-typelength-{v}", body, m)
    # lists that claim far more elements than they carry
    for n in (2**28, 2**31 - 1, 20000):
        m = clone(meta); f = get(m, 2); f[2] = ("L", T_LIST, T_STRUCT, f[2][3][:2], n); emit_r(f"{bname}-fake-schema-{n}", body, m)
        m = clone(meta); f = get(m, 4); f[2] = ("L", T_LIST, T_STRUCT, f[2][3], n); emit_r(f"{bname}-fake-rowgroups-{n}", body, m)
        m = clone(meta); f = get(row_groups(m)[0], 1); f[2] = ("L", T_LIST, T_STRUCT, f[2][3], n); emit_r(f"{bname}-fake-columns-{n}", body, m)
        m = clone(meta); put(cm0(m, 0), 2, T_LIST, fake_list(T_I32, [0], n)); emit_r(f"{bname}-fake-encodings-{n}", body, m)
        m = clone(meta); put(cm0(m, 0), 3, T_LIST, fake_list(T_BINARY, [b"i"], n)); emit_r(f"{bname}-fake-path-{n}", body, m)
        m = clone(meta); put(m, 5, T_LIST, ("L", T_LIST, T_STRUCT, [[[1, T_BINARY, b"k"], [2, T_BINARY, b"v"]]], n)); emit_r(f"{bname}-fake-kv-{n}", body, m)
        m = clone(meta); put(m, 7, T_LIST, fake_list(T_STRUCT, [[]], n)); emit_r(f"{bname}-fake-colorders-{n}", body, m)
        m = clone(meta); put(cm0(m, 0), 13, T_LIST, ("L", T_LIST, T_STRUCT, [[[1, T_I32, 0], [2, T_I32, 0], [3, T_I32, 1]]], n)); emit_r(f"{bname}-fake-encstats-{n}", body, m)
    # binaries that claim a gigabyte
    for n in (2**30, I32MAX, 2**28):
        m = clone(meta); put(m, 6, T_BINARY, ("B", n, b"x")); emit_r(f"{bname}-fake-createdby-{n}", body, m)
        m = clone(meta); put(schema(m)[1], 4, T_BINARY, ("B", n, b"i")); emit_r(f"{bname}-fake-name-{n}", body, m)
        m = clone(meta); put(m, 5, T_LIST, ("L", T_LIST, T_STRUCT, [[[1, T_BINARY, ("B", n, b"k")]]])); emit_r(f"{bname}-fake-kvkey-{n}", body, m)

# ---- page headers ------------------------------------------------------------------------------------------
for bname, (body, meta) in bases.items():
    v2 = "dp2.0" in bname
    sub = 8 if v2 else 5
    def sized(fid, v, bname=bname):
        def edit(h): put(h, fid, T_I32, v)
        return edit
    for v in (I32MAX, 2**30, 2**28, 2**20, -1, 0):
        for fid, label in ((2, "uncompressed"), (3, "compressed")):
            b2, m2 = header_edit(body, meta, sized(fid, v))
            emit_r(f"page-{bname}-{label}-{v}", b2, m2, routes=(0x00, 0x04, 0x64))
        def count(h, v=v, sub=sub):
            s = get(h, sub) or get(h, 7)
            if s: put(s[2], 1, T_I32, v)
        b2, m2 = header_edit(body, meta, count)
        emit_r(f"page-{bname}-numvalues-{v}", b2, m2, routes=(0x00, 0x04, 0x64))
        if v2:
            for fid, label in ((2, "nulls"), (3, "rows"), (5, "deflen"), (6, "replen")):
                def f(h, v=v, fid=fid):
                    s = get(h, 8)
                    if s: put(s[2], fid, T_I32, v)
                b2, m2 = header_edit(body, meta, f)
                emit_r(f"page-{bname}-v2{label}-{v}", b2, m2)
        else:
            for fid, label in ((2, "enc"), (3, "defenc"), (4, "repenc")):
                def f(h, v=v, fid=fid):
                    s = get(h, 5)
                    if s: put(s[2], fid, T_I32, v)
                b2, m2 = header_edit(body, meta, f)
                emit_r(f"page-{bname}-v1{label}-{v}", b2, m2)

# bloom filter header claiming a huge bitset
body, meta = bases["bloom"]
for n in (I32MAX, 2**30, 2**28):
    pos = get(cm0(meta), 14)[2]
    b2 = bytearray(body)
    # bloom header: numBytes (field 1, i32) first; rewrite the first field in place when it has a 1-byte varint
    r = R(bytes(b2)); r.i = pos
    hdr = read_struct(r)
    old_len = r.i - pos
    put(hdr, 1, T_I32, n)
    o = bytearray(); write_struct(o, hdr)
    nb = bytes(b2[:pos]) + bytes(o) + bytes(b2[pos + old_len:])
    m = clone(meta)
    put(cm0(m), 15, T_I32, len(o) + 32)
    emit_r(f"bloom-numbytes-{n}", nb, m)

print(f"wrote {written} resource seeds to {out}")
