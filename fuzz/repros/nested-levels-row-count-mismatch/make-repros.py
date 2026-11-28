#!/usr/bin/env python3
"""Writes fuzz/repros/nested-levels-row-count-mismatch/*.bin: list<int32> files whose repetition levels define a different number of rows
than the footer and the page header declare. Usage: uv run --with pyarrow python -I fuzz/repros-nested-rows.py <out-dir>"""
import os, sys
out_dir = sys.argv[1]
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "footer-seeds.py")).read().split("# ---- unknown fields at each level")[0]
sys.argv = [sys.argv[0], "/tmp/_nr_discard"]
exec(compile(src, "footer-seeds.py", "exec"))
src2 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "footer-seeds.py")).read()
src2 = src2.split("# ---- unknown fields inside page headers")[1].split("nodict = {}")[0].split("\n", 1)[1]
exec(compile(src2, "footer-seeds-hdr", "exec"))
os.makedirs(out_dir, exist_ok=True)
tbl = pa.table({"c": pa.array([[1], [2, 3], [4], [5, 6, 7]], pa.list_(pa.int32(), ), )})
tbl = tbl.cast(pa.schema([pa.field("c", pa.list_(pa.field("element", pa.int32(), nullable=False)), nullable=False)]))
for dpv in ("1.0", "2.0"):
    body, meta = split(pa_file(tbl, compression="none", use_dictionary=False, data_page_version=dpv))
    for declared in (2, 3, 6, 100):
        m = clone(meta)
        put(m, 3, T_I64, declared)
        put(row_groups(m)[0], 3, T_I64, declared)
        def edit(h, declared=declared, dpv=dpv):
            if dpv == "2.0":
                put(get(h, 8)[2], 3, T_I32, declared)
        b2, m2 = header_edit(body, m, edit)
        data = join(b2, m2)
        name = f"list-4rows-declared{declared}-dp{dpv}.bin"
        open(os.path.join(out_dir, name), "wb").write(bytes([0x00]) + data)
print("ok")

# ---- impossible level pairs: a continuation (rep=1) at a position whose definition level says the list is empty (def=0) ----
import struct as _st
tbl2 = pa.table({"c": pa.array([[1], [2, 3], [4]], pa.list_(pa.int32()))}).cast(
    pa.schema([pa.field("c", pa.list_(pa.field("element", pa.int32(), nullable=False)), nullable=False)]))
body, meta = split(pa_file(tbl2, compression="none", use_dictionary=False, data_page_version="2.0"))
def build(name, rep_bits, def_bits, values, nulls, rows=3):
    n = len(rep_bits)
    pack = lambda bits: bytes([(1 << 1) | 1, sum(b << i for i, b in enumerate(bits))])  # one bit-packed group of 8, width 1
    reps, defs = pack(rep_bits), pack(def_bits)
    vals = b"".join(_st.pack("<i", v) for v in values)
    payload = reps + defs + vals
    hdr = [[1, T_I32, 3], [2, T_I32, len(payload)], [3, T_I32, len(payload)],
           [8, T_STRUCT, [[1, T_I32, n], [2, T_I32, nulls], [3, T_I32, rows], [4, T_I32, 0], [5, T_I32, len(defs)], [6, T_I32, len(reps)], [7, T_TRUE, False]]]]
    h = bytearray(); write_struct(h, hdr)
    page = bytes(h) + payload
    new_body = b"PAR1" + page
    m = clone(meta)
    put(m, 3, T_I64, rows); put(row_groups(m)[0], 3, T_I64, rows)
    put(row_groups(m)[0], 2, T_I64, len(page))
    cm = get(col_chunks(row_groups(m)[0])[0], 3)[2]
    put(cm, 5, T_I64, n); put(cm, 6, T_I64, len(page)); put(cm, 7, T_I64, len(page)); put(cm, 9, T_I64, 4)
    for fid in (10, 11, 12, 13, 14, 15, 16): drop(cm, fid)
    for cc in col_chunks(row_groups(m)[0]):
        for fid in (4, 5, 6, 7): drop(cc, fid)
    open(os.path.join(out_dir, name), "wb").write(bytes([0x00]) + join(new_body, m))
# levels: rows [1] [2,3] [4]; valid: rep 0,0,1,0 def 1,1,1,1
build("levels-valid-control.bin", [0, 0, 1, 0], [1, 1, 1, 1], [1, 2, 3, 4], 0)
# invalid: position 2 is rep=1 (continues row 1's list) with def=0 (list empty): 3 dense values
build("levels-continuation-with-empty-def.bin", [0, 0, 1, 0], [1, 1, 0, 1], [1, 2, 4], 1)
# invalid: the first position continues a list (rep=1) although no row has started
build("levels-first-rep-nonzero.bin", [1, 0, 1, 0], [1, 1, 1, 1], [1, 2, 3, 4], 0, rows=2)
print("ok2")
