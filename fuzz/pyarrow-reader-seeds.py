#!/usr/bin/env python3
"""Reader seeds from a writer other than Plank's: pyarrow (Arrow C++).

Usage: uv run --with pyarrow python fuzz/pyarrow-reader-seeds.py <output-dir> [max-bytes=8192]

What Plank's writer cannot or does not emit, and real-world writers do: version 1.0 files with legacy
converted types only, INT96 timestamps, DELTA_BYTE_ARRAY on FIXED_LEN_BYTE_ARRAY, BYTE_STREAM_SPLIT on
every width, bloom filters with and without length, page indexes, page checksums, data page v1/v2, dictionary
fallbacks, every codec, decimals as integers, old-style (non-compliant) list shapes, many pages and row groups.

Each file is emitted under route bytes 0x00 (file schema), 0x04 (cross-check both nullabilities),
0x08 (also a pruned scan) and 0x02 (row API); see PlankReaderFuzzTarget.cs. Files above max-bytes are dropped.
"""
import decimal
import io
import itertools
import os
import sys

import pyarrow as pa
import pyarrow.parquet as pq

out = sys.argv[1]
max_bytes = int(sys.argv[2]) if len(sys.argv) > 2 else 8192
os.makedirs(out, exist_ok=True)
ROUTES = (0x00, 0x04, 0x08, 0x02)
written = 0
seen = set()


def n(count, f):
    return [f(i) for i in range(count)]


def with_nulls(values, every=4):
    return [None if i % every == 1 else v for i, v in enumerate(values)]


def emit(name, table, **kw):
    global written
    buf = io.BytesIO()
    try:
        pq.write_table(table, buf, **kw)
    except Exception as e:  # unsupported option combination in this pyarrow
        print(f"  skipped {name}: {type(e).__name__}: {str(e)[:100]}")
        return
    data = buf.getvalue()
    if len(data) > max_bytes or data in seen:
        return
    seen.add(data)
    for r in ROUTES:
        with open(os.path.join(out, f"pa-{name}-r{r:02x}.bin"), "wb") as f:
            f.write(bytes([r]) + data)
    written += 1


D = decimal.Decimal
COUNT = 300
cols = {
    "i32": pa.array(n(COUNT, lambda i: (i * 37) % 1000 - 300), pa.int32()),
    "i64": pa.array(n(COUNT, lambda i: i * 1_000_003 % 99991), pa.int64()),
    "f32": pa.array(n(COUNT, lambda i: (i % 50) / 4), pa.float32()),
    "f64": pa.array(n(COUNT, lambda i: (i % 50) / 8), pa.float64()),
    "bool": pa.array(n(COUNT, lambda i: i % 3 == 0), pa.bool_()),
    "str": pa.array(n(COUNT, lambda i: f"key-{i // 4:04d}-{'x' * (i % 5)}"), pa.string()),
    "bin": pa.array(n(COUNT, lambda i: bytes([i % 7]) * (i % 9)), pa.binary()),
    "flba": pa.array(n(COUNT, lambda i: (i // 3).to_bytes(16, "little")), pa.binary(16)),
    "dec32": pa.array(n(COUNT, lambda i: D(i) / 100), pa.decimal128(9, 2)),
    "dec64": pa.array(n(COUNT, lambda i: D(i * 997) / 1000), pa.decimal128(18, 3)),
    "dec128": pa.array(n(COUNT, lambda i: D(i * 7919) / 10**6), pa.decimal128(30, 6)),
    "date": pa.array(n(COUNT, lambda i: 18000 + i % 40), pa.date32()),
    "ts_ms": pa.array(n(COUNT, lambda i: 1_600_000_000_000 + i * 1000), pa.timestamp("ms")),
    "ts_us": pa.array(n(COUNT, lambda i: 1_600_000_000_000_000 + i * 1000), pa.timestamp("us", tz="UTC")),
    "ts_ns": pa.array(n(COUNT, lambda i: 1_600_000_000_000_000_000 + i * 1000), pa.timestamp("ns")),
    "time32": pa.array(n(COUNT, lambda i: i * 1000), pa.time32("ms")),
    "time64": pa.array(n(COUNT, lambda i: i * 1000), pa.time64("us")),
    "u8": pa.array(n(COUNT, lambda i: i % 256), pa.uint8()),
    "i16": pa.array(n(COUNT, lambda i: i - 100), pa.int16()),
    "u32": pa.array(n(COUNT, lambda i: i * 1_000_003 % (2**32)), pa.uint32()),
    "u64": pa.array(n(COUNT, lambda i: i * 1_000_003_000_003), pa.uint64()),
}
nullable = {k + "_opt": pa.array(with_nulls(v.to_pylist()), v.type) for k, v in cols.items()}
cols_all = {**cols, **nullable}

# 1. one column per file, every type, plain vs dictionary, v1 vs v2 pages, v1.0 vs 2.6 format (legacy converted types)
for name, arr in cols_all.items():
    t = pa.table({"c": arr})
    for ver, dpv, dic in itertools.product(("1.0", "2.6"), ("1.0", "2.0"), (True, False)):
        emit(f"{name}-v{ver}-dp{dpv}-d{int(dic)}", t, version=ver, data_page_version=dpv, use_dictionary=dic,
             compression="none")

# 2. codecs
for codec in ("snappy", "gzip", "brotli", "zstd", "lz4"):
    for name in ("i64", "str_opt", "f64", "dec64_opt"):
        for dpv in ("1.0", "2.0"):
            emit(f"codec-{codec}-{name}-dp{dpv}", pa.table({"c": cols_all[name]}), compression=codec,
                 data_page_version=dpv)
    for level in (1, 9):
        emit(f"codec-{codec}-lvl{level}", pa.table({"c": cols_all["str"]}), compression=codec,
             compression_level=level)

# 3. explicit encodings
ENC = {
    "i32": ("DELTA_BINARY_PACKED", "PLAIN", "BYTE_STREAM_SPLIT"),
    "i64": ("DELTA_BINARY_PACKED", "PLAIN", "BYTE_STREAM_SPLIT"),
    "f32": ("BYTE_STREAM_SPLIT", "PLAIN"),
    "f64": ("BYTE_STREAM_SPLIT", "PLAIN"),
    "bool": ("RLE", "PLAIN"),
    "str": ("DELTA_BYTE_ARRAY", "DELTA_LENGTH_BYTE_ARRAY", "PLAIN"),
    "bin": ("DELTA_BYTE_ARRAY", "DELTA_LENGTH_BYTE_ARRAY"),
    "flba": ("DELTA_BYTE_ARRAY", "BYTE_STREAM_SPLIT", "PLAIN"),
    "dec32": ("DELTA_BYTE_ARRAY", "BYTE_STREAM_SPLIT", "PLAIN"),
    "dec128": ("DELTA_BYTE_ARRAY", "BYTE_STREAM_SPLIT"),
    "date": ("DELTA_BINARY_PACKED", "BYTE_STREAM_SPLIT"),
    "ts_us": ("DELTA_BINARY_PACKED", "BYTE_STREAM_SPLIT"),
    "ts_ms": ("DELTA_BINARY_PACKED",),
    "time64": ("DELTA_BINARY_PACKED", "BYTE_STREAM_SPLIT"),
    "u32": ("DELTA_BINARY_PACKED", "BYTE_STREAM_SPLIT"),
    "u64": ("DELTA_BINARY_PACKED", "BYTE_STREAM_SPLIT"),
    "u8": ("DELTA_BINARY_PACKED",),
}
for name, encs in ENC.items():
    for enc in encs:
        for opt in ("", "_opt"):
            for dpv in ("1.0", "2.0"):
                emit(f"enc-{enc.lower()}-{name}{opt}-dp{dpv}", pa.table({"c": cols_all[name + opt]}),
                     use_dictionary=False, column_encoding={"c": enc}, data_page_version=dpv, compression="none")
for name in ("f32", "f64", "i32", "i64", "flba", "dec128"):
    emit(f"bss-flag-{name}", pa.table({"c": cols_all[name]}), use_dictionary=False, use_byte_stream_split=True,
         compression="none")

# 4. INT96, decimals as integers, coerced timestamps, adjusted-to-utc times
for unit in ("ms", "us", "ns"):
    arr = pa.array(n(COUNT, lambda i: 1_600_000_000_000 + i * 1000), pa.timestamp(unit))
    emit(f"int96-{unit}", pa.table({"c": arr}), use_deprecated_int96_timestamps=True, compression="none")
    emit(f"int96-{unit}-opt", pa.table({"c": pa.array(with_nulls(arr.to_pylist()), arr.type)}),
         use_deprecated_int96_timestamps=True, compression="none", use_dictionary=False)
    emit(f"coerce-{unit}", pa.table({"c": cols["ts_ns"]}), coerce_timestamps=unit, allow_truncated_timestamps=True,
         compression="none")
for name in ("dec32", "dec64", "dec128"):
    emit(f"decint-{name}", pa.table({"c": cols_all[name]}), store_decimal_as_integer=True, compression="none")
emit("time-utc", pa.table({"c": cols["time64"]}), write_time_adjusted_to_utc=True, compression="none")

# 5. page / row-group structure, page index, checksums, statistics off
big = pa.table({"a": cols["i32"], "b": cols_all["str_opt"], "c": cols["f64"]})
for rg in (0, 100, 37):
    for mrpp in (None, 50, 7):
        for idx in (False, True):
            emit(f"struct-rg{rg}-pp{mrpp}-idx{int(idx)}", big, row_group_size=rg or None, max_rows_per_page=mrpp,
                 write_page_index=idx, compression="none", use_dictionary=False, data_page_version="2.0")
emit("checksum-v1", big, write_page_checksum=True, data_page_version="1.0", compression="none")
emit("checksum-v2", big, write_page_checksum=True, data_page_version="2.0", compression="snappy")
emit("nostats", big, write_statistics=False, compression="none")
emit("dictlimit", pa.table({"c": cols["str"]}), dictionary_pagesize_limit=64, compression="none")
emit("cdc", big, use_content_defined_chunking=True, compression="none")
emit("sorted", pa.table({"c": pa.array(sorted(cols["i32"].to_pylist()))}),
     sorting_columns=[pq.SortingColumn(0)], compression="none")
emit("no-store-schema", big, store_schema=False, compression="none")

# 6. bloom filters: with and without the optional length field depending on writer, several column types
for name in ("i32", "i64", "str", "f64", "flba"):
    for opts in (True, {"ndv": 50, "fpp": 0.05}, {"ndv": 1000, "fpp": 0.001}):
        emit(f"bloom-{name}-{'default' if opts is True else opts['ndv']}", pa.table({"c": cols_all[name]}),
             bloom_filter_options={"c": opts}, compression="none")
emit("bloom-multi", big, bloom_filter_options={"a": True, "b": True, "c": True}, write_page_index=True,
     compression="none")

# 7. nested shapes, compliant and legacy (v1/"old list") layouts, maps, structs
lst = pa.array(n(100, lambda i: [j for j in range(i % 5)] if i % 7 else None), pa.list_(pa.int32()))
lst_str = pa.array(n(100, lambda i: [f"s{j}" for j in range(i % 4)] if i % 6 else None), pa.list_(pa.string()))
mp = pa.array(n(100, lambda i: [(f"k{j}", j) for j in range(i % 4)] if i % 5 else None), pa.map_(pa.string(), pa.int64()))
st = pa.array(n(100, lambda i: {"x": i, "y": f"v{i % 5}", "z": None if i % 3 == 0 else float(i)}),
              pa.struct([("x", pa.int32()), ("y", pa.string()), ("z", pa.float64())]))
deep = pa.array(n(60, lambda i: [[j] * (i % 3) for j in range(i % 4)] if i % 5 else None),
                pa.list_(pa.list_(pa.int16())))
for name, arr in (("list", lst), ("liststr", lst_str), ("map", mp), ("struct", st), ("deep", deep)):
    for compliant, dpv, enc in itertools.product((True, False), ("1.0", "2.0"), (True, False)):
        emit(f"nested-{name}-c{int(compliant)}-dp{dpv}-d{int(enc)}", pa.table({"c": arr}),
             use_compliant_nested_type=compliant, data_page_version=dpv, use_dictionary=enc, compression="none")
for enc in ("DELTA_BINARY_PACKED", "BYTE_STREAM_SPLIT", "PLAIN"):
    emit(f"nested-list-{enc.lower()}", pa.table({"c": lst}), use_dictionary=False,
         column_encoding={"c.list.element": enc}, compression="none")
for enc in ("DELTA_BYTE_ARRAY", "DELTA_LENGTH_BYTE_ARRAY"):
    emit(f"nested-liststr-{enc.lower()}", pa.table({"c": lst_str}), use_dictionary=False,
         column_encoding={"c.list.element": enc}, compression="none")

# 8. all-null / empty / single-row columns
emit("allnull", pa.table({"c": pa.array([None] * 50, pa.int64())}), compression="none")
emit("allnull-str", pa.table({"c": pa.array([None] * 50, pa.string())}), compression="snappy")
emit("single", pa.table({"c": pa.array([1], pa.int32())}), compression="none")
emit("empty", pa.table({"c": pa.array([], pa.int32())}), compression="none")
emit("empty-str-values", pa.table({"c": pa.array([""] * 40, pa.string())}), compression="none")

print(f"wrote {written} files x {len(ROUTES)} routes to {out}")
