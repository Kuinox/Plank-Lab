#!/usr/bin/env python3
"""Generate compact flat BYTE_ARRAY page variants for reader coverage."""
from pathlib import Path
import io
import pyarrow as pa
import pyarrow.parquet as pq

out = Path(__file__).with_name("nested-gap-seeds")
out.mkdir(exist_ok=True)
base = [bytes([i]) + (b"prefix-" * (i % 5)) + f"tail-{i:02d}".encode() for i in range(24)]
for nullable, encoding, page_version, dictionary in (
    (True, "PLAIN", "1.0", False), (True, "PLAIN", "2.0", False),
    (False, "PLAIN", "1.0", False), (False, "PLAIN", "2.0", False),
    (True, "DELTA_LENGTH_BYTE_ARRAY", "1.0", False),
    (True, "DELTA_LENGTH_BYTE_ARRAY", "2.0", False),
    (True, "DELTA_BYTE_ARRAY", "1.0", False),
    (True, "DELTA_BYTE_ARRAY", "2.0", False),
    (True, "PLAIN", "1.0", True), (True, "PLAIN", "2.0", True),
):
    values = base if not nullable else [None if i % 7 == 2 else value for i, value in enumerate(base)]
    typ = pa.binary()
    array = pa.array(values, type=typ)
    schema = pa.schema([pa.field("c", typ, nullable=nullable)])
    table = pa.Table.from_arrays([array], schema=schema)
    name = f"binary-flat-{'optional' if nullable else 'required'}-{encoding.lower().replace('_byte_array','')}-v{1 if page_version == '1.0' else 2}{'-dict' if dictionary else ''}"
    path = out / f"{name}.parquet"
    kwargs = dict(compression="NONE", data_page_version=page_version, write_statistics=False,
                  use_dictionary=dictionary)
    if not dictionary:
        kwargs["column_encoding"] = {"c": encoding}
    pq.write_table(table, path, **kwargs)
    parquet = path.read_bytes()
    meta = pq.ParquetFile(io.BytesIO(parquet)).metadata
    column = meta.schema.column(0)
    encodings = meta.row_group(0).column(0).encodings
    if column.physical_type != "BYTE_ARRAY" or (nullable != (meta.schema.column(0).max_definition_level > 0)):
        raise RuntimeError(f"{name}: unexpected schema: {column} {meta.schema}")
    if encoding != "PLAIN" and encoding not in encodings:
        raise RuntimeError(f"{name}: requested {encoding}, got {encodings}")
    seed = out / f"nested-gap-{name}.input"
    seed.write_bytes(b"\x00" + parquet)
    print(f"{seed.name}: {column.physical_type}, {'optional' if nullable else 'required'}, {encodings}, {len(parquet)} bytes")
    path.unlink()

# Optional Boolean PLAIN pages bypass fixed-width and encoded batch dispatch,
# reaching nullable physical-type dispatch; dictionary variants exercise the
# nullable dictionary path independently.
for page_version, dictionary in (("1.0", False), ("2.0", False), ("1.0", True), ("2.0", True)):
    values = [None if i % 6 == 1 else bool(i & 1) for i in range(30)]
    table = pa.table({"c": pa.array(values, type=pa.bool_())})
    name = f"boolean-flat-optional-{'dict' if dictionary else 'plain'}-v{1 if page_version == '1.0' else 2}"
    path = out / f"{name}.parquet"
    pq.write_table(table, path, compression="NONE", data_page_version=page_version,
                   use_dictionary=dictionary, write_statistics=False)
    parquet = path.read_bytes()
    meta = pq.ParquetFile(io.BytesIO(parquet)).metadata
    encodings = meta.row_group(0).column(0).encodings
    seed = out / f"nested-gap-{name}.input"
    seed.write_bytes(b"\x00" + parquet)
    print(f"{seed.name}: {encodings}, {len(parquet)} bytes")
    path.unlink()

# Large values force an owned plain-binary batch to stop at a value boundary
# and resume from the page's saved physical and payload offsets.
for nullable, page_version in ((True, "1.0"), (True, "2.0"), (False, "1.0")):
    large_values = [bytes([i + 1]) * 100000 for i in range(4)]
    small_values = [f"v{i}".encode() for i in range(96)]
    values = [large_values[0], None, large_values[1], *small_values] if nullable else [*large_values[:2], *small_values]
    typ = pa.binary()
    schema = pa.schema([pa.field("c", typ, nullable=nullable)])
    table = pa.Table.from_arrays([pa.array(values, type=typ)], schema=schema)
    name = f"binary-flat-{'optional' if nullable else 'required'}-large-v{1 if page_version == '1.0' else 2}"
    path = out / f"{name}.parquet"
    pq.write_table(table, path, compression="NONE", data_page_version=page_version,
                   use_dictionary=False, column_encoding={"c": "PLAIN"}, write_statistics=False)
    parquet = path.read_bytes()
    seed = out / f"nested-gap-{name}.input"
    seed.write_bytes(b"\x40" + parquet)  # stream source disables binary-payload borrowing
    print(f"{seed.name}: selector=0x40, {len(values)} values, {len(parquet)} bytes")
    path.unlink()
