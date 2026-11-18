#!/usr/bin/env python3
"""Generate tiny file-schema Variant seeds for the reader.

Usage: variant-schema-seeds.py <output-dir>

PyArrow does not expose Parquet's Variant logical annotation yet. The files
below are ordinary PyArrow-written Parquet files with the compact-Thrift
Variant annotation inserted into the outer struct's SchemaElement. This keeps
the physical pages and footer valid while covering the reader's Variant schema
validation paths.
"""
import os
import struct
import sys

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, os.path.dirname(__file__))
from tdump import R


def add_variant_annotation(data):
    footer_length = struct.unpack("<i", data[-8:-4])[0]
    footer_start = len(data) - 8 - footer_length
    nodes = next(value for _, field, kind, value in R(data, footer_start).struct()
                 if field == 2 and kind == "list")
    outer = next(node for node in nodes
                 if next((value for _, field, _, value in node if field == 4), None) == b"c")
    # Compact encoding for SchemaElement.logicalType = LogicalType.Variant.
    # Its position is immediately after the outer struct's name field.
    offset = next(start for start, field, _, _ in outer if field == 5)  # num_children
    # The original writer emits num_children directly after name; insert after it.
    insert = offset
    # Find the end of num_children's compact value (a zigzag varint).
    probe = R(data, insert)
    probe.byte()  # field header
    probe.varint()
    insert = probe.p
    out = bytearray(data[:-8])
    out[insert:insert] = b"\x5c\x0c\x20\x00\x00"
    return bytes(out) + struct.pack("<i", len(out) - footer_start) + b"PAR1"


def parquet(children, rows, annotated):
    struct_type = pa.struct(children)
    schema = pa.schema([pa.field("c", struct_type, nullable=False)])
    array = pa.array(rows, type=struct_type)
    table = pa.Table.from_arrays([array], schema=schema)
    import io
    stream = io.BytesIO()
    pq.write_table(table, stream, compression="NONE", use_dictionary=False,
                   data_page_version="2.0", write_statistics=False)
    data = stream.getvalue()
    return add_variant_annotation(data) if annotated else data


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: variant-schema-seeds.py <output-dir>")
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    binary = pa.binary()
    nested = pa.struct([pa.field("inner", binary)])
    required_nested = pa.struct([pa.field("inner", binary, nullable=False)])
    cases = [
        ("valid", [pa.field("metadata", binary, nullable=False), pa.field("value", binary)],
         [{"metadata": b"m1", "value": b"v1"}, {"metadata": b"m2", "value": None}]),
        ("invalid-metadata", [pa.field("other", binary, nullable=False), pa.field("value", binary)],
         [{"other": b"m1", "value": b"v1"}]),
        ("invalid-metadata-optional", [pa.field("metadata", binary), pa.field("value", binary)],
         [{"metadata": b"m1", "value": b"v1"}]),
        ("invalid-metadata-physical", [pa.field("metadata", pa.int32(), nullable=False), pa.field("value", binary)],
         [{"metadata": 42, "value": b"v1"}]),
        ("invalid-metadata-group", [pa.field("metadata", required_nested, nullable=False), pa.field("value", binary)],
         [{"metadata": {"inner": b"m1"}, "value": b"v1"}]),
        ("invalid-value", [pa.field("metadata", binary, nullable=False), pa.field("value", nested)],
         [{"metadata": b"m1", "value": {"inner": b"v1"}}]),
    ]
    for name, children, rows in cases:
        data = parquet(children, rows, annotated=True)
        with open(os.path.join(out, f"py-variant-{name}.bin"), "wb") as file:
            file.write(b"\x00" + data)


if __name__ == "__main__":
    main()
