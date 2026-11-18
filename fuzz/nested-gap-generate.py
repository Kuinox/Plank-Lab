#!/usr/bin/env python3
"""Generate small valid nested Parquet inputs for cold reader decoder paths."""
from pathlib import Path
from decimal import Decimal
import io
import struct
import pyarrow as pa
import pyarrow.parquet as pq
from tdump import R

OUT = Path(__file__).with_name("nested-gap-seeds")
OUT.mkdir(exist_ok=True)

# Arrow list columns produce a standard three-level LIST schema; selector zero
# tells the reader target to bind and drain the complete file schema.
values = [[bytes((i, i + 1, i + 2, i + 3)) for i in range(4)], [],
          [bytes((10 + i, 20 + i, 30 + i, 40 + i)) for i in range(7)]]
fixed = pa.list_(pa.binary(4))
table = pa.Table.from_arrays([pa.array(values, type=fixed)], names=["c"])
p = OUT / "nested-list-flba-bss"
pq.write_table(table, p, compression="NONE", use_dictionary=False,
               column_encoding={"c.list.element": "BYTE_STREAM_SPLIT"},
               data_page_version="2.0", write_statistics=False)
(OUT / "nested-list-flba-bss.input").write_bytes(b"\x00" + p.read_bytes())
p.unlink()

values = [[b"prefix-a", b"prefix-ab", b"prefix-abc", b"prefix-abd"],
          [], [b"prefix-z", b"prefix-za", b"prefix-zab", b"prefix-zac", b"prefix-zad"]]
table = pa.Table.from_arrays([pa.array(values, type=pa.list_(pa.binary()))], names=["c"])
p = OUT / "nested-list-binary-delta-byte-array"
pq.write_table(table, p, compression="NONE", use_dictionary=False,
               column_encoding={"c.list.element": "DELTA_BYTE_ARRAY"},
               data_page_version="2.0", write_statistics=False)
(OUT / "nested-list-binary-delta-byte-array.input").write_bytes(b"\x00" + p.read_bytes())
p.unlink()

# Print the actual leaf encodings so unsupported writer fallbacks are visible.
for name in ("nested-list-flba-bss", "nested-list-binary-delta-byte-array"):
    data = (OUT / f"{name}.input").read_bytes()[1:]
    metadata = pq.ParquetFile(io.BytesIO(data)).metadata
    encodings = metadata.row_group(0).column(0).encodings
    print(f"{name}: {encodings}, {len(data)} bytes")

# Signed delta values whose zigzag representation needs the selected bit width
# drive the fixed-width mini-block kernels. Alternating 0 and the positive
# endpoint keeps every Int32 value in range, even at width 32; the delta from
# the endpoint back to zero is also valid and sets the block's minimum delta.
# Width 25 was produced in the previous iteration; regenerate it with its
# original endpoint so this helper remains sufficient to recreate every seed.
for width in range(17, 33):
    delta = (1 << 24) - 1 if width == 25 else 1 << (width - 2)
    values = [delta if i & 1 else 0 for i in range(1024)]
    table = pa.table({"c": pa.array(values, type=pa.int32())})
    p = OUT / f"delta-i32-w{width}.parquet"
    pq.write_table(table, p, compression="NONE", use_dictionary=False,
                   column_encoding={"c": "DELTA_BINARY_PACKED"},
                   data_page_version="2.0", write_statistics=False)
    output = OUT / f"nested-gap-delta-i32-w{width}.input"
    output.write_bytes(b"\x00" + p.read_bytes())
    import io
    metadata = pq.ParquetFile(io.BytesIO(p.read_bytes())).metadata
    encodings = metadata.row_group(0).column(0).encodings
    print(f"delta-i32-w{width}: {encodings}, {p.stat().st_size} bytes")
    p.unlink()

# Fixed-length DECIMAL DELTA_BYTE_ARRAY is decoded through the CLR logical
# converter, so use an annotated Arrow field rather than unannotated
# fixed_size_binary. The null-bearing optional case covers the nullable batch
# route; V1 and V2 cover both level layouts. PyArrow can emit UUID metadata too,
# but the current Plank reader rejects Guid projections as variable-length
# bytes before decoding, so those files do not reach the decoder under test.
value_type = pa.decimal128(28, 6)
present_values = [
    Decimal("0.000001"), Decimal("1.234567"), Decimal("1.234568"),
    Decimal("-99.123456"), Decimal("9999999999999999999999.999999"),
    Decimal("-9999999999999999999999.999999"), Decimal("1000000.000001"),
]
for nullable in (False, True):
    values = present_values + present_values[:2] + present_values[2:4]
    if nullable:
        values = [None if i % 5 == 2 else value for i, value in enumerate(values)]
    array = pa.array(values, type=value_type)
    schema = pa.schema([pa.field("c", value_type, nullable=nullable)])
    table = pa.Table.from_arrays([array], schema=schema)
    for page_version in ("1.0", "2.0"):
        suffix = "opt" if nullable else "req"
        version = "v1" if page_version == "1.0" else "v2"
        name = f"fixed-decimal-deltabyte-{suffix}-{version}"
        p = OUT / f"{name}.parquet"
        pq.write_table(table, p, compression="NONE", use_dictionary=False,
                       column_encoding={"c": "DELTA_BYTE_ARRAY"},
                       data_page_version=page_version, write_statistics=False)
        metadata = pq.ParquetFile(io.BytesIO(p.read_bytes())).metadata
        column = metadata.schema.column(0)
        encodings = metadata.row_group(0).column(0).encodings
        if column.physical_type != "FIXED_LEN_BYTE_ARRAY" or "DELTA_BYTE_ARRAY" not in encodings:
            raise RuntimeError(f"{name}: expected FIXED_LEN_BYTE_ARRAY DELTA_BYTE_ARRAY, got "
                               f"{column.physical_type} {encodings}")
        (OUT / f"nested-gap-{name}.input").write_bytes(b"\x00" + p.read_bytes())
        print(f"{name}: {column.physical_type} {column.logical_type}, {encodings}, {p.stat().st_size} bytes")
        p.unlink()

# Standard MAP annotations reconstruct a key_value repeated group, with a
# required key and optional value. Empty and multi-entry rows exercise the
# repeated/definition-level transitions. Emit both string and raw-binary keys,
# both page versions, and the file-schema and row-API reader selectors.
for key_name, key_type, key_rows in (
    ("string", pa.string(), ["a", "b", "empty-neighbor", "x", "y", "z", "tail"]),
    ("binary", pa.binary(), [b"\x00", b"\xff", b"empty-neighbor", b"a\x00", b"b\xff", b"c", b"tail"]),
):
    for value_nullable in (True, False):
        map_type = pa.map_(key_type, pa.field("value", pa.int32(), nullable=value_nullable))
        rows = [
            [(key_rows[0], 1), (key_rows[1], None if value_nullable else 2)],
            [],
            [(key_rows[2], -1), (key_rows[3], 123), (key_rows[4], None if value_nullable else 5)],
            [(key_rows[5], 0), (key_rows[6], 42)],
        ]
        array = pa.array(rows, type=map_type)
        table = pa.Table.from_arrays([array], names=["c"])
        value_name = "optional" if value_nullable else "required"
        for page_version in ("1.0", "2.0"):
            version = "v1" if page_version == "1.0" else "v2"
            p = OUT / f"map-{key_name}-{value_name}-{version}.parquet"
            pq.write_table(table, p, compression="NONE", use_dictionary=False,
                           data_page_version=page_version, write_statistics=False)
            metadata = pq.ParquetFile(io.BytesIO(p.read_bytes())).metadata
            schema_text = str(metadata.schema)
            if "(map)" not in schema_text.lower() or "key_value" not in schema_text:
                raise RuntimeError(f"map-{key_name}-{version}: expected standard MAP schema, got {schema_text}")
            leaves = [metadata.schema.column(i) for i in range(metadata.num_columns)]
            if len(leaves) != 2 or leaves[0].physical_type != "BYTE_ARRAY" or leaves[1].physical_type != "INT32":
                raise RuntimeError(f"map-{key_name}-{version}: unexpected key/value leaves: {leaves}")
            if ("required int32" in schema_text) != (not value_nullable):
                raise RuntimeError(f"map-{key_name}-{version}: value nullability mismatch: {schema_text}")
            encodings = [metadata.row_group(0).column(i).encodings for i in range(metadata.num_columns)]
            for selector_name, selector in (("file", 0), ("rowapi", 2)):
                # Preserve the original optional-value seed names for corpus stability.
                suffix = "" if value_nullable else "-required"
                name = f"map-{key_name}-{version}{suffix}-{selector_name}"
                (OUT / f"nested-gap-{name}.input").write_bytes(bytes([selector]) + p.read_bytes())
                print(f"{name}: {schema_text.replace(chr(10), '; ')}, {encodings}")
            p.unlink()

# Bounded malformed footer variants start from a valid MAP file and alter only
# one schema element field. They reach the reader's explicit MAP schema guards
# while retaining a valid footer/container and unchanged page bytes.
base_map = bytearray((OUT / "nested-gap-map-string-v1-file.input").read_bytes()[1:])
footer_length = struct.unpack("<I", base_map[-8:-4])[0]
footer_start = len(base_map) - 8 - footer_length
file_fields = R(base_map, footer_start).struct()
schema_list = next(value for _, field_id, kind, value in file_fields
                   if field_id == 2 and kind == "list")
schema_names = [next((value for _, field_id, _, value in node if field_id == 4), None)
                for node in schema_list]
key_value_index = schema_names.index(b"key_value")
key_value = schema_list[key_value_index]
value_node = schema_list[schema_names.index(b"value")]

def field_for(node, field_id):
    return next(item for item in node if item[1] == field_id)

def set_compact_i32(blob, field, value):
    start = field[0]
    if blob[start] >> 4 == 0:
        raise RuntimeError("MAP mutation expects a compact field-id delta")
    encoded = (value << 1) ^ (value >> 31)
    if encoded >= 0x80:
        raise RuntimeError("MAP mutation value unexpectedly needs a multi-byte varint")
    blob[start + 1] = encoded

def write_invalid_map(name, mutate):
    data = bytearray(base_map)
    old_length = struct.unpack("<I", data[-8:-4])[0]
    delta = mutate(data)
    struct.pack_into("<I", data, len(data) - 8, old_length + delta)
    (OUT / f"nested-gap-{name}.input").write_bytes(b"\x00" + data)

for child_count, suffix in ((0, "zero"), (3, "three")):
    field = field_for(key_value, 5)
    write_invalid_map(
        f"map-invalid-keyvalue-childcount-{suffix}",
        lambda data, f=field, count=child_count: (set_compact_i32(data, f, count) or 0))

write_invalid_map(
    "map-invalid-repeated-value",
    lambda data: (set_compact_i32(data, field_for(value_node, 3), 2) or 0))

# Omit all physical schema nodes below the MAP field but retain its declared
# single child, so binding reaches the missing-key_value index check.
def omit_map_children(data):
    nodes = R(data, footer_start).struct()
    schema_field = next(item for item in nodes if item[1] == 2)
    schema_nodes = schema_field[3]
    names = [next((value for _, field_id, _, value in node if field_id == 4), None)
             for node in schema_nodes]
    start = schema_nodes[names.index(b"key_value")][0][0]
    next_field = next(item[0] for item in nodes if item[1] == 3)
    header_offset = schema_field[0] + 1
    header = data[footer_start + header_offset]
    if header >> 4 == 15 or (header & 15) != 6:
        raise RuntimeError("MAP mutation expected a compact list of structs")
    data[footer_start + header_offset] = (2 << 4) | (header & 15)
    absolute_start = footer_start + start
    absolute_end = footer_start + next_field
    removed = absolute_end - absolute_start
    del data[absolute_start:absolute_end]
    return -removed

write_invalid_map("map-invalid-missing-keyvalue", omit_map_children)

# Inject an illegal physical type into the key_value group SchemaElement. The
# new first field is compact i32 field 1; field 3's delta is adjusted from 3 to 2.
def type_keyvalue_as_leaf(data):
    nodes = R(data, footer_start).struct()
    schema_nodes = next(item[3] for item in nodes if item[1] == 2)
    node = next(node for node in schema_nodes
                if next((value for _, field_id, _, value in node if field_id == 4), None) == b"key_value")
    start = node[0][0] + footer_start
    if data[start] != 0x65:
        raise RuntimeError("MAP mutation expected repetition_type as first key_value field")
    data[start:start] = b"\x15\x02"
    data[start + 2] = 0x25
    return 2

write_invalid_map("map-invalid-keyvalue-physical-type", type_keyvalue_as_leaf)


# A single marker bit selects a bounded two-worker row-reader pass when the
# replay process explicitly opts in with PLANK_FUZZ_ENABLE_ROW_WORKERS=1. AFL
# runs leave that variable unset, preserving single-thread instrumentation
# stability. Four small row groups are enough to enqueue and consume read-ahead.
table = pa.table({
    "id": pa.array([0, 1, -1, 42, 123, -456, 7, 8], type=pa.int32()),
    "label": pa.array(["a", None, "longer", "", "x", "y", None, "tail"]),
    "flag": pa.array([True, False, True, None, False, True, False, True]),
})
p = OUT / "rowreader-workers-multigroup.parquet"
pq.write_table(table, p, compression="NONE", use_dictionary=False,
               data_page_version="2.0", write_statistics=False, row_group_size=2)
metadata = pq.ParquetFile(io.BytesIO(p.read_bytes())).metadata
if metadata.num_row_groups != 4 or metadata.num_columns != 3:
    raise RuntimeError("rowreader worker seed must contain 4 row groups and 3 columns")
(OUT / "nested-gap-rowreader-workers-multigroup.input").write_bytes(b"\x22" + p.read_bytes())
print(f"rowreader-workers-multigroup: {metadata.num_row_groups} groups, "
      f"{metadata.num_columns} columns, selector 0x22, {p.stat().st_size} bytes")
p.unlink()
