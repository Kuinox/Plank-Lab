#!/usr/bin/env python3
"""Generate valid integer/time logical annotations for strict projection checks."""
from pathlib import Path
import struct
import pyarrow as pa
import pyarrow.parquet as pq
from tdump import R

out = Path(__file__).with_name("nested-gap-seeds")
out.mkdir(exist_ok=True)

# selector, fields (name, Arrow type, values), requested schema slot, expected
# INT signedness transformation (None leaves non-INT annotations untouched).
cases = []
for width, arrow_type, values in (
    (8, pa.uint8(), [0, 1, 17, 64, 127]),
    (16, pa.uint16(), [0, 1, 17, 1024, 32767]),
    (32, pa.uint32(), [0, 1, 17, 1024, 2147483647]),
):
    for signed in (True, False):
        cases.append((f"int32-w{width}-{'signed' if signed else 'unsigned'}", 1,
                      [("c0", arrow_type, values)], 0, signed))
for width, arrow_type, values in (
    (64, pa.uint64(), [0, 1, 17, 1024, 9223372036854775807]),
):
    for signed in (True, False):
        cases.append((f"int64-w{width}-{'signed' if signed else 'unsigned'}", 7,
                      [("c0", arrow_type, values), ("c1", pa.float64(), [0., 1., -1., 2., 3.])], 3, signed))

# Logical annotations that are physically INT32/INT64 but are not INT. These
# should take the logical compatibility rejection path under an unannotated
# requested schema, while preserving a valid Parquet schema and page payload.
for label, selector, primary_type, values, slot in (
    ("time32-ms", 5, pa.time32("ms"), [0, 1, 1000, 12345, 86399999], 2),
    ("time64-us", 7, pa.time64("us"), [0, 1, 1000, 1234567, 86399999999], 3),
    ("timestamp-ms", 7, pa.timestamp("ms"), [0, 1, 1000, 123456789, 1700000000000], 3),
    ("timestamp-us", 7, pa.timestamp("us"), [0, 1, 1000, 123456789, 1700000000000000], 3),
):
    fields = [("c0", primary_type, values)]
    if slot == 2:
        fields.append(("c1", pa.bool_(), [True, False, True, False, True]))
    else:
        fields.append(("c1", pa.float64(), [0., 1., -1., 2., 3.]))
    cases.append((label, selector, fields, slot, None))

for label, selector, fields, schema_slot, signedness in cases:
    base = out / f"logical-compat-{label}.parquet"
    schema = pa.schema([pa.field(name, typ, nullable=False) for name, typ, _ in fields])
    table = pa.Table.from_arrays([pa.array(vals, type=typ) for _, typ, vals in fields], schema=schema)
    pq.write_table(table, base, compression="NONE", use_dictionary=False, write_statistics=False)
    data = bytearray(base.read_bytes())
    footer_len = struct.unpack("<I", data[-8:-4])[0]
    footer = len(data) - 8 - footer_len
    file_fields = R(data, footer).struct()
    nodes = next(value for _, fid, kind, value in file_fields if fid == 2 and kind == "list")
    node = next(node for node in nodes if any(fid == 4 and value == fields[0][0].encode() for _, fid, _, value in node))
    logical_field = next((value for _, fid, kind, value in node if fid == 10 and kind == "struct"), None)
    if logical_field is None:
        raise RuntimeError(f"{label}: PyArrow did not emit a logical type")
    logical_type = next((value for _, fid, kind, value in logical_field if kind == "struct"), None)
    if signedness is not None:
        int_type = next(value for _, fid, kind, value in logical_field if fid == 10 and kind == "struct")
        width = next(field[3] for field in int_type if field[1] == 1)
        signed = next(field for field in int_type if field[1] == 2)
        original = signed[3]
        if width not in (8, 16, 32, 64):
            raise RuntimeError(f"{label}: unexpected Int annotation: {int_type}")
        if original != signedness:
            data[signed[0]] = (data[signed[0]] & 0xf0) | (1 if signedness else 2)
        annotation = f"Int(bitWidth={width}, isSigned={str(signedness).lower()})"
    else:
        annotation = str(logical_type)
    seed_label = f"signed-int{width}" if label.endswith("-signed") and label.startswith("int32-w") else label
    if label == "int32-w8-signed": seed_label = "signed-int8"
    if label == "int32-w16-signed": seed_label = "signed-int16"
    if label == "int32-w32-signed": seed_label = "signed-int32"
    name = out / f"nested-gap-logical-compat-{seed_label}.input"
    name.write_bytes(bytes([selector]) + data)
    print(f"{name.name}: selector={selector}, {len(data)} bytes, {annotation}")
    base.unlink()
