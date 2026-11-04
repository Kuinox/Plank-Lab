#!/usr/bin/env python3
"""Write reader seeds that Plank's own writer cannot produce, using pyarrow.

Usage: pyarrow-seeds.py <output-dir>

Plank's writer refuses DELTA_BYTE_ARRAY on FIXED_LEN_BYTE_ARRAY although the
reader accepts it, so DecodeFixedDeltaByteArrayBatch had no seed at all. Arrow
writes decimals as FIXED_LEN_BYTE_ARRAY and can encode them that way.

Each file is written three times with a different route byte in front:
0x00 (file-schema read), 0x04 (also cross-check the two decode paths) and
0x08 (also cross-check a pruned scan); see PlankReaderFuzzTarget.cs.
"""
import decimal
import io
import os
import sys

import pyarrow as pa
import pyarrow.parquet as pq

D = decimal.Decimal
ROUTES = (0x00, 0x04, 0x08)


def decimal_values(precision):
    # Values must fit the precision with scale 6; repeat them so a page holds
    # more than one DELTA_BYTE_ARRAY block.
    small = [D("0"), D("1.234567"), D("-1.234567"), D("42.5"), D("-0.000001")]
    large = [D("1000000"), D("-999999.999999")]
    values = small + (large if precision >= 13 else [])
    quantum = D(1).scaleb(-6)
    return [v.quantize(quantum) for v in values] * 20


def main(out):
    os.makedirs(out, exist_ok=True)
    written = 0
    for precision in (28, 18, 9):
        values = decimal_values(precision)
        decimal_type = pa.decimal128(precision, 6)
        for nullable, with_nulls in ((False, False), (True, True), (True, False)):
            data = [None if with_nulls and i % 7 == 3 else v for i, v in enumerate(values)]
            table = pa.table({"c": pa.array(data, decimal_type)},
                             schema=pa.schema([pa.field("c", decimal_type, nullable=nullable)]))
            shape = "req" if not nullable else ("opt" if with_nulls else "opt-nonull")
            for page_version in ("1.0", "2.0"):
                buffer = io.BytesIO()
                pq.write_table(table, buffer, use_dictionary=False,
                               column_encoding={"c": "DELTA_BYTE_ARRAY"},
                               data_page_version=page_version, store_decimal_as_integer=False,
                               compression="none")
                for route in ROUTES:
                    name = f"py-dba-dec{precision}-{shape}-v{page_version[0]}-r{route:02x}.bin"
                    with open(os.path.join(out, name), "wb") as f:
                        f.write(bytes([route]) + buffer.getvalue())
                    written += 1
    print(f"wrote {written} seeds to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
