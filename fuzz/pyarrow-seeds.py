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
import struct
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


class _Compact:
    """Just enough of the Thrift compact protocol to walk a Parquet footer."""

    def __init__(self, data, pos):
        self.d, self.p = data, pos

    def byte(self):
        self.p += 1
        return self.d[self.p - 1]

    def varint(self):
        result = shift = 0
        while True:
            b = self.byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return result

    def zigzag(self):
        v = self.varint()
        return (v >> 1) ^ -(v & 1)

    def skip(self, t, in_list=False):
        if t in (1, 2):
            # A struct field carries its bool in the type nibble; a list element
            # takes a byte of its own.
            if in_list:
                self.p += 1
            return
        if t == 3:
            self.p += 1
        elif t in (4, 5, 6):
            self.varint()
        elif t == 7:
            self.p += 8
        elif t == 8:
            length = self.varint()   # not `self.p += self.varint()`: that reads p first
            self.p += length
        elif t in (9, 10):
            h = self.byte()
            n = h >> 4 if h >> 4 != 15 else self.varint()
            for _ in range(n):
                self.skip(h & 15, in_list=True)
        elif t == 12:
            self.struct(lambda f, ft: self.skip(ft))
        else:
            raise ValueError(t)

    def struct(self, on_field):
        last = 0
        while True:
            h = self.byte()
            if h == 0:
                return self.p - 1
            delta, t = h >> 4, h & 15
            last = last + delta if delta else self.zigzag()
            on_field(last, t)


def column_metadata_stops(data):
    """Footer offsets of each ColumnMetaData's stop byte."""
    footer_length = struct.unpack("<i", data[-8:-4])[0]
    r = _Compact(data, len(data) - 8 - footer_length)
    stops = []

    def list_of_structs(t, on_field):
        h = r.byte()
        n = h >> 4 if h >> 4 != 15 else r.varint()
        for _ in range(n):
            r.struct(on_field)

    def column_chunk(f, t):
        if f == 3 and t == 12:
            stops.append(r.struct(lambda f2, t2: r.skip(t2)))
        else:
            r.skip(t)

    def row_group(f, t):
        if f == 1 and t == 9:
            list_of_structs(t, column_chunk)
        else:
            r.skip(t)

    def file_metadata(f, t):
        if f == 4 and t == 9:
            list_of_structs(t, row_group)
        else:
            r.skip(t)

    r.struct(file_metadata)
    return len(data) - 8 - footer_length, stops


def insert_into_column_metadata(data, field_bytes):
    """Insert a field before every ColumnMetaData stop byte and fix the footer length."""
    footer_start, stops = column_metadata_stops(data)
    out = bytearray(data[:-8])
    for stop in reversed(stops):
        out[stop:stop] = field_bytes
    footer_length = len(out) - footer_start
    return bytes(out) + struct.pack("<i", footer_length) + b"PAR1"


def geospatial_statistics(xmin, xmax, ymin, ymax, geometry_types):
    """ColumnMetaData field 17: GeospatialStatistics { 1: BoundingBox bbox, 2: list<i32> geospatial_types }."""
    def dbl(v):
        return bytes([0x17]) + struct.pack("<d", v)          # delta 1, double
    bbox = dbl(xmin) + dbl(xmax) + dbl(ymin) + dbl(ymax) + b"\x00"
    def varint(v):
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            out.append(b | (0x80 if v else 0))
            if not v:
                return bytes(out)
    types = bytes([0x19, (len(geometry_types) << 4) | 5]) + b"".join(
        varint((t << 1) ^ (t >> 31)) for t in geometry_types)   # delta 1, list<i32> of zigzag varints
    return bytes([0x0C, 0x22]) + b"\x1c" + bbox + types + b"\x00"   # field 17 (long form), struct


def geospatial_seeds(out, routes):
    written = 0
    wkb = [struct.pack("<BIdd", 1, 1, x, y) for x, y in ((1, 2), (3, 4), (-5, 6.5), (0, 0))]
    for nullable in (False, True):
        values = [None if nullable and i == 2 else v for i, v in enumerate(wkb)]
        table = pa.table({"g": pa.array(values, pa.binary())},
                         schema=pa.schema([pa.field("g", pa.binary(), nullable=nullable)]))
        buffer = io.BytesIO()
        pq.write_table(table, buffer, compression="none")
        for name, stats in (("point", geospatial_statistics(-5, 3, 0, 6.5, [1])),
                            ("mixed", geospatial_statistics(-180, 180, -90, 90, [1, 2, 3, 1001])),
                            ("empty-types", geospatial_statistics(0, 0, 0, 0, []))):
            data = insert_into_column_metadata(buffer.getvalue(), stats)
            for route in routes:
                path = os.path.join(out, f"py-geo-{name}-{'opt' if nullable else 'req'}-r{route:02x}.bin")
                with open(path, "wb") as f:
                    f.write(bytes([route]) + data)
                written += 1
    return written


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
    # Geospatial statistics live in ColumnMetaData field 17; Arrow only writes
    # them for GEOMETRY columns, which this pyarrow cannot produce from Python,
    # so they are inserted into the footer of an ordinary binary column.
    written += geospatial_seeds(out, ROUTES)
    print(f"wrote {written} seeds to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
