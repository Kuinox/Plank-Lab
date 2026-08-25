#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


def build_reference(source: Path, raw_output: Path, column_name: str) -> dict:
    parquet = pq.ParquetFile(source)
    schema = parquet.schema_arrow
    if len(schema) != 1:
        raise ValueError(f"expected one column, found {len(schema)}")
    field = schema.field(0)
    if field.name != column_name or str(field.type) != "timestamp[us, tz=UTC]":
        raise ValueError(f"unexpected input schema: {schema}")

    raw_output.parent.mkdir(parents=True, exist_ok=True)
    temporary = raw_output.with_suffix(raw_output.suffix + ".tmp")
    digest = hashlib.sha256()
    rows = nulls = 0
    first = last = minimum = maximum = None
    with temporary.open("wb") as out:
        for batch in parquet.iter_batches(batch_size=2_000_000, columns=[column_name]):
            values = batch.column(0).cast(pa.int64())
            nulls += values.null_count
            array = values.to_numpy(zero_copy_only=False).astype("<i8", copy=False)
            payload = array.tobytes()
            out.write(payload)
            digest.update(payload)
            if array.size:
                local_min = int(array.min())
                local_max = int(array.max())
                first = int(array[0]) if first is None else first
                last = int(array[-1])
                minimum = local_min if minimum is None else min(minimum, local_min)
                maximum = local_max if maximum is None else max(maximum, local_max)
            rows += len(array)
        out.flush()
        os.fsync(out.fileno())
    temporary.replace(raw_output)
    return {
        "source": str(source.resolve()),
        "column": column_name,
        "logical_type": "timestamp[us, tz=UTC]",
        "nullable": False,
        "rows": rows,
        "nulls": nulls,
        "first": first,
        "last": last,
        "min": minimum,
        "max": maximum,
        "sha256_i64_le": digest.hexdigest(),
        "raw_values": str(raw_output),
        "raw_bytes": raw_output.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("raw_output", type=Path)
    parser.add_argument("reference", type=Path)
    parser.add_argument("--column", default="TradeTimestamp")
    args = parser.parse_args()
    reference = build_reference(args.source, args.raw_output, args.column)
    if reference["rows"] != 225_000_000 or reference["nulls"] != 0:
        raise ValueError(f"unexpected input cardinality/nulls: {reference}")
    args.reference.write_text(json.dumps(reference, indent=2, sort_keys=True) + "\n")
    print(json.dumps(reference, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
