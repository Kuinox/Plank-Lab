# Plank writes `distinct_count = 0` for columns without a defined sort order

Found 2026-11-27 by the full-value oracle (`Plank.Fuzzing/FullValueOracle.cs`, check
"written: statistics distinct_count differs from the values"), against Plank master 3a6a28a.

For a column chunk whose type has no type-defined sort order — INT96, FIXED_LEN_BYTE_ARRAY
INTERVAL, BYTE_ARRAY GEOMETRY/GEOGRAPHY — Plank writes no min/max (correct) but writes
`Statistics.distinct_count = 0` even though the chunk holds several distinct non-null values.
The specification defines `distinct_count` as the count of distinct values occurring; 0 is
false for any chunk with a non-null value (it should be the real count, or absent).
A query engine trusting it (cardinality estimates, "no distinct values ⇒ all null") is misled.
Plank's reader and Arrow both read back the 0, so no round trip sees it.

Files (bare Parquet, written by Plank):

- `int96-plain.parquet`: one required INT96 column, 3 distinct values (`EncodingCoverageWriterCases.WriteInt96PlainPayloads`).
  Footer: `ColumnMetaData.statistics = { null_count: 0, distinct_count: 0 }`.
- `interval.parquet`: one required FLBA(12) INTERVAL column, 3 distinct values. Same statistics.

Dump the statistics with `python3 fuzz/tdump.py <file>` (field 12 of ColumnMetaData, field 4 = distinct_count).

Writer seeds that reproduce it through the replay driver (`MISMATCH` lines):

```
Plank.Fuzzing.Replay writer fuzz/corpus/encoding-plain-int96.bin fuzz/corpus/logical-metadata-interval.bin \
  fuzz/corpus/logical-metadata-geometry.bin fuzz/corpus/logical-metadata-geography.bin \
  fuzz/writer-gap-seeds/append-compare-int96.bin fuzz/writer-gap-seeds/append-interval-unknown-order.bin
```

Columns with a defined order get a correct distinct count (e.g. BYTE_ARRAY DELTA seeds write 1 for one distinct value).
