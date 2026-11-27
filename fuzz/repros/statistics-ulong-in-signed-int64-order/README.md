# `ulong` values written to a plain (signed) INT64 column get statistics in unsigned order

Found 2026-11-27 by `WriterStatisticsOracle` after it was changed to take the sort order from the COLUMN
(physical type + logical type) instead of from the CLR type. Sibling of
[`../statistics-uint-in-signed-int32-order/`](../statistics-uint-in-signed-int32-order/) (same defect, 64-bit).

Route `WTM1` (`0xC8`, `WriterTypeMatrixCases.Unsigned`), required column, `CreateSerializedColumn<ulong>` on
`ColumnDefinition.Leaf("u", ParquetPhysicalType.Int64, ...)` with **no** logical type (so signed).
Values are ulongs that include numbers above `long.MaxValue` (stored as negative bit patterns).

Observed (all four encodings: PLAIN_DICTIONARY, RLE_DICTIONARY, DELTA_BINARY_PACKED, BYTE_STREAM_SPLIT),
e.g. `wtm1-ulong-in-signed-int64-plain-dictionary.bin`:

    chunk min = 2612606290749247232 (positive), expected min = -5 (signed order of the stored values)

The written min/max follow the CLR type's unsigned order: min > max in the column's signed order, so a reader
pruning `col < 0` skips a chunk that contains negative values. Reading the values back is correct.
The optional (`ulong?`) form and the 32-bit `uint` form through this route did not reproduce; the 32-bit
one is the oracle agent's finding (generic dispatch route).

Replay: `Plank.Fuzzing.Replay writer fuzz/repros/statistics-ulong-in-signed-int64-order/` ->
`FAULT ... int 64 annotatedUnsigned=False clr=unsigned ... statistics: chunk min ... vs expected -5`.
