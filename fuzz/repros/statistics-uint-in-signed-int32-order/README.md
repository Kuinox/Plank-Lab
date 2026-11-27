# `uint` values written to a plain INT32 column get statistics in unsigned order

Found 2026-11-27 by the full-value oracle (`Plank.Fuzzing/FullValueOracle.cs`, check
"written: chunk statistics min differs from the values"), against Plank master 3a6a28a.

`EncodingCoverageWriterCases.WriteDeltaInt32GenericDispatchInputs` declares
`ColumnDefinition.Leaf("delta-int32-uint", ParquetPhysicalType.Int32, ...)` — INT32 with **no**
logical type, i.e. signed — and writes it from `uint[] { 0, 1, 65536, 1_000_000, uint.MaxValue }`
through `CreateSerializedColumn<uint>`. Plank accepts that, stores the bit patterns
`0, 1, 65536, 1000000, -1`, and writes

```
min_value = 00000000 (0)      max_value = FFFFFFFF (-1)      is_min/max_value_exact = true
```

That is the unsigned order of the CLR type. The column's order (signed INT32) gives min = -1 and
max = 1000000: the written statistics have min > max, and a reader pruning `col < 0` with them
skips a chunk that contains -1. Plank's reader and Arrow read the same bytes back, so a round trip
cannot see it; the oracle recomputes min/max from Arrow-decoded values with the column's order.

Either the statistics must follow the column's declared order, or `CreateSerializedColumn<uint>`
must require an unsigned INT(32) annotation (the source generator presumably adds one; the runtime
schema API does not require it). The same probably applies to `ulong` on an unannotated INT64
(not yet confirmed by a seed).

File: `delta-int32-generic-dispatch.parquet` (column 3). Replay:

```
Plank.Fuzzing.Replay writer fuzz/writer-gap-seeds/delta-binary-packed-int32/public-generic-dispatch.bin
```
