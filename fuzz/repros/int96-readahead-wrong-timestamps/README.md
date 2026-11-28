# Row reader read-ahead returns wrong timestamps for INT96 columns (silent data corruption)

Found by `Plank.Fuzzing.Scale` (`run evolve 6 0`: "Timestamp value 1991441589148299689 is outside the range representable by a
date and time" on the second row group, only with `WorkerCount = 8, MaxReadAheadRowGroups = 1`), 2026-11-28, Plank `3a6a28a`.

A file with an INT96 timestamp column, read by the generated row reader into a `DateTime` property declared as
TIMESTAMP(MICROS) with `ParquetSchemaEvolutionOptions.PhysicalTypes = AllowCompatible` (the documented INT96 → timestamp
materialization, #275). The first row group is right. When the reader has workers (`Execution.WorkerCount > 1`) and read-ahead
(`MaxReadAheadRowGroups = 1`, the default), the **prefetched row group is decoded without the INT96 conversion**: its 12-byte INT96
values are read as 8-byte INT64 TIMESTAMP(MICROS) values. Depending on the bytes this either throws
`CorruptParquetException: Timestamp value … is outside the range` (most real data) or — when every 8-byte window happens to be in
range — **returns wrong timestamps without any error**. One worker, or `MaxReadAheadRowGroups = 0`, is exact.

`int96-two-row-groups.parquet` (in this directory): columns `Id` INT64 and `Stamp` INT96, two row groups of 4 rows, every
timestamp 1970-01-01T00:00:00Z (INT96 nanoseconds 0, Julian day 2440588).

```
Plank.Fuzzing.Scale/bin/Release/net10.0/Plank.Fuzzing.Scale repro int96-readahead /tmp/x
WorkerCount=1 MaxReadAheadRowGroups=0: 8 rows, 0 wrong
WorkerCount=1 MaxReadAheadRowGroups=1: 8 rows, 0 wrong
WorkerCount=2 MaxReadAheadRowGroups=0: 8 rows, 0 wrong
WorkerCount=2 MaxReadAheadRowGroups=1: row 5 Stamp 1970-01-01T00:00:02.4405880Z (expected 1970-01-01T00:00:00.0000000Z); row 6 Stamp 2302-03-04T06:54:03.0100480Z (expected 1970-01-01T00:00:00.0000000Z); 8 rows, 2 wrong
WorkerCount=8 MaxReadAheadRowGroups=1: (same)
```

(Row 4 is "right" by accident: its first 8 bytes are nanoseconds 0, i.e. 0 µs. Row 5's 2.4405880 s is the Julian day 2440588
read as microseconds.) `ParquetSchemaEvolutionOptions` is only needed to allow the INT96 binding; the logical reader's
`Column<DateTime>` on the same column is right. Default `RowReaderOptions` are `WorkerCount = Environment.ProcessorCount`,
`MaxReadAheadRowGroups = 1`, so any multi-core machine reading a multi-row-group INT96 file this way is affected.

Cause (read after the fuzz finding): `RowReaderCore.StartReadAhead` creates the read-ahead states with
`state.Descriptor.CreateState()` and copies `Projected`, `Materialized` and `Ordinal` from the current states, but not
`ReadDefinition`, which binding (`RowReaderCore.cs:502`) sets only for the INT96 → timestamp conversion. The prefetched row
group is therefore decoded with the property's own INT64 TIMESTAMP definition.
