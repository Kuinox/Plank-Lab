# A writer keeps every SerializedColumn it ever created (per-row-group columns grow memory without bound)

Found by `Plank.Fuzzing.Scale` (`run append 10095 0` peaked at 7.8 GB for 2,047 rows: 1,000 row groups × 6 columns, columns
created per row group, `InitialPageCapacity = 4096`), 2026-11-28, Plank `3a6a28a`.

`ParquetWriter.CreateSerializedColumn<T>` (which `RowGroupWriter.CreateSerializedColumn<T>` forwards to) appends the new
column to the writer's `_serializedColumns` list (`Writing/ParquetWriter.cs:183`), and nothing removes it after the row group
is written. Creating the column from each `RowGroupWriter` — the API `RowGroupWriter` offers — therefore keeps every column of
every past row group, with its page list (`InitialPageCapacity` entries) and state, until the writer is disposed: memory grows
linearly with row groups × columns. About 2.2 KB per column per row group with the default `InitialPageCapacity = 4`, ~1.25 MB
with `InitialPageCapacity = 4096`. Creating the column once (writer level) and reusing it stays flat. No data is affected.

Repro (prints live managed memory after a full GC, writer still open; exits 1 when the per-row-group variant grows):

```
Plank.Fuzzing.Scale/bin/Release/net10.0/Plank.Fuzzing.Scale repro serialized-column-per-row-group-retained /tmp/rp
shared column: after 10 row groups, live managed memory 91 KB
shared column: after 2000 row groups, live managed memory 100 KB
per-row-group column: after 10 row groups, live managed memory 124 KB
per-row-group column: after 500 row groups, live managed memory 1204 KB
per-row-group column: after 1000 row groups, live managed memory 2309 KB
per-row-group column: after 2000 row groups, live managed memory 4517 KB
```

The scale driver only draws per-row-group columns when groups × columns × InitialPageCapacity stays affordable.
