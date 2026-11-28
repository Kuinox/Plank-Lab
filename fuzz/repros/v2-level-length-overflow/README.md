# v2 page header level byte lengths overflow `int` → `OverflowException` instead of `CorruptParquetException`

Found 2026-11-28 by `StructuredPageMutator` (`count-overflow`, arithmetic-overflow boundary values) from the
generated corpus seed `gen-gap-dec64-rledictionary-opt-x.bin` (and three other seeds), Plank master 3a6a28a.

A DataPageV2 header with `repetition_levels_byte_length = 2147483647` (plus any definition length) makes the page
cursor compute `checked((int)(RepetitionLevelsByteLength + DefinitionLevelsByteLength))`; the two `uint` fields sum
past `int.MaxValue` and the checked cast throws `OverflowException` before the "DataPageV2 level bytes exceed the page
payload" check can report the corruption. Same in the fixed-width batch start (`TryStartFixedWidthPageBatches`).
Checked arithmetic, so no memory-safety impact; the defect is that malformed input escapes as a non-`CorruptParquetException`
(callers catching `CorruptParquetException` for bad files crash instead).

```
Plank.Fuzzing.Replay reader fuzz/repros/v2-level-length-overflow/reader-input.bin
# FAULT ... System.OverflowException  Arithmetic operation resulted in an overflow.
```
`mutant.parquet` is the bare file (row group 0, column 0, page 0: v2 repetition byte length 0 -> 2147483647).
