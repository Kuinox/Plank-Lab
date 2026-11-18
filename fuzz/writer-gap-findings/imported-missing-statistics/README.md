# Imported Parquet column chunk without statistics

`fuzz/writer-gap-seeds/imported-missing-statistics-ims1.bin` is a valid external
Parquet file preceded by the exact `0xE6` + `IMS1` writer-route marker. PyArrow
26.0.0 created its single required INT32 column with statistics disabled; it has
one row group and five values: `17, -3, 0, 2147483647, -2147483648`.

The route calls the public `ParquetSchema.CreateMerger` API. It verifies that
the source has no min, max, null-count, or distinct-count statistics, then
checks merger counters, strict Plank readback, and that the merged footer still
has no statistics. ParquetSharp independently checks the merged footer and all
values. A private PyArrow check also confirmed the merged file has no column
statistics and reads the same five values.

Private actual-route Coverlet hit
`ParquetMetadataThriftWriter.WriteImportedStatistics` at `(line 904, offset 6,
Path 0, ordinal 0)` once. The tuple has zero hits in each raw writer `ae`
scalar/SSE/AVX2/AVX512 report. This focused valid-source coverage result is
pending the next full writer snapshot.
