# C physical-column laboratory

This workspace contains no Plank or .NET source. `candidate.c` reads the exact ordered
`int64` values, encodes each page with standard Parquet `DELTA_BINARY_PACKED`, compresses
the encoded bytes with libzstd, and writes a small `PQCOL01` bundle. The trusted gate
adds standard Parquet page headers, statistics, ColumnIndex, OffsetIndex, schema, and
footer; those wrapper bytes are not part of the research implementation.

Build and run the starter:

```sh
make
./candidate /input/values.i64le submission/candidate.column
```

Optional arguments after the output path are:

```text
block_values page_rows zstd_level windowLog hashLog chainLog searchLog minMatch targetLength strategy page_version
```

Defaults are `128 225000000 10 31 23 25 7 6 128 5 1`. `page_rows` is especially
important: every page resets delta encoding and compression, so splitting around a
large negative delta can increase the encoded size yet reduce the final compressed
size. The starter uses equal page sizes only as a starting point. You may replace its
page planner, encoder, or compressor completely, as long as the emitted payload is a
standard encoding/codec advertised by the bundle header.

The bundle ABI is documented in `research/COLUMN_FORMAT.md`.
