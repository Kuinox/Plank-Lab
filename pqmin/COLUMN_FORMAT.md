# PQCOL01 physical-column bundle

Workers write this little-endian bundle from C. It contains only standard encoded and compressed
page payloads. The gate turns it into the scored Parquet file and supplies all non-research wrapper
metadata.

## File header

| Bytes | Type | Meaning |
|---:|---|---|
| 8 | byte[8] | `PQCOL01\0` |
| 4 | uint32 | format version, currently `1` |
| 4 | uint32 | Parquet Encoding enum: `0` PLAIN, `5` DELTA_BINARY_PACKED, `9` BYTE_STREAM_SPLIT |
| 4 | uint32 | Parquet CompressionCodec enum (`0` uncompressed, `1` snappy, `2` gzip, `4` brotli, `5` lz4, `6` zstd, `7` lz4_raw) |
| 4 | uint32 | data page version, `1` or `2` |
| 4 | uint32 | page count |
| 8 | uint64 | total row count |

## Repeated page record

| Bytes | Type | Meaning |
|---:|---|---|
| 8 | uint64 | rows in this page |
| 8 | int64 | exact page minimum |
| 8 | int64 | exact page maximum |
| 8 | uint64 | byte length after value encoding, before compression |
| 8 | uint64 | compressed payload byte length |
| variable | byte[] | compressed standard Parquet value-encoding payload |

Pages cover the input in order and their row counts must sum to the header count. The required flat
column has no repetition or definition-level bytes. For V1, the payload is the codec-compressed value
encoding. For V2, it is likewise the compressed data section and the wrapper declares zero-byte
level sections. Each page is an independent encoding and compression stream, so arbitrary reset
points—including data-dependent boundaries around disruptive deltas—are allowed.

The gate verifies the advertised sizes structurally, writes exact page statistics into both page
headers and ColumnIndex, writes OffsetIndex locations, and then validates every decoded value through
unchanged PyArrow and DuckDB. Incorrect statistics or payloads cannot be promoted.
