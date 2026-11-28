# Size and parallelism thresholds in Plank (scale agent, 2026-11-28)

Plank master `3a6a28a`. This lists every count/length threshold in `library/Plank/Plank` where the code changes
behaviour (a different path, a growth step, a limit), and whether a fuzz route crosses it. AFL routes are capped hard:
`PlankRowApiFuzzTarget.MaxRows = 48`, `PlankDatasetFuzzTarget.MaxRows = 64`, `PlankCrossWriterFuzzTarget.MaxRowsPerGroup = 40`,
`PlankMergerFuzzTarget.MaxRowsPerFile = 32`, and AFL inputs are a few KB, so pages, chunks and files stay tiny. Everything that
only switches on at thousands of rows, MB-sized pages or GB-sized offsets was unreached until the `Plank.Fuzzing.Scale` driver
(this note's companion, see the end).

"AFL" = any existing AFL route reaches it. "Scale" = the scale driver's drawn shapes cross it (mode/tier in brackets).

## Writer: encoding

| Threshold | Where | Effect | AFL | Scale |
|---|---|---|---|---|
| `DictionaryDropCheckPeriodRows = 2048` | `Writing/Encoding/Encoding.cs:16` | the dictionary builders ask `ShouldDropDictionary` every 2048 present values (and at the end) | end-of-chunk check only (≤ 48 rows) | yes: row counts 2047/2048/2049, 4097, 20k..6M (columnar/row t0–t2) |
| `DefaultStrategy.ShouldDropDictionary`: no decision before `max(16384, total/8)` rows; drop when unique ≥ 98 % seen, or projected unique ≥ 75 % and unique ≥ 85 % | `Writing/PageStrategy/DefaultStrategy.cs:27-45` | mid-chunk fallback from dictionary to the data encoding (`pages.Clear(); return false` and re-encode) | only the final check, on tiny chunks | yes: high-cardinality / low-card-prefix-then-high-card (pattern 10) / segmented patterns over ≥ 16384 rows |
| `MaximumInitialForcedDictionaryCapacity = 2048`, `GetInitialForcedDictionaryCapacity = max(256, min(rows, 2048))` | `Encoding.cs:17, 3990` | initial dictionary table size; growth beyond it | no (≤ 256 entries) | yes: cardinalities 255..1<<20 |
| `SmallDoubleDictionaryCapacity = 512`, table 1024 (stackalloc, linear probing) | `Encoding.cs:22-23, 2891-2975` | small double dictionaries use a fixed table, then switch (`usesSmallDoubleIndexes = false`) to the general map | no | yes: double columns with cardinality 511/512/513/1023/1024/1025 |
| `DictionarySortOrder` kept in the column's strategy context across row groups (Volatile) | `Encoding.cs:1160, 1248, 1313` | a sorted dictionary detected in one row group is assumed for the next one | barely (single row group mostly) | yes: ascending/descending/sorted-then-random segments over many row groups (columnar 1000 groups, row API small `TargetRowGroupSizeBytes`) |
| dictionary index bit width (`GetBitWidthFromMaxValue(count-1)`) per page, page rows = `targetBits / bitWidth` | `Encoding.cs:888-898, 1184-1190` | bit width steps at 2, 3, 5, 9, 17, 257, 65537 … entries | to ~6 bits | yes: cardinalities around every power of two up to 2^20+1 |
| `TryGetFixedWidthRowsPerPage`: `targetPageBytes > int.MaxValue / 8` for booleans; `targetPageBytes / width` | `Encoding.cs:815-830` | rows per page; clamps | page sizes drawn independently by wide routes | yes: page 1 B … 256 MB |
| `DeltaBinaryPacked`: block 128, 4 miniblocks of 32 | `DeltaBinaryPackedEncoding.cs:13-15` | multiple blocks / partial last miniblock | yes (≥ 33 values in some routes), multi-block rarely | yes |
| `AlpEncoding`: vector 1024 values, `MaxStackOffsets = 256` vectors (stackalloc vs rented) | `AlpEncoding.cs:11-13, 45, 81` | > 256 vectors (> 262 144 values in a page) switches to a rented offset buffer | no | yes when a page holds > 262 144 doubles/floats (ALP, page ≥ 2 MB, t1/t2) |
| `ByteStreamSplit`: `MaxStackConvertedValues = 256` | `ByteStreamSplitEncoding.cs:15` | chunks of 256 converted values | yes (when > 256 values, rarely) | yes |
| `EncodingPrimitives` fixed length `> int.MaxValue` | `EncodingPrimitives.cs:314` | refusal | n/a | n/a |
| `StringWriteScratch` doubling up to `Array.MaxLength` | `Writing/StringWriteScratch.cs:45` | scratch growth for string columns | small | yes: string columns, values up to 17 MB |

## Writer: buffers, pages, row groups, files

| Threshold | Where | Effect | AFL | Scale |
|---|---|---|---|---|
| `TargetDataPageSizeBytes` default 1 MB, `<= int.MaxValue` | `ParquetWriterOptions.cs:27, 77` | page split; `int.MaxValue` overflows the pool (known finding) | drawn, but data never fills a page above a few KB | yes: 1, 7, 1 K, 8 K, 1 M, 1 M+1, 16 M, 64 M, 256 M with data filling them |
| `BufferWriterFactory.MinimumPageChunkBytes = 4096`, `PageHeaderChunkBytes = 1024` | `BufferWriterFactory.cs:16, 61` | page buffers are chained segments; multi-segment pages | partially | yes: `BufferChunkSizeBytes` 1 / 4 K / 64 K / 1 M / 64 M with MB pages |
| `BufferWriter` chunk / initial size `<= int.MaxValue`, segment growth | `BufferWriter.cs:21-26, 312` | segment rollover | small | yes |
| `InitialColumnBufferBytes` default 40 MB; `InitialPageCapacity` | `ParquetWriterOptions.cs:20` | growth of column buffers / page list (`PageList`) beyond initial capacity | growth with tiny data only | yes: capacity 1–4096 pages with up to ~1M pages per chunk (page 1 B × 50k rows) |
| `TargetRowGroupSizeBytes` default 128 MB | `ParquetWriterOptions.cs:30` | row API row-group cut (`GetFixedRowsPerGroup`, `checked(int)`) | drawn small; rows ≤ 48 | yes: 1 B … 4 GB+5 with up to 6M rows |
| `TargetFileSizeBytes` default 512 MB | `ParquetWriterOptions.cs:33` | file rollover | LIF1 (small) | yes (`rollover` mode) |
| `RowApiInitialRowCapacity` default 1024; `RowBufferSlot.Grow` doubling to `int.MaxValue` | `ParquetWriterOptions.cs:25`, `RowApi/RowBufferSlot.cs:154-165` | slot growth past 1024 rows (the #276 class) | only since 6b94e7b, ≤ 48 rows | yes: capacity 1..65536 with up to 6M rows |
| `RowApiMaxParallelism` (default `WorkerCount` = CPU count) | `ParquetWriterOptions.cs:56`, `RowWriterBase.cs` | slot pipeline with several workers, `Monitor`/`SemaphoreSlim` hand-off | EXEC route, few rows | yes: 1..16 with many row groups (`concurrency`) |
| `ParquetWriter` row-group count `int.MaxValue` | `ParquetWriter.cs:263, 312` | refusal | no | no (unaffordable) |
| `OffsetIndexLength > int.MaxValue` | `ParquetWriter.cs:731` | refusal | no | no |
| file offsets are `ulong` (`DataPageOffset`, `ColumnIndexOffset`…) — 2 GB / 4 GB boundaries | `Writing/Thrift/*`, `Reading/Physical/ParquetColumnChunkInfo` | offsets above `int.MaxValue` / `uint.MaxValue` | no (files are KB) | yes: `big` mode writes 2.3 GB and 4.3 GB files and a single 2.1 GB column chunk |
| `DatasetWriterOptions.PendingRowCapacity` default 4096; `DatasetBufferSlot.SnapshotChunkSize = 64 KB` | `Dataset/*` | pending-row flush; snapshot chunk chaining for binary values > 64 KB | ≤ 64 rows | yes: capacity 1/2/100/4095/4096/4097/65536, values up to 17 MB, 300 partitions with 1..8 open files (reopen = append) |
| Bloom filter `MaximumSupportedBytes = 128 MB`, `MinimumBytes = 32` | `ParquetBloomFilterOptions.cs:27-28` | sizing from NDV | small NDV | yes: NDV up to 6M (bloom on 25 % of columns) |
| `DefaultParquetBufferPool`: buckets 2^4..2^30, colored above 64 KB, pressure check above 64 MB retained | `DefaultParquetBufferPool.cs:8-15` | buffer reuse / retention policy changes | small buffers only | yes: MB/GB buffers, 64 MB+ retained |

## Reader

| Threshold | Where | Effect | AFL | Scale |
|---|---|---|---|---|
| `ColumnChunkReader.DecodeBatchSizeBytes = 256 KB` | `ColumnChunkReader.cs:13, 522`, `EncodedBatching.cs:328-341, 1552` | decoded buffers split a page into batches (≥ 32768 longs, 65536 ints) | no (pages hold ≤ 48 values) | yes: any page ≥ 256 KB of values (t1/t2, page 1 MB+) |
| `PageMetadataReader.InitialPageHeaderLength = 64 KB`, `PageHeaderProbe.CursorInitialLength = 64 KB`, `ExactProbeCount = 128` | `PageMetadataReader.cs:10, 455`, `PageHeaderProbe.cs:8-9` | header read window; re-read for larger headers | resource seeds (hand-made) | yes: pages with huge statistics (17 MB binary min/max — if not truncated) |
| `TotalCompressedSize / CompressedSize > int.MaxValue` refusals | `PageMetadataReader.cs:285-431`, `ParquetPageCursor.cs:44, 166` | a column chunk above 2 GB cannot be read | hand-made footers only | yes: `big` variant 2 (real 2.1 GB chunk) |
| `MaximumPageValueCount = (int.MaxValue - 1024) / 8` | `ColumnChunkReader.cs:1905` | per-page value limit | no | no |
| `ColumnReadBuffers` byte length `> int.MaxValue` | `ColumnReadBuffers.cs:189-200` | refusal | no | partially (17 MB values) |
| row reader `WorkerCount > 1` → `RowReaderWorkers` threads; non-built-in sources wrapped in `RowReaderSynchronizedSource`; `MaxReadAheadRowGroups` 0/1 | `RowReaderCore.cs:699-728` | parallel column decode + one-row-group read-ahead | EXEC route; fuzzer reader target uses WorkerCount = 1 | yes: `concurrency` (workers 1..16, read-ahead, custom jittering source, jittering stream, Reset mid-file, shared-source parallel readers) |
| `RowReaderCore` `availableRows = int.MaxValue` / `_usingMissing` | `RowReaderCore.cs:550`, `RowApi*ReadState*.cs` | batch alignment across columns with different batch sizes | small | yes: projections over columns with different page/batch boundaries |
| `Lz4LegacyDecompressor` block sizes 64 KB..4 MB | `Reading/Lz4LegacyDecompressor.cs:65-66` | n/a (Plank never writes LZ4 frames) | WCD1 seeds | no |
| Thrift `MaxStructDepth = 64` | `CompactProtocolReader.cs:80` | refusal | yes | n/a |
| `DeltaBinaryPackedDecoder.MaxMiniBlockCount = 64` | `DeltaBinaryPackedDecoder.cs:24` | refusal | yes | n/a |
| `AlpDecoder` log vector size 3..15 | `AlpDecoder.cs:131-134` | refusal / vector loop | yes | yes (writer vectors of 1024) |

## Not crossed by anything yet

- More than `int.MaxValue` rows, values, pages or row groups (unaffordable; the guards are refusals).
- A dictionary page above 2 GB.
- Thousands of columns at large row counts (the wide columnar shapes are 300–3000 columns with ≤ 50 rows).
- Nested (repeated) columns at scale: the `ScaleNested` type is declared but no scale mode drives it yet.

## The scale driver

`Plank.Fuzzing.Scale` (`run <mode> <seed> [tier]`, `campaign <mode> <seed0> <count> [tier] [log]`). Every value is a pure
function of (column seed, row index), so files of any size are verified while streaming. Modes: `columnar` (runtime schema,
drawn encodings/compression/bloom per column, drawn row-group sizes including 0, 2047/2048/2049, serialized columns shared
across groups or per group), `row` (generated `ScaleRow`, `GetRow`/cursor, drawn row-API options), `rollover`
(`TargetFileSizeBytes` file rollover), `dataset` (partitioned, few open files so files are reopened and appended),
`concurrency` (hundreds of multi-threaded reads/writes per input against the single-threaded file), `big` (2.3 / 4.3 GB files and
a 2.1 GB chunk). Each file is read back with: the runtime logical reader over `FileReadSource`, `StreamReadSource` and
`MemoryReadSource` (values, nulls, chunk statistics, offset/column index per page, Bloom no-false-negative), a projected read
with a random page pruner (values must equal exactly the kept pages' rows), the generated row reader (random projection,
WorkerCount, read-ahead) and typed reader, and ParquetSharp (Arrow C++).
