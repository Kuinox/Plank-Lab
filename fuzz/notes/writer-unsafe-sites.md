# Writer-side unsafe / stackalloc / MemoryMarshal / native sites (library master 3a6a28a)

Scope: `library/Plank/Plank/{Writing,Schema,Compression}`, `ParquetBuffer.cs`, `DefaultParquetBufferPool.cs`.
Counted with `grep -E "unsafe |Unsafe\.|MemoryMarshal\.|stackalloc|fixed \(|NativeMemory"`. `ArrayPool` is not used
anywhere on the write side (buffers come from `IParquetBufferPool`, which the writer routes now vary: see *Pools*).

"Reached by" lists the writer routes that drive a site with fuzzer-chosen sizes. Route names:
generic = the columnar `Decode()` route (no magic), WTM1 = `0xC8 WTM1` typed matrix (`WriterTypeMatrixCases`),
WNS1 = `0xC7 WNS1` nested shapes (`WriterNestedCases`), ENCG/WMD1/BWOV/... = the older hand-written routes.

## Sites whose size is chosen by the data (the interesting ones)

| Site | Size / bound | Boundary that must be hit | Reached by |
|---|---|---|---|
| `Encoding/DeltaBinaryPackedEncoding.cs:421,472` `stackalloc int/long[values.Length]` if `<= 256` | value count of a page | 255 / 256 / 257 (+ block size 128: 127/128/129) | WTM1 kind 6 and narrow kind 4 (row counts 255..258, 127..129, 383..385, 513); generic route multi-page |
| `Encoding/DeltaBinaryPackedEncoding.cs:59,102,144` `stackalloc long[128]` | fixed block | every bit width 0..63, constant deltas, extremes | WTM1 kind 6 (bit width, pattern, 64/32 bit, optional) |
| `Encoding/ByteStreamSplitEncoding.cs:142` `valueLength <= 256 ? stackalloc : new` (decimal FLBA) | `TypeLength` | 255 / 256 / 257 | WTM1 kind 3 (decimal FLBA, `TypeLength` = minimal + {0,1,240,250,256}, BYTE_STREAM_SPLIT) |
| `Encoding/ByteStreamSplitEncoding.cs:257,296` `stackalloc uint/ulong[256]` | converted values per call | 255 / 256 / 257 values | WTM1 narrow/unsigned with BYTE_STREAM_SPLIT, generic float/double BSS |
| `BloomFilterBuilder.cs:255` `length <= 256 ? stackalloc : new` (decimal FLBA bloom) | `TypeLength` | 255 / 256 / 257 | WTM1 kind 3 does not enable bloom on decimals (a decimal bloom is a known NotSupported gap, see `OptionalDecimalBloomGap`); **unreached with width > 16 by CLR `decimal` values** - see "Unreached" |
| `Encoding/AlpEncoding.cs:46,82` `vectorCount <= 256 ? stackalloc uint[vectorCount]` | `ceil(values/1024)` | > 256 vectors = > 262,144 values in one page | WTM1 kind 9: 1-in-40 draw of 263,000 rows with a 64 MiB page target |
| `Encoding/Encoding.cs:375,1367,2217` `stackalloc int[512 / 256]` small integer dictionaries | values in `[min, min+count)` | values -129 / -128 / 127 / 128, 0 / 511 / 512, distinct 255..257, 511..513 | WTM1 kind 5 (distinct and value base drawn independently, int/long, required/optional) |
| `Encoding/Encoding.cs:1163,2894` `stackalloc long/int[1024]` small double dictionary | distinct doubles | 511 / 512 / 513 distinct | WTM1 kind 9 (float/double + PLAIN_DICTIONARY, row counts 1023..1025) - distinct count is data driven, not yet drawn independently |
| `Encoding/RleBitPackingHybridEncoding.cs:475,514` `stackalloc int[8]` | tail | value counts mod 8 for every bit width | WTM1 kind 5 (distinct 1..70000 gives bit widths 1..17), nested levels in WNS1 |
| `Encoding/PlainEncoding.cs:685` `stackalloc double[Vector256.Count]` | vector lanes | n < lanes, n % lanes != 0 | generic route and WTM1 kind 9 (row counts 1, 2, 9, 100, 1023..1025) |
| `Schema/ParquetDecimalConverter.cs` `stackalloc byte[16]` / `int[4]` | decimal width | scale 0..28, 28-29 digit values, negative values | WTM1 kind 3 (precision 1..28, every physical form) |
| `ParquetWriter.cs:903` `stackalloc byte[8]` (footer length + magic) | fixed | - | every route |
| `Writing/Thrift/ParquetMetadataThriftWriter.cs:902-944` `stackalloc byte[sizeof(T)]` | fixed | - | every route (footer) |
| `Writing/Compression/GzipDeflater.cs:10-30` `stackalloc` + `fixed` over the page, native zlib state | page size, output buffer size | tiny (1 B) page, page larger than the output buffer, incompressible data | WTM1 kind 7 (levels 0..9, up to 20,000 rows of random-tail text, pages 64 B..1 MiB), generic route (pages 64 B..1 MiB) |
| `Writing/Compression/ZstdCompression.cs:13-14` `fixed` input / output | page size | empty page, large page, all levels `Compressor.MinCompressionLevel..MaxCompressionLevel` | WTM1 kind 7, generic route, CompressionLevel (0xF2) route |
| `DefaultParquetBufferPool.cs:123,161,350` `NativeMemory.AlignedAlloc/Free` | rent size 0, 1, bucket edges (2^4..2^30), > 2^30 | exact bucket sizes, size+1, `ZeroAllocation` policy, `maximumRetainedBytes` 0 | writer routes now vary the pool (`WriterFuzzPool`: shared, ZeroAllocation, Adaptive no-retention / 1 MiB retention, exact-length, padded, dirty); `PBAP` buffer API route; direct bucket-edge rent sizes are owned by the `pools` agent |
| `ParquetBuffer.cs` `Unsafe.AsRef` / `MemoryMarshal.CreateSpan` / `RetainSlice` | slice offset / length | offset == length, 0-length, exact-length slices | `WriterFuzzPool` exact-length pools (writer routes), `PBAP` |

## Sites with a fixed or type-driven size (reached whenever the type is written)

`Unsafe.Add` / `Unsafe.As` / `MemoryMarshal.Cast|AsBytes|GetReference` in `PlainEncoding`, `EncodingPrimitives`,
`ByteStreamSplitEncoding`, `DeltaBinaryPackedEncoding`, `RleBitPackingHybridEncoding`, `WyHashing`, `MinMaxScan`,
`ColumnStatistics`, `SerializedColumn`, `Encoding`, `ReusableDictionaryState`, `ByteArrayRow`,
`DeltaLengthByteArrayEncoding`, `DeltaByteArrayEncoding`, `TimestampConversion`, `ParquetValueConverterOfT`.
They index spans by element or lane count. They are reached by every route that writes the corresponding CLR type; the
inputs that matter are the element counts around vector widths (2, 4, 8, 16, 32 lanes) and around the block / page
boundaries listed above. All of these counts are now drawn by WTM1 (rows 1, 2, 3, 5, 7, 9, 31..33, 127..129,
255..258, 383..385, 513, 1023..1025, 4097, 20000) and by the generic route (1..64 x 1..70 tiling).

## Unreached (documented, not fuzzable through the public API)

* Decimal FLBA bloom / BSS with `TypeLength` > 16 *and* a value that needs it: the CLR `decimal` is 16 bytes, so widths
  above 16 are only sign extension. WTM1 now draws such widths for plain / dictionary / BYTE_STREAM_SPLIT; a bloom filter on
  a decimal column is rejected by the library (`NotSupported`, tracked by the `OptionalDecimalBloomGap` route).
* `DefaultParquetBufferPool.cs:364` `stackalloc int[100]` (adaptive sample sort): fixed, reached by any retaining pool.
* `Compression/ZlibNative.cs` P/Invoke marshalling: reached only through the gzip writer; the resolver paths
  (missing library) are platform dependent, see `coverage-gaps` gap 7.

## How reachability was decided

By reading each site's size expression (above) and checking that some route draws the controlling quantity
independently of the others. Coverage-based confirmation (zero-hit methods per file) is in
`fuzz/notes/coverage-gaps-detail-master-3a6a28a.md`; the numbers before this change were
`Writing/Encoding` 77 % branches, `DeltaBinaryPackedEncoding` 68.5 %, `ByteStreamSplitEncoding` 76.6 %,
`MinMaxScan` 59.7 %, `ColumnStatistics` 60.5 %, `BloomFilterBuilder` 61.2 %.
