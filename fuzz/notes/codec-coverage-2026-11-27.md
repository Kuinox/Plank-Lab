# Codec coverage before / after route WCD1 (2026-11-27)

Measured with coverlet around `Plank.Fuzzing.Replay writer` (`fuzz/tools/codec-coverage.py` compares the two cobertura
files; runs: `agents/writer-c/run_cov.sh`).

* **before** - the existing writer corpus (`fuzz/corpus` minus the dataset-operational / row-API / merge seeds, minus
  `writer-codec-*`), 493 inputs.
* **after** - the same plus 600 random `0xDB WCD1` inputs and the 24 `writer-codec-*` seeds, 1,119 inputs.

```
group                                    lines before      lines after    branches before     branches after
K4os LZ4 (encoder)                       0.0% (0/433)     0.0% (0/433)       0.0% (0/204)       0.0% (0/204)
K4os LZ4 (other)                      31.0% (916/2957)  35.0% (1034/2957)   24.0% (415/1728)   29.6% (512/1728)
Plank Writing/Compression               85.0% (68/80)    92.5% (74/80)      60.9% (14/23)      69.6% (16/23)
Plank read-side decompressors          22.4% (53/237)   36.3% (86/237)     12.7% (16/126)     29.4% (37/126)
Plank zlib glue (Compression/)          51.5% (50/97)    51.5% (50/97)      33.8% (22/65)      33.8% (22/65)
```

Per file (lines / branches, before → after; x32-only `LL32.*` and `Mem32` omitted):

| group | file | lines | branches |
|---|---|---|---|
| K4os LZ4 (other) | `AssemblyHook.cs` | 0/1 → 0/1 | 0/0 → 0/0 |
| K4os LZ4 (other) | `BufferPool.cs` | 9/9 → 9/9 | 4/8 → 4/8 |
| K4os LZ4 (other) | `Extensions.cs` | 0/15 → 0/15 | 0/22 → 0/22 |
| K4os LZ4 (other) | `LL.high.cs` | 72/124 → 79/124 | 22/50 → 27/50 |
| K4os LZ4 (other) | `LL.tools.cs` | 29/69 → 39/69 | 21/54 → 29/54 |
| K4os LZ4 (other) | `LL.types.high.cs` | 4/4 → 4/4 | 0/0 → 0/0 |
| K4os LZ4 (other) | `LL64.dec.cs` | 108/206 → 109/206 | 77/168 → 93/168 |
| K4os LZ4 (other) | `LL64.fast.cs` | 151/298 → 159/298 | 79/188 → 85/188 |
| K4os LZ4 (other) | `LL64.high.cs` | 417/658 → 507/658 | 169/348 → 228/348 |
| K4os LZ4 (other) | `LL64.tools.cs` | 26/54 → 27/54 | 21/36 → 22/36 |
| K4os LZ4 (other) | `LLxx.cs` | 12/61 → 12/61 | 6/32 → 6/32 |
| K4os LZ4 (other) | `LZ4Codec.cs` | 22/82 → 23/82 | 8/54 → 10/54 |
| K4os LZ4 (other) | `Mem.cs` | 20/37 → 20/37 | 2/4 → 2/4 |
| K4os LZ4 (other) | `Mem64.cs` | 21/30 → 21/30 | 2/4 → 2/4 |
| K4os LZ4 (other) | `PinnedMemory.cs` | 25/47 → 25/47 | 4/16 → 4/16 |
| K4os LZ4 (other) | `Pubternal.cs` | 0/9 → 0/9 | 0/0 → 0/0 |
| K4os LZ4 (other) | `UnmanagedResources.cs` | 0/16 → 0/16 | 0/6 → 0/6 |
| Plank Writing/Compression | `BrotliCompression.cs` | 6/7 → 6/7 | 1/2 → 1/2 |
| Plank Writing/Compression | `Compression.cs` | 11/16 → 15/16 | 5/7 → 6/7 |
| Plank Writing/Compression | `GzipCompression.cs` | 4/4 → 4/4 | 0/0 → 0/0 |
| Plank Writing/Compression | `GzipDeflater.cs` | 24/28 → 26/28 | 6/10 → 7/10 |
| Plank Writing/Compression | `Lz4Compression.cs` | 7/8 → 7/8 | 1/2 → 1/2 |
| Plank Writing/Compression | `SnappyCompression.cs` | 6/6 → 6/6 | 0/0 → 0/0 |
| Plank Writing/Compression | `ZstdCompression.cs` | 10/11 → 10/11 | 1/2 → 1/2 |
| Plank read-side decompressors | `GzipInflater.cs` | 29/33 → 30/33 | 6/12 → 9/12 |
| Plank read-side decompressors | `Lz4LegacyDecompressor.cs` | 0/163 → 23/163 | 0/97 → 12/97 |
| Plank read-side decompressors | `ParquetDecompressor.cs` | 24/41 → 33/41 | 10/17 → 16/17 |
| Plank zlib glue (Compression/) | `ZlibLibraryResolver.cs` | 34/71 → 34/71 | 17/55 → 17/55 |
| Plank zlib glue (Compression/) | `ZlibNative.cs` | 16/26 → 16/26 | 5/10 → 5/10 |

## What is left, and why

* `LZ4Block*/LZ4Chain*/LZ4Encoder*/LZ4Pickler*` ("K4os LZ4 (encoder)" above, 433 lines): the stream / pickler / chain encoders
  of the vendored library. Plank only uses the block `LZ4Codec.Encode/Decode`; these are never called, so they are not
  coverable through any Plank route. The group is mis-named (it also holds the stream decoders).
* `LL32.*` / `Mem32.cs` (about 1,250 lines): 32-bit pointer variants, unreachable in a 64-bit process.
* `LL64.high.cs` (levels 3..12): about 150 lines remain. The optimal parser (levels 10-12) needs long, highly
  repetitive inputs with many equal-length matches; the route covers sizes up to 4 MiB with six repetitive patterns, but
  random draws reach each level on only a fraction of inputs. Next step: pin level and pattern from the first bytes so
  one input can exercise level 12 on a repetitive 1 MiB buffer.
* `LL64.dec.cs` and `Lz4LegacyDecompressor.cs`: the remaining lines are the decoder's error and Hadoop / frame
  variants. The damaged-payload rounds of WCD1 now reach many of them (read-side decompressors 12.7 % → 29.4 % of branches),
  the rest needs LZ4 *frame* inputs (legacy frames with block checksums, dictionary ids, linked blocks), which is the
  reader agent's decompressor route.
* `ZlibLibraryResolver.cs` / `ZlibNative.cs`: library lookup fallbacks and zlib error codes (`Z_BUF_ERROR` growth,
  malformed library); platform dependent, not driven by data.
* `Writing/Compression` (verified line by line): the 6 lines left are `throw` statements - brotli `TryCompress` failure
  (`BrotliCompression.cs:14`), zstd error code (`ZstdCompression.cs:19`), the unsupported-kind default
  (`Compression.cs:36`), zlib `deflateInit2` / `deflate` error returns (`GzipDeflater.cs:20,57`), and the LZ4
  `written <= 0` throw (`Lz4Compression.cs:15`). The last one IS reachable (an empty buffer, `codec.direct.Lz4.empty-input-rejected`
  in the evidence counters; see FINDINGS) but none of the 600 coverage inputs drew size 0 with LZ4. The others need the
  codec library itself to fail on valid input.

## Route summary

`WCD1` compresses fuzzer-sized buffers (0, 1, token / window / block boundaries up to 4 MiB; zero, 0xFF, random, short
repeats, text, window-edge back-references, half random / half zero, counters, tiny alphabet) with every codec Plank writes
and its levels, through the internal `Compression.Compress` with a randomly chunked source and destination
`BufferWriter`. The output is decoded by reference decoders written in `WriterCodecCases.cs` (LZ4 block, Snappy), by
`System.IO.Compression` (gzip, brotli) and by ZstdSharp's high-level decompressor, and by Plank's `ParquetDecompressor`;
declared sizes (snappy preamble, zstd frame content size, gzip trailer CRC and ISIZE), `BufferWriter.ComputeCrc32`, the
Hadoop LZ4 framing, damaged payloads (flip / truncate / extend / escape bytes / head), real written pages (header sizes,
page CRC, V1 and V2 payloads decoded independently and compared with Plank's view) and ParquetSharp's reading of the same
files are all checked. 0 faults in 1,500 + 1,024 random inputs.
