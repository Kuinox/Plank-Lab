# Reader code the fuzzer does not reach

Tracked so that "cold" code is not re-investigated every round, and so that dead code gets deleted. Source of
truth for coverage: `fuzz/coverage-tiers.sh <tag>` (all four ISA tiers), then `fuzz/coverage-summary.py <tag>`
and `fuzz/coverage-lines.py <tag> <file> <from> <to>` for a method. Line numbers are as of Plank master abeb527.

Status keys: **dead?** = no input can reach it on any machine (verify, then delete like #187 / #192);
**hardware** = reachable only on another CPU; **harness** = reachable by users, not by the fuzz harness by design;
**seed** = reachable, the corpus lacks a shape that gets there; **fixed** = gap closed (kept one round for history).

## dead? — candidates for deletion

| Code | Evidence | Plan |
|---|---|---|
| `ColumnChunkReader.TryDecodeNullablePageIntoNative` after the guard at ColumnChunkReader.cs:1310 (and its callees `TryDecodeNullableValuesByPhysicalType`, `TryDecodeNullableValues`, the `DecodeDefinitionLevels` call at :1358) — ~120 lines | Guard returns false on all 1,550 calls over the 2026-11-07 corpus (4 tiers): every flat nullable page is taken by the batched decoders first, including empty pages since #202. | Wait for the non-nullable definition-level fix (fix/nonnullable-definition-levels) to merge, re-measure, then brief an agent to prove no caller reaches it (by construction of the dispatch in `ColumnBufferEnumerable.MoveNext`) and delete. |

## hardware — keep, needs another machine

| Code | Runs only when | Plan |
|---|---|---|
| `DecodeNullableInt32DictionaryNineBitPortable` (ColumnChunkReader.DictionaryPortable.cs:16) | `AdvSimd.IsSupported` (ARM64) and bit width 9 | Fuzz on the ARM64 phone host, or cover with a unit test run on ARM CI. |
| `DecodeDictionaryLiteralInt64IndexesWideScalar`, `GatherDictionaryInt64Scalar` (ColumnChunkReader.cs:4169, :4230) | `UseScalarWideInt64Gather` = Intel family 6 model 158 (Coffee Lake) | A Coffee Lake fleet host, or a test hook that forces the flag. |
| `DeltaBinaryPackedDecoder.Decode{Int32,Int64,NullableInt32}MiniBlockAvx2`, `UnpackEightAvx2` | AVX2 without fast PDEP (Zen 1/2); this Zen 4 box always takes the BMI2 kernels | A Zen 1/2 host. `DOTNET_EnableBMI2=0` is a no-op on .NET 10. |

## harness — reachable by users, out of the fuzzer's reach by design

| Code | Why | Plan |
|---|---|---|
| `RowReaderWorkers.*`, `RowReaderCore.WaitForWork/QueueBuffer`, `RowReaderSynchronizedSource` | Fuzzing runs with WorkerCount 1: threads scramble SharpFuzz's edge map (stability 92% → 55%). | Separate non-AFL stress test comparing WorkerCount N with 1 on the corpus. |
| `FileReadSource` | Harness uses memory and stream sources; file I/O per execution is too slow. | Unit tests only. |
| `DefaultParquetBufferPool.Dispose/CancelRent`, `ParquetBloomFilter.Dispose`, `ColumnBuffer.Retain`, `StreamReadSource.Reset` | Lifecycle APIs the read loop never calls. | Unit tests; not a fuzzing target. |

## seed — reachable, corpus lacks the shape

| Code | Missing shape | Plan |
|---|---|---|
| `DecodeByteStreamSplitBinaryValues` (ColumnChunkReader.cs:2158) | BYTE_STREAM_SPLIT on a nested FIXED_LEN_BYTE_ARRAY column | Add a list<FLBA> BSS seed. |
| Success path of nested `DecodeDeltaBinaryValues` (ColumnChunkReader.cs:2040, 0 of 20 returns) | A valid nested DELTA_BYTE_ARRAY column | Add list<binary> DELTA_BYTE_ARRAY seeds (Plank writer, and pyarrow for FLBA). |

## fixed

| Code | How (2026-11-07) |
|---|---|
| `PlanRleBatch`, `PlanDeltaPairBatch`, `LeastCommonMultiple`, `CountLogicalValuesThroughPhysical`, delta/ALP `NextBatchCount` | `split-*` seeds: pages larger than one 256 KiB decode batch (CorpusGenerator.BatchSplitColumns). |

## Not reader code

Schema-construction and writer helpers were counted in the reader total until 2026-11-07 (ParquetDecimalConverter
write side, ColumnOptions equality, ColumnDefinition factories, ParquetBloomFilterOptions, SplitBlockBloomFilter.InsertHash,
RowGroupWriterCore, ParquetValueConverter.ConvertToPhysical, ParquetColumnAttribute, ParquetTypeMap). The writer
target covers them.
