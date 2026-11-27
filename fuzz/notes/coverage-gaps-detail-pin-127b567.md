# Plank fuzz coverage gaps

- **Plank**: lines 19350/26602 (72.7%), branches 9394/13698 (68.6%) — union of writer+reader+merger replays over all ISA tiers; host-default tier only: lines 70.2%, branches 67.4%
- **Plank.K4os.LZ4**: lines 648/3390 (19.1%), branches 271/1932 (14.0%) — union of writer+reader+merger replays over all ISA tiers; host-default tier only: lines 19.1%, branches 14.0%
- **Plank.Native.Zlib**: ships only `libz` native binaries (no managed code); exercised indirectly through Plank's GZIP codec, measured as part of Plank.

Per-target (Plank only): writer 65.5% branch / 69.6% line; reader 24.9% branch / 27.0% line; merger 10.6% branch / 15.7% line; 

## Per namespace (directory)

| namespace | assembly | lines | line % | branches | branch % | writer br% | reader br% | merger br% |
|---|---|---|---|---|---|---|---|---|
| K4os.LZ4/Encoders | Plank.K4os.LZ4 | 280 | 0.0% | 136 | 0.0% | 0.0% | 0.0% | 0.0% |
| K4os.LZ4/Engine/x32 | Plank.K4os.LZ4 | 1217 | 0.0% | 734 | 0.0% | 0.0% | 0.0% | 0.0% |
| K4os.LZ4/Internal/x32 | Plank.K4os.LZ4 | 20 | 0.0% | 4 | 0.0% | 0.0% | 0.0% | 0.0% |
| generated (obj/DeltaBinaryPackedIntegerGenerator) | Plank | 2291 | 10.4% | 611 | 5.9% | 4.9% | 2.0% | 0.0% |
| K4os.LZ4/. | Plank.K4os.LZ4 | 236 | 9.3% | 122 | 6.6% | 6.6% | 0.0% | 0.0% |
| K4os.LZ4/Internal | Plank.K4os.LZ4 | 124 | 43.5% | 56 | 17.9% | 17.9% | 0.0% | 0.0% |
| K4os.LZ4/Engine | Plank.K4os.LZ4 | 267 | 36.0% | 136 | 25.7% | 25.7% | 0.0% | 0.0% |
| K4os.LZ4/Engine/x64 | Plank.K4os.LZ4 | 1216 | 37.4% | 740 | 29.2% | 29.2% | 0.0% | 0.0% |
| Compression | Plank | 97 | 51.5% | 65 | 33.8% | 33.8% | 33.8% | 33.8% |
| Reading | Plank | 739 | 63.7% | 342 | 48.5% | 41.5% | 45.0% | 30.1% |
| K4os.LZ4/Internal/x64 | Plank.K4os.LZ4 | 30 | 70.0% | 4 | 50.0% | 50.0% | 0.0% | 0.0% |
| Reading/Physical | Plank | 608 | 73.5% | 212 | 50.9% | 48.1% | 48.1% | 34.9% |
| Writing/Compression | Plank | 80 | 85.0% | 23 | 60.9% | 60.9% | 0.0% | 34.8% |
| Reading/Logical/Internal | Plank | 6719 | 66.4% | 3838 | 61.5% | 54.3% | 52.1% | 7.0% |
| RowApi | Plank | 1264 | 81.7% | 683 | 69.3% | 66.0% | 42.6% | 0.0% |
| Reading/Logical | Plank | 682 | 84.2% | 314 | 71.7% | 59.9% | 66.2% | 29.9% |
| Reading/Physical/Internal | Plank | 726 | 81.3% | 407 | 72.2% | 64.1% | 67.3% | 33.4% |
| Writing/Encoding | Plank | 5779 | 83.6% | 2977 | 77.7% | 77.7% | 0.2% | 1.3% |
| (root) | Plank | 354 | 86.7% | 185 | 78.4% | 78.4% | 41.1% | 37.8% |
| Writing | Plank | 4816 | 86.0% | 2908 | 78.7% | 78.7% | 0.0% | 13.1% |
| Dataset | Plank | 570 | 81.9% | 296 | 80.7% | 80.7% | 0.0% | 0.0% |
| Schema | Plank | 833 | 78.8% | 453 | 81.9% | 78.8% | 51.2% | 19.6% |
| BloomFilters | Plank | 99 | 98.0% | 20 | 85.0% | 80.0% | 50.0% | 0.0% |
| Writing/Thrift | Plank | 814 | 96.4% | 303 | 87.1% | 87.1% | 0.0% | 44.9% |
| Writing/PageStrategy | Plank | 36 | 94.4% | 22 | 90.9% | 90.9% | 0.0% | 22.7% |
| Reading/Internal | Plank | 95 | 97.9% | 39 | 94.9% | 87.2% | 79.5% | 64.1% |

## Per file (Plank, lowest branch coverage first; files with ≥ 99% omitted)

| file | lines | line % | branches | branch % | covered by | owner |
|---|---|---|---|---|---|---|
| Plank/ParquetBufferPoolExtensions.cs | 2 | 0.0% | 0 | n/a | NONE | NEW buffer-pool/execution-options target (nobody owns) |
| Plank/ParquetWorkerContext.cs | 1 | 0.0% | 0 | n/a | NONE | NEW buffer-pool/execution-options target (nobody owns) |
| Plank/Reading/Logical/RowReaderBase.cs | 14 | 0.0% | 2 | 0.0% | NONE | reader |
| Plank/Reading/Lz4LegacyDecompressor.cs | 163 | 0.0% | 97 | 0.0% | NONE | reader |
| Plank/Reading/Physical/ParquetGeospatialStatistics.cs | 48 | 0.0% | 24 | 0.0% | NONE | reader (+ writer round trip for the matching encoder) |
| Plank/Schema/ParquetColumnAttribute.cs | 27 | 0.0% | 0 | n/a | NONE | writer (schema conversion/validation) + reader |
| Plank/Schema/ParquetSchemaAttribute.cs | 1 | 0.0% | 0 | n/a | NONE | writer (schema conversion/validation) + reader |
| Plank/Schema/RowSchema.cs | 10 | 0.0% | 4 | 0.0% | NONE | writer (schema conversion/validation) + reader |
| Plank/Schema/RowSchemaColumn.cs | 33 | 0.0% | 6 | 0.0% | NONE | writer (schema conversion/validation) + reader |
| Plank/Writing/Encoding/BitPackedEncoding.cs | 2 | 0.0% | 0 | n/a | NONE | writer |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/AssemblyHook.cs | 1 | 0.0% | 0 | n/a | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4BlockDecoder.cs | 42 | 0.0% | 20 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4BlockEncoder.cs | 4 | 0.0% | 0 | n/a | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4ChainDecoder.cs | 66 | 0.0% | 24 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4Decoder.cs | 3 | 0.0% | 2 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4Encoder.cs | 7 | 0.0% | 4 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4EncoderBase.cs | 43 | 0.0% | 16 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4EncoderExtensions.cs | 93 | 0.0% | 66 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4FastChainEncoder.cs | 9 | 0.0% | 0 | n/a | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4HighChainEncoder.cs | 13 | 0.0% | 4 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/Pubternal.cs | 9 | 0.0% | 0 | n/a | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.dec.cs | 206 | 0.0% | 168 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.fast.cs | 298 | 0.0% | 188 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.high.cs | 657 | 0.0% | 348 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.tools.cs | 56 | 0.0% | 30 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/Extensions.cs | 15 | 0.0% | 22 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/UnmanagedResources.cs | 16 | 0.0% | 6 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/x32/Mem32.cs | 20 | 0.0% | 4 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/LZ4Pickler.pickle.cs | 81 | 0.0% | 40 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/LZ4Pickler.unpickle.cs | 72 | 0.0% | 28 | 0.0% | NONE | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/obj/Release/net10.0/Plank.InternalGen/Plank.InternalGen.DeltaBinaryPackedIntegerGenerator/DeltaBinaryPackedDecoder.FastInteger.g.cs | 2291 | 10.4% | 611 | 5.9% | writer,reader | writer |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x64/LL64.high.cs | 658 | 26.3% | 348 | 12.1% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/Reading/Logical/Internal/InternalColumnChunkMetadata.cs | 43 | 72.1% | 8 | 12.5% | writer,reader,merger | reader |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/LZ4Codec.cs | 82 | 26.8% | 54 | 14.8% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/LLxx.cs | 61 | 19.7% | 32 | 18.8% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/Reading/Logical/Internal/ColumnChunkReader.DictionaryPortable.cs | 74 | 37.8% | 26 | 19.2% | writer | reader (+ writer round trip for the matching encoder) |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/LL.high.cs | 124 | 42.7% | 50 | 20.0% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/PinnedMemory.cs | 47 | 53.2% | 16 | 25.0% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/Compression/ZlibLibraryResolver.cs | 71 | 47.9% | 55 | 30.9% | writer,reader,merger | NEW compression-codec target (PlankDecompressorFuzzTarget exists; extend) + writer compression-level options |
| Plank/Reading/Logical/Internal/X86DecodeCapabilities.cs | 10 | 60.0% | 12 | 33.3% | writer,reader | reader |
| Plank/Reading/Logical/ParquetColumnChunkMetadata.cs | 26 | 92.3% | 6 | 33.3% | writer,reader | reader |
| Plank/Reading/StreamReadSource.cs | 28 | 57.1% | 12 | 33.3% | writer,reader,merger | reader |
| Plank/Reading/Logical/Internal/DeltaBinaryPackedReader.cs | 45 | 60.0% | 20 | 35.0% | writer,reader | reader |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/LL.tools.cs | 69 | 39.1% | 54 | 35.2% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/Writing/Encoding/ReadOnlyMemoryByteComparer.cs | 5 | 40.0% | 0 | n/a | writer | writer |
| Plank/Writing/ParquetSourceIdentity.cs | 8 | 62.5% | 10 | 40.0% | writer,merger | writer |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x64/LL64.fast.cs | 298 | 49.7% | 188 | 40.4% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/Reading/Logical/ParquetFileMetadata.cs | 16 | 43.8% | 0 | n/a | writer,reader,merger | reader |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x64/LL64.dec.cs | 206 | 52.4% | 168 | 45.8% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/Compression/ZlibNative.cs | 26 | 61.5% | 10 | 50.0% | writer,reader,merger | NEW compression-codec target (PlankDecompressorFuzzTarget exists; extend) + writer compression-level options |
| Plank/CorruptParquetException.cs | 4 | 50.0% | 0 | n/a | writer,reader | writer |
| Plank/ParquetExecutionOptions.cs | 6 | 66.7% | 2 | 50.0% | writer,reader,merger | NEW buffer-pool/execution-options target (nobody owns) |
| Plank/Reading/Logical/Internal/InternalParquetFooter.cs | 18 | 66.7% | 4 | 50.0% | writer,reader,merger | reader |
| Plank/Reading/Logical/Internal/InternalRowGroupMetadata.cs | 13 | 84.6% | 2 | 50.0% | writer,reader,merger | reader |
| Plank/Reading/Logical/Internal/PageMetadataEntry.cs | 10 | 100.0% | 10 | 50.0% | writer,reader,merger | reader |
| Plank/Reading/Logical/NestedColumnBuffer.cs | 21 | 95.2% | 6 | 50.0% | writer,reader | reader |
| Plank/Reading/MemoryReadSource.cs | 18 | 77.8% | 10 | 50.0% | writer,reader,merger | reader |
| Plank/Reading/Physical/ParquetBloomFilter.cs | 26 | 69.2% | 4 | 50.0% | writer,reader | reader (+ writer round trip for the matching encoder) |
| Plank/RowApi/RowApiColumnReadState.cs | 53 | 71.7% | 10 | 50.0% | writer,reader | rowapi |
| Plank/RowApi/RowReaderOptions.cs | 15 | 73.3% | 4 | 50.0% | writer,reader | rowapi |
| Plank/Writing/BufferWriterFactory.cs | 27 | 66.7% | 10 | 50.0% | writer,merger | writer |
| Plank/Writing/Compression/BrotliCompression.cs | 7 | 85.7% | 2 | 50.0% | writer | writer |
| Plank/Writing/Compression/Lz4Compression.cs | 8 | 87.5% | 2 | 50.0% | writer | writer |
| Plank/Writing/Compression/ZstdCompression.cs | 11 | 90.9% | 2 | 50.0% | writer,merger | writer |
| Plank/Writing/Encoding/ByteArrayComparer.cs | 11 | 45.5% | 8 | 50.0% | writer | writer |
| Plank/Writing/Encoding/RleEncoding.cs | 13 | 69.2% | 4 | 50.0% | writer | writer |
| Plank/Writing/PageIndex.cs | 10 | 100.0% | 6 | 50.0% | writer,merger | writer |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/BufferPool.cs | 9 | 100.0% | 8 | 50.0% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/Mem.cs | 37 | 54.1% | 4 | 50.0% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/x64/Mem64.cs | 30 | 70.0% | 4 | 50.0% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/Reading/Logical/Internal/AlpDecoder.cs | 213 | 64.8% | 106 | 52.8% | writer,reader | reader (+ writer round trip for the matching encoder) |
| Plank/Reading/Physical/ParquetPageCursor.cs | 219 | 62.6% | 134 | 53.0% | writer,reader,merger | reader |
| Plank/Writing/TimestampConversion.cs | 117 | 70.1% | 58 | 55.2% | writer | writer |
| Plank/Reading/Logical/Internal/DeltaBinaryPackedDecoder.cs | 867 | 57.9% | 388 | 57.5% | writer,reader | reader (+ writer round trip for the matching encoder) |
| Plank/Reading/Logical/Internal/ColumnChunkReader.cs | 2958 | 59.7% | 1922 | 58.0% | writer,reader,merger | reader |
| Plank/Reading/GzipInflater.cs | 33 | 87.9% | 12 | 58.3% | writer,reader,merger | reader |
| third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x64/LL64.tools.cs | 54 | 48.1% | 36 | 58.3% | writer | NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise |
| Plank/Reading/ParquetDecompressor.cs | 41 | 58.5% | 17 | 58.8% | writer,reader,merger | reader |
| Plank/Reading/Physical/Internal/BloomFilterReader.cs | 111 | 68.5% | 47 | 59.6% | writer,reader | reader (+ writer round trip for the matching encoder) |
| Plank/Writing/MinMaxScan.cs | 198 | 54.0% | 72 | 59.7% | writer,merger | writer |
| Plank/RowApi/RowReaderCore.cs | 431 | 76.1% | 266 | 59.8% | writer,reader | rowapi |
| Plank/Reading/Logical/Internal/BinaryValueDescriptor.cs | 13 | 76.9% | 10 | 60.0% | writer,reader | reader |
| Plank/Reading/Physical/ParquetPage.cs | 5 | 60.0% | 0 | n/a | reader | reader |
| Plank/Writing/Compression/GzipDeflater.cs | 28 | 85.7% | 10 | 60.0% | writer,merger | writer |
| Plank/Writing/StreamParquetSource.cs | 37 | 83.8% | 20 | 60.0% | writer,merger | writer |
| Plank/Reading/Physical/ParquetFileReader.cs | 103 | 83.5% | 28 | 60.7% | writer,reader,merger | reader |
| Plank/RowApi/RowBufferSlot.cs | 131 | 78.6% | 70 | 61.4% | writer | rowapi |
| Plank/Reading/Logical/RowGroup.cs | 154 | 78.6% | 92 | 62.0% | writer,reader,merger | reader |
| Plank/Reading/FileReadSource.cs | 17 | 88.2% | 8 | 62.5% | reader | reader |
| Plank/Reading/Logical/ParquetDataPageMetadataCollection.cs | 25 | 88.0% | 8 | 62.5% | writer,reader | reader |
| Plank/RowApi/PipelineRowWriterBase.cs | 84 | 85.7% | 32 | 62.5% | writer | rowapi |
| Plank/RowApi/RowApiColumnReadStateOfT.cs | 60 | 93.3% | 16 | 62.5% | writer,reader | rowapi |
| Plank/Writing/Encoding/ByteArrayRow.cs | 36 | 58.3% | 16 | 62.5% | writer | writer |
| Plank/Schema/LogicalType.cs | 31 | 90.3% | 22 | 63.6% | writer,reader,merger | writer (schema conversion/validation) + reader |
| Plank/Reading/CompactProtocolReader.cs | 207 | 74.4% | 98 | 64.3% | writer,reader,merger | reader |
| Plank/Reading/Logical/Internal/PageMetadataReader.cs | 344 | 77.0% | 220 | 64.5% | writer,reader,merger | reader |
| Plank/Reading/ParquetThriftConversions.cs | 14 | 85.7% | 17 | 64.7% | writer,reader,merger | reader |
| Plank/Writing/Encoding/PlainEncoding.cs | 807 | 71.9% | 443 | 65.9% | writer,merger | writer |
| Plank/Writing/Encoding/RleBitPackingHybridEncoding.cs | 351 | 78.3% | 203 | 66.5% | writer | writer |
| Plank/Schema/Column.cs | 24 | 87.5% | 6 | 66.7% | writer,reader,merger | writer (schema conversion/validation) + reader |
| Plank/Schema/EncodingCompatibility.cs | 25 | 84.0% | 30 | 66.7% | writer,reader,merger | writer (schema conversion/validation) + reader |
| Plank/Writing/Encoding/ValueEncodingDispatcher.cs | 29 | 75.9% | 18 | 66.7% | writer | writer |
| Plank/DefaultParquetBufferPool.cs | 199 | 83.9% | 94 | 67.0% | writer,reader,merger | NEW buffer-pool/execution-options target (nobody owns) |
| Plank/Writing/Encoding/DeltaBinaryPackedEncoding.cs | 634 | 81.4% | 235 | 68.5% | writer | writer |
| Plank/Reading/Logical/ColumnBuffer.cs | 145 | 84.8% | 74 | 68.9% | writer,reader,merger | reader |
| Plank/Reading/Logical/Internal/PhysicalSchemaBinder.cs | 282 | 79.1% | 184 | 69.0% | writer,reader,merger | reader |
| Plank/Schema/ParquetDecimalConverter.cs | 103 | 73.8% | 56 | 69.6% | writer,reader | writer (schema conversion/validation) + reader |
| Plank/Writing/BloomFilterBuilder.cs | 232 | 80.6% | 234 | 69.7% | writer,merger | writer |
| Plank/BloomFilters/SplitBlockBloomFilter.cs | 36 | 94.4% | 10 | 70.0% | writer,reader | writer (bloom options) + reader (bloom probe) |
| Plank/Reading/Logical/Internal/ColumnChunkReader.Timestamps.cs | 63 | 82.5% | 40 | 70.0% | writer,reader | reader |
| Plank/RowApi/RowGroupWriterCore.cs | 22 | 95.5% | 10 | 70.0% | writer | rowapi |
| Plank/Reading/Logical/Internal/ColumnReadBuffers.cs | 90 | 87.8% | 64 | 70.3% | writer,reader,merger | reader |
| Plank/Reading/Logical/Internal/ColumnChunkReader.EncodedBatching.cs | 1358 | 74.7% | 730 | 71.0% | writer,reader,merger | reader |
| Plank/Writing/Compression/Compression.cs | 16 | 68.8% | 7 | 71.4% | writer,merger | writer |
| Plank/Writing/PageList.cs | 31 | 87.1% | 14 | 71.4% | writer,merger | writer |
| Plank/RowApi/RowReaderWorkers.cs | 76 | 71.1% | 18 | 72.2% | writer,reader | rowapi |
| Plank/Writing/RowWriterBase.cs | 374 | 82.4% | 142 | 72.5% | writer | writer |
| Plank/RowApi/RowValueSizeEstimator.cs | 80 | 81.2% | 91 | 73.6% | writer | rowapi |
| Plank/Writing/AppendSortingOrder.cs | 94 | 89.4% | 176 | 73.9% | writer | writer |
| Plank/Reading/Physical/Internal/PhysicalMetadataThriftReader.cs | 615 | 83.6% | 360 | 73.9% | writer,reader,merger | reader |
| Plank/Writing/LatestRowGroupValues.cs | 133 | 81.2% | 107 | 74.8% | writer | writer |
| Plank/Dataset/DatasetWriterBase.cs | 457 | 78.1% | 228 | 75.0% | writer | rowapi-dataset-merger (dataset targets) |
| Plank/Reading/Logical/Internal/NestedColumnBufferEnumerable.cs | 55 | 89.1% | 12 | 75.0% | writer,reader | reader |
| Plank/Reading/Logical/Internal/PageMetadataHandle.cs | 31 | 87.1% | 12 | 75.0% | writer,reader,merger | reader |
| Plank/Reading/Logical/RowGroupCollection.cs | 26 | 84.6% | 4 | 75.0% | writer,reader,merger | reader |
| Plank/Reading/Physical/ParquetColumnChunkEncodings.cs | 11 | 81.8% | 4 | 75.0% | writer,reader,merger | reader (+ writer round trip for the matching encoder) |
| Plank/Reading/Physical/ParquetFileMetadata.cs | 93 | 100.0% | 12 | 75.0% | writer,reader,merger | reader |
| Plank/RowApi/RowApiColumnWriteStateOfT.cs | 35 | 94.3% | 12 | 75.0% | writer | rowapi |
| Plank/Schema/ParquetValueConverterOfT.cs | 55 | 80.0% | 32 | 75.0% | writer,reader | writer (schema conversion/validation) + reader |
| Plank/Writing/Encoding/DictionaryIndexEncodingDispatcher.cs | 6 | 66.7% | 4 | 75.0% | writer | writer |
| Plank/Writing/ColumnStatistics.cs | 1063 | 81.5% | 730 | 75.1% | writer,merger | writer |
| Plank/Writing/BufferWriter.cs | 189 | 87.3% | 118 | 75.4% | writer,merger | writer |
| Plank/Writing/Encoding/EncodingPrimitives.cs | 149 | 83.2% | 82 | 75.6% | writer,reader | writer |
| Plank/Writing/Encoding/ByteStreamSplitEncoding.cs | 417 | 84.7% | 146 | 76.7% | writer | writer |
| Plank/Writing/Encoding/OptionalRow.cs | 9 | 77.8% | 0 | n/a | writer | writer |
| Plank/Writing/ParquetFileMerger.cs | 79 | 92.4% | 18 | 77.8% | writer,merger | writer |
| Plank/Reading/RequiredFields.cs | 33 | 97.0% | 10 | 80.0% | writer,reader,merger | reader |
| Plank/Writing/Encoding/DeltaByteArrayEncoding.cs | 165 | 89.1% | 58 | 81.0% | writer | writer |
| Plank/RowApi/RowApiBinaryColumnReadState.cs | 45 | 97.8% | 16 | 81.2% | writer,reader | rowapi |
| Plank/Reading/Logical/ParquetReader.cs | 151 | 88.7% | 86 | 82.6% | writer,reader,merger | reader |
| Plank/Writing/Encoding/Encoding.cs | 2574 | 87.0% | 1512 | 82.6% | writer,merger | writer |
| Plank/Reading/Logical/Internal/BooleanBitUnpacker.cs | 70 | 78.6% | 30 | 83.3% | writer,reader | reader |
| Plank/Reading/ParquetSchemaEvolutionOptions.cs | 6 | 83.3% | 0 | n/a | reader | reader |
| Plank/Writing/PageStrategy/ForceDictionaryPageStrategy.cs | 6 | 83.3% | 0 | n/a | writer | writer |
| Plank/Writing/Encoding/ReusableDictionaryState.cs | 158 | 81.0% | 64 | 84.4% | writer,merger | writer |
| Plank/Writing/MutationSchemaValidator.cs | 55 | 89.1% | 58 | 84.5% | writer,merger | writer |
| Plank/RowApi/RowApiNestedColumnReadState.cs | 143 | 83.9% | 84 | 84.5% | writer,reader | rowapi |
| Plank/ParquetBuffer.cs | 77 | 92.2% | 46 | 84.8% | writer,reader,merger | NEW buffer-pool/execution-options target (nobody owns) |
| Plank/Reading/Logical/NestedRowGroupColumn.cs | 33 | 97.0% | 14 | 85.7% | writer,reader | reader |
| Plank/Reading/PageHeaderReader.cs | 136 | 94.1% | 51 | 86.3% | writer,reader,merger | reader |
| Plank/Writing/ParquetWriter.cs | 474 | 91.4% | 224 | 86.6% | writer,merger | writer |
| Plank/Schema/LeafColumn.cs | 15 | 86.7% | 0 | n/a | writer,reader,merger | writer (schema conversion/validation) + reader |
| Plank/Writing/Thrift/ParquetMetadataThriftWriter.cs | 814 | 96.4% | 303 | 87.1% | writer,merger | writer |
| Plank/Reading/Logical/Internal/StatisticsBufferBuilder.cs | 35 | 97.1% | 8 | 87.5% | writer,reader | reader (+ writer round trip for the matching encoder) |
| Plank/Reading/Logical/ParquetStatistics.cs | 13 | 92.3% | 8 | 87.5% | writer,reader | reader (+ writer round trip for the matching encoder) |
| Plank/Schema/ParquetTypeMap.cs | 57 | 80.7% | 40 | 87.5% | writer,reader,merger | writer (schema conversion/validation) + reader |
| Plank/Writing/Encoding/WyHashing.cs | 44 | 100.0% | 24 | 87.5% | writer | writer |
| Plank/Writing/SerializedColumn.cs | 1283 | 92.4% | 717 | 87.7% | writer,merger | writer |
| Plank/Schema/ColumnDefinition.cs | 204 | 81.9% | 128 | 88.3% | writer,reader,merger | writer (schema conversion/validation) + reader |
| Plank/Reading/Internal/StatisticsThriftReader.cs | 67 | 97.0% | 19 | 89.5% | writer,reader,merger | reader (+ writer round trip for the matching encoder) |
| Plank/Reading/Logical/Internal/ColumnBufferEnumerable.cs | 107 | 97.2% | 30 | 90.0% | writer,reader,merger | reader |
| Plank/Reading/PageHeaderProbe.cs | 21 | 95.2% | 10 | 90.0% | writer,reader,merger | reader |
| Plank/Writing/RowGroupWriter.cs | 231 | 96.5% | 128 | 90.6% | writer,merger | writer |
| Plank/Writing/PageStrategy/DefaultStrategy.cs | 26 | 96.2% | 22 | 90.9% | writer,merger | writer |
| Plank/Writing/Encoding/DeltaLengthByteArrayEncoding.cs | 130 | 94.6% | 56 | 91.1% | writer | writer |
| Plank/Writing/Encoding/AlpEncoding.cs | 221 | 98.2% | 86 | 91.9% | writer | writer |
| Plank/Schema/ParquetBloomFilterOptions.cs | 27 | 100.0% | 28 | 92.9% | writer | writer (schema conversion/validation) + reader |
| Plank/Schema/ParquetSchema.cs | 162 | 95.1% | 75 | 93.3% | writer,reader,merger | writer (schema conversion/validation) + reader |
| Plank/Reading/Physical/ParquetColumnSchemaInfo.cs | 16 | 93.8% | 0 | n/a | writer,reader,merger | reader |
| Plank/Reading/Physical/ParquetRowGroupInfo.cs | 16 | 93.8% | 0 | n/a | writer,reader,merger | reader |
| Plank/Reading/Logical/ParquetDataPageMetadata.cs | 17 | 94.1% | 0 | n/a | reader | reader |
| Plank/ParquetCrc32.cs | 27 | 92.6% | 19 | 94.7% | writer | writer |

## Whole files with zero covered lines

- `Plank/ParquetBufferPoolExtensions.cs` (2 lines) — owner: NEW buffer-pool/execution-options target (nobody owns)
- `Plank/ParquetWorkerContext.cs` (1 lines) — owner: NEW buffer-pool/execution-options target (nobody owns)
- `Plank/Reading/Logical/RowReaderBase.cs` (14 lines) — owner: reader
- `Plank/Reading/Lz4LegacyDecompressor.cs` (163 lines) — owner: reader
- `Plank/Reading/Physical/ParquetGeospatialStatistics.cs` (48 lines) — owner: reader (+ writer round trip for the matching encoder)
- `Plank/Schema/ParquetColumnAttribute.cs` (27 lines) — owner: writer (schema conversion/validation) + reader
- `Plank/Schema/ParquetSchemaAttribute.cs` (1 lines) — owner: writer (schema conversion/validation) + reader
- `Plank/Schema/RowSchema.cs` (10 lines) — owner: writer (schema conversion/validation) + reader
- `Plank/Schema/RowSchemaColumn.cs` (33 lines) — owner: writer (schema conversion/validation) + reader
- `Plank/Writing/Encoding/BitPackedEncoding.cs` (2 lines) — owner: writer
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/AssemblyHook.cs` (1 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4BlockDecoder.cs` (42 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4BlockEncoder.cs` (4 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4ChainDecoder.cs` (66 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4Decoder.cs` (3 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4Encoder.cs` (7 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4EncoderBase.cs` (43 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4EncoderExtensions.cs` (93 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4FastChainEncoder.cs` (9 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4HighChainEncoder.cs` (13 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/Pubternal.cs` (9 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.dec.cs` (206 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.fast.cs` (298 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.high.cs` (657 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.tools.cs` (56 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/Extensions.cs` (15 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/UnmanagedResources.cs` (16 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/x32/Mem32.cs` (20 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/LZ4Pickler.pickle.cs` (81 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise
- `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/LZ4Pickler.unpickle.cs` (72 lines) — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

## Zero-hit methods (never executed by any target), grouped by file

Compiler-generated (lambda/state machine/local-function) bodies are folded out; accessibility is read from the source declaration line (`?` = could not tell).

639 methods, 288 declared `public`.

### `Plank/obj/Release/net10.0/Plank.InternalGen/Plank.InternalGen.DeltaBinaryPackedIntegerGenerator/DeltaBinaryPackedDecoder.FastInteger.g.cs` — 72 zero-hit methods, 2012 lines — owner: writer

- L247 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW7` (?, 25 lines)
- L279 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW8` (?, 25 lines)
- L311 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW9` (?, 27 lines)
- L345 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW10` (?, 27 lines)
- L379 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW11` (?, 27 lines)
- L413 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW12` (?, 27 lines)
- L481 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW14` (?, 27 lines)
- L515 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW15` (?, 27 lines)
- L549 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW16` (?, 27 lines)
- L583 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW17` (?, 29 lines)
- L619 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW18` (?, 29 lines)
- L655 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW19` (?, 29 lines)
- L691 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW20` (?, 29 lines)
- L727 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW21` (?, 29 lines)
- L763 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW22` (?, 29 lines)
- L799 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW23` (?, 29 lines)
- L835 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW24` (?, 29 lines)
- L871 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW25` (?, 31 lines)
- L909 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW26` (?, 31 lines)
- L947 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW27` (?, 31 lines)
- L985 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW28` (?, 31 lines)
- L1023 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW29` (?, 31 lines)
- L1061 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW30` (?, 31 lines)
- L1099 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW31` (?, 31 lines)
- L1137 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockFastW32` (?, 31 lines)
- L1176 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFast` (?, 33 lines)
- L1216 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW1` (?, 25 lines)
- L1248 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW2` (?, 25 lines)
- L1280 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW3` (?, 25 lines)
- L1312 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW4` (?, 25 lines)
- L1344 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW5` (?, 25 lines)
- L1376 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW6` (?, 25 lines)
- L1408 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW7` (?, 25 lines)
- L1440 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW8` (?, 25 lines)
- L1472 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW9` (?, 27 lines)
- L1506 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW10` (?, 27 lines)
- L1540 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW11` (?, 27 lines)
- L1574 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW12` (?, 27 lines)
- L1608 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW13` (?, 27 lines)
- L1642 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW14` (?, 27 lines)
- L1676 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW15` (?, 27 lines)
- L1710 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW16` (?, 27 lines)
- L1744 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW17` (?, 29 lines)
- L1780 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW18` (?, 29 lines)
- L1816 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW19` (?, 29 lines)
- L1852 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW20` (?, 29 lines)
- L1888 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW21` (?, 29 lines)
- L1924 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW22` (?, 29 lines)
- L1960 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW23` (?, 29 lines)
- L1996 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW24` (?, 29 lines)
- L2032 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW25` (?, 31 lines)
- L2070 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW26` (?, 31 lines)
- L2108 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW27` (?, 31 lines)
- L2146 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW28` (?, 31 lines)
- L2184 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW29` (?, 31 lines)
- L2222 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW30` (?, 31 lines)
- L2260 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW31` (?, 31 lines)
- L2298 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockFastW32` (?, 31 lines)
- L2393 `DeltaBinaryPackedDecoder.DecodeInt64MiniBlockFastW2` (?, 25 lines)
- L2425 `DeltaBinaryPackedDecoder.DecodeInt64MiniBlockFastW3` (?, 25 lines)
- … 12 more

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.high.cs` — 19 zero-hit methods, 657 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L48 `LL32.LZ4HC_countPattern` (public, 14 lines)
- L93 `LL32.LZ4HC_InsertAndGetWiderMatch` (?, 167 lines)
- L401 `LL32.LZ4HC_InsertAndFindBestMatch` (public, 4 lines)
- L419 `LL32.LZ4HC_FindLongerMatch` (public, 14 lines)
- L453 `LL32.LZ4HC_encodeSequence` (public, 31 lines)
- L530 `LL32.LZ4HC_compress_hashChain` (public, 145 lines)
- L825 `LL32.LZ4HC_compress_optimal` (?, 162 lines)
- L1131 `LL32..cctor` (?, 15 lines)
- L1158 `LL32.LZ4HC_compress_generic_internal` (public, 26 lines)
- L1208 `LL32.LZ4HC_compress_generic_noDictCtx` (public, 2 lines)
- L1221 `LL32.LZ4HC_compress_generic_dictCtx` (public, 14 lines)
- L1254 `LL32.LZ4HC_compress_generic` (public, 5 lines)
- L1272 `LL32.LZ4_compressHC_continue_generic` (public, 18 lines)
- L1310 `LL32.LZ4_compress_HC_continue` (public, 7 lines)
- L1324 `LL32.LZ4_compress_HC_continue_destSize` (public, 3 lines)
- L1333 `LL32.LZ4_compress_HC_destSize` (public, 7 lines)
- L1347 `LL32.LZ4_compress_HC_extStateHC_fastReset` (public, 12 lines)
- L1367 `LL32.LZ4_compress_HC_extStateHC` (public, 4 lines)
- L1377 `LL32.LZ4_compress_HC` (public, 7 lines)

### `Plank/Reading/Logical/Internal/ColumnChunkReader.cs` — 31 zero-hit methods, 484 lines — owner: reader

- L267 `ColumnChunkReader.FormatLevelEncoding` (?, 1 lines)
- L351 `ColumnChunkReader.TryStartFixedWidthPageBatches` (internal, 2 lines)
- L644 `ColumnChunkReader.ValidateEmptyTimestampProjection` (?, 8 lines)
- L914 `ColumnChunkReader.DecodeAllPresentPlainInt32BatchForTesting` (internal, 2 lines)
- L970 `ColumnChunkReader.ExpandAllPresentDateTimeBatch` (?, 26 lines)
- L1125 `ColumnChunkReader.ScatterNullableDoubleBatchForTesting` (internal, 1 lines)
- L1129 `ColumnChunkReader.ScatterNullableInt64BatchForTesting` (internal, 1 lines)
- L1323 `ColumnChunkReader.TryDecodeNullablePageIntoNative` (internal, 2 lines)
- L1470 `ColumnChunkReader.ExpandAllPresentInt64BatchForTesting` (internal, 1 lines)
- L1702 `ColumnChunkReader.TryDecodeRequiredPageIntoNative` (internal, 2 lines)
- L1809 `ColumnChunkReader.TryDecodeConvertedRequiredByPhysicalType` (?, 44 lines)
- L1861 `ColumnChunkReader.TryDecodeConvertedRequired` (?, 15 lines)
- L2165 `ColumnChunkReader.DecodeBorrowedPlainBinaryValues` (?, 5 lines)
- L2175 `ColumnChunkReader.FillBorrowedPlainByteArrayDescriptors` (?, 21 lines)
- L2204 `ColumnChunkReader.DecodeByteStreamSplitBinaryValues` (?, 16 lines)
- L2228 `ColumnChunkReader.DecodeDeltaLengthBinaryValues` (?, 29 lines)
- L2268 `ColumnChunkReader.DecodeDeltaBinaryValues` (?, 54 lines)
- L2551 `ColumnChunkReader.TryDecodeDeltaByteArrayIntoNative` (?, 37 lines)
- L2934 `ColumnChunkReader.TryDecodeDeltaBinaryPackedIntoNative` (?, 70 lines)
- L3210 `ColumnChunkReader.DecodeByteStreamSplitInt32` (?, 1 lines)
- L3720 `ColumnChunkReader.LoadLowerUInt32` (?, 1 lines)
- L3724 `ColumnChunkReader.DecodeByteStreamSplitFloat` (?, 3 lines)
- L3730 `ColumnChunkReader.DecodeByteStreamSplitDouble` (?, 3 lines)
- L4084 `ColumnChunkReader.DecodeDictionaryLiteralInt64Indexes11Bit` (?, 18 lines)
- L4113 `ColumnChunkReader.GetRepeatedDictionaryBlockCount` (?, 11 lines)
- L4130 `ColumnChunkReader.RepeatDictionaryValues` (?, 7 lines)
- L4144 `ColumnChunkReader.DecodeDictionaryLiteralInt64Indexes11BitCore` (?, 27 lines)
- L4182 `ColumnChunkReader.DecodeDictionaryLiteralInt64IndexesWide` (?, 31 lines)
- L4228 `ColumnChunkReader.DecodeDictionaryLiteralInt64IndexesWideScalar` (?, 31 lines)
- L4274 `ColumnChunkReader.GatherDictionaryInt64` (?, 8 lines)
- L4289 `ColumnChunkReader.GatherDictionaryInt64Scalar` (?, 6 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.fast.cs` — 5 zero-hit methods, 298 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L56 `LL32.LZ4_compress_generic` (?, 218 lines)
- L528 `LL32.LZ4_compress_fast_extState` (public, 31 lines)
- L581 `LL32.LZ4_compress_fast` (public, 2 lines)
- L587 `LL32.LZ4_compress_default` (public, 1 lines)
- L596 `LL32.LZ4_compress_fast_continue` (public, 46 lines)

### `Plank/Reading/Logical/Internal/DeltaBinaryPackedDecoder.cs` — 31 zero-hit methods, 280 lines — owner: reader (+ writer round trip for the matching encoder)

- L44 `DeltaBinaryPackedDecoder.NextBatchCount` (internal, 7 lines)
- L269 `DeltaBinaryPackedDecoder.ReadInt32` (internal, 2 lines)
- L275 `DeltaBinaryPackedDecoder.ReadInt64` (internal, 2 lines)
- L280 `DeltaBinaryPackedDecoder.ReadInt32` (internal, 1 lines)
- L284 `DeltaBinaryPackedDecoder.ReadNullableInt32` (internal, 1 lines)
- L288 `DeltaBinaryPackedDecoder.ReadNarrowInt32` (internal, 1 lines)
- L291 `DeltaBinaryPackedDecoder.ReadInt64` (internal, 1 lines)
- L295 `DeltaBinaryPackedDecoder.ReadNonNegativeInt32WithConsumedBytes` (internal, 5 lines)
- L304 `DeltaBinaryPackedDecoder.ReadUInt32WithConsumedBytes` (internal, 8 lines)
- L318 `DeltaBinaryPackedDecoder.ReadInt32Core` (?, 13 lines)
- L341 `DeltaBinaryPackedDecoder.ReadInt32Core` (?, 11 lines)
- L362 `DeltaBinaryPackedDecoder.ReadNullableInt32Core` (?, 11 lines)
- L386 `DeltaBinaryPackedDecoder.ReadInt32Values` (?, 4 lines)
- L454 `DeltaBinaryPackedDecoder.ReadNullableInt32Values` (?, 5 lines)
- L518 `DeltaBinaryPackedDecoder..cctor` (?, 1 lines)
- L522 `DeltaBinaryPackedDecoder.Create` (internal, 12 lines)
- L545 `DeltaBinaryPackedDecoder.UnpackEightAvx2` (?, 4 lines)
- L557 `DeltaBinaryPackedDecoder.DecodeInt32MiniBlockAvx2` (internal, 9 lines)
- L573 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockAvx2` (internal, 9 lines)
- L589 `DeltaBinaryPackedDecoder.DecodeInt64MiniBlockAvx2` (internal, 22 lines)
- L660 `DeltaBinaryPackedDecoder.DecodeNullableInt32MiniBlockBmi2` (?, 22 lines)
- L705 `DeltaBinaryPackedDecoder.ReconstructEightNullableInt32` (?, 11 lines)
- L722 `DeltaBinaryPackedDecoder.ReconstructEightNullableInt32` (?, 9 lines)
- L1029 `DeltaBinaryPackedDecoder.ReadPackedWordBmi2` (?, 7 lines)
- L1044 `DeltaBinaryPackedDecoder.ReadNarrowInt32Core` (?, 32 lines)
- L1096 `DeltaBinaryPackedDecoder.ReadInt64Core` (?, 13 lines)
- L1119 `DeltaBinaryPackedDecoder.ReadInt64Core` (?, 11 lines)
- L1140 `DeltaBinaryPackedDecoder.ReadInt64Values` (?, 4 lines)
- L1299 `DeltaBinaryPackedDecoder.ReconstructEightInt64` (?, 8 lines)
- L1321 `DeltaBinaryPackedDecoder.DecodeConstantInt64DeltaBlock` (?, 29 lines)
- L1486 `DeltaBinaryPackedDecoder.StoreNarrowInt32` (?, 5 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.dec.cs` — 10 zero-hit methods, 206 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L119 `LL32.LZ4_decompress_generic` (?, 9 lines)
- L143 `LL32.LZ4_decompress_generic` (?, 129 lines)
- L481 `LL32.LZ4_decompress_safe` (public, 5 lines)
- L491 `LL32.LZ4_decompress_safe_withPrefix64k` (public, 5 lines)
- L502 `LL32.LZ4_decompress_safe_withSmallPrefix` (public, 5 lines)
- L513 `LL32.LZ4_decompress_safe_doubleDict` (public, 5 lines)
- L525 `LL32.LZ4_decompress_safe_forceExtDict` (public, 5 lines)
- L536 `LL32.LZ4_decompress_safe_usingDict` (public, 10 lines)
- L560 `LL32.LZ4_decompress_safe_partial` (public, 5 lines)
- L571 `LL32.LZ4_decompress_safe_continue` (public, 28 lines)

### `Plank/Reading/Lz4LegacyDecompressor.cs` — 9 zero-hit methods, 163 lines — owner: reader

- L16 `Lz4LegacyDecompressor.Decompress` (internal, 5 lines)
- L25 `Lz4LegacyDecompressor.DecompressFrames` (?, 14 lines)
- L49 `Lz4LegacyDecompressor.DecompressFrame` (?, 84 lines)
- L160 `Lz4LegacyDecompressor.TryDecompressHadoop` (?, 19 lines)
- L188 `Lz4LegacyDecompressor.TryReadHadoopBlock` (?, 21 lines)
- L223 `Lz4LegacyDecompressor.DecodeBlock` (?, 6 lines)
- L235 `Lz4LegacyDecompressor.StartsWithFrame` (?, 4 lines)
- L243 `Lz4LegacyDecompressor.SkipFrame` (?, 7 lines)
- L253 `Lz4LegacyDecompressor.EnsureAvailable` (?, 3 lines)

### `Plank/Writing/ColumnStatistics.cs` — 12 zero-hit methods, 106 lines — owner: writer

- L247 `ColumnStatistics.CreateOptional` (internal, 3 lines)
- L619 `ColumnStatistics.CreateDecimal` (?, 7 lines)
- L646 `ColumnStatistics.CreateNullableDecimal` (?, 7 lines)
- L756 `ColumnStatistics.CreateByteArray` (?, 11 lines)
- L797 `ColumnStatistics.CreateOptionalByteArray` (?, 17 lines)
- L865 `ColumnStatistics.CreateMemory` (?, 11 lines)
- L906 `ColumnStatistics.CreateNullableMemory` (?, 17 lines)
- L1478 `ColumnStatistics.CountNulls` (?, 5 lines)
- L1837 `ColumnStatistics.ToUnixTimeForStatistics` (?, 7 lines)
- L1849 `ColumnStatistics.ToUnixTimeForStatistics` (?, 9 lines)
- L1862 `ColumnStatistics.ToUnixTimeOffsetForStatistics` (?, 4 lines)
- L1871 `ColumnStatistics.ToTimeValueForStatistics` (?, 8 lines)

### `Plank/Writing/Encoding/PlainEncoding.cs` — 7 zero-hit methods, 106 lines — owner: writer

- L167 `PlainEncoding.WriteByteValuesAsUInt32` (?, 34 lines)
- L215 `PlainEncoding.WriteUInt16ValuesAsUInt32` (?, 34 lines)
- L553 `PlainEncoding.ExtractOptionalDoubleValuesAdvSimd` (?, 12 lines)
- L1336 `PlainEncoding.WriteInt32PageWithVector128Statistics` (internal, 12 lines)
- L1362 `PlainEncoding.WriteInt64PageWithVector128Statistics` (internal, 12 lines)
- L1387 `PlainEncoding.CanUseInt32Vector128` (internal, 1 lines)
- L1391 `PlainEncoding.CanUseInt64Vector128` (internal, 1 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x64/LL64.high.cs` — 7 zero-hit methods, 95 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L41 `LL64.LZ4HC_countPattern` (public, 15 lines)
- L446 `LL64.LZ4HC_encodeSequence` (public, 31 lines)
- L1214 `LL64.LZ4HC_compress_generic_dictCtx` (public, 14 lines)
- L1265 `LL64.LZ4_compressHC_continue_generic` (public, 18 lines)
- L1303 `LL64.LZ4_compress_HC_continue` (public, 7 lines)
- L1317 `LL64.LZ4_compress_HC_continue_destSize` (public, 3 lines)
- L1326 `LL64.LZ4_compress_HC_destSize` (public, 7 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4EncoderExtensions.cs` — 20 zero-hit methods, 93 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L19 `LZ4EncoderExtensions.Topup` (public, 3 lines)
- L33 `LZ4EncoderExtensions.Topup` (public, 2 lines)
- L47 `LZ4EncoderExtensions.Topup` (public, 3 lines)
- L62 `LZ4EncoderExtensions.Encode` (public, 2 lines)
- L78 `LZ4EncoderExtensions.Encode` (public, 6 lines)
- L97 `LZ4EncoderExtensions.Encode` (public, 6 lines)
- L124 `LZ4EncoderExtensions.TopupAndEncode` (public, 6 lines)
- L155 `LZ4EncoderExtensions.TopupAndEncode` (public, 7 lines)
- L181 `LZ4EncoderExtensions.TopupAndEncode` (public, 7 lines)
- L196 `LZ4EncoderExtensions.FlushAndEncode` (private, 10 lines)
- L225 `LZ4EncoderExtensions.FlushAndEncode` (public, 1 lines)
- L242 `LZ4EncoderExtensions.FlushAndEncode` (public, 4 lines)
- L259 `LZ4EncoderExtensions.FlushAndEncode` (public, 4 lines)
- L277 `LZ4EncoderExtensions.Drain` (public, 3 lines)
- L292 `LZ4EncoderExtensions.Drain` (public, 3 lines)
- L310 `LZ4EncoderExtensions.DecodeAndDrain` (public, 8 lines)
- L340 `LZ4EncoderExtensions.DecodeAndDrain` (public, 8 lines)
- L362 `LZ4EncoderExtensions.DecodeAndDrain` (public, 6 lines)
- L383 `LZ4EncoderExtensions.Inject` (public, 2 lines)
- L401 `LZ4EncoderExtensions.Decode` (public, 2 lines)

### `Plank/Writing/MinMaxScan.cs` — 2 zero-hit methods, 89 lines — owner: writer

- L202 `MinMaxScan.ComputeVector128Bulk` (internal, 36 lines)
- L253 `MinMaxScan.CopyAndComputeVector128Bulk` (internal, 53 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/LZ4Pickler.pickle.cs` — 19 zero-hit methods, 81 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L25 `LZ4Pickler.Pickle` (public, 1 lines)
- L36 `LZ4Pickler.Pickle` (public, 1 lines)
- L45 `LZ4Pickler.Pickle` (public, 1 lines)
- L54 `LZ4Pickler.Pickle` (public, 10 lines)
- L80 `LZ4Pickler.PickleWithBuffer` (private, 16 lines)
- L118 `LZ4Pickler.Pickle` (public, 16 lines)
- L158 `LZ4Pickler.Pickle` (public, 1 lines)
- L162 `LZ4Pickler.GetPessimisticHeaderSize` (private, 4 lines)
- L169 `LZ4Pickler.GetUncompressedHeaderSize` (private, 4 lines)
- L176 `LZ4Pickler.GetCompressedHeaderSize` (private, 4 lines)
- L184 `LZ4Pickler.EncodeUncompressedHeader` (private, 4 lines)
- L192 `LZ4Pickler.EncodeUncompressedHeaderV0` (private, 2 lines)
- L198 `LZ4Pickler.EncodeCompressedHeader` (private, 4 lines)
- L206 `LZ4Pickler.EncodeCompressedHeaderV0` (private, 5 lines)
- L216 `LZ4Pickler.PokeN` (private, 4 lines)
- L222 `LZ4Pickler.EncodeHeaderByteV0` (private, 1 lines)
- L225 `LZ4Pickler.EffectiveSizeOf` (private, 1 lines)
- L228 `LZ4Pickler.EncodeSizeOf` (private, 1 lines)
- L231 `LZ4Pickler.UnexpectedVersion` (private, 1 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/LZ4Pickler.unpickle.cs` — 19 zero-hit methods, 72 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L19 `LZ4Pickler.Unpickle` (public, 1 lines)
- L27 `LZ4Pickler.Unpickle` (public, 1 lines)
- L34 `LZ4Pickler.Unpickle` (public, 1 lines)
- L41 `LZ4Pickler.Unpickle` (public, 7 lines)
- L59 `LZ4Pickler.Unpickle` (public, 9 lines)
- L76 `LZ4Pickler.Unpickle` (public, 1 lines)
- L84 `LZ4Pickler.UnpickledSize` (public, 1 lines)
- L92 `LZ4Pickler.UnpickledSize` (private, 1 lines)
- L102 `LZ4Pickler.Unpickle` (public, 5 lines)
- L112 `LZ4Pickler.UnpickleCore` (private, 14 lines)
- L132 `LZ4Pickler.DecodeHeader` (private, 4 lines)
- L139 `LZ4Pickler.DecodeHeaderV0` (private, 9 lines)
- L152 `LZ4Pickler.PeekN` (private, 6 lines)
- L161 `LZ4Pickler.CorruptedPickle` (private, 1 lines)
- L167 `PickleHeader.get_DataOffset` (public, 1 lines)
- L168 `PickleHeader.get_Flags` (public, 1 lines)
- L169 `PickleHeader.get_ResultLength` (public, 1 lines)
- L170 `PickleHeader.get_IsCompressed` (public, 1 lines)
- L174 `PickleHeader..ctor` (public, 7 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/LL.high.cs` — 12 zero-hit methods, 70 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L20 `LL.LZ4_sizeofStateHC` (public, 1 lines)
- L32 `LL.LZ4_favorDecompressionSpeed` (public, 2 lines)
- L126 `LL.LZ4HC_setExternalDict` (public, 11 lines)
- L171 `LL.LZ4_saveDictHC` (public, 14 lines)
- L189 `LL.LZ4_loadDictHC` (public, 11 lines)
- L210 `LL.LZ4HC_rotl32` (public, 1 lines)
- L214 `LL.LZ4HC_protectDictEnd` (public, 1 lines)
- L219 `LL.LZ4HC_countBack` (public, 6 lines)
- L235 `LL.LZ4HC_reverseCountPattern` (public, 10 lines)
- L260 `LL.LZ4HC_rotatePattern` (public, 4 lines)
- L269 `LL.LZ4HC_literalsPrice` (public, 4 lines)
- L279 `LL.LZ4HC_sequencePrice` (public, 5 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4ChainDecoder.cs` — 14 zero-hit methods, 66 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L20 `LZ4ChainDecoder.get_OutputBuffer` (private, 1 lines)
- L21 `LZ4ChainDecoder.get_Context` (private, 1 lines)
- L26 `LZ4ChainDecoder..ctor` (public, 9 lines)
- L39 `LZ4ChainDecoder.get_BlockSize` (public, 1 lines)
- L42 `LZ4ChainDecoder.get_BytesReady` (public, 1 lines)
- L47 `LZ4ChainDecoder.Decode` (public, 9 lines)
- L66 `LZ4ChainDecoder.Inject` (public, 16 lines)
- L98 `LZ4ChainDecoder.Drain` (public, 5 lines)
- L108 `LZ4ChainDecoder.Peek` (public, 5 lines)
- L119 `LZ4ChainDecoder.Prepare` (private, 4 lines)
- L127 `LZ4ChainDecoder.CopyDict` (private, 5 lines)
- L136 `LZ4ChainDecoder.ApplyDict` (private, 4 lines)
- L143 `LZ4ChainDecoder.DecodeBlock` (private, 1 lines)
- L148 `LZ4ChainDecoder.ReleaseUnmanaged` (protected, 4 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x64/LL64.dec.cs` — 7 zero-hit methods, 63 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L484 `LL64.LZ4_decompress_safe_withPrefix64k` (public, 5 lines)
- L495 `LL64.LZ4_decompress_safe_withSmallPrefix` (public, 5 lines)
- L506 `LL64.LZ4_decompress_safe_doubleDict` (public, 5 lines)
- L518 `LL64.LZ4_decompress_safe_forceExtDict` (public, 5 lines)
- L529 `LL64.LZ4_decompress_safe_usingDict` (public, 10 lines)
- L553 `LL64.LZ4_decompress_safe_partial` (public, 5 lines)
- L564 `LL64.LZ4_decompress_safe_continue` (public, 28 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/LZ4Codec.cs` — 9 zero-hit methods, 56 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L23 `LZ4Codec.get_Enforce32` (public, 1 lines)
- L24 `LZ4Codec.set_Enforce32` (public, 1 lines)
- L87 `LZ4Codec.Encode` (public, 8 lines)
- L127 `LZ4Codec.PartialDecode` (public, 5 lines)
- L149 `LZ4Codec.Decode` (public, 6 lines)
- L166 `LZ4Codec.PartialDecode` (public, 6 lines)
- L201 `LZ4Codec.Decode` (public, 12 lines)
- L229 `LZ4Codec.Decode` (public, 7 lines)
- L255 `LZ4Codec.Decode` (public, 10 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x32/LL32.tools.cs` — 8 zero-hit methods, 56 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L44 `LL32..cctor` (?, 7 lines)
- L56 `LL32.LZ4_NbCommonBytes` (protected, 1 lines)
- L98 `LL32.LZ4_count` (protected, 19 lines)
- L149 `LL32.LZ4_hashPosition` (protected, 1 lines)
- L155 `LL32.LZ4_putPosition` (protected, 1 lines)
- L160 `LL32.LZ4_getPosition` (protected, 1 lines)
- L167 `LL32.LZ4_renormDictT` (protected, 10 lines)
- L185 `LL32.LZ4_loadDict` (public, 16 lines)

### `Plank/Reading/Physical/ParquetGeospatialStatistics.cs` — 14 zero-hit methods, 48 lines — owner: reader (+ writer round trip for the matching encoder)

- L6 `ParquetGeospatialStatistics..ctor` (internal, 4 lines)
- L12 `ParquetGeospatialStatistics.get_BoundingBox` (public, 1 lines)
- L15 `ParquetGeospatialStatistics.get_GeospatialTypes` (public, 1 lines)
- L19 `ParquetGeospatialStatistics.Read` (internal, 17 lines)
- L48 `ParquetBoundingBox..ctor` (internal, 5 lines)
- L55 `ParquetBoundingBox.get_XMin` (public, 1 lines)
- L56 `ParquetBoundingBox.get_XMax` (public, 1 lines)
- L57 `ParquetBoundingBox.get_YMin` (public, 1 lines)
- L58 `ParquetBoundingBox.get_YMax` (public, 1 lines)
- L59 `ParquetBoundingBox.get_ZMin` (public, 1 lines)
- L60 `ParquetBoundingBox.get_ZMax` (public, 1 lines)
- L61 `ParquetBoundingBox.get_MMin` (public, 1 lines)
- L62 `ParquetBoundingBox.get_MMax` (public, 1 lines)
- L66 `ParquetBoundingBox.Read` (internal, 12 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x64/LL64.fast.cs` — 2 zero-hit methods, 47 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L580 `LL64.LZ4_compress_default` (public, 1 lines)
- L589 `LL64.LZ4_compress_fast_continue` (public, 46 lines)

### `Plank/Reading/Physical/ParquetPageCursor.cs` — 4 zero-hit methods, 47 lines — owner: reader

- L56 `ParquetPageCursor..ctor` (internal, 6 lines)
- L90 `ParquetPageCursor.GetEnumerator` (public, 1 lines)
- L112 `ParquetPageCursor.MoveNextPruned` (?, 35 lines)
- L330 `ParquetPageCursor.VerifyPageCrc` (?, 5 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4EncoderBase.cs` — 8 zero-hit methods, 43 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L21 `LZ4EncoderBase.get_InputBuffer` (private, 1 lines)
- L27 `LZ4EncoderBase..ctor` (protected, 9 lines)
- L40 `LZ4EncoderBase.get_BlockSize` (public, 1 lines)
- L43 `LZ4EncoderBase.get_BytesReady` (public, 1 lines)
- L48 `LZ4EncoderBase.Topup` (public, 10 lines)
- L67 `LZ4EncoderBase.Encode` (public, 13 lines)
- L92 `LZ4EncoderBase.Commit` (private, 5 lines)
- L117 `LZ4EncoderBase.ReleaseUnmanaged` (protected, 3 lines)

### `Plank/Reading/Logical/Internal/ColumnChunkReader.DictionaryPortable.cs` — 1 zero-hit methods, 43 lines — owner: reader (+ writer round trip for the matching encoder)

- L16 `ColumnChunkReader.DecodeNullableInt32DictionaryNineBitPortable` (?, 43 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4BlockDecoder.cs` — 9 zero-hit methods, 42 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L19 `LZ4BlockDecoder.get_OutputBuffer` (private, 1 lines)
- L23 `LZ4BlockDecoder..ctor` (public, 7 lines)
- L33 `LZ4BlockDecoder.get_BlockSize` (public, 1 lines)
- L36 `LZ4BlockDecoder.get_BytesReady` (public, 1 lines)
- L41 `LZ4BlockDecoder.Decode` (public, 10 lines)
- L60 `LZ4BlockDecoder.Inject` (public, 8 lines)
- L76 `LZ4BlockDecoder.Drain` (public, 6 lines)
- L88 `LZ4BlockDecoder.Peek` (public, 5 lines)
- L100 `LZ4BlockDecoder.ReleaseUnmanaged` (protected, 3 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/LLxx.cs` — 6 zero-hit methods, 40 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L15 `LLxx.AlgorithmNotImplemented` (private, 1 lines)
- L33 `LLxx.LZ4_decompress_safe_partial` (public, 7 lines)
- L45 `LLxx.LZ4_decompress_safe_usingDict` (public, 7 lines)
- L57 `LLxx.LZ4_decompress_safe_continue` (public, 7 lines)
- L82 `LLxx.LZ4_compress_fast_continue` (public, 11 lines)
- L109 `LLxx.LZ4_compress_HC_continue` (public, 7 lines)

### `Plank/RowApi/RowReaderCore.cs` — 3 zero-hit methods, 39 lines — owner: rowapi

- L168 `RowReaderCore.Reset` (public, 15 lines)
- L196 `RowReaderCore.Reset` (public, 6 lines)
- L206 `RowReaderCore.ResetCore` (?, 18 lines)

### `Plank/Dataset/DatasetWriterBase.cs` — 3 zero-hit methods, 39 lines — owner: rowapi-dataset-merger (dataset targets)

- L670 `DatasetWriterBase`1.TryReleaseAfterFailure` (?, 6 lines)
- L680 `DatasetWriterBase`1.ReleaseAfterFailure` (?, 16 lines)
- L706 `DatasetWriterBase`1.DiscardPendingPartition` (?, 17 lines)

### `Plank/Reading/Logical/Internal/ColumnChunkReader.EncodedBatching.cs` — 3 zero-hit methods, 38 lines — owner: reader

- L1260 `ColumnChunkReader.StoreNullableInt64Values` (?, 7 lines)
- L1294 `ColumnChunkReader.DecodeNullableInt32DictionaryNineBit` (?, 18 lines)
- L1321 `ColumnChunkReader.DecodeNullableInt32DictionaryBytes` (?, 13 lines)

### `Plank/Writing/Encoding/DeltaBinaryPackedEncoding.cs` — 4 zero-hit methods, 33 lines — owner: writer

- L406 `DeltaBinaryPackedEncoding.GetMinimum` (?, 3 lines)
- L872 `DeltaBinaryPackedEncoding.NormalizeDeltasVectorized` (?, 15 lines)
- L974 `DeltaBinaryPackedEncoding.CombineBits` (?, 1 lines)
- L978 `DeltaBinaryPackedEncoding.WritePackedUnsignedValues` (internal, 14 lines)

### `Plank/Schema/RowSchemaColumn.cs` — 12 zero-hit methods, 33 lines — owner: writer (schema conversion/validation) + reader

- L9 `RowSchemaColumn..ctor` (public, 2 lines)
- L16 `RowSchemaColumn..ctor` (public, 2 lines)
- L20 `RowSchemaColumn..ctor` (public, 17 lines)
- L39 `RowSchemaColumn.get_Name` (public, 1 lines)
- L41 `RowSchemaColumn.get_PhysicalType` (public, 1 lines)
- L43 `RowSchemaColumn.get_ClrType` (public, 1 lines)
- L45 `RowSchemaColumn.get_Options` (public, 1 lines)
- L47 `RowSchemaColumn.get_LogicalType` (public, 1 lines)
- L49 `RowSchemaColumn.get_PageStrategy` (public, 1 lines)
- L52 `RowSchemaColumn.get_Converter` (public, 1 lines)
- L54 `RowSchemaColumn.get_FieldId` (public, 1 lines)
- L57 `RowSchemaColumn.ToDefinition` (internal, 4 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/LL.tools.cs` — 11 zero-hit methods, 32 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L27 `LL.Assert` (public, 1 lines)
- L44 `LL.LZ4_decoderRingBufferSize` (internal, 1 lines)
- L56 `LL.LZ4_hash5` (protected, 2 lines)
- L66 `LL.LZ4_clearHash` (protected, 6 lines)
- L144 `LL.LZ4_getPositionOnHash` (protected, 3 lines)
- L154 `LL.MIN` (public, 1 lines)
- L157 `LL.MAX` (public, 1 lines)
- L160 `LL.MAX` (public, 1 lines)
- L163 `LL.MIN` (public, 1 lines)
- L197 `LL.LZ4_saveDict` (public, 9 lines)
- L244 `LL.LZ4_setStreamDecode` (public, 6 lines)

### `Plank/Reading/Logical/Internal/PageMetadataReader.cs` — 2 zero-hit methods, 32 lines — owner: reader

- L335 `PageMetadataReader.PopulateHeaderStatistics` (?, 15 lines)
- L397 `PageMetadataReader.ValidateLocationGap` (?, 17 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/x64/LL64.tools.cs` — 3 zero-hit methods, 27 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L153 `LL64.LZ4_getPosition` (protected, 1 lines)
- L160 `LL64.LZ4_renormDictT` (protected, 10 lines)
- L178 `LL64.LZ4_loadDict` (public, 16 lines)

### `Plank/Schema/ParquetColumnAttribute.cs` — 19 zero-hit methods, 27 lines — owner: writer (schema conversion/validation) + reader

- L6 `ParquetColumnAttribute..ctor` (public, 1 lines)
- L8 `ParquetColumnAttribute..ctor` (public, 2 lines)
- L11 `ParquetColumnAttribute..ctor` (public, 4 lines)
- L17 `ParquetColumnAttribute..ctor` (public, 5 lines)
- L24 `ParquetColumnAttribute.get_Name` (public, 1 lines)
- L26 `ParquetColumnAttribute.get_PhysicalType` (public, 1 lines)
- L28 `ParquetColumnAttribute.get_HasPhysicalType` (public, 1 lines)
- L30 `ParquetColumnAttribute.get_Encodings` (public, 1 lines)
- L33 `ParquetColumnAttribute.get_Compression` (public, 1 lines)
- L36 `ParquetColumnAttribute.get_CompressionLevel` (public, 1 lines)
- L38 `ParquetColumnAttribute.get_LogicalType` (public, 1 lines)
- L40 `ParquetColumnAttribute.get_FieldId` (public, 1 lines)
- L42 `ParquetColumnAttribute.get_Precision` (public, 1 lines)
- L44 `ParquetColumnAttribute.get_Scale` (public, 1 lines)
- L47 `ParquetColumnAttribute.get_Converter` (public, 1 lines)
- L50 `ParquetColumnAttribute.get_BloomFilter` (public, 1 lines)
- L53 `ParquetColumnAttribute.get_BloomFilterFalsePositiveProbability` (public, 1 lines)
- L56 `ParquetColumnAttribute.get_BloomFilterExpectedDistinctValueCount` (public, 1 lines)
- L59 `ParquetColumnAttribute.get_BloomFilterMaximumBytes` (public, 1 lines)

### `Plank/Writing/Encoding/RleBitPackingHybridEncoding.cs` — 3 zero-hit methods, 25 lines — owner: writer

- L18 `RleBitPackingHybridEncoding.WriteWithBitWidthPrefix` (internal, 3 lines)
- L25 `RleBitPackingHybridEncoding.Write` (internal, 3 lines)
- L36 `RleBitPackingHybridEncoding.ValidateValues` (?, 19 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/x32/Mem32.cs` — 6 zero-hit methods, 20 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L94 `Mem32.PeekW` (public, 1 lines)
- L100 `Mem32.PokeW` (public, 1 lines)
- L124 `Mem32.Copy16` (public, 3 lines)
- L134 `Mem32.Copy18` (public, 4 lines)
- L152 `Mem32.WildCopy8` (public, 5 lines)
- L174 `Mem32.WildCopy32` (public, 6 lines)

### `Plank/Writing/Encoding/Encoding.cs` — 6 zero-hit methods, 20 lines — owner: writer

- L3398 `Encoding.MeasureByteArrayPageRows` (?, 7 lines)
- L3768 `Encoding.WriteBooleanDictionaryPage` (?, 9 lines)
- L4324 `Encoding.GetHashCode` (public, 1 lines)
- L4334 `Encoding.GetHashCode` (public, 1 lines)
- L4412 `Encoding.Write` (public, 1 lines)
- L4418 `Encoding.Write` (public, 1 lines)

### `Plank/Writing/Encoding/ReusableDictionaryState.cs` — 1 zero-hit methods, 19 lines — owner: writer

- L175 `ReusableDictionaryState`1.Resize` (?, 19 lines)

### `Plank/Reading/Logical/Internal/AlpDecoder.cs` — 5 zero-hit methods, 19 lines — owner: reader (+ writer round trip for the matching encoder)

- L20 `AlpDecoder.get_Active` (internal, 1 lines)
- L24 `AlpDecoder.NextBatchCount` (internal, 5 lines)
- L35 `AlpDecoder.TryDecode` (internal, 7 lines)
- L79 `AlpDecoder.DecodeFloatPage` (?, 3 lines)
- L85 `AlpDecoder.DecodeDoublePage` (?, 3 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/PinnedMemory.cs` — 7 zero-hit methods, 18 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L29 `PinnedMemory.get_Pointer` (public, 1 lines)
- L36 `PinnedMemory.get_Span` (public, 1 lines)
- L52 `PinnedMemory.Alloc` (public, 2 lines)
- L87 `PinnedMemory.Alloc` (public, 2 lines)
- L92 `PinnedMemory.AllocateNative` (private, 6 lines)
- L114 `PinnedMemory.Clear` (public, 3 lines)
- L146 `PinnedMemory.ReleaseNative` (private, 3 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/Mem.cs` — 15 zero-hit methods, 17 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L47 `Mem..cctor` (?, 1 lines)
- L61 `Mem.RoundUp` (public, 1 lines)
- L140 `Mem.AllocZero` (public, 1 lines)
- L145 `Mem.Free` (public, 1 lines)
- L167 `Mem.Peek1` (public, 1 lines)
- L173 `Mem.Poke1` (public, 1 lines)
- L182 `Mem.Peek2` (public, 2 lines)
- L191 `Mem.Poke2` (public, 1 lines)
- L209 `Mem.Poke4` (public, 1 lines)
- L218 `Mem.Peek8` (public, 2 lines)
- L227 `Mem.Poke8` (public, 1 lines)
- L234 `Mem.Copy1` (public, 1 lines)
- L241 `Mem.Copy2` (public, 1 lines)
- L248 `Mem.Copy4` (public, 1 lines)
- L255 `Mem.Copy8` (public, 1 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/UnmanagedResources.cs` — 7 zero-hit methods, 16 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L15 `UnmanagedResources.get_IsDisposed` (public, 1 lines)
- L21 `UnmanagedResources.ThrowIfDisposed` (protected, 3 lines)
- L26 `UnmanagedResources.ReleaseUnmanaged` (protected, 1 lines)
- L29 `UnmanagedResources.ReleaseManaged` (protected, 1 lines)
- L38 `UnmanagedResources.Dispose` (protected, 6 lines)
- L50 `UnmanagedResources.Dispose` (public, 3 lines)
- L55 `UnmanagedResources.Finalize` (?, 1 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/Extensions.cs` — 5 zero-hit methods, 15 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L16 `Extensions.Required` (internal, 1 lines)
- L24 `Extensions.AssertTrue` (public, 2 lines)
- L30 `Extensions.ThrowAssertionFailed` (private, 1 lines)
- L35 `Extensions.ThrowArgumentNullException` (private, 1 lines)
- L41 `Extensions.Validate` (internal, 10 lines)

### `Plank/Reading/Logical/Internal/DeltaBinaryPackedReader.cs` — 1 zero-hit methods, 15 lines — owner: reader

- L71 `DeltaBinaryPackedReader.ReadPackedUnsigned` (internal, 15 lines)

### `Plank/Reading/Physical/Internal/BloomFilterReader.cs` — 1 zero-hit methods, 14 lines — owner: reader (+ writer round trip for the matching encoder)

- L54 `BloomFilterReader.OpenWithoutLength` (?, 14 lines)

### `Plank/Reading/Logical/RowReaderBase.cs` — 5 zero-hit methods, 14 lines — owner: reader

- L10 `RowReaderBase`1..ctor` (protected, 6 lines)
- L19 `RowReaderBase`1.get_Reader` (protected, 1 lines)
- L22 `RowReaderBase`1.get_Metadata` (public, 1 lines)
- L25 `RowReaderBase`1.get_RowGroups` (public, 1 lines)
- L29 `RowReaderBase`1.Dispose` (public, 5 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4HighChainEncoder.cs` — 5 zero-hit methods, 13 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L16 `LZ4HighChainEncoder.get_Context` (private, 1 lines)
- L23 `LZ4HighChainEncoder..ctor` (public, 7 lines)
- L35 `LZ4HighChainEncoder.ReleaseUnmanaged` (protected, 3 lines)
- L42 `LZ4HighChainEncoder.EncodeBlock` (protected, 1 lines)
- L46 `LZ4HighChainEncoder.CopyDict` (protected, 1 lines)

### `Plank/RowApi/RowBufferSlot.cs` — 4 zero-hit methods, 13 lines — owner: rowapi

- L123 `RowBufferSlot.GetRowSize` (internal, 6 lines)
- L151 `RowBufferSlot.OnBuffersResized` (protected, 1 lines)
- L157 `RowBufferSlot.RegisterOwner` (public, 3 lines)
- L222 `RowBufferSlot.EnsureRowAvailable` (protected, 3 lines)

### `Plank/Reading/Logical/Internal/PhysicalSchemaBinder.cs` — 2 zero-hit methods, 13 lines — owner: reader

- L214 `PhysicalSchemaBinder.IsNestedRepeatedListElement` (?, 6 lines)
- L226 `PhysicalSchemaBinder.BuildRepeatedGroupElement` (?, 7 lines)

### `Plank/Writing/TimestampConversion.cs` — 2 zero-hit methods, 12 lines — owner: writer

- L208 `TimestampConversion.ConvertNanos` (?, 4 lines)
- L218 `TimestampConversion.ConvertNullableNanos` (?, 8 lines)

### `Plank/Reading/Logical/Internal/InternalColumnChunkMetadata.cs` — 10 zero-hit methods, 12 lines — owner: reader

- L44 `InternalColumnChunkMetadata.get_Path` (internal, 1 lines)
- L46 `InternalColumnChunkMetadata.get_PhysicalType` (internal, 1 lines)
- L50 `InternalColumnChunkMetadata.get_DataPageOffset` (internal, 1 lines)
- L52 `InternalColumnChunkMetadata.get_DictionaryPageOffset` (internal, 1 lines)
- L54 `InternalColumnChunkMetadata.get_TotalCompressedSize` (internal, 1 lines)
- L56 `InternalColumnChunkMetadata.get_TotalUncompressedSize` (internal, 1 lines)
- L64 `InternalColumnChunkMetadata.get_ColumnIndexOffset` (internal, 1 lines)
- L68 `InternalColumnChunkMetadata.get_OffsetIndexOffset` (internal, 1 lines)
- L74 `InternalColumnChunkMetadata.get_BloomFilterLength` (internal, 1 lines)
- L79 `InternalColumnChunkMetadata.get_ChunkOffset` (internal, 3 lines)

### `Plank/Compression/ZlibLibraryResolver.cs` — 2 zero-hit methods, 12 lines — owner: NEW compression-codec target (PlankDecompressorFuzzTarget exists; extend) + writer compression-level options

- L117 `ZlibLibraryResolver.GetSystemLibraryCandidates` (internal, 9 lines)
- L136 `ZlibLibraryResolver.CreateFailureMessage` (?, 3 lines)

### `Plank/DefaultParquetBufferPool.cs` — 4 zero-hit methods, 11 lines — owner: NEW buffer-pool/execution-options target (nobody owns)

- L74 `DefaultParquetBufferPool.Finalize` (?, 1 lines)
- L87 `DefaultParquetBufferPool.get_NativeAllocationCount` (internal, 1 lines)
- L230 `DefaultParquetBufferPool.IsProcessUnderMemoryPressure` (?, 3 lines)
- L290 `DefaultParquetBufferPool.CancelRent` (internal, 6 lines)

### `Plank/Writing/RowWriterBase.cs` — 3 zero-hit methods, 11 lines — owner: writer

- L176 `RowWriterBase`1.get_WorkerThreadNamePrefix` (protected, 1 lines)
- L182 `RowWriterBase`1.OnSlotWritten` (protected, 1 lines)
- L601 `RowWriterBase`1.RecordFault` (?, 9 lines)

### `Plank/Schema/RowSchema.cs` — 7 zero-hit methods, 10 lines — owner: writer (schema conversion/validation) + reader

- L8 `RowSchema..ctor` (public, 4 lines)
- L14 `RowSchema.get_Columns` (public, 1 lines)
- L16 `RowSchema.get_ParquetSchema` (public, 1 lines)
- L19 `RowSchema.Create` (public, 1 lines)
- L22 `RowSchema.Create` (public, 1 lines)
- L26 `RowSchema.Column` (public, 1 lines)
- L31 `RowSchema.Column` (public, 1 lines)

### `Plank/RowApi/RowReaderWorkers.cs` — 5 zero-hit methods, 10 lines — owner: rowapi

- L54 `RowReaderWorkers.get_Count` (internal, 1 lines)
- L130 `RowReaderSynchronizedSource..ctor` (public, 2 lines)
- L137 `RowReaderSynchronizedSource.get_Length` (public, 3 lines)
- L143 `RowReaderSynchronizedSource.ReadExactly` (public, 3 lines)
- L146 `RowReaderSynchronizedSource.Dispose` (public, 1 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Internal/x64/Mem64.cs` — 4 zero-hit methods, 9 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L44 `Mem64.Copy1` (public, 1 lines)
- L70 `Mem64.Poke8` (public, 1 lines)
- L107 `Mem64.PokeW` (public, 1 lines)
- L167 `Mem64.WildCopy32` (public, 6 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Engine/Pubternal.cs` — 4 zero-hit methods, 9 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L20 `Pubternal.get_Context` (internal, 1 lines)
- L23 `Pubternal..ctor` (public, 2 lines)
- L27 `Pubternal.ReleaseUnmanaged` (protected, 1 lines)
- L45 `Pubternal.CompressFast` (public, 5 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4FastChainEncoder.cs` — 5 zero-hit methods, 9 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L16 `LZ4FastChainEncoder.get_Context` (private, 1 lines)
- L22 `LZ4FastChainEncoder..ctor` (public, 3 lines)
- L30 `LZ4FastChainEncoder.ReleaseUnmanaged` (protected, 3 lines)
- L37 `LZ4FastChainEncoder.EncodeBlock` (protected, 1 lines)
- L41 `LZ4FastChainEncoder.CopyDict` (protected, 1 lines)

### `Plank/Reading/CompactProtocolReader.cs` — 4 zero-hit methods, 9 lines — owner: reader

- L33 `CompactProtocolReader.ReadI16` (internal, 2 lines)
- L57 `CompactProtocolReader.ReadDouble` (internal, 2 lines)
- L111 `CompactProtocolReader.ReadDouble` (?, 4 lines)
- L253 `CompactProtocolReader.ThrowInvalidCompactType` (?, 1 lines)

### `Plank/Reading/Logical/ParquetFileMetadata.cs` — 4 zero-hit methods, 9 lines — owner: reader

- L9 `ParquetFileMetadata..ctor` (public, 6 lines)
- L29 `ParquetFileMetadata.get_FooterOffset` (public, 1 lines)
- L31 `ParquetFileMetadata.get_FooterLength` (public, 1 lines)
- L33 `ParquetFileMetadata.get_Version` (public, 1 lines)

### `Plank/Reading/StreamReadSource.cs` — 2 zero-hit methods, 8 lines — owner: reader

- L8 `StreamReadSource.get_Stream` (internal, 1 lines)
- L23 `StreamReadSource.Reset` (public, 7 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4Encoder.cs` — 4 zero-hit methods, 7 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L16 `LZ4Encoder.Create` (public, 4 lines)
- L22 `LZ4Encoder.CreateBlockEncoder` (private, 1 lines)
- L25 `LZ4Encoder.CreateFastEncoder` (private, 1 lines)
- L29 `LZ4Encoder.CreateHighEncoder` (private, 1 lines)

### `Plank/Writing/Encoding/ByteArrayRow.cs` — 7 zero-hit methods, 7 lines — owner: writer

- L29 `RequiredByteArrayRow.get_ValueRequired` (public, 1 lines)
- L31 `RequiredByteArrayRow.IsPresent` (public, 1 lines)
- L33 `RequiredByteArrayRow.GetSpan` (public, 1 lines)
- L38 `OptionalByteArrayRow.get_ValueRequired` (public, 1 lines)
- L40 `OptionalByteArrayRow.IsPresent` (public, 1 lines)
- L42 `OptionalByteArrayRow.GetSpan` (public, 1 lines)
- L121 `ByteArrayRows.ThrowNullValue` (internal, 1 lines)

### `Plank/Schema/ParquetTypeMap.cs` — 2 zero-hit methods, 7 lines — owner: writer (schema conversion/validation) + reader

- L30 `ParquetTypeMap.TryGetPhysicalType` (public, 3 lines)
- L37 `ParquetTypeMap.GetPhysicalType` (public, 4 lines)

### `Plank/RowApi/RowApiColumnReadState.cs` — 3 zero-hit methods, 7 lines — owner: rowapi

- L61 `RowApiColumnReadState.ResetForMissingUnprojected` (internal, 5 lines)
- L79 `RowApiColumnReadState.PrepareBatch` (internal, 1 lines)
- L127 `RowApiColumnReadState.Dispose` (public, 1 lines)

### `Plank/Schema/ColumnDefinition.cs` — 5 zero-hit methods, 6 lines — owner: writer (schema conversion/validation) + reader

- L12 `ColumnDefinition.RequiredGroup` (public, 1 lines)
- L22 `ColumnDefinition.OptionalGroup` (public, 1 lines)
- L26 `ColumnDefinition.OptionalGroup` (public, 1 lines)
- L49 `ColumnDefinition.OptionalLeaf` (public, 2 lines)
- L78 `ColumnDefinition.List` (public, 1 lines)

### `Plank/RowApi/RowApiNestedColumnReadState.cs` — 1 zero-hit methods, 6 lines — owner: rowapi

- L43 `RowApiNestedColumnReadState`2.SetMissingValue` (internal, 6 lines)

### `Plank/Reading/Physical/ParquetBloomFilter.cs` — 4 zero-hit methods, 6 lines — owner: reader (+ writer round trip for the matching encoder)

- L20 `ParquetBloomFilter.get_BitsetSizeBytes` (public, 2 lines)
- L30 `ParquetBloomFilter.get_Bitset` (public, 2 lines)
- L45 `ParquetBloomFilter.MightContain` (public, 1 lines)
- L49 `ParquetBloomFilter.MightContain` (public, 1 lines)

### `Plank/Reading/Logical/Internal/InternalParquetFooter.cs` — 5 zero-hit methods, 6 lines — owner: reader

- L9 `InternalParquetFooter..ctor` (internal, 2 lines)
- L29 `InternalParquetFooter.get_Version` (internal, 1 lines)
- L31 `InternalParquetFooter.get_Schema` (internal, 1 lines)
- L35 `InternalParquetFooter.get_RowGroupsOffset` (internal, 1 lines)
- L37 `InternalParquetFooter.get_RowGroupsEndOffset` (internal, 1 lines)

### `Plank/Writing/Thrift/ParquetMetadataThriftWriter.cs` — 3 zero-hit methods, 5 lines — owner: writer

- L251 `ParquetMetadataThriftWriter.WriteRowGroup` (internal, 1 lines)
- L1026 `ParquetMetadataThriftWriter.GetPathSegments` (?, 3 lines)
- L1273 `ParquetMetadataThriftWriter.WriteRaw` (internal, 1 lines)

### `Plank/Writing/Encoding/ByteArrayComparer.cs` — 1 zero-hit methods, 5 lines — owner: writer

- L19 `ByteArrayComparer.GetHashCode` (public, 5 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4BlockEncoder.cs` — 3 zero-hit methods, 4 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L14 `LZ4BlockEncoder..ctor` (public, 2 lines)
- L20 `LZ4BlockEncoder.EncodeBlock` (protected, 1 lines)
- L23 `LZ4BlockEncoder.CopyDict` (protected, 1 lines)

### `Plank/Reading/Physical/ParquetFileReader.cs` — 1 zero-hit methods, 4 lines — owner: reader

- L137 `ParquetFileReader.OpenPages` (internal, 4 lines)

### `Plank/Reading/Logical/RowGroupCollection.cs` — 4 zero-hit methods, 4 lines — owner: reader

- L27 `RowGroupCollection.System.Collections.Generic.IEnumerable<Plank.Reading.Logical.RowGroup>.GetEnumerator` (?, 1 lines)
- L30 `RowGroupCollection.System.Collections.IEnumerable.GetEnumerator` (?, 1 lines)
- L51 `RowGroupCollection.System.Collections.IEnumerator.get_Current` (?, 1 lines)
- L68 `RowGroupCollection.System.Collections.IEnumerator.Reset` (?, 1 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/Encoders/LZ4Decoder.cs` — 3 zero-hit methods, 3 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L15 `LZ4Decoder.Create` (public, 1 lines)
- L18 `LZ4Decoder.CreateChainDecoder` (private, 1 lines)
- L21 `LZ4Decoder.CreateBlockDecoder` (private, 1 lines)

### `Plank/Writing/Encoding/ByteStreamSplitEncoding.cs` — 3 zero-hit methods, 3 lines — owner: writer

- L717 `ByteStreamSplitEncoding.NarrowToByte` (?, 1 lines)
- L721 `ByteStreamSplitEncoding.NarrowToByte` (?, 1 lines)
- L725 `ByteStreamSplitEncoding.StoreLowerUInt64` (?, 1 lines)

### `Plank/Writing/Encoding/ReadOnlyMemoryByteComparer.cs` — 1 zero-hit methods, 3 lines — owner: writer

- L12 `ReadOnlyMemoryByteComparer.GetHashCode` (public, 3 lines)

### `Plank/Reading/ParquetDecompressor.cs` — 1 zero-hit methods, 3 lines — owner: reader

- L12 `ParquetDecompressor.Decompress` (internal, 3 lines)

### `Plank/Reading/Logical/RowGroup.cs` — 3 zero-hit methods, 3 lines — owner: reader

- L27 `RowGroup.get_MetadataOffset` (public, 1 lines)
- L30 `RowGroup.get_ColumnChunkOffset` (public, 1 lines)
- L36 `RowGroup.get_PreviousColumns` (internal, 1 lines)

### `Plank/Dataset/DatasetBufferSlot.cs` — 3 zero-hit methods, 3 lines — owner: rowapi-dataset-merger (dataset targets)

- L198 `DatasetBufferSlot.Pin` (public, 1 lines)
- L200 `DatasetBufferSlot.Unpin` (public, 1 lines)
- L202 `DatasetBufferSlot.Dispose` (protected, 1 lines)

### `Plank/CorruptParquetException.cs` — 1 zero-hit methods, 2 lines — owner: writer

- L9 `CorruptParquetException..ctor` (public, 2 lines)

### `Plank/ParquetBufferPoolExtensions.cs` — 1 zero-hit methods, 2 lines — owner: NEW buffer-pool/execution-options target (nobody owns)

- L10 `ParquetBufferPoolExtensions.Rent` (public, 2 lines)

### `Plank/Writing/ParquetWriter.cs` — 1 zero-hit methods, 2 lines — owner: writer

- L163 `ParquetWriter.get_RowApiMaxParallelism` (public, 2 lines)

### `Plank/Writing/StreamParquetSource.cs` — 2 zero-hit methods, 2 lines — owner: writer

- L24 `StreamParquetSource.Open` (public, 1 lines)
- L67 `StreamParquetSource.Dispose` (public, 1 lines)

### `Plank/Writing/Encoding/BitPackedEncoding.cs` — 1 zero-hit methods, 2 lines — owner: writer

- L9 `BitPackedEncoding.WriteValues` (internal, 2 lines)

### `Plank/Writing/Encoding/OptionalRow.cs` — 2 zero-hit methods, 2 lines — owner: writer

- L55 `RequiredRow`1.IsPresent` (public, 1 lines)
- L58 `RequiredRow`1.GetValue` (public, 1 lines)

### `Plank/Schema/LeafColumn.cs` — 2 zero-hit methods, 2 lines — owner: writer (schema conversion/validation) + reader

- L55 `LeafColumn.get_FieldId` (public, 1 lines)
- L59 `LeafColumn.get_PageStrategy` (public, 1 lines)

### `Plank/Reading/Physical/ParquetPage.cs` — 2 zero-hit methods, 2 lines — owner: reader

- L13 `ParquetPage.get_Header` (public, 1 lines)
- L15 `ParquetPage.get_Payload` (public, 1 lines)

### `Plank/Reading/Logical/ParquetColumnChunkMetadata.cs` — 1 zero-hit methods, 2 lines — owner: reader

- L53 `ParquetColumnChunkMetadata.ReadGeospatialStatistics` (public, 2 lines)

### `Plank/Reading/Logical/ParquetDataPageMetadataCollection.cs` — 1 zero-hit methods, 2 lines — owner: reader

- L26 `ParquetDataPageMetadataCollection.get_BoundaryOrder` (public, 2 lines)

### `Plank/Reading/Logical/Internal/ColumnChunkReader.Timestamps.cs` — 1 zero-hit methods, 2 lines — owner: reader

- L55 `ColumnChunkReader.ThrowTimestampOutOfRange` (?, 2 lines)

### `Plank/Reading/Logical/Internal/InternalRowGroupMetadata.cs` — 2 zero-hit methods, 2 lines — owner: reader

- L18 `InternalRowGroupMetadata.get_MetadataOffset` (internal, 1 lines)
- L20 `InternalRowGroupMetadata.get_ColumnChunkOffset` (internal, 1 lines)

### `third_party/K4os.Compression.LZ4/src/K4os.Compression.LZ4/AssemblyHook.cs` — 1 zero-hit methods, 1 lines — owner: NEW compression-codec target (LZ4 raw/frame/block via Parquet LZ4_RAW + LZ4 pages); mostly unreachable library surface otherwise

- L5 `AssemblyHook..ctor` (private, 1 lines)

### `Plank/ParquetCrc32.cs` — 1 zero-hit methods, 1 lines — owner: writer

- L23 `ParquetCrc32.Compute` (internal, 1 lines)

### `Plank/ParquetWorkerContext.cs` — 1 zero-hit methods, 1 lines — owner: NEW buffer-pool/execution-options target (nobody owns)

- L3 `ParquetWorkerContext.get_WorkerIndex` (public, 1 lines)

### `Plank/Writing/LatestRowGroupValues.cs` — 1 zero-hit methods, 1 lines — owner: writer

- L201 `LatestRowGroupValues.Unsupported` (?, 1 lines)

### `Plank/Writing/PageStrategy/ForceDictionaryPageStrategy.cs` — 1 zero-hit methods, 1 lines — owner: writer

- L16 `ForceDictionaryPageStrategy.ShouldDropDictionary` (public, 1 lines)

### `Plank/Schema/Column.cs` — 1 zero-hit methods, 1 lines — owner: writer (schema conversion/validation) + reader

- L36 `Column.get_FieldId` (public, 1 lines)

### `Plank/Schema/ParquetSchemaAttribute.cs` — 1 zero-hit methods, 1 lines — owner: writer (schema conversion/validation) + reader

- L6 `ParquetSchemaAttribute.get_AllowAllocatingValues` (public, 1 lines)

### `Plank/RowApi/RowApiNestedColumnDescriptor.cs` — 1 zero-hit methods, 1 lines — owner: rowapi

- L65 `RowApiNestedColumnDescriptor`2.CreateWriteState` (internal, 1 lines)

### `Plank/RowApi/RowValueSizeEstimator.cs` — 1 zero-hit methods, 1 lines — owner: rowapi

- L73 `RowValueSizeEstimator.Estimate` (?, 1 lines)

### `Plank/Reading/PageHeaderReader.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L9 `PageHeaderReader.Read` (internal, 1 lines)

### `Plank/Reading/ParquetSchemaEvolutionOptions.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L11 `ParquetSchemaEvolutionOptions.get_Default` (public, 1 lines)

### `Plank/Reading/Physical/ParquetColumnSchemaInfo.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L31 `ParquetColumnSchemaInfo.get_TypeLength` (public, 1 lines)

### `Plank/Reading/Physical/ParquetRowGroupInfo.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L23 `ParquetRowGroupInfo.get_Ordinal` (public, 1 lines)

### `Plank/Reading/Logical/NestedRowGroupColumn.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L28 `NestedRowGroupColumn`1.get_Metadata` (public, 1 lines)

### `Plank/Reading/Logical/ParquetDataPageMetadata.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L19 `ParquetDataPageMetadata.get_RowGroupIndex` (public, 1 lines)

### `Plank/Reading/Logical/ParquetStatistics.cs` — 1 zero-hit methods, 1 lines — owner: reader (+ writer round trip for the matching encoder)

- L19 `ParquetStatistics.get_Definition` (public, 1 lines)

### `Plank/Reading/Logical/Internal/BinaryValueDescriptor.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L29 `BinaryValueDescriptor.get_Offset` (internal, 1 lines)

### `Plank/Reading/Logical/Internal/ColumnReadBuffers.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L78 `ColumnReadBuffers`1.SetBorrowedBinaryDictionaryPayload` (internal, 1 lines)

### `Plank/Reading/Logical/Internal/PageMetadataHandle.cs` — 1 zero-hit methods, 1 lines — owner: reader

- L27 `PageMetadataHandle.get_BoundaryOrder` (internal, 1 lines)
