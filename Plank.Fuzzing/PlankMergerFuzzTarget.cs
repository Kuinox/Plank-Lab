using System.Collections.Immutable;
using ParquetSharp;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>
/// Writes several small files, merges them, and checks the merged file still
/// holds every value in order.
/// </summary>
/// <remarks>
/// ParquetFileMerger measured 0/74 lines, and it is a better fuzz target than
/// its size suggests: it is the one write path that does not re-encode. It reads
/// each source file's metadata, splices the column chunks across verbatim, and
/// rewrites the offsets to match their new positions. That is offset arithmetic
/// over lengths taken from a file, which is exactly the shape of code worth
/// pointing a fuzzer at.
///
/// The oracle is concatenation: merging files holding A then B must produce
/// exactly A followed by B. A merger that miscounted a row group, dropped a
/// chunk or wrote a stale offset fails that, and fails it loudly rather than by
/// crashing.
/// </remarks>
public static class PlankMergerFuzzTarget
{
    const int MaxFiles = 4;
    const int MaxRowsPerFile = 32;
    static ReadOnlySpan<byte> OptionalAllNullNoIndexMagic => "MNU1"u8;
    static ReadOnlySpan<byte> AppendCoverageMagic => "MAC1"u8;
    static ReadOnlySpan<byte> ImportedIndexesAndBloomMagic => "IMX1"u8;
    static ReadOnlySpan<byte> ImportRollbackMagic => "MTR1"u8;
    static ReadOnlySpan<byte> MutationSchemaMagic => "MSC1"u8;

    public static void Execute(ReadOnlySpan<byte> data)
    {
        // Generated-schema merge and dataset routes (see PlankRowApiFuzzTarget): they run
        // without an expected-exception filter, so any exception is a finding.
        // The corpus seeds carry the writer target's 0xFF row-API marker; accept them as they are.
        var rowApiData = data.Length > 4 && data[0] == 0xFF ? data[1..] : data;
        if (rowApiData.Length >= 4 && (rowApiData[..4].SequenceEqual("RMW1"u8) || rowApiData[..4].SequenceEqual("RMN1"u8)
            || rowApiData[..4].SequenceEqual("RDW1"u8) || rowApiData[..4].SequenceEqual("RDN1"u8)
            || rowApiData[..4].SequenceEqual("RDA1"u8) || rowApiData[..4].SequenceEqual("RMD1"u8) || rowApiData[..4].SequenceEqual("RDD1"u8)))
        {
            PlankRowApiFuzzTarget.Execute(rowApiData);
            return;
        }

        if (data.Length >= MutationSchemaMagic.Length
            && data[..MutationSchemaMagic.Length].SequenceEqual(MutationSchemaMagic))
        {
            MutationSchemaCoverageCases.Run();
            return;
        }

        if (data.Length >= ImportRollbackMagic.Length
            && data[..ImportRollbackMagic.Length].SequenceEqual(ImportRollbackMagic))
        {
            if (data.Length > ImportRollbackMagic.Length && data[ImportRollbackMagic.Length] is 1 or 2)
                RunInitialImportRollback(data[ImportRollbackMagic.Length] == 2 ? 0 : 1);
            else
                RunImportRollback();
            return;
        }

        if (data.Length >= 4 && data[..4].SequenceEqual("IMS1"u8))
        {
            ExecuteImportedMissingStatistics(data[4..]);
            return;
        }

        if (data.Length >= ImportedIndexesAndBloomMagic.Length
            && data[..ImportedIndexesAndBloomMagic.Length].SequenceEqual(ImportedIndexesAndBloomMagic))
        {
            RunImportedIndexesAndBloom();
            return;
        }

        if (data.Length >= AppendCoverageMagic.Length
            && data[..AppendCoverageMagic.Length].SequenceEqual(AppendCoverageMagic))
        {
            RunAppendCoverageCases();
            return;
        }

        if (data.Length >= OptionalAllNullNoIndexMagic.Length
            && data[..OptionalAllNullNoIndexMagic.Length].SequenceEqual(OptionalAllNullNoIndexMagic))
        {
            try
            {
                RunOptionalAllNullNoIndex();
            }
            catch (Exception ex) when (ex is CorruptParquetException or NotSupportedException
                or InvalidOperationException or ArgumentException)
            {
                // Keep expected malformed-input failures consistent with the main merger route.
            }
            return;
        }

        if (data.Length < 2)
            return;

        try
        {
            Run(data);
        }
        catch (Exception ex) when (ex is CorruptParquetException or NotSupportedException
            or InvalidOperationException or ArgumentException)
        {
            // ArgumentException is expected here as well as the usual set: the
            // merger rejects a destination that is also a source, and rejects
            // files whose schema does not match the one it was created with.
        }
    }

    static void RunImportRollback()
    {
        var schema = CreateRequiredInt32Schema();
        var options = new ParquetWriterOptions { Compression = CompressionKind.None, BufferChunkSizeBytes = 64 };
        var firstBytes = WriteFocusedFile(schema, [[1, 3, 5]], options);
        var secondBytes = WriteFocusedFile(schema, [[7, 9], [11, 13]], options);
        using var metadataReader = new Plank.Reading.Physical.ParquetFileReader();
        using var secondMetadataSource = new MemoryReadSource(secondBytes);
        metadataReader.Reset(secondMetadataSource);
        var failOffset = metadataReader.Metadata.ColumnChunk(1, 0).ChunkOffset;

        using var firstSource = new MemoryReadSource(firstBytes);
        using var destination = new MemoryReadWriteSource();
        var merger = schema.CreateMerger(firstSource, destination,
            new ParquetMergeOptions { WriterOptions = options });
        using (var faultSource = new FaultingReadSource(secondBytes, failOffset))
        {
            try
            {
                merger.AppendFile(faultSource);
                throw new MergeException("The injected second-chunk read failure was accepted.");
            }
            catch (IOException exception) when (exception.Message == "Injected second-chunk read failure.")
            {
            }
        }

        if (merger.SourceFileCount != 1 || merger.RowGroupCount != 1 || merger.RowCount != 3)
            throw new MergeException("Failed import changed merger counters.");
        merger.CloseFile();
        VerifyFocusedFile(schema, destination, [1, 3, 5], [3], null, []);
    }

    static void RunInitialImportRollback(int failRowGroupIndex)
    {
        var schema = CreateRequiredInt32Schema();
        var options = new ParquetWriterOptions { Compression = CompressionKind.None };
        var bytes = WriteFocusedFile(schema, [[7, 9], [11, 13]], options);
        using var metadataReader = new Plank.Reading.Physical.ParquetFileReader();
        using var metadataSource = new MemoryReadSource(bytes);
        metadataReader.Reset(metadataSource);
        var failOffset = metadataReader.Metadata.ColumnChunk(failRowGroupIndex, 0).ChunkOffset;

        using var source = new FaultingReadSource(bytes, failOffset);
        using var destination = new MemoryReadWriteSource();
        try
        {
            schema.CreateMerger(source, destination, new ParquetMergeOptions { WriterOptions = options });
            throw new MergeException("The injected first-file import failure was accepted.");
        }
        catch (IOException exception) when (exception.Message == "Injected second-chunk read failure.")
        {
        }
        VerifyFocusedFile(schema, destination, [], [], null, []);
    }

    sealed class FaultingReadSource(byte[] bytes, ulong failOffset) : IParquetReadSource
    {
        readonly MemoryReadSource _source = new(bytes);
        public ulong Length => _source.Length;

        public void ReadExactly(ulong offset, Span<byte> destination)
        {
            if (offset == failOffset)
                throw new IOException("Injected second-chunk read failure.");
            _source.ReadExactly(offset, destination);
        }

        public void Dispose() => _source.Dispose();
    }

    internal static void ExecuteImportedMissingStatistics(ReadOnlySpan<byte> sourceBytes)
    {
        List<int>? expected;
        try
        {
            expected = ReadNoStatisticsSourceValues(sourceBytes);
        }
        catch (Exception ex) when (ex is CorruptParquetException or NotSupportedException
            or InvalidOperationException or ArgumentException or EndOfStreamException)
        {
            // Mutations that invalidate the external source are not merger findings.
            return;
        }

        if (expected is null)
            return;

        MergeAndVerifyMissingStatistics(sourceBytes.ToArray(), expected);
    }

    static void RunImportedIndexesAndBloom()
    {
        var schema = CreateRequiredInt32Schema(withBloomFilter: true);
        var values = new[] { 3, 7, 11, 19 };
        var sourceFile = WriteFocusedFile(schema, [[3, 7, 11, 19]], new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = true
        });

        using var destination = new MemoryReadWriteSource();
        var merger = schema.CreateMerger(new MemoryReadSource(sourceFile), destination,
            new ParquetMergeOptions
            {
                PreserveFirstFileMetadata = true,
                WriterOptions = new ParquetWriterOptions { Compression = CompressionKind.None }
            });
        merger.CloseFile();
        VerifyFocusedFile(schema, destination, values, [4], null, []);

        using var physicalReader = new Plank.Reading.Physical.ParquetFileReader();
        physicalReader.Reset(destination);
        var chunk = physicalReader.Metadata.ColumnChunk(0, 0);
        if (!chunk.HasBloomFilter || chunk.ColumnIndexLength == 0 || chunk.OffsetIndexLength == 0)
            throw new MergeException("Imported metadata lost its Bloom filter or page indexes.");

        using var independentReader = new ParquetFileReader(new MemoryStream(destination.ToArray(), writable: false),
            leaveOpen: true);
        if (independentReader.FileMetaData.NumRowGroups != 1)
            throw new MergeException("Imported metadata changed the independent row-group count.");
        using var rowGroup = independentReader.RowGroup(0);
        using var column = rowGroup.Column(0).LogicalReader<int>();
        if (!column.ReadAll(values.Length).AsSpan().SequenceEqual(values))
            throw new MergeException("Imported metadata changed independent values.");
    }

    static List<int>? ReadNoStatisticsSourceValues(ReadOnlySpan<byte> sourceBytes)
    {
        if (sourceBytes.Length is < 12 or > 1_048_576 || !sourceBytes[..4].SequenceEqual("PAR1"u8))
            return null;

        var schema = new ParquetSchema([ColumnDefinition.Leaf("value", ParquetPhysicalType.Int32,
            new ColumnOptions(ParquetRepetition.Required, encodings: ImmutableArray.Create(EncodingKind.Plain)))]);
        var sourceFile = sourceBytes.ToArray();
        var expected = new List<int>();
        using (var source = new MemoryReadSource(sourceFile))
        using (var reader = schema.CreateReader(source))
        {
            if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 5)
                return null;

            var statistics = reader.RowGroups[0].GetColumnMetadata(schema.LeafColumns[0]).Statistics;
            if (statistics.HasMinimum || statistics.HasMaximum || statistics.NullCount is not null
                || statistics.DistinctCount is not null)
                return null;

            foreach (var buffer in reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
                foreach (var value in buffer.Values)
                    expected.Add(value);
        }

        if (expected.Count != 5)
            return null;
        return expected;
    }

    static void MergeAndVerifyMissingStatistics(byte[] sourceFile, List<int> expected)
    {
        var schema = new ParquetSchema([ColumnDefinition.Leaf("value", ParquetPhysicalType.Int32,
            new ColumnOptions(ParquetRepetition.Required, encodings: ImmutableArray.Create(EncodingKind.Plain)))]);
        using var destination = new MemoryReadWriteSource();
        var merger = schema.CreateMerger(new MemoryReadSource(sourceFile), destination,
            new ParquetMergeOptions { PreserveFirstFileMetadata = true });
        if (merger.SourceFileCount != 1 || merger.RowGroupCount != 1 || merger.RowCount != expected.Count)
            throw new MergeException("No-statistics import changed the merger source counters.");
        merger.CloseFile();

        var merged = destination.ToArray();
        using var mergedSource = new MemoryReadSource(merged);
        using var mergedReader = schema.CreateReader(mergedSource);
        if (mergedReader.RowGroups.Count != 1 || mergedReader.RowGroups[0].RowCount != (ulong)expected.Count)
            throw new MergeException("No-statistics import changed the merged row-group shape.");

        var mergedStatistics = mergedReader.RowGroups[0].GetColumnMetadata(schema.LeafColumns[0]).Statistics;
        if (mergedStatistics.HasMinimum || mergedStatistics.HasMaximum || mergedStatistics.NullCount is not null
            || mergedStatistics.DistinctCount is not null)
            throw new MergeException("No-statistics import added column statistics to the merged footer.");

        var actual = new List<int>(expected.Count);
        foreach (var buffer in mergedReader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
            foreach (var value in buffer.Values)
                actual.Add(value);
        if (!actual.SequenceEqual(expected))
            throw new MergeException("No-statistics import changed the source values.");

        using var independentReader = new ParquetFileReader(new MemoryStream(merged, writable: false), leaveOpen: true);
        if (independentReader.FileMetaData.NumRowGroups != 1)
            throw new MergeException("ParquetSharp reported an unexpected merged row-group count.");
        using var independentRowGroup = independentReader.RowGroup(0);
        using (var independentMetadata = independentRowGroup.MetaData.GetColumnChunkMetaData(0))
            if (independentMetadata.IsStatsSet)
                throw new MergeException("ParquetSharp found statistics in the merged footer.");
        using var independentValues = independentRowGroup.Column(0).LogicalReader<int>();
        var independentActual = independentValues.ReadAll(expected.Count);
        if (!independentActual.SequenceEqual(expected))
            throw new MergeException("ParquetSharp readback changed the source values.");
    }

    static void RunAppendCoverageCases()
    {
        var schema = CreateRequiredInt32Schema();
        var originalOptions = new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            CreatedBy = "first-created-by",
            KeyValueMetadata = [new("source", "first"), new("empty-value", null)]
        };
        var firstFile = WriteFocusedFile(schema, [[], [10, 20]], originalOptions);
        VerifyFocusedFile(schema, new MemoryReadSource(firstFile), [10, 20], [0, 2],
            "first-created-by", [("source", "first"), ("empty-value", null)]);

        using (var destination = new MemoryReadWriteSource())
        {
            destination.Write(0, firstFile);
            var merger = schema.CreateMerger(destination, new ParquetMergeOptions
            {
                PreserveFirstFileMetadata = true,
                WriterOptions = new ParquetWriterOptions
                {
                    Compression = CompressionKind.None,
                    CreatedBy = "merge-created-by",
                    KeyValueMetadata = [new("added", "second")]
                }
            });
            if (merger.SourceFileCount != 1 || merger.RowGroupCount != 1 || merger.RowCount != 2)
                throw new MergeException("In-place merger miscounted a zero-row group.");

            merger.AppendFile(new MemoryReadSource(WriteFocusedFile(schema, [[], [30]], originalOptions)));
            if (merger.SourceFileCount != 2 || merger.RowGroupCount != 2 || merger.RowCount != 3)
                throw new MergeException("In-place merger miscounted imported rows.");
            merger.CloseFile();
            VerifyFocusedFile(schema, destination, [10, 20, 30], [2, 1], "merge-created-by",
                [("source", "first"), ("empty-value", null), ("added", "second")]);
        }

        using (var source = new MemoryReadSource(firstFile))
        using (var destination = new MemoryReadWriteSource())
        {
            var merger = schema.CreateMerger(source, destination, new ParquetMergeOptions
            {
                PreserveFirstFileMetadata = true,
                WriterOptions = new ParquetWriterOptions
                {
                    Compression = CompressionKind.None,
                    CreatedBy = "copy-created-by",
                    KeyValueMetadata = [new("added-copy", "third")]
                }
            });
            merger.AppendFile(new MemoryReadSource(WriteFocusedFile(schema, [[40]], originalOptions)));
            if (merger.SourceFileCount != 2 || merger.RowGroupCount != 2 || merger.RowCount != 3)
                throw new MergeException("Out-of-place merger miscounted imported rows.");
            merger.CloseFile();
            VerifyFocusedFile(schema, destination, [10, 20, 40], [2, 1], "copy-created-by",
                [("source", "first"), ("empty-value", null), ("added-copy", "third")]);
        }

        var bloomSchema = CreateRequiredInt32Schema(withBloomFilter: true);
        var appendOptions = new ParquetWriterOptions { Compression = CompressionKind.None, WritePageIndexes = true };
        var appendFile = WriteFocusedFile(bloomSchema, [[1, 2], [5, 6]], appendOptions);
        byte[] appendedFile;
        using (var stream = new MemoryStream())
        {
            stream.Write(appendFile);
            stream.Position = 0;
            var appender = bloomSchema.CreateAppender(stream, new ParquetAppendOptions
            {
                WriterOptions = appendOptions,
                AppendToLatestRowGroup = true
            });
            var column = appender.CreateSerializedColumn<int>(bloomSchema.LeafColumns[0]);
            column.Serialize([7]);
            appender.StartRowGroup().Write(column);
            appender.CloseFile();
            appendedFile = stream.ToArray();
        }
        VerifyFocusedFile(bloomSchema, new MemoryReadSource(appendedFile), [1, 2, 5, 6, 7], [2, 3], null, []);
        using (var physicalReader = new Plank.Reading.Physical.ParquetFileReader())
        {
            physicalReader.Reset(new MemoryReadSource(appendedFile));
            var firstChunk = physicalReader.Metadata.ColumnChunk(0, 0);
            if (firstChunk.ColumnIndexLength == 0 || !firstChunk.HasBloomFilter)
                throw new MergeException("Append-to-latest lost the earlier row group's index or Bloom filter.");
        }

        byte[] unchangedAppendFile;
        using (var stream = new MemoryStream())
        {
            stream.Write(appendFile);
            stream.Position = 0;
            var appender = bloomSchema.CreateAppender(stream, new ParquetAppendOptions
            {
                WriterOptions = appendOptions,
                AppendToLatestRowGroup = true
            });
            appender.CloseFile();
            unchangedAppendFile = stream.ToArray();
        }
        VerifyFocusedFile(bloomSchema, new MemoryReadSource(unchangedAppendFile), [1, 2, 5, 6], [2, 2], null,
            []);

        var metadataSource = new MemoryReadWriteSource();
        metadataSource.Write(0, firstFile);
        var metadataMerger = schema.CreateMerger(metadataSource, new ParquetMergeOptions
        {
            PreserveFirstFileMetadata = true,
            WriterOptions = new ParquetWriterOptions { Compression = CompressionKind.None }
        });
        metadataMerger.CloseFile();
        VerifyFocusedFile(schema, metadataSource, [10, 20], [2], "first-created-by",
            [("source", "first"), ("empty-value", null)]);

        var sortedSchema = CreateRequiredInt32Schema();
        var sortedFile = WriteFocusedFile(sortedSchema, [[1, 2]], new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            SortingColumns = [new ParquetSortingColumn(0)]
        });
        using (var source = new MemoryReadSource(sortedFile))
        using (var destination = new MemoryReadWriteSource())
        {
            var appender = sortedSchema.CreateAppender(source, destination, new ParquetAppendOptions
            {
                AppendToLatestRowGroup = true,
                WriterOptions = new ParquetWriterOptions
                {
                    Compression = CompressionKind.None,
                    SortingColumns = [new ParquetSortingColumn(0, descending: true)]
                }
            });
            var column = appender.CreateSerializedColumn<int>(sortedSchema.LeafColumns[0]);
            column.Serialize([3]);
            appender.StartRowGroup().Write(column);
            appender.CloseFile();
            VerifyFocusedFile(sortedSchema, destination, [1, 2, 3], [3], null, []);
            using var physicalReader = new Plank.Reading.Physical.ParquetFileReader();
            physicalReader.Reset(destination);
            if (physicalReader.Metadata.RowGroupSortingColumns(0).Length != 0)
                throw new MergeException("Appender retained a sorting order that was not established for old rows.");
        }
    }

    static ParquetSchema CreateRequiredInt32Schema(bool withBloomFilter = false)
        => new([ColumnDefinition.Leaf("c", ParquetPhysicalType.Int32,
            new ColumnOptions(ParquetRepetition.Required,
                encodings: ImmutableArray.Create(EncodingKind.Plain),
                bloomFilter: withBloomFilter ? new ParquetBloomFilterOptions { MaximumBytes = 32 } : null))]);

    static byte[] WriteFocusedFile(ParquetSchema schema, int[][] rowGroups, ParquetWriterOptions options)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, options);
        foreach (var rows in rowGroups)
        {
            var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            column.Serialize(rows);
            writer.StartRowGroup().Write(column);
        }
        writer.CloseFile();
        return stream.ToArray();
    }

    static void VerifyFocusedFile(ParquetSchema schema, IParquetReadSource source,
        ReadOnlySpan<int> expectedValues,
        ReadOnlySpan<int> expectedRowsPerGroup, string? expectedCreatedBy,
        (string Key, string? Value)[] expectedMetadata)
    {
        using (var reader = schema.CreateReader(source))
        {
            if (reader.RowGroups.Count != expectedRowsPerGroup.Length)
                throw new MergeException(
                    $"Focused writer route produced {reader.RowGroups.Count} row groups; expected {expectedRowsPerGroup.Length}.");

            var values = new List<int>();
            for (var groupIndex = 0; groupIndex < expectedRowsPerGroup.Length; groupIndex++)
            {
                var group = reader.RowGroups[groupIndex];
                if (group.RowCount != (ulong)expectedRowsPerGroup[groupIndex])
                    throw new MergeException(
                        $"Focused writer row group {groupIndex} has {group.RowCount} rows; expected {expectedRowsPerGroup[groupIndex]}.");
                foreach (var buffer in group.Column<int>(schema.LeafColumns[0]))
                    values.AddRange(buffer.Values.ToArray());
            }
            if (!values.ToArray().AsSpan().SequenceEqual(expectedValues))
                throw new MergeException("Focused writer route changed or reordered values.");
        }

        if (expectedCreatedBy is null && expectedMetadata.Length == 0)
            return;

        using var physicalReader = new Plank.Reading.Physical.ParquetFileReader();
        physicalReader.Reset(source);
        var metadata = physicalReader.Metadata;
        var createdBy = metadata.HasCreatedBy
            ? System.Text.Encoding.UTF8.GetString(metadata.CreatedByUtf8)
            : null;
        if (createdBy != expectedCreatedBy || metadata.KeyValueMetadataCount != expectedMetadata.Length)
            throw new MergeException("Focused writer route changed CreatedBy or key-value metadata count.");
        for (var i = 0; i < expectedMetadata.Length; i++)
        {
            var key = System.Text.Encoding.UTF8.GetString(metadata.KeyValueMetadataKeyUtf8(i));
            var value = metadata.KeyValueMetadata[i].HasValue
                ? System.Text.Encoding.UTF8.GetString(metadata.KeyValueMetadataValueUtf8(i))
                : null;
            if (key != expectedMetadata[i].Key || value != expectedMetadata[i].Value)
                throw new MergeException($"Focused writer metadata entry {i} changed.");
        }
    }

    static void Run(ReadOnlySpan<byte> data)
    {
        var cursor = new Cursor(data);
        var fileCount = cursor.NextInt(1, MaxFiles + 1);

        // One schema for every file: the merger requires them to match, and a
        // mismatch is rejected long before any of the splicing runs.
        var schema = new ParquetSchema([ColumnDefinition.Leaf("c", ParquetPhysicalType.Int32,
            new ColumnOptions(ParquetRepetition.Required,
                encodings: ImmutableArray.Create(EncodingKind.Plain)))]);

        var files = new byte[fileCount][];
        var expected = new List<int>();
        for (var i = 0; i < fileCount; i++)
        {
            var rows = cursor.NextInt(1, MaxRowsPerFile + 1);
            var values = new int[rows];
            for (var r = 0; r < rows; r++)
                values[r] = cursor.NextInt32();
            expected.AddRange(values);
            // Codecs vary per file on purpose: the merger copies chunks without
            // re-encoding, so a merged file legitimately holds several codecs at
            // once and has to record each chunk's own.
            files[i] = WriteFile(schema, values, PickCompression(ref cursor));
        }

        using var destination = new MemoryReadWriteSource();
        var options = new ParquetMergeOptions
        {
            PreserveFirstFileMetadata = cursor.NextInt(0, 2) == 0
        };

        // Two ways in, and they take different constructors. The two-argument
        // form starts an empty destination from a first source file. The
        // one-argument form appends to a destination that already holds a file,
        // which is the only path through ParquetAppendOptions and the only one
        // that has to read back existing footer counts before writing.
        ParquetFileMerger merger;
        var appendToExisting = cursor.NextInt(0, 2) == 0;
        if (appendToExisting)
        {
            destination.Write(0, files[0]);
            merger = schema.CreateMerger(destination, options);
        }
        else
        {
            merger = schema.CreateMerger(new MemoryReadSource(files[0]), destination, options);
        }

        for (var i = 1; i < fileCount; i++)
            merger.AppendFile(new MemoryReadSource(files[i]));

        if (merger.SourceFileCount != fileCount)
            throw new MergeException($"Merger counted {merger.SourceFileCount} source files, expected {fileCount}.");
        if (merger.RowCount != expected.Count)
            throw new MergeException($"Merger counted {merger.RowCount} rows, expected {expected.Count}.");
        merger.CloseFile();

        VerifyConcatenation(schema, destination.ToArray(), expected);
    }

    static void RunOptionalAllNullNoIndex()
    {
        const int firstRowCount = 3;
        const int secondRowCount = 2;
        const int expectedRowCount = firstRowCount + secondRowCount;
        var schema = new ParquetSchema([ColumnDefinition.OptionalLeaf("c", ParquetPhysicalType.Int32,
            new ColumnOptions(ParquetRepetition.Optional,
                encodings: ImmutableArray.Create(EncodingKind.Plain)))]);
        var files = new[]
        {
            WriteOptionalAllNullFile(schema, firstRowCount),
            WriteOptionalAllNullFile(schema, secondRowCount)
        };

        using var destination = new MemoryReadWriteSource();
        var merger = schema.CreateMerger(new MemoryReadSource(files[0]), destination,
            new ParquetMergeOptions { PreserveFirstFileMetadata = true });
        merger.AppendFile(new MemoryReadSource(files[1]));
        if (merger.SourceFileCount != files.Length || merger.RowGroupCount != files.Length
            || merger.RowCount != expectedRowCount)
            throw new MergeException(
                $"All-null merge counted {merger.SourceFileCount} files, {merger.RowGroupCount} row groups, "
                + $"and {merger.RowCount} rows; expected {files.Length}, {files.Length}, and {expectedRowCount}.");
        merger.CloseFile();

        VerifyOptionalAllNull(destination.ToArray(), schema,
            [firstRowCount, secondRowCount], expectedRowCount);
    }

    static byte[] WriteOptionalAllNullFile(ParquetSchema schema, int rowCount)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            WritePageIndexes = false
        });
        var column = writer.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
        column.Serialize(new int?[rowCount]);
        writer.StartRowGroup().Write(column);
        writer.CloseFile();
        return stream.ToArray();
    }

    static void VerifyOptionalAllNull(byte[] merged, ParquetSchema schema,
        ReadOnlySpan<int> expectedRowsPerGroup, int expectedRowCount)
    {
        using var source = new MemoryReadSource(merged);
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != expectedRowsPerGroup.Length)
            throw new MergeException(
                $"All-null merge produced {reader.RowGroups.Count} row groups; expected {expectedRowsPerGroup.Length}.");

        var valuesRead = 0;
        for (var groupIndex = 0; groupIndex < expectedRowsPerGroup.Length; groupIndex++)
        {
            var group = reader.RowGroups[groupIndex];
            if (group.RowCount != (ulong)expectedRowsPerGroup[groupIndex])
                throw new MergeException(
                    $"All-null merge row group {groupIndex} has {group.RowCount} rows; "
                    + $"expected {expectedRowsPerGroup[groupIndex]}.");

            foreach (var buffer in group.Column<int?>(schema.LeafColumns[0]))
                foreach (var value in buffer.Values)
                {
                    if (value.HasValue)
                        throw new MergeException(
                            $"All-null merge produced non-null value {value.Value} at row {valuesRead}.");
                    valuesRead++;
                }
        }

        if (valuesRead != expectedRowCount)
            throw new MergeException(
                $"All-null merge read {valuesRead} values; expected {expectedRowCount}.");
    }

    static void VerifyConcatenation(ParquetSchema schema, byte[] merged, List<int> expected)
    {
        var actual = new List<int>();
        using var reader = schema.CreateReader(new MemoryStream(merged, writable: false));
        foreach (var rowGroup in reader.RowGroups)
            foreach (var buffer in rowGroup.Column<int>(schema.LeafColumns[0]))
                foreach (var value in buffer.Values)
                    actual.Add(value);

        if (actual.Count != expected.Count)
            throw new MergeException($"Merged file holds {actual.Count} values, expected {expected.Count}.");
        for (var i = 0; i < actual.Count; i++)
            if (actual[i] != expected[i])
                throw new MergeException(
                    $"Merged value {i} is {actual[i]}, expected {expected[i]} — the merge did not concatenate in order.");
    }

    static byte[] WriteFile(ParquetSchema schema, int[] values, CompressionKind compression)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = compression });
        var group = writer.StartRowGroup();
        var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize(values);
        group.Write(column);
        writer.CloseFile();
        return stream.ToArray();
    }

    static CompressionKind PickCompression(ref Cursor cursor)
        => cursor.NextInt(0, 4) switch
        {
            0 => CompressionKind.None,
            1 => CompressionKind.Snappy,
            2 => CompressionKind.Gzip,
            _ => CompressionKind.Zstd
        };

    /// <summary>Signals that a merge lost, reordered or duplicated values.</summary>
    public sealed class MergeException(string message) : Exception(message);

    /// <summary>An in-memory destination the merger can both read and write.</summary>
    internal sealed class MemoryReadWriteSource : IParquetReadWriteSource
    {
        readonly MemoryStream _stream = new();

        public ulong Length
            => (ulong)_stream.Length;

        public void Open(ReadOnlySpan<byte> path, FileMode mode)
        {
            if (mode == FileMode.Create)
                _stream.SetLength(0);
        }

        public void Close()
        {
        }

        public void Write(ulong offset, ReadOnlySpan<byte> source)
        {
            var end = offset + (ulong)source.Length;
            if (end > int.MaxValue)
                throw new NotSupportedException("In-memory destinations larger than Int32.MaxValue are not supported.");
            if ((ulong)_stream.Length < end)
                _stream.SetLength((long)end);
            _stream.Position = (long)offset;
            _stream.Write(source);
        }

        public void SetLength(ulong length)
        {
            if (length > int.MaxValue)
                throw new NotSupportedException("In-memory destinations larger than Int32.MaxValue are not supported.");
            _stream.SetLength((long)length);
        }

        public void Flush()
        {
        }

        public void ReadExactly(ulong offset, Span<byte> destination)
        {
            var length = (ulong)_stream.Length;
            if (offset > length || (ulong)destination.Length > length - offset)
                throw new CorruptParquetException(
                    $"Attempted to read {destination.Length} bytes at offset {offset} but the destination is only {length} bytes long.");
            _stream.Position = (long)offset;
            _stream.ReadExactly(destination);
        }

        internal byte[] ToArray()
            => _stream.ToArray();

        public void Dispose()
            => _stream.Dispose();
    }

    ref struct Cursor(ReadOnlySpan<byte> data)
    {
        readonly ReadOnlySpan<byte> _data = data;
        int _offset;

        byte NextByte()
            => _offset < _data.Length ? _data[_offset++] : (byte)0;

        internal int NextInt(int minInclusive, int maxExclusive)
        {
            var range = maxExclusive - minInclusive;
            return range <= 0 ? minInclusive : minInclusive + (NextByte() % range);
        }

        internal int NextInt32()
            => (NextByte() << 24) | (NextByte() << 16) | (NextByte() << 8) | NextByte();
    }
}
