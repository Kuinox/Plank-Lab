using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

internal static class LatestRowGroupValuesCoverageCases
{
    internal static void Execute(ReadOnlySpan<byte> controls)
    {
        if (controls.IsEmpty)
            return;

        switch (controls[0])
        {
            case 1:
                AppendOptionalPrimitiveColumns();
                break;
            case 2:
                RejectRepeatedLatestRowGroup();
                break;
            case 3:
                AppendLatestRowGroupAfterPriorData();
                break;
            case 4:
                AppendLatestRowGroupAfterPriorIndexesAndBloom();
                break;
            case 5:
                AppendExternalLayout(controls[1..]);
                break;
        }
    }

    static void AppendOptionalPrimitiveColumns()
    {
        var plain = new ColumnOptions(ParquetRepetition.Optional,
            encodings: ImmutableArray.Create(EncodingKind.Plain));
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("optional-bool", ParquetPhysicalType.Boolean, plain),
            ColumnDefinition.OptionalLeaf("optional-int32", ParquetPhysicalType.Int32, plain),
            ColumnDefinition.OptionalLeaf("optional-float", ParquetPhysicalType.Float, plain),
            ColumnDefinition.OptionalLeaf("optional-double", ParquetPhysicalType.Double, plain)
        ]);
        bool?[] originalBools = [true, null, false];
        int?[] originalInts = [-4, null, 8];
        float?[] originalFloats = [-1.5f, null, 3.25f];
        double?[] originalDoubles = [-9.5, null, 12.75];

        using var initial = new MemoryStream();
        using (var writer = schema.CreateWriter(initial, new ParquetWriterOptions
               {
                   Compression = CompressionKind.None,
                   SortingColumns = []
               }))
        {
            var rowGroup = writer.StartRowGroup();
            Write(rowGroup, schema.LeafColumns[0], originalBools);
            Write(rowGroup, schema.LeafColumns[1], originalInts);
            Write(rowGroup, schema.LeafColumns[2], originalFloats);
            Write(rowGroup, schema.LeafColumns[3], originalDoubles);
            writer.CloseFile();
        }

        using var appended = new MemoryStream();
        appended.Write(initial.ToArray());
        appended.Position = 0;
        using (var writer = schema.CreateAppender(appended, new ParquetAppendOptions
               {
                   AppendToLatestRowGroup = true,
                   WriterOptions = new ParquetWriterOptions
                   {
                       Compression = CompressionKind.None,
                       SortingColumns = []
                   }
               }))
        {
            var rowGroup = writer.StartRowGroup();
            Write(rowGroup, schema.LeafColumns[0], originalBools);
            Write(rowGroup, schema.LeafColumns[1], originalInts);
            Write(rowGroup, schema.LeafColumns[2], originalFloats);
            Write(rowGroup, schema.LeafColumns[3], originalDoubles);
            writer.CloseFile();
        }

        using var reader = schema.CreateReader(FullValueOracle.Source(appended.ToArray()));
        var group = reader.RowGroups[0];
        if (reader.RowGroups.Count != 1 || group.RowCount != 6)
            throw new InvalidOperationException("Optional primitive append changed row-group shape.");
        AssertReadBack(group.Column<bool?>(schema.LeafColumns[0]), originalBools);
        AssertReadBack(group.Column<int?>(schema.LeafColumns[1]), originalInts);
        AssertReadBack(group.Column<float?>(schema.LeafColumns[2]), originalFloats);
        AssertReadBack(group.Column<double?>(schema.LeafColumns[3]), originalDoubles);
    }

    static void Write<T>(RowGroupWriter rowGroup, LeafColumn column, T[] values)
    {
        var serialized = rowGroup.CreateSerializedColumn<T>(column);
        serialized.Serialize(values);
        rowGroup.Write(serialized);
    }

    static void AssertReadBack<T>(RowGroupColumn<T> column, T[] expected)
    {
        var actual = new List<T>();
        foreach (var buffer in column)
            actual.AddRange(buffer.Values.ToArray());
        if (!actual.SequenceEqual(expected.Concat(expected)))
            throw new InvalidOperationException("Optional primitive append changed values.");
    }

    static void RejectRepeatedLatestRowGroup()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.List("items", ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int32))
        ]);
        using var initial = new MemoryStream();
        using (var writer = schema.CreateWriter(initial, new ParquetWriterOptions
               {
                   Compression = CompressionKind.None,
                   SortingColumns = []
               }))
        {
            var column = writer.CreateSerializedColumn<int[]>(schema.LeafColumns[0]);
            column.Serialize([[1, 2], [3]]);
            writer.StartRowGroup().Write(column);
            writer.CloseFile();
        }

        using var appended = new MemoryStream();
        appended.Write(initial.ToArray());
        appended.Position = 0;
        Exception? observed = null;
        try
        {
            using var writer = schema.CreateAppender(appended, new ParquetAppendOptions
            {
                AppendToLatestRowGroup = true,
                WriterOptions = new ParquetWriterOptions
                {
                    Compression = CompressionKind.None,
                    SortingColumns = []
                }
            });
        }
        catch (NotSupportedException error)
        {
            observed = error;
        }

        if (observed is null || !observed.Message.Contains(
            "Appending to the latest row group is not supported for repeated column", StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Expected repeated latest-row-group append rejection, got '{observed?.Message}'.");
    }

    static void AppendLatestRowGroupAfterPriorData()
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("replacement-offset-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        int[][] initialGroups = [[10, 11], [20, 21]];
        using var initial = new MemoryStream();
        using (var writer = schema.CreateWriter(initial, new ParquetWriterOptions
               {
                   Compression = CompressionKind.None,
                   WritePageIndexes = false,
                   SortingColumns = []
               }))
        {
            foreach (var values in initialGroups)
            {
                var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
                column.Serialize(values);
                writer.StartRowGroup().Write(column);
            }
            writer.CloseFile();
        }

        using var appended = new MemoryStream();
        appended.Write(initial.ToArray());
        appended.Position = 0;
        int[] incoming = [22, 23];
        using (var writer = schema.CreateAppender(appended, new ParquetAppendOptions
               {
                   AppendToLatestRowGroup = true,
                   WriterOptions = new ParquetWriterOptions
                   {
                       Compression = CompressionKind.None,
                       WritePageIndexes = false,
                       SortingColumns = []
                   }
               }))
        {
            var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            column.Serialize(incoming);
            writer.StartRowGroup().Write(column);
            writer.CloseFile();
        }

        using var reader = schema.CreateReader(FullValueOracle.Source(appended.ToArray()));
        if (reader.RowGroups.Count != 2 || reader.RowGroups[0].RowCount != 2 || reader.RowGroups[1].RowCount != 4)
            throw new InvalidOperationException("Replacement-offset append changed the row-group layout.");
        AssertExactReadBack(reader.RowGroups[0].Column<int>(schema.LeafColumns[0]), initialGroups[0]);
        AssertExactReadBack(reader.RowGroups[1].Column<int>(schema.LeafColumns[0]), [20, 21, 22, 23]);
    }

    static void AssertExactReadBack<T>(RowGroupColumn<T> column, T[] expected)
    {
        var actual = new List<T>();
        foreach (var buffer in column)
            actual.AddRange(buffer.Values.ToArray());
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException("Replacement-offset append changed values.");
    }

    static void AppendLatestRowGroupAfterPriorIndexesAndBloom()
    {
        var bloom = new ParquetBloomFilterOptions { MaximumBytes = 256 };
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("replacement-offset-indexed-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain), bloomFilter: bloom))
        ]);
        int[][] initialGroups = [[10, 11], [20, 21]];
        using var initial = new MemoryStream();
        using (var writer = schema.CreateWriter(initial, new ParquetWriterOptions
               {
                   Compression = CompressionKind.None,
                   WritePageIndexes = true,
                   SortingColumns = []
               }))
        {
            foreach (var values in initialGroups)
            {
                var rowGroup = writer.StartRowGroup();
                Write(rowGroup, schema.LeafColumns[0], values);
            }
            writer.CloseFile();
        }

        using var appended = new MemoryStream();
        appended.Write(initial.ToArray());
        appended.Position = 0;
        int[] incoming = [22, 23];
        using (var writer = schema.CreateAppender(appended, new ParquetAppendOptions
               {
                   AppendToLatestRowGroup = true,
                   WriterOptions = new ParquetWriterOptions
                   {
                       Compression = CompressionKind.None,
                       WritePageIndexes = true,
                       SortingColumns = []
                   }
               }))
        {
            var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            column.Serialize(incoming);
            writer.StartRowGroup().Write(column);
            writer.CloseFile();
        }

        using var reader = schema.CreateReader(FullValueOracle.Source(appended.ToArray()));
        if (reader.RowGroups.Count != 2 || reader.RowGroups[0].RowCount != 2 || reader.RowGroups[1].RowCount != 4)
            throw new InvalidOperationException("Indexed replacement-offset append changed the row-group layout.");
        AssertExactReadBack(reader.RowGroups[0].Column<int>(schema.LeafColumns[0]), initialGroups[0]);
        AssertExactReadBack(reader.RowGroups[1].Column<int>(schema.LeafColumns[0]), [20, 21, 22, 23]);
    }

    static void AppendExternalLayout(ReadOnlySpan<byte> controls)
    {
        if (controls.Length < 2)
            throw new InvalidOperationException("External append layout seed is truncated.");

        var layout = controls[0];
        var sourceBytes = controls[1..].ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("x", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        using (var sourceReader = schema.CreateReader(new MemoryReadSource(sourceBytes)))
        {
            if (sourceReader.RowGroups.Count != 2)
                throw new InvalidOperationException("External append source must contain two row groups.");
            var chunk = sourceReader.PhysicalReader.Metadata.ColumnChunk(0, 0);
            if (layout == 0 && (chunk.ColumnIndexLength == 0 || chunk.OffsetIndexLength == 0))
                throw new InvalidOperationException("External indexed fixture lacks both page indexes.");
            if (layout == 1 && (chunk.ColumnIndexLength != 0 || chunk.OffsetIndexLength == 0))
                throw new InvalidOperationException("External offset-index fixture has unexpected indexes.");
            if (layout == 2 && (!chunk.HasBloomFilter || chunk.BloomFilterLength == 0))
                throw new InvalidOperationException("External Bloom fixture lacks a nonempty Bloom filter.");
            if (layout == 3 && (!chunk.HasBloomFilter || chunk.BloomFilterLength != 0))
                throw new InvalidOperationException("External zero-length Bloom fixture has unexpected length.");
            if (layout == 4 && chunk.ChunkOffset <=
                sourceReader.PhysicalReader.Metadata.ColumnChunk(1, 0).ChunkOffset)
                throw new InvalidOperationException("External reordered fixture does not place prior data after latest data.");
        }

        using var appended = new MemoryStream();
        appended.Write(sourceBytes);
        appended.Position = 0;
        int[] incoming = [22, 23];
        using (var writer = schema.CreateAppender(appended, new ParquetAppendOptions
               {
                   AppendToLatestRowGroup = true,
                   WriterOptions = new ParquetWriterOptions
                   {
                       Compression = CompressionKind.None,
                       WritePageIndexes = true,
                       SortingColumns = []
                   }
               }))
        {
            var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            column.Serialize(incoming);
            writer.StartRowGroup().Write(column);
            writer.CloseFile();
        }

        using var reader = schema.CreateReader(FullValueOracle.SourceDerivedFrom(appended.ToArray(), sourceBytes));
        if (reader.RowGroups.Count != 2 || reader.RowGroups[0].RowCount != 2 || reader.RowGroups[1].RowCount != 4)
            throw new InvalidOperationException("External replacement-offset append changed row-group shape.");
        if (layout == 4)
        {
            AssertExactReadBack(reader.RowGroups[0].Column<int>(schema.LeafColumns[0]), [20, 21]);
            AssertExactReadBack(reader.RowGroups[1].Column<int>(schema.LeafColumns[0]), [10, 11, 22, 23]);
        }
        else
        {
            AssertExactReadBack(reader.RowGroups[0].Column<int>(schema.LeafColumns[0]), [10, 11]);
            AssertExactReadBack(reader.RowGroups[1].Column<int>(schema.LeafColumns[0]), [20, 21, 22, 23]);
        }
    }
}
