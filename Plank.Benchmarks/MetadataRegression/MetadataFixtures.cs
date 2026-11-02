using System.Collections.Immutable;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Benchmarks.MetadataRegression;

public static class MetadataFixtures
{
    public static void Generate(string directory, bool quick = false)
    {
        Directory.CreateDirectory(directory);
        WriteFlat(Path.Combine(directory, "wide.parquet"), quick ? 24 : 1200, 3, 16, false, ParquetDataPageVersion.V2);
        WriteFlat(Path.Combine(directory, "row-groups.parquet"), 3, quick ? 20 : 1200, 16, false, ParquetDataPageVersion.V2);
        WriteFlat(Path.Combine(directory, "pages-v1.parquet"), 1, 1, quick ? 4096 : 262144, true, ParquetDataPageVersion.V1);
        WriteFlat(Path.Combine(directory, "pages-v2.parquet"), 1, 1, quick ? 4096 : 262144, true, ParquetDataPageVersion.V2);
        WriteNested(Path.Combine(directory, "nested.parquet"));
    }

    static void WriteNested(string path)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredGroup("container",
                ColumnDefinition.List("outer", ColumnDefinition.List("inner", ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32))),
                ColumnDefinition.Map("map", ColumnDefinition.RequiredLeaf("key", ParquetPhysicalType.Int32),
                    ColumnDefinition.OptionalLeaf("value", ParquetPhysicalType.Int32))),
            ColumnDefinition.RequiredLeaf("date", ParquetPhysicalType.Int32, logicalType: new LogicalType.Date())
        ]);
        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            CreatedBy = "Plank metadata regression fixtures", KeyValueMetadata = [new("suite", "nested"), new("version", "1")],
            InitialColumnBufferBytes = 4096, InitialPageBufferBytes = 4096
        });
        var group = writer.StartRowGroup();
        var list = group.CreateSerializedColumn<int[][]>(schema.LeafColumns[0]);
        list.Serialize([[[1, 2], [], [3]], [], [[4]]]); group.Write(list);
        var keys = group.CreateSerializedColumn<int[]>(schema.LeafColumns[1]);
        keys.Serialize([[1, 2], [], [3]]); group.Write(keys);
        var values = group.CreateSerializedColumn<int?[]>(schema.LeafColumns[2]);
        values.Serialize([[10, null], [], [30]]); group.Write(values);
        var dates = group.CreateSerializedColumn<int>(schema.LeafColumns[3]);
        dates.Serialize([100, 200, 300]); group.Write(dates);
        writer.CloseFile(); File.WriteAllBytes(path, stream.ToArray());
    }

    static void WriteFlat(string path, int columns, int groups, int rows, bool pages, ParquetDataPageVersion version)
    {
        var definitions = Enumerable.Range(0, columns).Select(i => ColumnDefinition.RequiredLeaf($"column_{i:D4}",
            ParquetPhysicalType.Int32, new ColumnOptions(ParquetRepetition.Required, [EncodingKind.Plain],
                bloomFilter: pages ? ParquetBloomFilterOptions.Default : null))).ToImmutableArray();
        var schema = new ParquetSchema(definitions);
        using var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None, DataPageVersion = version, WritePageIndexes = true,
            TargetDataPageSizeBytes = pages ? 128u : 4096u,
            InitialColumnBufferBytes = 4096, InitialPageBufferBytes = 4096,
            CreatedBy = "Plank metadata regression fixtures",
            KeyValueMetadata = [new("suite", "metadata-regression"), new("deterministic", "true")]
        });
        var values = Enumerable.Range(0, rows).Select(i => i * 13 % 100003).ToArray();
        for (var g = 0; g < groups; g++)
        {
            var rowGroup = writer.StartRowGroup();
            for (var c = 0; c < columns; c++)
            {
                var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[c]);
                column.Serialize(values);
                rowGroup.Write(column);
            }
        }
        writer.CloseFile();
        File.WriteAllBytes(path, stream.ToArray());
    }
}
