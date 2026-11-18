using System.Collections.Immutable;
using Plank.Schema;
using Plank.Writing;

var encodings = ImmutableArray.Create(EncodingKind.Plain);
foreach (var enabled in new[] { false, true })
{
    Run("required", enabled, new decimal[] { 1.23m, -4.56m });
    Run("optional", enabled, new decimal?[] { 1.23m, null, -4.56m });
}

void Run<T>(string shape, bool bloomEnabled, T[] values)
{
    var options = new ColumnOptions(encodings: encodings,
        bloomFilter: bloomEnabled ? new ParquetBloomFilterOptions
        {
            FalsePositiveProbability = 0.001,
            MaximumBytes = 256
        } : null);
    var column = shape == "required"
        ? ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32, options,
            new LogicalType.Decimal(9, 2))
        : ColumnDefinition.OptionalLeaf("value", ParquetPhysicalType.Int32, options,
            new LogicalType.Decimal(9, 2));
    var schema = new ParquetSchema([column]);
    using var stream = new MemoryStream();
    var writer = schema.CreateWriter(stream,
        new ParquetWriterOptions { Compression = CompressionKind.None });
    try
    {
        var serialized = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();
        Console.WriteLine($"{shape} bloom={bloomEnabled}: success");
    }
    catch (NotSupportedException e)
    {
        Console.WriteLine($"{shape} bloom={bloomEnabled}: {e.GetType().Name}: {e.Message}");
    }
}
