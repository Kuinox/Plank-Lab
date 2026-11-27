using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

internal static class DecimalBinaryStatisticsCoverageCase
{
    internal static void Execute(byte control)
    {
        // Any control byte >= 2 draws the third value set, so the expectation below must use the same
        // normalised variant (mutated DBS1 inputs with control > 2 used to fault on a correct library).
        var order = control >= 2 ? 2 : control;
        var definition = ColumnDefinition.Leaf("decimal-binary-bytes",
            ParquetPhysicalType.ByteArray,
            new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)),
            new LogicalType.Decimal(9, 0));
        var schema = new ParquetSchema([definition]);
        byte[][] values = order switch
        {
            0 => [[], [], [0], [0x7f], [0x80], [0xff], [0, 1], [0xff, 0xfe]],
            1 => [[0], [], [0x7f], [0x80], [0xff], [0, 1], [0xff, 0xfe]],
            _ => [[1], [2], [1, 0], [0xff], [0xff, 0], [0x80], [0x7f], [], []]
        };

        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream,
            new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var serialized = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        rowGroup.Write(serialized);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        var statistics = reader.RowGroups[0].GetColumnMetadata(0).Statistics;
        byte[] expectedMin = order == 2 ? [0xff, 0] : [0x80];
        byte[] expectedMax = order == 2 ? [1, 0] : [0x7f];
        if (!statistics.HasMinimum || !statistics.HasMaximum ||
            !statistics.Minimum.SequenceEqual(expectedMin) ||
            !statistics.Maximum.SequenceEqual(expectedMax))
            throw new InvalidOperationException("Decimal binary statistics changed.");
    }
}
