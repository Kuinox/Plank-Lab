using System.Buffers.Binary;
using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Bounded public-writer cases for fixed-width BSS and decimal DELTA_BINARY_PACKED.</summary>
internal static class FixedBinaryDeltaWriterCases
{
    static readonly ImmutableArray<EncodingKind> ByteStreamSplit = [EncodingKind.ByteStreamSplit];
    static readonly ImmutableArray<EncodingKind> DeltaBinaryPacked = [EncodingKind.DeltaBinaryPacked];

    internal static void Execute(ReadOnlySpan<byte> controls)
    {
        switch (controls.IsEmpty ? 0 : controls[0])
        {
            case 0:
                WriteFixedWidthBinary();
                break;
            case 1:
                WriteDecimalDeltaInt32();
                break;
            default:
                // Mutations outside the two named cases remain bounded and inert.
                break;
        }
    }

    static void WriteFixedWidthBinary()
    {
        byte[][] expected =
        [
            [0x10, 0x20, 0x30],
            [0x40, 0x50, 0x60],
            [0x70, 0x80, 0x90],
            [0xA0, 0xB0, 0xC0]
        ];
        var definition = ColumnDefinition.RequiredLeaf("fixed-bss", ParquetPhysicalType.FixedLenByteArray,
            new ColumnOptions(encodings: ByteStreamSplit, typeLength: 3));
        var schema = new ParquetSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        column.Serialize(expected);
        rowGroup.Write(column);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Fixed-width BSS changed the row-group shape.");
        var actual = new List<byte[]>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<byte>(0))
            for (var i = 0; i < buffer.Count; i++)
                actual.Add(buffer.GetValue(i).ToArray());
        if (actual.Count != expected.Length)
            throw new InvalidOperationException("Fixed-width BSS changed the binary value count.");
        for (var i = 0; i < expected.Length; i++)
            if (!actual[i].AsSpan().SequenceEqual(expected[i]))
                throw new InvalidOperationException($"Fixed-width BSS changed binary value {i}.");

        var statistics = reader.RowGroups[0].GetColumnMetadata(0).Statistics;
        if (!statistics.HasMinimum || !statistics.HasMaximum
            || !statistics.Minimum.SequenceEqual(expected[0])
            || !statistics.Maximum.SequenceEqual(expected[^1])
            || statistics.NullCount != 0
            || !statistics.IsMinimumExact || !statistics.IsMaximumExact)
            throw new InvalidOperationException("Fixed-width BSS footer statistics mismatch.");
    }

    static void WriteDecimalDeltaInt32()
    {
        decimal[] expected = [-12.34m, 0m, 12.34m, 99.99m];
        var definition = ColumnDefinition.RequiredLeaf("decimal-delta", ParquetPhysicalType.Int32,
            new ColumnOptions(encodings: DeltaBinaryPacked), new LogicalType.Decimal(9, 2));
        var schema = new ParquetSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<decimal>(schema.LeafColumns[0]);
        column.Serialize(expected);
        rowGroup.Write(column);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Decimal DELTA changed the row-group shape.");
        var actual = new List<decimal>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<decimal>(0))
            actual.AddRange(buffer.Values);
        if (actual.Count != expected.Length || !actual.SequenceEqual(expected))
            throw new InvalidOperationException("Decimal DELTA changed logical values.");

        var minimum = new byte[sizeof(int)];
        var maximum = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(minimum, -1234);
        BinaryPrimitives.WriteInt32LittleEndian(maximum, 9999);
        var statistics = reader.RowGroups[0].GetColumnMetadata(0).Statistics;
        if (!statistics.HasMinimum || !statistics.HasMaximum
            || !statistics.Minimum.SequenceEqual(minimum)
            || !statistics.Maximum.SequenceEqual(maximum)
            || statistics.NullCount != 0
            || !statistics.IsMinimumExact || !statistics.IsMaximumExact)
            throw new InvalidOperationException("Decimal DELTA footer statistics mismatch.");
    }
}
