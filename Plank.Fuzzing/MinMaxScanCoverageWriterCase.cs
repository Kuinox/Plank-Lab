using System.Buffers.Binary;
using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Reaches Vector128 PLAIN copy/min/max and the scalar-tail comparisons via the public writer.</summary>
internal static class MinMaxScanCoverageWriterCase
{
    internal static void Execute()
    {
        // With four INT32 lanes and four-way unrolling, 301 values exercise the
        // unrolled block, vector remainder, and one-element scalar tail.
        var lowTail = CreateValues(int.MinValue);
        var highTail = CreateValues(int.MaxValue);
        var schema = new ParquetSchema([
            ColumnDefinition.Leaf("minmax-low-tail", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain))),
            ColumnDefinition.Leaf("minmax-high-tail", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);

        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var lowColumn = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        lowColumn.Serialize(lowTail);
        rowGroup.Write(lowColumn);
        var highColumn = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[1]);
        highColumn.Serialize(highTail);
        rowGroup.Write(highColumn);
        writer.CloseFile();

        using var source = new MemoryReadSource(stream.ToArray());
        using var reader = schema.CreateReader(source);
        AssertColumn(reader, 0, lowTail, int.MinValue, 600);
        AssertColumn(reader, 1, highTail, -200, int.MaxValue);
    }

    static int[] CreateValues(int tail)
    {
        var values = Enumerable.Range(0, 301).Select(index => index - 150).ToArray();
        // These put the vector minimum and maximum in lanes other than lane 0,
        // so both lane-wise comparisons take true and false outcomes.
        values[0] = 500;
        values[1] = -200;
        values[2] = 600;
        values[^1] = tail;
        return values;
    }

    static void AssertColumn(Plank.Reading.Logical.ParquetReader reader, int columnIndex, int[] expected,
        int expectedMinimum, int expectedMaximum)
    {
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("MinMaxScan coverage case changed the row-group shape.");

        var actual = new List<int>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<int>(columnIndex))
            actual.AddRange(buffer.Values);
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException($"MinMaxScan coverage case changed column {columnIndex} values.");

        var statistics = reader.RowGroups[0].GetColumnMetadata(columnIndex).Statistics;
        if (!statistics.HasMinimum || !statistics.HasMaximum || !statistics.IsMinimumExact
            || !statistics.IsMaximumExact
            || !statistics.Minimum.SequenceEqual(EncodeInt32(expectedMinimum))
            || !statistics.Maximum.SequenceEqual(EncodeInt32(expectedMaximum)))
            throw new InvalidOperationException($"MinMaxScan coverage case changed column {columnIndex} statistics.");
    }

    static byte[] EncodeInt32(int value)
    {
        var bytes = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        return bytes;
    }
}
