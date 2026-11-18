using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Checks resetting an open file onto the same seekable stream.</summary>
internal static class SameStreamResetWriterCases
{
    internal static void Execute(byte seed)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32)
        ]);
        var stream = new MemoryStream();
        using var writer = schema.CreateWriter(stream);

        var stale = Values(seed, 5, 1_000);
        WriteValues(writer, schema, stale);

        // Reset before finishing the first file exercises the same-stream path and
        // verifies that the old row-group bytes are replaced by a valid new file.
        writer.Reset(stream);
        var expected = Values(seed, 9, -200);
        WriteValues(writer, schema, expected);
        writer.CloseFile();

        using var reader = schema.CreateReader(new MemoryReadSource(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Same-stream reset retained the old file shape.");

        var actual = new List<int>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
            foreach (var value in buffer.Values)
                actual.Add(value);
        if (!actual.ToArray().AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException("Same-stream reset changed the replacement values.");
    }

    static int[] Values(byte seed, int count, int offset)
    {
        var values = new int[count];
        for (var i = 0; i < values.Length; i++)
            values[i] = unchecked((seed - 128) * 1_003 + offset + i * 37);
        return values;
    }

    static void WriteValues(ParquetWriter writer, ParquetSchema schema, int[] values)
    {
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize(values);
        rowGroup.Write(column);
    }
}
