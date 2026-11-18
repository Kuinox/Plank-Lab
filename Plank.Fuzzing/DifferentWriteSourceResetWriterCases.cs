using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Checks resetting an open writer onto a distinct public write source.</summary>
internal static class DifferentWriteSourceResetWriterCases
{
    internal static void Execute(byte seed)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32)
        ]);
        var original = new MemoryStream();
        using var writer = schema.CreateWriter(original);
        WriteValues(writer, schema, Values(seed, 5, 1_000));

        IParquetWriteSource destination = new MemoryWriteSource();
        writer.Reset(destination);
        if (original.CanWrite)
            throw new InvalidOperationException("Reset did not close the prior stream.");

        var expected = Values(seed, 9, -200);
        WriteValues(writer, schema, expected);
        writer.CloseFile();
        if (destination is not MemoryWriteSource memory || memory.CloseCount != 1)
            throw new InvalidOperationException("Reset did not close the replacement write source once.");
        Verify(schema, memory.ToArray(), expected);
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

    static void Verify(ParquetSchema schema, byte[] bytes, int[] expected)
    {
        using var reader = schema.CreateReader(new MemoryReadSource(bytes));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Distinct-source reset retained the wrong file shape.");
        var actual = new List<int>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
            foreach (var value in buffer.Values)
                actual.Add(value);
        if (!actual.ToArray().AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException("Distinct-source reset changed replacement values.");
    }

    sealed class MemoryWriteSource : IParquetWriteSource
    {
        readonly MemoryStream _stream = new();
        internal int CloseCount { get; private set; }

        public void Open(ReadOnlySpan<byte> path, FileMode mode)
            => throw new NotSupportedException();

        public void Close() => CloseCount++;

        public void Write(ulong offset, ReadOnlySpan<byte> source)
        {
            _stream.Position = checked((long)offset);
            _stream.Write(source);
        }

        public void SetLength(ulong length) => _stream.SetLength(checked((long)length));

        public void Flush() => _stream.Flush();

        internal byte[] ToArray() => _stream.ToArray();

        public void Dispose() => _stream.Dispose();
    }
}
