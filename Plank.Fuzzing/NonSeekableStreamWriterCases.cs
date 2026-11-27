using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Exercises bounded, strictly readable writes to sequential output streams.</summary>
internal static class NonSeekableStreamWriterCases
{
    const int RowCount = 16_384;

    internal static void Execute(byte seed)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32)
        ]);
        var random = new Random(seed);
        var expected = new int[RowCount];
        for (var i = 0; i < expected.Length; i++)
            expected[i] = random.Next(int.MinValue, int.MaxValue);

        var first = new NonSeekableOutputStream();
        var second = new NonSeekableOutputStream();
        var writer = schema.CreateWriter(first, new ParquetWriterOptions
        {
            Compression = CompressionKind.Gzip,
            TargetDataPageSizeBytes = 128 * 1024
        });

        WriteValues(writer, schema, expected);
        writer.CloseFile();
        writer.Reset(second);
        WriteValues(writer, schema, expected);
        writer.CloseFile();

        ValidateReadback(schema, first.ToArray(), expected, "first");
        ValidateReadback(schema, second.ToArray(), expected, "reset");
    }

    static void WriteValues(ParquetWriter writer, ParquetSchema schema, int[] values)
    {
        var rowGroup = writer.StartRowGroup();
        var column = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize(values);
        rowGroup.Write(column);
    }

    static void ValidateReadback(ParquetSchema schema, byte[] bytes, int[] expected, string fileName)
    {
        using var source = FullValueOracle.Source(bytes);
        using var reader = schema.CreateReader(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException($"Non-seekable {fileName} output changed its row-group shape.");

        var actual = new List<int>(expected.Length);
        foreach (var buffer in reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
            foreach (var value in buffer.Values)
                actual.Add(value);
        if (!actual.ToArray().AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException($"Non-seekable {fileName} output failed strict value readback.");
    }

    sealed class NonSeekableOutputStream : Stream
    {
        readonly MemoryStream _backing = new();

        internal byte[] ToArray()
            => _backing.ToArray();

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length
            => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
            => _backing.Flush();

        public override void Write(byte[] buffer, int offset, int count)
            => _backing.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer)
            => _backing.Write(buffer);

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
            => base.Dispose(disposing);
    }
}
