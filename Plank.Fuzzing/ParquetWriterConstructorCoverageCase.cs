using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

internal static class ParquetWriterConstructorCoverageCase
{
    internal static void Execute(byte mode)
    {
        if (mode % 2 == 0)
        {
            var empty = new ParquetSchema([]);
            using var stream = new MemoryStream();
            var writer = empty.CreateWriter(stream);
            writer.CloseFile();
            if (stream.ToArray().Length < 8)
                throw new InvalidOperationException("Empty-schema writer produced no Parquet file.");
            return;
        }

        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.Int32)
        ]);
        using var destination = new InMemoryWriteSource();
        try
        {
            _ = schema.CreateAppender((IParquetReadSource)null!, destination);
        }
        catch (ArgumentNullException exception) when (exception.ParamName == "appendSource")
        {
            return;
        }
        throw new InvalidOperationException("Null append source was not rejected by the writer.");
    }

    sealed class InMemoryWriteSource : IParquetWriteSource
    {
        readonly MemoryStream _stream = new();

        public void Open(ReadOnlySpan<byte> path, FileMode mode) => throw new NotSupportedException();
        public void Close() { }
        public void Write(ulong offset, ReadOnlySpan<byte> source)
        {
            _stream.Position = checked((long)offset);
            _stream.Write(source);
        }
        public void SetLength(ulong length) => _stream.SetLength(checked((long)length));
        public void Flush() => _stream.Flush();
        public void Dispose() => _stream.Dispose();
    }
}
