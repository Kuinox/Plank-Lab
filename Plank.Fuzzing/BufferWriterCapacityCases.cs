using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

// Public writer construction with a maximal uint chunk size reaches the
// internal BufferWriter Int32 bound before any large buffer is rented.
internal static class BufferWriterCapacityCases
{
    internal static void Execute(byte mode)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("capacity", ParquetPhysicalType.Int32)
        ]);
        using var stream = new MemoryStream();
        try
        {
            using var writer = schema.CreateWriter(stream, new ParquetWriterOptions
            {
                BufferChunkSizeBytes = (mode & 1) == 0 ? uint.MaxValue : 64 * 1024,
                InitialPageBufferBytes = (mode & 1) == 0 ? 320 * 1024 : uint.MaxValue
            });
            var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            column.Serialize([1]);
            writer.StartRowGroup().Write(column);
            writer.CloseFile();
        }
        catch (ArgumentOutOfRangeException exception)
            when (exception.ParamName == ((mode & 1) == 0 ? "chunkSizeBytes" : "initialBufferBytes"))
        {
            return;
        }

        throw new InvalidOperationException("Oversized buffer size was accepted.");
    }
}
