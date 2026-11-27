using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

// Public writer construction with a maximal uint chunk size reaches the
// internal BufferWriter Int32 bound before any large buffer is rented.
internal static class BufferWriterCapacityCases
{
    // Bit 0 keeps the historical choice (chunk vs initial page buffer). Bits 1-2 pick the oversized value
    // (previously only uint.MaxValue), bit 3 swaps in the third buffer option, the initial column buffer,
    // which no case ever sent an oversized value.
    internal static void Execute(byte mode)
    {
        // A dictionary column is what rents the column buffer; a plain required column never does.
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("capacity", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: [EncodingKind.RleDictionary]))
        ]);
        uint oversized = ((mode >> 1) & 3) switch
        {
            0 => uint.MaxValue,
            1 => (uint)int.MaxValue + 1,
            2 => (uint)int.MaxValue + 2,
            _ => 0xFFFF_0000u
        };
        var target = (mode & 8) != 0 ? 2 : mode & 1; // 0 chunk, 1 page, 2 column
        using var stream = new MemoryStream();
        try
        {
            using var writer = schema.CreateWriter(stream, new ParquetWriterOptions
            {
                BufferChunkSizeBytes = target == 0 ? oversized : 64 * 1024,
                InitialPageBufferBytes = target == 1 ? oversized : 320 * 1024,
                InitialColumnBufferBytes = target == 2 ? oversized : 4096
            });
            var column = writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            column.Serialize([1, 1, 2, 2]);
            writer.StartRowGroup().Write(column);
            writer.CloseFile();
        }
        catch (ArgumentOutOfRangeException exception)
            when (target == 2 || exception.ParamName == (target == 0 ? "chunkSizeBytes" : "initialBufferBytes"))
        {
            return;
        }

        throw new InvalidOperationException("Oversized buffer size was accepted.");
    }
}
