using Plank.Reading.Physical;
using Plank.Schema;

// Plank master 3a6a28a: ParquetColumnChunkInfo is a public readonly record struct; its generated Equals/GetHashCode
// compare the ParquetColumnChunkEncodings member, whose storage is an [InlineArray] struct with no custom equality.
// Expected: value equality (true, same hash). Observed: NotSupportedException on the first Equals call of the process.
var schema = new ParquetSchema([ColumnDefinition.RequiredLeaf("a", ParquetPhysicalType.Int32)]);
using var stream = new MemoryStream();
var writer = schema.CreateWriter(stream);
var group = writer.StartRowGroup();
var column = group.CreateSerializedColumn<int>(schema.LeafColumns[0]);
column.Serialize([1, 2, 3]);
group.Write(column);
writer.CloseFile();

using var reader = new ParquetFileReader();
reader.Reset(new MemoryStream(stream.ToArray(), writable: false));
var a = reader.Metadata.ColumnChunk(0, 0);
var b = reader.Metadata.ColumnChunks[0];
for (var attempt = 1; attempt <= 3; attempt++)
{
    foreach (var (name, call) in new (string, Func<object>)[]
    {
        ("Equals(ParquetColumnChunkInfo)", () => a.Equals(b)),
        ("Equals(object)", () => ((object)a).Equals(b)),
        ("GetHashCode equal", () => a.GetHashCode() == b.GetHashCode()),
        ("== operator", () => a == b),
    })
    {
        try { Console.WriteLine($"attempt {attempt}: {name} => {call()}"); }
        catch (Exception e) { Console.WriteLine($"attempt {attempt}: {name} THREW {e.GetType().Name}: {e.Message}"); }
    }
}
