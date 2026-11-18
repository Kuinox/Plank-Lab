using System.Collections.Immutable;
using Plank;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

if (args.Length != 1)
{
    Console.Error.WriteLine("usage: dotnet run --project OptionalFixedMemoryPlain.csproj -- <output.parquet>");
    return 2;
}

ReadOnlyMemory<byte>?[] values =
[
    new byte[] { 0x10, 0x20, 0x30, 0x40 },
    null,
    new byte[] { 0x50, 0x60, 0x70, 0x80 }
];
byte[]?[] expected = [[0x10, 0x20, 0x30, 0x40], null, [0x50, 0x60, 0x70, 0x80]];
var schema = new ParquetSchema(
[
    ColumnDefinition.OptionalLeaf("fixed-memory-plain", ParquetPhysicalType.FixedLenByteArray,
        new ColumnOptions(ParquetRepetition.Optional, typeLength: 4,
            encodings: ImmutableArray.Create(EncodingKind.Plain)))
]);

using var output = new MemoryStream();
var writer = schema.CreateWriter(output, new ParquetWriterOptions { Compression = CompressionKind.None });
var column = writer.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
column.Serialize(values);
writer.StartRowGroup().Write(column);
writer.CloseFile();

var parquetBytes = output.ToArray();
if (parquetBytes.Length == 0)
    throw new InvalidOperationException("Writer closed without producing Parquet bytes.");
File.WriteAllBytes(args[0], parquetBytes);
Console.WriteLine($"writer closed successfully; wrote {parquetBytes.Length} bytes to {args[0]}");

try
{
    using var source = new MemoryReadSource(parquetBytes);
    using var reader = schema.CreateReader(source);
    var actual = new List<byte[]?>();
    foreach (var buffer in reader.RowGroups[0].Column<byte>(0))
        for (var i = 0; i < buffer.Count; i++)
            actual.Add(buffer.IsNull(i) ? null : buffer.GetValue(i).ToArray());

    var equal = actual.Count == expected.Length;
    for (var i = 0; equal && i < expected.Length; i++)
        equal = expected[i] is null
            ? actual[i] is null
            : actual[i] is { } bytes && bytes.AsSpan().SequenceEqual(expected[i]);
    if (equal)
        throw new InvalidOperationException("The optional FixedLenByteArray memory values unexpectedly round-tripped.");

    throw new InvalidOperationException("Plank decoded the file but returned different optional fixed-width values.");
}
catch (CorruptParquetException error)
{
    Console.WriteLine($"Plank reader rejected writer output: {error.GetType().Name}: {error.Message}");
    return 0;
}
