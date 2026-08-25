using System.IO.MemoryMappedFiles;
using Plank.Schema;
using Plank.Writing;

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: BaselineWriter <values.i64le> <output.parquet>");
    return 2;
}

var input = Path.GetFullPath(args[0]);
var output = Path.GetFullPath(args[1]);
var bytes = new FileInfo(input).Length;
if (bytes != 225_000_000L * sizeof(long))
    throw new InvalidDataException($"expected 1,800,000,000 input bytes, found {bytes}");

var schema = new ParquetSchema([
    ColumnDefinition.RequiredLeaf(
        "TradeTimestamp",
        ParquetPhysicalType.Int64,
        new ColumnOptions(encodings: [EncodingKind.DeltaBinaryPacked]),
        new LogicalType.Timestamp(TimeUnit.Micros, true))
]);
var options = new ParquetWriterOptions
{
    Compression = CompressionKind.Zstd,
    CompressionLevel = 3,
    WritePageIndexes = true,
    WritePageStatistics = true
};

Directory.CreateDirectory(Path.GetDirectoryName(output)!);
using var mapped = MemoryMappedFile.CreateFromFile(input, FileMode.Open, null, 0,
    MemoryMappedFileAccess.Read);
using var view = mapped.CreateViewAccessor(0, bytes, MemoryMappedFileAccess.Read);
unsafe
{
    byte* pointer = null;
    view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
    try
    {
        pointer += view.PointerOffset;
        var values = new ReadOnlySpan<long>(pointer, 225_000_000);
        using var stream = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None,
            1024 * 1024, FileOptions.SequentialScan);
        using var writer = schema.CreateWriter(stream, options);
        var column = writer.CreateSerializedColumn<long>(schema.LeafColumns[0]);
        column.Serialize(values);
        var rowGroup = writer.StartRowGroup();
        rowGroup.Write(column);
        writer.CloseFile();
    }
    finally
    {
        view.SafeMemoryMappedViewHandle.ReleasePointer();
    }
}

Console.WriteLine(new FileInfo(output).Length);
return 0;
