using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Exercises buffer constructors through public writer and reader APIs.</summary>
internal static class ColumnBufferConstructorCoverageCases
{
    internal static void Run(IParquetBufferPool bufferPool)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("number", ParquetPhysicalType.Int32,
                options: new ColumnOptions(encodings: [EncodingKind.Plain])),
            ColumnDefinition.RequiredLeaf("borrowed", ParquetPhysicalType.ByteArray,
                options: new ColumnOptions(encodings: [EncodingKind.Plain])),
            ColumnDefinition.RequiredLeaf("owned", ParquetPhysicalType.ByteArray,
                options: new ColumnOptions(encodings: [EncodingKind.RleDictionary]))
        ]);
        var expectedNumbers = new[] { 11, -7, 42 };
        byte[][] expectedBytes = [[0x10, 0x11], [0x20], [0x30, 0x31, 0x32]];
        var parquetBytes = WriteFile(schema, expectedNumbers, expectedBytes);

        using var source = new MemoryReadSource(parquetBytes);
        using var reader = schema.CreateReader(source, new ParquetReaderOptions { BufferPool = bufferPool });
        var group = reader.RowGroups[0];

        var numbers = new List<int>();
        foreach (var buffer in group.Column<int>(schema.LeafColumns[0]))
            numbers.AddRange(buffer.Values.ToArray());
        if (!numbers.SequenceEqual(expectedNumbers))
            throw new InvalidDataException("The borrowed fixed-width column values changed.");

        ReadBinary(group.Column<byte>(schema.LeafColumns[1]), expectedBytes,
            "borrowed variable-length column");
        ReadBinary(group.Column<byte>(schema.LeafColumns[2]), expectedBytes,
            "owned variable-length column");
        ReadBorrowedBinaryThroughRowApi(schema, parquetBytes, expectedNumbers, expectedBytes);
    }

    static byte[] WriteFile(ParquetSchema schema, int[] numbers, byte[][] values)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        var rowGroup = writer.StartRowGroup();
        var numberColumn = rowGroup.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        numberColumn.Serialize(numbers);
        rowGroup.Write(numberColumn);
        for (var i = 1; i < schema.LeafColumns.Length; i++)
        {
            var column = rowGroup.CreateSerializedColumn<byte[]>(schema.LeafColumns[i]);
            column.Serialize(values);
            rowGroup.Write(column);
        }
        writer.CloseFile();
        return stream.ToArray();
    }

    static void ReadBinary(RowGroupColumn<byte> column, byte[][] expected, string label)
    {
        var actual = new List<byte[]>();
        foreach (var buffer in column)
            for (var i = 0; i < buffer.Count; i++)
                actual.Add(buffer.GetValue(i).ToArray());
        if (actual.Count != expected.Length)
            throw new InvalidDataException($"The {label} value count changed.");
        for (var i = 0; i < expected.Length; i++)
            if (!actual[i].AsSpan().SequenceEqual(expected[i]))
                throw new InvalidDataException($"The {label} values changed.");
    }

    static void ReadBorrowedBinaryThroughRowApi(ParquetSchema schema, byte[] parquetBytes,
        int[] expectedNumbers, byte[][] expectedBytes)
    {
        var number = new RowApiColumnDescriptor<int>("number", schema.LeafColumns[0]);
        var borrowed = new RowApiColumnDescriptor<byte[]>("borrowed", schema.LeafColumns[1]);
        var owned = new RowApiColumnDescriptor<byte[]>("owned", schema.LeafColumns[2]);
        RowApiColumnDescriptor[] descriptors = [number, borrowed, owned];
        var options = new RowReaderOptions { Execution = new ParquetExecutionOptions { WorkerCount = 1 } };
        using var source = new MemoryReadSource(parquetBytes);
        using var rows = new RowReaderCore(source, schema, descriptors, projection: null, options,
            schemaEvolution: null);
        var index = 0;
        while (rows.MoveNext())
        {
            if (index >= expectedNumbers.Length || rows.GetCurrent(number) != expectedNumbers[index] ||
                !rows.GetCurrent(borrowed).AsSpan().SequenceEqual(expectedBytes[index]) ||
                !rows.GetCurrent(owned).AsSpan().SequenceEqual(expectedBytes[index]))
                throw new InvalidDataException("Borrowed Row API column values changed.");
            index++;
        }
        if (index != expectedNumbers.Length)
            throw new InvalidDataException("Borrowed Row API row count changed.");
    }
}
