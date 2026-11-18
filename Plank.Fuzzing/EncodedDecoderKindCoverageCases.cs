using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Physical;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Drives encoded-page dispatch from public Parquet files and page-header encoding changes.</summary>
internal static class EncodedDecoderKindCoverageCases
{
    static readonly byte[][] BinaryValues = [[0x10, 0x11], [0x20], [0x30, 0x31, 0x32]];
    static readonly Guid[] GuidValues =
    [
        Guid.Empty,
        Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
        Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100")
    ];
    static bool _reportedSourcePageEncoding;

    internal static void Run(IParquetBufferPool bufferPool)
    {
        var binarySchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("binary", ParquetPhysicalType.ByteArray,
                options: new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        var binaryFile = WriteBinary(binarySchema, BinaryValues);
        foreach (var encoding in new[]
        {
            EncodingKind.Rle, EncodingKind.BitPacked, EncodingKind.DeltaBinaryPacked,
            EncodingKind.ByteStreamSplit, EncodingKind.RleDictionary, EncodingKind.PlainDictionary,
            EncodingKind.DeltaLengthByteArray, EncodingKind.DeltaByteArray, EncodingKind.Alp
        })
            ReadBinary(binarySchema, PatchDataPageEncoding(binaryFile, encoding), bufferPool);

        var fixedBinarySchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("uuid", ParquetPhysicalType.FixedLenByteArray,
                options: new ColumnOptions(typeLength: 16, encodings: ImmutableArray.Create(EncodingKind.Plain)),
                logicalType: new LogicalType.Uuid())
        ]);
        var fixedBinaryFile = WriteGuids(fixedBinarySchema, GuidValues);
        ReadBinary(new ParquetSchema([
                ColumnDefinition.RequiredLeaf("uuid", ParquetPhysicalType.FixedLenByteArray,
                    options: new ColumnOptions(typeLength: 16), logicalType: new LogicalType.Uuid())
            ]), PatchDataPageEncoding(fixedBinaryFile, EncodingKind.DeltaLengthByteArray), bufferPool);
        ReadGuid(fixedBinarySchema, PatchDataPageEncoding(fixedBinaryFile, EncodingKind.DeltaByteArray), bufferPool);

        var intSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("number", ParquetPhysicalType.Int32,
                options: new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        var intFile = WriteInt32(intSchema, [11, -7, 42]);
        foreach (var encoding in new[]
        {
            EncodingKind.DeltaBinaryPacked, EncodingKind.DeltaByteArray, EncodingKind.Alp,
            EncodingKind.ByteStreamSplit
        })
            ReadInt32(intSchema, PatchDataPageEncoding(intFile, encoding), bufferPool);

        var floatSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("real", ParquetPhysicalType.Float,
                options: new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        ReadFloat(floatSchema, PatchDataPageEncoding(WriteFloat(floatSchema, [1.25f, -3.5f]),
            EncodingKind.Alp), bufferPool);
        ReadFloat(floatSchema, PatchDataPageEncoding(WriteFloat(floatSchema, [1.25f, -3.5f]),
            EncodingKind.DeltaBinaryPacked), bufferPool);

        var boolSchema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("flag", ParquetPhysicalType.Boolean,
                options: new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.Plain)))
        ]);
        ReadBoolean(boolSchema, PatchDataPageEncoding(WriteBoolean(boolSchema, [true, false, true]),
            EncodingKind.Rle), bufferPool);
        ReadBoolean(boolSchema, PatchDataPageEncoding(WriteBoolean(boolSchema, [true, false, true]),
            EncodingKind.DeltaBinaryPacked), bufferPool);
    }

    static byte[] PatchDataPageEncoding(byte[] file, EncodingKind encoding)
    {
        using var source = new MemoryReadSource(file);
        using var reader = new ParquetFileReader();
        reader.Reset(source);
        var offset = checked((int)reader.Metadata.ColumnChunk(0, 0).DataPageOffset);
        var original = PageHeaderReader.Read(file.AsSpan(offset));
        if (original.Type is not (PageHeaderType.DataPage or PageHeaderType.DataPageV2))
            throw new InvalidDataException($"The encoding-probe source is not a data page ({original.Type}).");
        if (!_reportedSourcePageEncoding)
        {
            Console.WriteLine($"encoded-decoder source page: {original.Type}/{original.Encoding}");
            _reportedSourcePageEncoding = true;
        }

        var header = file.AsSpan(offset, original.HeaderLength).ToArray();
        var originalEnum = checked((byte)((int)original.Encoding << 1));
        var encodedEnum = checked((byte)((int)encoding << 1));
        for (var i = header.Length - 1; i >= 0; i--)
        {
            if (header[i] != originalEnum)
                continue;
            header[i] = encodedEnum;
            try
            {
                if (PageHeaderReader.Read(header).Encoding == encoding)
                {
                    header.CopyTo(file.AsSpan(offset, header.Length));
                    return file;
                }
            }
            catch (CorruptParquetException)
            {
            }
            header[i] = 0;
        }

        throw new InvalidDataException($"Could not patch the page encoding to {encoding}.");
    }

    static byte[] WriteBinary(ParquetSchema schema, byte[][] values)
    {
        using var stream = new MemoryStream();
        var writer = CreateWriter(schema, stream);
        var group = writer.StartRowGroup();
        var column = group.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
        column.Serialize(values);
        group.Write(column);
        writer.CloseFile();
        return stream.ToArray();
    }

    static byte[] WriteGuids(ParquetSchema schema, Guid[] values)
    {
        using var stream = new MemoryStream();
        var writer = CreateWriter(schema, stream);
        var group = writer.StartRowGroup();
        var column = group.CreateSerializedColumn<Guid>(schema.LeafColumns[0]);
        column.Serialize(values);
        group.Write(column);
        writer.CloseFile();
        return stream.ToArray();
    }

    static byte[] WriteInt32(ParquetSchema schema, int[] values)
    {
        using var stream = new MemoryStream();
        var writer = CreateWriter(schema, stream);
        var group = writer.StartRowGroup();
        var column = group.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize(values);
        group.Write(column);
        writer.CloseFile();
        return stream.ToArray();
    }

    static byte[] WriteFloat(ParquetSchema schema, float[] values)
    {
        using var stream = new MemoryStream();
        var writer = CreateWriter(schema, stream);
        var group = writer.StartRowGroup();
        var column = group.CreateSerializedColumn<float>(schema.LeafColumns[0]);
        column.Serialize(values);
        group.Write(column);
        writer.CloseFile();
        return stream.ToArray();
    }

    static byte[] WriteBoolean(ParquetSchema schema, bool[] values)
    {
        using var stream = new MemoryStream();
        var writer = CreateWriter(schema, stream);
        var group = writer.StartRowGroup();
        var column = group.CreateSerializedColumn<bool>(schema.LeafColumns[0]);
        column.Serialize(values);
        group.Write(column);
        writer.CloseFile();
        return stream.ToArray();
    }

    static ParquetWriter CreateWriter(ParquetSchema schema, Stream stream)
        => schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = ParquetDataPageVersion.V1,
            TargetDataPageSizeBytes = 1_048_576
        });

    static void ReadBinary(ParquetSchema schema, byte[] file, IParquetBufferPool bufferPool)
    {
        ReadExpectedPageResult(() =>
        {
            using var reader = schema.CreateReader(new MemoryReadSource(file),
                new ParquetReaderOptions { BufferPool = bufferPool });
            foreach (var buffer in reader.RowGroups[0].Column<byte>(schema.LeafColumns[0]))
                for (var i = 0; i < buffer.Count; i++)
                    _ = buffer.GetValue(i).Length;
        });
    }

    static void ReadGuid(ParquetSchema schema, byte[] file, IParquetBufferPool bufferPool)
    {
        ReadExpectedPageResult(() =>
        {
            using var reader = schema.CreateReader(new MemoryReadSource(file),
                new ParquetReaderOptions { BufferPool = bufferPool });
            foreach (var buffer in reader.RowGroups[0].Column<Guid>(schema.LeafColumns[0]))
                _ = buffer.Values.Length;
        });
    }

    static void ReadInt32(ParquetSchema schema, byte[] file, IParquetBufferPool bufferPool)
    {
        ReadExpectedPageResult(() =>
        {
            using var reader = schema.CreateReader(new MemoryReadSource(file),
                new ParquetReaderOptions { BufferPool = bufferPool });
            foreach (var buffer in reader.RowGroups[0].Column<int>(schema.LeafColumns[0]))
                _ = buffer.Values.Length;
        });
    }

    static void ReadFloat(ParquetSchema schema, byte[] file, IParquetBufferPool bufferPool)
    {
        ReadExpectedPageResult(() =>
        {
            using var reader = schema.CreateReader(new MemoryReadSource(file),
                new ParquetReaderOptions { BufferPool = bufferPool });
            foreach (var buffer in reader.RowGroups[0].Column<float>(schema.LeafColumns[0]))
                _ = buffer.Values.Length;
        });
    }

    static void ReadBoolean(ParquetSchema schema, byte[] file, IParquetBufferPool bufferPool)
    {
        ReadExpectedPageResult(() =>
        {
            using var reader = schema.CreateReader(new MemoryReadSource(file),
                new ParquetReaderOptions { BufferPool = bufferPool });
            foreach (var buffer in reader.RowGroups[0].Column<bool>(schema.LeafColumns[0]))
                _ = buffer.Values.Length;
        });
    }

    static void ReadExpectedPageResult(Action read)
    {
        try
        {
            read();
        }
        catch (Exception error) when (error is CorruptParquetException or NotSupportedException
            or InvalidOperationException or ArgumentException)
        {
            // Mismatched page encoding/data is intentionally rejected after selector dispatch.
        }
    }
}
