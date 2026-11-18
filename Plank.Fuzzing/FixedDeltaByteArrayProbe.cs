using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>Reads fixed-width UUID DELTA_BYTE_ARRAY values through a requested Guid converter.</summary>
internal static class FixedDeltaByteArrayProbe
{
    internal static void RunNullable(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("value", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(encodings: [EncodingKind.DeltaByteArray], typeLength: 16),
                new LogicalType.Uuid(), converter: new IdentityGuidConverter())
        ]);

        using var source = new MemoryReadSource(parquetBytes);
        using var reader = schema.CreateReader(source, new ParquetReaderOptions { BufferPool = bufferPool });
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 40)
            throw new InvalidDataException("The optional fixed DeltaByteArray probe fixture changed its row shape.");

        var values = new List<Guid?>();
        foreach (var buffer in reader.RowGroups[0].Column<Guid?>(schema.LeafColumns[0]))
            values.AddRange(buffer.Values.ToArray());
        var expected = Enumerable.Range(0, 40)
            .Select(static i => i % 3 == 0 ? (Guid?)null : new Guid(i, 0, 0, new byte[8]));
        if (!values.SequenceEqual(expected))
            throw new InvalidDataException("The optional fixed DeltaByteArray probe Guid values changed.");
    }

    internal static void Run(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(encodings: [EncodingKind.DeltaByteArray], typeLength: 16),
                new LogicalType.Uuid(), converter: new IdentityGuidConverter())
        ]);

        using var source = new MemoryReadSource(parquetBytes);
        using var reader = schema.CreateReader(source, new ParquetReaderOptions { BufferPool = bufferPool });
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 40)
            throw new InvalidDataException("The fixed DeltaByteArray probe fixture changed its row shape.");

        var values = new List<Guid>();
        foreach (var buffer in reader.RowGroups[0].Column<Guid>(schema.LeafColumns[0]))
            values.AddRange(buffer.Values.ToArray());
        var expected = Enumerable.Range(0, 40)
            .Select(static i => new Guid(i, 0, 0, new byte[8]));
        if (!values.SequenceEqual(expected))
            throw new InvalidDataException("The fixed DeltaByteArray probe Guid values changed.");
    }

    sealed class IdentityGuidConverter : ParquetValueConverter<Guid, Guid>
    {
        public override Guid ConvertToPhysical(Guid value) => value;
        public override Guid ConvertFromPhysical(Guid value) => value;
    }
}
