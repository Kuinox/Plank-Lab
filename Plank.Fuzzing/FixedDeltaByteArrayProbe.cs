using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>Reads fixed-width UUID DELTA_BYTE_ARRAY values through a requested Guid converter.</summary>
internal static class FixedDeltaByteArrayProbe
{
    // The exact-value checks describe the shipped fixtures only. A mutated payload
    // legitimately decodes to other values (or another row count), so those
    // assertions apply to the fixture hash alone; mutants are still fully decoded
    // and any non-corruption exception from the decoder still surfaces.
    const string RequiredFixtureHash = "a5d88e047cf5a4218e106a9171d15ba51a0ef490c635d17fd85a6ebfb0debc51";
    const string OptionalFixtureHash = "d74c531435f43cf5d580628deb01b9086803112f954c058e15c62647ff97a401";

    static bool IsFixture(byte[] bytes, string hash)
        => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)) == hash;

    internal static void RunNullable(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("value", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(encodings: [EncodingKind.DeltaByteArray], typeLength: 16),
                new LogicalType.Uuid(), converter: new IdentityGuidConverter())
        ]);

        using var source = new MemoryReadSource(parquetBytes);
        using var reader = schema.CreateReader(source, new ParquetReaderOptions { BufferPool = bufferPool });
        var exact = IsFixture(parquetBytes, OptionalFixtureHash);
        if (!exact && (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount > 4096))
            return;
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 40)
            throw new InvalidDataException("The optional fixed DeltaByteArray probe fixture changed its row shape.");

        var values = new List<Guid?>();
        foreach (var buffer in reader.RowGroups[0].Column<Guid?>(schema.LeafColumns[0]))
            values.AddRange(buffer.Values.ToArray());
        var expected = Enumerable.Range(0, 40)
            .Select(static i => i % 3 == 0 ? (Guid?)null : new Guid(i, 0, 0, new byte[8]));
        if (exact && !values.SequenceEqual(expected))
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
        var exact = IsFixture(parquetBytes, RequiredFixtureHash);
        if (!exact && (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount > 4096))
            return;
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 40)
            throw new InvalidDataException("The fixed DeltaByteArray probe fixture changed its row shape.");

        var values = new List<Guid>();
        foreach (var buffer in reader.RowGroups[0].Column<Guid>(schema.LeafColumns[0]))
            values.AddRange(buffer.Values.ToArray());
        var expected = Enumerable.Range(0, 40)
            .Select(static i => new Guid(i, 0, 0, new byte[8]));
        if (exact && !values.SequenceEqual(expected))
            throw new InvalidDataException("The fixed DeltaByteArray probe Guid values changed.");
    }

    sealed class IdentityGuidConverter : ParquetValueConverter<Guid, Guid>
    {
        public override Guid ConvertToPhysical(Guid value) => value;
        public override Guid ConvertFromPhysical(Guid value) => value;
    }
}
