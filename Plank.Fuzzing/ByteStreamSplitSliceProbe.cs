using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>Drives public Guid and decimal projections through fixed-width BSS slice decoding.</summary>
internal static class ByteStreamSplitSliceProbe
{
    internal static void Run(byte[] parquetBytes, IParquetBufferPool bufferPool)
    {
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("id", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(encodings: [EncodingKind.ByteStreamSplit], typeLength: 16),
                new LogicalType.Uuid(), converter: new ProbeGuidConverter()),
            ColumnDefinition.RequiredLeaf("amount", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(encodings: [EncodingKind.ByteStreamSplit], typeLength: 16),
                new LogicalType.Decimal(18, 2)),
            ColumnDefinition.RequiredLeaf("small_amount", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: [EncodingKind.ByteStreamSplit]),
                new LogicalType.Decimal(9, 2)),
            ColumnDefinition.RequiredLeaf("wide_amount", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: [EncodingKind.ByteStreamSplit]),
                new LogicalType.Decimal(18, 2)),
            ColumnDefinition.RequiredLeaf("overwide_amount", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(encodings: [EncodingKind.ByteStreamSplit], typeLength: 300),
                new LogicalType.Decimal(1, 0))
        ]);
        // Value assertions describe the shipped fixture only; mutants still decode fully.
        var exact = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(parquetBytes))
            == "6051451e1e0b2ea40907fa2ef7e3b5519a401de1d975e1b5783926e3a14689cc";
        using var source = new MemoryReadSource(parquetBytes);
        using var reader = schema.CreateReader(source, new ParquetReaderOptions { BufferPool = bufferPool });
        if (!exact && (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount > 4096))
            return;
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != 3)
            throw new InvalidDataException("The BSS slice probe fixture changed its row shape.");

        var actualIds = new List<ProbeGuid>();
        foreach (var buffer in reader.RowGroups[0].Column<ProbeGuid>(schema.LeafColumns[0]))
            actualIds.AddRange(buffer.Values.ToArray());
        ProbeGuid[] expectedIds =
        [
            new(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff")),
            new(Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100")),
            new(Guid.Parse("01234567-89ab-cdef-0123-456789abcdef"))
        ];
        if (exact && !actualIds.SequenceEqual(expectedIds))
            throw new InvalidDataException("The BSS slice probe Guid values changed.");

        var actualAmounts = new List<decimal>();
        foreach (var buffer in reader.RowGroups[0].Column<decimal>(schema.LeafColumns[1]))
            actualAmounts.AddRange(buffer.Values.ToArray());
        decimal[] expectedAmounts = [12.34m, -0.01m, 999999.99m];
        if (exact && !actualAmounts.SequenceEqual(expectedAmounts))
            throw new InvalidDataException("The BSS slice probe decimal values changed.");

        ReadDecimals(reader.RowGroups[0].Column<decimal>(schema.LeafColumns[2]), expectedAmounts,
            "INT32", exact);
        ReadDecimals(reader.RowGroups[0].Column<decimal>(schema.LeafColumns[3]), expectedAmounts,
            "INT64", exact);
        ReadDecimals(reader.RowGroups[0].Column<decimal>(schema.LeafColumns[4]), [1m, -1m, 0m],
            "300-byte FIXED_LEN_BYTE_ARRAY", exact);
    }

    static void ReadDecimals(RowGroupColumn<decimal> column, decimal[] expected, string label, bool exact)
    {
        var values = new List<decimal>();
        foreach (var buffer in column)
            values.AddRange(buffer.Values.ToArray());
        if (exact && !values.SequenceEqual(expected))
            throw new InvalidDataException($"The BSS slice probe {label} decimal values changed.");
    }

    readonly record struct ProbeGuid(Guid Value);

    sealed class ProbeGuidConverter : ParquetValueConverter<ProbeGuid, Guid>
    {
        public override Guid ConvertToPhysical(ProbeGuid value)
            => value.Value;

        public override ProbeGuid ConvertFromPhysical(Guid value)
            => new(value);
    }
}
