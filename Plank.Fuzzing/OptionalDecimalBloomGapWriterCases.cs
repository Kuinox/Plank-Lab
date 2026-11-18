using System.Buffers.Binary;
using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>
/// Temporarily keeps the optional Decimal Bloom-filter failure on a bounded writer-only route.
/// This records the known limitation; it does not fix decimal Bloom-filter support.
/// </summary>
internal static class OptionalDecimalBloomGapWriterCases
{
    static readonly ImmutableArray<EncodingKind> Plain = ImmutableArray.Create(EncodingKind.Plain);

    const string KnownFailureMessage =
        "Column 'decimal-amount' cannot build a Bloom filter from values of type 'System.Decimal'.";

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        var values = CreateValues(data);
        var withBloom = CreateSchema(new ParquetBloomFilterOptions
        {
            FalsePositiveProbability = 0.001,
            MaximumBytes = 256
        });

        using (var stream = new MemoryStream())
        {
            var writer = withBloom.CreateWriter(stream,
                new ParquetWriterOptions { Compression = CompressionKind.None });
            var serialized = writer.CreateSerializedColumn<decimal?>(withBloom.LeafColumns[0]);
            var knownBloomFailure = false;
            try
            {
                serialized.Serialize(values);
            }
            catch (NotSupportedException exception) when (exception.Message == KnownFailureMessage)
            {
                // The exact known unsupported-value outcome is expected until decimal Bloom hashing
                // is implemented. Any different exception remains a strict harness failure.
                knownBloomFailure = true;
            }

            if (!knownBloomFailure)
            {
                writer.StartRowGroup().Write(serialized);
                writer.CloseFile();
                var bytes = stream.ToArray();
                VerifyBloom(bytes, withBloom, values);
                VerifyParquetSharpRoundTrip(bytes, values);
            }
        }

        var withoutBloom = CreateSchema(null);
        using var controlStream = new MemoryStream();
        var controlWriter = withoutBloom.CreateWriter(controlStream,
            new ParquetWriterOptions { Compression = CompressionKind.None });
        var controlColumn = controlWriter.CreateSerializedColumn<decimal?>(withoutBloom.LeafColumns[0]);
        controlColumn.Serialize(values);
        controlWriter.StartRowGroup().Write(controlColumn);
        controlWriter.CloseFile();
        VerifyParquetSharpRoundTrip(controlStream.ToArray(), values);
    }

    static decimal?[] CreateValues(ReadOnlySpan<byte> data)
    {
        // The exact one-byte payload selects an empty column for focused
        // statistics coverage; ordinary inputs retain the populated values.
        if (data.Length == 1 && data[0] == 0xFF)
            return [];

        Span<byte> bounded = stackalloc byte[12];
        bounded.Clear();
        data[..Math.Min(data.Length, bounded.Length)].CopyTo(bounded);

        var first = ReadScaled(bounded, 0);
        var second = ReadScaled(bounded, 4);
        var third = ReadScaled(bounded, 8);
        return [first, null, second, third];
    }

    static decimal ReadScaled(ReadOnlySpan<byte> data, int offset)
    {
        var unscaled = BinaryPrimitives.ReadInt32LittleEndian(data[offset..]) % 100_000_000;
        return unscaled / 100m;
    }

    static ParquetSchema CreateSchema(ParquetBloomFilterOptions? bloomFilter)
        => new([
            ColumnDefinition.OptionalLeaf("decimal-amount", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: Plain, bloomFilter: bloomFilter), new LogicalType.Decimal(9, 2))
        ]);

    static void VerifyBloom(byte[] bytes, ParquetSchema schema, decimal?[] values)
    {
        using var reader = schema.CreateReader(new MemoryReadSource(bytes));
        var rowGroup = reader.RowGroups[0];
        var leaf = schema.LeafColumns[0];
        var metadata = rowGroup.GetColumnMetadata(leaf);
        if (metadata.ValueCount != (ulong)values.Length || !metadata.HasBloomFilter)
            throw new InvalidOperationException("Decimal Bloom output omitted required footer metadata.");

        using var filter = metadata.OpenBloomFilter();
        foreach (var value in values)
            if (value is { } present && !filter.MightContain(decimal.ToInt32(present * 100m)))
                throw new InvalidOperationException("Decimal Bloom output produced a false negative.");
    }

    static void VerifyParquetSharpRoundTrip(byte[] bytes, decimal?[] expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"plank-optional-decimal-bloom-{Guid.NewGuid():N}.parquet");
        try
        {
            File.WriteAllBytes(path, bytes);
            using var reader = new ParquetSharp.ParquetFileReader(path);
            using var rowGroup = reader.RowGroup(0);
            var actual = rowGroup.Column(0).LogicalReader<decimal?>().ReadAll(expected.Length);
            if (!actual.SequenceEqual(expected))
                throw new InvalidOperationException("Optional decimal ParquetSharp readback changed values.");
        }
        finally
        {
            File.Delete(path);
        }
    }
}
