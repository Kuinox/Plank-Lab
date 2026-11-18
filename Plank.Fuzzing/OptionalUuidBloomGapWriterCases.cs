using System.Collections.Immutable;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Public optional UUID Bloom input that exercises the nullable Guid hashing route.</summary>
internal static class OptionalUuidBloomGapWriterCases
{
    static readonly ImmutableArray<EncodingKind> Plain = ImmutableArray.Create(EncodingKind.Plain);
    static readonly Guid[] PresentValues =
    [
        Guid.Empty,
        Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
        Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100")
    ];

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        var values = new Guid?[] { PresentValues[0], null, PresentValues[1], PresentValues[2] };
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("bloom-optional-uuid", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(typeLength: 16, encodings: Plain, bloomFilter: new ParquetBloomFilterOptions
                {
                    FalsePositiveProbability = 0.001,
                    MaximumBytes = 256
                }), new LogicalType.Uuid())
        ]);

        using var stream = new MemoryStream();
        var selector = data.IsEmpty ? (byte)0 : data[0];
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = (selector & 1) == 0 ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2,
            WritePageCrc = (selector & 2) != 0,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var serialized = writer.CreateSerializedColumn<Guid?>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var reader = schema.CreateReader(new MemoryReadSource(stream.ToArray()));
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)values.Length)
            throw new InvalidOperationException("Optional UUID Bloom write changed the row-group shape.");

        var leaf = schema.LeafColumns[0];
        var metadata = reader.RowGroups[0].GetColumnMetadata(leaf);
        if (metadata.ValueCount != (ulong)values.Length || !metadata.HasBloomFilter
            || metadata.HasColumnIndex || !metadata.HasOffsetIndex)
            throw new InvalidOperationException("Optional UUID Bloom output changed its expected footer metadata.");

        using (var filter = metadata.OpenBloomFilter())
            foreach (var value in PresentValues)
                if (!filter.MightContain(value))
                    throw new InvalidOperationException("Optional UUID Bloom filter produced a false negative.");

        // UUID values are exposed through the physical FixedLenByteArray reader as
        // their canonical big-endian bytes; this also verifies the null position.
        using var pages = reader.RowGroups[0].Column<byte>(leaf).GetEnumerator();
        var row = 0;
        while (pages.MoveNext())
        {
            var page = pages.Current;
            for (var i = 0; i < page.Count; i++, row++)
            {
                var expected = values[row] is { } guid ? EncodeUuid(guid) : null;
                if (expected is null)
                {
                    if (!page.IsNull(i))
                        throw new InvalidOperationException("Optional UUID round-trip lost a null.");
                }
                else if (page.IsNull(i) || !page.GetValue(i).SequenceEqual(expected))
                    throw new InvalidOperationException("Optional UUID round-trip changed fixed-length bytes.");
            }
        }
        if (row != values.Length)
            throw new InvalidOperationException("Optional UUID round-trip returned the wrong value count.");

        VerifyParquetSharpRoundTrip(stream.ToArray(), values);
    }

    static void VerifyParquetSharpRoundTrip(byte[] bytes, Guid?[] expected)
    {
        var path = Path.Combine(Path.GetTempPath(), $"plank-optional-uuid-bloom-{Guid.NewGuid():N}.parquet");
        try
        {
            File.WriteAllBytes(path, bytes);
            using var reader = new ParquetSharp.ParquetFileReader(path);
            using var rowGroup = reader.RowGroup(0);
            var actual = rowGroup.Column(0).LogicalReader<Guid?>().ReadAll(expected.Length);
            if (!actual.SequenceEqual(expected))
                throw new InvalidOperationException("Optional UUID ParquetSharp readback changed values.");
        }
        finally
        {
            File.Delete(path);
        }
    }

    static byte[] EncodeUuid(Guid value)
    {
        var bytes = new byte[16];
        if (!value.TryWriteBytes(bytes, bigEndian: true, out var written) || written != bytes.Length)
            throw new InvalidOperationException("Could not encode UUID for round-trip validation.");
        return bytes;
    }
}
