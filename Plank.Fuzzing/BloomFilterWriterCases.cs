using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Deterministic writer plans for Bloom-filter value representations and repeated rows.</summary>
internal static class BloomFilterWriterCases
{
    static readonly ParquetBloomFilterOptions Bloom = new()
    {
        FalsePositiveProbability = 0.001,
        MaximumBytes = 256
    };

    // These cases exercise sizing from a bounded caller estimate instead of
    // the observed row count. The memory payloads below have exactly two
    // distinct non-null values.
    static readonly ParquetBloomFilterOptions BloomWithExpectedDistinctValues = new()
    {
        FalsePositiveProbability = 0.001,
        ExpectedDistinctValueCount = 2,
        MaximumBytes = 256
    };

    internal static void ExerciseNestedRepeatedBloom(byte selector)
    {
        int[][][] rows =
        [
            [[1, 2], [], [3]],
            [],
            [[-17], [int.MaxValue, int.MinValue]]
        ];
        var expected = rows.SelectMany(static row => row).SelectMany(static values => values).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("outer",
                ColumnDefinition.List("inner",
                    ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int32,
                        new ColumnOptions(encodings: Plain(), bloomFilter: Bloom))))
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = (selector & 1) == 0 ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2,
            WritePageCrc = (selector & 2) != 0,
            WritePageIndexes = true,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64
        });
        var serialized = writer.CreateSerializedColumn<int[][]>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)rows.Length)
            throw new InvalidOperationException("Nested Bloom write changed the row-group shape.");

        var leaf = reader.Schema.LeafColumns[0];
        var rowGroup = reader.RowGroups[0];
        var metadata = rowGroup.GetColumnMetadata(leaf);
        // Repeated value count includes a marker for each empty repeated level.
        if (metadata.ValueCount != 8 || !metadata.HasBloomFilter || !metadata.HasColumnIndex || !metadata.HasOffsetIndex)
            throw new InvalidOperationException("Nested Bloom write omitted required footer metadata.");

        using (var pages = metadata.OpenPages())
            if (pages.Count == 0)
                throw new InvalidOperationException("Nested Bloom write omitted indexed data pages.");

        var actual = new List<int>();
        foreach (var nestedBuffer in rowGroup.NestedColumn<int>(leaf))
            for (var i = 0; i < nestedBuffer.Values.Count; i++)
                actual.Add(nestedBuffer.Values.GetValue(i)[0]);
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException("Nested Bloom write changed leaf values.");

        using var filter = metadata.OpenBloomFilter();
        AssertAllPresent(filter, expected);
    }

    internal static void ExerciseNullableListBloom()
    {
        int?[][] rows = [[1, null, 3], null!, [], [5]];
        var schema = new ParquetSchema([
            ColumnDefinition.List("optional-bloom-list",
                ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Int32,
                    new ColumnOptions(encodings: Plain(), bloomFilter: Bloom)),
                ParquetRepetition.Optional)
        ]);
        var bytes = WriteRepeated(schema, rows, 0);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)rows.Length)
            throw new InvalidOperationException("Optional Bloom list changed row count.");
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, [1, 3, 5]);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, [1, 3, 5]);
    }

    internal static void Execute(byte selector)
    {
        switch ((selector & 0x7f) % 17)
        {
            case 0:
                ExerciseRepeatedInt32(selector);
                break;
            case 1:
                ExerciseOptionalRepeatedInt32(selector);
                break;
            case 2:
                ExerciseRepeatedFixedBinary(selector);
                break;
            case 3:
                ExerciseUnsignedInt32(selector);
                break;
            case 4:
                ExerciseUnsignedInt64(selector);
                break;
            case 5:
                ExerciseOptionalBinary(selector);
                break;
            case 6:
                ExerciseUuid(selector);
                break;
            case 7:
                ExerciseRepeatedInt64(selector);
                break;
            case 8:
                ExerciseOptionalRepeatedInt64(selector);
                break;
            case 9:
                ExerciseRequiredReadOnlyMemory(selector);
                break;
            case 10:
                ExerciseOptionalReadOnlyMemory(selector);
                break;
            case 11:
                ExerciseRepeatedFloat(selector);
                break;
            case 12:
                ExerciseRepeatedDouble(selector);
                break;
            case 13:
                ExerciseOptionalRepeatedFloat(selector);
                break;
            case 14:
                ExerciseOptionalRepeatedDouble(selector);
                break;
            case 15:
                ExerciseKnownDecimalBloomLimitation();
                break;
            default:
                ExerciseDecimalWithoutBloom(selector);
                break;
        }
    }

    static void ExerciseRequiredReadOnlyMemory(byte selector)
    {
        ReadOnlyMemory<byte>[] values = ["alpha"u8.ToArray(), "omega"u8.ToArray(), "alpha"u8.ToArray()];
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("bloom-required-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: Plain(), bloomFilter: BloomWithExpectedDistinctValues))
        ]);
        var bytes = WriteFlat(schema, values, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertBloomContains(filter, values);
        AssertFlatBinaryRoundTrip(reader.RowGroups[0], leaf,
            values.Select(static value => value.ToArray()).ToArray());
    }

    static void ExerciseOptionalReadOnlyMemory(byte selector)
    {
        ReadOnlyMemory<byte>?[] values = ["alpha"u8.ToArray(), null, ReadOnlyMemory<byte>.Empty,
            "alpha"u8.ToArray()];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("bloom-optional-memory", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: Plain(), bloomFilter: BloomWithExpectedDistinctValues))
        ]);
        var bytes = WriteOptionalFlat(schema, values, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        foreach (var value in values)
            if (value is { } memory && !filter.MightContain(memory.Span))
                throw new InvalidOperationException("Bloom filter missed an optional ReadOnlyMemory<byte> value.");
        AssertFlatBinaryRoundTrip(reader.RowGroups[0], leaf,
            values.Select(static value => value is { } memory ? memory.ToArray() : null!).ToArray());
    }

    static void ExerciseRepeatedFloat(byte selector)
    {
        float[][] rows = [[-17.5f, 0f, 1.25f], [], [42f, float.MinValue, float.MaxValue]];
        var expected = rows.SelectMany(static row => row).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-repeated-float",
                ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Float,
                    new ColumnOptions(encodings: Plain(), bloomFilter:
                        (selector & 0x80) != 0 ? BloomWithExpectedDistinctValues : Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, expected);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    static void ExerciseRepeatedDouble(byte selector)
    {
        double[][] rows = [[-17.5d, 0d, 1.25d], [], [42d, double.MinValue, double.MaxValue]];
        var expected = rows.SelectMany(static row => row).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-repeated-double",
                ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Double,
                    new ColumnOptions(encodings: Plain(), bloomFilter: Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, expected);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    static void ExerciseOptionalRepeatedFloat(byte selector)
    {
        float?[][] rows = [[-9.5f, null, 4f], [], [null, 11.25f, float.MaxValue]];
        var expected = rows.SelectMany(static row => row).Where(static value => value.HasValue)
            .Select(static value => value.GetValueOrDefault()).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-optional-repeated-float",
                ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Float,
                    new ColumnOptions(encodings: Plain(), bloomFilter: Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, expected);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    static void ExerciseOptionalRepeatedDouble(byte selector)
    {
        double?[][] rows = [[-9.5d, null, 4d], [], [null, 11.25d, double.MaxValue]];
        var expected = rows.SelectMany(static row => row).Where(static value => value.HasValue)
            .Select(static value => value.GetValueOrDefault()).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-optional-repeated-double",
                ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Double,
                    new ColumnOptions(encodings: Plain(), bloomFilter: Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, expected);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    // Keep the regression seed for decimal Bloom serialization and readback.
    static void ExerciseKnownDecimalBloomLimitation()
    {
        var schema = DecimalSchema(Bloom);
        decimal[] values = [1.23m, -4.56m];
        var bytes = WriteFlat(schema, values, 0);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        if (!reader.RowGroups[0].GetColumnMetadata(leaf).HasBloomFilter)
            throw new InvalidOperationException("Decimal Bloom filter was not written.");
        AssertFlatRoundTrip(reader.RowGroups[0], leaf, values);
    }

    static void ExerciseDecimalWithoutBloom(byte selector)
    {
        var schema = DecimalSchema(null);
        var values = new[] { 1.23m, -4.56m };
        var bytes = WriteFlat(schema, values, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        AssertFlatRoundTrip(reader.RowGroups[0], schema.LeafColumns[0], values);
    }

    static ParquetSchema DecimalSchema(ParquetBloomFilterOptions? bloomFilter)
        => new([
            ColumnDefinition.RequiredLeaf("decimal-amount", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: Plain(), bloomFilter: bloomFilter), new LogicalType.Decimal(9, 2))
        ]);

    static void ExerciseRepeatedInt64(byte selector)
    {
        long[][] rows = [[-17, 0, 1], [], [42, long.MinValue, long.MaxValue]];
        var expected = rows.SelectMany(static row => row).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-repeated-i64",
                ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int64,
                    new ColumnOptions(encodings: Plain(), bloomFilter: Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, expected);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    static void ExerciseOptionalRepeatedInt64(byte selector)
    {
        long?[][] rows = [[-9, null, 4], [], [null, 11, long.MaxValue]];
        var expected = rows.SelectMany(static row => row).Where(static value => value.HasValue)
            .Select(static value => value.GetValueOrDefault()).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-optional-repeated-i64",
                ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Int64,
                    new ColumnOptions(encodings: Plain(), bloomFilter: Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, expected);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    static void ExerciseRepeatedInt32(byte selector)
    {
        int[][] rows = [[-17, 0, 1], [], [42, int.MinValue, int.MaxValue]];
        var expected = rows.SelectMany(static row => row).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-repeated-i32",
                ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.Int32,
                    new ColumnOptions(encodings: Plain(), bloomFilter: Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, expected);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    static void ExerciseOptionalRepeatedInt32(byte selector)
    {
        int?[][] rows = [[-9, null, 4], [], [null, 11, int.MaxValue]];
        var expected = rows.SelectMany(static row => row).Where(static value => value.HasValue)
            .Select(static value => value.GetValueOrDefault()).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-optional-repeated-i32",
                ColumnDefinition.OptionalLeaf("element", ParquetPhysicalType.Int32,
                    new ColumnOptions(encodings: Plain(), bloomFilter: Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        AssertAllPresent(filter, expected);
        AssertNestedRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    static void ExerciseRepeatedFixedBinary(byte selector)
    {
        byte[][][] rows =
        [
            [Guid.Parse("00112233-4455-6677-8899-aabbccddeeff").ToByteArray(), new byte[16]],
            [],
            [Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100").ToByteArray()]
        ];
        var expected = rows.SelectMany(static row => row).ToArray();
        var schema = new ParquetSchema([
            ColumnDefinition.List("bloom-repeated-fixed-binary",
                ColumnDefinition.RequiredLeaf("element", ParquetPhysicalType.FixedLenByteArray,
                    new ColumnOptions(typeLength: 16, encodings: Plain(), bloomFilter: Bloom)))
        ]);
        var bytes = WriteRepeated(schema, rows, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        foreach (var value in expected)
            if (!filter.MightContain(value))
                throw new InvalidOperationException("Bloom filter missed a repeated fixed-length value.");
        AssertNestedBinaryRoundTrip(reader.RowGroups[0], leaf, expected);
    }

    static void ExerciseUnsignedInt32(byte selector)
    {
        uint[] values = [0, 1, 123, uint.MaxValue];
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("bloom-u32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: Plain(), bloomFilter: Bloom), new LogicalType.Int(32, false))
        ]);
        var bytes = WriteFlat(schema, values, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        foreach (var value in values)
            if (!filter.MightContain(value))
                throw new InvalidOperationException($"Bloom filter missed UINT32 value {value}.");
        AssertFlatRoundTrip(reader.RowGroups[0], leaf, values);
    }

    static void ExerciseUnsignedInt64(byte selector)
    {
        ulong[] values = [0, 1, 123, ulong.MaxValue];
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("bloom-u64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: Plain(), bloomFilter: Bloom), new LogicalType.Int(64, false))
        ]);
        var bytes = WriteFlat(schema, values, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        foreach (var value in values)
            if (!filter.MightContain(value))
                throw new InvalidOperationException($"Bloom filter missed UINT64 value {value}.");
        AssertFlatRoundTrip(reader.RowGroups[0], leaf, values);
    }

    static void ExerciseUuid(byte selector)
    {
        Guid[] values =
        [
            Guid.Empty,
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
            Guid.Parse("ffeeddcc-bbaa-9988-7766-554433221100")
        ];
        var schema = new ParquetSchema([
            ColumnDefinition.RequiredLeaf("bloom-uuid", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(typeLength: 16, encodings: Plain(), bloomFilter: Bloom), new LogicalType.Uuid())
        ]);
        var bytes = WriteFlat(schema, values, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        foreach (var value in values)
            if (!filter.MightContain(value))
                throw new InvalidOperationException($"Bloom filter missed UUID {value}.");
        var encoded = new byte[values.Length][];
        for (var i = 0; i < values.Length; i++)
        {
            encoded[i] = new byte[16];
            values[i].TryWriteBytes(encoded[i], bigEndian: true, out _);
        }
        AssertFlatBinaryRoundTrip(reader.RowGroups[0], leaf, encoded);
    }

    static void ExerciseOptionalBinary(byte selector)
    {
        byte[][] values = ["alpha"u8.ToArray(), null!, [], "omega"u8.ToArray()];
        var schema = new ParquetSchema([
            ColumnDefinition.OptionalLeaf("bloom-optional-binary", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: Plain(), bloomFilter:
                    (selector & 0x80) != 0 ? BloomWithExpectedDistinctValues : Bloom))
        ]);
        var bytes = WriteFlat(schema, values, selector);
        using var reader = schema.CreateReader(FullValueOracle.Source(bytes));
        var leaf = schema.LeafColumns[0];
        using var filter = reader.RowGroups[0].GetColumnMetadata(leaf).OpenBloomFilter();
        if (!filter.MightContain("alpha"u8) || !filter.MightContain(ReadOnlySpan<byte>.Empty) ||
            !filter.MightContain("omega"u8))
            throw new InvalidOperationException("Optional binary Bloom filter produced a false negative.");
        AssertFlatBinaryRoundTrip(reader.RowGroups[0], leaf, values);
    }

    static ImmutableArray<EncodingKind> Plain()
        => ImmutableArray.Create(EncodingKind.Plain);

    static byte[] WriteRepeated<T>(ParquetSchema schema, T[] rows, byte selector)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, Options(selector));
        var serialized = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        serialized.Serialize(rows);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();
        return stream.ToArray();
    }

    static byte[] WriteFlat<T>(ParquetSchema schema, T[] values, byte selector)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, Options(selector));
        var serialized = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();
        return stream.ToArray();
    }

    static byte[] WriteOptionalFlat(ParquetSchema schema, ReadOnlyMemory<byte>?[] values, byte selector)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, Options(selector));
        var serialized = writer.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();
        return stream.ToArray();
    }

    static ParquetWriterOptions Options(byte selector)
        => new()
        {
            Compression = CompressionKind.None,
            DataPageVersion = (selector & 0x80) == 0
                ? ParquetDataPageVersion.V1
                : ParquetDataPageVersion.V2,
            WritePageCrc = true,
            WritePageIndexes = false,
            FileVersion = ParquetFileVersion.V1,
            TargetDataPageSizeBytes = 64,
            BufferChunkSizeBytes = 128
        };

    static void AssertAllPresent(Plank.Reading.Physical.ParquetBloomFilter filter, int[] values)
    {
        foreach (var value in values)
            if (!filter.MightContain(value))
                throw new InvalidOperationException($"Bloom filter missed INT32 value {value}.");
    }

    static void AssertAllPresent(Plank.Reading.Physical.ParquetBloomFilter filter, long[] values)
    {
        foreach (var value in values)
            if (!filter.MightContain(value))
                throw new InvalidOperationException($"Bloom filter missed INT64 value {value}.");
    }

    static void AssertAllPresent(Plank.Reading.Physical.ParquetBloomFilter filter, float[] values)
    {
        foreach (var value in values)
            if (!filter.MightContain(value))
                throw new InvalidOperationException($"Bloom filter missed FLOAT value {value}.");
    }

    static void AssertAllPresent(Plank.Reading.Physical.ParquetBloomFilter filter, double[] values)
    {
        foreach (var value in values)
            if (!filter.MightContain(value))
                throw new InvalidOperationException($"Bloom filter missed DOUBLE value {value}.");
    }

    static void AssertBloomContains(Plank.Reading.Physical.ParquetBloomFilter filter,
        ReadOnlyMemory<byte>[] values)
    {
        foreach (var value in values)
            if (!filter.MightContain(value.Span))
                throw new InvalidOperationException("Bloom filter missed a ReadOnlyMemory<byte> value.");
    }

    static void AssertNestedRoundTrip<T>(RowGroup rowGroup, LeafColumn leaf, T[] expected)
        where T : notnull
    {
        var actual = new List<T>(expected.Length);
        using var pages = rowGroup.NestedColumn<T>(leaf).GetEnumerator();
        while (pages.MoveNext())
            actual.AddRange(pages.Current.Values.Values.ToArray());
        if (!ValuesMatch(actual, expected))
            throw new InvalidOperationException("Bloom-filter repeated values did not round-trip.");
    }

    static void AssertFlatRoundTrip<T>(RowGroup rowGroup, LeafColumn leaf, T[] expected)
    {
        var actual = new List<T>(expected.Length);
        using var pages = rowGroup.Column<T>(leaf).GetEnumerator();
        while (pages.MoveNext())
            actual.AddRange(pages.Current.Values.ToArray());
        if (!ValuesMatch(actual, expected))
            throw new InvalidOperationException("Bloom-filter values did not round-trip.");
    }

    static void AssertFlatBinaryRoundTrip(RowGroup rowGroup, LeafColumn leaf, byte[][] expected)
    {
        using var pages = rowGroup.Column<byte>(leaf).GetEnumerator();
        var row = 0;
        while (pages.MoveNext())
        {
            var page = pages.Current;
            for (var i = 0; i < page.Count; i++, row++)
            {
                if (row >= expected.Length)
                    throw new InvalidOperationException("Bloom-filter binary round-trip returned extra values.");
                if (expected[row] is null)
                {
                    if (!page.IsNull(i))
                        throw new InvalidOperationException("Bloom-filter binary round-trip lost a null.");
                }
                else if (page.IsNull(i) || !page.GetValue(i).SequenceEqual(expected[row]))
                    throw new InvalidOperationException("Bloom-filter binary payload did not round-trip.");
            }
        }
        if (row != expected.Length)
            throw new InvalidOperationException("Bloom-filter binary round-trip returned too few values.");
    }

    static void AssertNestedBinaryRoundTrip(RowGroup rowGroup, LeafColumn leaf, byte[][] expected)
    {
        using var pages = rowGroup.NestedColumn<byte>(leaf).GetEnumerator();
        var index = 0;
        while (pages.MoveNext())
        {
            var values = pages.Current.Values;
            for (var i = 0; i < values.Count; i++, index++)
                if (index >= expected.Length || !values.GetValue(i).SequenceEqual(expected[index]))
                    throw new InvalidOperationException("Repeated Bloom-filter binary values did not round-trip.");
        }
        if (index != expected.Length)
            throw new InvalidOperationException("Repeated Bloom-filter binary round-trip returned too few values.");
    }

    static bool ValuesMatch<T>(List<T> actual, T[] expected)
    {
        if (actual.Count != expected.Length)
            return false;
        for (var i = 0; i < expected.Length; i++)
        {
            if (actual[i] is byte[] actualBytes && expected[i] is byte[] expectedBytes)
            {
                if (!actualBytes.AsSpan().SequenceEqual(expectedBytes))
                    return false;
            }
            else if (!EqualityComparer<T>.Default.Equals(actual[i], expected[i]))
                return false;
        }
        return true;
    }
}
