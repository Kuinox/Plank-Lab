using System.Collections.Immutable;
using System.Buffers.Binary;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;
using Plank.Writing.PageStrategy;
using PlankSchema = Plank.Schema.ParquetSchema;
using PlankWriterTarget = Plank.Fuzzing.PlankWriterFuzzTarget;

namespace Plank.Fuzzing;

/// <summary>Small public-writer probes for footer, statistics, and page-index metadata.</summary>
internal static class WriterMetadataCases
{
    static readonly ImmutableArray<EncodingKind> Plain = ImmutableArray.Create(EncodingKind.Plain);
    static readonly byte[] UInt8RequiredValues = [0, 1, 127, 255];
    static readonly int[] UInt8RequiredExpected = [0, 1, 127, 255];

    internal static void Execute(ReadOnlySpan<byte> controls)
    {
        if (!controls.IsEmpty && controls[0] == 11)
        {
            ExerciseRequiredDateTimeDictionaryBoundary([new(2020, 1, 2, 3, 4, 5, DateTimeKind.Unspecified)]);
            return;
        }
        if (!controls.IsEmpty && controls[0] == 12)
        {
            ExerciseRequiredDateTimeDictionaryBoundary([]);
            return;
        }
        if (!controls.IsEmpty && controls[0] == 13)
        {
            ExerciseRequiredDateTimeDictionaryWrongPhysicalType();
            return;
        }
        if (!controls.IsEmpty && controls[0] == 14)
        {
            ExerciseRequiredDateTimeStatisticsKindBoundary(controls.Length > 1 ? controls[1] : (byte)0);
            return;
        }
        if (!controls.IsEmpty && controls[0] == 15)
        {
            ExerciseEmptyPrimitiveStatistics();
            return;
        }
        if (!controls.IsEmpty && controls[0] == 16)
        {
            ExerciseNullableEmptyAndNaNStatistics();
            return;
        }
        if (!controls.IsEmpty && controls[0] == 17)
        {
            ExerciseNullableUnsignedStatisticsExtremes();
            return;
        }
        if (!controls.IsEmpty && controls[0] == 18)
        {
            ExerciseNullableFloatDoubleMinMax();
            return;
        }

        switch (controls.IsEmpty ? 0 : controls[0] % 11)
        {
            case 0:
                ExerciseBasicMap();
                break;
            case 1:
                ExerciseNestedMap();
                break;
            case 2:
                ExerciseStatisticsAndPageIndexes(ParquetDataPageVersion.V1);
                break;
            case 3:
                ExerciseStatisticsAndPageIndexes(ParquetDataPageVersion.V2);
                break;
            case 4:
                ExerciseUnsignedStatistics();
                break;
            case 5:
                ExerciseMemoryStatistics();
                break;
            case 6:
                ExerciseDecimalStatistics();
                break;
            case 7:
                ExerciseRepeatedUnsignedStatistics();
                break;
            case 8:
                ExerciseRequiredDateTimeDictionaryStatistics();
                break;
            case 9:
                ExerciseNullablePrimitiveStatisticsDispatch();
                break;
            case 10:
                ExerciseRequiredDateTimePlainFallback();
                break;
            default:
                ExerciseInvalidTimeUnitMetadata();
                break;
        }
    }

    static void ExerciseInvalidTimeUnitMetadata()
    {
        const TimeUnit invalidUnit = (TimeUnit)99;
        var definition = ColumnDefinition.Leaf("invalid-time-unit", ParquetPhysicalType.Int64,
            logicalType: new LogicalType.Timestamp(invalidUnit, IsAdjustedToUtc: false));
        var schema = new PlankSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions { Compression = CompressionKind.None });
        try
        {
            writer.CloseFile();
        }
        catch (ArgumentOutOfRangeException error) when (error.ParamName == "unit" &&
            error.ActualValue is TimeUnit value && value == invalidUnit)
        {
            return;
        }

        throw new InvalidOperationException("Invalid timestamp unit was not rejected during footer serialization.");
    }

    static void ExerciseRepeatedUnsignedStatistics()
    {
        var definitions = new[]
        {
            ColumnDefinition.Leaf("repeated-uint32", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Repeated, encodings: Plain),
                logicalType: new LogicalType.Int(32, false)),
            ColumnDefinition.Leaf("repeated-uint64", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Repeated, encodings: Plain),
                logicalType: new LogicalType.Int(64, false))
        };
        int[][] expected32 =
        [
            [int.MinValue, 3, 0, -1],
            [42, int.MinValue, int.MaxValue],
            [0, -2, 1]
        ];
        long[][] expected64 =
        [
            [long.MinValue, 3, 0, -1],
            [42, long.MinValue + 1, long.MaxValue],
            [0, -2, 1]
        ];

        var schema = new PlankSchema([.. definitions]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, StatisticsWriterOptions());
        var rowGroup = writer.StartRowGroup();
        var uint32 = rowGroup.CreateSerializedColumn<int[]>(schema.LeafColumns[0]);
        uint32.Serialize(expected32);
        rowGroup.Write(uint32);
        var uint64 = rowGroup.CreateSerializedColumn<long[]>(schema.LeafColumns[1]);
        uint64.Serialize(expected64);
        rowGroup.Write(uint64);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected32.Length)
            throw new InvalidOperationException("Repeated unsigned statistics changed the row-group shape.");

        var expectedPhysical32 = expected32.SelectMany(static row => row.Select(static value => unchecked((uint)value))).ToArray();
        var expectedPhysical64 = expected64.SelectMany(static row => row.Select(static value => unchecked((ulong)value))).ToArray();
        var actual32 = ReadAllNestedValues(reader.RowGroups[0].NestedColumn<uint>(reader.Schema.LeafColumns[0]));
        var actual64 = ReadAllNestedValues(reader.RowGroups[0].NestedColumn<ulong>(reader.Schema.LeafColumns[1]));
        if (!actual32.AsSpan().SequenceEqual(expectedPhysical32)
            || !actual64.AsSpan().SequenceEqual(expectedPhysical64))
            throw new InvalidOperationException("Repeated unsigned statistics changed nested values.");

        AssertStatistics(reader.RowGroups[0].GetColumnMetadata(0).Statistics,
            [0, 0, 0, 0], [byte.MaxValue, byte.MaxValue, byte.MaxValue, byte.MaxValue], 0,
            "repeated-uint32");
        AssertStatistics(reader.RowGroups[0].GetColumnMetadata(1).Statistics,
            new byte[sizeof(ulong)], Enumerable.Repeat(byte.MaxValue, sizeof(ulong)).ToArray(), 0,
            "repeated-uint64");
    }

    static void ExerciseRequiredDateTimeDictionaryStatistics()
    {
        var definition = ColumnDefinition.Leaf("required-timestamp-dictionary", ParquetPhysicalType.Int64,
            new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
            logicalType: new LogicalType.Timestamp(TimeUnit.Micros, false),
            pageStrategy: ForceDictionaryPageStrategy.Shared);
        DateTime[] expected =
        [
            new(1971, 1, 1, 0, 0, 0, DateTimeKind.Unspecified),
            new(1960, 1, 1, 0, 0, 0, DateTimeKind.Unspecified),
            new(2020, 12, 31, 0, 0, 0, DateTimeKind.Unspecified)
        ];

        var schema = new PlankSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, StatisticsWriterOptions());
        var rowGroup = writer.StartRowGroup();
        var timestamp = rowGroup.CreateSerializedColumn<DateTime>(schema.LeafColumns[0]);
        timestamp.Serialize(expected);
        rowGroup.Write(timestamp);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("DateTime dictionary statistics changed the row-group shape.");

        var actual = ReadAllBuffers(reader.RowGroups[0].Column<DateTime>(reader.Schema.LeafColumns[0]));
        if (!actual.AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException("DateTime dictionary statistics changed timestamp values.");

        AssertStatistics(reader.RowGroups[0].GetColumnMetadata(0).Statistics,
            EncodeUnixMicros(expected[1]), EncodeUnixMicros(expected[2]), 0,
            "required-timestamp-dictionary");
    }

    static void ExerciseRequiredDateTimeStatisticsKindBoundary(byte mode)
    {
        var adjusted = (mode & 1) != 0;
        var expectedKind = adjusted ? DateTimeKind.Utc : DateTimeKind.Unspecified;
        var firstKind = (mode & 2) != 0 ? DateTimeKind.Local : expectedKind;
        var secondKind = (mode & 4) != 0 ? DateTimeKind.Local : expectedKind;
        var definition = ColumnDefinition.Leaf("required-timestamp-kind-boundary", ParquetPhysicalType.Int64,
            new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
            logicalType: new LogicalType.Timestamp(TimeUnit.Micros, adjusted),
            pageStrategy: ForceDictionaryPageStrategy.Shared);
        var schema = new PlankSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, StatisticsWriterOptions());
        var rowGroup = writer.StartRowGroup();
        var timestamp = rowGroup.CreateSerializedColumn<DateTime>(schema.LeafColumns[0]);
        DateTime[] values = [new(2020, 1, 2, 3, 4, 5, firstKind), new(2021, 2, 3, 4, 5, 6, secondKind)];
        try
        {
            timestamp.Serialize(values);
        }
        catch (InvalidOperationException error) when (error.Message.Contains("DateTime values must have kind", StringComparison.Ordinal))
        {
            if (firstKind == expectedKind && secondKind == expectedKind)
                throw new InvalidOperationException("Valid DateTime kinds were rejected.", error);
            return;
        }
        if (firstKind != expectedKind || secondKind != expectedKind)
            throw new InvalidOperationException("Mismatched DateTime kinds were accepted.");
        rowGroup.Write(timestamp);
        writer.CloseFile();
    }

    static void ExerciseRequiredDateTimeDictionaryBoundary(DateTime[] expected)
    {
        var definition = ColumnDefinition.Leaf("required-timestamp-dictionary-boundary", ParquetPhysicalType.Int64,
            new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
            logicalType: new LogicalType.Timestamp(TimeUnit.Micros, false),
            pageStrategy: ForceDictionaryPageStrategy.Shared);
        var schema = new PlankSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, StatisticsWriterOptions());
        var rowGroup = writer.StartRowGroup();
        var timestamp = rowGroup.CreateSerializedColumn<DateTime>(schema.LeafColumns[0]);
        timestamp.Serialize(expected);
        rowGroup.Write(timestamp);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].RowCount != (ulong)expected.Length)
            throw new InvalidOperationException("Required timestamp dictionary boundary changed the row-group shape.");
        if (expected.Length != 0)
        {
            var actual = ReadAllBuffers(reader.RowGroups[0].Column<DateTime>(reader.Schema.LeafColumns[0]));
            if (!actual.AsSpan().SequenceEqual(expected))
                throw new InvalidOperationException("Required timestamp dictionary boundary changed values.");
        }
    }

    static void ExerciseRequiredDateTimeDictionaryWrongPhysicalType()
    {
        // Library master validates the logical/physical pairing when the column is defined, so the
        // mismatch is rejected before any writer exists. (Older builds rejected it in the encoder.)
        try
        {
            _ = ColumnDefinition.Leaf("required-timestamp-wrong-physical", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: ImmutableArray.Create(EncodingKind.RleDictionary)),
                logicalType: new LogicalType.Timestamp(TimeUnit.Micros, false),
                pageStrategy: ForceDictionaryPageStrategy.Shared);
        }
        catch (ArgumentException error) when (error.ParamName == "physicalType")
        {
            return;
        }

        throw new InvalidOperationException("Wrong-physical timestamp column definition was accepted.");
    }

    static void ExerciseRequiredDateTimePlainFallback()
    {
        var definition = ColumnDefinition.Leaf("required-timestamp-plain", ParquetPhysicalType.Int64,
            logicalType: new LogicalType.Timestamp(TimeUnit.Micros, false));
        DateTime[] expected =
        [
            new(1971, 1, 1, 0, 0, 0, DateTimeKind.Unspecified),
            new(1960, 1, 1, 0, 0, 0, DateTimeKind.Unspecified),
            new(2020, 12, 31, 0, 0, 0, DateTimeKind.Unspecified)
        ];

        var schema = new PlankSchema([definition]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, StatisticsWriterOptions());
        var rowGroup = writer.StartRowGroup();
        var timestamp = rowGroup.CreateSerializedColumn<DateTime>(schema.LeafColumns[0]);
        timestamp.Serialize(expected);
        rowGroup.Write(timestamp);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        var actual = ReadAllBuffers(reader.RowGroups[0].Column<DateTime>(reader.Schema.LeafColumns[0]));
        if (!actual.AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException("Plain timestamp fallback changed timestamp values.");

        AssertStatistics(reader.RowGroups[0].GetColumnMetadata(0).Statistics,
            EncodeUnixMicros(expected[1]), EncodeUnixMicros(expected[2]), 0,
            "required-timestamp-plain");
    }

    static void ExerciseNullablePrimitiveStatisticsDispatch()
    {
        var definitions = new[]
        {
            ColumnDefinition.OptionalLeaf("optional-bool", ParquetPhysicalType.Boolean, new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("optional-int32", ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("optional-int64", ParquetPhysicalType.Int64, new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("optional-float", ParquetPhysicalType.Float, new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("optional-double", ParquetPhysicalType.Double, new ColumnOptions(encodings: Plain))
        };
        Array[] expected =
        [
            new bool?[] { null, false, true }, new int?[] { null, -7, 11 },
            new long?[] { null, -7000000001L, 11000000001L },
            new float?[] { null, -7.5f, 11.25f }, new double?[] { null, -7.5d, 11.25d }
        ];
        var schema = new PlankSchema([.. definitions]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, StatisticsWriterOptions());
        var rowGroup = writer.StartRowGroup();
        for (var i = 0; i < definitions.Length; i++)
            WriteNullablePrimitive(writer, rowGroup, schema.LeafColumns[i], i, expected[i]);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        for (var i = 0; i < expected.Length; i++)
            if (!ReadNullablePrimitive(reader, i).Cast<object?>().SequenceEqual(expected[i].Cast<object?>()))
                throw new InvalidOperationException($"Nullable primitive statistics changed values in column {i}.");
    }

    static void ExerciseNullableEmptyAndNaNStatistics()
    {
        // With no present values, optional numeric serialization takes the generic
        // statistics fallback. NaN-only float and double columns exercise the
        // present-value page-statistics path without a finite minimum or maximum.
        var definitions = new[]
        {
            ColumnDefinition.OptionalLeaf("all-null-int32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("all-null-int64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("all-null-float", ParquetPhysicalType.Float,
                new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("all-null-double", ParquetPhysicalType.Double,
                new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("nan-only-float", ParquetPhysicalType.Float,
                new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("nan-only-double", ParquetPhysicalType.Double,
                new ColumnOptions(encodings: Plain))
        };
        int?[] nullInt32 = [null, null];
        long?[] nullInt64 = [null, null];
        float?[] nullFloat = [null, null];
        double?[] nullDouble = [null, null];
        float?[] nanFloat = [float.NaN, float.NaN];
        double?[] nanDouble = [double.NaN, double.NaN];

        var schema = new PlankSchema([.. definitions]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, StatisticsWriterOptions());
        var rowGroup = writer.StartRowGroup();
        WriteNullable(writer, rowGroup, schema.LeafColumns[0], nullInt32);
        WriteNullable(writer, rowGroup, schema.LeafColumns[1], nullInt64);
        WriteNullable(writer, rowGroup, schema.LeafColumns[2], nullFloat);
        WriteNullable(writer, rowGroup, schema.LeafColumns[3], nullDouble);
        WriteNullable(writer, rowGroup, schema.LeafColumns[4], nanFloat);
        WriteNullable(writer, rowGroup, schema.LeafColumns[5], nanDouble);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 1)
            throw new InvalidOperationException("Nullable empty and NaN statistics case changed the row-group count.");
        if (!ReadAllBuffers(reader.RowGroups[0].Column<int?>(0)).AsSpan().SequenceEqual(nullInt32)
            || !ReadAllBuffers(reader.RowGroups[0].Column<long?>(1)).AsSpan().SequenceEqual(nullInt64)
            || !ReadAllBuffers(reader.RowGroups[0].Column<float?>(2)).AsSpan().SequenceEqual(nullFloat)
            || !ReadAllBuffers(reader.RowGroups[0].Column<double?>(3)).AsSpan().SequenceEqual(nullDouble))
            throw new InvalidOperationException("All-null nullable numeric writer values changed on readback.");

        var actualNanFloat = ReadAllBuffers(reader.RowGroups[0].Column<float?>(4));
        var actualNanDouble = ReadAllBuffers(reader.RowGroups[0].Column<double?>(5));
        if (actualNanFloat.Length != nanFloat.Length || actualNanFloat.Any(static value => value is not { } v || !float.IsNaN(v))
            || actualNanDouble.Length != nanDouble.Length
            || actualNanDouble.Any(static value => value is not { } v || !double.IsNaN(v)))
            throw new InvalidOperationException("NaN-only nullable numeric writer values changed on readback.");
    }

    static void ExerciseNullableUnsignedStatisticsExtremes()
    {
        // Start at the maximum, descend to zero, then ascend again. This makes
        // both min and max comparisons take both outcomes in nullable unsigned
        // statistics while preserving valid physical readback values.
        WriteAndReadPhysical("uint8-optional-extremes", ColumnDefinition.OptionalLeaf("uint8-optional-extremes",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(8, false)),
            new byte?[] { null, byte.MaxValue, 0, byte.MaxValue }, new int?[] { null, byte.MaxValue, 0, byte.MaxValue });
        WriteAndReadPhysical("uint16-optional-extremes", ColumnDefinition.OptionalLeaf("uint16-optional-extremes",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(16, false)),
            new ushort?[] { null, ushort.MaxValue, 0, ushort.MaxValue }, new int?[] { null, ushort.MaxValue, 0, ushort.MaxValue });
        WriteAndReadPhysical("uint32-optional-extremes", ColumnDefinition.OptionalLeaf("uint32-optional-extremes",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(32, false)),
            new uint?[] { null, uint.MaxValue, 0, uint.MaxValue },
            new int?[] { null, -1, 0, -1 });
        WriteAndReadPhysical("uint64-optional-extremes", ColumnDefinition.OptionalLeaf("uint64-optional-extremes",
                ParquetPhysicalType.Int64, new ColumnOptions(encodings: Plain), new LogicalType.Int(64, false)),
            new ulong?[] { null, ulong.MaxValue, 0, ulong.MaxValue },
            new long?[] { null, -1, 0, -1 });
    }

    static void ExerciseNullableFloatDoubleMinMax()
    {
        // Present zero first so the later negative zero exercises the signed-zero
        // comparison; finite extremes then take both min/max comparison outcomes.
        float?[] floats = [null, float.NaN, +0.0f, -0.0f, float.MaxValue, -float.MaxValue];
        double?[] doubles = [null, double.NaN, +0.0d, -0.0d, double.MaxValue, -double.MaxValue];
        var definitions = new[]
        {
            ColumnDefinition.OptionalLeaf("nullable-float-minmax", ParquetPhysicalType.Float,
                new ColumnOptions(encodings: Plain)),
            ColumnDefinition.OptionalLeaf("nullable-double-minmax", ParquetPhysicalType.Double,
                new ColumnOptions(encodings: Plain))
        };
        var schema = new PlankSchema([.. definitions]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, StatisticsWriterOptions());
        var rowGroup = writer.StartRowGroup();
        WriteNullable(writer, rowGroup, schema.LeafColumns[0], floats);
        WriteNullable(writer, rowGroup, schema.LeafColumns[1], doubles);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        AssertNullableFloatValues(ReadAllBuffers(reader.RowGroups[0].Column<float?>(0)), floats);
        AssertNullableDoubleValues(ReadAllBuffers(reader.RowGroups[0].Column<double?>(1)), doubles);
        AssertStatistics(reader.RowGroups[0].GetColumnMetadata(0).Statistics,
            EncodeFloat(-float.MaxValue), EncodeFloat(float.MaxValue), 1, "nullable-float-minmax");
        AssertStatistics(reader.RowGroups[0].GetColumnMetadata(1).Statistics,
            EncodeDouble(-double.MaxValue), EncodeDouble(double.MaxValue), 1, "nullable-double-minmax");
    }

    static void AssertNullableFloatValues(float?[] actual, float?[] expected)
    {
        if (actual.Length != expected.Length)
            throw new InvalidOperationException("Nullable float min/max writer changed the value count.");
        for (var i = 0; i < expected.Length; i++)
        {
            if (expected[i] is not { } expectedValue)
            {
                if (actual[i] is not null)
                    throw new InvalidOperationException($"Nullable float min/max writer changed value {i}.");
                continue;
            }
            if (actual[i] is not { } actualValue || (float.IsNaN(expectedValue)
                ? !float.IsNaN(actualValue)
                : BitConverter.SingleToInt32Bits(actualValue) != BitConverter.SingleToInt32Bits(expectedValue)))
                throw new InvalidOperationException($"Nullable float min/max writer changed value {i}.");
        }
    }

    static void AssertNullableDoubleValues(double?[] actual, double?[] expected)
    {
        if (actual.Length != expected.Length)
            throw new InvalidOperationException("Nullable double min/max writer changed the value count.");
        for (var i = 0; i < expected.Length; i++)
        {
            if (expected[i] is not { } expectedValue)
            {
                if (actual[i] is not null)
                    throw new InvalidOperationException($"Nullable double min/max writer changed value {i}.");
                continue;
            }
            if (actual[i] is not { } actualValue || (double.IsNaN(expectedValue)
                ? !double.IsNaN(actualValue)
                : BitConverter.DoubleToInt64Bits(actualValue) != BitConverter.DoubleToInt64Bits(expectedValue)))
                throw new InvalidOperationException($"Nullable double min/max writer changed value {i}.");
        }
    }

    static byte[] EncodeFloat(float value)
    {
        var bytes = new byte[sizeof(float)];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, BitConverter.SingleToInt32Bits(value));
        return bytes;
    }

    static byte[] EncodeDouble(double value)
    {
        var bytes = new byte[sizeof(double)];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, BitConverter.DoubleToInt64Bits(value));
        return bytes;
    }

    static void WriteNullablePrimitive(ParquetWriter writer, RowGroupWriter rowGroup, LeafColumn column, int index,
        Array values)
    {
        switch (index)
        {
            case 0: WriteNullable(writer, rowGroup, column, (bool?[])values); break;
            case 1: WriteNullable(writer, rowGroup, column, (int?[])values); break;
            case 2: WriteNullable(writer, rowGroup, column, (long?[])values); break;
            case 3: WriteNullable(writer, rowGroup, column, (float?[])values); break;
            default: WriteNullable(writer, rowGroup, column, (double?[])values); break;
        }
    }

    static void WriteNullable<T>(ParquetWriter writer, RowGroupWriter rowGroup, LeafColumn column, T?[] values)
        where T : struct
    {
        var serialized = writer.CreateSerializedColumn<T?>(column);
        serialized.Serialize(values);
        rowGroup.Write(serialized);
    }

    static Array ReadNullablePrimitive(ParquetReader reader, int index)
        => index switch
        {
            0 => ReadAllBuffers(reader.RowGroups[0].Column<bool?>(index)),
            1 => ReadAllBuffers(reader.RowGroups[0].Column<int?>(index)),
            2 => ReadAllBuffers(reader.RowGroups[0].Column<long?>(index)),
            3 => ReadAllBuffers(reader.RowGroups[0].Column<float?>(index)),
            _ => ReadAllBuffers(reader.RowGroups[0].Column<double?>(index))
        };


    static byte[] EncodeUnixMicros(DateTime value)
    {
        var result = new byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(result, (value.Ticks - DateTime.UnixEpoch.Ticks) / 10);
        return result;
    }

    static void AssertStatistics(ParquetStatistics statistics, ReadOnlySpan<byte> minimum,
        ReadOnlySpan<byte> maximum, long nullCount, string name)
    {
        if (!statistics.HasMinimum || !statistics.HasMaximum
            || !statistics.Minimum.SequenceEqual(minimum)
            || !statistics.Maximum.SequenceEqual(maximum)
            || statistics.NullCount != nullCount
            || !statistics.IsMinimumExact || !statistics.IsMaximumExact)
            throw new InvalidOperationException($"Footer statistics mismatch for '{name}'.");
    }

    static T[] ReadAllNestedValues<T>(NestedRowGroupColumn<T> column)
    {
        var values = new List<T>();
        foreach (var nestedBuffer in column)
            for (var i = 0; i < nestedBuffer.Values.Count; i++)
                values.Add(nestedBuffer.Values.GetValue(i)[0]);
        return values.ToArray();
    }

    static ParquetWriterOptions StatisticsWriterOptions()
        => new()
        {
            Compression = CompressionKind.None,
            DataPageVersion = ParquetDataPageVersion.V2,
            WritePageIndexes = false,
            TargetDataPageSizeBytes = 1024
        };

    static void ExerciseBasicMap()
    {
        var schema = new PlankSchema([ColumnDefinition.Map("attributes",
            ColumnDefinition.RequiredLeaf("key", ParquetPhysicalType.ByteArray,
                logicalType: new LogicalType.String()),
            ColumnDefinition.OptionalLeaf("value", ParquetPhysicalType.Int64,
                logicalType: new LogicalType.Timestamp(TimeUnit.Micros, true)))]);
        WriteAndCheckEmptySchema(schema);
    }

    static void ExerciseNestedMap()
    {
        var value = ColumnDefinition.List("items",
            ColumnDefinition.OptionalLeaf("item", ParquetPhysicalType.Int32,
                logicalType: new LogicalType.Int(16, false)));
        var schema = new PlankSchema([ColumnDefinition.Map("nested_attributes",
            ColumnDefinition.RequiredLeaf("key", ParquetPhysicalType.Int32, fieldId: 3,
                logicalType: new LogicalType.Int(32, true)),
            value, fieldId: 7, repetition: ParquetRepetition.Optional)]);
        WriteAndCheckEmptySchema(schema);
    }

    static void WriteAndCheckEmptySchema(PlankSchema schema)
    {
        using var stream = new MemoryStream();
        schema.CreateWriter(stream, WriterOptions(ParquetDataPageVersion.V2)).CloseFile();
        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 0)
            throw new InvalidOperationException("Metadata-only writer case unexpectedly wrote a row group.");
        if (reader.Schema.Definitions.Length != schema.Definitions.Length)
            throw new InvalidOperationException("Metadata-only writer case changed the schema root count.");
        for (var i = 0; i < schema.Definitions.Length; i++)
            AssertDefinition(schema.Definitions[i], reader.Schema.Definitions[i], schema.Definitions[i].Name);
    }

    static void AssertDefinition(ColumnDefinition expected, ColumnDefinition actual, string path,
        string? wireName = null)
    {
        if ((wireName ?? expected.Name) != actual.Name || expected.Kind != actual.Kind
            || expected.Repetition != actual.Repetition || expected.FieldId != actual.FieldId
            || expected.PhysicalType != actual.PhysicalType || !Equals(expected.LogicalType, actual.LogicalType)
            || expected.Children.Length != actual.Children.Length)
            throw new InvalidOperationException(
                $"Plank readback changed metadata for schema node '{path}': expected "
                + $"{wireName ?? expected.Name}/{expected.Kind}/{expected.Repetition}/field={expected.FieldId}/physical={expected.PhysicalType}/logical={expected.LogicalType}/children={expected.Children.Length}; got "
                + $"{actual.Name}/{actual.Kind}/{actual.Repetition}/field={actual.FieldId}/physical={actual.PhysicalType}/logical={actual.LogicalType}/children={actual.Children.Length}.");

        for (var i = 0; i < expected.Children.Length; i++)
        {
            var childWireName = expected.Kind switch
            {
                NodeKind.Map => i == 0 ? "key" : "value",
                NodeKind.List => "element",
                _ => null
            };
            AssertDefinition(expected.Children[i], actual.Children[i],
                $"{path}.{expected.Children[i].Name}", childWireName);
        }
    }

    static void ExerciseStatisticsAndPageIndexes(ParquetDataPageVersion pageVersion)
    {
        const int rowCount = 64;
        var requiredIntegers = new int[rowCount];
        var optionalIntegers = new int?[rowCount];
        var optionalFloats = new float?[rowCount];
        var optionalDoubles = new double?[rowCount];
        var optionalBinary = new byte[]?[rowCount];
        for (var i = 0; i < rowCount; i++)
        {
            requiredIntegers[i] = ((i * 17) % 23) - 11;
            optionalIntegers[i] = i < 16 || i % 7 == 0 ? null : requiredIntegers[i] * 4096;
            optionalFloats[i] = i < 16 || i % 9 == 0
                ? null
                : i % 11 == 0 ? float.NaN : i % 2 == 0 ? -0.0f : i - 31.5f;
            optionalDoubles[i] = i < 16 || i % 8 == 0
                ? null
                : i % 13 == 0 ? double.NaN : i % 2 == 0 ? -0.0d : i - 27.25d;
            optionalBinary[i] = (i % 8) switch
            {
                0 => null,
                1 => [],
                _ => [(byte)(255 - i), (byte)i, (byte)(i * 7)]
            };
        }

        var columns = new[]
        {
            new PlankWriterTarget.ColumnSpec(ColumnDefinition.RequiredLeaf("required-int32",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain)), typeof(int)),
            new PlankWriterTarget.ColumnSpec(ColumnDefinition.OptionalLeaf("optional-int32",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain)), typeof(int?)),
            new PlankWriterTarget.ColumnSpec(ColumnDefinition.OptionalLeaf("optional-float",
                ParquetPhysicalType.Float, new ColumnOptions(encodings: Plain)), typeof(float?)),
            new PlankWriterTarget.ColumnSpec(ColumnDefinition.OptionalLeaf("optional-double",
                ParquetPhysicalType.Double, new ColumnOptions(encodings: Plain)), typeof(double?)),
            new PlankWriterTarget.ColumnSpec(ColumnDefinition.OptionalLeaf("optional-binary",
                ParquetPhysicalType.ByteArray, new ColumnOptions(encodings: Plain)), typeof(byte[]))
        };
        var rowGroup = new Array[]
        {
            requiredIntegers, optionalIntegers, optionalFloats, optionalDoubles, optionalBinary
        };
        var fuzzCase = new PlankWriterTarget.FuzzCase(columns, [rowGroup], CompressionKind.None,
            new PlankWriterTarget.WriterSettings(pageVersion, WritePageCrc: true, WritePageIndexes: true,
                FileVersion: ParquetFileVersion.V1, TargetDataPageSizeBytes: 32,
                BufferChunkSizeBytes: 64, WithKeyValueMetadata: true));
        PlankWriterTarget.Validate(fuzzCase);
    }

    static void ExerciseUnsignedStatistics()
    {
        WriteAndReadPhysical("uint8-required", ColumnDefinition.RequiredLeaf("uint8-required",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(8, false)),
            UInt8RequiredValues, UInt8RequiredExpected);
        WriteAndReadPhysical("uint8-optional", ColumnDefinition.OptionalLeaf("uint8-optional",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(8, false)),
            new byte?[] { null, 0, 127, 255 }, new int?[] { null, 0, 127, 255 });
        WriteAndReadPhysical("uint16-required", ColumnDefinition.RequiredLeaf("uint16-required",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(16, false)),
            new ushort[] { 0, 1, 32768, ushort.MaxValue }, new int[] { 0, 1, 32768, ushort.MaxValue });
        WriteAndReadPhysical("uint16-optional", ColumnDefinition.OptionalLeaf("uint16-optional",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(16, false)),
            new ushort?[] { null, 0, 32768, ushort.MaxValue }, new int?[] { null, 0, 32768, ushort.MaxValue });
        WriteAndReadPhysical("uint32-required", ColumnDefinition.RequiredLeaf("uint32-required",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(32, false)),
            new uint[] { 0, 1, 0x8000_0000, uint.MaxValue },
            new[] { 0, 1, unchecked((int)0x8000_0000), -1 });
        WriteAndReadPhysical("uint32-optional", ColumnDefinition.OptionalLeaf("uint32-optional",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(32, false)),
            new uint?[] { null, 0, 0x8000_0000, uint.MaxValue },
            new int?[] { null, 0, unchecked((int)0x8000_0000), -1 });
        WriteAndReadPhysical("uint64-required", ColumnDefinition.RequiredLeaf("uint64-required",
                ParquetPhysicalType.Int64, new ColumnOptions(encodings: Plain), new LogicalType.Int(64, false)),
            new ulong[] { 0, 1, 0x8000_0000_0000_0000, ulong.MaxValue },
            new[] { 0L, 1L, unchecked((long)0x8000_0000_0000_0000), -1L });
        WriteAndReadPhysical("uint64-optional", ColumnDefinition.OptionalLeaf("uint64-optional",
                ParquetPhysicalType.Int64, new ColumnOptions(encodings: Plain), new LogicalType.Int(64, false)),
            new ulong?[] { null, 0, 0x8000_0000_0000_0000, ulong.MaxValue },
            new long?[] { null, 0, unchecked((long)0x8000_0000_0000_0000), -1 });
    }

    static void ExerciseEmptyPrimitiveStatistics()
    {
        // Empty serialization still builds column statistics for these CLR types.
        // Keep each public writer route in one selector so the empty-span guards
        // in ColumnStatistics can be replayed without a generated large plan.
        WriteAndReadPhysical("uint8-empty", ColumnDefinition.RequiredLeaf("uint8-empty",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(8, false)),
            Array.Empty<byte>(), Array.Empty<int>());
        WriteAndReadPhysical("uint16-empty", ColumnDefinition.RequiredLeaf("uint16-empty",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(16, false)),
            Array.Empty<ushort>(), Array.Empty<int>());
        WriteAndReadPhysical("uint32-empty", ColumnDefinition.RequiredLeaf("uint32-empty",
                ParquetPhysicalType.Int32, new ColumnOptions(encodings: Plain), new LogicalType.Int(32, false)),
            Array.Empty<uint>(), Array.Empty<int>());
        WriteAndReadPhysical("uint64-empty", ColumnDefinition.RequiredLeaf("uint64-empty",
                ParquetPhysicalType.Int64, new ColumnOptions(encodings: Plain), new LogicalType.Int(64, false)),
            Array.Empty<ulong>(), Array.Empty<long>());
    }

    static void ExerciseMemoryStatistics()
    {
        var required = new ReadOnlyMemory<byte>[]
        {
            new byte[] { 0 }, new byte[] { 0, 255 }, new byte[] { 1 }, new byte[] { 255 }
        };
        WriteAndReadMemory("memory-required", ColumnDefinition.RequiredLeaf("memory-required",
            ParquetPhysicalType.ByteArray, new ColumnOptions(encodings: Plain)), required,
            required.Select(static value => (byte[]?)value.ToArray()).ToArray());

        ReadOnlyMemory<byte>?[] optional = [null, Array.Empty<byte>(), new byte[] { 0 }, new byte[] { 255 }];
        WriteAndReadMemory("memory-optional", ColumnDefinition.OptionalLeaf("memory-optional",
            ParquetPhysicalType.ByteArray, new ColumnOptions(encodings: Plain)), optional,
            optional.Select(static value => value is { } memory ? memory.ToArray() : null).ToArray());
    }

    static void ExerciseDecimalStatistics()
    {
        // Keep Bloom filters disabled: decimal Bloom insertion is a separate, known
        // limitation and should not mask the nullable statistics path under test.
        var definitions = new[]
        {
            ColumnDefinition.OptionalLeaf("decimal-i32", ParquetPhysicalType.Int32,
                new ColumnOptions(encodings: Plain, bloomFilter: null), new LogicalType.Decimal(9, 2)),
            ColumnDefinition.OptionalLeaf("decimal-i64", ParquetPhysicalType.Int64,
                new ColumnOptions(encodings: Plain, bloomFilter: null), new LogicalType.Decimal(18, 4)),
            ColumnDefinition.OptionalLeaf("decimal-fixed", ParquetPhysicalType.FixedLenByteArray,
                new ColumnOptions(encodings: Plain, typeLength: 2, bloomFilter: null), new LogicalType.Decimal(3, 0)),
            ColumnDefinition.OptionalLeaf("decimal-binary", ParquetPhysicalType.ByteArray,
                new ColumnOptions(encodings: Plain, bloomFilter: null), new LogicalType.Decimal(3, 0))
        };
        decimal?[][] expected =
        [
            [null, -4.56m, 0m, 1.23m, null],
            [null, -1.2345m, 0m, 9999.9999m, null],
            [null, -129m, 0m, 128m, null],
            [null, -129m, 0m, 128m, null]
        ];
        byte[][] expectedMinimums =
        [
            [0x38, 0xfe, 0xff, 0xff],
            [0xc7, 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            [0xff, 0x7f],
            [0xff, 0x7f]
        ];
        byte[][] expectedMaximums =
        [
            [0x7b, 0x00, 0x00, 0x00],
            [0xff, 0xe0, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x80],
            [0x00, 0x80]
        ];

        var schema = new PlankSchema([.. definitions]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, WriterOptions(ParquetDataPageVersion.V2));
        var serialized = new SerializedColumn<decimal?>[definitions.Length];
        for (var i = 0; i < serialized.Length; i++)
        {
            serialized[i] = writer.CreateSerializedColumn<decimal?>(schema.LeafColumns[i]);
            serialized[i].Serialize(expected[i]);
        }
        var rowGroup = writer.StartRowGroup();
        foreach (var column in serialized)
            rowGroup.Write(column);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 1)
            throw new InvalidOperationException("Decimal statistics case changed the row-group count.");

        for (var i = 0; i < definitions.Length; i++)
        {
            var column = reader.RowGroups[0].Column<decimal?>(i);
            var actual = ReadAllBuffers(column);
            if (!actual.AsSpan().SequenceEqual(expected[i]))
                throw new InvalidOperationException(
                    $"Decimal readback mismatch for '{definitions[i].Name}'.");

            var metadata = column.Metadata;
            var statistics = metadata.Statistics;
            if (metadata.HasBloomFilter)
                throw new InvalidOperationException(
                    $"Decimal statistics case unexpectedly enabled a Bloom filter for '{definitions[i].Name}'.");
            if (!statistics.HasMinimum || !statistics.HasMaximum
                || !statistics.Minimum.SequenceEqual(expectedMinimums[i])
                || !statistics.Maximum.SequenceEqual(expectedMaximums[i])
                || statistics.NullCount != 2
                || !statistics.IsMinimumExact || !statistics.IsMaximumExact)
                throw new InvalidOperationException(
                    $"Decimal footer statistics mismatch for '{definitions[i].Name}'.");
        }
    }

    static void WriteAndReadPhysical<T, TPhysical>(string name, ColumnDefinition column, T[] values,
        TPhysical[] expected)
    {
        var schema = new PlankSchema([column]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, WriterOptions(ParquetDataPageVersion.V2));
        var serialized = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 1)
            throw new InvalidOperationException($"Writer metadata case '{name}' changed the row-group count.");
        var actual = ReadAllBuffers(reader.RowGroups[0].Column<TPhysical>(reader.Schema.LeafColumns[0]));
        if (!actual.AsSpan().SequenceEqual(expected))
            throw new InvalidOperationException($"Plank readback mismatch for writer metadata case '{name}'.");
    }

    static void WriteAndReadMemory<T>(string name, ColumnDefinition column, T[] values, byte[]?[] expected)
    {
        var schema = new PlankSchema([column]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, WriterOptions(ParquetDataPageVersion.V2));
        var serialized = writer.CreateSerializedColumn<T>(schema.LeafColumns[0]);
        serialized.Serialize(values);
        writer.StartRowGroup().Write(serialized);
        writer.CloseFile();

        using var source = FullValueOracle.Source(stream.ToArray());
        using var reader = new ParquetReader();
        reader.Reset(source);
        if (reader.RowGroups.Count != 1)
            throw new InvalidOperationException($"Writer metadata case '{name}' changed the row-group count.");

        var actual = new List<byte[]?>();
        foreach (var buffer in reader.RowGroups[0].Column<byte>(reader.Schema.LeafColumns[0]))
            for (var i = 0; i < buffer.Count; i++)
                actual.Add(buffer.IsNull(i) ? null : buffer.GetValue(i).ToArray());
        if (actual.Count != expected.Length)
            throw new InvalidOperationException($"Plank readback length mismatch for writer metadata case '{name}'.");
        for (var i = 0; i < expected.Length; i++)
            if (expected[i] is null ? actual[i] is not null : actual[i] is null
                || !actual[i]!.AsSpan().SequenceEqual(expected[i]))
                throw new InvalidOperationException($"Plank readback mismatch for writer metadata case '{name}' at row {i}.");
    }

    static T[] ReadAllBuffers<T>(RowGroupColumn<T> column)
    {
        var values = new List<T>();
        foreach (var buffer in column)
            foreach (var value in buffer.Values)
                values.Add(value);
        return values.ToArray();
    }

    static ParquetWriterOptions WriterOptions(ParquetDataPageVersion pageVersion)
        => new()
        {
            Compression = CompressionKind.None,
            DataPageVersion = pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            FileVersion = ParquetFileVersion.V1,
            TargetDataPageSizeBytes = 32,
            BufferChunkSizeBytes = 64,
            KeyValueMetadata = [new ParquetKeyValueMetadata("fuzz-metadata", "1")]
        };
}
