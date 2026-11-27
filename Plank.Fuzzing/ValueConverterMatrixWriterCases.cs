using System.Collections.Immutable;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;
using PlankWriterTarget = Plank.Fuzzing.PlankWriterFuzzTarget;

namespace Plank.Fuzzing;

/// <summary>Bounded custom-converter routes covering every supported physical CLR type.</summary>
public static class ValueConverterMatrixWriterCases
{
    static readonly ImmutableArray<EncodingKind> Plain = [EncodingKind.Plain];
    static readonly DateOnly UnixEpochDate = new(1970, 1, 1);

    public static void Execute(ReadOnlySpan<byte> controls)
    {
        var selector = Control(controls, 0, 0) % 28;
        var physical = selector % 14;
        var rowCount = 4 + Control(controls, 1, 5) % 9;
        var pageVersion = (Control(controls, 2, 0) & 1) == 0
            ? ParquetDataPageVersion.V2
            : ParquetDataPageVersion.V1;
        var valueBase = (Control(controls, 3, 137) - 128) * 4;
        var step = 1 + Control(controls, 4, 3) % 7;
        var nullMask = Control(controls, 5, 0xA5);
        var pageSize = new uint[] { 16, 64, 256 }[Control(controls, 6, 1) % 3];
        _pageVersion = pageVersion;
        _pageSize = pageSize;

        if (selector < 14)
            ExecuteRequired(physical, rowCount, valueBase, step, pageVersion, pageSize);
        else
            ExecuteOptional(physical, rowCount, valueBase, step, nullMask, pageVersion, pageSize);
    }

    static void ExecuteRequired(int physical, int rowCount, int valueBase, int step,
        ParquetDataPageVersion pageVersion, uint pageSize)
    {
        switch (physical)
        {
            case 0:
                RunRequired(ParquetPhysicalType.Boolean, null, 0, rowCount, valueBase, step,
                    static value => (value & 1) != 0, static value => value ? 1 : 0, static value => value,
                    static value => value & 1);
                break;
            case 1:
                RunRequired(ParquetPhysicalType.Int32, null, 0, rowCount, valueBase, step,
                    static value => unchecked((byte)value), static value => value, static value => (int)value,
                    static value => PositiveModulo(value, 256));
                break;
            case 2:
                RunRequired(ParquetPhysicalType.Int32, null, 0, rowCount, valueBase, step,
                    static value => unchecked((ushort)value), static value => value, static value => (int)value,
                    static value => PositiveModulo(value, 65_536));
                break;
            case 3:
                RunRequired(ParquetPhysicalType.Int32, null, 0, rowCount, valueBase, step,
                    static value => value, static value => value, static value => value);
                break;
            case 4:
                RunRequired(ParquetPhysicalType.Int32, null, 0, rowCount, valueBase, step,
                    static value => (uint)value, static value => checked((int)value), static value => unchecked((int)value),
                    static value => Math.Abs(value));
                break;
            case 5:
                RunRequired(ParquetPhysicalType.Int64, null, 0, rowCount, valueBase, step,
                    static value => (long)value, static value => checked((int)value), static value => value);
                break;
            case 6:
                RunRequired(ParquetPhysicalType.Int64, null, 0, rowCount, valueBase, step,
                    static value => (ulong)value, static value => checked((int)value), static value => unchecked((long)value),
                    static value => Math.Abs(value));
                break;
            case 7:
                RunRequired(ParquetPhysicalType.Float, null, 0, rowCount, valueBase, step,
                    static value => value / 4f, static value => checked((int)MathF.Round(value * 4f)), static value => value);
                break;
            case 8:
                RunRequired(ParquetPhysicalType.Double, null, 0, rowCount, valueBase, step,
                    static value => value / 4d, static value => checked((int)Math.Round(value * 4d)), static value => value);
                break;
            case 9:
                RunRequired(ParquetPhysicalType.FixedLenByteArray, new LogicalType.Uuid(), 16,
                    rowCount, valueBase, step,
                    static value => new Guid(value, 0, 0, new byte[8]),
                    static value => BitConverter.ToInt32(value.ToByteArray()),
                    static value => GuidToPhysicalBytes(value));
                break;
            case 10:
                RunRequired(ParquetPhysicalType.Int32, new LogicalType.Date(), 0,
                    rowCount, valueBase, step,
                    static value => UnixEpochDate.AddDays(value),
                    static value => value.DayNumber - UnixEpochDate.DayNumber,
                    static value => value);
                break;
            case 11:
                RunRequired(ParquetPhysicalType.Int64, new LogicalType.Timestamp(TimeUnit.Millis, false), 0,
                    rowCount, valueBase, step,
                    static value => FromDateTimeMilliseconds(value),
                    static value => checked((int)((value.Ticks - DateTime.UnixEpoch.Ticks) / TimeSpan.TicksPerMillisecond)),
                    static value => value);
                break;
            case 12:
                RunRequired(ParquetPhysicalType.Int64, new LogicalType.Timestamp(TimeUnit.Millis, true), 0,
                    rowCount, valueBase, step,
                    static value => DateTimeOffset.UnixEpoch.AddMilliseconds(value),
                    static value => checked((int)value.ToUnixTimeMilliseconds()),
                    static value => value);
                break;
            case 13:
                RunRequired(ParquetPhysicalType.Int64, new LogicalType.Time(TimeUnit.Micros, false), 0,
                    rowCount, valueBase, step,
                    static value => TimeOnly.MinValue.Add(TimeSpan.FromMilliseconds(PositiveModulo(value, 86_400_000))),
                    static value => checked((int)(value.Ticks / TimeSpan.TicksPerMillisecond)),
                    static value => value,
                    static value => PositiveModulo(value, 86_400_000));
                break;
            default:
                throw new InvalidOperationException($"Unknown converter physical type index {physical}.");
        }
    }

    static void ExecuteOptional(int physical, int rowCount, int valueBase, int step, byte nullMask,
        ParquetDataPageVersion pageVersion, uint pageSize)
    {
        switch (physical)
        {
            case 0:
                RunOptional(ParquetPhysicalType.Boolean, null, 0, rowCount, valueBase, step, nullMask,
                    static value => (value & 1) != 0, static value => value ? 1 : 0, static value => value,
                    static value => value & 1);
                break;
            case 1:
                RunOptional(ParquetPhysicalType.Int32, null, 0, rowCount, valueBase, step, nullMask,
                    static value => unchecked((byte)value), static value => value, static value => (int)value,
                    static value => PositiveModulo(value, 256));
                break;
            case 2:
                RunOptional(ParquetPhysicalType.Int32, null, 0, rowCount, valueBase, step, nullMask,
                    static value => unchecked((ushort)value), static value => value, static value => (int)value,
                    static value => PositiveModulo(value, 65_536));
                break;
            case 3:
                RunOptional(ParquetPhysicalType.Int32, null, 0, rowCount, valueBase, step, nullMask,
                    static value => value, static value => value, static value => value);
                break;
            case 4:
                RunOptional(ParquetPhysicalType.Int32, null, 0, rowCount, valueBase, step, nullMask,
                    static value => (uint)value, static value => checked((int)value), static value => unchecked((int)value),
                    static value => Math.Abs(value));
                break;
            case 5:
                RunOptional(ParquetPhysicalType.Int64, null, 0, rowCount, valueBase, step, nullMask,
                    static value => (long)value, static value => checked((int)value), static value => value);
                break;
            case 6:
                RunOptional(ParquetPhysicalType.Int64, null, 0, rowCount, valueBase, step, nullMask,
                    static value => (ulong)value, static value => checked((int)value), static value => unchecked((long)value),
                    static value => Math.Abs(value));
                break;
            case 7:
                RunOptional(ParquetPhysicalType.Float, null, 0, rowCount, valueBase, step, nullMask,
                    static value => value / 4f, static value => checked((int)MathF.Round(value * 4f)),
                    static value => value, static value => value);
                break;
            case 8:
                RunOptional(ParquetPhysicalType.Double, null, 0, rowCount, valueBase, step, nullMask,
                    static value => value / 4d, static value => checked((int)Math.Round(value * 4d)), static value => value,
                    static value => value);
                break;
            case 9:
                RunOptionalGuid(rowCount, valueBase, step, nullMask);
                break;
            case 10:
                RunOptional(ParquetPhysicalType.Int32, new LogicalType.Date(), 0,
                    rowCount, valueBase, step, nullMask,
                    static value => UnixEpochDate.AddDays(value),
                    static value => value.DayNumber - UnixEpochDate.DayNumber,
                    static value => value);
                break;
            case 11:
                RunOptional(ParquetPhysicalType.Int64, new LogicalType.Timestamp(TimeUnit.Millis, false), 0,
                    rowCount, valueBase, step, nullMask,
                    static value => FromDateTimeMilliseconds(value),
                    static value => checked((int)((value.Ticks - DateTime.UnixEpoch.Ticks) / TimeSpan.TicksPerMillisecond)),
                    static value => value);
                break;
            case 12:
                RunOptional(ParquetPhysicalType.Int64, new LogicalType.Timestamp(TimeUnit.Millis, true), 0,
                    rowCount, valueBase, step, nullMask,
                    static value => DateTimeOffset.UnixEpoch.AddMilliseconds(value),
                    static value => checked((int)value.ToUnixTimeMilliseconds()),
                    static value => value);
                break;
            case 13:
                RunOptional(ParquetPhysicalType.Int64, new LogicalType.Time(TimeUnit.Micros, false), 0,
                    rowCount, valueBase, step, nullMask,
                    static value => TimeOnly.MinValue.Add(TimeSpan.FromMilliseconds(PositiveModulo(value, 86_400_000))),
                    static value => checked((int)(value.Ticks / TimeSpan.TicksPerMillisecond)),
                    static value => value,
                    static value => PositiveModulo(value, 86_400_000));
                break;
            default:
                throw new InvalidOperationException($"Unknown converter physical type index {physical}.");
        }
    }

    static void RunRequired<TPhysical>(ParquetPhysicalType physicalType, LogicalType? logicalType, uint typeLength,
        int rowCount, int valueBase, int step, Func<int, TPhysical> toPhysical,
        Func<TPhysical, int> fromPhysical, Func<TPhysical, object?> project,
        Func<int, int>? normalize = null)
        where TPhysical : unmanaged
    {
        normalize ??= static value => value;
        var values = new IntBox[rowCount];
        var expectedPhysical = new object?[rowCount];
        for (var i = 0; i < rowCount; i++)
        {
            var value = normalize(valueBase + i * step);
            values[i] = new IntBox(value);
            expectedPhysical[i] = project(toPhysical(value));
        }

        var converter = new MatrixConverter<IntBox, TPhysical>(
            value => toPhysical(value.Value), value => new IntBox(fromPhysical(value)));
        Validate(ParquetRepetition.Required, physicalType, logicalType, typeLength, converter,
            values, typeof(IntBox), expectedPhysical, rowCount);
    }

    static void RunOptional<TPhysical>(ParquetPhysicalType physicalType, LogicalType? logicalType, uint typeLength,
        int rowCount, int valueBase, int step, byte nullMask, Func<int, TPhysical> toPhysical,
        Func<TPhysical, int> fromPhysical, Func<TPhysical, object?> project,
        Func<int, int>? normalize = null)
        where TPhysical : unmanaged
    {
        normalize ??= static value => value;
        var values = new LongBox?[rowCount];
        var expectedPhysical = new object?[rowCount];
        for (var i = 0; i < rowCount; i++)
        {
            if (i != 0 && (i == 1 || (nullMask & (1 << (i & 7))) != 0))
            {
                values[i] = null;
                expectedPhysical[i] = null;
                continue;
            }

            var value = normalize(valueBase + i * step);
            values[i] = new LongBox(value);
            expectedPhysical[i] = project(toPhysical(value));
        }

        var converter = new MatrixConverter<LongBox, TPhysical>(
            value => toPhysical(checked((int)value.Value)), value => new LongBox(fromPhysical(value)));
        Validate(ParquetRepetition.Optional, physicalType, logicalType, typeLength, converter,
            values, typeof(LongBox?), expectedPhysical, rowCount);
    }

    static void RunOptionalGuid(int rowCount, int valueBase, int step, byte nullMask)
    {
        var values = new LongBox?[rowCount];
        var expectedPhysical = new object?[rowCount];
        for (var i = 0; i < rowCount; i++)
        {
            if (i != 0 && (i == 1 || (nullMask & (1 << (i & 7))) != 0))
            {
                values[i] = null;
                expectedPhysical[i] = null;
                continue;
            }

            var value = valueBase + i * step;
            values[i] = new LongBox(value);
            expectedPhysical[i] = GuidToPhysicalBytes(new Guid(value, 0, 0, new byte[8]));
        }

        var converter = new MatrixConverter<LongBox, Guid>(
            value => new Guid(checked((int)value.Value), 0, 0, new byte[8]),
            value => new LongBox(BitConverter.ToInt32(value.ToByteArray())));
        Validate(ParquetRepetition.Optional, ParquetPhysicalType.FixedLenByteArray,
            new LogicalType.Uuid(), 16, converter, values, typeof(LongBox?), expectedPhysical, rowCount);
    }

    static void Validate<TValue, TPhysical>(ParquetRepetition repetition, ParquetPhysicalType physicalType,
        LogicalType? logicalType, uint typeLength, MatrixConverter<TValue, TPhysical> converter,
        Array expectedValues, Type valueType, object?[] expectedPhysical, int rowCount)
        where TValue : unmanaged
        where TPhysical : unmanaged
    {
        var options = new ColumnOptions(repetition, Plain, typeLength);
        var definition = ColumnDefinition.RequiredLeaf("converter-matrix", physicalType, options,
            logicalType, converter: converter);
        if (repetition == ParquetRepetition.Optional)
            definition = ColumnDefinition.OptionalLeaf("converter-matrix", physicalType, options,
                logicalType, converter: converter);
        var schema = new ParquetSchema([definition]);

        using var output = new MemoryStream();
        var writer = schema.CreateWriter(output, new ParquetWriterOptions
        {
            Compression = CompressionKind.None,
            DataPageVersion = _pageVersion,
            WritePageCrc = true,
            WritePageIndexes = true,
            FileVersion = ParquetFileVersion.V1,
            TargetDataPageSizeBytes = _pageSize,
            BufferChunkSizeBytes = 64
        });
        WriteConverted(writer, schema.LeafColumns[0], expectedValues, valueType);
        writer.CloseFile();
        var bytes = output.ToArray();

        AssertLogicalReadback(schema, bytes, expectedValues, valueType, rowCount);
        AssertPhysicalReadback(definition, bytes, physicalType, repetition, expectedPhysical, rowCount);
    }

    // The selectors pin these values before writing one case; keeping them thread-local avoids
    // passing writer-only controls through every typed branch.
    [ThreadStatic] static ParquetDataPageVersion _pageVersion;
    [ThreadStatic] static uint _pageSize;

    static void WriteConverted(ParquetWriter writer, LeafColumn column, Array values, Type valueType)
    {
        if (valueType == typeof(IntBox))
        {
            var serialized = writer.CreateSerializedColumn<IntBox>(column);
            serialized.Serialize((IntBox[])values);
            writer.StartRowGroup().Write(serialized);
            return;
        }

        if (valueType == typeof(LongBox?))
        {
            var serialized = writer.CreateSerializedColumn<LongBox?>(column);
            serialized.Serialize((LongBox?[])values);
            writer.StartRowGroup().Write(serialized);
            return;
        }

        throw new InvalidOperationException($"Unsupported converter matrix value type '{valueType}'.");
    }

    static void AssertLogicalReadback(ParquetSchema schema, byte[] bytes, Array expected, Type valueType, int rowCount)
    {
        using var input = new MemoryStream(bytes, writable: false);
        using var reader = schema.CreateReader(input);
        if (reader.RowGroups.Count != 1 || reader.RowGroups[0].Metadata.RowCount != (uint)rowCount)
            throw new InvalidOperationException("Converter matrix logical row-group count mismatch.");

        Array actual = valueType == typeof(IntBox)
            ? ReadAll(reader.RowGroups[0].Column<IntBox>(reader.Schema.LeafColumns[0]))
            : ReadAllNullable(reader.RowGroups[0].Column<LongBox?>(reader.Schema.LeafColumns[0]));
        AssertArraysEqual(expected, actual, "logical converter");
    }

    static void AssertPhysicalReadback(ColumnDefinition definition, byte[] bytes, ParquetPhysicalType physicalType,
        ParquetRepetition repetition, object?[] expected, int rowCount)
    {
        var rawDefinition = definition with { Converter = null };
        var rawSchema = new ParquetSchema([rawDefinition]);
        using var input = new MemoryStream(bytes, writable: false);
        using var reader = rawSchema.CreateReader(input);
        if (reader.Schema.LeafColumns.Length != 1 || reader.RowGroups.Count != 1
            || reader.RowGroups[0].Metadata.RowCount != (uint)rowCount)
            throw new InvalidOperationException("Converter matrix physical schema or row-group count mismatch.");

        var leaf = reader.Schema.LeafColumns[0];
        var chunk = GetChunkMetadata(reader.RowGroups[0], leaf, physicalType);
        if (leaf.PhysicalType != physicalType || leaf.LogicalType != definition.LogicalType
            || leaf.Options.Repetition != repetition || chunk.Definition.PhysicalType != physicalType
            || chunk.ValueCount != (ulong)rowCount)
            throw new InvalidOperationException(
                $"Converter matrix footer mismatch for {physicalType}/{repetition}: " +
                $"got {leaf.PhysicalType}/{leaf.LogicalType}/{leaf.Options.Repetition}, values={chunk.ValueCount}.");

        Array actual = physicalType switch
        {
            ParquetPhysicalType.Boolean => ReadPhysical<bool>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.Int32 when definition.LogicalType is LogicalType.Date
                => ReadPhysical<DateOnly>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.Int32 => ReadPhysical<int>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.Int64 when definition.LogicalType is LogicalType.Timestamp { IsAdjustedToUtc: true }
                => ReadPhysical<DateTimeOffset>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.Int64 when definition.LogicalType is LogicalType.Timestamp
                => ReadPhysical<DateTime>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.Int64 when definition.LogicalType is LogicalType.Time
                => ReadPhysical<TimeOnly>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.Int64 => ReadPhysical<long>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.Float => ReadPhysical<float>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.Double => ReadPhysical<double>(reader.RowGroups[0], leaf, repetition),
            ParquetPhysicalType.FixedLenByteArray when definition.LogicalType is LogicalType.Uuid
                => ReadFixedBinary(reader.RowGroups[0], leaf),
            _ => throw new InvalidOperationException($"Unexpected converter matrix physical type {physicalType}.")
        };
        AssertArraysEqual(expected, actual, "physical projection");
    }

    static byte[]?[] ReadFixedBinary(RowGroup rowGroup, LeafColumn column)
    {
        var values = new List<byte[]?>();
        foreach (var buffer in rowGroup.Column<byte>(column))
            for (var i = 0; i < buffer.Count; i++)
                values.Add(buffer.IsNull(i) ? null : buffer.GetValue(i).ToArray());
        return values.ToArray();
    }

    static ParquetColumnChunkMetadata GetChunkMetadata(RowGroup rowGroup, LeafColumn column,
        ParquetPhysicalType physicalType)
        => physicalType switch
        {
            ParquetPhysicalType.Boolean => rowGroup.Column<bool>(column).Metadata,
            ParquetPhysicalType.Int32 => rowGroup.Column<int>(column).Metadata,
            ParquetPhysicalType.Int64 => rowGroup.Column<long>(column).Metadata,
            ParquetPhysicalType.Float => rowGroup.Column<float>(column).Metadata,
            ParquetPhysicalType.Double => rowGroup.Column<double>(column).Metadata,
            ParquetPhysicalType.FixedLenByteArray => rowGroup.Column<byte>(column).Metadata,
            _ => throw new InvalidOperationException($"Unexpected converter matrix physical type {physicalType}.")
        };

    static Array ReadPhysical<T>(RowGroup rowGroup, LeafColumn column, ParquetRepetition repetition)
        where T : unmanaged
        => repetition == ParquetRepetition.Optional
            ? ReadAllNullable(rowGroup.Column<T?>(column))
            : ReadAll(rowGroup.Column<T>(column));

    static T[] ReadAll<T>(RowGroupColumn<T> column)
    {
        var values = new List<T>();
        foreach (var buffer in column)
            values.AddRange(buffer.Values.ToArray());
        return values.ToArray();
    }

    static T?[] ReadAllNullable<T>(RowGroupColumn<T?> column) where T : struct
    {
        var values = new List<T?>();
        foreach (var buffer in column)
            values.AddRange(buffer.Values.ToArray());
        return values.ToArray();
    }

    static void AssertArraysEqual(Array expected, Array actual, string view)
    {
        if (expected.Length != actual.Length)
            throw new InvalidOperationException($"Converter matrix {view} length mismatch: {expected.Length} vs {actual.Length}.");
        for (var i = 0; i < expected.Length; i++)
        {
            var expectedValue = expected.GetValue(i);
            var actualValue = actual.GetValue(i);
            var equal = expectedValue is byte[] expectedBytes && actualValue is byte[] actualBytes
                ? expectedBytes.AsSpan().SequenceEqual(actualBytes)
                : Equals(expectedValue, actualValue);
            if (!equal)
                throw new InvalidOperationException(
                    $"Converter matrix {view} mismatch at row {i}: {Describe(expectedValue)} vs {Describe(actualValue)}.");
        }
    }

    static string Describe(object? value)
        => value is byte[] bytes ? Convert.ToHexString(bytes) : value?.ToString() ?? "null";

    static int PositiveModulo(int value, int modulus)
        => (int)(((long)value % modulus + modulus) % modulus);

    static byte[] GuidToPhysicalBytes(Guid value)
    {
        var bytes = new byte[16];
        if (!value.TryWriteBytes(bytes, bigEndian: true, out var bytesWritten) || bytesWritten != bytes.Length)
            throw new InvalidOperationException("Guid did not produce its 16-byte Parquet UUID representation.");
        return bytes;
    }

    static DateTime FromDateTimeMilliseconds(int milliseconds)
        => new(DateTime.UnixEpoch.Ticks + milliseconds * TimeSpan.TicksPerMillisecond,
            DateTimeKind.Unspecified);

    static byte Control(ReadOnlySpan<byte> data, int index, byte fallback)
        => data.Length > index ? data[index] : fallback;

    sealed class MatrixConverter<TValue, TPhysical>(Func<TValue, TPhysical> toPhysical,
        Func<TPhysical, TValue> fromPhysical) : ParquetValueConverter<TValue, TPhysical>
        where TValue : unmanaged
        where TPhysical : unmanaged
    {
        public override TPhysical ConvertToPhysical(TValue value) => toPhysical(value);

        public override TValue ConvertFromPhysical(TPhysical value) => fromPhysical(value);
    }
}
