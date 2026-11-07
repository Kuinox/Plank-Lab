using System.Numerics;
using Plank.Reading.Logical;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>
/// Checks the CLR values Plank produces for annotated columns against a conversion of the
/// physical values written from the Parquet specification.
/// </summary>
/// <remarks>
/// The Arrow oracle compares physical values, and CrossCheckReadPaths compares two Plank
/// read paths with each other. Neither can see a logical conversion that is wrong
/// everywhere — a date off by a day, a decimal with the wrong sign, a UUID with swapped
/// bytes, a timestamp with the wrong DateTimeKind — and Plank implements several of those
/// conversions more than once (one per decode family). The physical values compared here
/// are Plank's own, which the Arrow comparison has already checked.
///
/// Plank may reject a value it cannot represent (throwing on odd input is fine). What it
/// must not do is return a value that differs from the specified conversion, or return
/// any value at all for a physical value the CLR type cannot represent.
/// </remarks>
public static class LogicalOracle
{
    public static long ComparedValues;

    enum Verdict { Representable, Unrepresentable, Unspecified }

    readonly record struct Expected<T>(Verdict Verdict, T Value)
    {
        public static Expected<T> Is(T value) => new(Verdict.Representable, value);
        public static readonly Expected<T> Not = new(Verdict.Unrepresentable, default!);
        public static readonly Expected<T> Any = new(Verdict.Unspecified, default!);
    }

    static readonly DateOnly UnixEpochDate = DateOnly.FromDateTime(DateTime.UnixEpoch);

    public static void Check(RowGroup rowGroup, LeafColumn column, ColumnTrace trace)
    {
        if (trace.Nested || trace.Overflowed || column.MaxRepetitionLevel > 0)
            return;
        var physical = column.PhysicalType;
        switch (column.LogicalType)
        {
            case LogicalType.Date when physical == ParquetPhysicalType.Int32:
                Compare(rowGroup, column, trace, "Date", static b => ExpectDate(BitConverter.ToInt32(b)),
                    static (e, a) => e == a);
                return;
            case LogicalType.Time time:
                Compare(rowGroup, column, trace, $"Time({time.Unit})", b => ExpectTime(time.Unit, physical, b),
                    static (e, a) => e == a);
                return;
            case LogicalType.Timestamp timestamp when physical == ParquetPhysicalType.Int64:
            {
                var kind = timestamp.IsAdjustedToUtc ? DateTimeKind.Utc : DateTimeKind.Unspecified;
                Compare(rowGroup, column, trace, $"Timestamp({timestamp.Unit}, utc={timestamp.IsAdjustedToUtc})",
                    b => ExpectTimestamp(timestamp.Unit, BitConverter.ToInt64(b), kind),
                    static (e, a) => e.Ticks == a.Ticks && e.Kind == a.Kind);
                if (timestamp.IsAdjustedToUtc)
                    Compare(rowGroup, column, trace, $"TimestampOffset({timestamp.Unit})",
                        b => ExpectTimestamp(timestamp.Unit, BitConverter.ToInt64(b), kind) is var e
                            && e.Verdict == Verdict.Representable
                            ? Expected<DateTimeOffset>.Is(new DateTimeOffset(e.Value.Ticks, TimeSpan.Zero))
                            : new Expected<DateTimeOffset>(e.Verdict, default),
                        static (e, a) => e.UtcTicks == a.UtcTicks && a.Offset == TimeSpan.Zero);
                return;
            }
            case LogicalType.Decimal decimalType:
                Compare(rowGroup, column, trace, $"Decimal({decimalType.Precision},{decimalType.Scale})",
                    b => ExpectDecimal(physical, b, decimalType.Scale),
                    // decimal equality is numeric; the scale a value carries is a representation detail.
                    static (e, a) => e == a);
                return;
            case LogicalType.Uuid when physical == ParquetPhysicalType.FixedLenByteArray:
                Compare(rowGroup, column, trace, "Uuid",
                    static b => b.Length == 16 ? Expected<Guid>.Is(new Guid(b, bigEndian: true)) : Expected<Guid>.Any,
                    static (e, a) => e == a);
                return;
            case LogicalType.Int { IsSigned: false, BitWidth: 8 } when physical == ParquetPhysicalType.Int32:
                Compare(rowGroup, column, trace, "UInt8",
                    static b => BitConverter.ToInt32(b) is >= 0 and <= byte.MaxValue and var v
                        ? Expected<byte>.Is((byte)v) : Expected<byte>.Any,
                    static (e, a) => e == a);
                return;
            case LogicalType.Int { IsSigned: false, BitWidth: 16 } when physical == ParquetPhysicalType.Int32:
                Compare(rowGroup, column, trace, "UInt16",
                    static b => BitConverter.ToInt32(b) is >= 0 and <= ushort.MaxValue and var v
                        ? Expected<ushort>.Is((ushort)v) : Expected<ushort>.Any,
                    static (e, a) => e == a);
                return;
            case LogicalType.Int { IsSigned: false, BitWidth: 32 } when physical == ParquetPhysicalType.Int32:
                // Stored as the bits of the unsigned value.
                Compare(rowGroup, column, trace, "UInt32",
                    static b => Expected<uint>.Is(BitConverter.ToUInt32(b)), static (e, a) => e == a);
                return;
            case LogicalType.Int { IsSigned: false, BitWidth: 64 } when physical == ParquetPhysicalType.Int64:
                Compare(rowGroup, column, trace, "UInt64",
                    static b => Expected<ulong>.Is(BitConverter.ToUInt64(b)), static (e, a) => e == a);
                return;
        }
    }

    static Expected<DateOnly> ExpectDate(int days)
    {
        var dayNumber = (long)UnixEpochDate.DayNumber + days;
        return dayNumber >= DateOnly.MinValue.DayNumber && dayNumber <= DateOnly.MaxValue.DayNumber
            ? Expected<DateOnly>.Is(DateOnly.FromDayNumber((int)dayNumber))
            : Expected<DateOnly>.Not;
    }

    static Expected<TimeOnly> ExpectTime(TimeUnit unit, ParquetPhysicalType physical, byte[] b)
    {
        // Only the combinations the specification allows have a defined meaning.
        Int128 ticks;
        switch (unit)
        {
            case TimeUnit.Millis when physical == ParquetPhysicalType.Int32:
                ticks = (Int128)BitConverter.ToInt32(b) * TimeSpan.TicksPerMillisecond;
                break;
            case TimeUnit.Micros when physical == ParquetPhysicalType.Int64:
                ticks = (Int128)BitConverter.ToInt64(b) * 10;
                break;
            case TimeUnit.Nanos when physical == ParquetPhysicalType.Int64:
            {
                var raw = BitConverter.ToInt64(b);
                if (raw < 0)
                    return Expected<TimeOnly>.Not;
                ticks = raw / 100;
                break;
            }
            default:
                return Expected<TimeOnly>.Any;
        }
        return ticks >= 0 && ticks <= TimeOnly.MaxValue.Ticks
            ? Expected<TimeOnly>.Is(new TimeOnly((long)ticks))
            : Expected<TimeOnly>.Not;
    }

    static Expected<DateTime> ExpectTimestamp(TimeUnit unit, long raw, DateTimeKind kind)
    {
        Int128 ticks = unit switch
        {
            TimeUnit.Millis => (Int128)raw * TimeSpan.TicksPerMillisecond,
            TimeUnit.Micros => (Int128)raw * 10,
            // Truncation toward zero, as Plank documents for sub-tick values.
            TimeUnit.Nanos => raw / 100,
            _ => Int128.MinValue,
        };
        if (ticks == Int128.MinValue)
            return Expected<DateTime>.Any;
        ticks += DateTime.UnixEpoch.Ticks;
        return ticks >= 0 && ticks <= DateTime.MaxValue.Ticks
            ? Expected<DateTime>.Is(new DateTime((long)ticks, kind))
            : Expected<DateTime>.Not;
    }

    static Expected<decimal> ExpectDecimal(ParquetPhysicalType physical, byte[] b, int scale)
    {
        BigInteger unscaled;
        switch (physical)
        {
            case ParquetPhysicalType.Int32: unscaled = BitConverter.ToInt32(b); break;
            case ParquetPhysicalType.Int64: unscaled = BitConverter.ToInt64(b); break;
            case ParquetPhysicalType.FixedLenByteArray or ParquetPhysicalType.ByteArray when b.Length > 0:
                unscaled = new BigInteger(b, isUnsigned: false, isBigEndian: true);
                break;
            default:
                return Expected<decimal>.Any;
        }
        if (scale < 0)
            return Expected<decimal>.Any;
        // Reduce trailing zeros so that a value with a large scale or a large unscaled
        // part still counts as representable when System.Decimal can hold it exactly.
        while (scale > 0 && !unscaled.IsZero && unscaled % 10 == 0)
        {
            unscaled /= 10;
            scale--;
        }
        if (unscaled.IsZero)
            scale = 0;
        if (scale > 28)
            return Expected<decimal>.Not;
        var magnitude = BigInteger.Abs(unscaled);
        if (magnitude >> 96 != 0)
            return Expected<decimal>.Not;
        var words = magnitude.ToByteArray(isUnsigned: true, isBigEndian: false);
        Array.Resize(ref words, 12);
        return Expected<decimal>.Is(new decimal(BitConverter.ToInt32(words, 0), BitConverter.ToInt32(words, 4),
            BitConverter.ToInt32(words, 8), unscaled.Sign < 0, (byte)scale));
    }

    static void Compare<T>(RowGroup rowGroup, LeafColumn column, ColumnTrace trace, string what,
        Func<byte[], Expected<T>> expect, Func<T, T, bool> same) where T : struct
    {
        List<T?> actual;
        try
        {
            actual = Read<T>(rowGroup, column);
        }
        catch (Exception error) when (error is CorruptParquetException or NotSupportedException
                                          or InvalidOperationException)
        {
            // Rejecting is always allowed.
            return;
        }

        var physical = trace.FlatValues();
        if (physical.Count != actual.Count)
            throw new ReaderAcceptanceMismatchException(
                $"Decoded value mismatch (logical {what}) — {physical.Count} physical values, {actual.Count} logical values, column '{column.Path}'.");

        for (var i = 0; i < physical.Count; i++)
        {
            var bytes = physical[i];
            var value = actual[i];
            if ((bytes is null) != (value is null))
                throw new ReaderAcceptanceMismatchException(
                    $"Decoded value mismatch (logical {what}) — row {i}: physical {(bytes is null ? "null" : "present")}, logical {(value is null ? "null" : "present")}.");
            if (bytes is null)
                continue;
            ComparedValues++;
            var expected = expect(bytes);
            switch (expected.Verdict)
            {
                case Verdict.Unrepresentable:
                    throw new ReaderAcceptanceMismatchException(
                        $"Decoded value mismatch (logical {what}) — row {i}: physical={Convert.ToHexString(bytes)} is outside {typeof(T).Name}, but Plank returned {Show(value!.Value)}.");
                case Verdict.Representable when !same(expected.Value, value!.Value):
                    throw new ReaderAcceptanceMismatchException(
                        $"Decoded value mismatch (logical {what}) — row {i}: physical={Convert.ToHexString(bytes)}, Plank={Show(value.Value)}, expected={Show(expected.Value)}.");
            }
        }
    }

    static string Show<T>(T value) => value switch
    {
        DateTime d => $"{d:O} ({d.Kind}, ticks {d.Ticks})",
        DateTimeOffset o => $"{o:O} (ticks {o.UtcTicks})",
        TimeOnly t => $"{t:O} (ticks {t.Ticks})",
        _ => value?.ToString() ?? "null",
    };

    static List<T?> Read<T>(RowGroup rowGroup, LeafColumn column) where T : struct
    {
        var values = new List<T?>();
        if (column.MaxDefinitionLevel > 0)
        {
            foreach (var buffer in rowGroup.Column<T?>(column))
                foreach (var value in buffer.Values)
                    values.Add(value);
        }
        else
        {
            foreach (var buffer in rowGroup.Column<T>(column))
                foreach (var value in buffer.Values)
                    values.Add(value);
        }
        return values;
    }
}
