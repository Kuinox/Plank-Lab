using System.Numerics;
using Plank.Reading.Logical;
using Plank.Schema;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Independent check of everything the writer derives from the values it was given: chunk min / max /
/// null_count, per-page column-index min / max / null flags, offset-index row ranges, boundary order and
/// Bloom-filter membership. Wrong statistics make readers skip data that matches, so they are silent corruption.
/// </summary>
/// <remarks>
/// The expected bounds are computed from the CLR values with their own ordering rules (signed / unsigned integer
/// order, IEEE order with NaN excluded, signed big-endian two's-complement order for decimal byte arrays,
/// unsigned lexicographic order for binary) and compared with the statistics decoded from the file bytes.
/// Float zero signs are compared numerically (the spec only recommends -0 / +0 for min / max).
/// </remarks>
internal static class WriterStatisticsOracle
{
    sealed class ByteKey(byte[] bytes) : IComparable
    {
        public byte[] Bytes { get; } = bytes;
        public int CompareTo(object? other) => Bytes.AsSpan().SequenceCompareTo(((ByteKey)other!).Bytes);
        public override string ToString() => Convert.ToHexString(Bytes);
    }

    static readonly long UnixEpochTicks = DateTime.UnixEpoch.Ticks;

    // Proof the oracle compares something: PLANK_ORACLE_COUNTERS=1 prints these when the process exits.
    static long _chunks, _minMax, _pages, _pageMinMax, _bloomProbes, _boundaryOrders;

    static WriterStatisticsOracle()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"ORACLE chunks={_chunks} minmax={_minMax} pages={_pages} pageMinMax={_pageMinMax} " +
                $"bloomProbes={_bloomProbes} orderedBoundaryChecks={_boundaryOrders}");
    }

    internal static void Check<T>(string what, PlankSchema schema, byte[] file, int[] bounds, T[] values,
        bool pageIndexExpected, bool bloomExpected, Func<T, IComparable?>? keyOverride = null)
    {
        var column = schema.LeafColumns[0];
        // `keyOverride` is for columns with a value converter: the order is that of the converted physical value.
        var key = keyOverride ?? KeyFor<T>(column);
        var decode = DecoderFor(column);
        if (key is null || decode is null)
            return;

        using var reader = schema.CreateReader(new MemoryStream(file, writable: false));
        for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            var from = bounds[g];
            var to = bounds[g + 1];
            var keys = new IComparable?[to - from];
            var isNull = new bool[to - from];
            var nulls = 0;
            for (var i = 0; i < keys.Length; i++)
            {
                var v = values[from + i];
                if (IsNull(v))
                {
                    nulls++;
                    isNull[i] = true;
                }
                else
                    keys[i] = key(v);
            }

            // Negative test of the oracle itself: PLANK_ORACLE_SELFTEST=1 corrupts one expected key, so
            // every case with a comparable integer / decimal / date value must then fail.
            if (Environment.GetEnvironmentVariable("PLANK_ORACLE_SELFTEST") == "1")
                for (var i = 0; i < keys.Length; i++)
                    if (keys[i] is long l)
                    {
                        keys[i] = l + 1;
                        break;
                    }
                    else if (keys[i] is BigInteger bi)
                    {
                        keys[i] = bi + 1;
                        break;
                    }

            var chunk = reader.RowGroups[g].GetColumnMetadata(0);
            _chunks++;
            var statistics = chunk.Statistics;
            if (statistics.NullCount is { } nullCount && nullCount != nulls)
                throw Fail(what, g, $"null_count {nullCount} != {nulls}");
            CheckBounds(what, g, "chunk", statistics.HasMinimum, statistics.HasMaximum,
                statistics.Minimum, statistics.Maximum, statistics.IsMinimumExact, statistics.IsMaximumExact,
                keys, decode);

            if (pageIndexExpected)
                CheckPages(what, g, chunk, keys, isNull, decode);

            if (bloomExpected && keys.Any(static k => k is not null))
                CheckBloom(what, g, chunk, values.AsSpan(from, to - from));
        }
    }

    /// <summary>
    /// Chunk and page statistics plus Bloom membership of one NESTED leaf column. `values` are the non-null leaf
    /// values of the chunk (boxed model values). null_count is not compared: for nested columns it also counts
    /// empty and null ancestors, which is a convention rather than a value fact.
    /// </summary>
    internal static void CheckNestedChunk(string what, int group, LeafColumn column,
        ParquetColumnChunkMetadata chunk, IReadOnlyList<object> values, bool bloomExpected)
    {
        var decode = DecoderFor(column);
        if (decode is null)
            return;
        var keys = values.Select(v => KeyOfModelValue(column, v)).ToArray();
        _chunks++;
        var statistics = chunk.Statistics;
        CheckBounds(what, group, "nested chunk", statistics.HasMinimum, statistics.HasMaximum,
            statistics.Minimum, statistics.Maximum, statistics.IsMinimumExact, statistics.IsMaximumExact, keys, decode);

        if (chunk.HasOffsetIndex || chunk.HasColumnIndex)
        {
            using var pages = chunk.OpenPages();
            IComparable? lowest = null, highest = null;
            var allExact = true;
            for (var i = 0; i < pages.Count; i++)
            {
                var page = pages[i];
                _pages++;
                var stats = page.Statistics;
                if (stats is { HasMinimum: true, HasMaximum: true })
                {
                    var min = decode(stats.Minimum.ToArray());
                    var max = decode(stats.Maximum.ToArray());
                    if (min is null || max is null)
                        continue;
                    _pageMinMax++;
                    if (min.CompareTo(max) > 0)
                        throw Fail(what, group, $"nested page {i} min {min} is greater than max {max}");
                    allExact &= stats.IsMinimumExact && stats.IsMaximumExact;
                    lowest = lowest is null || min.CompareTo(lowest) < 0 ? min : lowest;
                    highest = highest is null || max.CompareTo(highest) > 0 ? max : highest;
                }
            }

            var present = keys.Where(static k => k is not null).Select(static k => k!).ToArray();
            if (present.Length > 0 && lowest is not null && highest is not null && allExact
                && pages.Count > 0 && (lowest.CompareTo(present.Min()!) != 0 || highest.CompareTo(present.Max()!) != 0)
                && present.Length == values.Count)
            {
                // Pages with only NaN or no bounds are skipped above; with every page bounded the union must be exact.
                if (Enumerable.Range(0, pages.Count).All(i => pages[i].Statistics.HasMinimum))
                    throw Fail(what, group, $"nested pages cover [{lowest}, {highest}], values span [{present.Min()}, {present.Max()}]");
            }
        }

        if (bloomExpected && values.Count > 0)
        {
            if (!chunk.HasBloomFilter)
                throw Fail(what, group, "a bloom filter was requested but the nested chunk has none");
            using var filter = chunk.OpenBloomFilter();
            foreach (var value in values)
            {
                var present = value switch
                {
                    int v when column.PhysicalType == ParquetPhysicalType.Int32 => filter.MightContain(v),
                    BigInteger v when column.PhysicalType == ParquetPhysicalType.Int32 => filter.MightContain((int)v),
                    BigInteger v when column.PhysicalType == ParquetPhysicalType.Int64 => filter.MightContain((long)v),
                    double v => filter.MightContain(v),
                    byte[] v when column.LogicalType is not LogicalType.Decimal => filter.MightContain(v),
                    _ => (bool?)null
                };
                if (present is null)
                    continue;
                _bloomProbes++;
                if (!present.Value)
                    throw Fail(what, group, $"nested bloom filter does not contain written value '{value}'");
            }
        }
    }

    static void CheckBounds(string what, int group, string level, bool hasMin, bool hasMax,
        ReadOnlySpan<byte> minBytes, ReadOnlySpan<byte> maxBytes, bool minExact, bool maxExact,
        IComparable?[] keys, Func<byte[], IComparable?> decode)
    {
        var present = keys.Where(static k => k is not null).Select(static k => k!).ToArray();
        if (present.Length == 0)
            return;
        var trueMin = present.Min()!;
        var trueMax = present.Max()!;
        if (hasMin)
        {
            var actual = decode(minBytes.ToArray());
            if (actual is not null)
            {
                if (level == "chunk") _minMax++; else _pageMinMax++;
                var order = actual.CompareTo(trueMin);
                if (minExact ? order != 0 : order > 0)
                    throw Fail(what, group, $"{level} min {actual} vs expected {trueMin} (exact={minExact})");
            }
        }

        if (hasMax)
        {
            var actual = decode(maxBytes.ToArray());
            if (actual is not null)
            {
                var order = actual.CompareTo(trueMax);
                if (maxExact ? order != 0 : order < 0)
                    throw Fail(what, group, $"{level} max {actual} vs expected {trueMax} (exact={maxExact})");
            }
        }
    }

    static void CheckPages(string what, int group, ParquetColumnChunkMetadata chunk, IComparable?[] keys, bool[] isNull,
        Func<byte[], IComparable?> decode)
    {
        if (!chunk.HasOffsetIndex)
            throw Fail(what, group, "page indexes were requested but the chunk has no offset index");
        using var pages = chunk.OpenPages();
        if (pages.Count == 0)
            throw Fail(what, group, "offset index lists no pages");

        ulong nextRow = 0;
        IComparable? previousMin = null, previousMax = null;
        var ascending = true;
        var descending = true;
        for (var i = 0; i < pages.Count; i++)
        {
            var page = pages[i];
            _pages++;
            var first = page.FirstRowIndex;
            var count = page.RowCount;
            if (first is null || count is null)
                throw Fail(what, group, $"page {i} has no row range");
            if (first != nextRow)
                throw Fail(what, group, $"page {i} starts at row {first}, expected {nextRow}");
            nextRow += count.Value;
            if (nextRow > (ulong)keys.Length)
                throw Fail(what, group, $"page {i} runs past the {keys.Length} rows of the chunk");

            var slice = keys.AsSpan((int)first.Value, (int)count.Value).ToArray();
            var pageNulls = isNull.AsSpan((int)first.Value, (int)count.Value).ToArray().Count(static n => n);
            var stats = page.Statistics;
            if (stats.NullCount is { } pageNullCount && pageNullCount != pageNulls)
                throw Fail(what, group, $"page {i} null_count {pageNullCount} != {pageNulls}");
            if (page.IsNullPage is { } nullPageFlag && nullPageFlag != (pageNulls == slice.Length))
                throw Fail(what, group, $"page {i} null_page flag {nullPageFlag} but {pageNulls}/{slice.Length} nulls");
            CheckBounds(what, group, $"page {i}", stats.HasMinimum, stats.HasMaximum, stats.Minimum, stats.Maximum,
                stats.IsMinimumExact, stats.IsMaximumExact, slice, decode);

            if (stats is { HasMinimum: true, HasMaximum: true })
            {
                var min = decode(stats.Minimum.ToArray());
                var max = decode(stats.Maximum.ToArray());
                if (min is not null && max is not null && min.CompareTo(max) > 0)
                    throw Fail(what, group, $"page {i} min {min} is greater than max {max}");
                if (previousMin is not null && min is not null && max is not null && previousMax is not null)
                {
                    ascending &= previousMin.CompareTo(min) <= 0 && previousMax.CompareTo(max) <= 0;
                    descending &= previousMin.CompareTo(min) >= 0 && previousMax.CompareTo(max) >= 0;
                }

                previousMin = min;
                previousMax = max;
            }
        }

        if (nextRow != (ulong)keys.Length)
            throw Fail(what, group, $"pages cover {nextRow} rows, the chunk has {keys.Length}");
        var order = pages.BoundaryOrder;
        // boundary_order is a required field of the ColumnIndex: when the index exists it must say something
        // (Unordered is always a valid answer, and is what the writer currently writes for every column).
        if (chunk.HasColumnIndex && order == ParquetBoundaryOrder.Unknown)
            throw Fail(what, group, "the column index has no boundary order");
        if (order is ParquetBoundaryOrder.Ascending or ParquetBoundaryOrder.Descending)
            _boundaryOrders++;
        if (order == ParquetBoundaryOrder.Ascending && !ascending)
            throw Fail(what, group, "boundary order says ascending but the page bounds are not");
        if (order == ParquetBoundaryOrder.Descending && !descending)
            throw Fail(what, group, "boundary order says descending but the page bounds are not");
    }

    static void CheckBloom<T>(string what, int group, ParquetColumnChunkMetadata chunk, ReadOnlySpan<T> values)
    {
        if (!chunk.HasBloomFilter)
            throw Fail(what, group, "a bloom filter was requested but the chunk has none");
        using var filter = chunk.OpenBloomFilter();
        foreach (var value in values)
        {
            var present = Contains(filter, value);
            if (present is not null)
                _bloomProbes++;
            if (present == false)
                throw Fail(what, group, $"bloom filter does not contain written value '{value}'");
        }
    }

    // Returns null when the filter has no probe for this CLR type (the value is then not checked).
    static bool? Contains<T>(Plank.Reading.Physical.ParquetBloomFilter filter, T value)
        => value switch
        {
            null => null,
            int v => filter.MightContain(v),
            long v => filter.MightContain(v),
            uint v => filter.MightContain(v),
            ulong v => filter.MightContain(v),
            float v => filter.MightContain(v),
            double v => filter.MightContain(v),
            byte[] v => filter.MightContain(v),
            ReadOnlyMemory<byte> v => filter.MightContain(v.Span),
            _ => null
        };

    static Exception Fail(string what, int group, string message)
        => new InvalidOperationException($"{what}: row group {group} statistics: {message}.");

    static bool IsNull<T>(T value)
        => value is null;

    static Func<T, IComparable?>? KeyFor<T>(LeafColumn column)
    {
        var type = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
        var logical = column.LogicalType;
        var unsigned = logical is LogicalType.Int { IsSigned: false };
        object Box(T value) => value!;
        // Integers: the writer stores the value's bit pattern in the column's physical type, and the column's own
        // sort order (signed unless the logical type is an unsigned INT) decides min/max. The CLR type must not
        // pick the order: `uint` into an unannotated INT32 column is ordered as signed, `int` into an unsigned
        // column as unsigned. (An earlier version keyed by CLR type and missed exactly that.)
        if (type == typeof(bool))
            return v => (bool)Box(v) ? 1L : 0L;
        if (type == typeof(byte))
            return v => OrderByColumn(column, (byte)Box(v));
        if (type == typeof(ushort))
            return v => OrderByColumn(column, (ushort)Box(v));
        if (type == typeof(int))
            return v => OrderByColumn(column, (int)Box(v));
        if (type == typeof(uint))
            return v => OrderByColumn(column, unchecked((int)(uint)Box(v)));
        if (type == typeof(long))
            return v => OrderByColumn(column, (long)Box(v));
        if (type == typeof(ulong))
            return v => OrderByColumn(column, unchecked((long)(ulong)Box(v)));
        if (type == typeof(float))
            return v => float.IsNaN((float)Box(v)) ? null : (double)(float)Box(v);
        if (type == typeof(double))
            return v => double.IsNaN((double)Box(v)) ? null : (double)Box(v);
        if (type == typeof(decimal) && logical is LogicalType.Decimal decimalType)
            return v => new BigInteger(Math.Truncate((decimal)Box(v) * Pow10(decimalType.Scale)));
        if (type == typeof(DateTime) && logical is LogicalType.Timestamp timestamp)
            return v => Ticks(((DateTime)Box(v)).Ticks - UnixEpochTicks, timestamp.Unit);
        if (type == typeof(DateTimeOffset) && logical is LogicalType.Timestamp offsetTimestamp)
            return v => Ticks(((DateTimeOffset)Box(v)).UtcTicks - UnixEpochTicks, offsetTimestamp.Unit);
        if (type == typeof(DateOnly))
            return v => (long)(((DateOnly)Box(v)).DayNumber - DateOnly.FromDateTime(DateTime.UnixEpoch).DayNumber);
        if (type == typeof(TimeOnly) && logical is LogicalType.Time time)
            return v => Ticks(((TimeOnly)Box(v)).Ticks, time.Unit);
        if (type == typeof(byte[]))
            return v => new ByteKey((byte[])Box(v));
        if (type == typeof(ReadOnlyMemory<byte>))
            return v => new ByteKey(((ReadOnlyMemory<byte>)Box(v)).ToArray());
        return null;
    }

    // `raw` is the sign-extended bit pattern that lands in the physical column.
    internal static IComparable OrderByColumn(LeafColumn column, long raw)
    {
        var unsigned = column.LogicalType is LogicalType.Int { IsSigned: false };
        return column.PhysicalType switch
        {
            ParquetPhysicalType.Int32 => unsigned ? (ulong)(uint)raw : (long)(int)raw,
            ParquetPhysicalType.Int64 => unsigned ? unchecked((ulong)raw) : raw,
            _ => raw
        };
    }

    // Key of a value read from the nested / group routes (their expected values are boxed model values).
    internal static IComparable? KeyOfModelValue(LeafColumn column, object value)
        => value switch
        {
            int v => OrderByColumn(column, v),
            long v => OrderByColumn(column, v),
            BigInteger v => v,
            decimal v when column.LogicalType is LogicalType.Decimal d => new BigInteger(Math.Truncate(v * Pow10(d.Scale))),
            double v => double.IsNaN(v) ? null : v,
            float v => float.IsNaN(v) ? null : (double)v,
            byte[] v => new ByteKey(v),
            _ => null
        };

    static IComparable Ticks(long ticks, TimeUnit unit)
        => unit switch
        {
            TimeUnit.Millis => ticks / TimeSpan.TicksPerMillisecond,
            TimeUnit.Micros => ticks / (TimeSpan.TicksPerMillisecond / 1000),
            _ => ticks * 100
        };

    static decimal Pow10(int scale)
    {
        var value = 1m;
        for (var i = 0; i < scale; i++)
            value *= 10m;
        return value;
    }

    // Statistics hold the PLAIN encoding of the bound: little-endian for numbers, raw bytes for binary,
    // big-endian two's complement for decimal byte arrays.
    internal static Func<byte[], IComparable?>? DecoderFor(LeafColumn column)
    {
        var logical = column.LogicalType;
        var unsigned = logical is LogicalType.Int { IsSigned: false };
        switch (column.PhysicalType)
        {
            case ParquetPhysicalType.Boolean:
                return static b => b.Length == 1 ? (long)(b[0] & 1) : null;
            case ParquetPhysicalType.Int32:
                if (logical is LogicalType.Decimal)
                    return static b => b.Length == 4 ? new BigInteger(BitConverter.ToInt32(b)) : null;
                return unsigned
                    ? b => b.Length == 4 ? (ulong)BitConverter.ToUInt32(b) : null
                    : b => b.Length == 4 ? (long)BitConverter.ToInt32(b) : null;
            case ParquetPhysicalType.Int64:
                if (logical is LogicalType.Decimal)
                    return static b => b.Length == 8 ? new BigInteger(BitConverter.ToInt64(b)) : null;
                return unsigned
                    ? b => b.Length == 8 ? (ulong)BitConverter.ToUInt64(b) : null
                    : b => b.Length == 8 ? (long)BitConverter.ToInt64(b) : null;
            case ParquetPhysicalType.Float:
                return static b => b.Length == 4 ? NaNToNull(BitConverter.ToSingle(b)) : null;
            case ParquetPhysicalType.Double:
                return static b => b.Length == 8 ? NaNToNull(BitConverter.ToDouble(b)) : null;
            case ParquetPhysicalType.FixedLenByteArray or ParquetPhysicalType.ByteArray:
                if (logical is LogicalType.Decimal)
                    return static b => b.Length == 0
                        ? null
                        : new BigInteger(b, isUnsigned: false, isBigEndian: true);
                return static b => new ByteKey(b);
            default:
                return null;
        }
    }

    static IComparable? NaNToNull(double value)
        => double.IsNaN(value) ? null : value;
}
