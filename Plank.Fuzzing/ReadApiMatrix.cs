using System.Buffers.Binary;
using System.IO.Hashing;
using System.Numerics;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>
/// Every Plank read API that decodes a column, compared value for value with Arrow on the same file.
/// </summary>
/// <remarks>
/// The reader target reads each column once, through the physical CLR type; everything else Plank
/// offers — reading an INT32 column as long/byte/uint/decimal/double, a timestamp as DateTime or
/// DateTimeOffset, INT96 as DateTime, a UUID as Guid, nullable and non-nullable forms, the nested
/// readers, the row reader by descriptor and by ordinal (the generated readers' fast path), with and
/// without a projection, and the physical page cursor — is a separate decode/convert path that no
/// oracle looked at. Each one is held to the Arrow-decoded physical value of the same entry,
/// converted by the specification (logical type) or by C#'s own numeric conversion:
/// <list type="bullet">
/// <item>a refusal (NotSupported/InvalidOperation/InvalidCast/Overflow/Corrupt) is always allowed;</item>
/// <item>a returned value must be the conversion; a value outside the CLR type that comes back
/// wrapped or truncated is a finding;</item>
/// <item>combinations the specification does not define are accepted with any value but must
/// still return one value (or null) per Arrow entry, in order.</item>
/// </list>
/// </remarks>
public static class ReadApiMatrix
{
    public static long Reads, Values, Refusals, RowReads, Pages;

    static readonly bool Disabled = Environment.GetEnvironmentVariable("PLANK_FUZZ_READ_MATRIX") == "0";

    static readonly IProbe[] Probes =
    [
        new Probe<bool>(), new Probe<sbyte>(), new Probe<byte>(), new Probe<short>(), new Probe<ushort>(),
        new Probe<int>(), new Probe<uint>(), new Probe<long>(), new Probe<ulong>(), new Probe<Half>(),
        new Probe<float>(), new Probe<double>(), new Probe<decimal>(), new Probe<DateOnly>(), new Probe<TimeOnly>(),
        new Probe<TimeSpan>(), new Probe<DateTime>(), new Probe<DateTimeOffset>(), new Probe<Guid>(),
    ];

    /// <param name="arrow">Arrow-decoded levels and values per row group and leaf (null = not decodable by Arrow).</param>
    /// <param name="strict">Plank wrote the file: page CRCs must also be right.</param>
    internal static void Check(byte[] file, ParquetReader plank, FullValueOracle.ArrowColumn?[][] arrow, bool strict)
    {
        if (Disabled)
            return;
        var leaves = plank.Schema.LeafColumns;
        var accepted = new bool[leaves.Length, Probes.Length];
        for (var g = 0; g < plank.RowGroups.Count && g < arrow.Length; g++)
        {
            var group = plank.RowGroups[g];
            for (var c = 0; c < leaves.Length; c++)
            {
                if (arrow[g][c] is not { } column)
                    continue;
                var leaf = leaves[c];
                for (var p = 0; p < Probes.Length; p++)
                {
                    // Column<byte>/NestedColumn<byte> on a binary column is the variable-length
                    // byte API (one entry per value, compared by ColumnTrace), not a byte read.
                    if (Probes[p] is Probe<byte> && leaf.PhysicalType is ParquetPhysicalType.ByteArray
                            or ParquetPhysicalType.FixedLenByteArray or ParquetPhysicalType.Int96)
                        continue;
                    var where = $"row group {g}, column {c} '{leaf.Path}' ({leaf.PhysicalType}, {Describe(leaf)}), as {Probes[p].Name}";
                    if (leaf.MaxRepetitionLevel > 0)
                        accepted[c, p] |= Probes[p].CheckNested(group, leaf, column, where);
                    else
                    {
                        accepted[c, p] |= Probes[p].CheckFlat(group, leaf, column, nullable: true, where + "?");
                        if (leaf.MaxDefinitionLevel == 0)
                            accepted[c, p] |= Probes[p].CheckFlat(group, leaf, column, nullable: false, where);
                    }
                }
            }
        }
        CheckRowReader(file, plank, arrow, accepted);
        CheckConverters(file, plank, arrow);
        CheckPageCursor(file, plank, arrow, strict);
    }

    // ---- Value expectations ---------------------------------------------------

    enum Verdict { Ok, Unspecified, Wrong }

    /// <summary>Whether <paramref name="value"/> is what reading <paramref name="physical"/> as its CLR type must give.</summary>
    static (Verdict Verdict, string Expected) Judge(object value, byte[] physical, LeafColumn leaf)
    {
        var type = leaf.PhysicalType;
        var logical = leaf.LogicalType;
        var integers = IntegerCandidates(physical, leaf);
        switch (value)
        {
            case bool b:
                return type == ParquetPhysicalType.Boolean && physical.Length == 1
                    ? Is(b == (physical[0] != 0), (physical[0] != 0).ToString())
                    : (Verdict.Unspecified, "");
            case sbyte or byte or short or ushort or int or uint or long or ulong:
            {
                if (integers is null)
                    return (Verdict.Unspecified, "");
                var actual = value switch
                {
                    sbyte v => (BigInteger)v, byte v => v, short v => v, ushort v => v, int v => v,
                    uint v => v, long v => v, _ => (BigInteger)(ulong)value,
                };
                if (integers.Contains(actual))
                    return (Verdict.Ok, "");
                // Reading a column as its physical CLR type (int for INT32, long for INT64) is the
                // raw physical read, whatever the annotation: the signed bits of a UINT column.
                if ((value is int && type == ParquetPhysicalType.Int32 && physical.Length == 4
                        && actual == BinaryPrimitives.ReadInt32LittleEndian(physical))
                    || (value is long && type == ParquetPhysicalType.Int64 && physical.Length == 8
                        && actual == BinaryPrimitives.ReadInt64LittleEndian(physical)))
                    return (Verdict.Ok, "");
                if (IsKnownUnsignedWrap(value, actual, integers[0], leaf))
                {
                    KnownUnsignedWraps++;
                    return (Verdict.Unspecified, "");
                }
                return (Verdict.Wrong, string.Join(" or ", integers));
            }
            case Half or float or double:
            {
                double? expected = null;
                if (type == ParquetPhysicalType.Float && physical.Length == 4)
                    expected = BinaryPrimitives.ReadSingleLittleEndian(physical);
                else if (type == ParquetPhysicalType.Double && physical.Length == 8)
                    expected = BinaryPrimitives.ReadDoubleLittleEndian(physical);
                else if (logical is LogicalType.Float16 && physical.Length == 2)
                    expected = (double)BinaryPrimitives.ReadHalfLittleEndian(physical);
                else if (logical is LogicalType.Decimal d && LogicalOracle.ExpectDecimal(type, physical, d.Scale) is { Verdict: LogicalOracle.Verdict.Representable } dec)
                    expected = (double)dec.Value;
                else if (integers is { Count: > 0 } && logical is not LogicalType.Decimal)
                    expected = (double)integers[0];
                if (expected is not { } e)
                    return (Verdict.Unspecified, "");
                // C#'s own conversion of the exact value to the requested width.
                var ok = value switch
                {
                    Half h => SameReal((double)h, (double)(Half)e) || (type == ParquetPhysicalType.Double && SameReal((double)h, (double)(Half)(float)e)),
                    float f => SameReal(f, (float)e) || (integers is { Count: > 0 } && SameReal(f, (float)integers[0])),
                    double x => SameReal(x, e) || (integers is { Count: > 0 } && SameReal(x, (double)integers[0])),
                    _ => false,
                };
                return Is(ok, e.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
            }
            case decimal m:
            {
                if (logical is LogicalType.Decimal d)
                {
                    var e = LogicalOracle.ExpectDecimal(type, physical, d.Scale);
                    return e.Verdict switch
                    {
                        LogicalOracle.Verdict.Representable => Is(e.Value == m, e.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                        LogicalOracle.Verdict.Unrepresentable => (Verdict.Wrong, "outside System.Decimal"),
                        _ => (Verdict.Unspecified, ""),
                    };
                }
                if (integers is { Count: > 0 })
                    return Is(integers.Any(i => (BigInteger)m == i && decimal.Truncate(m) == m), string.Join(" or ", integers));
                return (Verdict.Unspecified, "");
            }
            case DateOnly date:
                if (logical is LogicalType.Date && type == ParquetPhysicalType.Int32 && physical.Length == 4)
                    return FromOracle(LogicalOracle.ExpectDate(BinaryPrimitives.ReadInt32LittleEndian(physical)), date, static (e, a) => e == a);
                return (Verdict.Unspecified, "");
            case TimeOnly time:
                if (logical is LogicalType.Time t)
                    return FromOracle(LogicalOracle.ExpectTime(t.Unit, type, physical), time, static (e, a) => e == a);
                return (Verdict.Unspecified, "");
            case TimeSpan span:
                if (logical is LogicalType.Time ts)
                    {
                    var e = LogicalOracle.ExpectTime(ts.Unit, type, physical);
                    return FromOracle(new LogicalOracle.Expected<TimeSpan>(e.Verdict, e.Verdict == LogicalOracle.Verdict.Representable ? e.Value.ToTimeSpan() : default),
                        span, static (x, y) => x.Ticks == y.Ticks);
                }
                return (Verdict.Unspecified, "");
            case DateTime dateTime:
                if (ExpectedUtcTicks(physical, leaf) is { } ticks)
                    return ticks.Verdict == LogicalOracle.Verdict.Representable
                        ? Is(ticks.Value == dateTime.Ticks, $"{ticks.Value} ticks")
                        : ticks.Verdict == LogicalOracle.Verdict.Unrepresentable ? (Verdict.Wrong, "outside DateTime") : (Verdict.Unspecified, "");
                return (Verdict.Unspecified, "");
            case DateTimeOffset offset:
                if (ExpectedUtcTicks(physical, leaf) is { } utc)
                    return utc.Verdict == LogicalOracle.Verdict.Representable
                        ? Is(utc.Value == offset.UtcTicks && offset.Offset == TimeSpan.Zero, $"{utc.Value} UTC ticks, offset 0")
                        : utc.Verdict == LogicalOracle.Verdict.Unrepresentable ? (Verdict.Wrong, "outside DateTimeOffset") : (Verdict.Unspecified, "");
                return (Verdict.Unspecified, "");
            case Guid guid:
                if (logical is LogicalType.Uuid && physical.Length == 16)
                    return Is(guid == new Guid(physical, bigEndian: true), new Guid(physical, bigEndian: true).ToString());
                return (Verdict.Unspecified, "");
            default:
                return (Verdict.Unspecified, "");
        }

        static (Verdict, string) Is(bool ok, string expected) => (ok ? Verdict.Ok : Verdict.Wrong, expected);
    }

    public static long KnownUnsignedWraps;
    static readonly bool StrictNarrowing = Environment.GetEnvironmentVariable("PLANK_FUZZ_STRICT_NARROWING") == "1";

    /// <summary>
    /// Known library finding (fuzz/FINDINGS.md, "narrow unsigned reads wrap"): Column/NestedColumn/row
    /// reads as byte/ushort/uint/ulong return the physical value truncated to the type's width
    /// (unchecked cast) for any INT32/INT64 column. Excluded only when the returned value is exactly
    /// that wrap and the column's annotation does not promise the range (or its data breaks the
    /// annotation's range); PLANK_FUZZ_STRICT_NARROWING=1 reports it again.
    /// </summary>
    static bool IsKnownUnsignedWrap(object value, BigInteger actual, BigInteger physical, LeafColumn leaf)
    {
        if (StrictNarrowing)
            return false;
        var bits = value switch { byte => 8, ushort => 16, uint => 32, ulong => 64, _ => 0 };
        if (bits == 0)
            return false;
        var wrapped = physical & ((BigInteger.One << bits) - 1);
        if (wrapped != actual)
            return false;
        // An unsigned annotation no wider than the type promises in-range values; out-of-range
        // data in such a column is invalid input, where wrapping is defensible.
        if (leaf.LogicalType is LogicalType.Int { IsSigned: false } u && u.BitWidth <= bits)
            return physical < 0 || physical >= BigInteger.One << u.BitWidth;
        return true;
    }

    static (Verdict, string) FromOracle<T>(LogicalOracle.Expected<T> expected, T actual, Func<T, T, bool> same)
        => expected.Verdict switch
        {
            LogicalOracle.Verdict.Representable => (same(expected.Value, actual) ? Verdict.Ok : Verdict.Wrong, expected.Value?.ToString() ?? ""),
            LogicalOracle.Verdict.Unrepresentable => (Verdict.Wrong, "outside the CLR type"),
            _ => (Verdict.Unspecified, ""),
        };

    static bool SameReal(double a, double b) => a.Equals(b) || (a == 0 && b == 0);

    /// <summary>The integer values a CLR integer read may return: the physical signed value, or the
    /// unsigned one for an unsigned-annotated column (Plank documents byte/ushort/uint/ulong as such).</summary>
    static List<BigInteger>? IntegerCandidates(byte[] physical, LeafColumn leaf)
    {
        if (leaf.LogicalType is LogicalType.Decimal { Scale: not 0 })
            return null;
        switch (leaf.PhysicalType)
        {
            case ParquetPhysicalType.Int32 when physical.Length == 4:
            {
                var v = BinaryPrimitives.ReadInt32LittleEndian(physical);
                return leaf.LogicalType is LogicalType.Int { IsSigned: false } ? [(uint)v] : [v];
            }
            case ParquetPhysicalType.Int64 when physical.Length == 8:
            {
                var v = BinaryPrimitives.ReadInt64LittleEndian(physical);
                return leaf.LogicalType is LogicalType.Int { IsSigned: false } ? [(ulong)v] : [v];
            }
            case ParquetPhysicalType.FixedLenByteArray or ParquetPhysicalType.ByteArray
                when leaf.LogicalType is LogicalType.Decimal { Scale: 0 } && physical.Length > 0:
                return [new BigInteger(physical, isUnsigned: false, isBigEndian: true)];
            default:
                return null;
        }
    }

    /// <summary>UTC-relative ticks for TIMESTAMP (any unit) and legacy INT96 timestamps.</summary>
    static LogicalOracle.Expected<long>? ExpectedUtcTicks(byte[] physical, LeafColumn leaf)
    {
        if (leaf.LogicalType is LogicalType.Timestamp t && leaf.PhysicalType == ParquetPhysicalType.Int64 && physical.Length == 8)
        {
            var e = LogicalOracle.ExpectTimestamp(t.Unit, BinaryPrimitives.ReadInt64LittleEndian(physical), DateTimeKind.Unspecified);
            return new LogicalOracle.Expected<long>(e.Verdict, e.Verdict == LogicalOracle.Verdict.Representable ? e.Value.Ticks : 0);
        }
        if (leaf.PhysicalType == ParquetPhysicalType.Int96 && physical.Length == 12)
        {
            // Impala/Hive layout: nanoseconds of the day (int64), then the Julian day (int32).
            var nanos = BinaryPrimitives.ReadInt64LittleEndian(physical);
            var julian = BinaryPrimitives.ReadInt32LittleEndian(physical.AsSpan(8));
            if (nanos is < 0 or >= 86_400_000_000_000)
                return LogicalOracle.Expected<long>.Any;
            var ticks = (Int128)(julian - 2_440_588L) * TimeSpan.TicksPerDay + nanos / 100 + DateTime.UnixEpoch.Ticks;
            return ticks >= 0 && ticks <= DateTime.MaxValue.Ticks
                ? LogicalOracle.Expected<long>.Is((long)ticks)
                : LogicalOracle.Expected<long>.Not;
        }
        return null;
    }

    static string Describe(LeafColumn leaf) => leaf.LogicalType?.ToString() ?? "none";

    static void Fail(string bucket, string detail)
        => throw new ReaderAcceptanceMismatchException("Read-API matrix: " + bucket,
            new InvalidDataException($"read API: {bucket} — {detail}"));

    static bool IsRefusal(Exception error)
        => error is NotSupportedException or InvalidOperationException or InvalidCastException or OverflowException
            or CorruptParquetException;

    static void Compare(string api, string where, LeafColumn leaf, FullValueOracle.ArrowColumn column,
        List<object?> actual, bool presentOnly)
    {
        Reads++;
        var expectedCount = presentOnly ? column.Values.Count : column.EntryCount;
        if (actual.Count != expectedCount)
            Fail($"{api}: value count differs from Arrow", $"{where}: Plank={actual.Count}, Arrow={expectedCount}");
        for (var i = 0; i < actual.Count; i++)
        {
            var physical = presentOnly ? column.Values[i] : column.ValueAtEntry(i);
            if ((physical is null) != (actual[i] is null))
                Fail($"{api}: null-ness differs from Arrow", $"{where}, entry {i}: Plank={(actual[i] is null ? "null" : "value")}, Arrow={(physical is null ? "null" : "value")}");
            if (physical is null)
                continue;
            Values++;
            var (verdict, expected) = Judge(actual[i]!, physical, leaf);
            if (verdict == Verdict.Wrong)
                Fail($"{api}: value differs from the conversion of Arrow's value",
                    $"{where}, entry {i}: physical={Convert.ToHexString(physical)}, Plank={Show(actual[i]!)}, expected={expected}");
        }
    }

    static string Show(object value) => value switch
    {
        DateTime d => $"{d:O} ({d.Kind}, {d.Ticks} ticks)",
        DateTimeOffset o => $"{o:O} ({o.UtcTicks} UTC ticks)",
        _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "",
    };

    // ---- Per-type probes --------------------------------------------------------

    interface IProbe
    {
        string Name { get; }
        bool CheckFlat(RowGroup group, LeafColumn leaf, FullValueOracle.ArrowColumn column, bool nullable, string where);
        bool CheckNested(RowGroup group, LeafColumn leaf, FullValueOracle.ArrowColumn column, string where);
        RowApiColumnDescriptor Descriptor(string name, LeafColumn leaf);
        object? Current(RowReaderCore rows, RowApiColumnDescriptor descriptor, int ordinal, bool byOrdinal);
    }

    sealed class Probe<T> : IProbe where T : struct
    {
        public string Name => typeof(T).Name;

        public bool CheckFlat(RowGroup group, LeafColumn leaf, FullValueOracle.ArrowColumn column, bool nullable, string where)
        {
            var values = new List<object?>();
            try
            {
                if (nullable)
                {
                    foreach (var buffer in group.Column<T?>(leaf))
                        foreach (var value in buffer.Values)
                            values.Add(value);
                }
                else
                {
                    foreach (var buffer in group.Column<T>(leaf))
                        foreach (var value in buffer.Values)
                            values.Add(value);
                }
            }
            catch (Exception error) when (IsRefusal(error))
            {
                Refusals++;
                return false;
            }
            Compare(nullable ? "RowGroup.Column<T?>" : "RowGroup.Column<T>", where, leaf, column, values, presentOnly: false);
            return true;
        }

        public bool CheckNested(RowGroup group, LeafColumn leaf, FullValueOracle.ArrowColumn column, string where)
        {
            var values = new List<object?>();
            var entry = 0;
            try
            {
                foreach (var buffer in group.NestedColumn<T>(leaf))
                {
                    var definitions = buffer.DefinitionLevels;
                    var repetitions = buffer.RepetitionLevels;
                    for (var i = 0; i < definitions.Length; i++, entry++)
                    {
                        if (entry >= column.EntryCount)
                            Fail("NestedColumn<T>: more level entries than Arrow", $"{where}: Arrow={column.EntryCount}");
                        if (definitions[i] != column.DefinitionAt(entry) || (i < repetitions.Length && repetitions[i] != column.RepetitionAt(entry)))
                            Fail("NestedColumn<T>: levels differ from Arrow",
                                $"{where}, entry {entry}: Plank def/rep={definitions[i]}/{(i < repetitions.Length ? repetitions[i] : -1)}, Arrow={column.DefinitionAt(entry)}/{column.RepetitionAt(entry)}");
                    }
                    foreach (var value in buffer.Values.Values)
                        values.Add(value);
                }
            }
            catch (Exception error) when (IsRefusal(error))
            {
                Refusals++;
                return false;
            }
            if (entry != column.EntryCount)
                Fail("NestedColumn<T>: level entry count differs from Arrow", $"{where}: Plank={entry}, Arrow={column.EntryCount}");
            Compare("NestedColumn<T>", where, leaf, column, values, presentOnly: true);
            return true;
        }

        public RowApiColumnDescriptor Descriptor(string name, LeafColumn leaf)
            => leaf.MaxDefinitionLevel > 0
                ? new RowApiColumnDescriptor<T?>(name, leaf)
                : new RowApiColumnDescriptor<T>(name, leaf);

        public object? Current(RowReaderCore rows, RowApiColumnDescriptor descriptor, int ordinal, bool byOrdinal)
            => descriptor switch
            {
                RowApiColumnDescriptor<T?> optional => byOrdinal ? rows.GetCurrent<T?>(ordinal) : rows.GetCurrent(optional),
                RowApiColumnDescriptor<T> required => byOrdinal ? rows.GetCurrent<T>(ordinal) : rows.GetCurrent(required),
                _ => throw new InvalidOperationException("descriptor type"),
            };
    }

    // ---- Row reader ------------------------------------------------------------

    static readonly RowReaderOptions SingleWorker = new() { Execution = new ParquetExecutionOptions { WorkerCount = 1 } };

    /// <summary>
    /// One row-reader pass per CLR type: every flat column the columnar API accepted as that type is
    /// read as it (others as their physical type), by descriptor and by ordinal, then again projected
    /// to the typed columns only.
    /// </summary>
    static void CheckRowReader(byte[] file, ParquetReader plank, FullValueOracle.ArrowColumn?[][] arrow, bool[,] accepted)
    {
        var leaves = plank.Schema.LeafColumns;
        if (leaves.Length == 0 || leaves.Any(static l => l.MaxRepetitionLevel > 0) || arrow.Length != plank.RowGroups.Count)
            return;
        for (var p = 0; p < Probes.Length; p++)
        {
            var descriptors = new RowApiColumnDescriptor[leaves.Length];
            var typed = new List<int>();
            for (var c = 0; c < leaves.Length; c++)
            {
                if (accepted[c, p])
                {
                    descriptors[c] = Probes[p].Descriptor($"p{c}", leaves[c]);
                    typed.Add(c);
                }
                else
                    descriptors[c] = PhysicalDescriptor(leaves[c], $"p{c}");
            }
            if (typed.Count == 0)
                continue;
            RunRows(file, plank, arrow, descriptors, typed, Probes[p], projection: null, byOrdinal: false);
            RunRows(file, plank, arrow, descriptors, typed, Probes[p], projection: null, byOrdinal: true);
            if (typed.Count < leaves.Length)
                RunRows(file, plank, arrow, descriptors, typed, Probes[p], projection: typed.Select(c => descriptors[c]).ToArray(), byOrdinal: false);
        }
    }

    static RowApiColumnDescriptor PhysicalDescriptor(LeafColumn leaf, string name) => leaf.PhysicalType switch
    {
        ParquetPhysicalType.Boolean => new RowApiColumnDescriptor<bool>(name, leaf),
        ParquetPhysicalType.Int32 => new RowApiColumnDescriptor<int>(name, leaf),
        ParquetPhysicalType.Int64 => new RowApiColumnDescriptor<long>(name, leaf),
        ParquetPhysicalType.Float => new RowApiColumnDescriptor<float>(name, leaf),
        ParquetPhysicalType.Double => new RowApiColumnDescriptor<double>(name, leaf),
        _ => new RowApiColumnDescriptor<byte[]>(name, leaf),
    };

    static void RunRows(byte[] file, ParquetReader plank, FullValueOracle.ArrowColumn?[][] arrow,
        RowApiColumnDescriptor[] descriptors, List<int> typed, IProbe probe, RowApiColumnDescriptor[]? projection, bool byOrdinal)
    {
        var leaves = plank.Schema.LeafColumns;
        var api = $"RowReaderCore.GetCurrent<{probe.Name}>({(byOrdinal ? "ordinal" : "descriptor")}{(projection is null ? "" : ", projected")})";
        var values = typed.ToDictionary(c => c, _ => new List<object?>());
        try
        {
            using var rows = new RowReaderCore(new MemoryReadSource(file), plank.Schema, descriptors, projection, SingleWorker, schemaEvolution: null);
            while (rows.MoveNext())
                foreach (var c in typed)
                    values[c].Add(probe.Current(rows, descriptors[c], c, byOrdinal));
        }
        catch (Exception error) when (IsRefusal(error))
        {
            Refusals++;
            return;
        }
        RowReads++;
        foreach (var c in typed)
        {
            // Concatenate the row groups' Arrow entries: the row reader crosses group boundaries.
            var merged = FullValueOracle.ArrowColumn.Concat(arrow.Select(group => group[c]));
            if (merged is null)
                continue;
            Compare(api, $"column {c} '{leaves[c].Path}' ({leaves[c].PhysicalType}, {Describe(leaves[c])})", leaves[c], merged,
                values[c], presentOnly: false);
        }
    }

    // ---- Value converters (requested schema) -------------------------------------

    public static long ConverterReads;

    readonly record struct Box<T>(T Value) where T : unmanaged;

    sealed class BoxConverter<T> : ParquetValueConverter<Box<T>, T> where T : unmanaged
    {
        public override Box<T> ConvertFromPhysical(T value) => new(value);
        public override T ConvertToPhysical(Box<T> value) => value.Value;
    }

    /// <summary>
    /// The file read through a requested schema mirroring its own flat schema, with a value
    /// converter on every fixed-width column: the converted (whole-page) decode paths must return
    /// Arrow's physical values.
    /// </summary>
    static void CheckConverters(byte[] file, ParquetReader plank, FullValueOracle.ArrowColumn?[][] arrow)
    {
        var leaves = plank.Schema.LeafColumns;
        if (leaves.Length == 0 || leaves.Length > 32 || leaves.Any(static l => l.MaxRepetitionLevel > 0 || l.Path.Contains('.')))
            return;
        var definitions = new ColumnDefinition[leaves.Length];
        for (var c = 0; c < leaves.Length; c++)
        {
            var leaf = leaves[c];
            ParquetValueConverter? converter = leaf.PhysicalType switch
            {
                ParquetPhysicalType.Boolean => new BoxConverter<bool>(),
                ParquetPhysicalType.Int32 => new BoxConverter<int>(),
                ParquetPhysicalType.Int64 => new BoxConverter<long>(),
                ParquetPhysicalType.Float => new BoxConverter<float>(),
                ParquetPhysicalType.Double => new BoxConverter<double>(),
                _ => null,
            };
            var options = new ColumnOptions(leaf.MaxDefinitionLevel > 0 ? ParquetRepetition.Optional : ParquetRepetition.Required,
                typeLength: leaf.Options.TypeLength);
            definitions[c] = leaf.MaxDefinitionLevel > 0
                ? ColumnDefinition.OptionalLeaf(leaf.Path, leaf.PhysicalType, options, leaf.LogicalType, converter: converter)
                : ColumnDefinition.RequiredLeaf(leaf.Path, leaf.PhysicalType, options, leaf.LogicalType, converter: converter);
        }
        ParquetReader converted;
        try
        {
            converted = new ParquetSchema(System.Collections.Immutable.ImmutableArray.Create(definitions)).CreateReader(new MemoryReadSource(file));
        }
        catch (Exception error) when (IsRefusal(error) || error is ArgumentException)
        {
            Refusals++;
            return;
        }
        using (converted)
        {
            for (var g = 0; g < converted.RowGroups.Count && g < arrow.Length; g++)
                for (var c = 0; c < leaves.Length; c++)
                {
                    if (arrow[g][c] is not { } column)
                        continue;
                    var where = $"row group {g}, column {c} '{leaves[c].Path}' ({leaves[c].PhysicalType}, {Describe(leaves[c])}), converter";
                    var optional = leaves[c].MaxDefinitionLevel > 0;
                    switch (leaves[c].PhysicalType)
                    {
                        case ParquetPhysicalType.Boolean: ReadConverted<bool>(converted.RowGroups[g], converted.Schema.LeafColumns[c], optional, column, where); break;
                        case ParquetPhysicalType.Int32: ReadConverted<int>(converted.RowGroups[g], converted.Schema.LeafColumns[c], optional, column, where); break;
                        case ParquetPhysicalType.Int64: ReadConverted<long>(converted.RowGroups[g], converted.Schema.LeafColumns[c], optional, column, where); break;
                        case ParquetPhysicalType.Float: ReadConverted<float>(converted.RowGroups[g], converted.Schema.LeafColumns[c], optional, column, where); break;
                        case ParquetPhysicalType.Double: ReadConverted<double>(converted.RowGroups[g], converted.Schema.LeafColumns[c], optional, column, where); break;
                    }
                }
        }
    }

    static void ReadConverted<T>(RowGroup group, LeafColumn leaf, bool optional, FullValueOracle.ArrowColumn column, string where)
        where T : unmanaged
    {
        var values = new List<byte[]?>();
        try
        {
            if (optional)
            {
                foreach (var buffer in group.Column<Box<T>?>(leaf))
                    foreach (var value in buffer.Values)
                        values.Add(value is { } v ? Bytes(v.Value) : null);
            }
            else
            {
                foreach (var buffer in group.Column<Box<T>>(leaf))
                    foreach (var value in buffer.Values)
                        values.Add(Bytes(value.Value));
            }
        }
        catch (Exception error) when (IsRefusal(error))
        {
            Refusals++;
            return;
        }
        ConverterReads++;
        if (values.Count != column.EntryCount)
            Fail("converter: value count differs from Arrow", $"{where}: Plank={values.Count}, Arrow={column.EntryCount}");
        for (var i = 0; i < values.Count; i++)
        {
            var expected = column.ValueAtEntry(i);
            if ((expected is null) != (values[i] is null) || (expected is not null && !expected.AsSpan().SequenceEqual(values[i])))
                Fail("converter: value differs from Arrow's physical value",
                    $"{where}, entry {i}: Plank={(values[i] is { } a ? Convert.ToHexString(a) : "null")}, Arrow={(expected is { } b ? Convert.ToHexString(b) : "null")}");
            Values++;
        }

        static byte[] Bytes(T value)
            => typeof(T) == typeof(bool)
                ? [(byte)((bool)(object)value ? 1 : 0)]
                : System.Runtime.InteropServices.MemoryMarshal.AsBytes(new ReadOnlySpan<T>(in value)).ToArray();
    }

    // ---- Physical page cursor ---------------------------------------------------

    /// <summary>
    /// The page cursor's headers against Arrow's level stream: data-page value counts must add up
    /// to the chunk's entries, a v2 page's null and row counts must match its slice of entries and
    /// it must start at a record; on Plank's own files every stored page CRC must be right.
    /// </summary>
    static void CheckPageCursor(byte[] file, ParquetReader plank, FullValueOracle.ArrowColumn?[][] arrow, bool strict)
    {
        using var physical = new Plank.Reading.Physical.ParquetFileReader();
        physical.Reset(new MemoryReadSource(file));
        var leaves = plank.Schema.LeafColumns;
        for (var g = 0; g < arrow.Length && g < physical.Metadata.RowGroupCount; g++)
            for (var c = 0; c < leaves.Length; c++)
            {
                if (arrow[g][c] is not { } column)
                    continue;
                var where = $"row group {g}, column {c} '{leaves[c].Path}'";
                var entry = 0;
                var page = 0;
                // Raw page walk for the CRC: the cursor's payload is decompressed, the CRC covers the
                // stored bytes after the header (v2: levels + compressed values).
                var chunkInfo = physical.Metadata.ColumnChunk(g, c);
                var raw = chunkInfo.DictionaryPageOffset != 0 && chunkInfo.DictionaryPageOffset < chunkInfo.DataPageOffset
                    ? chunkInfo.DictionaryPageOffset
                    : chunkInfo.DataPageOffset;
                using var pages = physical.OpenPages(g, c);
                while (pages.MoveNext())
                {
                    var header = pages.CurrentHeader;
                    Pages++;
                    var bodyStart = raw + (ulong)header.HeaderLength;
                    var bodyEnd = bodyStart + header.CompressedPageSize;
                    if (strict && header.Crc is { } crc && bodyEnd <= (ulong)file.Length
                        && Crc32.HashToUInt32(file.AsSpan((int)bodyStart, (int)header.CompressedPageSize)) is var actualCrc
                        && actualCrc != crc)
                        Fail("page cursor: page CRC does not match the stored page bytes", $"{where}, page {page} ({header.Type}) at {bodyStart}: crc={crc:X8}, actual={actualCrc:X8}");
                    raw = bodyEnd;
                    if (header.Type is PageHeaderType.DataPage or PageHeaderType.DataPageV2)
                    {
                        var count = (int)Math.Min(header.ValueCount, int.MaxValue);
                        if (entry + (long)count > column.EntryCount)
                            Fail("page cursor: data page value counts exceed Arrow's entries", $"{where}, page {page}: num_values={header.ValueCount}, entries so far={entry}, Arrow={column.EntryCount}");
                        // v2 num_nulls/num_rows are not cross-validated by Plank or Arrow when reading
                        // (both decode the levels): on foreign/fuzzed files a wrong header field is an
                        // input-tolerance difference; on Plank's own files it must be right.
                        if (strict && header.Type == PageHeaderType.DataPageV2)
                        {
                            int nulls = 0, rows = 0;
                            for (var e = entry; e < entry + count; e++)
                            {
                                if (column.ValueAtEntry(e) is null) nulls++;
                                if (column.MaxRep == 0 || column.RepetitionAt(e) == 0) rows++;
                            }
                            if (header.NullCount != nulls)
                                Fail("page cursor: v2 page num_nulls differs from Arrow's entries", $"{where}, page {page}: num_nulls={header.NullCount}, actual={nulls}");
                            if (header.RowCount != rows)
                                Fail("page cursor: v2 page num_rows differs from Arrow's entries", $"{where}, page {page}: num_rows={header.RowCount}, actual={rows}");
                            if (count > 0 && column.MaxRep > 0 && column.RepetitionAt(entry) != 0)
                                Fail("page cursor: v2 page starts inside a record", $"{where}, page {page}");
                        }
                        entry += count;
                    }
                    page++;
                }
                if (entry != column.EntryCount)
                    Fail("page cursor: data page value counts differ from Arrow's entries", $"{where}: pages={entry}, Arrow={column.EntryCount}");
            }
    }
}
