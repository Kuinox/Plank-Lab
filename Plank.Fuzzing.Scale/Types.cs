using System.Buffers.Binary;
using System.Numerics;
using System.Text;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing.Scale;

public enum LKind { DecI32, DecI64, DecFlba, DecBin, Ts, Int96, Date, Time, Uuid, F16, Interval, Enum, Json, Bson, IntN }

/// <summary>
/// A logical-type column at scale. The value is the base pattern of <see cref="Spec"/> mapped into the type's domain,
/// so dictionary fallback, sorted runs, low/high cardinality and null patterns apply to every logical type. The raw
/// physical value feeds every existing check; <see cref="Semantic"/> is the independently computed CLR meaning.
/// </summary>
public sealed class LType
{
    public required ColSpec Spec;
    public LKind K;
    public int Precision, Scale, Length, Bits;
    public bool Signed, Utc, Padded;
    public TimeUnit Unit;
    /// <summary>0: values inside the CLR range; 1: arbitrary raw values (out-of-range must be refused, never wrapped).</summary>
    public int Domain;

    static readonly long EpochTicks = DateTime.UnixEpoch.Ticks;
    const int JulianUnixEpoch = 2440588;

    public override string ToString() => $"{K} p={Precision} s={Scale} len={Length} bits={Bits}{(Signed ? "s" : "u")} unit={Unit} utc={Utc} pad={Padded} domain={Domain} :: {Spec}";

    // ---------------- drawing ----------------

    public static LType Draw(Rng rng, string name, long rows, bool optional)
    {
        var k = (LKind)rng.Int(15);
        if (Environment.GetEnvironmentVariable("SCALE_LKIND") is { } forced)
            k = Enum.Parse<LKind>(forced);
        var basePhysical = k switch
        {
            LKind.DecI32 or LKind.Date => Kind.Int32,
            LKind.DecI64 => Kind.Int64,
            LKind.DecFlba or LKind.Uuid or LKind.F16 or LKind.Interval => Kind.Fixed,
            LKind.Int96 => Kind.Int96,
            LKind.Ts => Kind.Int64,
            LKind.DecBin or LKind.Enum or LKind.Json or LKind.Bson => Kind.Bytes,
            _ => Kind.Int32,
        };
        var spec = ColSpec.Draw(rng, name, basePhysical == Kind.Int96 ? Kind.Fixed : basePhysical, optional, rows, allowHuge: false);
        var t = new LType { Spec = spec, K = k, Domain = rng.Chance(8) ? 1 : 0 };
        if (Environment.GetEnvironmentVariable("SCALE_DOMAIN") is { } domain)
            t.Domain = int.Parse(domain);
        switch (k)
        {
            case LKind.DecI32: t.Precision = 1 + rng.Int(9); break;
            case LKind.DecI64: t.Precision = rng.Chance(30) ? 1 + rng.Int(9) : 10 + rng.Int(9); break;
            case LKind.DecFlba:
            case LKind.DecBin:
                t.Precision = rng.Pick(1, 5, 9, 10, 18, 19, 20, 27, 28, 29, 30, 38, 1 + rng.Int(38));
                t.Padded = rng.Chance(25);
                t.Length = MinBytes(t.Precision) + (t.Padded ? 1 + rng.Int(4) : 0);
                break;
            case LKind.Ts: t.Unit = (TimeUnit)rng.Int(3); t.Utc = rng.Chance(50); break;
            case LKind.Time:
                t.Unit = (TimeUnit)rng.Int(3); t.Utc = rng.Chance(50);
                spec.Kind = t.Unit == TimeUnit.Millis ? Kind.Int32 : Kind.Int64;
                break;
            case LKind.IntN:
                t.Bits = rng.Pick(8, 16, 32, 64); t.Signed = rng.Chance(50);
                spec.Kind = t.Bits == 64 ? Kind.Int64 : Kind.Int32;
                break;
        }
        if (t.K is LKind.DecI32 or LKind.DecI64 or LKind.DecFlba or LKind.DecBin)
            t.Scale = Math.Min(t.Precision, rng.Pick(0, 0, 1, 2, 6, t.Precision, rng.Int(t.Precision + 1)));
        t.Configure(rng);
        return t;
    }

    static int MinBytes(int precision)
    {
        var max = BigInteger.Pow(10, precision) - 1;
        var bytes = 1;
        while (BigInteger.Pow(2, 8 * bytes - 1) - 1 < max) bytes++;
        return bytes;
    }

    /// <summary>A column with a fixed logical layout (e.g. the one the source generator picks for a CLR type).</summary>
    public static LType Make(Rng rng, string name, LKind k, bool optional, long rows, int precision = 0, int scale = 0, int length = 0,
        TimeUnit unit = TimeUnit.Micros, bool utc = false, int bits = 0, bool signed = false)
    {
        var physical = k switch
        {
            LKind.DecFlba or LKind.Uuid or LKind.F16 or LKind.Interval => Kind.Fixed,
            LKind.Date or LKind.DecI32 => Kind.Int32,
            LKind.DecBin or LKind.Enum or LKind.Json or LKind.Bson => Kind.Bytes,
            LKind.Time when unit == TimeUnit.Millis => Kind.Int32,
            LKind.IntN when bits < 64 => Kind.Int32,
            _ => Kind.Int64,
        };
        var spec = ColSpec.Draw(rng, name, physical, optional, rows, allowHuge: false);
        var t = new LType { Spec = spec, K = k, Precision = precision, Scale = scale, Length = length, Unit = unit, Utc = utc, Bits = bits, Signed = signed };
        t.Configure(rng);
        spec.Encodings = [];
        spec.Compression = null;
        spec.Bloom = false;
        return t;
    }

    void Configure(Rng rng)
    {
        var s = Spec;
        s.TypeName = $"{K}" + K switch
        {
            LKind.DecI32 or LKind.DecI64 or LKind.DecFlba or LKind.DecBin => $"({Precision},{Scale}{(Padded ? ",pad" : "")})",
            LKind.Ts or LKind.Time => $"({Unit},{(Utc ? "utc" : "local")})",
            LKind.IntN => $"({Bits},{(Signed ? "s" : "u")})",
            _ => "",
        } + (Domain == 1 ? "!" : "");
        switch (K)
        {
            case LKind.DecI32:
                s.Kind = Kind.Int32; s.Logical = new LogicalType.Decimal(Precision, Scale);
                s.Raw32 = r => (int)Unscaled(r);
                break;
            case LKind.DecI64:
                s.Kind = Kind.Int64; s.Logical = new LogicalType.Decimal(Precision, Scale);
                s.Raw64 = r => (long)Unscaled(r);
                break;
            case LKind.DecFlba:
                s.Kind = Kind.Fixed; s.L1 = Length; s.LenMode = 0; s.Logical = new LogicalType.Decimal(Precision, Scale);
                s.RawBytes = r => BigEndian(Unscaled(r), Length);
                s.Order = StatOrder.SignedBigEndian;
                break;
            case LKind.DecBin:
                s.Kind = Kind.Bytes; s.Logical = new LogicalType.Decimal(Precision, Scale);
                s.RawBytes = r => Padded ? BigEndian(Unscaled(r), Length) : Unscaled(r).ToByteArray(isUnsigned: false, isBigEndian: true);
                s.Order = StatOrder.SignedBigEndian;
                break;
            case LKind.Ts:
                s.Kind = Kind.Int64; s.Logical = new LogicalType.Timestamp(Unit, Utc);
                s.Raw64 = TimestampRaw;
                break;
            case LKind.Int96:
                s.Kind = Kind.Int96; s.L1 = 12; s.LenMode = 0;
                s.RawBytes = Int96Raw; s.Order = StatOrder.None;
                break;
            case LKind.Date:
                s.Kind = Kind.Int32; s.Logical = new LogicalType.Date();
                s.Raw32 = r => Domain == 1 ? (int)s.Base(r) : (int)(-719162 + Mod(s.Base(r), 2932896L + 719162 + 1));
                break;
            case LKind.Time:
                s.Logical = new LogicalType.Time(Unit, Utc);
                var perDay = Unit switch { TimeUnit.Millis => 86_400_000L, TimeUnit.Micros => 86_400_000_000L, _ => 86_400_000_000_000L };
                if (Unit == TimeUnit.Millis)
                    s.Raw32 = r => Domain == 1 ? (int)s.Base(r) : (int)Mod(s.Base(r), perDay);
                else
                    s.Raw64 = r => Domain == 1 ? s.Base(r) : Mod(s.Base(r), perDay);
                break;
            case LKind.Uuid:
                s.Kind = Kind.Fixed; s.L1 = 16; s.LenMode = 0; s.Logical = new LogicalType.Uuid();
                s.RawBytes = r =>
                {
                    var b = new byte[16];
                    var v = s.Base(r);
                    BinaryPrimitives.WriteInt64BigEndian(b, v);
                    BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8), Rng.Mix((ulong)v ^ s.Seed));
                    return b;
                };
                break;
            case LKind.F16:
                s.Kind = Kind.Fixed; s.L1 = 2; s.LenMode = 0; s.Logical = new LogicalType.Float16();
                s.RawBytes = r =>
                {
                    var b = new byte[2];
                    BinaryPrimitives.WriteUInt16LittleEndian(b, (ushort)s.Base(r));
                    return b;
                };
                s.Order = StatOrder.Half;
                break;
            case LKind.Interval:
                s.Kind = Kind.Fixed; s.L1 = 12; s.LenMode = 0; s.Logical = new LogicalType.Interval();
                s.RawBytes = r =>
                {
                    var b = new byte[12];
                    var v = (ulong)s.Base(r);
                    BinaryPrimitives.WriteUInt32LittleEndian(b, (uint)(v % 1200));
                    BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), (uint)(v / 1200 % 36500));
                    BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), (uint)(v >> 32));
                    return b;
                };
                s.Order = StatOrder.None;
                break;
            case LKind.Enum:
                s.Kind = Kind.Bytes; s.Logical = new LogicalType.Enum();
                s.RawBytes = r => Encoding.ASCII.GetBytes("E" + (s.Base(r) & 0xFFFF));
                break;
            case LKind.Json:
                s.Kind = Kind.Bytes; s.Logical = new LogicalType.Json();
                s.RawBytes = r => Encoding.ASCII.GetBytes($"{{\"v\":{s.Base(r)}}}");
                break;
            case LKind.Bson:
                s.Kind = Kind.Bytes; s.Logical = new LogicalType.Bson();
                s.RawBytes = r => { var b = new byte[8]; BinaryPrimitives.WriteInt64LittleEndian(b, s.Base(r)); return b; };
                break;
            case LKind.IntN:
                s.Logical = new LogicalType.Int((byte)Bits, Signed);
                if (Bits == 64)
                    s.Raw64 = r => s.Base(r);
                else
                    s.Raw32 = r => (Bits, Signed) switch
                    {
                        (8, true) => (sbyte)s.Base(r),
                        (8, false) => (byte)s.Base(r),
                        (16, true) => (short)s.Base(r),
                        (16, false) => (ushort)s.Base(r),
                        _ => (int)s.Base(r),
                    };
                if (!Signed) s.Order = StatOrder.Unsigned;
                break;
        }
        // Encodings: keep only those valid for the physical type (the drawn list was for the base kind).
        s.Encodings = s.Kind switch
        {
            Kind.Int96 => rng.Chance(50) ? [] : [EncodingKind.Plain],
            Kind.Fixed => rng.Pick<System.Collections.Immutable.ImmutableArray<EncodingKind>>([], [EncodingKind.Plain], [EncodingKind.RleDictionary],
                [EncodingKind.RleDictionary, EncodingKind.Plain], s.Optional ? [] : [EncodingKind.ByteStreamSplit]),
            Kind.Bytes => rng.Pick<System.Collections.Immutable.ImmutableArray<EncodingKind>>([], [EncodingKind.Plain], [EncodingKind.RleDictionary],
                [EncodingKind.DeltaLengthByteArray], [EncodingKind.DeltaByteArray], [EncodingKind.RleDictionary, EncodingKind.DeltaByteArray]),
            Kind.Int32 or Kind.Int64 => rng.Pick<System.Collections.Immutable.ImmutableArray<EncodingKind>>([], [EncodingKind.Plain], [EncodingKind.RleDictionary],
                [EncodingKind.DeltaBinaryPacked], [EncodingKind.ByteStreamSplit], [EncodingKind.RleDictionary, EncodingKind.DeltaBinaryPacked]),
            _ => [],
        };
        if (K is LKind.Int96 or LKind.Interval or LKind.F16)
            s.Bloom = false;
    }

    static long Mod(long v, long m) => (long)((ulong)v % (ulong)m);

    // ---------------- raw values ----------------

    public BigInteger Unscaled(long r)
    {
        var b = Spec.Base(r);
        if (Precision <= 18)
        {
            var m = Pow10L(Precision);
            return Domain == 1 && Precision <= 9 && K == LKind.DecI32 ? b % m : b % m;
        }
        var tail = Rng.Mix((ulong)b ^ Spec.Seed) % (ulong)Pow10L(Math.Min(18, Precision - 19 + 1));
        var u = (BigInteger)b * BigInteger.Pow(10, Precision - 19) + (BigInteger)(tail % (ulong)Pow10L(Math.Min(18, Precision - 19)));
        var limit = BigInteger.Pow(10, Precision);
        return BigInteger.Remainder(u, limit);
    }

    static long Pow10L(int p) { long v = 1; for (var i = 0; i < p; i++) v *= 10; return v; }

    static byte[] BigEndian(BigInteger v, int length)
    {
        var minimal = v.ToByteArray(isUnsigned: false, isBigEndian: true);
        if (minimal.Length > length)
            throw new InvalidOperationException($"value {v} needs {minimal.Length} bytes, column has {length}");
        var b = new byte[length];
        if (v.Sign < 0) b.AsSpan().Fill(0xFF);
        minimal.CopyTo(b, length - minimal.Length);
        return b;
    }

    long TicksPerUnitNum => Unit switch { TimeUnit.Millis => TimeSpan.TicksPerMillisecond, TimeUnit.Micros => 10, _ => 1 };

    long TimestampRaw(long r)
    {
        var b = Spec.Base(r);
        if (Domain == 1)
            return b;
        // Inside DateTime's range for the unit.
        long lo, hi;
        switch (Unit)
        {
            case TimeUnit.Millis: lo = (DateTime.MinValue.Ticks - EpochTicks) / 10_000; hi = (DateTime.MaxValue.Ticks - EpochTicks) / 10_000; break;
            case TimeUnit.Micros: lo = (DateTime.MinValue.Ticks - EpochTicks) / 10; hi = (DateTime.MaxValue.Ticks - EpochTicks) / 10; break;
            default:
                // Int64 nanoseconds span 1677..2262; keep most values on whole ticks so DateTime is exact.
                var n = b / 100 * 100;
                return Spec.Pattern % 3 == 0 ? b : n;
        }
        return lo + Mod(b, hi - lo + 1);
    }

    byte[] Int96Raw(long r)
    {
        var b = Spec.Base(r);
        var bytes = new byte[12];
        if (Domain == 1)
        {
            BinaryPrimitives.WriteInt64LittleEndian(bytes, b);
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), (int)Rng.Mix((ulong)b));
            return bytes;
        }
        var julian = 1721426 + (int)Mod(b, 5373484 - 1721426 + 1);
        var nanos = Mod((long)Rng.Mix((ulong)b ^ 7), 86_400_000_000_000L);
        if (Spec.Pattern % 2 == 0) nanos = nanos / 100 * 100;
        BinaryPrimitives.WriteInt64LittleEndian(bytes, nanos);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), julian);
        return bytes;
    }

    // ---------------- semantic values ----------------

    /// <summary>The decimal the row means, or null when it does not fit System.Decimal.</summary>
    public decimal? Decimal(long r)
    {
        if (Scale > 28) return null;
        var u = Unscaled(r);
        var mag = BigInteger.Abs(u);
        if (mag >= BigInteger.One << 96) return null;
        var bytes = mag.ToByteArray(isUnsigned: true, isBigEndian: false);
        Span<byte> w = stackalloc byte[12];
        bytes.AsSpan(0, Math.Min(12, bytes.Length)).CopyTo(w);
        return new decimal(BinaryPrimitives.ReadInt32LittleEndian(w), BinaryPrimitives.ReadInt32LittleEndian(w[4..]),
            BinaryPrimitives.ReadInt32LittleEndian(w[8..]), u.Sign < 0, (byte)Scale);
    }

    /// <summary>DateTime ticks (exact), or null when outside DateTime; Inexact marks a nanosecond value not on a tick.</summary>
    public long? TimestampTicks(long r, out bool inexact)
    {
        inexact = false;
        var raw = Spec.Int64(r);
        BigInteger ticks = Unit switch
        {
            TimeUnit.Millis => (BigInteger)raw * 10_000,
            TimeUnit.Micros => (BigInteger)raw * 10,
            _ => (BigInteger)raw / 100,
        };
        if (Unit == TimeUnit.Nanos && raw % 100 != 0) inexact = true;
        ticks += EpochTicks;
        if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks) return null;
        return (long)ticks;
    }

    public long? Int96Ticks(long r)
    {
        var b = Spec.Bytes(r);
        var nanos = BinaryPrimitives.ReadInt64LittleEndian(b);
        var julian = BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(8));
        // INT96 is read leniently (like Arrow): day + nanoseconds, even outside [0, 1 day).
        var ticks = (BigInteger)(julian - (long)JulianUnixEpoch) * TimeSpan.TicksPerDay + nanos / 100 + EpochTicks;
        if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks) return null;
        return (long)ticks;
    }

    public DateOnly? Date(long r)
    {
        var days = (long)Spec.Int32(r) + 719162;
        return days is < 0 or > 3652058 ? null : DateOnly.FromDayNumber((int)days);
    }

    public static long KnownTimeNanosNegative;

    public TimeOnly? Time(long r)
    {
        var raw = Unit == TimeUnit.Millis ? Spec.Int32(r) : Spec.Int64(r);
        var perDay = Unit switch { TimeUnit.Millis => 86_400_000L, TimeUnit.Micros => 86_400_000_000L, _ => 86_400_000_000_000L };
        // Known defect (fuzz/repros/time-nanos-negative-accepted): TIME(NANOS) -1..-99 reads as 00:00:00. Tolerated unless strict.
        if (Unit == TimeUnit.Nanos && raw is > -100 and < 0 && Environment.GetEnvironmentVariable("SCALE_STRICT") != "1")
        {
            Interlocked.Increment(ref KnownTimeNanosNegative);
            return new TimeOnly(0);
        }
        if (raw < 0 || raw >= perDay) return null;
        var ticks = Unit switch { TimeUnit.Millis => raw * 10_000, TimeUnit.Micros => raw * 10, _ => raw / 100 };
        return new TimeOnly(ticks);
    }

    public Guid Uuid(long r) => new(Spec.Bytes(r), bigEndian: true);
}

/// <summary>Columnar writer for logical-type columns: each column is fed raw physical values or semantic CLR values.</summary>
public static class TypesWriter
{
    public static string[] Write(Stream output, LType[] cols, long[] groups, ParquetWriterOptions options, Rng rng)
    {
        var schema = new ParquetSchema([.. cols.Select(c => c.Spec.Definition())]);
        // Per column: semantic (CLR) input when every value is representable, else raw.
        var mode = cols.Select(c => SemanticOk(c, groups.Sum()) && rng.Chance(60) ? "semantic" : "raw").ToArray();
        using var writer = schema.CreateWriter(output, options);
        s_shared = new Dictionary<int, object>();
        long start = 0;
        foreach (var n in groups)
        {
            var rg = writer.StartRowGroup();
            for (var c = 0; c < cols.Length; c++)
            {
                var t = cols[c];
                var leaf = schema.LeafColumns[c];
                if (mode[c] == "semantic")
                    WriteSemantic(writer, rg, leaf, t, start, n);
                else
                    WriteRaw(writer, rg, leaf, t.Spec, start, n);
            }
            start += n;
        }
        writer.CloseFile();
        return mode;
    }

    static bool SemanticOk(LType t, long rows)
    {
        if (t.Domain == 1) return false;
        // Plank refuses System.Decimal input for precision > 29 even when the values fit (a limitation).
        if (t.K is LKind.DecI32 or LKind.DecI64 or LKind.DecFlba && (t.Precision > 29 || t.Scale > 28)) return false;
        var probe = Math.Min(rows, 50_000);
        for (long r = 0; r < probe; r++)
        {
            if (t.Spec.IsNull(r)) continue;
            switch (t.K)
            {
                case LKind.DecI32 or LKind.DecI64 or LKind.DecFlba when t.Decimal(r) is null: return false;
                case LKind.DecBin: return false; // System.Decimal is written as FIXED_LEN_BYTE_ARRAY / INT32 / INT64 only
                case LKind.Ts:
                    if (t.TimestampTicks(r, out var inexact) is null || inexact) return false;
                    break;
                case LKind.Date when t.Date(r) is null: return false;
                case LKind.Time when t.Time(r) is null || t.Unit == TimeUnit.Nanos: return false;
                case LKind.Int96 or LKind.F16 or LKind.Interval or LKind.Bson: return false;
            }
        }
        if (t.K is LKind.Int96 or LKind.F16 or LKind.Interval or LKind.Bson or LKind.DecBin) return false;
        if (t.K == LKind.IntN && t.Signed) return false;
        if (t.K is LKind.DecFlba && t.Padded) return false; // System.Decimal input uses the column's declared width anyway
        return rows <= 50_000 || t.Domain == 0;
    }

    static T[] Fill<T>(long n, Func<long, T> f) { var a = new T[n]; for (long i = 0; i < n; i++) a[i] = f(i); return a; }

    // One SerializedColumn per (leaf, CLR type), reused across row groups: the writer keeps every column it creates.
    [ThreadStatic] static Dictionary<int, object>? s_shared;

    static void Put<T>(RowGroupWriter rg, LeafColumn leaf, T[] values)
    {
        var key = HashCode.Combine(leaf.Path, typeof(T));
        if (!s_shared!.TryGetValue(key, out var shared))
            s_shared[key] = shared = rg.CreateSerializedColumn<T>(leaf);
        var column = (SerializedColumn<T>)shared;
        column.Serialize(values);
        rg.Write(column);
    }

    static void WriteRaw(ParquetWriter writer, RowGroupWriter rg, LeafColumn leaf, ColSpec s, long start, long n)
    {
        switch (s.Kind, s.Optional)
        {
            case (Kind.Int32, false): Put(rg, leaf, Fill(n, r => s.Int32(start + r))); break;
            case (Kind.Int32, true): Put(rg, leaf, Fill(n, r => s.IsNull(start + r) ? (int?)null : s.Int32(start + r))); break;
            case (Kind.Int64, false): Put(rg, leaf, Fill(n, r => s.Int64(start + r))); break;
            case (Kind.Int64, true): Put(rg, leaf, Fill(n, r => s.IsNull(start + r) ? (long?)null : s.Int64(start + r))); break;
            default: Put(rg, leaf, Fill(n, r => s.IsNull(start + r) ? null : s.Bytes(start + r))); break;
        }
    }

    static void WriteSemantic(ParquetWriter writer, RowGroupWriter rg, LeafColumn leaf, LType t, long start, long n)
    {
        var s = t.Spec;
        bool N(long r) => s.IsNull(start + r);
        switch (t.K)
        {
            case LKind.DecI32 or LKind.DecI64 or LKind.DecFlba:
                if (s.Optional) Put(rg, leaf, Fill(n, r => N(r) ? null : t.Decimal(start + r)));
                else Put(rg, leaf, Fill(n, r => t.Decimal(start + r)!.Value));
                break;
            case LKind.Ts when t.Utc && (start & 1) == 0:
                if (s.Optional) Put(rg, leaf, Fill(n, r => N(r) ? (DateTimeOffset?)null : new DateTimeOffset(t.TimestampTicks(start + r, out _)!.Value, TimeSpan.Zero)));
                else Put(rg, leaf, Fill(n, r => new DateTimeOffset(t.TimestampTicks(start + r, out _)!.Value, TimeSpan.Zero)));
                break;
            case LKind.Ts:
                var kind = t.Utc ? DateTimeKind.Utc : DateTimeKind.Unspecified;
                if (s.Optional) Put(rg, leaf, Fill(n, r => N(r) ? (DateTime?)null : new DateTime(t.TimestampTicks(start + r, out _)!.Value, kind)));
                else Put(rg, leaf, Fill(n, r => new DateTime(t.TimestampTicks(start + r, out _)!.Value, kind)));
                break;
            case LKind.Date:
                if (s.Optional) Put(rg, leaf, Fill(n, r => N(r) ? null : t.Date(start + r)));
                else Put(rg, leaf, Fill(n, r => t.Date(start + r)!.Value));
                break;
            case LKind.Time:
                if (s.Optional) Put(rg, leaf, Fill(n, r => N(r) ? null : t.Time(start + r)));
                else Put(rg, leaf, Fill(n, r => t.Time(start + r)!.Value));
                break;
            case LKind.Uuid:
                if (s.Optional) Put(rg, leaf, Fill(n, r => N(r) ? (Guid?)null : t.Uuid(start + r)));
                else Put(rg, leaf, Fill(n, r => t.Uuid(start + r)));
                break;
            case LKind.Enum or LKind.Json:
                Put(rg, leaf, Fill(n, r => N(r) ? null! : Encoding.ASCII.GetString(s.Bytes(start + r))));
                break;
            case LKind.IntN:
                switch (t.Bits, s.Optional)
                {
                    case (8, false): Put(rg, leaf, Fill(n, r => (byte)s.Int32(start + r))); break;
                    case (8, true): Put(rg, leaf, Fill(n, r => N(r) ? (byte?)null : (byte)s.Int32(start + r))); break;
                    case (16, false): Put(rg, leaf, Fill(n, r => (ushort)s.Int32(start + r))); break;
                    case (16, true): Put(rg, leaf, Fill(n, r => N(r) ? (ushort?)null : (ushort)s.Int32(start + r))); break;
                    case (32, false): Put(rg, leaf, Fill(n, r => (uint)s.Int32(start + r))); break;
                    case (32, true): Put(rg, leaf, Fill(n, r => N(r) ? (uint?)null : (uint)s.Int32(start + r))); break;
                    case (64, false): Put(rg, leaf, Fill(n, r => (ulong)s.Int64(start + r))); break;
                    default: Put(rg, leaf, Fill(n, r => N(r) ? (ulong?)null : (ulong)s.Int64(start + r))); break;
                }
                break;
            default:
                WriteRaw(writer, rg, leaf, s, start, n);
                break;
        }
    }
}

/// <summary>Reads each logical-type column with Plank's semantic CLR projections and checks the meaning row by row.</summary>
public static class TypesVerify
{
    public static long SemanticValues, SemanticRefusals;
    public static readonly Dictionary<string, long> Refused = [];

    public static void Check(Plank.Reading.IParquetReadSource source, LType[] cols, Expected e)
    {
        using var reader = new ParquetReader();
        reader.Reset(source);
        for (var c = 0; c < cols.Length; c++)
        {
            var t = cols[c];
            var leaf = reader.Schema.LeafColumns[c];
            foreach (var (name, read) in Projections(t))
            {
                long start = 0;
                try
                {
                    foreach (RowGroup g in reader.RowGroups)
                    {
                        var n = read(g, leaf, start, e, $"semantic {name} rg{g.Index} col{c}({t.Spec.TypeName})");
                        if (n != (long)g.RowCount)
                            throw new Finding($"semantic {name} col{c}({t.Spec.TypeName}): {n} values for {g.RowCount} rows");
                        start += (long)g.RowCount;
                    }
                }
                catch (Finding) { throw; }
                catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException or OverflowException
                                               or ArgumentOutOfRangeException or CorruptParquetException or InvalidCastException)
                {
                    // A refusal is acceptable only when some value of the column cannot be represented, or the projection
                    // is not offered for this logical type. Counted per (type, projection, exception) for the notes.
                    SemanticRefusals++;
                    var key = $"{t.K}{(t.K == LKind.Ts || t.K == LKind.Time ? "/" + t.Unit + (t.Utc ? "/utc" : "/local") : "")}{(t.Domain == 1 ? "!" : "")} -> {name}: {ex.GetType().Name}: {Trim(ex.Message)}";
                    lock (Refused) Refused[key] = Refused.GetValueOrDefault(key) + 1;
                    if (t.Domain == 0 && RepresentableEverywhere(t, e) && !ExpectedRefusal(t, name))
                        throw new Finding($"semantic {name} col{c}({t.Spec.TypeName}) refused although every value is representable: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }
    }

    static string Trim(string m) => m.Length > 90 ? m[..90] : m;

    /// <summary>Projections Plank documents as unsupported for a type (not findings).</summary>
    static bool ExpectedRefusal(LType t, string projection)
        => (t.K == LKind.Ts && !t.Utc && projection.StartsWith("DateTimeOffset", StringComparison.Ordinal))
           || (t.K is LKind.DecI32 or LKind.DecI64 or LKind.DecFlba or LKind.DecBin && t.Precision > 29)
           // RowGroup.ValidatePhysicalType refuses Guid on purpose (logical API reads FLBA as bytes; the row API has Guid).
           || (t.K == LKind.Uuid && projection == "Guid")
           // BYTE_ARRAY decimals in DELTA_LENGTH_BYTE_ARRAY / DELTA_BYTE_ARRAY pages are not decoded into decimal (limitation).
           || (t.K == LKind.DecBin && t.Spec.Encodings.Any(x => x is EncodingKind.DeltaLengthByteArray or EncodingKind.DeltaByteArray));

    static bool RepresentableEverywhere(LType t, Expected e)
    {
        for (long i = 0; i < Math.Min(e.Rows, 100_000); i++)
        {
            var r = e.Row(i);
            if (t.Spec.IsNull(r)) continue;
            var ok = t.K switch
            {
                LKind.DecI32 or LKind.DecI64 or LKind.DecFlba or LKind.DecBin => t.Decimal(r) is not null,
                LKind.Ts => t.TimestampTicks(r, out _) is not null,
                LKind.Int96 => t.Int96Ticks(r) is not null,
                LKind.Date => t.Date(r) is not null,
                LKind.Time => t.Time(r) is not null,
                _ => true,
            };
            if (!ok) return false;
        }
        return true;
    }

    delegate long Reader(RowGroup g, LeafColumn leaf, long start, Expected e, string where);

    static IEnumerable<(string, Reader)> Projections(LType t)
    {
        var s = t.Spec;
        var opt = s.Optional;
        switch (t.K)
        {
            case LKind.DecI32 or LKind.DecI64 or LKind.DecFlba or LKind.DecBin:
                yield return ("decimal", (g, leaf, start, e, where) => opt
                    ? Read<decimal>(g.Column<decimal?>(leaf), start, e, s, where, r => t.Decimal(r), (a, b) => a == b)
                    : Read<decimal>(g.Column<decimal>(leaf), start, e, s, where, r => t.Decimal(r), (a, b) => a == b));
                break;
            case LKind.Ts:
            {
                var kind = t.Utc ? DateTimeKind.Utc : DateTimeKind.Unspecified;
                yield return ("DateTime", (g, leaf, start, e, where) => opt
                    ? ReadTs(g.Column<DateTime?>(leaf), start, e, t, where, kind)
                    : ReadTs(g.Column<DateTime>(leaf), start, e, t, where, kind));
                yield return ("DateTimeOffset", (g, leaf, start, e, where) => opt
                    ? Read<DateTimeOffset>(g.Column<DateTimeOffset?>(leaf), start, e, s, where, r => TsOffset(t, r), SameOffset)
                    : Read<DateTimeOffset>(g.Column<DateTimeOffset>(leaf), start, e, s, where, r => TsOffset(t, r), SameOffset));
                break;
            }
            case LKind.Int96:
                yield return ("DateTime", (g, leaf, start, e, where) => opt
                    ? Read<DateTime>(g.Column<DateTime?>(leaf), start, e, s, where, r => t.Int96Ticks(r) is { } k ? new DateTime(k) : null, (a, b) => a.Ticks == b.Ticks)
                    : Read<DateTime>(g.Column<DateTime>(leaf), start, e, s, where, r => t.Int96Ticks(r) is { } k ? new DateTime(k) : null, (a, b) => a.Ticks == b.Ticks));
                break;
            case LKind.Date:
                yield return ("DateOnly", (g, leaf, start, e, where) => opt
                    ? Read<DateOnly>(g.Column<DateOnly?>(leaf), start, e, s, where, r => t.Date(r), (a, b) => a == b)
                    : Read<DateOnly>(g.Column<DateOnly>(leaf), start, e, s, where, r => t.Date(r), (a, b) => a == b));
                break;
            case LKind.Time:
                yield return ("TimeOnly", (g, leaf, start, e, where) => opt
                    ? Read<TimeOnly>(g.Column<TimeOnly?>(leaf), start, e, s, where, r => t.Time(r), (a, b) => a == b)
                    : Read<TimeOnly>(g.Column<TimeOnly>(leaf), start, e, s, where, r => t.Time(r), (a, b) => a == b));
                break;
            case LKind.Uuid:
                yield return ("Guid", (g, leaf, start, e, where) => opt
                    ? Read<Guid>(g.Column<Guid?>(leaf), start, e, s, where, r => t.Uuid(r), (a, b) => a == b)
                    : Read<Guid>(g.Column<Guid>(leaf), start, e, s, where, r => t.Uuid(r), (a, b) => a == b));
                break;
            case LKind.IntN when !t.Signed:
                switch (t.Bits)
                {
                    case 8: yield return ("byte", (g, leaf, start, e, where) => opt ? Read<byte>(g.Column<byte?>(leaf), start, e, s, where, r => (byte)s.Int32(r), (a, b) => a == b) : Read<byte>(g.Column<byte>(leaf), start, e, s, where, r => (byte)s.Int32(r), (a, b) => a == b)); break;
                    case 16: yield return ("ushort", (g, leaf, start, e, where) => opt ? Read<ushort>(g.Column<ushort?>(leaf), start, e, s, where, r => (ushort)s.Int32(r), (a, b) => a == b) : Read<ushort>(g.Column<ushort>(leaf), start, e, s, where, r => (ushort)s.Int32(r), (a, b) => a == b)); break;
                    case 32: yield return ("uint", (g, leaf, start, e, where) => opt ? Read<uint>(g.Column<uint?>(leaf), start, e, s, where, r => (uint)s.Int32(r), (a, b) => a == b) : Read<uint>(g.Column<uint>(leaf), start, e, s, where, r => (uint)s.Int32(r), (a, b) => a == b)); break;
                    default: yield return ("ulong", (g, leaf, start, e, where) => opt ? Read<ulong>(g.Column<ulong?>(leaf), start, e, s, where, r => (ulong)s.Int64(r), (a, b) => a == b) : Read<ulong>(g.Column<ulong>(leaf), start, e, s, where, r => (ulong)s.Int64(r), (a, b) => a == b)); break;
                }
                break;
        }
    }

    static DateTimeOffset? TsOffset(LType t, long r)
        => t.TimestampTicks(r, out _) is { } k ? new DateTimeOffset(k, TimeSpan.Zero) : null;

    static bool SameOffset(DateTimeOffset a, DateTimeOffset b) => a.UtcTicks == b.UtcTicks && a.Offset == b.Offset;

    static long Read<T>(RowGroupColumn<T> column, long start, Expected e, ColSpec s, string where, Func<long, T?> want, Func<T, T, bool> same)
        where T : struct
    {
        long i = 0;
        foreach (var b in column)
            foreach (var v in b.Values)
            {
                var r = e.Row(start + i);
                var w = want(r);
                if (w is null)
                    throw new Finding($"{where}: row {start + i}: returned {v} for a value outside the CLR type (raw {Raw(s, r)})");
                if (!same(v, w.Value))
                    throw new Finding($"{where}: row {start + i}: read {Show(v)}, expected {Show(w.Value)} (raw {Raw(s, r)})");
                i++;
                SemanticValues++;
            }
        return i;
    }

    static long Read<T>(RowGroupColumn<T?> column, long start, Expected e, ColSpec s, string where, Func<long, T?> want, Func<T, T, bool> same)
        where T : struct
    {
        long i = 0;
        foreach (var b in column)
            foreach (var v in b.Values)
            {
                var r = e.Row(start + i);
                if (s.IsNull(r) != !v.HasValue)
                    throw new Finding($"{where}: row {start + i}: null {!v.HasValue}, expected {s.IsNull(r)}");
                if (v.HasValue)
                {
                    var w = want(r);
                    if (w is null)
                        throw new Finding($"{where}: row {start + i}: returned {v} for a value outside the CLR type (raw {Raw(s, r)})");
                    if (!same(v.Value, w.Value))
                        throw new Finding($"{where}: row {start + i}: read {Show(v.Value)}, expected {Show(w.Value)} (raw {Raw(s, r)})");
                }
                i++;
                SemanticValues++;
            }
        return i;
    }

    static long ReadTs(RowGroupColumn<DateTime> column, long start, Expected e, LType t, string where, DateTimeKind kind)
        => Read<DateTime>(column, start, e, t.Spec, where, r => TsWant(t, r, kind), (a, b) => TsSame(t, a, b, kind));

    static long ReadTs(RowGroupColumn<DateTime?> column, long start, Expected e, LType t, string where, DateTimeKind kind)
        => Read<DateTime>(column, start, e, t.Spec, where, r => TsWant(t, r, kind), (a, b) => TsSame(t, a, b, kind));

    static DateTime? TsWant(LType t, long r, DateTimeKind kind) => t.TimestampTicks(r, out _) is { } k ? new DateTime(k, kind) : null;

    // Nanosecond values off a tick may truncate or floor; both are accepted. The kind must follow isAdjustedToUTC.
    static bool TsSame(LType t, DateTime a, DateTime b, DateTimeKind kind)
        => a.Kind == kind && (a.Ticks == b.Ticks || (t.Unit == TimeUnit.Nanos && Math.Abs(a.Ticks - b.Ticks) == 1));

    static string Raw(ColSpec s, long r) => s.Kind switch
    {
        Kind.Int32 => s.Int32(r).ToString(System.Globalization.CultureInfo.InvariantCulture),
        Kind.Int64 => s.Int64(r).ToString(System.Globalization.CultureInfo.InvariantCulture),
        _ => Verify.Hex(s.Bytes(r)),
    };

    static string Show<T>(T v) => v is DateTime d ? $"{d:O} ({d.Ticks}, {d.Kind})" : v is DateTimeOffset o ? $"{o:O} ({o.UtcTicks})" : v is decimal m ? $"{m} (scale {m.Scale})" : $"{v}";
}
