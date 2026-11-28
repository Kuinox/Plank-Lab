using System.Text;
using Plank.Schema;
using Ps = ParquetSharp;

namespace Plank.Fuzzing.Scale;

/// <summary>
/// Logical types written by Arrow C++ (ParquetSharp's logical writers: decimal, DateTime/DateTimeNanos in every unit, Date,
/// TimeSpan/TimeSpanNanos, Guid, Half, sbyte..ulong, JSON/ENUM strings) at scale, then read by Plank raw (every read path,
/// statistics as bounds, page index) and semantically.
/// </summary>
public static class ArrowTypes
{
    static readonly LKind[] Kinds = [LKind.DecFlba, LKind.Ts, LKind.Date, LKind.Time, LKind.Uuid, LKind.F16, LKind.IntN, LKind.Json];

    public static LType Draw(Rng rng, string name, long rows)
    {
        var k = rng.Pick(Kinds);
        var optional = rng.Chance(50);
        return k switch
        {
            LKind.DecFlba => DrawDecimal(rng, name, optional, rows),
            LKind.Ts => LType.Make(rng, name, k, optional, rows, unit: (TimeUnit)rng.Int(3), utc: rng.Chance(50)),
            LKind.Time => LType.Make(rng, name, k, optional, rows, unit: (TimeUnit)rng.Int(3), utc: rng.Chance(50)),
            LKind.IntN => LType.Make(rng, name, k, optional, rows, bits: rng.Pick(8, 16, 32, 64), signed: rng.Chance(50)),
            _ => LType.Make(rng, name, k, optional, rows),
        };
    }

    static LType DrawDecimal(Rng rng, string name, bool optional, long rows)
    {
        var p = rng.Pick(1, 5, 9, 10, 18, 19, 27, 28);
        var s = Math.Min(p, rng.Pick(0, 1, 2, 6, p));
        var bytes = 1;
        while (System.Numerics.BigInteger.Pow(2, 8 * bytes - 1) - 1 < System.Numerics.BigInteger.Pow(10, p) - 1) bytes++;
        return LType.Make(rng, name, LKind.DecFlba, optional, rows, p, s, bytes);
    }

    static Ps.TimeUnit Unit(TimeUnit u) => u switch { TimeUnit.Millis => Ps.TimeUnit.Millis, TimeUnit.Micros => Ps.TimeUnit.Micros, _ => Ps.TimeUnit.Nanos };

    static Ps.Column Column(LType t)
    {
        var n = t.Spec.Name;
        var o = t.Spec.Optional;
        return t.K switch
        {
            LKind.DecFlba => new Ps.Column(o ? typeof(decimal?) : typeof(decimal), n, Ps.LogicalType.Decimal(t.Precision, t.Scale)),
            LKind.Ts when t.Unit == TimeUnit.Nanos => new Ps.Column(o ? typeof(Ps.DateTimeNanos?) : typeof(Ps.DateTimeNanos), n, Ps.LogicalType.Timestamp(t.Utc, Ps.TimeUnit.Nanos)),
            LKind.Ts => new Ps.Column(o ? typeof(DateTime?) : typeof(DateTime), n, Ps.LogicalType.Timestamp(t.Utc, Unit(t.Unit))),
            LKind.Date => new Ps.Column(o ? typeof(Ps.Date?) : typeof(Ps.Date), n),
            LKind.Time when t.Unit == TimeUnit.Nanos => new Ps.Column(o ? typeof(Ps.TimeSpanNanos?) : typeof(Ps.TimeSpanNanos), n, Ps.LogicalType.Time(t.Utc, Ps.TimeUnit.Nanos)),
            LKind.Time => new Ps.Column(o ? typeof(TimeSpan?) : typeof(TimeSpan), n, Ps.LogicalType.Time(t.Utc, Unit(t.Unit))),
            LKind.Uuid => new Ps.Column(o ? typeof(Guid?) : typeof(Guid), n),
            LKind.F16 => new Ps.Column(o ? typeof(Half?) : typeof(Half), n),
            LKind.IntN => new Ps.Column(IntType(t, o), n),
            LKind.Json => new Ps.Column(typeof(string), n, Ps.LogicalType.Json()),
            _ => new Ps.Column(typeof(string), n, Ps.LogicalType.Enum()),
        };
    }

    static Type IntType(LType t, bool o) => (t.Bits, t.Signed) switch
    {
        (8, true) => o ? typeof(sbyte?) : typeof(sbyte),
        (8, false) => o ? typeof(byte?) : typeof(byte),
        (16, true) => o ? typeof(short?) : typeof(short),
        (16, false) => o ? typeof(ushort?) : typeof(ushort),
        (32, true) => o ? typeof(int?) : typeof(int),
        (32, false) => o ? typeof(uint?) : typeof(uint),
        (64, true) => o ? typeof(long?) : typeof(long),
        _ => o ? typeof(ulong?) : typeof(ulong),
    };

    public static void Write(string path, LType[] cols, long[] groups, Rng rng)
    {
        var b = new Ps.WriterPropertiesBuilder()
            .Compression(rng.Pick(Ps.Compression.Uncompressed, Ps.Compression.Snappy, Ps.Compression.Zstd))
            .DataPagesize(rng.Pick(64L, 1024L, 1L << 20))
            .DictionaryPagesizeLimit(rng.Pick(256L, 65536L, 1L << 20))
            .MaxRowGroupLength(long.MaxValue)
            .DataPageVersion(rng.Chance(50) ? Ps.ParquetDataPageVersion.V1 : Ps.ParquetDataPageVersion.V2);
        b = rng.Chance(70) ? b.EnableWritePageIndex() : b.DisableWritePageIndex();
        if (rng.Chance(50)) b = b.DisableDictionary();
        using var props = b.Build();
        using var writer = new Ps.ParquetFileWriter(path, [.. cols.Select(Column)], props);
        long start = 0;
        foreach (var n in groups)
        {
            using var rg = writer.AppendRowGroup();
            foreach (var t in cols)
            {
                using var column = rg.NextColumn();
                WriteColumn(column, t, start, n);
            }
            start += n;
        }
        writer.Close();
    }

    static void WriteColumn(Ps.ColumnWriter column, LType t, long start, long n)
    {
        var s = t.Spec;
        bool N(long r) => s.IsNull(r);
        switch (t.K)
        {
            case LKind.DecFlba:
                if (s.Optional) All(column, start, n, r => N(r) ? null : t.Decimal(r)); else All(column, start, n, r => t.Decimal(r)!.Value);
                break;
            case LKind.Ts when t.Unit == TimeUnit.Nanos:
                if (s.Optional) All(column, start, n, r => N(r) ? (Ps.DateTimeNanos?)null : new Ps.DateTimeNanos(s.Int64(r)));
                else All(column, start, n, r => new Ps.DateTimeNanos(s.Int64(r)));
                break;
            case LKind.Ts:
                var kind = t.Utc ? DateTimeKind.Utc : DateTimeKind.Unspecified;
                if (s.Optional) All(column, start, n, r => N(r) ? (DateTime?)null : new DateTime(t.TimestampTicks(r, out _)!.Value, kind));
                else All(column, start, n, r => new DateTime(t.TimestampTicks(r, out _)!.Value, kind));
                break;
            case LKind.Date:
                if (s.Optional) All(column, start, n, r => N(r) ? (Ps.Date?)null : new Ps.Date(s.Int32(r))); else All(column, start, n, r => new Ps.Date(s.Int32(r)));
                break;
            case LKind.Time when t.Unit == TimeUnit.Nanos:
                if (s.Optional) All(column, start, n, r => N(r) ? (Ps.TimeSpanNanos?)null : new Ps.TimeSpanNanos(s.Int64(r)));
                else All(column, start, n, r => new Ps.TimeSpanNanos(s.Int64(r)));
                break;
            case LKind.Time:
                if (s.Optional) All(column, start, n, r => N(r) ? (TimeSpan?)null : t.Time(r)!.Value.ToTimeSpan()); else All(column, start, n, r => t.Time(r)!.Value.ToTimeSpan());
                break;
            case LKind.Uuid:
                if (s.Optional) All(column, start, n, r => N(r) ? (Guid?)null : t.Uuid(r)); else All(column, start, n, r => t.Uuid(r));
                break;
            case LKind.F16:
                Half H(long r) => BitConverter.UInt16BitsToHalf(BitConverter.ToUInt16(s.Bytes(r)));
                if (s.Optional) All(column, start, n, r => N(r) ? (Half?)null : H(r)); else All(column, start, n, H);
                break;
            case LKind.IntN:
                switch (t.Bits, t.Signed, s.Optional)
                {
                    case (8, true, false): All(column, start, n, r => (sbyte)s.Int32(r)); break;
                    case (8, true, true): All(column, start, n, r => N(r) ? (sbyte?)null : (sbyte)s.Int32(r)); break;
                    case (8, false, false): All(column, start, n, r => (byte)s.Int32(r)); break;
                    case (8, false, true): All(column, start, n, r => N(r) ? (byte?)null : (byte)s.Int32(r)); break;
                    case (16, true, false): All(column, start, n, r => (short)s.Int32(r)); break;
                    case (16, true, true): All(column, start, n, r => N(r) ? (short?)null : (short)s.Int32(r)); break;
                    case (16, false, false): All(column, start, n, r => (ushort)s.Int32(r)); break;
                    case (16, false, true): All(column, start, n, r => N(r) ? (ushort?)null : (ushort)s.Int32(r)); break;
                    case (32, true, false): All(column, start, n, r => s.Int32(r)); break;
                    case (32, true, true): All(column, start, n, r => N(r) ? (int?)null : s.Int32(r)); break;
                    case (32, false, false): All(column, start, n, r => (uint)s.Int32(r)); break;
                    case (32, false, true): All(column, start, n, r => N(r) ? (uint?)null : (uint)s.Int32(r)); break;
                    case (64, true, false): All(column, start, n, r => s.Int64(r)); break;
                    case (64, true, true): All(column, start, n, r => N(r) ? (long?)null : s.Int64(r)); break;
                    case (64, false, false): All(column, start, n, r => (ulong)s.Int64(r)); break;
                    default: All(column, start, n, r => N(r) ? (ulong?)null : (ulong)s.Int64(r)); break;
                }
                break;
            default:
                All(column, start, n, r => N(r) ? null! : Encoding.ASCII.GetString(s.Bytes(r)));
                break;
        }
    }

    static void All<T>(Ps.ColumnWriter column, long start, long n, Func<long, T> value)
    {
        using var writer = column.LogicalWriter<T>();
        const int batch = 65536;
        for (long off = 0; off < n; off += batch)
        {
            var m = (int)Math.Min(batch, n - off);
            var a = new T[m];
            for (var i = 0; i < m; i++) a[i] = value(start + off + i);
            writer.WriteBatch(a);
        }
    }
}
