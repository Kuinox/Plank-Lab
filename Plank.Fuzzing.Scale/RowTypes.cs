using System.Text;
using Plank.Reading;
using Plank.RowApi;
using Plank.Writing;
using Ps = ParquetSharp;

namespace Plank.Fuzzing.Scale;

/// <summary>
/// Semantic CLR types (decimal, DateTime, DateTimeOffset, DateOnly, TimeOnly, Guid, unsigned ints, JSON string) through the
/// generated row writer (pipeline, cursor, parallel), the dataset writer and the generated row reader. Each column is an
/// <see cref="LType"/> with the layout the source generator picks, so the raw physical bytes Plank writes are checked
/// against an independent encoding of the same value (byte order, scaling, units), by every raw reader and by Arrow.
/// </summary>
public static class RowTypes
{
    public static LType[] Columns(Rng rng, long rows) =>
    [
        LType.Make(rng, "Dec9", LKind.DecFlba, false, rows, 9, 2, 4),
        LType.Make(rng, "Dec18", LKind.DecFlba, true, rows, 18, 4, 8),
        LType.Make(rng, "Dec28", LKind.DecFlba, false, rows, 28, 10, 12),
        LType.Make(rng, "Stamp", LKind.Ts, false, rows, unit: Plank.Schema.TimeUnit.Micros, utc: true),
        LType.Make(rng, "StampUtc", LKind.Ts, true, rows, unit: Plank.Schema.TimeUnit.Micros, utc: true),
        LType.Make(rng, "Day", LKind.Date, false, rows),
        LType.Make(rng, "Clock", LKind.Time, true, rows, unit: Plank.Schema.TimeUnit.Micros, utc: false),
        LType.Make(rng, "Key", LKind.Uuid, false, rows),
        LType.Make(rng, "MaybeKey", LKind.Uuid, true, rows),
        LType.Make(rng, "U32", LKind.IntN, false, rows, bits: 32),
        LType.Make(rng, "U64", LKind.IntN, true, rows, bits: 64),
        LType.Make(rng, "U8", LKind.IntN, false, rows, bits: 8),
        LType.Make(rng, "U16", LKind.IntN, true, rows, bits: 16),
        LType.Make(rng, "Doc", LKind.Json, true, rows),
    ];

    public static ColSpec IdSpec() => new() { Name = "Id", Kind = Kind.Int64, Pattern = 1, P1 = 0, P2 = 1 };

    static DateTime Stamp(LType t, long r) => new(t.TimestampTicks(r, out _)!.Value, DateTimeKind.Utc);

    public static void Fill(ScaleTypes.Row row, LType[] c, long r)
    {
        row.Id = r;
        row.Dec9 = c[0].Decimal(r)!.Value;
        row.Dec18 = c[1].Spec.IsNull(r) ? null : c[1].Decimal(r);
        row.Dec28 = c[2].Decimal(r)!.Value;
        row.Stamp = Stamp(c[3], r);
        row.StampUtc = c[4].Spec.IsNull(r) ? null : new DateTimeOffset(c[4].TimestampTicks(r, out _)!.Value, TimeSpan.Zero);
        row.Day = c[5].Date(r)!.Value;
        row.Clock = c[6].Spec.IsNull(r) ? null : c[6].Time(r);
        row.Key = c[7].Uuid(r);
        row.MaybeKey = c[8].Spec.IsNull(r) ? null : c[8].Uuid(r);
        row.U32 = (uint)c[9].Spec.Int32(r);
        row.U64 = c[10].Spec.IsNull(r) ? null : (ulong)c[10].Spec.Int64(r);
        row.U8 = (byte)c[11].Spec.Int32(r);
        row.U16 = c[12].Spec.IsNull(r) ? null : (ushort)c[12].Spec.Int32(r);
        row.Doc = c[13].Spec.IsNull(r) ? null : Encoding.ASCII.GetString(c[13].Spec.Bytes(r));
    }

    public static ScaleTypes Make(LType[] c, long r) => new()
    {
        Id = r,
        Dec9 = c[0].Decimal(r)!.Value,
        Dec18 = c[1].Spec.IsNull(r) ? null : c[1].Decimal(r),
        Dec28 = c[2].Decimal(r)!.Value,
        Stamp = Stamp(c[3], r),
        StampUtc = c[4].Spec.IsNull(r) ? null : new DateTimeOffset(c[4].TimestampTicks(r, out _)!.Value, TimeSpan.Zero),
        Day = c[5].Date(r)!.Value,
        Clock = c[6].Spec.IsNull(r) ? null : c[6].Time(r),
        Key = c[7].Uuid(r),
        MaybeKey = c[8].Spec.IsNull(r) ? null : c[8].Uuid(r),
        U32 = (uint)c[9].Spec.Int32(r),
        U64 = c[10].Spec.IsNull(r) ? null : (ulong)c[10].Spec.Int64(r),
        U8 = (byte)c[11].Spec.Int32(r),
        U16 = c[12].Spec.IsNull(r) ? null : (ushort)c[12].Spec.Int32(r),
        Doc = c[13].Spec.IsNull(r) ? null : Encoding.ASCII.GetString(c[13].Spec.Bytes(r)),
    };

    public static void WriteRows(Stream output, LType[] c, long rows, ParquetWriterOptions options, Rng rng)
    {
        var parallel = rng.Chance(40) ? rng.Pick(1u, 2u, 4u, 8u) : 0u;
        using var writer = parallel != 0 ? ScaleTypes.CreateRowWriter(output, parallel, options) : ScaleTypes.CreateRowWriter(output, options);
        for (long r = 0; r < rows; r++)
            Fill(writer.GetRow(), c, r);
        writer.Complete();
    }

    /// <summary>Generated row reader (all properties) against the semantic values.</summary>
    public static void CheckRows(IParquetReadSource source, LType[] c, Expected e, RowReaderOptions options, string where)
    {
        using var reader = ScaleTypes.CreateRowReader(source, default, options);
        long i = 0;
        while (reader.MoveNext())
        {
            var row = reader.Current;
            var r = e.Row(i);
            var want = Make(c, r);
            void Check<T>(string name, T got, T expected)
            {
                if (!EqualityComparer<T>.Default.Equals(got, expected))
                    throw new Finding($"{where}: row {i} {name}: read {Show(got)}, expected {Show(expected)}");
            }
            Check("Id", row.Id, want.Id);
            Check("Dec9", row.Dec9, want.Dec9);
            Check("Dec18", row.Dec18, want.Dec18);
            Check("Dec28", row.Dec28, want.Dec28);
            Check("Stamp", row.Stamp, want.Stamp);
            Check("Stamp.Kind", row.Stamp.Kind, want.Stamp.Kind);
            Check("StampUtc", row.StampUtc, want.StampUtc);
            Check("Day", row.Day, want.Day);
            Check("Clock", row.Clock, want.Clock);
            Check("Key", row.Key, want.Key);
            Check("MaybeKey", row.MaybeKey, want.MaybeKey);
            Check("U32", row.U32, want.U32);
            Check("U64", row.U64, want.U64);
            Check("U8", row.U8, want.U8);
            Check("U16", row.U16, want.U16);
            Check("Doc", row.Doc, want.Doc);
            i++;
        }
        if (i != e.Rows)
            throw new Finding($"{where}: {i} rows, expected {e.Rows}");
    }

    /// <summary>Partitioned dataset of ScaleTypes rows (few open files so partitions are reopened and appended).</summary>
    public static Dictionary<string, byte[]> Dataset(LType[] c, long rows, ParquetWriterOptions options, Rng rng, out Func<long, string> partitionOf)
    {
        var partitions = rng.Pick(1, 2, 7, 64);
        var open = Math.Max(1, Math.Min(partitions, rng.Pick(1, 2, 8)));
        var salt = rng.Next();
        var names = Enumerable.Range(0, partitions).Select(p => Encoding.UTF8.GetBytes($"p={p:D2}/t.parquet")).ToArray();
        partitionOf = id => $"p={(int)(Rng.Mix((ulong)id ^ salt) % (ulong)partitions):D2}/t.parquet";
        var files = new MemFiles();
        var sources = Enumerable.Range(0, open).Select(_ => new MemFiles.Source(files)).ToArray();
        var datasetOptions = new Plank.Dataset.DatasetWriterOptions
        {
            WriterOptions = options,
            PendingRowCapacity = rng.Pick(1u, 100u, 4096u, 65536u),
            AppendOptions = new ParquetAppendOptions { AppendToLatestRowGroup = rng.Chance(40), WriterOptions = options },
        };
        var sessions = rng.Pick(1, 2);
        long r = 0;
        for (var session = 0; session < sessions; session++)
        {
            var end = session == sessions - 1 ? rows : Math.Min(rows, r + rows / sessions);
            using var writer = ScaleTypes.CreateDatasetWriter(
                (ScaleTypes row, Plank.IParquetBufferPool pool, out Plank.ParquetBuffer? allocation) =>
                {
                    allocation = null;
                    return names[(int)(Rng.Mix((ulong)row.Id ^ salt) % (ulong)partitions)];
                }, sources, datasetOptions);
            for (; r < end; r++)
                writer.Queue(Make(c, r));
        }
        foreach (var source in sources)
            source.Dispose();
        return files.Files.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray());
    }

    static string Show<T>(T v) => v is DateTime d ? $"{d:O} {d.Kind}" : $"{v}";

    /// <summary>Arrow's logical readers (decimal, DateTime, Date, TimeSpan, Guid, unsigned ints, string) against the semantic values.</summary>
    public static void CheckArrowLogical(string path, LType[] c, Expected e)
    {
        using var file = new Ps.ParquetFileReader(path);
        long start = 0;
        for (var g = 0; g < file.FileMetaData.NumRowGroups; g++)
        {
            using var group = file.RowGroup(g);
            var n = group.MetaData.NumRows;
            Col<decimal>(group, 1, n, start, e, "Dec9", r => c[0].Decimal(r)!.Value);
            Col<decimal?>(group, 2, n, start, e, "Dec18", r => c[1].Spec.IsNull(r) ? null : c[1].Decimal(r));
            Col<decimal>(group, 3, n, start, e, "Dec28", r => c[2].Decimal(r)!.Value);
            Col<DateTime>(group, 4, n, start, e, "Stamp", r => Stamp(c[3], r), (a, b) => a.Ticks == b.Ticks);
            Col<DateTime?>(group, 5, n, start, e, "StampUtc", r => c[4].Spec.IsNull(r) ? null : Stamp(c[4], r), (a, b) => a?.Ticks == b?.Ticks);
            Col<Ps.Date>(group, 6, n, start, e, "Day", r => new Ps.Date(c[5].Spec.Int32(r)), (a, b) => a.Days == b.Days);
            Col<TimeSpan?>(group, 7, n, start, e, "Clock", r => c[6].Spec.IsNull(r) ? null : c[6].Time(r)!.Value.ToTimeSpan());
            Col<Guid>(group, 8, n, start, e, "Key", r => c[7].Uuid(r));
            Col<Guid?>(group, 9, n, start, e, "MaybeKey", r => c[8].Spec.IsNull(r) ? null : c[8].Uuid(r));
            Col<uint>(group, 10, n, start, e, "U32", r => (uint)c[9].Spec.Int32(r));
            Col<ulong?>(group, 11, n, start, e, "U64", r => c[10].Spec.IsNull(r) ? null : (ulong)c[10].Spec.Int64(r));
            Col<byte>(group, 12, n, start, e, "U8", r => (byte)c[11].Spec.Int32(r));
            Col<ushort?>(group, 13, n, start, e, "U16", r => c[12].Spec.IsNull(r) ? null : (ushort)c[12].Spec.Int32(r));
            Col<string?>(group, 14, n, start, e, "Doc", r => c[13].Spec.IsNull(r) ? null : Encoding.ASCII.GetString(c[13].Spec.Bytes(r)));
            start += n;
        }
    }

    static void Col<T>(Ps.RowGroupReader group, int column, long n, long start, Expected e, string name, Func<long, T> want,
        Func<T, T, bool>? same = null)
    {
        using var reader = group.Column(column).LogicalReader<T>();
        var values = reader.ReadAll(checked((int)n));
        for (var i = 0; i < values.Length; i++)
        {
            var w = want(e.Row(start + i));
            if (!(same?.Invoke(values[i], w) ?? EqualityComparer<T>.Default.Equals(values[i], w)))
                throw new Finding($"arrow logical {name} row {start + i}: arrow {values[i]}, expected {w}");
        }
    }
}
