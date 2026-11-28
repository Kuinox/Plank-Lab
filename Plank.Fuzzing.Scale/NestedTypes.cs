using Plank.Reading;
using Plank.Writing;
using Ps = ParquetSharp;

namespace Plank.Fuzzing.Scale;

/// <summary>
/// Repeated logical types (List&lt;DateTime | Guid | DateOnly | uint | TimeOnly&gt;) at scale through the generated row
/// writer; checked with the generated row reader (workers, jitter) and Arrow's logical array readers.
/// </summary>
public static class NestedTypes
{
    static readonly long MinMicros = (DateTime.MinValue.Ticks - DateTime.UnixEpoch.Ticks) / 10;
    static readonly long MaxMicros = (DateTime.MaxValue.Ticks - DateTime.UnixEpoch.Ticks) / 10;

    static ulong V(ListSpec s, long r, int j) => Rng.Mix((ulong)s.Int(r, j) ^ s.Seed);

    public static DateTime Stamp(ListSpec s, long r, int j)
        => new(DateTime.UnixEpoch.Ticks + 10 * (MinMicros + (long)(V(s, r, j) % (ulong)(MaxMicros - MinMicros + 1))), DateTimeKind.Utc);

    public static Guid Key(ListSpec s, long r, int j)
    {
        Span<byte> b = stackalloc byte[16];
        BitConverter.TryWriteBytes(b, V(s, r, j));
        BitConverter.TryWriteBytes(b[8..], Rng.Mix(V(s, r, j)));
        return new Guid(b);
    }

    public static DateOnly Day(ListSpec s, long r, int j) => DateOnly.FromDayNumber((int)(V(s, r, j) % 3_652_059));
    public static uint Count(ListSpec s, long r, int j) => (uint)V(s, r, j);
    public static TimeOnly Clock(ListSpec s, long r, int j) => new((long)(V(s, r, j) % 86_400_000_000UL) * 10);

    static List<T>? L<T>(ListSpec s, long r, Func<ListSpec, long, int, T> f)
    {
        var n = s.Length(r);
        if (n < 0) return null;
        var list = new List<T>(n);
        for (var j = 0; j < n; j++) list.Add(f(s, r, j));
        return list;
    }

    public static void Run(Rng rng, int tier, List<string> describe)
    {
        var rows = tier switch { 0 => rng.Pick(1L, 1025L, 5000L, 20_000L), _ => rng.Pick(100_000L, 300_000L) };
        var specs = Enumerable.Range(0, 5).Select(_ => ListSpec.Draw(rng, rows)).ToArray();
        foreach (var s in specs)
            if (s.HugeEvery > 0 && rows / Math.Max(1, s.HugeEvery) * (long)s.HugeLength > 10_000_000)
                s.HugeEvery = 0;
        var options = Writers.DrawOptions(rng, rows, tier, rowApi: true, 6);
        describe.Add($"nestedtypes rows={rows} page={options.TargetDataPageSizeBytes} rg={options.TargetRowGroupSizeBytes} cap={options.RowApiInitialRowCapacity} par={options.RowApiMaxParallelism}");
        describe.AddRange(specs.Select(s => s.ToString()));
        var path = Path.Combine(Environment.GetEnvironmentVariable("SCALE_TMP") ?? Path.GetTempPath(), $"scale-{Environment.ProcessId}-nt.parquet");
        try
        {
            using (var output = File.Create(path))
            using (var writer = ScaleTypesNested.CreateRowWriter(output, options))
            {
                for (long r = 0; r < rows; r++)
                {
                    var row = writer.GetRow();
                    row.Id = r;
                    row.Stamps = L(specs[0], r, Stamp);
                    row.Keys = L(specs[1], r, Key);
                    row.Days = L(specs[2], r, Day);
                    row.Counts = L(specs[3], r, Count);
                    row.Clocks = L(specs[4], r, Clock);
                }
                writer.Complete();
            }
            var bytes = File.ReadAllBytes(path);
            foreach (var source in new IParquetReadSource[] { new MemoryReadSource(bytes), new JitterSource(bytes) })
            {
                var options2 = RowRead.DrawOptions(rng);
                using var reader = ScaleTypesNested.CreateRowReader(source, default, options2);
                long r = 0;
                while (reader.MoveNext())
                {
                    var row = reader.Current;
                    if (row.Id != r) throw new Finding($"nestedtypes row reader: row {r} Id {row.Id}");
                    Same("Stamps", r, row.Stamps, L(specs[0], r, Stamp), options2);
                    Same("Keys", r, row.Keys, L(specs[1], r, Key), options2);
                    Same("Days", r, row.Days, L(specs[2], r, Day), options2);
                    Same("Counts", r, row.Counts, L(specs[3], r, Count), options2);
                    Same("Clocks", r, row.Clocks, L(specs[4], r, Clock), options2);
                    r++;
                }
                if (r != rows) throw new Finding($"nestedtypes row reader: {r} rows, expected {rows}");
            }
            // Arrow logical arrays.
            using var file = new Ps.ParquetFileReader(path);
            long start = 0;
            for (var g = 0; g < file.FileMetaData.NumRowGroups; g++)
            {
                using var group = file.RowGroup(g);
                var n = (int)group.MetaData.NumRows;
                Arrow<DateTime>(group, 1, n, start, "Stamps", r => L(specs[0], r, Stamp), (a, b) => a.Ticks == b.Ticks);
                Arrow<Guid>(group, 2, n, start, "Keys", r => L(specs[1], r, Key), (a, b) => a == b);
                Arrow<Ps.Date>(group, 3, n, start, "Days", r => L(specs[2], r, (s, rr, j) => new Ps.Date(Day(s, rr, j).DayNumber - 719162)), (a, b) => a.Days == b.Days);
                Arrow<uint>(group, 4, n, start, "Counts", r => L(specs[3], r, Count), (a, b) => a == b);
                Arrow<TimeSpan>(group, 5, n, start, "Clocks", r => L(specs[4], r, (s, rr, j) => Clock(s, rr, j).ToTimeSpan()), (a, b) => a == b);
                start += n;
            }
            if (start != rows) throw new Finding($"nestedtypes arrow: {start} rows");
        }
        finally { File.Delete(path); }
    }

    static void Same<T>(string name, long r, List<T>? got, List<T>? want, Plank.RowApi.RowReaderOptions o)
    {
        if ((got is null) != (want is null) || (got is not null && !got.SequenceEqual(want!)))
            throw new Finding($"nestedtypes row reader (workers={o.Execution.WorkerCount}) row {r} {name}: {got?.Count.ToString() ?? "null"} elements" +
                              $"{(got is not null && want is not null && got.Count == want.Count ? $", first difference at {got.Zip(want).TakeWhile(p => EqualityComparer<T>.Default.Equals(p.First, p.Second)).Count()}" : "")}, expected {want?.Count.ToString() ?? "null"}");
    }

    static void Arrow<T>(Ps.RowGroupReader group, int column, int n, long start, string name, Func<long, List<T>?> want, Func<T, T, bool> same)
    {
        using var reader = group.Column(column).LogicalReader<T[]?>();
        var values = reader.ReadAll(n);
        for (var i = 0; i < n; i++)
        {
            var w = want(start + i);
            var got = values[i];
            if ((got is null) != (w is null) || (got is not null && (got.Length != w!.Count || !got.Zip(w).All(p => same(p.First, p.Second)))))
                throw new Finding($"nestedtypes arrow {name} row {start + i}: arrow {got?.Length.ToString() ?? "null"} elements, expected {w?.Count.ToString() ?? "null"}");
        }
    }
}
