using System.Text;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Writing;
using Ps = ParquetSharp;

namespace Plank.Fuzzing.Scale;

/// <summary>
/// Lists at scale (ScaleNested: optional list&lt;int&gt;, optional list&lt;string&gt;): rows with empty/null lists and,
/// rarely, lists of up to hundreds of thousands of elements, so a single row spans pages, decode batches and
/// row-API slot growth.
/// </summary>
public sealed class ListSpec
{
    public ulong Seed;
    public int NullPerMille, EmptyPerMille;
    public int SmallMax;          // typical length in [0, SmallMax]
    public int HugeEvery;         // every N-th row (by hash) is huge; 0 = never
    public int HugeLength;
    public long Cardinality;
    public int StringMax;

    public static ListSpec Draw(Rng rng, long rows) => new()
    {
        Seed = rng.Next(),
        NullPerMille = rng.Pick(0, 0, 10, 500, 1000),
        EmptyPerMille = rng.Pick(0, 10, 300),
        SmallMax = rng.Pick(0, 1, 3, 8, 64),
        HugeEvery = rng.Pick(0, 0, 1000, 50_000),
        HugeLength = rng.Pick(1025, 2049, 65537, 300_000),
        Cardinality = rng.Pick(ColSpec.Cardinalities),
        StringMax = rng.Pick(0, 4, 40, 300),
    };

    ulong H(long r, ulong salt) => Rng.Mix(Seed ^ salt ^ (ulong)r * 0x9E3779B97F4A7C15UL);

    /// <summary>-1 = null list.</summary>
    public int Length(long r)
    {
        var h = H(r, 1);
        if ((int)(h % 1000) < NullPerMille) return -1;
        if ((int)((h >> 10) % 1000) < EmptyPerMille) return 0;
        if (HugeEvery > 0 && (h >> 20) % (ulong)HugeEvery == 0) return HugeLength;
        return (int)((h >> 40) % (ulong)(SmallMax + 1));
    }

    public int Int(long r, int j) => (int)(H(r * 1_000_003 + j, 2) % (ulong)Math.Max(1, Cardinality));

    public string Str(long r, int j)
    {
        var h = H(r * 1_000_003 + j, 3);
        var len = StringMax == 0 ? 0 : (int)(h % (ulong)(StringMax + 1));
        var key = (long)(h >> 8) % Math.Max(1, Cardinality);
        var sb = new StringBuilder(len);
        var x = (ulong)key ^ Seed;
        for (var i = 0; i < len; i++)
        {
            if ((i & 7) == 0) x = Rng.Mix(x);
            sb.Append((char)('a' + (byte)(x >> ((i & 7) * 8)) % 26));
        }
        return sb.ToString();
    }

    public override string ToString() => $"list null={NullPerMille}‰ empty={EmptyPerMille}‰ small={SmallMax} huge={HugeLength}/every {HugeEvery} card={Cardinality} str={StringMax}";
}

public static class NestedMode
{
    public static void Run(Rng rng, int tier, List<string> describe)
    {
        var rows = tier switch { 0 => rng.Pick(1L, 1025L, 5000L, 20_000L), 1 => rng.Pick(100_000L, 300_000L), _ => 2_000_000L };
        var values = ListSpec.Draw(rng, rows);
        var tags = ListSpec.Draw(rng, rows);
        // Keep the total element count affordable.
        foreach (var s in new[] { values, tags })
            if (s.HugeEvery > 0 && rows / Math.Max(1, s.HugeEvery) * (long)s.HugeLength > 20_000_000)
                s.HugeEvery = 0;
        var options = Writers.DrawOptions(rng, rows, tier, rowApi: true, 3);
        describe.Add($"nested rows={rows} page={options.TargetDataPageSizeBytes} rg={options.TargetRowGroupSizeBytes} cap={options.RowApiInitialRowCapacity} par={options.RowApiMaxParallelism} v{(int)options.DataPageVersion}");
        describe.Add("Values " + values);
        describe.Add("Tags " + tags);
        var output = new MemoryStream();
        using (var writer = ScaleNested.CreateRowWriter(output, options))
        {
            for (long r = 0; r < rows; r++)
            {
                var row = writer.GetRow();
                row.Id = r;
                row.Values = MakeInts(values, r);
                row.Tags = MakeStrings(tags, r);
            }
            writer.Complete();
        }
        var bytes = output.ToArray();
        CheckLogical(new MemoryReadSource(bytes), rows, values, tags);
        CheckRows(new MemoryReadSource(bytes), rows, values, tags, RowRead.DrawOptions(rng));
        CheckRows(new JitterSource(bytes), rows, values, tags, RowRead.DrawOptions(rng));
        var path = Path.Combine(Environment.GetEnvironmentVariable("SCALE_TMP") ?? Path.GetTempPath(), $"scale-{Environment.ProcessId}-nested.parquet");
        try
        {
            File.WriteAllBytes(path, bytes);
            CheckArrow(path, rows, values, tags);
        }
        finally { File.Delete(path); }
    }

    static List<int>? MakeInts(ListSpec s, long r)
    {
        var n = s.Length(r);
        if (n < 0) return null;
        var list = new List<int>(n);
        for (var j = 0; j < n; j++) list.Add(s.Int(r, j));
        return list;
    }

    static List<string>? MakeStrings(ListSpec s, long r)
    {
        var n = s.Length(r);
        if (n < 0) return null;
        var list = new List<string>(n);
        for (var j = 0; j < n; j++) list.Add(s.Str(r, j));
        return list;
    }

    /// <summary>Streams (def, rep, value) entries of a 3-level optional list with required elements and checks rows.</summary>
    sealed class Assembler(ListSpec spec, bool strings, long totalRows, string where)
    {
        long _row = -1;
        int _expected, _seen;
        public long Entries;

        public void Entry(int def, int rep, int intValue, ReadOnlySpan<byte> bytesValue)
        {
            Entries++;
            if (rep == 0)
            {
                Finish();
                _row++;
                if (_row >= totalRows)
                    throw new Finding($"{where}: more rows than {totalRows}");
                _expected = spec.Length(_row);
                _seen = 0;
                if (def == 0) { if (_expected != -1) throw new Finding($"{where}: row {_row} read null, expected length {_expected}"); _seen = -1; return; }
                if (def == 1) { if (_expected != 0) throw new Finding($"{where}: row {_row} read empty, expected length {_expected}"); return; }
            }
            else if (rep != 1 || _row < 0)
                throw new Finding($"{where}: row {_row}: repetition level {rep}");
            if (def != 2)
                throw new Finding($"{where}: row {_row} element {_seen}: definition level {def} for a required element");
            if (_seen >= _expected)
                throw new Finding($"{where}: row {_row}: more than {_expected} elements");
            if (strings)
            {
                var want = Encoding.UTF8.GetBytes(spec.Str(_row, _seen));
                if (!bytesValue.SequenceEqual(want))
                    throw new Finding($"{where}: row {_row} element {_seen}: string differs");
            }
            else if (intValue != spec.Int(_row, _seen))
                throw new Finding($"{where}: row {_row} element {_seen}: read {intValue}, expected {spec.Int(_row, _seen)}");
            _seen++;
        }

        void Finish()
        {
            if (_row >= 0 && _seen != _expected && !(_seen == -1 && _expected == -1))
                throw new Finding($"{where}: row {_row}: {_seen} elements, expected {_expected}");
        }

        public long Rows() { Finish(); return _row + 1; }
    }

    static void CheckLogical(IParquetReadSource source, long rows, ListSpec values, ListSpec tags)
    {
        using var reader = new ParquetReader();
        reader.Reset(source);
        var leaves = reader.Schema.LeafColumns;
        var a = new Assembler(values, false, rows, "logical Values");
        var b = new Assembler(tags, true, rows, "logical Tags");
        long idRows = 0;
        foreach (RowGroup group in reader.RowGroups)
        {
            foreach (var buf in group.Column<long>(leaves[0]))
                foreach (var id in buf.Values)
                    if (id != idRows++) throw new Finding($"logical Id {id} at {idRows - 1}");
            foreach (var nb in group.NestedColumn<int>(leaves[1]))
            {
                var defs = nb.DefinitionLevels; var reps = nb.RepetitionLevels; var vals = nb.Values.Values;
                var v = 0;
                for (var i = 0; i < defs.Length; i++)
                {
                    a.Entry(defs[i], reps[i], defs[i] == 2 ? vals[v] : 0, default);
                    if (defs[i] == 2) v++;
                }
                if (v != vals.Length) throw new Finding($"logical Values: {v} present entries, {vals.Length} values in the buffer");
            }
            foreach (var nb in group.NestedColumn<byte>(leaves[2]))
            {
                var defs = nb.DefinitionLevels; var reps = nb.RepetitionLevels; var vals = nb.Values;
                var v = 0;
                for (var i = 0; i < defs.Length; i++)
                {
                    b.Entry(defs[i], reps[i], 0, defs[i] == 2 ? vals.GetValue(v) : default);
                    if (defs[i] == 2) v++;
                }
                if (v != vals.Count) throw new Finding($"logical Tags: {v} present entries, {vals.Count} values in the buffer");
            }
        }
        if (a.Rows() != rows || b.Rows() != rows || idRows != rows)
            throw new Finding($"logical nested: rows {a.Rows()}/{b.Rows()}/{idRows}, expected {rows}");
    }

    static void CheckRows(IParquetReadSource source, long rows, ListSpec values, ListSpec tags, Plank.RowApi.RowReaderOptions options)
    {
        using var reader = ScaleNested.CreateRowReader(source, default, options);
        long r = 0;
        while (reader.MoveNext())
        {
            var row = reader.Current;
            if (row.Id != r) throw new Finding($"row reader nested: row {r} Id {row.Id} (workers={options.Execution.WorkerCount})");
            var v = row.Values;
            var n = values.Length(r);
            if ((v is null) != (n < 0) || (v is not null && v.Count != n))
                throw new Finding($"row reader nested: row {r} Values count {v?.Count.ToString() ?? "null"}, expected {n} (workers={options.Execution.WorkerCount})");
            for (var j = 0; v is not null && j < v.Count; j++)
                if (v[j] != values.Int(r, j)) throw new Finding($"row reader nested: row {r} Values[{j}] {v[j]}");
            var t = row.Tags;
            n = tags.Length(r);
            if ((t is null) != (n < 0) || (t is not null && t.Count != n))
                throw new Finding($"row reader nested: row {r} Tags count {t?.Count.ToString() ?? "null"}, expected {n}");
            for (var j = 0; t is not null && j < t.Count; j++)
                if (t[j] != tags.Str(r, j)) throw new Finding($"row reader nested: row {r} Tags[{j}] differs");
            r++;
        }
        if (r != rows) throw new Finding($"row reader nested: {r} rows, expected {rows}");
    }

    static unsafe void CheckArrow(string path, long rows, ListSpec values, ListSpec tags)
    {
        using var file = new Ps.ParquetFileReader(path);
        var a = new Assembler(values, false, rows, "arrow Values");
        var b = new Assembler(tags, true, rows, "arrow Tags");
        for (var g = 0; g < file.FileMetaData.NumRowGroups; g++)
        {
            using var group = file.RowGroup(g);
            using (var col = (Ps.ColumnReader<int>)group.Column(1))
            {
                var buf = new int[4096]; var defs = new short[4096]; var reps = new short[4096];
                while (col.HasNext)
                {
                    var levels = col.ReadBatch(buf.Length, defs, reps, buf, out var read);
                    var v = 0;
                    for (var i = 0; i < levels; i++)
                    {
                        a.Entry(defs[i], reps[i], defs[i] == 2 ? buf[v] : 0, default);
                        if (defs[i] == 2) v++;
                    }
                }
            }
            using (var col = (Ps.ColumnReader<Ps.ByteArray>)group.Column(2))
            {
                var buf = new Ps.ByteArray[4096]; var defs = new short[4096]; var reps = new short[4096];
                while (col.HasNext)
                {
                    var levels = col.ReadBatch(buf.Length, defs, reps, buf, out var read);
                    var v = 0;
                    for (var i = 0; i < levels; i++)
                    {
                        b.Entry(defs[i], reps[i], 0, defs[i] == 2 ? new ReadOnlySpan<byte>((void*)buf[v].Pointer, buf[v].Length) : default);
                        if (defs[i] == 2) v++;
                    }
                }
            }
        }
        if (a.Rows() != rows || b.Rows() != rows)
            throw new Finding($"arrow nested: rows {a.Rows()}/{b.Rows()}, expected {rows}");
    }
}
