using Plank.Reading;
using Plank.Writing;

namespace Plank.Fuzzing.Scale;

/// <summary>
/// More than int.MaxValue rows in one file (several row groups of up to 2^27 rows): every row counter that is an
/// int instead of a long overflows here. Columns are Flag (bool pattern), Small (sawtooth with a small period) and
/// Missing (optional int, almost all null), so the file stays a few MB.
/// </summary>
public static class ManyRows
{
    public static void Run(Rng rng, int tier, List<string> describe)
    {
        var total = rng.Pick((1L << 31) + 7, (1L << 31) + (1L << 27), (1L << 32) + 3);
        var perGroup = rng.Pick(1L << 26, 1L << 27, (1L << 27) - 1);
        var period = rng.Pick(1, 2, 7, 255, 4096);
        var flagRun = rng.Pick(1L, 3L, 1L << 20, 1L << 31);
        var presentEvery = rng.Pick(0L, 1L << 20, (1L << 31) + 1);
        bool Flag(long r) => (r / flagRun) % 2 == 1;
        int Small(long r) => (int)(r % period);
        int? Missing(long r) => presentEvery != 0 && r % presentEvery == 0 ? (int)(r >> 20) : null;
        var options = new ParquetWriterOptions
        {
            TargetDataPageSizeBytes = rng.Pick(1u << 20, 64u << 20),
            WritePageIndexes = rng.Chance(50),
            DataPageVersion = rng.Chance(50) ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2,
            Compression = rng.Pick(Plank.Schema.CompressionKind.None, Plank.Schema.CompressionKind.Snappy, Plank.Schema.CompressionKind.Zstd),
        };
        describe.Add($"manyrows total={total} perGroup={perGroup} period={period} flagRun={flagRun} presentEvery={presentEvery} page={options.TargetDataPageSizeBytes} v{(int)options.DataPageVersion} {options.Compression}");
        Console.WriteLine("  " + describe[0]);
        var path = Path.Combine(Environment.GetEnvironmentVariable("SCALE_TMP") ?? Path.GetTempPath(), $"scale-{Environment.ProcessId}-many.parquet");
        try
        {
            var schema = ScaleMany.Schema;
            using (var output = File.Create(path))
            using (var writer = schema.CreateWriter(output, options))
            {
                var flag = writer.CreateSerializedColumn<bool>(schema.LeafColumns[0]);
                var small = writer.CreateSerializedColumn<int>(schema.LeafColumns[1]);
                var missing = writer.CreateSerializedColumn<int?>(schema.LeafColumns[2]);
                var fb = new bool[perGroup]; var sb = new int[perGroup]; var mb = new int?[perGroup];
                for (long start = 0; start < total; start += perGroup)
                {
                    var n = (int)Math.Min(perGroup, total - start);
                    for (var i = 0; i < n; i++) { var r = start + i; fb[i] = Flag(r); sb[i] = Small(r); mb[i] = Missing(r); }
                    var rg = writer.StartRowGroup();
                    flag.Serialize(fb.AsSpan(0, n)); rg.Write(flag);
                    small.Serialize(sb.AsSpan(0, n)); rg.Write(small);
                    missing.Serialize(mb.AsSpan(0, n)); rg.Write(missing);
                }
                writer.CloseFile();
            }
            describe.Add($"file={new FileInfo(path).Length}");
            Console.WriteLine("  " + describe[^1]);

            // Logical reader.
            using (var source = new FileReadSource(path))
            using (var reader = ScaleMany.CreateReader(source))
            {
                long r0 = 0;
                foreach (var g in reader.RowGroups)
                {
                    long i = 0;
                    foreach (var b in g.FlagColumn) foreach (var v in b.Values) { if (v != Flag(r0 + i)) throw new Finding($"logical Flag row {r0 + i}"); i++; }
                    if (i != (long)g.RowCount) throw new Finding($"logical rg{g.Index}: {i} Flag values for {g.RowCount} rows");
                    i = 0;
                    foreach (var b in g.SmallColumn) foreach (var v in b.Values) { if (v != Small(r0 + i)) throw new Finding($"logical Small row {r0 + i}: {v}"); i++; }
                    i = 0;
                    foreach (var b in g.MissingColumn) foreach (var v in b.Values) { if (v != Missing(r0 + i)) throw new Finding($"logical Missing row {r0 + i}: {v}"); i++; }
                    if (i != (long)g.RowCount) throw new Finding($"logical rg{g.Index}: {i} Missing values");
                    r0 += (long)g.RowCount;
                }
                if (r0 != total) throw new Finding($"logical: {r0} rows, expected {total}");
                if (reader.Metadata is var m && reader.RowGroups.Count != (int)((total + perGroup - 1) / perGroup))
                    throw new Finding($"row group count {reader.RowGroups.Count}");
            }
            Console.WriteLine("  logical ok");

            // Row reader, multi-worker, over a file source.
            var options2 = RowRead.DrawOptions(rng);
            using (var source = new FileReadSource(path))
            using (var rows = ScaleMany.CreateRowReader(source, default, options2))
            {
                long r = 0;
                while (rows.MoveNext())
                {
                    var row = rows.Current;
                    if (row.Flag != Flag(r) || row.Small != Small(r) || row.Missing != Missing(r))
                        throw new Finding($"row reader (workers={options2.Execution.WorkerCount}) row {r}: {row.Flag}/{row.Small}/{row.Missing}");
                    r++;
                }
                if (r != total) throw new Finding($"row reader: {r} rows, expected {total}");
            }
            Console.WriteLine("  row reader ok");

            // Arrow.
            using (var file = new ParquetSharp.ParquetFileReader(path))
            {
                if (file.FileMetaData.NumRows != total) throw new Finding($"arrow num_rows {file.FileMetaData.NumRows}");
                long r0 = 0;
                for (var g = 0; g < file.FileMetaData.NumRowGroups; g++)
                {
                    using var group = file.RowGroup(g);
                    var n = group.MetaData.NumRows;
                    using (var c = (ParquetSharp.ColumnReader<int>)group.Column(1))
                    {
                        var buf = new int[65536]; long i = 0;
                        while (c.HasNext)
                        {
                            var k = c.ReadBatch(buf.Length, buf, out _);
                            for (var j = 0; j < k; j++, i++) if (buf[j] != Small(r0 + i)) throw new Finding($"arrow Small row {r0 + i}");
                        }
                        if (i != n) throw new Finding($"arrow rg{g}: {i} values for {n} rows");
                    }
                    r0 += n;
                }
                if (r0 != total) throw new Finding($"arrow: {r0} rows");
            }
            Console.WriteLine("  arrow ok");
        }
        finally { File.Delete(path); }
    }
}
