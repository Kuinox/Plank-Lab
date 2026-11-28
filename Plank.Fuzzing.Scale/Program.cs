using System.Diagnostics;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Writing;

namespace Plank.Fuzzing.Scale;

/// <summary>
/// Scale and concurrency driver (not an AFL target). Usage:
///   Plank.Fuzzing.Scale run &lt;mode&gt; &lt;seed&gt; [tier]        one case; exit 1 on a finding
///   Plank.Fuzzing.Scale campaign &lt;mode&gt; &lt;seed0&gt; &lt;count&gt; [tier] [log]   many cases; logs findings, continues
/// Modes: columnar, row, rollover, dataset, concurrency, big. Tiers: 0 small, 1 medium, 2 large (millions of rows),
/// 3 huge (files over 2 / 4 GB, mode big). A case is a pure function of (mode, seed, tier): rerun it to reproduce.
/// SCALE_TMP sets the scratch directory for files (default /tmp); files are deleted after each case.
/// </summary>
static class Program
{
    static readonly System.Reflection.PropertyInfo s_nativeCount = typeof(DefaultParquetBufferPool).GetProperty("NativeAllocationCount", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;

    static readonly bool Verbose = Environment.GetEnvironmentVariable("SCALE_VERBOSE") == "1";

    static string Tmp => Environment.GetEnvironmentVariable("SCALE_TMP") ?? Path.GetTempPath();

    static int Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "repro")
            return Repros.Run(args[1], args[2]);
        if (args.Length == 2 && args[0] == "inspect")
            return Inspect.Run(args[1]);
        if (args.Length < 3)
        {
            Console.Error.WriteLine("usage: run|campaign <mode> <seed> [count] [tier] [log]");
            return 2;
        }
        var mode = args[1];
        var seed = ulong.Parse(args[2]);
        if (args[0] == "run")
        {
            var tier = args.Length > 3 ? int.Parse(args[3]) : 0;
            return RunOne(mode, seed, tier, out _) ? 0 : 1;
        }
        var count = int.Parse(args[3]);
        var t = args.Length > 4 ? int.Parse(args[4]) : 0;
        var log = args.Length > 5 ? args[5] : null;
        var findings = 0;
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < count; i++)
        {
            if (!RunOne(mode, seed + (ulong)i, t, out var message))
            {
                findings++;
                if (log is not null)
                    File.AppendAllText(log, $"{DateTime.UtcNow:O} run {mode} {seed + (ulong)i} {t}: {message}\n");
            }
        }
        Console.WriteLine($"campaign {mode} tier {t} seeds {seed}..{seed + (ulong)count - 1}: {findings} findings in {sw.Elapsed}; " +
                          $"values={Verify.Values} arrow={Verify.ArrowValues} rows={RowRead.Rows} chunks={Verify.Chunks} pages={Verify.Pages} " +
                          $"selftestCaught={s_selfTestCaught} arrowSkipped={Verify.ArrowSkipped} arrowHugeHeader={Verify.ArrowSkippedHugeHeader} stats={Verify.StatsChecked} statsMissing={Verify.StatsMissing} bloom={Verify.BloomProbes} pruned={Verify.PrunedPages}");
        return findings == 0 ? 0 : 1;
    }

    static bool RunOne(string mode, ulong seed, int tier, out string message)
    {
        var sw = Stopwatch.StartNew();
        var rng = new Rng(seed * 0x2545F4914F6CDD1DUL + (ulong)tier);
        var describe = new List<string>();
        try
        {
            switch (mode)
            {
                case "columnar": Columnar(rng, tier, describe); break;
                case "row": Row(rng, tier, describe, rollover: false); break;
                case "rollover": Row(rng, tier, describe, rollover: true); break;
                case "dataset": Dataset(rng, tier, describe); break;
                case "concurrency": Concurrency(rng, tier, describe); break;
                case "big": Big(rng, tier, describe); break;
                case "nested": NestedMode.Run(rng, tier, describe); break;
                case "append": Append(rng, tier, describe); break;
                case "arrow": ArrowFiles(rng, tier, describe); break;
                case "merge": Merge(rng, tier, describe); break;
                default: throw new ArgumentException("unknown mode " + mode);
            }
            message = "";
            Console.WriteLine($"OK {mode} {seed} t{tier} {sw.Elapsed.TotalSeconds:F1}s {string.Join(" | ", describe.Take(1))}");
            return true;
        }
        catch (Exception ex)
        {
            message = $"{ex.GetType().Name}: {ex.Message.ReplaceLineEndings(" ")} :: {string.Join(" | ", describe)}";
            Console.WriteLine($"FINDING {mode} {seed} t{tier}: {message}");
            Console.WriteLine(ex.ToString());
            return false;
        }
        finally
        {
            Jitter.Percent = 0;
        }
    }

    /// <summary>SCALE_KEEP=dir: keep each case's file (for triage) before it is deleted.</summary>
    static void Keep(string path)
    {
        if (Environment.GetEnvironmentVariable("SCALE_KEEP") is { } dir && File.Exists(path))
        {
            Directory.CreateDirectory(dir);
            File.Copy(path, Path.Combine(dir, Path.GetFileName(path)), overwrite: true);
        }
    }

    static string TempFile(string tag) => Path.Combine(Tmp, $"scale-{Environment.ProcessId}-{tag}.parquet");

    static ColSpec[] DrawColumns(Rng rng, int count, long rows, bool allowHuge)
    {
        var cols = new ColSpec[count];
        ColSpec.BudgetBytes = Math.Min(96L << 20, ColSpec.FileBudgetBytes / Math.Max(1, count));
        for (var c = 0; c < count; c++)
        {
            var kind = (Kind)rng.Int(8);
            cols[c] = ColSpec.Draw(rng, $"c{c}", kind, rng.Chance(50), rows, allowHuge);
        }
        return cols;
    }

    // Read the file back through every path. Big files skip MemoryReadSource.
    static readonly bool SelfTest = Environment.GetEnvironmentVariable("SCALE_SELFTEST") == "1";

    /// <summary>
    /// SCALE_SELFTEST=1: plant a one-row mismatch in the expectation and require every value reader to report it,
    /// so a silent comparison gap shows up as "SELFTEST MISSED".
    /// </summary>
    static void PlantedMismatch(string path, Expected e, Rng rng, bool scaleRow)
    {
        if (e.Rows < 2)
            return;
        var skew = rng.Long(e.Rows - 1);
        var differing = Enumerable.Range(0, e.Cols.Length).Where(c => Verify.Fp(e.Cols[c], e.Row(skew)) != Verify.Fp(e.Cols[c], e.Row(skew) + 1)).ToArray();
        if (differing.Length == 0)
            return;
        var bad = new Expected { Cols = e.Cols, Rows = e.Rows, RowGroupSizes = e.RowGroupSizes, RowMap = e.RowMap, Skew = skew };
        var bytes = File.ReadAllBytes(path);
        var readers = new List<(string, Action)>
        {
            ("logical", () => Verify.PlankLogical(new MemoryReadSource(bytes), bad, null, checkMetadata: false)),
            ("arrow", () => Verify.Arrow(path, bad)),
        };
        if (scaleRow)
        {
            var all = Enumerable.Repeat(true, 8).ToArray();
            readers.Add(("rowreader", () => RowRead.ScaleRows(new MemoryReadSource(bytes), bad, ScaleRow.Projection.All, all, RowRead.DrawOptions(rng), "selftest")));
        }
        foreach (var (name, read) in readers)
        {
            try { read(); Console.WriteLine($"SELFTEST MISSED {name}: row {skew} (columns {string.Join(",", differing)})"); }
            catch (Finding) { Interlocked.Increment(ref s_selfTestCaught); }
        }
    }

    static long s_selfTestCaught;

    static void VerifyAll(string path, Expected e, Rng rng, List<string> describe, bool scaleRow)
    {
        if (SelfTest)
            PlantedMismatch(path, e, new Rng(rng.Next()), scaleRow);
        var length = new FileInfo(path).Length;
        using (var fileSource = new FileReadSource(path))
            Verify.PlankLogical(fileSource, e, null, checkMetadata: true);
        using (var stream = File.OpenRead(path))
            Verify.PlankLogical(new StreamReadSource(stream), e, new ParquetReaderOptions { VerifyPageCrc = rng.Chance(50) }, checkMetadata: false);
        using (var fileSource = new FileReadSource(path))
            Verify.PlankPruned(fileSource, e, rng);
        if (length < (1L << 30))
        {
            var bytes = File.ReadAllBytes(path);
            Verify.PlankLogical(new MemoryReadSource(bytes), e, null, checkMetadata: false);
            if (scaleRow)
            {
                var (projection, selected) = RowRead.DrawProjection(rng);
                RowRead.ScaleRows(new MemoryReadSource(bytes), e, projection, selected, RowRead.DrawOptions(rng), "rowreader(memory)");
                RowRead.ScaleColumns(new MemoryReadSource(bytes), e);
            }
        }
        if (scaleRow)
        {
            var (projection, selected) = RowRead.DrawProjection(rng);
            using var fileSource = new FileReadSource(path);
            RowRead.ScaleRows(fileSource, e, projection, selected, RowRead.DrawOptions(rng), "rowreader(file)");
        }
        Verify.Arrow(path, e);
    }

    static void Columnar(Rng rng, int tier, List<string> describe)
    {
        long rows;
        int columns;
        var wide = tier == 0 && rng.Chance(15);
        switch (tier)
        {
            case 0: rows = wide ? rng.Pick(0L, 1L, 2L, 50L) : rng.Pick(0L, 1L, 2L, 3L, 100L, 2047L, 2048L, 2049L, 4097L, 20_000L, rng.Long(20_000)); columns = wide ? rng.Pick(300, 1000, 3000) : 1 + rng.Int(12); break;
            case 1: rows = rng.Pick(65535L, 65536L, 65537L, 100_000L, 262_145L, 500_000L, 2049 + rng.Long(500_000)); columns = 1 + rng.Int(8); break;
            default: rows = rng.Pick(1L << 20, (1L << 20) + 1, 2_000_000L, 4_194_305L, 6_000_000L); columns = 1 + rng.Int(3); break;
        }
        var cols = DrawColumns(rng, columns, rows, allowHuge: tier <= 1 && rows <= 20_000);
        var groups = Writers.DrawRowGroups(rng, rows);
        var options = Writers.DrawOptions(rng, rows, tier, rowApi: false, columns);
        describe.Add($"columnar rows={rows} cols={columns} groups={groups.Length} page={options.TargetDataPageSizeBytes} v{(int)options.DataPageVersion} idx={options.WritePageIndexes} comp={options.Compression}");
        describe.AddRange(cols.Take(40).Select(c => c.ToString()));
        describe.Add("groups=" + string.Join(",", groups.Take(30)));
        var path = TempFile("col");
        try
        {
            using (var output = File.Create(path))
                Writers.Columnar(rng.Chance(20) ? new JitterWriteStream(output) : output, cols, groups, options, rng);
            VerifyAll(path, new Expected { Cols = cols, Rows = rows, RowGroupSizes = groups }, rng, describe, scaleRow: false);
        }
        finally { Keep(path); File.Delete(path); }
    }

    static (long Rows, int Columns) DrawSize(Rng rng, int tier) => tier switch
    {
        0 => (rng.Pick(1L, 2L, 100L, 2047L, 2048L, 2049L, 16384L, 16385L, rng.Long(30_000)), 1 + rng.Int(8)),
        1 => (rng.Pick(65537L, 200_000L, rng.Long(400_000)), 1 + rng.Int(6)),
        _ => (rng.Pick(1L << 20, 3_000_000L), 1 + rng.Int(3)),
    };

    /// <summary>Existing file, then 1-3 appender sessions (new row groups or AppendToLatestRowGroup), checked as one file.</summary>
    static void Append(Rng rng, int tier, List<string> describe)
    {
        var (rows0, columns) = DrawSize(rng, tier);
        var cols = DrawColumns(rng, columns, rows0 * 3, allowHuge: false);
        foreach (var c in cols)
            if (c.Encodings.Contains(Plank.Schema.EncodingKind.Alp))
                c.Encodings = []; // keep Arrow able to read every chunk
        var options = Writers.DrawOptions(rng, rows0, tier, rowApi: false, columns);
        var schema = Writers.Schema(cols);
        var sizes = new List<long>(Writers.DrawRowGroups(rng, rows0));
        describe.Add($"append rows0={rows0} cols={columns} groups0={sizes.Count} page={options.TargetDataPageSizeBytes} idx={options.WritePageIndexes}");
        describe.AddRange(cols.Select(c => c.ToString()));
        var path = TempFile("app");
        try
        {
            using (var output = File.Create(path))
                Writers.Columnar(output, cols, [.. sizes], options, rng);
            long total = rows0;
            var sessions = 1 + rng.Int(3);
            for (var s = 0; s < sessions; s++)
            {
                var more = Writers.DrawRowGroups(rng, rng.Pick(0L, 1L, 2049L, rows0, rng.Long(rows0 + 1)));
                var latest = rng.Chance(50);
                var appendOptions = new ParquetAppendOptions
                {
                    AppendToLatestRowGroup = latest,
                    PreserveExistingMetadata = rng.Chance(50),
                    WriterOptions = Writers.DrawOptions(rng, rows0, tier, rowApi: false, columns),
                };
                describe.Add($"session {s}: latest={latest} groups={string.Join(",", more.Take(20))}");
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
                using (var appender = schema.CreateAppender(stream, appendOptions))
                {
                    Writers.WriteGroups(appender, schema, cols, more, total, rng);
                    appender.CloseFile();
                }
                // Expected row groups: with AppendToLatestRowGroup the first new group extends the last existing one.
                var rest = more.AsEnumerable();
                if (latest && more.Length > 0 && sizes.Count > 0)
                {
                    sizes[^1] += more[0];
                    rest = more.Skip(1);
                }
                sizes.AddRange(rest);
                total += more.Sum();
            }
            VerifyAll(path, new Expected { Cols = cols, Rows = total, RowGroupSizes = [.. sizes] }, rng, describe, scaleRow: false);
        }
        finally { Keep(path); File.Delete(path); }
    }

    /// <summary>2-6 files of consecutive rows merged into one (copying merger or in-place merger).</summary>
    static void Merge(Rng rng, int tier, List<string> describe)
    {
        var (rows0, columns) = DrawSize(rng, tier);
        var cols = DrawColumns(rng, columns, rows0 * 4, allowHuge: false);
        foreach (var c in cols)
            if (c.Encodings.Contains(Plank.Schema.EncodingKind.Alp))
                c.Encodings = [];
        var schema = Writers.Schema(cols);
        var files = 2 + rng.Int(5);
        var parts = new List<byte[]>();
        long total = 0;
        describe.Add($"merge files={files} rows0={rows0} cols={columns}");
        describe.AddRange(cols.Select(c => c.ToString()));
        for (var f = 0; f < files; f++)
        {
            var rows = rng.Pick(0L, 1L, rows0, rng.Long(rows0 + 1));
            var groups = Writers.DrawRowGroups(rng, rows);
            var options = Writers.DrawOptions(rng, rows, tier, rowApi: false, columns);
            var output = new MemoryStream();
            using (var writer = schema.CreateWriter(output, options))
            {
                Writers.WriteGroups(writer, schema, cols, groups, total, rng);
                writer.CloseFile();
            }
            parts.Add(output.ToArray());
            describe.Add($"file {f}: rows={rows} groups={groups.Length}");
            total += rows;
        }
        var store = new MemFiles();
        var destination = new MemFiles.Source(store);
        destination.Open("merged.parquet"u8, FileMode.Create);
        var mergeOptions = new ParquetMergeOptions { PreserveFirstFileMetadata = rng.Chance(50), WriterOptions = Writers.DrawOptions(rng, rows0, tier, rowApi: false, columns) };
        var inPlace = rng.Chance(50);
        ParquetFileMerger merger;
        if (inPlace)
        {
            destination.Write(0, parts[0]);
            merger = schema.CreateMerger(destination, mergeOptions);
        }
        else
            merger = schema.CreateMerger(new MemoryReadSource(parts[0]), destination, mergeOptions);
        for (var f = 1; f < parts.Count; f++)
            merger.AppendFile(rng.Chance(50) ? new MemoryReadSource(parts[f]) : new JitterSource(parts[f]));
        if (merger.RowCount != total)
            throw new Finding($"merger.RowCount {merger.RowCount}, expected {total} (inPlace={inPlace})");
        merger.CloseFile();
        destination.Close();
        var path = TempFile("merge");
        try
        {
            File.WriteAllBytes(path, store.Files["merged.parquet"].ToArray());
            VerifyAll(path, new Expected { Cols = cols, Rows = total }, rng, describe, scaleRow: false);
        }
        finally { Keep(path); File.Delete(path); }
    }

    /// <summary>Files written by Arrow C++ with drawn properties, read with every Plank API.</summary>
    static void ArrowFiles(Rng rng, int tier, List<string> describe)
    {
        var (rows, columns) = DrawSize(rng, tier);
        var cols = DrawColumns(rng, columns, rows, allowHuge: false);
        foreach (var c in cols)
        {
            // ParquetSharp's string / byte[] columns are optional.
            if (c.Kind == Kind.Fixed)
            {
                c.Kind = Kind.Bytes; // ParquetSharp's typed columns have no FLBA without a custom node
                c.LenMode = 0;
            }
            if (c.Kind is Kind.Bytes or Kind.String && !c.Optional)
            {
                c.Optional = true;
                c.NullPattern = 0;
            }
            c.Encodings = [];
            c.Compression = null;
            c.Bloom = false;
        }
        var groups = Writers.DrawRowGroups(rng, rows);
        describe.Add($"arrow rows={rows} cols={columns} groups={groups.Length}");
        describe.AddRange(cols.Select(c => c.ToString()));
        var path = TempFile("arrow");
        try
        {
            ArrowWrite.Write(path, cols, groups, rng, describe);
            VerifyAll(path, new Expected { Cols = cols, Rows = rows, RowGroupSizes = groups }, rng, describe, scaleRow: false);
        }
        finally { Keep(path); File.Delete(path); }
    }

    static long RowCount(Rng rng, int tier) => tier switch
    {
        0 => rng.Pick(0L, 1L, 2L, 1023L, 1024L, 1025L, 2049L, 5000L, rng.Long(20_000)),
        1 => rng.Pick(65537L, 100_000L, 300_000L, rng.Long(500_000)),
        _ => rng.Pick(1L << 20, 3_000_000L, 5_000_001L),
    };

    static void Row(Rng rng, int tier, List<string> describe, bool rollover)
    {
        var rows = RowCount(rng, tier);
        var specs = Writers.ScaleRowSpecs(rng, rows, allowHuge: tier == 0 && rows <= 5000);
        var options = Writers.DrawOptions(rng, rows, tier, rowApi: true, 8);
        describe.Add($"{(rollover ? "rollover" : "row")} rows={rows} page={options.TargetDataPageSizeBytes} rg={options.TargetRowGroupSizeBytes} file={options.TargetFileSizeBytes} cap={options.RowApiInitialRowCapacity} par={options.RowApiMaxParallelism} workers={options.Execution.WorkerCount}");
        describe.AddRange(specs.Select(c => c.ToString()));
        if (rollover)
        {
            var parts = Writers.RowApiRollover(specs, rows, options);
            describe.Add($"files={parts.Count}");
            // Files are consecutive slices of the rows: map each file through its first Id.
            long offset = 0;
            foreach (var part in parts)
            {
                using var reader = new ParquetReader();
                reader.Reset(new MemoryReadSource(part));
                long count = 0;
                foreach (RowGroup g in reader.RowGroups) count += (long)g.RowCount;
                var map = new long[count];
                for (long i = 0; i < count; i++) map[i] = offset + i;
                var e = new Expected { Cols = specs, Rows = count, RowMap = map };
                Verify.PlankLogical(new MemoryReadSource(part), e, null, checkMetadata: true);
                var (projection, selected) = RowRead.DrawProjection(rng);
                RowRead.ScaleRows(new MemoryReadSource(part), e, projection, selected, RowRead.DrawOptions(rng), "rollover rowreader");
                offset += count;
            }
            if (offset != rows)
                throw new Finding($"rollover files hold {offset} rows, expected {rows}");
            return;
        }
        var path = TempFile("row");
        try
        {
            using (var output = File.Create(path))
                Writers.RowApi(rng.Chance(20) ? new JitterWriteStream(output) : output, specs, rows, options, rng);
            VerifyAll(path, new Expected { Cols = specs, Rows = rows }, rng, describe, scaleRow: true);
        }
        finally { Keep(path); File.Delete(path); }
    }

    static void Dataset(Rng rng, int tier, List<string> describe)
    {
        var rows = tier == 0 ? rng.Pick(0L, 1L, 100L, 4097L, rng.Long(20_000)) : RowCount(rng, Math.Min(tier, 1));
        var specs = Writers.ScaleRowSpecs(rng, rows, allowHuge: tier == 0 && rows <= 5000);
        var options = Writers.DrawOptions(rng, rows, tier, rowApi: true, 8);
        describe.Add($"dataset rows={rows} page={options.TargetDataPageSizeBytes} rg={options.TargetRowGroupSizeBytes} cap={options.RowApiInitialRowCapacity} par={options.RowApiMaxParallelism}");
        describe.AddRange(specs.Select(c => c.ToString()));
        var files = Writers.Dataset(specs, rows, options, rng, out var partitionOf);
        var seen = new bool[rows];
        long total = 0;
        foreach (var (name, bytes) in files)
        {
            // Map the file's rows to global rows through Id, then check every column against that row.
            var ids = new List<long>();
            using (var reader = new ParquetReader())
            {
                reader.Reset(new MemoryReadSource(bytes));
                foreach (RowGroup g in reader.RowGroups)
                    foreach (var b in g.Column<long>(reader.Schema.LeafColumns[0]))
                        foreach (var id in b.Values) ids.Add(id);
            }
            foreach (var id in ids)
            {
                if (id < 0 || id >= rows)
                    throw new Finding($"dataset {name}: Id {id} out of range");
                if (seen[id])
                    throw new Finding($"dataset {name}: Id {id} written twice");
                seen[id] = true;
                if (partitionOf(id) != name)
                    throw new Finding($"dataset {name}: Id {id} belongs to {partitionOf(id)}");
            }
            total += ids.Count;
            var e = new Expected { Cols = specs, Rows = ids.Count, RowMap = [.. ids] };
            Verify.PlankLogical(new MemoryReadSource(bytes), e, null, checkMetadata: true);
            var (projection, selected) = RowRead.DrawProjection(rng);
            RowRead.ScaleRows(new MemoryReadSource(bytes), e, projection, selected, RowRead.DrawOptions(rng), $"dataset {name} rowreader");
            var tmp = TempFile("ds");
            try { File.WriteAllBytes(tmp, bytes); Verify.Arrow(tmp, e); }
            finally { File.Delete(tmp); }
        }
        if (total != rows)
            throw new Finding($"dataset files hold {total} rows, expected {rows}");
    }

    // ---------------- concurrency ----------------

    static void Concurrency(Rng rng, int tier, List<string> describe)
    {
        var rows = tier == 0 ? rng.Pick(2049L, 5000L, 20_000L, 50_000L) : rng.Pick(100_000L, 300_000L);
        var specs = Writers.ScaleRowSpecs(rng, rows, allowHuge: false);
        var baseOptions = Writers.DrawOptions(rng, rows, 0, rowApi: true, 8);
        // Many row groups so read-ahead and per-group worker hand-off happen often.
        var options = new ParquetWriterOptions
        {
            TargetRowGroupSizeBytes = rng.Pick(1000UL, 65536UL, 1UL << 20),
            TargetDataPageSizeBytes = rng.Pick(1024u, 8192u, 1u << 20),
            WritePageIndexes = baseOptions.WritePageIndexes,
            DataPageVersion = baseOptions.DataPageVersion,
            Compression = Environment.GetEnvironmentVariable("SCALE_COMPRESSION") is { } comp ? Enum.Parse<Plank.Schema.CompressionKind>(comp) : baseOptions.Compression,
            RowApiInitialRowCapacity = baseOptions.RowApiInitialRowCapacity,
            RowApiMaxParallelism = 1,
            Execution = new Plank.ParquetExecutionOptions { WorkerCount = 1 },
        };
        describe.Add($"concurrency rows={rows} rg={options.TargetRowGroupSizeBytes} page={options.TargetDataPageSizeBytes} cap={options.RowApiInitialRowCapacity} comp={options.Compression} v{(int)options.DataPageVersion}");
        describe.AddRange(specs.Select(c => c.ToString()));
        if (Verbose)
            Console.WriteLine("  " + describe[0]);
        var e = new Expected { Cols = specs, Rows = rows };

        // Baseline: single-threaded writer.
        var baseline = new MemoryStream();
        Writers.RowApi(baseline, specs, rows, options, new Rng(1));
        var bytes = baseline.ToArray();
        Verify.PlankLogical(new MemoryReadSource(bytes), e, null, checkMetadata: true);

        var iterations = tier == 0 ? 200 : 40;
        using var pressure = new Pressure(rng.Int(4), rng.Chance(50));
        for (var it = 0; it < iterations; it++)
        {
            Jitter.Percent = rng.Pick(0, 1, 5, 20, 50);
            var action = rng.Int(10);
            if (Environment.GetEnvironmentVariable("SCALE_ACTION") is { } forced)
                action = int.Parse(forced);
            var where = $"iteration {it} action {action} jitter {Jitter.Percent}%";
            if (Verbose)
            {
                using var self = System.Diagnostics.Process.GetCurrentProcess();
                Console.WriteLine($"  {DateTime.UtcNow:HH:mm:ss.fff} {where} rss={self.WorkingSet64 >> 20}MB managed={GC.GetTotalMemory(false) >> 20}MB threads={self.Threads.Count} poolRetained={DefaultParquetBufferPool.Shared.RetainedBytes >> 20}MB poolAllocs={s_nativeCount.GetValue(DefaultParquetBufferPool.Shared)} gcCommitted={GC.GetGCMemoryInfo().TotalCommittedBytes >> 20}MB gcFrag={GC.GetGCMemoryInfo().FragmentedBytes >> 20}MB");
            }
            Watchdog(where, TimeSpan.FromSeconds(300), () =>
            {
                switch (action)
                {
                    case <= 4:
                    {
                        // Row reader, multi-worker, over a random source kind.
                        var (projection, selected) = RowRead.DrawProjection(rng);
                        var readOptions = RowRead.DrawOptions(rng);
                        var kind = rng.Int(5);
                        IParquetReadSource source = kind switch
                        {
                            0 => new MemoryReadSource(bytes),
                            1 => new JitterSource(bytes),
                            2 => new StreamReadSource(new JitterStream(bytes)),
                            3 => new StreamReadSource(new MemoryStream(bytes, writable: false)),
                            _ => new JitterSource(bytes),
                        };
                        RowRead.ScaleRows(source, e, projection, selected, readOptions,
                            $"{where}: rowreader workers={readOptions.Execution.WorkerCount} ahead={readOptions.MaxReadAheadRowGroups} source={kind}");
                        break;
                    }
                    case 5:
                    {
                        // One row reader reused across Reset with changing projections.
                        var readOptions = RowRead.DrawOptions(rng);
                        var (p1, s1) = RowRead.DrawProjection(rng);
                        using var reader = ScaleRow.CreateRowReader(new JitterSource(bytes), p1, readOptions);
                        var partial = rng.Long(rows + 1);
                        for (long i = 0; i < partial && reader.MoveNext(); i++) { }
                        var (p2, s2) = RowRead.DrawProjection(rng);
                        reader.Reset(new JitterSource(bytes), p2);
                        long n = 0;
                        while (reader.MoveNext())
                        {
                            if (s2[0] && reader.Current.Id != specs[0].Int64(n))
                                throw new Finding($"{where}: after Reset row {n} Id {reader.Current.Id}");
                            if (s2[7] && reader.Current.Label != specs[7].Str(n))
                                throw new Finding($"{where}: after Reset row {n} Label differs");
                            n++;
                        }
                        if (n != rows)
                            throw new Finding($"{where}: after Reset {n} rows (partial first pass {partial})");
                        break;
                    }
                    case 6:
                    {
                        // Several independent readers on one shared source and the shared pool, in parallel.
                        var threads = rng.Pick(2, 3, 4, 8);
                        var shared = new MemoryReadSource(bytes);
                        var errors = new Exception?[threads];
                        var projections = Enumerable.Range(0, threads).Select(_ => RowRead.DrawProjection(rng)).ToArray();
                        var opts = Enumerable.Range(0, threads).Select(_ => RowRead.DrawOptions(rng, 4)).ToArray();
                        var logical = Enumerable.Range(0, threads).Select(_ => rng.Chance(40)).ToArray();
                        var ts = Enumerable.Range(0, threads).Select(t => new Thread(() =>
                        {
                            try
                            {
                                if (logical[t]) Verify.PlankLogical(shared, e, null, checkMetadata: false);
                                else RowRead.ScaleRows(shared, e, projections[t].Projection, projections[t].Selected, opts[t], $"{where}: thread {t}");
                            }
                            catch (Exception ex) { errors[t] = ex; }
                        })).ToArray();
                        foreach (var t in ts) t.Start();
                        foreach (var t in ts) t.Join();
                        foreach (var err in errors)
                            if (err is not null) throw new Finding($"{where}: parallel readers: {err.GetType().Name}: {err.Message}");
                        break;
                    }
                    default:
                    {
                        // Writer with parallel row workers / execution workers and a jittering sink.
                        var parallel = new ParquetWriterOptions
                        {
                            TargetRowGroupSizeBytes = options.TargetRowGroupSizeBytes,
                            TargetDataPageSizeBytes = options.TargetDataPageSizeBytes,
                            WritePageIndexes = options.WritePageIndexes,
                            DataPageVersion = options.DataPageVersion,
                            Compression = options.Compression,
                            RowApiInitialRowCapacity = options.RowApiInitialRowCapacity,
                            RowApiMaxParallelism = rng.Pick(2u, 3u, 4u, 8u, 16u),
                            Execution = new Plank.ParquetExecutionOptions
                            {
                                WorkerCount = rng.Pick(2, 4, 8, 16),
                                OnWorkerStarted = rng.Chance(50) ? _ => Jitter.Maybe() : null,
                            },
                        };
                        // A counting pool on some iterations: every buffer must be back once the writer is disposed.
                        var counting = rng.Chance(50) ? new CountingPool { CaptureStacks = Environment.GetEnvironmentVariable("SCALE_POOL_STACKS") == "1" } : null;
                        if (counting is not null)
                            parallel = new ParquetWriterOptions
                            {
                                TargetRowGroupSizeBytes = parallel.TargetRowGroupSizeBytes, TargetDataPageSizeBytes = parallel.TargetDataPageSizeBytes,
                                WritePageIndexes = parallel.WritePageIndexes, DataPageVersion = parallel.DataPageVersion, Compression = parallel.Compression,
                                RowApiInitialRowCapacity = parallel.RowApiInitialRowCapacity, RowApiMaxParallelism = parallel.RowApiMaxParallelism,
                                Execution = parallel.Execution, BufferPool = counting,
                            };
                        var output = new MemoryStream();
                        Writers.RowApi(new JitterWriteStream(output), specs, rows, parallel, new Rng(rng.Next()));
                        if (counting is not null)
                        {
                            GC.Collect();
                            GC.WaitForPendingFinalizers();
                            GC.Collect();
                            if (counting.Outstanding != 0)
                                throw new Finding($"{where}: row writer (par={parallel.RowApiMaxParallelism}, workers={parallel.Execution.WorkerCount}) disposed with {counting.Outstanding} of {counting.Rented} pool buffers ({counting.OutstandingBytes} bytes) never returned\n{counting.Describe(3)}");
                        }
                        var written = output.ToArray();
                        Verify.PlankLogical(new MemoryReadSource(written), e, null, checkMetadata: true);
                        if (!written.AsSpan().SequenceEqual(bytes))
                            Note($"{where}: parallel writer (par={parallel.RowApiMaxParallelism}, workers={parallel.Execution.WorkerCount}) bytes differ from the single-threaded file ({written.Length} vs {bytes.Length}) but decode identically");
                        break;
                    }
                }
            });
        }
    }

    static readonly HashSet<string> s_notes = [];

    static void Note(string text)
    {
        var key = text[..Math.Min(text.Length, 40)];
        lock (s_notes)
            if (s_notes.Count < 50 && s_notes.Add(text.Split(':')[^1]))
                Console.WriteLine("NOTE " + text);
    }

    static void Watchdog(string where, TimeSpan limit, Action action)
    {
        Exception? error = null;
        var thread = new Thread(() => { try { action(); } catch (Exception ex) { error = ex; } }, 16 << 20) { IsBackground = true };
        thread.Start();
        if (!thread.Join(limit))
        {
            Console.WriteLine($"HANG {where}: no progress after {limit}");
            Console.Out.Flush();
            Environment.Exit(3);
        }
        if (error is not null)
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
    }

    /// <summary>Background CPU and thread-pool pressure while a case runs.</summary>
    sealed class Pressure : IDisposable
    {
        volatile bool _stop;
        readonly List<Thread> _threads = [];

        public Pressure(int spinners, bool poolFlood)
        {
            for (var i = 0; i < spinners; i++)
            {
                var t = new Thread(() =>
                {
                    var junk = new List<byte[]>();
                    while (!_stop)
                    {
                        Thread.SpinWait(5000);
                        junk.Add(new byte[1024 * (1 + junk.Count % 64)]);
                        if (junk.Count > 256) junk.Clear();
                        Thread.Yield();
                    }
                }) { IsBackground = true, Priority = ThreadPriority.AboveNormal };
                t.Start();
                _threads.Add(t);
            }
            if (poolFlood)
            {
                var t = new Thread(() =>
                {
                    while (!_stop)
                    {
                        for (var k = 0; k < 64; k++)
                            ThreadPool.QueueUserWorkItem(_ => Thread.Sleep(1));
                        Thread.Sleep(5);
                    }
                }) { IsBackground = true };
                t.Start();
                _threads.Add(t);
            }
        }

        public void Dispose()
        {
            _stop = true;
            foreach (var t in _threads) t.Join();
        }
    }

    // ---------------- huge files ----------------

    static void Big(Rng rng, int tier, List<string> describe)
    {
        // Files over 2 GB / 4 GB: wide fixed-length binary values, an Int64 row index, many row groups;
        // variant 1 writes a single column chunk above 2 GB.
        var variant = rng.Int(3);
        var valueBytes = rng.Pick(4096, 65536, 1 << 20);
        var targetBytes = variant switch { 0 => (2L << 30) + (300L << 20), 1 => (4L << 30) + (300L << 20), _ => (2L << 30) + (100L << 20) };
        var rows = targetBytes / valueBytes;
        var id = new ColSpec { Name = "id", Kind = Kind.Int64, Seed = rng.Next(), Pattern = 1, P1 = 0, P2 = 1 };
        var blob = new ColSpec { Name = "blob", Kind = Kind.Bytes, Optional = rng.Chance(50), Seed = rng.Next(), Pattern = 5, LenMode = 0, L1 = valueBytes, NullPattern = 2, N1 = 1000, Encodings = [Plank.Schema.EncodingKind.Plain] };
        var cols = new[] { id, blob };
        long perGroup = variant == 2 ? rows : Math.Max(1, (400L << 20) / valueBytes);
        var groups = new List<long>();
        for (long left = rows; left > 0; left -= perGroup) groups.Add(Math.Min(perGroup, left));
        var options = new ParquetWriterOptions
        {
            TargetDataPageSizeBytes = rng.Pick(1u << 20, 64u << 20),
            WritePageIndexes = true,
            Compression = Plank.Schema.CompressionKind.None,
            DataPageVersion = rng.Chance(50) ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2,
        };
        describe.Add($"big variant={variant} rows={rows} value={valueBytes} groups={groups.Count} perGroup={perGroup} optional={blob.Optional} page={options.TargetDataPageSizeBytes}");
        var path = TempFile("big");
        try
        {
            using (var output = File.Create(path))
                Writers.Columnar(output, cols, [.. groups], options, rng);
            describe.Add($"file={new FileInfo(path).Length}");
            Console.WriteLine("  " + describe[^1]);
            var e = new Expected { Cols = cols, Rows = rows, RowGroupSizes = [.. groups] };
            using (var fileSource = new FileReadSource(path))
                Verify.PlankLogical(fileSource, e, null, checkMetadata: true);
            using (var fileSource = new FileReadSource(path))
                Verify.PlankPruned(fileSource, e, rng);
            Verify.Arrow(path, e);
        }
        finally { Keep(path); File.Delete(path); }
    }
}
