using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Reading.Physical;
using Plank.Writing;

namespace Plank.Benchmarks.MetadataRegression;

// AllocatedBytes is the exact batch total; divide by Operations for exact bytes/op.
public sealed record MetadataSample(double Microseconds, long AllocatedBytes, int Operations, double Load);
public sealed record MetadataCalibration(string Id, string InputSha256, int Operations);
public sealed record MetadataResult(string Id, string InputSha256, string Digest, List<MetadataSample> Samples);
public sealed record MetadataReport(string Label, string Revision, DateTimeOffset GeneratedAt, List<MetadataResult> Cases);

public static class MetadataRegressionCommand
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    static long sink;
    static string? Value(string[] args, string key) { var i = Array.IndexOf(args, key); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
    static bool Has(string[] args, string key) => Array.IndexOf(args, key) >= 0;
    static string FixturePath(string[] args) => Value(args, "--fixtures") ?? "artifacts/metadata-fixtures";

    public static int Run(string[] args)
    {
        var directory = FixturePath(args);
        if (Has(args, "--generate-fixtures"))
        {
            if (Directory.Exists(directory) && Directory.EnumerateFileSystemEntries(directory).Any())
                throw new InvalidOperationException("Fixture directory must be empty; never regenerate comparison inputs in place.");
            MetadataFixtures.Generate(directory, Has(args, "--quick"));
            Console.WriteLine($"Fixtures written to {directory}; reuse these exact files for every revision.");
            return 0;
        }
        if (Has(args, "--describe-fixtures"))
        {
            foreach (var path in Directory.GetFiles(directory, "*.parquet").Order(StringComparer.Ordinal))
            {
                var bytes = File.ReadAllBytes(path); var source = new MemoryReadSource(bytes);
                using var physical = new ParquetFileReader(); physical.Reset(source);
                using var logical = new ParquetReader(); logical.Reset(source);
                var chunk = physical.Metadata.ColumnChunk(0, 0);
                var pages = -1;
                if (chunk.ColumnIndexLength > 0 && chunk.OffsetIndexLength > 0)
                {
                    using var indexes = logical.RowGroups[0].GetColumnMetadata(0).OpenPages();
                    pages = indexes.Count;
                }
                Console.WriteLine($"{Path.GetFileName(path)} sha256={Convert.ToHexStringLower(SHA256.HashData(bytes))} columns={physical.Metadata.ColumnCount} row-groups={physical.Metadata.RowGroupCount} first-chunk-indexed-pages={pages} bloom={chunk.HasBloomFilter}");
            }
            return 0;
        }
        var label = Value(args, "--label") ?? "current";
        var output = Value(args, "--output") ?? $"artifacts/benchmarks/metadata-regression-{label}.json";
        var samples = int.Parse(Value(args, "--iterations") ?? (Has(args, "--quick") ? "3" : "30"), CultureInfo.InvariantCulture);
        var warmups = int.Parse(Value(args, "--warmups") ?? (Has(args, "--quick") ? "1" : "3"), CultureInfo.InvariantCulture);
        if (samples < 1 || warmups < 0) throw new ArgumentOutOfRangeException(nameof(args));
        var revision = Value(args, "--revision") ?? "unspecified";
        var states = Directory.GetFiles(directory, "*.parquet").Order(StringComparer.Ordinal)
            .SelectMany(path => Cases(path)).ToList();
        if (states.Count == 0) throw new InvalidOperationException("No fixture cases found.");
        foreach (var state in states)
            for (var i = 0; i < Math.Max(warmups, 1); i++) state.Operation(null);
        var calibrationPath = Value(args, "--calibration");
        if (Has(args, "--calibrate") || calibrationPath is null)
        {
            foreach (var state in states) state.Operations = Calibrate(state.Operation);
            if (Has(args, "--calibrate"))
            {
                var calibration = states.Select(s => new MetadataCalibration(s.Id, s.InputHash, s.Operations)).ToList();
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
                File.WriteAllText(output, JsonSerializer.Serialize(calibration, Json));
                Console.WriteLine($"Calibration: {output}");
                foreach (var state in states) state.Dispose();
                return 0;
            }
        }
        else
        {
            var calibration = (JsonSerializer.Deserialize<List<MetadataCalibration>>(File.ReadAllText(calibrationPath), Json)
                ?? throw new InvalidDataException("Invalid calibration.")).ToDictionary(c => c.Id, StringComparer.Ordinal);
            if (calibration.Count != states.Count) throw new InvalidDataException("Calibration case count differs.");
            foreach (var state in states)
            {
                if (!calibration.TryGetValue(state.Id, out var entry) || entry.InputSha256 != state.InputHash || entry.Operations < 1)
                    throw new InvalidDataException($"Invalid calibration for {state.Id}.");
                state.Operations = entry.Operations;
            }
        }
        for (var round = 0; round < samples; round++)
        {
            foreach (var state in states)
            {
                var load = ReadLoad();
                while (load > 10) { Thread.Sleep(5000); load = ReadLoad(); }
                long allocated = GC.GetAllocatedBytesForCurrentThread();
                var start = Stopwatch.GetTimestamp();
                long result = 0;
                for (var i = 0; i < state.Operations; i++) result ^= state.Operation(null);
                var elapsed = Stopwatch.GetElapsedTime(start).TotalMicroseconds / state.Operations;
                allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
                sink ^= result;
                state.Samples.Add(new(elapsed, allocated, state.Operations, load));
            }
            Console.WriteLine($"round {round + 1}/{samples}");
        }
        var report = new MetadataReport(label, revision, DateTimeOffset.UtcNow,
            states.Select(s => new MetadataResult(s.Id, s.InputHash, s.Digest, s.Samples)).ToList());
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        File.WriteAllText(output, JsonSerializer.Serialize(report, Json));
        Console.WriteLine($"Metadata regression snapshot: {output}");
        foreach (var state in states) state.Dispose();
        return 0;
    }

    // Powers of two avoid overfitting to an individual noisy short measurement. Long cases stay at one.
    static int Calibrate(Func<BinaryWriter?, long> operation)
    {
        const int maximum = 65536;
        for (var count = 1; ; count = Math.Min(count * 2, maximum))
        {
            var best = double.PositiveInfinity;
            for (var trial = 0; trial < 3; trial++)
            {
                var start = Stopwatch.GetTimestamp();
                long result = 0;
                for (var i = 0; i < count; i++) result ^= operation(null);
                sink ^= result;
                best = Math.Min(best, Stopwatch.GetElapsedTime(start).TotalMilliseconds);
            }
            if (best >= 1 || count == maximum) return count;
        }
    }

    public static double ReadLoad()
    {
        if (!File.Exists("/proc/loadavg")) throw new PlatformNotSupportedException("Linux /proc/loadavg is required.");
        return double.Parse(File.ReadAllText("/proc/loadavg").Split(' ')[0], CultureInfo.InvariantCulture);
    }

    sealed class State(string id, string inputHash, Func<BinaryWriter?, long> operation, string digest,
        ParquetFileReader physical, ParquetReader logical) : IDisposable
    {
        public string Id = id;
        public string InputHash = inputHash;
        public Func<BinaryWriter?, long> Operation = operation;
        public string Digest = digest;
        public List<MetadataSample> Samples = [];
        public int Operations = 1;
        public void Dispose() { physical.Dispose(); logical.Dispose(); }
    }
    static IEnumerable<State> Cases(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var source = new MemoryReadSource(bytes);
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var name = Path.GetFileNameWithoutExtension(path);
        using var physical = new ParquetFileReader();
        physical.Reset(source);
        using var logical = new ParquetReader();
        logical.Reset(source);
        var chunk = physical.Metadata.ColumnChunk(0, 0);
        var operations = new List<string> { "footer-open", "logical-open", "metadata-walk", "page-scan", "merge" };
        if (chunk.ColumnIndexLength != 0 && chunk.OffsetIndexLength != 0) operations.Add("page-index");
        if (chunk.HasBloomFilter) operations.Add("bloom-open");
        // Each state owns its readers: the operation closures outlive this iterator.
        foreach (var opName in operations)
        {
            var p = new ParquetFileReader(); p.Reset(source);
            var l = new ParquetReader(); l.Reset(source);
            Func<BinaryWriter?, long> op = opName switch
            {
                "footer-open" => w => { using var r = new ParquetFileReader(); r.Reset(source); return w is null ? r.Metadata.RowGroupCount : DumpPhysical(r.Metadata, w); },
                "logical-open" => w => { using var r = new ParquetReader(); r.Reset(source); return w is null ? r.Schema.LeafColumns.Length : DumpLogical(r, w); },
                "metadata-walk" => w => DumpLogical(l, w),
                "page-scan" => w => Scan(p, w),
                "merge" => w => Merge(source, l, w),
                "page-index" => w => Index(l, w),
                "bloom-open" => w => Bloom(p, w),
                _ => throw new InvalidOperationException()
            };
            using var dump = new MemoryStream();
            using var writer = new BinaryWriter(dump, Encoding.UTF8, true);
            op(writer); writer.Flush();
            yield return new State($"{name}/{opName}", hash, op, Convert.ToHexStringLower(SHA256.HashData(dump.ToArray())), p, l);
        }
    }
    static long DumpPhysical(Plank.Reading.Physical.ParquetFileMetadata m, BinaryWriter? w)
    {
        w?.Write(m.FileVersion); w?.Write(m.FooterOffset); w?.Write(m.FooterLength); w?.Write(m.SchemaNodeCount);
        w?.Write(m.ColumnCount); w?.Write(m.RowGroupCount); w?.Write(m.KeyValueMetadataCount);
        for (var i = 0; i < m.SchemaNodeCount; i++)
        {
            var node = m.SchemaNodes[i]; Bytes(w, m.SchemaNodeNameUtf8(i));
            w?.Write(node.ParentOrdinal); w?.Write((int)node.Kind); w?.Write((int)node.Repetition);
            w?.Write((int?)node.PhysicalType ?? -1); w?.Write(node.TypeLength); w?.Write(node.ChildCount); w?.Write(node.FieldId ?? -1);
            w?.Write(node.LogicalType.ToString()); Bytes(w, m.SchemaNodeLogicalTypeCrsUtf8(i));
        }
        for (var i = 0; i < m.KeyValueMetadataCount; i++) { Bytes(w, m.KeyValueMetadataKeyUtf8(i)); Bytes(w, m.KeyValueMetadataValueUtf8(i)); }
        long count = 0;
        foreach (var rg in m.RowGroups)
        {
            w?.Write(rg.RowCount); w?.Write(rg.ColumnCount); count += (long)rg.RowCount;
            for (var c = 0; c < rg.ColumnCount; c++)
            {
                var x = m.ColumnChunk(rg.Ordinal, c);
                w?.Write(x.ValueCount); w?.Write(x.DataPageOffset); w?.Write(x.DictionaryPageOffset);
                w?.Write(x.TotalCompressedSize); w?.Write(x.TotalUncompressedSize); w?.Write(x.ColumnIndexOffset);
                w?.Write(x.ColumnIndexLength); w?.Write(x.OffsetIndexOffset); w?.Write(x.OffsetIndexLength);
                w?.Write(x.BloomFilterOffset); w?.Write(x.BloomFilterLength);
            }
        }
        return count;
    }
    static long DumpLogical(ParquetReader r, BinaryWriter? w)
    {
        long count = 0;
        w?.Write(r.Schema.LeafColumns.Length); w?.Write(r.RowGroups.Count);
        if (w is not null)
            foreach (var leaf in r.Schema.LeafColumns)
            {
                w.Write(leaf.Path); w.Write((int)leaf.PhysicalType); w.Write(leaf.MaxDefinitionLevel);
                w.Write(leaf.MaxRepetitionLevel); w.Write(leaf.FieldId ?? -1); w.Write(leaf.LogicalType?.ToString() ?? "");
            }
        foreach (var rg in r.RowGroups)
        {
            w?.Write(rg.RowCount); count += (long)rg.RowCount;
            for (var c = 0; c < r.Schema.LeafColumns.Length; c++)
            {
                var x = rg.GetColumnMetadata(c);
                count = unchecked(count + (long)x.ValueCount + (int)x.Compression + (x.HasColumnIndex ? 1 : 0) + (x.HasOffsetIndex ? 1 : 0) + (x.HasBloomFilter ? 1 : 0));
                w?.Write(x.ValueCount); w?.Write((int)x.Compression); w?.Write(x.HasColumnIndex); w?.Write(x.HasOffsetIndex); w?.Write(x.HasBloomFilter);
                foreach (var e in x.Encodings) { count = unchecked(count + (int)e); w?.Write((int)e); }
                var statistics = x.Statistics;
                count = unchecked(count + statistics.Minimum.Length + statistics.Maximum.Length + (statistics.NullCount ?? 0));
                Stats(w, statistics);
            }
        }
        return count;
    }
    static void Stats(BinaryWriter? w, ParquetStatistics s)
    {
        if (w is null) return;
        w.Write(s.HasMinimum); w.Write(s.HasMaximum); Bytes(w, s.Minimum); Bytes(w, s.Maximum);
        w.Write(s.NullCount ?? -1); w.Write(s.DistinctCount ?? -1); w.Write(s.IsMinimumExact); w.Write(s.IsMaximumExact);
    }
    static void Bytes(BinaryWriter? w, ReadOnlySpan<byte> bytes) { if (w is null) return; w.Write(bytes.Length); w.Write(bytes); }
    static long Scan(ParquetFileReader r, BinaryWriter? w)
    {
        long count = 0;
        using var cursor = r.OpenPages(0, 0);
        while (cursor.MoveNext())
        {
            var h = cursor.CurrentHeader; count++;
            w?.Write((int)h.Type); w?.Write(h.HeaderLength); w?.Write(h.ValueCount); w?.Write((int)h.Encoding);
            w?.Write(h.CompressedPageSize); w?.Write(h.UncompressedPageSize); w?.Write(h.NullCount); w?.Write(h.RowCount);
        }
        w?.Write(count); return count;
    }
    static long Index(ParquetReader r, BinaryWriter? w)
    {
        using var pages = r.RowGroups[0].GetColumnMetadata(0).OpenPages();
        w?.Write(pages.Count); w?.Write((int)pages.BoundaryOrder);
        foreach (var p in pages) { w?.Write(p.PageOrdinal); w?.Write(p.Offset); w?.Write(p.CompressedSize); w?.Write(p.FirstRowIndex ?? ulong.MaxValue); w?.Write(p.RowCount ?? ulong.MaxValue); w?.Write(p.IsNullPage.HasValue ? (p.IsNullPage.Value ? 1 : 0) : -1); Stats(w, p.Statistics); }
        return pages.Count;
    }
    static long Bloom(ParquetFileReader r, BinaryWriter? w)
    {
        using var bloom = r.OpenBloomFilter(0, 0); Bytes(w, bloom.Bitset); return bloom.BitsetSizeBytes;
    }
    static long Merge(MemoryReadSource source, ParquetReader r, BinaryWriter? w)
    {
        using var destination = new MemoryDestination();
        var merger = r.Schema.CreateMerger(source, destination); merger.CloseFile();
        if (w is null) return merger.RowGroupCount;
        using var merged = new ParquetFileReader(); merged.Reset(new MemoryReadSource(destination.Bytes));
        return DumpPhysical(merged.Metadata, w);
    }
    sealed class MemoryDestination : IParquetWriteSource
    {
        readonly MemoryStream stream = new();
        public ReadOnlyMemory<byte> Bytes => stream.ToArray();
        public void Open(ReadOnlySpan<byte> path, FileMode mode) => throw new NotSupportedException();
        public void Close() { }
        public void Write(ulong offset, ReadOnlySpan<byte> source) { stream.Position = checked((long)offset); stream.Write(source); }
        public void SetLength(ulong length) => stream.SetLength(checked((long)length));
        public void Flush() { }
        public void Dispose() => stream.Dispose();
    }
    public static int Compare(string[] args)
    {
        if (args.Length < 2) throw new ArgumentException("Expected baseline and current JSON paths.");
        MetadataReport Load(string p) => JsonSerializer.Deserialize<MetadataReport>(File.ReadAllText(p), Json) ?? throw new InvalidDataException(p);
        var a = Load(args[0]); var b = Load(args[1]);
        var floorA = Value(args, "--noise-baseline"); var floorB = Value(args, "--noise-current");
        var noiseA = floorA is null ? null : Load(floorA).Cases.ToDictionary(x => x.Id);
        var noiseB = floorB is null ? null : Load(floorB).Cases.ToDictionary(x => x.Id);
        if ((noiseA is null) != (noiseB is null)) throw new ArgumentException("Supply both noise snapshots.");
        var baseline = a.Cases.ToDictionary(x => x.Id); var current = b.Cases.ToDictionary(x => x.Id);
        var failed = false;
        Console.WriteLine("case | median delta | baseline min/median/p90 us | current min/median/p90 us | allocation delta B | digest | verdict");
        foreach (var id in baseline.Keys.Union(current.Keys).Order(StringComparer.Ordinal))
        {
            if (!baseline.TryGetValue(id, out var x) || !current.TryGetValue(id, out var y)) { Console.WriteLine($"{id} | MISSING CASE"); failed = true; continue; }
            var xt = x.Samples.Select(s => s.Microseconds).Order().ToArray(); var yt = y.Samples.Select(s => s.Microseconds).Order().ToArray();
            var xm = Median(xt); var ym = Median(yt); var delta = (ym / xm - 1) * 100;
            var operations = x.Samples[0].Operations;
            if (operations < 1 || x.Samples.Any(s => s.Operations != operations) || y.Samples.Any(s => s.Operations != operations))
                throw new InvalidDataException($"Incompatible operation counts for {id}; use a shared calibration.");
            var xa = x.Samples.Select(s => s.AllocatedBytes).Order().ToArray(); var ya = y.Samples.Select(s => s.AllocatedBytes).Order().ToArray();
            var ad = MedianTwice(ya) - MedianTwice(xa); var same = x.Digest == y.Digest && x.InputSha256 == y.InputSha256;
            var spread = Math.Max((Percentile(xt, .9) - Percentile(xt, .1)) / xm * 100, (Percentile(yt, .9) - Percentile(yt, .1)) / ym * 100);
            double? floor = null;
            if (noiseA is not null && noiseB is not null && noiseA.TryGetValue(id, out var na) && noiseB.TryGetValue(id, out var nb))
            {
                if (na.InputSha256 != x.InputSha256 || nb.InputSha256 != x.InputSha256 ||
                    na.Samples.Any(s => s.Operations != operations) || nb.Samples.Any(s => s.Operations != operations))
                    throw new InvalidDataException($"Noise snapshots use different fixtures or calibration for {id}.");
                var am = Median(na.Samples.Select(s => s.Microseconds).Order().ToArray());
                var bm = Median(nb.Samples.Select(s => s.Microseconds).Order().ToArray());
                var at = na.Samples.Select(s => s.Microseconds).Order().ToArray();
                var bt = nb.Samples.Select(s => s.Microseconds).Order().ToArray();
                // Include both the master/master median shift and within-run p10–p90 spread.
                floor = Math.Max(Math.Abs((bm / am - 1) * 100),
                    Math.Max((Percentile(at, .9) - Percentile(at, .1)) / am * 100,
                             (Percentile(bt, .9) - Percentile(bt, .1)) / bm * 100));
            }
            var verdict = floor is null ? "time unclassified (no noise floor)" : Math.Abs(delta) <= Math.Max(floor.Value, spread) ? "no time change beyond noise" : delta > 0 ? "slower beyond noise" : "faster beyond noise";
            if (ad != 0 || xa[0] != ya[0] || xa[^1] != ya[^1]) verdict += "; allocations changed";
            if (!same) { verdict += "; parsed output or input changed"; failed = true; }
            Console.WriteLine(FormattableString.Invariant($"{id} | {delta:+0.0;-0.0;0.0}% (spread {spread:0.0}%, noise ±{floor?.ToString("0.0", CultureInfo.InvariantCulture) ?? "?"}%) | {xt[0]:0.00}/{xm:0.00}/{Percentile(xt, .9):0.00} | {yt[0]:0.00}/{ym:0.00}/{Percentile(yt, .9):0.00} | {Fraction(ad, 2L * operations)} ({Fraction(xa[0], operations)}..{Fraction(xa[^1], operations)} → {Fraction(ya[0], operations)}..{Fraction(ya[^1], operations)}; {operations} ops/sample) | {(same ? "same" : "CHANGED")} | {verdict}"));
        }
        return failed ? 1 : 0;
    }
    static long MedianTwice(long[] sorted) => checked(sorted[(sorted.Length - 1) / 2] + sorted[sorted.Length / 2]);
    static string Fraction(long numerator, long denominator)
    {
        var a = Math.Abs(numerator); var b = denominator;
        while (b != 0) (a, b) = (b, a % b);
        var divisor = a == 0 ? 1 : a;
        numerator /= divisor; denominator /= divisor;
        return denominator == 1 ? numerator.ToString(CultureInfo.InvariantCulture) : $"{numerator}/{denominator}";
    }
    public static double Median(double[] sorted) => sorted.Length % 2 == 0 ? (sorted[sorted.Length / 2 - 1] + sorted[sorted.Length / 2]) / 2 : sorted[sorted.Length / 2];
    public static double Percentile(double[] sorted, double p) => sorted[Math.Max(0, (int)Math.Ceiling(sorted.Length * p) - 1)];
}
