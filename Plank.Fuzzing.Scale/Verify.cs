using System.Buffers.Binary;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Ps = ParquetSharp;

namespace Plank.Fuzzing.Scale;

public sealed class Finding(string message) : Exception(message);

/// <summary>Expected file: the column specs, in leaf order, and the total row count.</summary>
public sealed class Expected
{
    public required ColSpec[] Cols;
    public required long Rows;
    /// <summary>Known row-group sizes (columnar writer) or null (row/dataset writers choose them).</summary>
    public long[]? RowGroupSizes;
    /// <summary>Global row index of each file row (dataset partitions); null = identity.</summary>
    public long[]? RowMap;
    /// <summary>Self-test: when set, file row Skew is expected to hold global row Skew+1 (a planted mismatch).</summary>
    public long Skew = -1;
    public long Row(long fileRow)
    {
        var r = RowMap is null ? fileRow : RowMap[fileRow];
        return fileRow == Skew ? r + 1 : r;
    }
}

public static class Verify
{
    public static long ArrowSkippedHugeHeader, ArrowSkipped, Values, Chunks, Pages, BloomProbes, StatsChecked, StatsMissing, PrunedPages, ArrowValues;

    static void Fail(string what) => throw new Finding(what);

    // ---------------- Plank logical (runtime schema) ----------------

    public static void PlankLogical(IParquetReadSource source, Expected e, ParquetReaderOptions? options, bool checkMetadata)
    {
        using var reader = new ParquetReader(options);
        reader.Reset(source);
        var leaves = reader.Schema.LeafColumns;
        if (leaves.Length != e.Cols.Length)
            Fail($"leaf count {leaves.Length} != {e.Cols.Length}");
        long start = 0;
        var groups = reader.RowGroups;
        // Row groups without rows may or may not be written: compare the non-empty groups in order.
        long[]? nonEmpty = e.RowGroupSizes?.Where(s => s > 0).ToArray();
        var actualNonEmpty = new List<long>();
        foreach (RowGroup group in groups)
            if (group.RowCount > 0)
                actualNonEmpty.Add((long)group.RowCount);
        if (nonEmpty is not null && !nonEmpty.SequenceEqual(actualNonEmpty))
            Fail($"non-empty row groups [{string.Join(",", actualNonEmpty.Take(12))}..] ({actualNonEmpty.Count}) != expected [{string.Join(",", nonEmpty.Take(12))}..] ({nonEmpty.Length})");
        var g = 0;
        foreach (RowGroup group in groups)
        {
            var count = (long)group.RowCount;
            for (var c = 0; c < leaves.Length; c++)
                Column(group, leaves[c], e.Cols[c], e, start, count, checkMetadata, $"rg{g} col{c}({e.Cols[c].Name})");
            start += count;
            g++;
        }
        if (start != e.Rows)
            Fail($"file has {start} rows, expected {e.Rows}");
    }

    sealed class Acc(ColSpec spec)
    {
        public long Nulls;
        public bool Has;
        public byte[]? Min, Max; // plain bytes
        public bool OnlyNaN = true;

        public void Add(long r)
        {
            if (spec.IsNull(r)) { Nulls++; return; }
            if (spec.Kind == Kind.Double && double.IsNaN(spec.Double(r))) return;
            if (spec.Kind == Kind.Float && float.IsNaN(spec.Float(r))) return;
            OnlyNaN = false;
            var v = spec.PlainBytes(r);
            if (!Has) { Min = Max = v; Has = true; return; }
            if (Cmp(spec.Kind, v, Min!) < 0) Min = v;
            if (Cmp(spec.Kind, v, Max!) > 0) Max = v;
        }
    }

    public static int Cmp(Kind kind, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => kind switch
    {
        Kind.Int32 => BinaryPrimitives.ReadInt32LittleEndian(a).CompareTo(BinaryPrimitives.ReadInt32LittleEndian(b)),
        Kind.Int64 => BinaryPrimitives.ReadInt64LittleEndian(a).CompareTo(BinaryPrimitives.ReadInt64LittleEndian(b)),
        // Numeric compare: -0 == +0 (the sign of a zero bound is not checked).
        Kind.Double => BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(a))
            .CompareTo(BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(b))) is var x && Zero(a, b, 8) ? 0 : x,
        Kind.Float => BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(a))
            .CompareTo(BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(b))) is var y && Zero(a, b, 4) ? 0 : y,
        Kind.Bool => a[0].CompareTo(b[0]),
        _ => a.SequenceCompareTo(b),
    };

    static bool Zero(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, int width)
    {
        if (width == 8)
            return BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(a)) == 0
                && BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(b)) == 0;
        return BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(a)) == 0
            && BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(b)) == 0;
    }

    static void Column(RowGroup group, LeafColumn leaf, ColSpec spec, Expected e, long start, long count, bool meta, string where)
    {
        long read = spec.Kind switch
        {
            Kind.Int32 => spec.Optional ? ReadOpt<int>(group, leaf, spec, e, start, where, static (s, r) => s.Int32(r))
                                        : ReadReq<int>(group, leaf, spec, e, start, where, static (s, r) => s.Int32(r)),
            Kind.Int64 => spec.Optional ? ReadOpt<long>(group, leaf, spec, e, start, where, static (s, r) => s.Int64(r))
                                        : ReadReq<long>(group, leaf, spec, e, start, where, static (s, r) => s.Int64(r)),
            Kind.Double => spec.Optional ? ReadOpt<double>(group, leaf, spec, e, start, where, static (s, r) => s.Double(r))
                                         : ReadReq<double>(group, leaf, spec, e, start, where, static (s, r) => s.Double(r)),
            Kind.Float => spec.Optional ? ReadOpt<float>(group, leaf, spec, e, start, where, static (s, r) => s.Float(r))
                                        : ReadReq<float>(group, leaf, spec, e, start, where, static (s, r) => s.Float(r)),
            Kind.Bool => spec.Optional ? ReadOpt<bool>(group, leaf, spec, e, start, where, static (s, r) => s.Bool(r))
                                       : ReadReq<bool>(group, leaf, spec, e, start, where, static (s, r) => s.Bool(r)),
            _ => ReadBytes(group, leaf, spec, e, start, where),
        };
        if (read != count)
            Fail($"{where}: read {read} values, expected {count}");
        Chunks++;
        if (meta)
            Metadata(MetadataOf(group, leaf, spec), spec, e, start, count, where);
    }

    static ParquetColumnChunkMetadata MetadataOf(RowGroup group, LeafColumn leaf, ColSpec spec) => spec.Kind switch
    {
        Kind.Int32 => spec.Optional ? group.Column<int?>(leaf).Metadata : group.Column<int>(leaf).Metadata,
        Kind.Int64 => spec.Optional ? group.Column<long?>(leaf).Metadata : group.Column<long>(leaf).Metadata,
        Kind.Double => spec.Optional ? group.Column<double?>(leaf).Metadata : group.Column<double>(leaf).Metadata,
        Kind.Float => spec.Optional ? group.Column<float?>(leaf).Metadata : group.Column<float>(leaf).Metadata,
        Kind.Bool => spec.Optional ? group.Column<bool?>(leaf).Metadata : group.Column<bool>(leaf).Metadata,
        _ => group.Column<byte>(leaf).Metadata,
    };

    static bool Same<T>(T a, T b) where T : unmanaged
    {
        if (typeof(T) == typeof(double))
            return BitConverter.DoubleToInt64Bits((double)(object)a) == BitConverter.DoubleToInt64Bits((double)(object)b);
        if (typeof(T) == typeof(float))
            return BitConverter.SingleToInt32Bits((float)(object)a) == BitConverter.SingleToInt32Bits((float)(object)b);
        return EqualityComparer<T>.Default.Equals(a, b);
    }

    static long ReadReq<T>(RowGroup group, LeafColumn leaf, ColSpec spec, Expected e, long start, string where,
        Func<ColSpec, long, T> expected) where T : unmanaged
    {
        long i = 0;
        foreach (ColumnBuffer<T> buffer in group.Column<T>(leaf))
        {
            var values = buffer.Values;
            if (values.Length != buffer.Count)
                Fail($"{where}: buffer Values.Length {values.Length} != Count {buffer.Count}");
            for (var k = 0; k < values.Length; k++, i++)
            {
                var want = expected(spec, e.Row(start + i));
                if (!Same(values[k], want))
                    Fail($"{where}: row {start + i}: read {values[k]}, expected {want}");
            }
            Values += values.Length;
        }
        return i;
    }

    static long ReadOpt<T>(RowGroup group, LeafColumn leaf, ColSpec spec, Expected e, long start, string where,
        Func<ColSpec, long, T> expected) where T : unmanaged
    {
        long i = 0;
        foreach (ColumnBuffer<T?> buffer in group.Column<T?>(leaf))
        {
            var values = buffer.Values;
            for (var k = 0; k < buffer.Count; k++, i++)
            {
                var r = e.Row(start + i);
                var isNull = spec.IsNull(r);
                if (buffer.IsNull(k) != isNull || values[k].HasValue == isNull)
                    Fail($"{where}: row {start + i}: null {buffer.IsNull(k)}/{!values[k].HasValue}, expected {isNull}");
                if (!isNull && !Same(values[k]!.Value, expected(spec, r)))
                    Fail($"{where}: row {start + i}: read {values[k]}, expected {expected(spec, r)}");
            }
            Values += buffer.Count;
        }
        return i;
    }

    [ThreadStatic] static byte[]? t_scratch;

    public static ReadOnlySpan<byte> ExpectedBytes(ColSpec spec, long r)
    {
        var b = spec.Base(r);
        var length = spec.ByteLength(b);
        var scratch = t_scratch;
        if (scratch is null || scratch.Length < length)
            t_scratch = scratch = new byte[Math.Max(length, 1024)];
        spec.FillBytes(b, scratch.AsSpan(0, length));
        return scratch.AsSpan(0, length);
    }

    static long ReadBytes(RowGroup group, LeafColumn leaf, ColSpec spec, Expected e, long start, string where)
    {
        long i = 0;
        foreach (ColumnBuffer<byte> buffer in group.Column<byte>(leaf))
        {
            long payload = 0;
            for (var k = 0; k < buffer.Count; k++, i++)
            {
                var r = e.Row(start + i);
                var isNull = spec.IsNull(r);
                if (buffer.IsNull(k) != isNull)
                    Fail($"{where}: row {start + i}: null {buffer.IsNull(k)}, expected {isNull}");
                if (isNull)
                {
                    if (buffer.GetValue(k).Length != 0)
                        Fail($"{where}: row {start + i}: null value has {buffer.GetValue(k).Length} bytes");
                    continue;
                }
                var got = buffer.GetValue(k);
                var want = ExpectedBytes(spec, r);
                if (!got.SequenceEqual(want))
                    Fail($"{where}: row {start + i}: read {got.Length} bytes {Hex(got)}, expected {want.Length} bytes {Hex(want)}");
                payload += got.Length;
            }
            if (buffer.Values.Length != payload)
                Fail($"{where}: concatenated Values {buffer.Values.Length} bytes != sum of values {payload}");
            Values += buffer.Count;
        }
        return i;
    }

    public static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b[..Math.Min(b.Length, 24)]) + (b.Length > 24 ? ".." : "");

    // ---------------- statistics, page index, bloom ----------------

    static void Metadata(ParquetColumnChunkMetadata m, ColSpec spec, Expected e, long start, long count, string where)
    {
        if (m.ValueCount != (ulong)count)
            Fail($"{where}: chunk ValueCount {m.ValueCount} != {count}");
        var acc = new Acc(spec);
        for (long i = 0; i < count; i++)
            acc.Add(e.Row(start + i));
        CheckStats(m.Statistics, acc, spec, where + " chunk");

        if (m.HasOffsetIndex)
        {
            long next = 0;
            using var pageCollection = m.OpenPages();
            foreach (var page in pageCollection)
            {
                Pages++;
                if (page.FirstRowIndex is not { } first || page.RowCount is not { } rows)
                    Fail($"{where}: page {page.PageOrdinal} lacks FirstRowIndex/RowCount despite an offset index");
                else
                {
                    if ((long)first != next)
                        Fail($"{where}: page {page.PageOrdinal} FirstRowIndex {first}, expected {next}");
                    if (rows == 0)
                        Fail($"{where}: page {page.PageOrdinal} has 0 rows");
                    var pageAcc = new Acc(spec);
                    for (long i = 0; i < (long)rows; i++)
                        pageAcc.Add(e.Row(start + (long)first + i));
                    if (page.IsNullPage is true && pageAcc.Has)
                        Fail($"{where}: page {page.PageOrdinal} flagged null page but has values");
                    if (m.HasColumnIndex)
                        CheckStats(page.Statistics, pageAcc, spec, $"{where} page {page.PageOrdinal} [{first},+{rows})");
                    next += (long)rows;
                }
            }
            if (next != count)
                Fail($"{where}: offset index covers {next} rows, expected {count}");
        }

        if (m.HasBloomFilter)
        {
            using var bloom = m.OpenBloomFilter();
            var step = Math.Max(1, count / 200_000);
            for (long i = 0; i < count; i += step)
            {
                var r = e.Row(start + i);
                if (spec.IsNull(r))
                    continue;
                BloomProbes++;
                var hit = spec.Kind switch
                {
                    Kind.Int32 => bloom.MightContain(spec.Int32(r)),
                    Kind.Int64 => bloom.MightContain(spec.Int64(r)),
                    Kind.Double => bloom.MightContain(spec.Double(r)),
                    Kind.Float => bloom.MightContain(spec.Float(r)),
                    Kind.Bool => true,
                    _ => bloom.MightContain(ExpectedBytes(spec, r)),
                };
                if (!hit)
                    Fail($"{where}: Bloom filter false negative for row {start + i}");
            }
        }
    }

    static void CheckStats(ParquetStatistics s, Acc acc, ColSpec spec, string where)
    {
        if (s.NullCount is { } nulls && nulls != acc.Nulls)
            Fail($"{where}: null_count {nulls}, expected {acc.Nulls}");
        if (!s.HasMinimum || !s.HasMaximum)
        {
            if (acc.Has && !(spec.Kind is Kind.Bytes or Kind.String))
                StatsMissing++;
            if (acc.Has && (spec.Kind is Kind.Bytes or Kind.String))
                StatsMissing++;
            return;
        }
        StatsChecked++;
        if (!acc.Has)
        {
            if (acc.OnlyNaN && acc.Nulls == 0 && spec.Kind is Kind.Double or Kind.Float)
                return; // all-NaN chunks: bound policy left to the writer
            if (acc.OnlyNaN && spec.Kind is Kind.Double or Kind.Float)
                return;
            Fail($"{where}: min/max present for a chunk with no non-null values");
        }
        var min = s.Minimum;
        var max = s.Maximum;
        if (spec.Kind is Kind.Bytes or Kind.String)
        {
            var cMin = min.SequenceCompareTo(acc.Min);
            var cMax = max.SequenceCompareTo(acc.Max);
            if (s.IsMinimumExact ? cMin != 0 : cMin > 0)
                Fail($"{where}: min {Hex(min)} (exact={s.IsMinimumExact}) vs actual {Hex(acc.Min)}");
            if (s.IsMaximumExact ? cMax != 0 : cMax < 0)
                Fail($"{where}: max {Hex(max)} (exact={s.IsMaximumExact}) vs actual {Hex(acc.Max)}");
            return;
        }
        if (min.Length != acc.Min!.Length || max.Length != acc.Max!.Length)
            Fail($"{where}: bound widths {min.Length}/{max.Length}");
        if (Cmp(spec.Kind, min, acc.Min) != 0)
            Fail($"{where}: min {Hex(min)} != actual {Hex(acc.Min)}");
        if (Cmp(spec.Kind, max, acc.Max!) != 0)
            Fail($"{where}: max {Hex(max)} != actual {Hex(acc.Max!)}");
    }

    // ---------------- pruned + projected read ----------------

    /// <summary>
    /// Reads a random projection with a random page pruner; values returned for a column must be exactly the
    /// rows of the pages the pruner kept (pages with row ranges from the offset index), in order.
    /// </summary>
    public static void PlankPruned(IParquetReadSource source, Expected e, Rng rng)
    {
        // Projection: a random non-empty subset, in a random order (the reader binds by name).
        var picked = Enumerable.Range(0, e.Cols.Length).Where(_ => rng.Chance(50)).ToList();
        if (picked.Count == 0)
            picked.Add(rng.Int(e.Cols.Length));
        var order = picked.OrderBy(_ => rng.Next()).ToArray();
        var schema = new ParquetSchema([.. order.Select(i => e.Cols[i].Definition())]);
        var keepPercent = rng.Pick(0, 10, 50, 90, 100);
        var pruneSeed = rng.Next();
        var kept = new Dictionary<(int Group, string Path, int Page), (long First, long Rows, bool Keep)>();
        bool Pruner(in ParquetDataPageMetadata page)
        {
            var path = page.Statistics.Definition.Path;
            var keep = page.FirstRowIndex is null || (int)(Rng.Mix(pruneSeed ^ (ulong)page.PageOrdinal * 31 ^ (ulong)page.RowGroupIndex * 1_000_003 ^ (ulong)path.GetHashCode()) % 100) < keepPercent;
            lock (kept)
                kept[(page.RowGroupIndex, path, page.PageOrdinal)] = ((long)(page.FirstRowIndex ?? 0UL), (long)(page.RowCount ?? 0UL), keep);
            if (!keep)
                PrunedPages++;
            return keep;
        }
        using var reader = schema.CreateReader(source, null, Pruner);
        long start = 0;
        foreach (RowGroup group in reader.RowGroups)
        {
            var count = (long)group.RowCount;
            for (var k = 0; k < order.Length; k++)
            {
                var spec = e.Cols[order[k]];
                var leaf = reader.Schema.LeafColumns[k];
                var got = new List<ulong>();
                Fingerprints(group, leaf, spec, got);
                // Expected: kept pages of this column, in page order; when no page was seen, every row.
                var pages = kept.Where(p => p.Key.Group == group.Index && p.Key.Path == leaf.Path)
                    .OrderBy(p => p.Key.Page).Select(p => p.Value).ToList();
                var want = new List<ulong>();
                if (pages.Count == 0 || pages.All(p => p.Rows == 0))
                {
                    if (pages.Count == 0 || pages.All(p => p.Keep))
                        for (long i = 0; i < count; i++) want.Add(Fp(spec, e.Row(start + i)));
                    else
                        want = null;
                }
                else
                    foreach (var p in pages.Where(p => p.Keep))
                        for (long i = 0; i < p.Rows; i++) want.Add(Fp(spec, e.Row(start + p.First + i)));
                if (want is not null)
                {
                    if (got.Count != want.Count)
                        Fail($"pruned rg{group.Index} {leaf.Path}: read {got.Count} values, kept pages hold {want.Count} (keep={keepPercent}%, pages={pages.Count})");
                    for (var i = 0; i < got.Count; i++)
                        if (got[i] != want[i])
                            Fail($"pruned rg{group.Index} {leaf.Path}: value {i} differs (keep={keepPercent}%)");
                }
            }
            start += count;
        }
    }

    public static ulong Fp(ColSpec spec, long r)
    {
        if (spec.IsNull(r))
            return 0x9E37_79B9_0000_0001UL;
        return spec.Kind switch
        {
            Kind.Int32 => (ulong)spec.Int32(r),
            Kind.Int64 => (ulong)spec.Int64(r),
            Kind.Double => (ulong)BitConverter.DoubleToInt64Bits(spec.Double(r)),
            Kind.Float => (ulong)BitConverter.SingleToInt32Bits(spec.Float(r)),
            Kind.Bool => spec.Bool(r) ? 1UL : 2UL,
            _ => FpBytes(ExpectedBytes(spec, r)),
        };
    }

    static ulong FpBytes(ReadOnlySpan<byte> b)
    {
        var h = 0xCBF29CE484222325UL ^ (ulong)b.Length;
        foreach (var x in b)
            h = (h ^ x) * 0x100000001B3UL;
        return Rng.Mix(h);
    }

    static void Fingerprints(RowGroup group, LeafColumn leaf, ColSpec spec, List<ulong> into)
    {
        const ulong nul = 0x9E37_79B9_0000_0001UL;
        switch (spec.Kind, spec.Optional)
        {
            case (Kind.Int32, false): foreach (var b in group.Column<int>(leaf)) foreach (var v in b.Values) into.Add((ulong)v); break;
            case (Kind.Int32, true): foreach (var b in group.Column<int?>(leaf)) foreach (var v in b.Values) into.Add(v is { } x ? (ulong)x : nul); break;
            case (Kind.Int64, false): foreach (var b in group.Column<long>(leaf)) foreach (var v in b.Values) into.Add((ulong)v); break;
            case (Kind.Int64, true): foreach (var b in group.Column<long?>(leaf)) foreach (var v in b.Values) into.Add(v is { } x ? (ulong)x : nul); break;
            case (Kind.Double, false): foreach (var b in group.Column<double>(leaf)) foreach (var v in b.Values) into.Add((ulong)BitConverter.DoubleToInt64Bits(v)); break;
            case (Kind.Double, true): foreach (var b in group.Column<double?>(leaf)) foreach (var v in b.Values) into.Add(v is { } x ? (ulong)BitConverter.DoubleToInt64Bits(x) : nul); break;
            case (Kind.Float, false): foreach (var b in group.Column<float>(leaf)) foreach (var v in b.Values) into.Add((ulong)BitConverter.SingleToInt32Bits(v)); break;
            case (Kind.Float, true): foreach (var b in group.Column<float?>(leaf)) foreach (var v in b.Values) into.Add(v is { } x ? (ulong)BitConverter.SingleToInt32Bits(x) : nul); break;
            case (Kind.Bool, false): foreach (var b in group.Column<bool>(leaf)) foreach (var v in b.Values) into.Add(v ? 1UL : 2UL); break;
            case (Kind.Bool, true): foreach (var b in group.Column<bool?>(leaf)) foreach (var v in b.Values) into.Add(v is { } x ? (x ? 1UL : 2UL) : nul); break;
            default:
                foreach (var b in group.Column<byte>(leaf))
                    for (var k = 0; k < b.Count; k++)
                        into.Add(b.IsNull(k) ? nul : FpBytes(b.GetValue(k)));
                break;
        }
    }

    // ---------------- ParquetSharp (Arrow C++) ----------------

    public static unsafe void Arrow(string path, Expected e)
    {
        using var file = new Ps.ParquetFileReader(path);
        var meta = file.FileMetaData;
        // Known Plank defect (fuzz/repros/page-header-untruncated-statistics): binary min/max are never truncated, so a
        // page with a value of 8 MB+ gets a page header above Arrow's 16 MB limit. Skip exactly those chunks.
        using var plankPhysical = new Plank.Reading.Physical.ParquetFileReader();
        using var plankStream = File.OpenRead(path);
        plankPhysical.Reset(plankStream);
        bool HugeHeader(int g, int c)
        {
            if (e.Cols[c].Kind is not (Kind.Bytes or Kind.String) || Math.Max(e.Cols[c].L1, e.Cols[c].L2) < (4 << 20))
                return false;
            foreach (var page in plankPhysical.OpenPages(g, c))
                if (page.Header.HeaderLength > 16 << 20)
                    return true;
            return false;
        }
        if (meta.NumRows != e.Rows)
            Fail($"arrow: file has {meta.NumRows} rows, expected {e.Rows}");
        if (meta.NumColumns != e.Cols.Length)
            Fail($"arrow: {meta.NumColumns} columns");
        long start = 0;
        for (var g = 0; g < meta.NumRowGroups; g++)
        {
            using var group = file.RowGroup(g);
            var rows = group.MetaData.NumRows;
            for (var c = 0; c < e.Cols.Length; c++)
            {
                var spec = e.Cols[c];
                var where = $"arrow rg{g} col{c}({spec.Name})";
                // Arrow C++ (ParquetSharp 24) has no ALP decoder: such chunks report an Undefined encoding.
                using (var chunkMeta = group.MetaData.GetColumnChunkMetaData(c))
                    if (chunkMeta.Encodings.Contains(Ps.Encoding.Undefined))
                    {
                        ArrowSkipped++;
                        continue;
                    }
                if (HugeHeader(g, c))
                {
                    ArrowSkippedHugeHeader++;
                    continue;
                }
                using var column = group.Column(c);
                long read = spec.Kind switch
                {
                    Kind.Int32 => ArrowRead((Ps.ColumnReader<int>)column, spec, e, start, where, static (s, r, v) => s.Int32(r) == v),
                    Kind.Int64 => ArrowRead((Ps.ColumnReader<long>)column, spec, e, start, where, static (s, r, v) => s.Int64(r) == v),
                    Kind.Double => ArrowRead((Ps.ColumnReader<double>)column, spec, e, start, where, static (s, r, v) => BitConverter.DoubleToInt64Bits(s.Double(r)) == BitConverter.DoubleToInt64Bits(v)),
                    Kind.Float => ArrowRead((Ps.ColumnReader<float>)column, spec, e, start, where, static (s, r, v) => BitConverter.SingleToInt32Bits(s.Float(r)) == BitConverter.SingleToInt32Bits(v)),
                    Kind.Bool => ArrowRead((Ps.ColumnReader<bool>)column, spec, e, start, where, static (s, r, v) => s.Bool(r) == v),
                    _ => ArrowRead((Ps.ColumnReader<Ps.ByteArray>)column, spec, e, start, where,
                        static (s, r, v) => new ReadOnlySpan<byte>((void*)v.Pointer, v.Length).SequenceEqual(ExpectedBytes(s, r))),
                };
                if (read != rows)
                    Fail($"{where}: read {read} rows, expected {rows}");
            }
            start += rows;
        }
        if (start != e.Rows)
            Fail($"arrow: {start} rows");
    }

    static long ArrowRead<T>(Ps.ColumnReader<T> reader, ColSpec spec, Expected e, long start, string where,
        Func<ColSpec, long, T, bool> equal) where T : unmanaged
    {
        var values = new T[4096];
        var defs = new short[values.Length];
        long i = 0;
        while (reader.HasNext)
        {
            var levels = reader.ReadBatch(values.Length, defs, null, values, out var valuesRead);
            if (levels == 0)
                Fail($"{where}: ParquetSharp made no progress");
            var next = 0;
            for (var k = 0; k < levels; k++, i++)
            {
                var r = e.Row(start + i);
                var isNull = spec.Optional && defs[k] == 0;
                if (isNull != spec.IsNull(r))
                    Fail($"{where}: row {start + i}: arrow null {isNull}, expected {spec.IsNull(r)}");
                if (isNull)
                    continue;
                if (!equal(spec, r, values[next]))
                    Fail($"{where}: row {start + i}: arrow value {values[next]} differs from expected");
                next++;
            }
            if (next != valuesRead)
                Fail($"{where}: ParquetSharp value count mismatch");
            ArrowValues += levels;
        }
        return i;
    }
}
