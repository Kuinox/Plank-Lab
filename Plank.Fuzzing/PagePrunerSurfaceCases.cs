using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;
using RowGroup = Plank.Reading.Logical.RowGroup;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Route 0xC6 "PRN1": page pruning, page metadata and Reset/reuse of <see cref="ParquetReader"/> with
/// fuzzer-chosen pruners. A wrong prune silently drops rows, so every pruned read is compared with the
/// unfiltered read of the same file:
/// <list type="bullet">
/// <item>a pruner keeping a fuzzer-chosen subset of pages must return exactly the rows of those pages
///   (positions come from the metadata the callback itself was handed);</item>
/// <item>a pruner built from the page statistics (min/max/IsNullPage) that skips pages which cannot hold a
///   probe value must still return every row equal to that value;</item>
/// <item>accept-all equals the plain read, reject-all returns nothing, a reader Reset between plain and pruned
///   scans (stream and IParquetReadSource overloads, same reader instance) must give identical results;</item>
/// <item>OpenPages() metadata is consistent (ordinals, contiguous row ranges that sum to the row-group row count,
///   indexer vs enumerator, Count, boundary-order enum, IsNullPage vs actual values).</item>
/// </list>
/// Page size, row-group split, compression, page version, page indexes, CRC, encoding, optionality, value
/// pattern and the probe are all drawn independently.
/// </summary>
internal static class PagePrunerSurfaceCases
{
    internal const byte Marker = 0xC6;
    internal static ReadOnlySpan<byte> Magic => "PRN1"u8;

    static long _runs, _pagesChecked, _subsetPages, _prunedAway, _probeRows;

    static PagePrunerSurfaceCases()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"PRN1 runs={_runs} pages={_pagesChecked} subsetPages={_subsetPages} prunedAway={_prunedAway} probeRowsKept={_probeRows}");
    }

    sealed class Cur(ReadOnlySpan<byte> data)
    {
        readonly byte[] _d = data.ToArray();
        int _i;
        public byte Byte() => _d.Length == 0 ? (byte)0 : _d[_i++ % _d.Length];
        public int Int(int min, int maxExclusive)
        {
            uint v = Byte();
            v |= (uint)Byte() << 8;
            v |= (uint)Byte() << 16;
            v |= (uint)Byte() << 24;
            return min + (int)(v % (uint)(maxExclusive - min));
        }
        public T Pick<T>(params T[] choices) => choices[Int(0, choices.Length)];
    }

    sealed record PageSeen(int Ordinal, ulong? First, ulong? Count, bool? Null, bool HasMin, bool HasMax, byte[] Min, byte[] Max,
        int GroupIndex, ulong Offset, uint Size);

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        _runs++;
        var c = new Cur(data);
        var binary = c.Int(0, 3) == 0;
        var optional = c.Int(0, 2) == 0;
        var rows = c.Pick(1, 2, 3, 7, 31, 100, 500, 1000, 3000);
        var groups = Math.Min(rows, c.Int(1, 4));
        var pageBytes = c.Pick(32u, 64u, 100u, 256u, 1000u, 8192u, 1024u * 1024);
        var compression = c.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Gzip, CompressionKind.Zstd,
            CompressionKind.Lz4);
        var version = c.Int(0, 2) == 0 ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2;
        var indexes = c.Int(0, 4) != 0;
        var crc = c.Int(0, 3) == 0;
        var encoding = binary
            ? c.Pick(EncodingKind.Plain, EncodingKind.RleDictionary, EncodingKind.DeltaLengthByteArray)
            : c.Pick(EncodingKind.Plain, EncodingKind.RleDictionary, EncodingKind.DeltaBinaryPacked);
        var pattern = c.Int(0, 4); // ascending, descending, few distinct, random
        var nullEvery = c.Pick(2, 3, 5, 50);
        var nullRun = c.Int(0, 3) == 0; // long null runs make all-null pages

        var keys = new long?[rows];
        long state = c.Int(0, 1 << 30);
        for (var i = 0; i < rows; i++)
        {
            state = unchecked(state * 6364136223846793005L + 1442695040888963407L + c.Byte());
            keys[i] = pattern switch
            {
                0 => i,
                1 => rows - i,
                2 => (state >> 33) % 5,
                _ => state >> 20
            };
            if (optional && (nullRun ? (i / nullEvery) % 2 == 1 : i % nullEvery == nullEvery - 1))
                keys[i] = null;
        }

        var options = new ParquetWriterOptions
        {
            Compression = compression,
            DataPageVersion = version,
            TargetDataPageSizeBytes = pageBytes,
            WritePageIndexes = indexes,
            WritePageCrc = crc
        };
        var definition = ColumnDefinition.Leaf("k", binary ? ParquetPhysicalType.ByteArray : ParquetPhysicalType.Int64,
            new ColumnOptions(optional ? ParquetRepetition.Optional : ParquetRepetition.Required,
                ImmutableArray.Create(encoding)), pageStrategy: null);
        var schema = new PlankSchema([definition]);
        var cutSet = new SortedSet<int> { 0, rows };
        while (cutSet.Count < groups + 1)
            cutSet.Add(c.Int(1, rows));
        var bounds = cutSet.ToArray();

        byte[] file;
        using (var stream = new MemoryStream())
        {
            var writer = schema.CreateWriter(stream, options);
            for (var g = 0; g + 1 < bounds.Length; g++)
            {
                var group = writer.StartRowGroup();
                var slice = keys.AsSpan(bounds[g], bounds[g + 1] - bounds[g]).ToArray();
                if (binary)
                {
                    if (optional)
                    {
                        var col = group.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
                        col.Serialize(slice.Select(static k => k is { } v ? (ReadOnlyMemory<byte>?)Text(v) : null).ToArray());
                        group.Write(col);
                    }
                    else
                    {
                        var col = group.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
                        col.Serialize(slice.Select(static k => (ReadOnlyMemory<byte>)Text(k!.Value)).ToArray());
                        group.Write(col);
                    }
                }
                else if (optional)
                {
                    var col = group.CreateSerializedColumn<long?>(schema.LeafColumns[0]);
                    col.Serialize(slice);
                    group.Write(col);
                }
                else
                {
                    var col = group.CreateSerializedColumn<long>(schema.LeafColumns[0]);
                    col.Serialize(slice.Select(static k => k!.Value).ToArray());
                    group.Write(col);
                }
            }

            writer.CloseFile();
            file = stream.ToArray();
        }

        var what = $"PRN1 binary={binary} optional={optional} rows={rows} groups={bounds.Length - 1} page={pageBytes} {compression} {version} idx={indexes} enc={encoding}";

        // One reader instance reused for the plain scan, then each pruned scan via Reset (both overloads).
        using var reader = new ParquetReader();
        reader.Reset(new MemoryStream(file, writable: false));
        var leaf = reader.Schema.LeafColumns[0];
        var plain = new List<string?[]>();
        var pageMeta = new List<PageSeen[]>();
        for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            plain.Add(ReadKeys(reader.RowGroups[g], leaf, binary, optional));
            pageMeta.Add(OpenPagesChecked(what, reader.RowGroups[g], g, plain[g], indexes, binary));
        }

        if (reader.RowGroups.Count != bounds.Length - 1)
            throw new InvalidOperationException($"{what}: group count {reader.RowGroups.Count} != {bounds.Length - 1}.");
        for (var g = 0; g < plain.Count; g++)
            for (var i = 0; i < plain[g].Length; i++)
                if (plain[g][i] != Expect(keys[bounds[g] + i], binary))
                    throw new InvalidOperationException($"{what}: plain read differs at group {g} row {i}.");

        // 1. accept all / reject all.
        var accept = ReadAllGroups(file, binary, optional, _ => true, useSource: c.Int(0, 2) == 0, reader, what).Values;
        for (var g = 0; g < plain.Count; g++)
            Require(what + " accept-all", plain[g], accept[g]);
        var reject = ReadAllGroups(file, binary, optional, _ => false, useSource: c.Int(0, 2) == 0, reader, what);
        for (var g = 0; g < reject.Values.Count; g++)
            if (reject.Values[g].Length != 0)
                throw new InvalidOperationException($"{what}: reject-all scan returned {reject.Values[g].Length} rows in group {g}.");

        // 2. fuzzer-chosen page subset.
        var maskBits = (ulong)c.Int(0, int.MaxValue) | ((ulong)c.Int(0, int.MaxValue) << 31);
        var modulus = c.Pick(1, 2, 3, 5, 64);
        Func<PageSeen, bool> mask = p => ((maskBits >> ((p.Ordinal + p.GroupIndex) % modulus % 63)) & 1) != 0;
        var subset = ReadAllGroups(file, binary, optional, mask, useSource: c.Int(0, 2) == 0, reader, what);
        for (var g = 0; g < subset.Values.Count; g++)
        {
            var seen = subset.Seen[g].OrderBy(static p => p.Ordinal).ToArray();
            if (seen.Any(static p => p.First is null || p.Count is null) || seen.Length == 0)
            {
                // no row positions available (no offset index): the pruned rows must be a subsequence of the plain rows.
                if (!IsSubsequence(subset.Values[g], plain[g]))
                    throw new InvalidOperationException($"{what}: pruned rows of group {g} are not a subsequence of the plain rows.");
                continue;
            }

            CheckSeen(what, seen, pageMeta[g], plain[g].Length, g);
            var expected = new List<string?>();
            foreach (var p in seen)
                if (mask(p))
                    for (var r = (int)p.First!.Value; r < (int)(p.First.Value + p.Count!.Value); r++)
                        expected.Add(plain[g][r]);
            _subsetPages += seen.Length;
            _prunedAway += seen.Count(p => !mask(p));
            Require($"{what} subset mask={maskBits:x} mod={modulus} group {g}", expected.ToArray(), subset.Values[g]);
        }

        // 3. statistics predicate: no row equal to the probe may be pruned away.
        var probeRow = c.Int(0, rows);
        var probeKey = c.Int(0, 3) == 0 ? c.Int(-2, rows + 3) : (keys[probeRow] ?? 0);
        var probe = Expect(probeKey, binary)!;
        var probeBytes = binary ? Text(probeKey) : BitConverter.GetBytes((long)probeKey);
        Func<PageSeen, bool> statistics = p =>
        {
            if (p.Null == true)
                return false;
            if (p.HasMin && p.HasMax && !(Compare(p.Min, probeBytes, binary) <= 0 && Compare(probeBytes, p.Max, binary) <= 0))
                return false;
            return true;
        };
        var stat = ReadAllGroups(file, binary, optional, statistics, useSource: c.Int(0, 2) == 0, reader, what);
        for (var g = 0; g < stat.Values.Count; g++)
        {
            var wanted = plain[g].Count(v => v == probe);
            var got = stat.Values[g].Count(v => v == probe);
            _probeRows += got;
            if (wanted != got)
                throw new InvalidOperationException(
                    $"{what}: statistics pruner for probe {probeKey} dropped matching rows in group {g}: {got} of {wanted} returned.");
        }

        // 4. the reused reader still reads the plain file after all the pruned resets.
        reader.Reset(new MemoryStream(file, writable: false));
        for (var g = 0; g < reader.RowGroups.Count; g++)
            Require(what + " after resets", plain[g], ReadKeys(reader.RowGroups[g], reader.Schema.LeafColumns[0], binary, optional));
    }

    static byte[] Text(long v) => System.Text.Encoding.ASCII.GetBytes(v.ToString("D20", System.Globalization.CultureInfo.InvariantCulture));

    static string? Expect(long? key, bool binary)
        => key is null ? null : binary ? Convert.ToHexString(Text(key.Value)) : key.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);

    static string?[] ReadKeys(RowGroup group, LeafColumn leaf, bool binary, bool optional)
    {
        var list = new List<string?>();
        if (binary)
        {
            foreach (var buffer in group.Column<byte>(leaf))
                for (var i = 0; i < buffer.Count; i++)
                    list.Add(buffer.IsNull(i) ? null : Convert.ToHexString(buffer.GetValue(i)));
        }
        else if (optional)
        {
            foreach (var buffer in group.Column<long?>(leaf))
                foreach (var v in buffer.Values)
                    list.Add(v?.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        else
        {
            foreach (var buffer in group.Column<long>(leaf))
                foreach (var v in buffer.Values)
                    list.Add(v.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        return list.ToArray();
    }

    sealed record Scan(List<string?[]> Values, List<List<PageSeen>> Seen);

    static Scan ReadAllGroups(byte[] file, bool binary, bool optional, Func<PageSeen, bool> keep, bool useSource,
        ParquetReader shared, string what)
    {
        var seen = new List<List<PageSeen>>();
        var values = new List<string?[]>();
        var groupSeen = new Dictionary<(int, int), PageSeen>();
        ParquetPagePruner pruner = (in ParquetDataPageMetadata page) =>
        {
            var s = Snapshot(page);
            lock (groupSeen)
                groupSeen[(s.GroupIndex, s.Ordinal)] = s;
            return keep(s);
        };
        // Alternate between the shared (reused) reader and a fresh one: both must behave identically.
        if (useSource)
            shared.Reset(FullValueOracle.Source(file), pruner);
        else
            shared.Reset(new MemoryStream(file, writable: false), pruner);
        for (var g = 0; g < shared.RowGroups.Count; g++)
        {
            values.Add(ReadKeys(shared.RowGroups[g], shared.Schema.LeafColumns[0], binary, optional));
            seen.Add(groupSeen.Where(kv => kv.Key.Item1 == g).Select(static kv => kv.Value).ToList());
        }

        return new Scan(values, seen);
    }

    static PageSeen Snapshot(in ParquetDataPageMetadata page)
    {
        var s = page.Statistics;
        return new PageSeen(page.PageOrdinal, page.FirstRowIndex, page.RowCount, page.IsNullPage,
            s.HasMinimum, s.HasMaximum, s.HasMinimum ? s.Minimum.ToArray() : [], s.HasMaximum ? s.Maximum.ToArray() : [],
            page.RowGroupIndex, page.Offset, page.CompressedSize);
    }

    static int Compare(byte[] a, byte[] b, bool binary)
    {
        if (binary)
            return a.AsSpan().SequenceCompareTo(b);
        if (a.Length != 8 || b.Length != 8)
            return 0; // not comparable: keep the page
        return BitConverter.ToInt64(a).CompareTo(BitConverter.ToInt64(b));
    }

    static PageSeen[] OpenPagesChecked(string what, RowGroup group, int groupIndex, string?[] plain, bool indexes, bool binary)
    {
        using var pages = group.GetColumnMetadata(0).OpenPages();
        var list = new List<PageSeen>();
        foreach (var page in pages)
            list.Add(Snapshot(page));
        if (list.Count != pages.Count)
            throw new InvalidOperationException($"{what}: OpenPages Count {pages.Count} != enumerated {list.Count}.");
        for (var i = 0; i < pages.Count; i++)
        {
            var viaIndexer = Snapshot(pages[i]);
            if (viaIndexer != list[i] && !(viaIndexer.Min.AsSpan().SequenceEqual(list[i].Min) && viaIndexer.Max.AsSpan().SequenceEqual(list[i].Max)
                    && viaIndexer.Ordinal == list[i].Ordinal && viaIndexer.First == list[i].First && viaIndexer.Count == list[i].Count))
                throw new InvalidOperationException($"{what}: OpenPages indexer {i} differs from the enumerator.");
        }

        foreach (var bad in new[] { -1, pages.Count })
        {
            try
            {
                _ = pages[bad];
                throw new InvalidOperationException($"{what}: OpenPages[{bad}] did not throw.");
            }
            catch (Exception error) when (error is ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
            }
        }

        _ = pages.BoundaryOrder;
        var metadata = group.GetColumnMetadata(0);
        if (indexes && !metadata.HasOffsetIndex)
            throw new InvalidOperationException($"{what}: WritePageIndexes=true but HasOffsetIndex is false.");
        var array = list.ToArray();
        _pagesChecked += array.Length;
        CheckSeen(what, array, array, plain.Length, groupIndex);
        foreach (var p in array)
            if (p.GroupIndex != groupIndex)
                throw new InvalidOperationException($"{what}: page metadata RowGroupIndex {p.GroupIndex} != {groupIndex}.");
        // an all-null page must really be all null
        if (array.All(static p => p.First is not null && p.Count is not null))
            foreach (var p in array.Where(static p => p.Null == true))
                for (var r = (int)p.First!.Value; r < (int)(p.First.Value + p.Count!.Value); r++)
                    if (plain[r] is not null)
                        throw new InvalidOperationException($"{what}: page {p.Ordinal} is flagged IsNullPage but row {r} has a value.");
        return array;
    }

    // Offered pages must be an ordinal-consistent, contiguous, non-overlapping partition of the row group.
    static void CheckSeen(string what, PageSeen[] seen, PageSeen[] reference, int rowCount, int group)
    {
        for (var i = 0; i < seen.Length; i++)
        {
            if (seen[i].Ordinal < 0 || seen[i].Ordinal >= reference.Length)
                throw new InvalidOperationException($"{what}: group {group} pruner saw page ordinal {seen[i].Ordinal} of {reference.Length}.");
            var r = reference[seen[i].Ordinal];
            if (r.First != seen[i].First || r.Count != seen[i].Count)
                throw new InvalidOperationException($"{what}: group {group} page {seen[i].Ordinal} row range differs between OpenPages and the pruner callback.");
        }

        if (reference.Length == 0 || reference.Any(static p => p.First is null || p.Count is null))
            return;
        ulong next = 0;
        foreach (var p in reference.OrderBy(static p => p.Ordinal))
        {
            if (p.First != next)
                throw new InvalidOperationException($"{what}: group {group} page {p.Ordinal} starts at {p.First}, expected {next}.");
            next += p.Count!.Value;
        }

        if (next != (ulong)rowCount)
            throw new InvalidOperationException($"{what}: group {group} page row counts sum to {next}, row group has {rowCount}.");
    }

    static bool IsSubsequence(string?[] part, string?[] whole)
    {
        var w = 0;
        foreach (var v in part)
        {
            while (w < whole.Length && whole[w] != v)
                w++;
            if (w == whole.Length)
                return false;
            w++;
        }

        return true;
    }

    static void Require(string what, string?[] expected, string?[] actual)
    {
        if (expected.Length != actual.Length)
            throw new InvalidOperationException($"{what}: {actual.Length} rows, expected {expected.Length}.");
        for (var i = 0; i < expected.Length; i++)
            if (expected[i] != actual[i])
                throw new InvalidOperationException($"{what}: row {i} is '{actual[i]}', expected '{expected[i]}'.");
    }
}
