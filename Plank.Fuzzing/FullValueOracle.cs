using System.Buffers.Binary;
using System.IO.Hashing;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;
using Ps = ParquetSharp;

namespace Plank.Fuzzing;

/// <summary>
/// Differential oracle for everything around the values: schema, row counts, key/value
/// metadata, sorting columns, statistics, page indexes and Bloom filters, checked against
/// Apache Arrow (ParquetSharp) and against values decoded by Arrow, never against Plank's
/// own reader alone.
/// </summary>
/// <remarks>
/// Almost every other check in this project is a Plank-to-Plank round trip, which cannot see
/// a defect that is symmetric in Plank's writer and reader: a statistic computed with the
/// wrong sort order and trusted the same wrong way, a Bloom filter hashed with the wrong
/// bytes on both sides, a page index whose row ranges are off by one in both directions.
///
/// Two entry points:
/// <list type="bullet">
/// <item><see cref="VerifyAccepted"/> (reader target): the bytes are fuzzed, so footer
/// contents may be nonsense; only compares Plank's view of the footer with Arrow's view of
/// the same footer, plus spec consistency of the Bloom filter probes.</item>
/// <item><see cref="VerifyWritten"/> (writer routes): the bytes were produced by Plank's
/// writer, so they must be valid. Arrow must read them; Plank's and Arrow's decoded values
/// must agree; and every piece of metadata Plank wrote must agree with the values Arrow
/// decoded (statistics, null counts, distinct counts, column/offset index, Bloom membership
/// computed with the specification's hash, declared sort order, row and value counts).</item>
/// </list>
/// Oracle capability gaps are listed explicitly in <see cref="IsArrowCapabilityGap"/>; value
/// and metadata mismatches are never suppressed.
/// </remarks>
public static class FullValueOracle
{
    public static long CheckedFiles, CheckedWrittenFiles, CheckedStatistics, CheckedPages, CheckedBloomValues,
        CheckedSortedRows;

    static readonly bool Disabled = Environment.GetEnvironmentVariable("PLANK_FUZZ_FULL_ORACLE") == "0";

    // ---- Entry points ------------------------------------------------------

    /// <summary>A writer route reads its own file back: check it first, then hand back the source.</summary>
    public static MemoryReadSource Source(ReadOnlyMemory<byte> bytes)
    {
        VerifyWritten(bytes);
        return new MemoryReadSource(bytes);
    }

    /// <summary>Same as <see cref="Source"/> for routes that read through a stream.</summary>
    public static byte[] Checked(byte[] bytes)
    {
        VerifyWritten(bytes);
        return bytes;
    }

    [ThreadStatic] static HashSet<ulong>? _seen;

    /// <summary>
    /// <c>ParquetWriterOptions.SortingColumns</c> is the caller's declaration (Plank does not
    /// check it), and routes declare orders over unsorted data. Only where Plank decides the
    /// declaration itself (appending, merging) is it a claim the rows must satisfy; those
    /// routes set this around their reads.
    /// </summary>
    [ThreadStatic] public static bool SortDeclarationsAreClaims;

    /// <summary>
    /// Checks a file Plank's writer produced. Files Plank itself does not read in full are
    /// left to the route (some routes damage their output on purpose to test the reader).
    /// </summary>
    public static void VerifyWritten(ReadOnlyMemory<byte> bytes)
    {
        if (Disabled || bytes.Length < 12 || bytes.Length > 32 << 20)
            return;
        // Routes read the same file several times; check it once.
        var seen = _seen ??= [];
        if (seen.Count > 4096)
            seen.Clear();
        if (!seen.Add(XxHash64.HashToUInt64(bytes.Span)))
            return;

        var file = bytes.ToArray();
        using var plank = new ParquetReader();
        var traces = new List<ColumnTrace?[]>();
        try
        {
            plank.Reset(new MemoryReadSource(file));
            foreach (var group in plank.RowGroups)
            {
                var groupTraces = new ColumnTrace?[plank.Schema.LeafColumns.Length];
                traces.Add(groupTraces);
                for (var c = 0; c < groupTraces.Length; c++)
                {
                    try
                    {
                        groupTraces[c] = ColumnTrace.CapturePlank(group, plank.Schema.LeafColumns[c]);
                    }
                    catch (InvalidOperationException)
                    {
                        // An API refusal for this column shape, not a file verdict.
                    }
                }
            }
        }
        catch (Exception error) when (error is CorruptParquetException or NotSupportedException
                                          or InvalidOperationException)
        {
            // Not a file Plank accepts; the route judges it.
            return;
        }

        CheckedWrittenFiles++;
        try
        {
            VerifyWrittenCore(file, plank, traces);
        }
        catch (ReaderAcceptanceMismatchException mismatch)
        {
            // Routes may catch broadly around their own reads; make the finding visible anyway.
            var name = "";
            if (Environment.GetEnvironmentVariable("PLANK_FUZZ_ORACLE_DUMP") is { Length: > 0 } dump)
            {
                Directory.CreateDirectory(dump);
                name = Path.Combine(dump, $"written-{XxHash64.HashToUInt64(file):x16}.parquet");
                File.WriteAllBytes(name, file);
            }
            Console.Error.WriteLine("ORACLE\twritten\t" + (mismatch.InnerException?.Message ?? mismatch.Message)
                .Replace('\n', ' ') + (name.Length > 0 ? "\t" + name : ""));
            throw;
        }
    }

    /// <summary>
    /// Reader target, file-schema route, after Plank decoded every column: compares the
    /// metadata Plank exposes with Arrow's reading of the same footer.
    /// </summary>
    public static void VerifyAccepted(byte[] fileBytes, ParquetReader plank)
    {
        if (Disabled)
            return;
        Ps.ParquetFileReader arrow;
        try
        {
            arrow = new Ps.ParquetFileReader(new MemoryStream(fileBytes, writable: false), leaveOpen: false);
        }
        catch (Exception error) when (error is Ps.ParquetException or ArgumentOutOfRangeException
                                          or OverflowException)
        {
            // Acceptance differences are ReaderAcceptanceOracle's business.
            return;
        }

        using (arrow)
        {
            try
            {
                CompareMetadata(plank, arrow, strict: false, values: null);
            }
            catch (Ps.ParquetException)
            {
                // Arrow could not parse a metadata structure Plank parsed: not a value verdict.
            }
        }
        CheckedFiles++;
    }

    // ---- Writer-side verification ------------------------------------------

    static void VerifyWrittenCore(byte[] file, ParquetReader plank, List<ColumnTrace?[]> traces)
    {
        Ps.ParquetFileReader arrow;
        try
        {
            arrow = new Ps.ParquetFileReader(new MemoryStream(file, writable: false), leaveOpen: false);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw Mismatch("written: Arrow cannot open a file Plank wrote and reads", error.Message, error);
        }

        using (arrow)
        {
            var leaves = plank.Schema.LeafColumns;
            var groupCount = arrow.FileMetaData.NumRowGroups;
            if (groupCount != plank.RowGroups.Count)
                throw Mismatch("written: row group count differs", $"Plank={plank.RowGroups.Count}, Arrow={groupCount}");
            if (arrow.FileMetaData.NumColumns != leaves.Length)
                throw Mismatch("written: column count differs", $"Plank={leaves.Length}, Arrow={arrow.FileMetaData.NumColumns}");

            var values = new ArrowColumn?[groupCount][];
            for (var g = 0; g < groupCount; g++)
            {
                values[g] = new ArrowColumn?[leaves.Length];
                using var group = arrow.RowGroup(g);
                for (var c = 0; c < leaves.Length; c++)
                {
                    using var chunk = group.MetaData.GetColumnChunkMetaData(c);
                    if (IsUndecodableByArrow(chunk, group, c))
                        continue;
                    try
                    {
                        // 1. Decoded values: Plank's physical bytes and levels against Arrow's.
                        if (traces[g][c] is { } plankTrace)
                        {
                            using var column = group.Column(c);
                            var descriptor = column.ColumnDescriptor;
                            var arrowTrace = ColumnTrace.CaptureArrow(column, descriptor.MaxRepetitionLevel > 0,
                                descriptor.MaxDefinitionLevel, descriptor.TypeLength);
                            if (ColumnTrace.Difference(plankTrace, arrowTrace) is { } difference)
                                throw Mismatch($"written: decoded values differ from Arrow ({difference[..difference.IndexOf('\n')]})",
                                    $"row group {g}, column {c} '{leaves[c].Path}', physical={leaves[c].PhysicalType}, "
                                    + $"encodings={string.Join(',', chunk.Encodings)}: {difference[(difference.IndexOf('\n') + 1)..]}");
                            // 2. Logical conversions of the (now Arrow-confirmed) physical values.
                            if (leaves[c].LogicalType is not null)
                                LogicalOracle.Check(plank.RowGroups[g], leaves[c], plankTrace);
                        }
                        // 3. Levels and values for the metadata checks below.
                        using var again = group.Column(c);
                        values[g][c] = ArrowColumn.Capture(again);
                    }
                    catch (Exception error) when (error is not ReaderAcceptanceMismatchException
                                                      and not OutOfMemoryException)
                    {
                        if (IsArrowCapabilityGap(error))
                            continue;
                        throw Mismatch("written: Arrow cannot decode a column Plank wrote and reads",
                            $"row group {g}, column {c} '{leaves[c].Path}', physical={leaves[c].PhysicalType}, "
                            + $"encodings={string.Join(',', chunk.Encodings)}: {error.GetType().Name}: {error.Message}", error);
                    }
                }
            }

            CompareMetadata(plank, arrow, strict: true, values);
            for (var g = 0; g < groupCount; g++)
                for (var c = 0; c < leaves.Length; c++)
                    if (values[g][c] is { } column)
                        CheckAgainstValues(plank, g, c, column);
            if (SortDeclarationsAreClaims)
                for (var g = 0; g < groupCount; g++)
                    CheckDeclaredSortOrder(plank, g, values[g]);
        }
    }

    // Narrow, named capability gaps of ParquetSharp 24 / Arrow C++ (see fuzz/README.md).
    static bool IsUndecodableByArrow(Ps.ColumnChunkMetaData chunk, Ps.RowGroupReader group, int column)
        // Encoding 10 (ALP, preview) is reported as Undefined: Arrow cannot decode it.
        => chunk.Encodings.Contains(Ps.Encoding.Undefined);

    static bool IsArrowCapabilityGap(Exception error)
        => error is Ps.ParquetException
            && (error.Message.Contains("Dictionary encoding not implemented for boolean type.", StringComparison.Ordinal)
                // A page using ALP while the chunk's encoding list does not say so.
                || error.Message.Contains("Unknown encoding type.", StringComparison.Ordinal));

    // ---- Metadata: Plank's view against Arrow's -----------------------------

    static void CompareMetadata(ParquetReader plank, Ps.ParquetFileReader arrow, bool strict, ArrowColumn?[][]? values)
    {
        var metadata = plank.PhysicalReader.Metadata;
        var leaves = plank.Schema.LeafColumns;
        var arrowMeta = arrow.FileMetaData;
        if (arrowMeta.NumColumns != leaves.Length || arrowMeta.NumRowGroups != plank.RowGroups.Count)
        {
            if (strict)
                throw Mismatch("metadata: column or row group count differs",
                    $"Plank={leaves.Length}/{plank.RowGroups.Count}, Arrow={arrowMeta.NumColumns}/{arrowMeta.NumRowGroups}");
            return;
        }

        // Schema of every leaf.
        var schema = arrowMeta.Schema;
        for (var c = 0; c < leaves.Length; c++)
        {
            var leaf = leaves[c];
            var descriptor = schema.Column(c);
            using var path = descriptor.Path;
            var arrowPath = string.Join('\u0001', path.ToDotVector());
            var plankSegments = new string[metadata.ColumnSchema(c).PathSegmentCount];
            for (var s = 0; s < plankSegments.Length; s++)
                plankSegments[s] = Encoding.UTF8.GetString(metadata.ColumnPathSegmentUtf8(c, s));
            var plankPath = string.Join('\u0001', plankSegments);
            if (arrowPath != plankPath && IsPlainUtf8(plankPath))
                throw Mismatch("metadata: column path differs",
                    $"column {c}: Plank='{plankPath.Replace('\u0001', '.')}', Arrow='{arrowPath.Replace('\u0001', '.')}'");
            if (descriptor.MaxDefinitionLevel != leaf.MaxDefinitionLevel || descriptor.MaxRepetitionLevel != leaf.MaxRepetitionLevel)
                throw Mismatch("metadata: column levels differ",
                    $"column {c} '{leaf.Path}': Plank def/rep={leaf.MaxDefinitionLevel}/{leaf.MaxRepetitionLevel}, "
                    + $"Arrow={descriptor.MaxDefinitionLevel}/{descriptor.MaxRepetitionLevel}");
            if (descriptor.PhysicalType.ToString() != leaf.PhysicalType.ToString())
                throw Mismatch("metadata: physical type differs",
                    $"column {c} '{leaf.Path}': Plank={leaf.PhysicalType}, Arrow={descriptor.PhysicalType}");
            if (leaf.PhysicalType == ParquetPhysicalType.FixedLenByteArray
                && descriptor.TypeLength != (int)metadata.ColumnSchema(c).TypeLength)
                throw Mismatch("metadata: FIXED_LEN_BYTE_ARRAY length differs",
                    $"column {c} '{leaf.Path}': Plank={metadata.ColumnSchema(c).TypeLength}, Arrow={descriptor.TypeLength}");
            string? a;
            try
            {
                using var arrowLogical = descriptor.LogicalType;
                a = Describe(arrowLogical);
            }
            catch (ArgumentOutOfRangeException)
            {
                // ParquetSharp 24 throws for logical types it has no class for (Geometry,
                // Geography, Variant): oracle capability gap, nothing to compare.
                a = null;
            }
            var p = Describe(leaf.LogicalType);
            if (a is not null && p is not null && a != p)
                throw Mismatch("metadata: logical type differs", $"column {c} '{leaf.Path}' ({leaf.PhysicalType}): Plank={p}, Arrow={a}");
        }

        // Row and value counts.
        long totalRows = 0;
        for (var g = 0; g < plank.RowGroups.Count; g++)
        {
            using var group = arrow.RowGroup(g);
            var plankRows = plank.RowGroups[g].RowCount;
            totalRows += (long)plankRows;
            if ((ulong)group.MetaData.NumRows != plankRows)
                throw Mismatch("metadata: row group row count differs", $"row group {g}: Plank={plankRows}, Arrow={group.MetaData.NumRows}");
            for (var c = 0; c < leaves.Length; c++)
            {
                using var chunk = group.MetaData.GetColumnChunkMetaData(c);
                var plankChunk = plank.RowGroups[g].GetColumnMetadata(leaves[c]);
                if ((ulong)chunk.NumValues != plankChunk.ValueCount)
                    throw Mismatch("metadata: column chunk value count differs",
                        $"row group {g}, column {c}: Plank={plankChunk.ValueCount}, Arrow={chunk.NumValues}");
                CompareStatistics(g, c, leaves[c], plankChunk.Statistics, chunk);
                if (plankChunk.HasBloomFilter)
                    CheckBloomProbes(plank, g, c, values?[g][c], strict);
            }

            // Sorting columns of the row group.
            var arrowSorting = group.MetaData.SortingColumns();
            var plankSorting = metadata.RowGroupSortingColumns(g);
            var same = arrowSorting.Length == plankSorting.Length;
            for (var i = 0; same && i < arrowSorting.Length; i++)
                same = arrowSorting[i].ColumnIndex == plankSorting[i].ColumnOrdinal
                    && arrowSorting[i].IsDescending == plankSorting[i].Descending
                    && arrowSorting[i].NullsFirst == plankSorting[i].NullsFirst;
            if (!same)
                throw Mismatch("metadata: sorting columns differ",
                    $"row group {g}: Plank=[{string.Join(',', plankSorting.ToArray().Select(s => $"{s.ColumnOrdinal}/{s.Descending}/{s.NullsFirst}"))}], "
                    + $"Arrow=[{string.Join(',', arrowSorting.Select(s => $"{s.ColumnIndex}/{s.IsDescending}/{s.NullsFirst}"))}]");
        }
        if (arrowMeta.NumRows != totalRows)
            throw Mismatch("metadata: file row count differs", $"Plank row groups sum={totalRows}, Arrow num_rows={arrowMeta.NumRows}");

        CompareKeyValueMetadata(metadata, arrowMeta);
    }

    static void CompareKeyValueMetadata(Plank.Reading.Physical.ParquetFileMetadata metadata, Ps.FileMetaData arrowMeta)
    {
        IReadOnlyDictionary<string, string>? arrowPairs;
        try
        {
            arrowPairs = arrowMeta.KeyValueMetadata;
        }
        catch (ArgumentException)
        {
            // ParquetSharp builds a dictionary: duplicate keys make it throw. Oracle gap.
            return;
        }

        var plankPairs = new Dictionary<string, string?>(StringComparer.Ordinal);
        var ambiguous = new HashSet<string>(StringComparer.Ordinal);
        var comparable = true;
        for (var i = 0; i < metadata.KeyValueMetadataCount; i++)
        {
            var keyBytes = metadata.KeyValueMetadataKeyUtf8(i);
            var valueBytes = metadata.KeyValueMetadataValueUtf8(i);
            // Arrow marshals these as C strings and replaces invalid UTF-8: compare only clean text.
            if (!IsComparableText(keyBytes) || !IsComparableText(valueBytes))
            {
                comparable = false;
                continue;
            }
            var key = Encoding.UTF8.GetString(keyBytes);
            var value = metadata.KeyValueMetadata[i].HasValue ? Encoding.UTF8.GetString(valueBytes) : null;
            if (!plankPairs.TryAdd(key, value) && plankPairs[key] != value)
                ambiguous.Add(key);
        }

        var arrowCount = arrowPairs?.Count ?? 0;
        if (comparable && arrowCount != plankPairs.Count)
            throw Mismatch("metadata: key/value count differs", $"Plank distinct keys={plankPairs.Count}, Arrow={arrowCount}");
        if (arrowPairs is null)
            return;
        foreach (var (key, value) in arrowPairs)
        {
            if (ambiguous.Contains(key))
                continue;
            if (!plankPairs.TryGetValue(key, out var plankValue))
            {
                if (comparable)
                    throw Mismatch("metadata: key/value key missing in Plank", $"key '{Escape(key)}'");
                continue;
            }
            // Arrow has no "no value" state: an absent value reads as "".
            if ((plankValue ?? "") != value)
                throw Mismatch("metadata: key/value value differs", $"key '{Escape(key)}': Plank='{Escape(plankValue)}', Arrow='{Escape(value)}'");
        }
    }

    static bool IsComparableText(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Contains((byte)0))
            return false;
        try
        {
            _ = new UTF8Encoding(false, throwOnInvalidBytes: true).GetCharCount(bytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    static bool IsPlainUtf8(string text) => !text.Contains('�') && !text.Contains('\0');

    static string Escape(string? text) => text is null ? "<null>" : text.Length > 40 ? text[..40] + "…" : text;

    // ---- Statistics: Plank's view against Arrow's --------------------------

    static void CompareStatistics(int g, int c, LeafColumn leaf, ParquetStatistics plank, Ps.ColumnChunkMetaData chunk)
    {
        if (!chunk.IsStatsSet)
            return;
        using var stats = chunk.Statistics;
        if (stats is null)
            return;
        CheckedStatistics++;
        var where = $"row group {g}, column {c} '{leaf.Path}' ({leaf.PhysicalType}, {Describe(leaf.LogicalType) ?? "none"})";
        // Arrow reports 0 for an absent null_count / distinct_count.
        if (plank.NullCount is { } nulls && nulls != stats.NullCount)
            throw Mismatch("statistics: null_count differs between Plank and Arrow", $"{where}: Plank={nulls}, Arrow={stats.NullCount}");
        if (plank.NullCount is null && stats.NullCount != 0)
            throw Mismatch("statistics: Plank lost a null_count Arrow reads", $"{where}: Arrow={stats.NullCount}");
        if (plank.DistinctCount is { } distinct && distinct != stats.DistinctCount)
            throw Mismatch("statistics: distinct_count differs between Plank and Arrow", $"{where}: Plank={distinct}, Arrow={stats.DistinctCount}");
        if (!stats.HasMinMax)
            return;
        var (arrowMin, arrowMax) = ArrowMinMax(stats, chunk.Type, leaf);
        if (arrowMin is null || arrowMax is null)
            return;
        if (!plank.HasMinimum || !plank.HasMaximum)
            throw Mismatch("statistics: Plank lost a min/max Arrow reads", $"{where}: Arrow min={Hex(arrowMin)}, max={Hex(arrowMax)}");
        if (!plank.Minimum.SequenceEqual(arrowMin) || !plank.Maximum.SequenceEqual(arrowMax))
            throw Mismatch("statistics: min/max bytes differ between Plank and Arrow",
                $"{where}: Plank min={Hex(plank.Minimum)} max={Hex(plank.Maximum)}, Arrow min={Hex(arrowMin)} max={Hex(arrowMax)}");
    }

    static (byte[]? Min, byte[]? Max) ArrowMinMax(Ps.Statistics stats, Ps.PhysicalType type, LeafColumn leaf)
        => stats switch
        {
            Ps.Statistics<bool> s => ([(byte)(s.Min ? 1 : 0)], [(byte)(s.Max ? 1 : 0)]),
            Ps.Statistics<int> s => (Le(s.Min), Le(s.Max)),
            Ps.Statistics<long> s => (Le(s.Min), Le(s.Max)),
            Ps.Statistics<float> s => (Le(s.Min), Le(s.Max)),
            Ps.Statistics<double> s => (Le(s.Min), Le(s.Max)),
            Ps.Statistics<Ps.Int96> s => (Le(s.Min), Le(s.Max)),
            Ps.Statistics<Ps.ByteArray> s => (Copy(s.Min.Pointer, s.Min.Length), Copy(s.Max.Pointer, s.Max.Length)),
            Ps.Statistics<Ps.FixedLenByteArray> s when TypeLength(leaf) is > 0 and var length
                => (Copy(s.Min.Pointer, length), Copy(s.Max.Pointer, length)),
            _ => (null, null),
        };

    static int TypeLength(LeafColumn leaf) => (int)leaf.Options.TypeLength;

    static byte[] Le<T>(T value) where T : unmanaged => MemoryMarshal.AsBytes(new ReadOnlySpan<T>(in value)).ToArray();

    static byte[] Copy(IntPtr pointer, int length)
    {
        if (length <= 0 || pointer == IntPtr.Zero)
            return [];
        var bytes = new byte[length];
        Marshal.Copy(pointer, bytes, 0, length);
        return bytes;
    }

    // ---- Metadata against Arrow-decoded values (written files) -------------

    static void CheckAgainstValues(ParquetReader plank, int g, int c, ArrowColumn column)
    {
        var leaf = plank.Schema.LeafColumns[c];
        var group = plank.RowGroups[g];
        var where = $"row group {g}, column {c} '{leaf.Path}' ({leaf.PhysicalType}, {Describe(leaf.LogicalType) ?? "none"}, def={column.MaxDef}, rep={column.MaxRep})";
        var rows = column.RowStarts.Count;
        if ((ulong)rows != group.RowCount)
            throw Mismatch("written: rows decoded by Arrow differ from the row group's num_rows", $"{where}: num_rows={group.RowCount}, Arrow rows={rows}");
        var meta = group.GetColumnMetadata(leaf);
        if ((ulong)column.EntryCount != meta.ValueCount)
            throw Mismatch("written: column chunk num_values differs from the level count", $"{where}: num_values={meta.ValueCount}, levels={column.EntryCount}");

        var order = Order.For(leaf);
        // Chunk statistics.
        var stats = meta.Statistics;
        var summary = column.Summarize(0, column.EntryCount, order);
        if (stats.NullCount is { } nulls && nulls != summary.Nulls)
            throw Mismatch("written: statistics null_count differs from the values", $"{where}: null_count={nulls}, actual={summary.Nulls}");
        if (stats.DistinctCount is { } distinct && distinct != summary.Distinct && distinct != summary.DistinctNumeric)
            throw Mismatch("written: statistics distinct_count differs from the values", $"{where}: distinct_count={distinct}, actual={summary.Distinct}");
        CheckMinMax("written: chunk statistics", where, stats, summary, order, leaf);

        // Column index and offset index.
        using (var pages = meta.OpenPages())
            CheckPageIndex(where, meta, pages, column, order, leaf, group.RowCount);

        // Bloom filter membership of every present value, with the specification's hash.
        if (meta.HasBloomFilter && leaf.PhysicalType != ParquetPhysicalType.Boolean)
        {
            using var bloom = meta.OpenBloomFilter();
            var bitset = bloom.Bitset;
            if (bitset.Length == 0 || bitset.Length % 32 != 0)
                throw Mismatch("written: Bloom filter bitset size is not a positive multiple of 32", $"{where}: {bitset.Length} bytes");
            var checkedValues = new HashSet<ulong>();
            foreach (var value in column.Values)
            {
                var hash = XxHash64.HashToUInt64(value);
                if (!checkedValues.Add(hash))
                    continue;
                CheckedBloomValues++;
                if (!SbbfContains(bitset, hash))
                    throw Mismatch("written: Bloom filter (spec SBBF/XXH64) lacks a present value",
                        $"{where}: value={Hex(value)}, hash={hash:X16}, bitset={bitset.Length} bytes");
            }
        }
    }

    static void CheckMinMax(string what, string where, ParquetStatistics stats, Summary summary, Order? order, LeafColumn leaf)
    {
        if (order is null)
            return;
        if (!stats.HasMinimum && !stats.HasMaximum)
            return;
        if (summary.Min is null)
        {
            // Only nulls (or only NaN): there is no value a min/max could describe.
            if (summary.NaNs == 0)
                throw Mismatch($"{what} min/max present for a chunk without values", $"{where}: min={Hex(stats.Minimum)}, max={Hex(stats.Maximum)}");
            return;
        }
        if (stats.HasMinimum)
        {
            var min = stats.Minimum.ToArray();
            if (!order.IsWellFormed(min))
                throw Mismatch($"{what} min has the wrong size for the type", $"{where}: min={Hex(min)}");
            var cmp = order.Compare(min, summary.Min);
            if (order.IsNaN(min) || (stats.IsMinimumExact ? cmp != 0 : cmp > 0))
                throw Mismatch($"{what} min differs from the values", $"{where}: min={Hex(min)} ({order.Show(min)}), actual={Hex(summary.Min)} ({order.Show(summary.Min)}), exact={stats.IsMinimumExact}");
        }
        if (stats.HasMaximum)
        {
            var max = stats.Maximum.ToArray();
            if (!order.IsWellFormed(max))
                throw Mismatch($"{what} max has the wrong size for the type", $"{where}: max={Hex(max)}");
            var cmp = order.Compare(max, summary.Max!);
            if (order.IsNaN(max) || (stats.IsMaximumExact ? cmp != 0 : cmp < 0))
                throw Mismatch($"{what} max differs from the values", $"{where}: max={Hex(max)} ({order.Show(max)}), actual={Hex(summary.Max!)} ({order.Show(summary.Max!)}), exact={stats.IsMaximumExact}");
        }
    }

    static void CheckPageIndex(string where, ParquetColumnChunkMetadata meta, ParquetDataPageMetadataCollection pages,
        ArrowColumn column, Order? order, LeafColumn leaf, ulong rowCount)
    {
        if (!meta.HasOffsetIndex)
            return;
        var count = pages.Count;
        if (count == 0)
        {
            if (rowCount != 0)
                throw Mismatch("written: offset index has no pages for a non-empty chunk", where);
            return;
        }
        var firsts = new ulong[count];
        for (var i = 0; i < count; i++)
        {
            if (pages[i].FirstRowIndex is not { } first)
                throw Mismatch("written: offset index page without first_row_index", $"{where}: page {i}");
            firsts[i] = first;
            if (i == 0 ? first != 0 : first <= firsts[i - 1])
                throw Mismatch("written: offset index first_row_index not strictly increasing from 0", $"{where}: page {i} first={first}, previous={(i == 0 ? "-" : firsts[i - 1].ToString())}");
        }
        if (firsts[^1] >= rowCount)
            throw Mismatch("written: offset index last page starts past the row group", $"{where}: first={firsts[^1]}, rows={rowCount}");

        Summary? previous = null;
        var boundary = pages.BoundaryOrder;
        for (var i = 0; i < count; i++)
        {
            var page = pages[i];
            var end = i + 1 < count ? firsts[i + 1] : rowCount;
            if (page.RowCount is { } pageRows && pageRows != end - firsts[i])
                throw Mismatch("written: page row count disagrees with the offset index", $"{where}: page {i} rows={pageRows}, from offsets={end - firsts[i]}");
            var startEntry = column.RowStarts[(int)firsts[i]];
            var endEntry = end == rowCount ? column.EntryCount : column.RowStarts[(int)end];
            var summary = column.Summarize(startEntry, endEntry, order);
            CheckedPages++;
            if (!meta.HasColumnIndex)
                continue;
            var stats = page.Statistics;
            var pageWhere = $"{where}, page {i} (rows {firsts[i]}..{end})";
            if (stats.NullCount is { } nulls && nulls != summary.Nulls)
                throw Mismatch("written: column index null_count differs from the page's values", $"{pageWhere}: null_count={nulls}, actual={summary.Nulls}");
            var allNull = summary.Present == 0;
            if (page.IsNullPage is { } isNull && isNull != allNull && !(summary.Present == summary.NaNs && summary.NaNs > 0))
                throw Mismatch("written: column index null_pages differs from the page's values", $"{pageWhere}: null_page={isNull}, present values={summary.Present}");
            if (allNull || page.IsNullPage == true)
                continue;
            CheckMinMax("written: column index", pageWhere, stats, summary, order, leaf);
            if (order is not null && previous is { Min: not null } && summary.Min is not null
                && stats.HasMinimum && stats.HasMaximum)
            {
                var prev = previous.Value;
                var ascending = order.Compare(prev.Min!, summary.Min) <= 0 && order.Compare(prev.Max!, summary.Max!) <= 0;
                var descending = order.Compare(prev.Min!, summary.Min) >= 0 && order.Compare(prev.Max!, summary.Max!) >= 0;
                if ((boundary == ParquetBoundaryOrder.Ascending && !ascending) || (boundary == ParquetBoundaryOrder.Descending && !descending))
                    throw Mismatch("written: column index boundary_order contradicts the pages", $"{pageWhere}: boundary_order={boundary}");
            }
            if (summary.Min is not null)
                previous = summary;
        }
    }

    // Declared sorting_columns must describe the rows (flat columns only; levels make a
    // nested column's order undefined here).
    static void CheckDeclaredSortOrder(ParquetReader plank, int g, ArrowColumn?[] columns)
    {
        var sorting = plank.PhysicalReader.Metadata.RowGroupSortingColumns(g).ToArray();
        if (sorting.Length == 0)
            return;
        var leaves = plank.Schema.LeafColumns;
        var keys = new List<(ArrowColumn Column, Order Order, ParquetSortingColumn Sorting)>();
        foreach (var s in sorting)
        {
            if ((uint)s.ColumnOrdinal >= (uint)columns.Length || columns[s.ColumnOrdinal] is not { MaxRep: 0 } column
                || Order.For(leaves[s.ColumnOrdinal]) is not { } order)
                break;
            keys.Add((column, order, s));
        }
        if (keys.Count == 0)
            return;
        var rows = keys[0].Column.EntryCount;
        for (var r = 1; r < rows; r++)
        {
            CheckedSortedRows++;
            foreach (var (column, order, s) in keys)
            {
                var a = column.ValueAtEntry(r - 1);
                var b = column.ValueAtEntry(r);
                int cmp;
                if (a is null || b is null)
                    cmp = a is null && b is null ? 0 : (a is null) == s.NullsFirst ? -1 : 1;
                else if (order.IsNaN(a) || order.IsNaN(b))
                    break; // NaN has no defined place; stop comparing this row pair.
                else
                    cmp = s.Descending ? -order.Compare(a, b) : order.Compare(a, b);
                if (cmp < 0)
                    break;
                if (cmp > 0)
                    throw Mismatch("written: rows violate the declared sorting_columns",
                        $"row group {g}, rows {r - 1}/{r}, column {s.ColumnOrdinal} '{leaves[s.ColumnOrdinal].Path}' desc={s.Descending} nullsFirst={s.NullsFirst}: "
                        + $"{(a is null ? "null" : order.Show(a))} then {(b is null ? "null" : order.Show(b))}");
            }
        }
    }

    // ---- Bloom filter probes (both modes) -----------------------------------

    static void CheckBloomProbes(ParquetReader plank, int g, int c, ArrowColumn? values, bool strict)
    {
        var leaf = plank.Schema.LeafColumns[c];
        var meta = plank.RowGroups[g].GetColumnMetadata(leaf);
        using var bloom = meta.OpenBloomFilter();
        var bitset = bloom.Bitset;
        if (bitset.Length < 32)
            return;
        var where = $"row group {g}, column {c} '{leaf.Path}' ({leaf.PhysicalType}, {Describe(leaf.LogicalType) ?? "none"})";
        // Probe values: the column's own values when known, plus fixed ones.
        IEnumerable<byte[]> probes = values?.Values.Take(64) ?? [];
        probes = probes.Concat(FixedProbes(leaf));
        foreach (var bytes in probes)
        {
            var hash = XxHash64.HashToUInt64(bytes);
            var expected = SbbfContains(bitset, hash);
            if (bloom.MightContainHash(hash) != expected)
                throw Mismatch("bloom: MightContainHash disagrees with the specification's SBBF", $"{where}: hash={hash:X16}, spec={expected}");
            bool? typed = TypedProbe(bloom, leaf, bytes);
            // A false positive is always allowed (Plank also answers true for the other
            // zero and for other NaN payloads, which equality semantics want); a false
            // negative against the specification's hash never is.
            if (typed is false && expected)
                throw Mismatch("bloom: typed MightContain misses a value present under XXH64 of the plain encoding",
                    $"{where}: value={Hex(bytes)}, MightContain=false, spec=true");
        }
    }

    static IEnumerable<byte[]> FixedProbes(LeafColumn leaf)
    {
        switch (leaf.PhysicalType)
        {
            case ParquetPhysicalType.Int32:
                foreach (var v in new[] { 0, 1, -1, 255, 65535, int.MinValue, int.MaxValue }) yield return Le(v);
                break;
            case ParquetPhysicalType.Int64:
                foreach (var v in new[] { 0L, 1, -1, long.MinValue, long.MaxValue, uint.MaxValue }) yield return Le(v);
                break;
            case ParquetPhysicalType.Float:
                foreach (var v in new[] { 0f, -0f, 1f, float.NaN, float.NegativeInfinity }) yield return Le(v);
                break;
            case ParquetPhysicalType.Double:
                foreach (var v in new[] { 0d, -0d, 1d, double.NaN, double.PositiveInfinity }) yield return Le(v);
                break;
            case ParquetPhysicalType.ByteArray:
                yield return [];
                yield return "a"u8.ToArray();
                break;
            case ParquetPhysicalType.FixedLenByteArray when TypeLength(leaf) is > 0 and <= 64 and var n:
                yield return new byte[n];
                break;
        }
    }

    // The typed overloads must hash the plain encoding of the column's physical value.
    static bool? TypedProbe(Plank.Reading.Physical.ParquetBloomFilter bloom, LeafColumn leaf, byte[] bytes)
    {
        switch (leaf.PhysicalType)
        {
            case ParquetPhysicalType.Int32 when bytes.Length == 4:
            {
                var v = BinaryPrimitives.ReadInt32LittleEndian(bytes);
                return leaf.LogicalType switch
                {
                    LogicalType.Int { IsSigned: false, BitWidth: 8 } when v is >= 0 and <= byte.MaxValue => bloom.MightContain((byte)v),
                    LogicalType.Int { IsSigned: false, BitWidth: 16 } when v is >= 0 and <= ushort.MaxValue => bloom.MightContain((ushort)v),
                    LogicalType.Int { IsSigned: false, BitWidth: 32 } => bloom.MightContain((uint)v),
                    _ => bloom.MightContain(v),
                };
            }
            case ParquetPhysicalType.Int64 when bytes.Length == 8:
            {
                var v = BinaryPrimitives.ReadInt64LittleEndian(bytes);
                return leaf.LogicalType is LogicalType.Int { IsSigned: false, BitWidth: 64 }
                    ? bloom.MightContain((ulong)v)
                    : bloom.MightContain(v);
            }
            case ParquetPhysicalType.Float when bytes.Length == 4:
                return bloom.MightContain(BinaryPrimitives.ReadSingleLittleEndian(bytes));
            case ParquetPhysicalType.Double when bytes.Length == 8:
                return bloom.MightContain(BinaryPrimitives.ReadDoubleLittleEndian(bytes));
            case ParquetPhysicalType.FixedLenByteArray when bytes.Length == 16 && leaf.LogicalType is LogicalType.Uuid:
                // UUID bytes are big-endian in the file; Guid is the CLR view of the same value.
                return bloom.MightContain(new Guid(bytes, bigEndian: true));
            case ParquetPhysicalType.ByteArray or ParquetPhysicalType.FixedLenByteArray or ParquetPhysicalType.Int96:
                return bloom.MightContain(bytes);
            default:
                return null;
        }
    }

    static readonly uint[] Salt =
        [0x47b6137bU, 0x44974d91U, 0x8824ad5bU, 0xa2b7289dU, 0x705495c7U, 0x2df1424bU, 0x9efc4947U, 0x5c6bfb31U];

    /// <summary>Split-block Bloom filter lookup exactly as the Parquet specification states it.</summary>
    static bool SbbfContains(ReadOnlySpan<byte> bitset, ulong hash)
    {
        var blocks = (ulong)(bitset.Length / 32);
        if (blocks == 0)
            return false;
        var block = (int)(((hash >> 32) * blocks) >> 32);
        var key = (uint)hash;
        for (var i = 0; i < 8; i++)
        {
            var mask = 1u << (int)((key * Salt[i]) >> 27);
            var word = BinaryPrimitives.ReadUInt32LittleEndian(bitset.Slice(block * 32 + i * 4, 4));
            if ((word & mask) == 0)
                return false;
        }
        return true;
    }

    // ---- Logical type descriptions -----------------------------------------

    static string? Describe(LogicalType? type) => type switch
    {
        null => "None",
        LogicalType.Date => "Date",
        LogicalType.Decimal d => $"Decimal({d.Precision},{d.Scale})",
        LogicalType.Int i => $"Int({i.BitWidth},{i.IsSigned})",
        LogicalType.Time t => $"Time({t.Unit},{t.IsAdjustedToUtc})",
        LogicalType.Timestamp t => $"Timestamp({t.Unit},{t.IsAdjustedToUtc})",
        LogicalType.String => "String",
        LogicalType.Json => "Json",
        LogicalType.Bson => "Bson",
        LogicalType.Enum => "Enum",
        LogicalType.Uuid => "Uuid",
        LogicalType.Float16 => "Float16",
        LogicalType.Interval => "Interval",
        LogicalType.Unknown => "Unknown",
        // Geometry, Geography and Variant are newer than ParquetSharp 24: not comparable.
        _ => null,
    };

    static string? Describe(Ps.LogicalType type) => type switch
    {
        Ps.NoneLogicalType => "None",
        Ps.DateLogicalType => "Date",
        Ps.DecimalLogicalType d => $"Decimal({d.Precision},{d.Scale})",
        Ps.IntLogicalType i => $"Int({i.BitWidth},{i.IsSigned})",
        Ps.TimeLogicalType t => $"Time({t.TimeUnit},{t.IsAdjustedToUtc})",
        Ps.TimestampLogicalType t => $"Timestamp({t.TimeUnit},{t.IsAdjustedToUtc})",
        Ps.StringLogicalType => "String",
        Ps.JsonLogicalType => "Json",
        Ps.BsonLogicalType => "Bson",
        Ps.EnumLogicalType => "Enum",
        Ps.UuidLogicalType => "Uuid",
        Ps.Float16LogicalType => "Float16",
        Ps.IntervalLogicalType => "Interval",
        Ps.NullLogicalType => "Unknown",
        _ => null,
    };

    // ---- Helpers -------------------------------------------------------------

    static string Hex(ReadOnlySpan<byte> bytes)
        => bytes.Length > 32 ? Convert.ToHexString(bytes[..32]) + "…" : Convert.ToHexString(bytes);

    static ReaderAcceptanceMismatchException Mismatch(string bucket, string detail, Exception? inner = null)
        => new("Full-value oracle: " + bucket,
            new InvalidDataException($"{bucket} — {detail}", inner));

    // ---- Arrow-decoded column --------------------------------------------------

    internal readonly record struct Summary(int Nulls, int Present, int NaNs, int Distinct, int DistinctNumeric,
        byte[]? Min, byte[]? Max);

    internal sealed class ArrowColumn
    {
        public short MaxDef, MaxRep;
        readonly List<short> _def = [];
        readonly List<short> _rep = [];
        readonly List<int> _valueOfEntry = [];
        public readonly List<byte[]> Values = [];
        public readonly List<int> RowStarts = [];

        public int EntryCount => _def.Count;

        public byte[]? ValueAtEntry(int entry) => _valueOfEntry[entry] is >= 0 and var v ? Values[v] : null;

        void Add(short definition, short repetition, byte[]? value)
        {
            if (MaxRep == 0 || repetition == 0)
                RowStarts.Add(_def.Count);
            _def.Add(definition);
            _rep.Add(repetition);
            if (value is null)
                _valueOfEntry.Add(-1);
            else
            {
                _valueOfEntry.Add(Values.Count);
                Values.Add(value);
            }
        }

        public Summary Summarize(int start, int end, Order? order)
        {
            int nulls = 0, present = 0, nans = 0;
            byte[]? min = null, max = null;
            var distinct = new HashSet<string>(StringComparer.Ordinal);
            var distinctNumeric = new HashSet<string>(StringComparer.Ordinal);
            for (var e = start; e < end; e++)
            {
                if (ValueAtEntry(e) is not { } value)
                {
                    nulls++;
                    continue;
                }
                present++;
                if (order?.IsNaN(value) == true)
                {
                    nans++;
                    continue;
                }
                distinct.Add(Convert.ToBase64String(value));
                distinctNumeric.Add(order?.Canonical(value) ?? Convert.ToBase64String(value));
                if (order is null)
                    continue;
                if (min is null || order.Compare(value, min) < 0) min = value;
                if (max is null || order.Compare(value, max) > 0) max = value;
            }
            return new Summary(nulls, present, nans, distinct.Count + (nans > 0 ? 1 : 0),
                distinctNumeric.Count + (nans > 0 ? 1 : 0), min, max);
        }

        public static ArrowColumn Capture(Ps.ColumnReader reader)
        {
            var descriptor = reader.ColumnDescriptor;
            var column = new ArrowColumn { MaxDef = descriptor.MaxDefinitionLevel, MaxRep = descriptor.MaxRepetitionLevel };
            var length = descriptor.TypeLength;
            switch (reader.Type)
            {
                case Ps.PhysicalType.Boolean: column.Read((Ps.ColumnReader<bool>)reader, static v => [(byte)(v ? 1 : 0)]); break;
                case Ps.PhysicalType.Int32: column.Read((Ps.ColumnReader<int>)reader, static v => Le(v)); break;
                case Ps.PhysicalType.Int64: column.Read((Ps.ColumnReader<long>)reader, static v => Le(v)); break;
                case Ps.PhysicalType.Int96: column.Read((Ps.ColumnReader<Ps.Int96>)reader, static v => Le(v)); break;
                case Ps.PhysicalType.Float: column.Read((Ps.ColumnReader<float>)reader, static v => Le(v)); break;
                case Ps.PhysicalType.Double: column.Read((Ps.ColumnReader<double>)reader, static v => Le(v)); break;
                case Ps.PhysicalType.ByteArray:
                    column.Read((Ps.ColumnReader<Ps.ByteArray>)reader, static v => Copy(v.Pointer, v.Length)); break;
                case Ps.PhysicalType.FixedLenByteArray:
                    column.Read((Ps.ColumnReader<Ps.FixedLenByteArray>)reader, v => Copy(v.Pointer, length)); break;
            }
            return column;
        }

        void Read<T>(Ps.ColumnReader<T> reader, Func<T, byte[]> toBytes) where T : unmanaged
        {
            var values = new T[1024];
            var definitions = new short[values.Length];
            var repetitions = new short[values.Length];
            while (reader.HasNext)
            {
                var levels = reader.ReadBatch(values.Length, definitions, repetitions, values, out var valuesRead);
                if (levels == 0)
                    throw new InvalidDataException("ParquetSharp could not finish reading the column.");
                if (MaxDef == 0 && MaxRep == 0)
                {
                    for (var i = 0; i < valuesRead; i++)
                        Add(0, 0, toBytes(values[i]));
                    continue;
                }
                var next = 0;
                for (var i = 0; i < levels; i++)
                {
                    var present = definitions[i] == MaxDef;
                    Add(definitions[i], MaxRep > 0 ? repetitions[i] : (short)0, present ? toBytes(values[next++]) : null);
                }
                if (next != valuesRead)
                    throw new InvalidDataException("ParquetSharp returned a value count that disagrees with its levels.");
            }
        }
    }

    // ---- Sort orders (Parquet specification, ColumnOrder TypeDefinedOrder) -----

    internal sealed class Order
    {
        enum Kind { Boolean, Int32, UInt32, Int64, UInt64, Float, Double, Half, SignedBigEndian, Unsigned }

        readonly Kind _kind;
        readonly int _width;

        Order(Kind kind, int width) { _kind = kind; _width = width; }

        /// <summary>The type-defined order of the column, or null where the specification leaves it undefined.</summary>
        public static Order? For(LeafColumn leaf)
        {
            var logical = leaf.LogicalType;
            switch (leaf.PhysicalType)
            {
                case ParquetPhysicalType.Boolean: return new(Kind.Boolean, 1);
                case ParquetPhysicalType.Int32:
                    return logical is LogicalType.Int { IsSigned: false } ? new(Kind.UInt32, 4) : new(Kind.Int32, 4);
                case ParquetPhysicalType.Int64:
                    return logical is LogicalType.Int { IsSigned: false } ? new(Kind.UInt64, 8) : new(Kind.Int64, 8);
                case ParquetPhysicalType.Float: return new(Kind.Float, 4);
                case ParquetPhysicalType.Double: return new(Kind.Double, 8);
                case ParquetPhysicalType.Int96: return null; // undefined order
                case ParquetPhysicalType.FixedLenByteArray or ParquetPhysicalType.ByteArray:
                    var width = leaf.PhysicalType == ParquetPhysicalType.FixedLenByteArray ? TypeLength(leaf) : -1;
                    return logical switch
                    {
                        LogicalType.Interval => null, // undefined order
                        LogicalType.Decimal => new(Kind.SignedBigEndian, width),
                        LogicalType.Float16 when width == 2 => new(Kind.Half, 2),
                        LogicalType.Float16 => null,
                        // Newer types whose orders this oracle does not model.
                        LogicalType.Geometry or LogicalType.Geography or LogicalType.Variant => null,
                        _ => new(Kind.Unsigned, width),
                    };
                default: return null;
            }
        }

        public bool IsWellFormed(byte[] value) => _width < 0 || value.Length == _width;

        public bool IsNaN(byte[] v) => _kind switch
        {
            Kind.Float => v.Length == 4 && float.IsNaN(BinaryPrimitives.ReadSingleLittleEndian(v)),
            Kind.Double => v.Length == 8 && double.IsNaN(BinaryPrimitives.ReadDoubleLittleEndian(v)),
            Kind.Half => v.Length == 2 && Half.IsNaN(BinaryPrimitives.ReadHalfLittleEndian(v)),
            _ => false,
        };

        /// <summary>Numeric identity for distinct counting (-0 and +0 are one value).</summary>
        public string Canonical(byte[] v) => _kind switch
        {
            Kind.Float or Kind.Double or Kind.Half => Show(v) == "-0" ? "0" : Show(v),
            Kind.SignedBigEndian => new BigInteger(v, isUnsigned: false, isBigEndian: true).ToString(),
            _ => Convert.ToBase64String(v),
        };

        public int Compare(byte[] a, byte[] b)
        {
            switch (_kind)
            {
                case Kind.Boolean: return a[0].CompareTo(b[0]);
                case Kind.Int32: return BinaryPrimitives.ReadInt32LittleEndian(a).CompareTo(BinaryPrimitives.ReadInt32LittleEndian(b));
                case Kind.UInt32: return BinaryPrimitives.ReadUInt32LittleEndian(a).CompareTo(BinaryPrimitives.ReadUInt32LittleEndian(b));
                case Kind.Int64: return BinaryPrimitives.ReadInt64LittleEndian(a).CompareTo(BinaryPrimitives.ReadInt64LittleEndian(b));
                case Kind.UInt64: return BinaryPrimitives.ReadUInt64LittleEndian(a).CompareTo(BinaryPrimitives.ReadUInt64LittleEndian(b));
                // Numeric order; -0 and +0 compare equal (the specification lets either stand for zero).
                case Kind.Float:
                {
                    var x = BinaryPrimitives.ReadSingleLittleEndian(a);
                    var y = BinaryPrimitives.ReadSingleLittleEndian(b);
                    return x < y ? -1 : x > y ? 1 : 0;
                }
                case Kind.Double:
                {
                    var x = BinaryPrimitives.ReadDoubleLittleEndian(a);
                    var y = BinaryPrimitives.ReadDoubleLittleEndian(b);
                    return x < y ? -1 : x > y ? 1 : 0;
                }
                case Kind.Half:
                {
                    var x = BinaryPrimitives.ReadHalfLittleEndian(a);
                    var y = BinaryPrimitives.ReadHalfLittleEndian(b);
                    return x < y ? -1 : x > y ? 1 : 0;
                }
                case Kind.SignedBigEndian:
                    return (a.Length == 0 ? BigInteger.Zero : new BigInteger(a, isUnsigned: false, isBigEndian: true))
                        .CompareTo(b.Length == 0 ? BigInteger.Zero : new BigInteger(b, isUnsigned: false, isBigEndian: true));
                default:
                    return a.AsSpan().SequenceCompareTo(b);
            }
        }

        public string Show(byte[] v)
        {
            if (!IsWellFormed(v))
                return Hex(v);
            return _kind switch
            {
                Kind.Boolean => (v[0] != 0).ToString(),
                Kind.Int32 => BinaryPrimitives.ReadInt32LittleEndian(v).ToString(System.Globalization.CultureInfo.InvariantCulture),
                Kind.UInt32 => BinaryPrimitives.ReadUInt32LittleEndian(v).ToString(System.Globalization.CultureInfo.InvariantCulture),
                Kind.Int64 => BinaryPrimitives.ReadInt64LittleEndian(v).ToString(System.Globalization.CultureInfo.InvariantCulture),
                Kind.UInt64 => BinaryPrimitives.ReadUInt64LittleEndian(v).ToString(System.Globalization.CultureInfo.InvariantCulture),
                Kind.Float => BinaryPrimitives.ReadSingleLittleEndian(v).ToString("R", System.Globalization.CultureInfo.InvariantCulture),
                Kind.Double => BinaryPrimitives.ReadDoubleLittleEndian(v).ToString("R", System.Globalization.CultureInfo.InvariantCulture),
                Kind.Half => ((float)BinaryPrimitives.ReadHalfLittleEndian(v)).ToString("R", System.Globalization.CultureInfo.InvariantCulture),
                Kind.SignedBigEndian => v.Length == 0 ? "0" : new BigInteger(v, isUnsigned: false, isBigEndian: true).ToString(System.Globalization.CultureInfo.InvariantCulture),
                _ => Hex(v),
            };
        }
    }
}
