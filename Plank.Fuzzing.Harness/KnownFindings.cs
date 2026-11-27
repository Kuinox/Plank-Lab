using System.Text;

namespace Plank.Fuzzing.Harness;

// Recognises faults that are already documented library findings (fuzz/FINDINGS.md), by their
// precise signature, so that an AFL build can keep exploring instead of re-finding them.
//
// PLANK_FUZZ_KNOWN_FINDINGS = comma-separated ids, or "all". Unset (the default, and always for the
// replay driver) means nothing is recognised. A recognised fault is NOT reported to AFL as a crash;
// it is counted in $PLANK_FUZZ_CRASH_DIR/known-findings-<target>-<pid>.txt instead.
//
// Every signature is matched against exception.ToString() (the whole chain with inner exceptions and stack
// traces) and is deliberately narrow: a different message or call site stays a crash.
internal static class KnownFindings
{
    internal static readonly string[] AllIds =
    [
        "276",                                  // row-group row writer does not grow its slot
        "distinct-count-zero-unordered",        // INT96/INTERVAL/GEOMETRY/GEOGRAPHY write distinct_count = 0
        "uint-ulong-signed-stats",              // uint/ulong in an unannotated signed INT32/INT64: unsigned-order min/max
        "chunk-info-equality",                  // ParquetColumnChunkInfo.Equals throws NotSupportedException
        "decimal-without-annotation",           // precision/scale without annotation read as DECIMAL
        "page-size-int-max",                    // TargetDataPageSizeBytes = int.MaxValue overflows the pool
        "dataset-append-latest-converter",      // AppendToLatestRowGroup on a converter column
        "stale-scalar-slot-reuse",              // unassigned scalar column keeps the previous row group's value
        "negative-workercount",                 // WorkerCount < 0 -> OverflowException instead of ArgumentOutOfRange
    ];

    static readonly HashSet<string> Enabled = Parse(Environment.GetEnvironmentVariable("PLANK_FUZZ_KNOWN_FINDINGS"));
    static readonly Dictionary<string, long> Counts = new();
    static readonly object Gate = new();
    static long _hits;

    internal static bool Active => Enabled.Count > 0;

    static HashSet<string> Parse(string? value)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(value))
            return set;
        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part == "all")
                foreach (var id in AllIds)
                    set.Add(id);
            else
                set.Add(part);
        }
        return set;
    }

    /// <summary>Returns the id of the known finding the exception matches, or null (also when none is enabled).</summary>
    internal static string? Match(Exception exception, IReadOnlySet<string>? enabled = null)
    {
        enabled ??= Enabled;
        if (enabled.Count == 0)
            return null;
        var text = exception.ToString();
        foreach (var id in AllIds)
            if (enabled.Contains(id) && Matches(id, exception, text))
                return id;
        return null;
    }

    internal static IReadOnlySet<string> ParseIds(string value) => Parse(value);

    static bool Matches(string id, Exception e, string t)
    {
        bool Has(string s) => t.Contains(s, StringComparison.Ordinal);
        bool Chain<T>() where T : Exception
        {
            for (Exception? x = e; x is not null; x = x.InnerException)
                if (x is T) return true;
            return false;
        }

        switch (id)
        {
            case "276":
                return Has("No more row slots are available")
                    || (Chain<ArgumentOutOfRangeException>() && Has("Row index is outside the buffer slot") && Has("RowApiNestedLeafBuffer"));
            case "distinct-count-zero-unordered":
                return Has("written: statistics distinct_count differs from the values") && Has("distinct_count=0,")
                    && (Has("(Int96,") || Has(", Interval,")
                        // GEOMETRY/GEOGRAPHY columns are described as "none" by the oracle. Only the two routes that
                        // build them are accepted, so a plain unannotated BYTE_ARRAY with distinct_count = 0 stays a crash.
                        || Has("'logical-metadata' (ByteArray, none,") || Has("'key' (ByteArray, none,"));
            case "uint-ulong-signed-stats":
                return (Has("annotatedUnsigned=False clr=unsigned") && Has("statistics"))
                    || (Has("chunk statistics m") && Has("differs from the values") && (Has("(Int32, None") || Has("(Int64, None"))
                        && (Has("-uint'") || Has("-ulong'") || Has("uint-") || Has("ulong-")));
            case "chunk-info-equality":
                return Chain<NotSupportedException>() && Has("ParquetColumnChunkInfo") && Has("Equals");
            case "decimal-without-annotation":
                return Has("Decimal(") && Has("logical type") && Has("annotation");
            case "page-size-int-max":
                return Chain<OverflowException>() && Has("DefaultParquetBufferPool.Rent") && Has("EnsureCurrentSegment");
            case "dataset-append-latest-converter":
                return Chain<InvalidOperationException>() && Has("uses a converter for") && Has("cannot be read as");
            case "stale-scalar-slot-reuse":
                return Has("RowApiRoundTripException") && Has("'unset ") && Has(" read ") && Has(", expected ");
            case "negative-workercount":
                return Chain<OverflowException>() && Has("get_RowApiMaxParallelism");
            default:
                return false;
        }
    }

    /// <summary>Counts a recognised fault; the counts are written beside the crash dir (or /tmp).</summary>
    internal static void Record(string targetName, string id)
    {
        lock (Gate)
        {
            Counts[id] = Counts.GetValueOrDefault(id) + 1;
            // Write on the first sighting of an id and then every 64 hits, not on every execution.
            if (Counts[id] != 1 && (++_hits & 63) != 0)
                return;
            try
            {
                var dir = Environment.GetEnvironmentVariable("PLANK_FUZZ_CRASH_DIR");
                if (string.IsNullOrEmpty(dir)) dir = "/tmp";
                Directory.CreateDirectory(dir);
                var sb = new StringBuilder();
                foreach (var kv in Counts.OrderBy(k => k.Key, StringComparer.Ordinal))
                    sb.Append(kv.Key).Append('\t').Append(kv.Value).Append('\n');
                File.WriteAllText(Path.Combine(dir, $"known-findings-{targetName}-{Environment.ProcessId}.txt"), sb.ToString());
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
