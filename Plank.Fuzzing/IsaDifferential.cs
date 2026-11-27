using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>
/// Decodes one file twice, with the library's dispatch flags at their machine defaults and then all inverted,
/// and requires identical results.
/// </summary>
internal static class IsaDifferential
{
    internal static void Check(byte[] fileBytes, ParquetReaderOptions options)
    {
        var saved = IsaFlags.Current;
        List<(string Label, (object?[]? Values, Exception? Error) Read)> baseline, inverted;
        try
        {
            IsaFlags.Apply(0);
            baseline = Snapshot(fileBytes, options);
            IsaFlags.Apply(IsaFlags.AllMask);
            inverted = Snapshot(fileBytes, options);
        }
        finally
        {
            IsaFlags.Apply(saved);
        }

        if (baseline.Count != inverted.Count)
            throw new ReaderAcceptanceMismatchException(
                $"Decoded value mismatch (ISA flags) — {baseline.Count} reads with default flags, {inverted.Count} inverted.");
        for (var i = 0; i < baseline.Count; i++)
        {
            var (label, a) = baseline[i];
            var (_, b) = inverted[i];
            // A read that fails identically (same exception type) has nothing to compare; one that
            // fails on one side only is a verdict mismatch.
            if (a.Error is not null || b.Error is not null)
            {
                if (a.Error?.GetType() != b.Error?.GetType())
                    throw new ReaderAcceptanceMismatchException(
                        $"Decoded value mismatch (ISA flags) — {label}: default flags {Describe(a.Error)}, inverted {Describe(b.Error)}.");
                continue;
            }
            if (a.Values is null || b.Values is null)
                continue;
            if (a.Values.Length != b.Values.Length)
                throw new ReaderAcceptanceMismatchException(
                    $"Decoded value mismatch (ISA flags) — {label}: {a.Values.Length} vs {b.Values.Length} entries.");
            for (var row = 0; row < a.Values.Length; row++)
                if (!Equals(a.Values[row], b.Values[row]))
                    throw new ReaderAcceptanceMismatchException(
                        $"Decoded value mismatch (ISA flags) — {label} row {row}: {a.Values[row]} (default flags) vs {b.Values[row]} (inverted).");
        }
    }

    // Cross-process differential: PLANK_FUZZ_DIGEST_FILE=<path> appends "<input hash>\t<digest of every decoded value>" for each
    // file-schema input. Run the same corpus under different ISA environments (AVX-512, AVX2, scalar) and compare the files:
    // identical inputs must give identical digests (`join` on the first column; see fuzz/tools-reader-coverage/digest-compare.sh).
    static readonly string? DigestFile = Environment.GetEnvironmentVariable("PLANK_FUZZ_DIGEST_FILE");

    internal static void AppendDigest(ReadOnlySpan<byte> input, byte[] fileBytes, ParquetReaderOptions options)
    {
        if (string.IsNullOrEmpty(DigestFile))
            return;
        var text = new System.Text.StringBuilder();
        foreach (var (label, (values, error)) in Snapshot(fileBytes, options))
        {
            text.Append(label).Append('=');
            if (error is not null)
                text.Append("ERR:").Append(error.GetType().Name);
            else if (values is not null)
                foreach (var v in values)
                    text.Append(v is IFormattable f ? f.ToString(null, System.Globalization.CultureInfo.InvariantCulture) : v?.ToString() ?? "null").Append(',');
            text.Append('\n');
        }
        var digest = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text.ToString())))[..16];
        var key = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(input))[..16];
        lock (DigestFile)
            File.AppendAllText(DigestFile, $"{key}\t{digest}\n");
    }

    static string Describe(Exception? error) => error is null ? "read it" : $"threw {error.GetType().Name}";

    // Reads every flat column of every row group as T and T? (where T is the column's natural CLR type), the
    // two shapes that reach the required and nullable vector kernels.
    static List<(string, (object?[]?, Exception?))> Snapshot(byte[] fileBytes, ParquetReaderOptions options)
    {
        var reads = new List<(string, (object?[]?, Exception?))>();
        try
        {
            using var reader = new ParquetReader(options);
            reader.Reset(new MemoryReadSource(fileBytes));
            for (var g = 0; g < reader.RowGroups.Count; g++)
            {
                var group = reader.RowGroups[g];
                if (group.RowCount > 20_000)
                    continue;
                foreach (var column in reader.Schema.LeafColumns)
                {
                    if (column.MaxRepetitionLevel > 0)
                        continue;
                    switch (column.LogicalType)
                    {
                        case LogicalType.Date: Both<DateOnly>(reads, g, group, column); continue;
                        case LogicalType.Time: Both<TimeOnly>(reads, g, group, column); continue;
                        case LogicalType.Timestamp: Both<DateTime>(reads, g, group, column); continue;
                        case LogicalType.Decimal: Both<decimal>(reads, g, group, column); continue;
                        case LogicalType.Int { BitWidth: 8, IsSigned: false }: Both<byte>(reads, g, group, column); continue;
                        case LogicalType.Int { BitWidth: 16, IsSigned: false }: Both<ushort>(reads, g, group, column); continue;
                        case LogicalType.Int { BitWidth: 32, IsSigned: false }: Both<uint>(reads, g, group, column); continue;
                        case LogicalType.Int { BitWidth: 64, IsSigned: false }: Both<ulong>(reads, g, group, column); continue;
                    }
                    switch (column.PhysicalType)
                    {
                        case ParquetPhysicalType.Boolean: Both<bool>(reads, g, group, column); break;
                        case ParquetPhysicalType.Int32: Both<int>(reads, g, group, column); break;
                        case ParquetPhysicalType.Int64: Both<long>(reads, g, group, column); break;
                        case ParquetPhysicalType.Float: Both<float>(reads, g, group, column); break;
                        case ParquetPhysicalType.Double: Both<double>(reads, g, group, column); break;
                    }
                }
            }
        }
        catch (Exception error) when (PlankReaderFuzzTarget.IsExpectedRejection(error))
        {
            reads.Add(("open", (null, error)));
        }
        return reads;
    }

    static void Both<T>(List<(string, (object?[]?, Exception?))> reads, int group, RowGroup rowGroup, LeafColumn column)
        where T : struct
    {
        reads.Add(($"{typeof(T).Name} rg{group} '{column.Path}'", PlankReaderFuzzTarget.TryReadPathPublic(
            () => Array.ConvertAll(PlankReaderFuzzTarget.DrainValuesPublic(rowGroup.Column<T>(column)), static v => (object?)v))));
        reads.Add(($"{typeof(T).Name}? rg{group} '{column.Path}'", PlankReaderFuzzTarget.TryReadPathPublic(
            () => Array.ConvertAll(PlankReaderFuzzTarget.DrainValuesPublic(rowGroup.Column<T?>(column)), static v => (object?)v))));
    }
}
