using System.IO.Hashing;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>
/// Twin-path consistency: the same column chunk decoded through every Plank path that reaches a
/// different implementation — the typed T read, the nullable T? read (another decode family), a
/// value converter (the converted whole-page decoders), an accept-all page pruner (page-at-a-time
/// reads), the borrow/no-borrow reader options, the nested reader, the binary reader and the row
/// reader — must agree: all reject, or all return the same levels and values. One path accepting
/// what another rejects is a finding even when Arrow rejects the file too (it means one of the
/// paths decoded impossible data). API refusals (NotSupported, InvalidOperation, InvalidCast) are
/// not verdicts. Scalar vs vector tiers are compared across processes (PLANK_FUZZ_VERDICTS +
/// DOTNET_EnableHWIntrinsic=0 / DOTNET_EnableAVX2=0 / DOTNET_EnableAVX512F=0 runs, diffed by
/// fuzz/tools/isa-verdicts.sh).
/// </summary>
public static partial class StructuredPageMutator
{
    public static long TwinReads, TwinDisagreements;

    sealed record Verdict(bool Rejected, ulong Digest, string Note);

    readonly record struct TwinBox<T>(T Value) where T : unmanaged;

    sealed class TwinBoxConverter<T> : ParquetValueConverter<TwinBox<T>, T> where T : unmanaged
    {
        public override TwinBox<T> ConvertFromPhysical(T value) => new(value);
        public override T ConvertToPhysical(TwinBox<T> value) => value.Value;
    }

    static bool IsApiRefusal(Exception e) => e is NotSupportedException or InvalidOperationException or InvalidCastException;

    static readonly ParquetPagePruner AcceptAll = static (in ParquetDataPageMetadata _) => true;

    /// <summary>Null when every path agrees; else a description. <paramref name="summary"/> digests all verdicts.</summary>
    static string? TwinDisagreement(byte[] file, out string summary)
    {
        summary = "";
        List<LeafColumn> leaves;
        int groupCount;
        try
        {
            using var probe = new ParquetReader();
            probe.Reset(new MemoryReadSource(file));
            leaves = [.. probe.Schema.LeafColumns];
            groupCount = probe.RowGroups.Count;
        }
        catch (Exception e) when (e is CorruptParquetException || IsApiRefusal(e))
        {
            summary = "footer-reject";
            return null;
        }

        var parts = new List<string>();
        var flatSchema = leaves.All(static l => l.MaxRepetitionLevel == 0) && leaves.Count > 0 && !leaves.Any(static l => l.Path.Contains('.'));
        var rowVerdicts = flatSchema ? RowReaderVerdicts(file, leaves) : null;
        for (var g = 0; g < groupCount; g++)
            for (var c = 0; c < leaves.Count; c++)
            {
                var verdicts = new List<(string Path, Verdict Verdict)>();
                foreach (var (name, read) in Paths(leaves[c], file))
                {
                    var v = Run(() => read(g, c));
                    if (v is not null) verdicts.Add((name, v));
                }
                if (rowVerdicts is not null && rowVerdicts[g, c] is { } rv)
                    verdicts.Add(("RowReaderCore", rv));
                TwinReads += verdicts.Count;
                parts.Add(string.Join(",", verdicts.Select(static v => v.Verdict.Rejected ? "R" : v.Verdict.Digest.ToString("x16"))));
                for (var i = 1; i < verdicts.Count; i++)
                {
                    var a = verdicts[0];
                    var b = verdicts[i];
                    if (a.Verdict.Rejected != b.Verdict.Rejected || (!a.Verdict.Rejected && a.Verdict.Digest != b.Verdict.Digest))
                    {
                        TwinDisagreements++;
                        summary = string.Join("|", parts);
                        return $"row group {g}, column {c} '{leaves[c].Path}' ({leaves[c].PhysicalType}): "
                            + $"{a.Path} {(a.Verdict.Rejected ? "rejects (" + a.Verdict.Note + ")" : "accepts")} but "
                            + $"{b.Path} {(b.Verdict.Rejected ? "rejects (" + b.Verdict.Note + ")" : "accepts")}"
                            + (a.Verdict.Rejected == b.Verdict.Rejected ? " with different values" : "");
                    }
                }
            }
        summary = string.Join("|", parts);
        return null;
    }

    static Verdict? Run(Func<ulong> read)
    {
        try
        {
            return new Verdict(false, read(), "");
        }
        catch (CorruptParquetException e)
        {
            return new Verdict(true, 0, e.Message.Length > 80 ? e.Message[..80] : e.Message);
        }
        catch (Exception e) when (IsApiRefusal(e))
        {
            return null;
        }
    }

    static ParquetReader Open(byte[] file, ParquetReaderOptions? options = null, ParquetPagePruner? pruner = null)
    {
        var reader = new ParquetReader(options);
        reader.Reset(new MemoryReadSource(file), pruner);
        return reader;
    }

    static IEnumerable<(string Name, Func<int, int, ulong> Read)> Paths(LeafColumn leaf, byte[] file)
    {
        var options = new (string Name, ParquetReaderOptions? Options, ParquetPagePruner? Pruner)[]
        {
            ("default", null, null),
            ("no-borrow", new ParquetReaderOptions { BorrowRequiredPlainValues = false, BorrowBinaryValues = false }, null),
            ("borrow-binary", new ParquetReaderOptions { BorrowRequiredPlainValues = true, BorrowBinaryValues = true }, null),
            ("pruner", null, AcceptAll),
        };
        foreach (var (name, opts, pruner) in options)
        {
            if (leaf.MaxRepetitionLevel > 0)
            {
                yield return ($"NestedColumn[{name}]", (g, c) => { using var r = Open(file, opts, pruner); return NestedDigest(r.RowGroups[g], r.Schema.LeafColumns[c]); });
                continue;
            }
            switch (leaf.PhysicalType)
            {
                case ParquetPhysicalType.Boolean: foreach (var p in Flat<bool>(name, file, opts, pruner, leaf)) yield return p; break;
                case ParquetPhysicalType.Int32: foreach (var p in Flat<int>(name, file, opts, pruner, leaf)) yield return p; break;
                case ParquetPhysicalType.Int64: foreach (var p in Flat<long>(name, file, opts, pruner, leaf)) yield return p; break;
                case ParquetPhysicalType.Float: foreach (var p in Flat<float>(name, file, opts, pruner, leaf)) yield return p; break;
                case ParquetPhysicalType.Double: foreach (var p in Flat<double>(name, file, opts, pruner, leaf)) yield return p; break;
                default:
                    yield return ($"Column<byte>[{name}]", (g, c) => { using var r = Open(file, opts, pruner); return BinaryDigest(r.RowGroups[g], r.Schema.LeafColumns[c]); });
                    break;
            }
        }
        // The converted whole-page decoders, through a requested schema mirroring the file's.
        if (leaf.MaxRepetitionLevel == 0)
        {
            switch (leaf.PhysicalType)
            {
                case ParquetPhysicalType.Int32: yield return ("converter", (g, c) => ConverterDigest<int>(file, g, c)); break;
                case ParquetPhysicalType.Int64: yield return ("converter", (g, c) => ConverterDigest<long>(file, g, c)); break;
                case ParquetPhysicalType.Float: yield return ("converter", (g, c) => ConverterDigest<float>(file, g, c)); break;
                case ParquetPhysicalType.Double: yield return ("converter", (g, c) => ConverterDigest<double>(file, g, c)); break;
                case ParquetPhysicalType.Boolean: yield return ("converter", (g, c) => ConverterDigest<bool>(file, g, c)); break;
            }
        }
    }

    static IEnumerable<(string Name, Func<int, int, ulong> Read)> Flat<T>(string name, byte[] file, ParquetReaderOptions? options,
        ParquetPagePruner? pruner, LeafColumn leaf) where T : unmanaged
    {
        // T? is its own decode family (nullable decoders) also on a required column.
        yield return ($"Column<T?>[{name}]", (g, c) =>
        {
            using var r = Open(file, options, pruner);
            var hash = new XxHash64();
            foreach (var buffer in r.RowGroups[g].Column<T?>(r.Schema.LeafColumns[c]))
                foreach (var value in buffer.Values)
                    AppendValue(hash, value);
            return hash.GetCurrentHashAsUInt64();
        });
        if (leaf.MaxDefinitionLevel == 0)
            yield return ($"Column<T>[{name}]", (g, c) =>
            {
                using var r = Open(file, options, pruner);
                var hash = new XxHash64();
                foreach (var buffer in r.RowGroups[g].Column<T>(r.Schema.LeafColumns[c]))
                    foreach (var value in buffer.Values)
                        AppendValue(hash, (T?)value);
                return hash.GetCurrentHashAsUInt64();
            });
    }

    static void AppendValue<T>(XxHash64 hash, T? value) where T : unmanaged
    {
        if (value is { } v)
        {
            hash.Append([1]);
            hash.Append(System.Runtime.InteropServices.MemoryMarshal.AsBytes(new ReadOnlySpan<T>(in v)));
        }
        else
            hash.Append([0]);
    }

    static ulong BinaryDigest(RowGroup group, LeafColumn leaf)
    {
        var hash = new XxHash64();
        foreach (var buffer in group.Column<byte>(leaf))
            for (var i = 0; i < buffer.Count; i++)
            {
                if (buffer.IsNull(i)) { hash.Append([0]); continue; }
                var value = buffer.GetValue(i);
                hash.Append([1]);
                hash.Append(BitConverter.GetBytes(value.Length));
                hash.Append(value);
            }
        return hash.GetCurrentHashAsUInt64();
    }

    static ulong NestedDigest(RowGroup group, LeafColumn leaf)
    {
        var hash = new XxHash64();
        switch (leaf.PhysicalType)
        {
            case ParquetPhysicalType.Boolean: NestedFixed<bool>(hash, group, leaf); break;
            case ParquetPhysicalType.Int32: NestedFixed<int>(hash, group, leaf); break;
            case ParquetPhysicalType.Int64: NestedFixed<long>(hash, group, leaf); break;
            case ParquetPhysicalType.Float: NestedFixed<float>(hash, group, leaf); break;
            case ParquetPhysicalType.Double: NestedFixed<double>(hash, group, leaf); break;
            default:
                foreach (var buffer in group.NestedColumn<byte>(leaf))
                {
                    hash.Append(System.Runtime.InteropServices.MemoryMarshal.AsBytes(buffer.DefinitionLevels));
                    hash.Append(System.Runtime.InteropServices.MemoryMarshal.AsBytes(buffer.RepetitionLevels));
                    var values = buffer.Values;
                    for (var i = 0; i < values.Count; i++)
                    {
                        hash.Append(BitConverter.GetBytes(values.GetValue(i).Length));
                        hash.Append(values.GetValue(i));
                    }
                }
                break;
        }
        return hash.GetCurrentHashAsUInt64();
    }

    static void NestedFixed<T>(XxHash64 hash, RowGroup group, LeafColumn leaf) where T : unmanaged
    {
        foreach (var buffer in group.NestedColumn<T>(leaf))
        {
            hash.Append(System.Runtime.InteropServices.MemoryMarshal.AsBytes(buffer.DefinitionLevels));
            hash.Append(System.Runtime.InteropServices.MemoryMarshal.AsBytes(buffer.RepetitionLevels));
            hash.Append(System.Runtime.InteropServices.MemoryMarshal.AsBytes(buffer.Values.Values));
        }
    }

    static ulong ConverterDigest<T>(byte[] file, int g, int c) where T : unmanaged
    {
        using var probe = Open(file);
        var leaves = probe.Schema.LeafColumns;
        var definitions = new ColumnDefinition[leaves.Length];
        for (var i = 0; i < leaves.Length; i++)
        {
            var l = leaves[i];
            var options = new ColumnOptions(l.MaxDefinitionLevel > 0 ? ParquetRepetition.Optional : ParquetRepetition.Required,
                typeLength: l.Options.TypeLength);
            ParquetValueConverter? converter = i == c ? new TwinBoxConverter<T>() : null;
            definitions[i] = l.MaxDefinitionLevel > 0
                ? ColumnDefinition.OptionalLeaf(l.Path, l.PhysicalType, options, l.LogicalType, converter: converter)
                : ColumnDefinition.RequiredLeaf(l.Path, l.PhysicalType, options, l.LogicalType, converter: converter);
        }
        using var reader = new ParquetSchema(System.Collections.Immutable.ImmutableArray.Create(definitions)).CreateReader(new MemoryReadSource(file));
        var hash = new XxHash64();
        var leaf = reader.Schema.LeafColumns[c];
        if (leaf.MaxDefinitionLevel > 0)
        {
            foreach (var buffer in reader.RowGroups[g].Column<TwinBox<T>?>(leaf))
                foreach (var value in buffer.Values)
                    AppendValue(hash, value is { } v ? (T?)v.Value : null);
        }
        else
        {
            foreach (var buffer in reader.RowGroups[g].Column<TwinBox<T>>(leaf))
                foreach (var value in buffer.Values)
                    AppendValue(hash, (T?)value.Value);
        }
        return hash.GetCurrentHashAsUInt64();
    }

    /// <summary>The row reader over a flat schema: per-row-group, per-column digests, or all rejected.</summary>
    static Verdict?[,]? RowReaderVerdicts(byte[] file, List<LeafColumn> leaves)
    {
        int groups;
        long[] rowsPerGroup;
        ParquetSchema schema;
        try
        {
            using var probe = Open(file);
            groups = probe.RowGroups.Count;
            rowsPerGroup = [.. probe.RowGroups.Select(static g => (long)g.RowCount)];
            schema = probe.Schema;
        }
        catch (Exception e) when (e is CorruptParquetException || IsApiRefusal(e))
        {
            return null;
        }
        // Descriptors must be built over the very schema instance the row reader is given.
        var descriptors = schema.LeafColumns.Select((l, i) => (RowApiColumnDescriptor)(l.PhysicalType switch
        {
            ParquetPhysicalType.Boolean => l.MaxDefinitionLevel > 0 ? new RowApiColumnDescriptor<bool?>($"p{i}", l) : new RowApiColumnDescriptor<bool>($"p{i}", l),
            ParquetPhysicalType.Int32 => l.MaxDefinitionLevel > 0 ? new RowApiColumnDescriptor<int?>($"p{i}", l) : new RowApiColumnDescriptor<int>($"p{i}", l),
            ParquetPhysicalType.Int64 => l.MaxDefinitionLevel > 0 ? new RowApiColumnDescriptor<long?>($"p{i}", l) : new RowApiColumnDescriptor<long>($"p{i}", l),
            ParquetPhysicalType.Float => l.MaxDefinitionLevel > 0 ? new RowApiColumnDescriptor<float?>($"p{i}", l) : new RowApiColumnDescriptor<float>($"p{i}", l),
            ParquetPhysicalType.Double => l.MaxDefinitionLevel > 0 ? new RowApiColumnDescriptor<double?>($"p{i}", l) : new RowApiColumnDescriptor<double>($"p{i}", l),
            _ => new RowApiColumnDescriptor<byte[]>($"p{i}", l),
        })).ToArray();
        var hashes = new XxHash64[groups, leaves.Count];
        for (var g = 0; g < groups; g++)
            for (var c = 0; c < leaves.Count; c++)
                hashes[g, c] = new XxHash64();
        var result = new Verdict?[groups, leaves.Count];
        try
        {
            using var rows = new RowReaderCore(new MemoryReadSource(file), schema, descriptors, projection: null,
                new RowReaderOptions { Execution = new ParquetExecutionOptions { WorkerCount = 1 } }, schemaEvolution: null);
            long row = 0;
            var group = 0;
            while (rows.MoveNext())
            {
                while (group < groups && row >= rowsPerGroup[group]) { row -= rowsPerGroup[group]; group++; }
                if (group >= groups) break;
                for (var c = 0; c < leaves.Count; c++)
                    AppendRowValue(hashes[group, c], rows, descriptors[c]);
                row++;
            }
        }
        catch (CorruptParquetException e)
        {
            // The row reader reads every column together: a rejection covers the file. It may stop at the
            // first bad column, so only "accepts while every columnar path rejects" is compared, below.
            for (var g = 0; g < groups; g++)
                for (var c = 0; c < leaves.Count; c++)
                    result[g, c] = null;
            _ = e;
            return result;
        }
        catch (Exception e) when (IsApiRefusal(e))
        {
            return null;
        }
        for (var g = 0; g < groups; g++)
            for (var c = 0; c < leaves.Count; c++)
                result[g, c] = new Verdict(false, hashes[g, c].GetCurrentHashAsUInt64(), "");
        return result;
    }

    static void AppendRowValue(XxHash64 hash, RowReaderCore rows, RowApiColumnDescriptor descriptor)
    {
        switch (descriptor)
        {
            case RowApiColumnDescriptor<bool> d: AppendValue(hash, (bool?)rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<bool?> d: AppendValue(hash, rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<int> d: AppendValue(hash, (int?)rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<int?> d: AppendValue(hash, rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<long> d: AppendValue(hash, (long?)rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<long?> d: AppendValue(hash, rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<float> d: AppendValue(hash, (float?)rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<float?> d: AppendValue(hash, rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<double> d: AppendValue(hash, (double?)rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<double?> d: AppendValue(hash, rows.GetCurrent(d)); break;
            case RowApiColumnDescriptor<byte[]> d:
            {
                var current = rows.GetCurrentBinary(d);
                if (current.IsNull) { hash.Append([0]); break; }
                hash.Append([1]);
                hash.Append(BitConverter.GetBytes(current.Value.Length));
                hash.Append(current.Value);
                break;
            }
        }
    }
}
