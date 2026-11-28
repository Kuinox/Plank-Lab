using System.Text;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;
using Plank.Schema;

namespace Plank.Fuzzing;

/// <summary>
/// Prints, for every repeated leaf of a file, what Plank's columnar nested reader and its row API each return — the raw
/// repetition/definition levels, the dense values and whether those levels respect the schema — so a file that Plank accepts can be
/// compared with what Arrow decodes. Diagnostic only (Reader.Target --triage-nested).
/// </summary>
public static class NestedTriage
{
    static void Trace(string stage)
    {
        if (Environment.GetEnvironmentVariable("PLANK_TRIAGE_TRACE") == "1")
            Console.Error.WriteLine("  stage: " + stage);
    }

    public static string Dump(byte[] file)
    {
        var text = new StringBuilder();
        try
        {
            using var reader = new ParquetReader(new ParquetReaderOptions { Strict = false });
            reader.Reset(new MemoryReadSource(file));
            var leaves = reader.Schema.LeafColumns;
            text.AppendLine($"schema: {string.Join("; ", leaves.Select(l => $"{l.Path}:{l.PhysicalType} rep<={l.MaxRepetitionLevel} def<={l.MaxDefinitionLevel}"))}");
            for (var g = 0; g < reader.RowGroups.Count; g++)
                for (var c = 0; c < leaves.Length; c++)
                {
                    if (leaves[c].MaxRepetitionLevel == 0)
                        continue;
                    text.Append($"[columnar rg{g} {leaves[c].Path}] ");
                    try { text.AppendLine(Columnar(reader.RowGroups[g], leaves[c])); }
                    catch (Exception ex) { text.AppendLine($"THROWS {ex.GetType().Name}: {ex.Message}"); }
                }
        }
        catch (Exception ex)
        {
            text.AppendLine($"open/columnar THROWS {ex.GetType().Name}: {ex.Message}");
        }

        try { text.Append(Rows(file)); }
        catch (Exception ex) { text.AppendLine($"[rowapi] THROWS {ex.GetType().Name}: {ex.Message}"); }
        return text.ToString();
    }

    static string Columnar(RowGroup group, LeafColumn leaf) => leaf.PhysicalType switch
    {
        ParquetPhysicalType.Boolean => Columnar<bool>(group, leaf),
        ParquetPhysicalType.Int32 => Columnar<int>(group, leaf),
        ParquetPhysicalType.Int64 => Columnar<long>(group, leaf),
        ParquetPhysicalType.Float => Columnar<float>(group, leaf),
        ParquetPhysicalType.Double => Columnar<double>(group, leaf),
        _ => Columnar<byte>(group, leaf)
    };

    static string Columnar<T>(RowGroup group, LeafColumn leaf) where T : unmanaged
    {
        var rep = new List<int>();
        var def = new List<int>();
        var values = new List<string>();
        var rows = 0;
        Trace("NestedColumn<T> enumerate");
        foreach (var page in group.NestedColumn<T>(leaf))
        {
            Trace($"page levels={page.Count} values={page.Values.Count} rows={page.RowCount}");
            rep.AddRange(page.RepetitionLevels.ToArray());
            Trace("rep copied");
            def.AddRange(page.DefinitionLevels.ToArray());
            Trace("def copied");
            for (var i = 0; i < page.Values.Count; i++)
                values.Add(page.Values.IsNull(i) ? "null" : Convert.ToString(page.Values.Values[i], System.Globalization.CultureInfo.InvariantCulture) ?? "");
            rows += page.RowCount;
        }
        return $"rows={rows} entries={rep.Count} values={values.Count} rep=[{string.Join(',', rep)}] def=[{string.Join(',', def)}] vals=[{string.Join(',', values)}] | {Check(rep, def, values.Count, leaf)}";
    }

    internal static string Check(IReadOnlyList<int> rep, IReadOnlyList<int> def, int valueCount, LeafColumn leaf)
    {
        var problems = new List<string>();
        var dense = 0;
        for (var i = 0; i < def.Count; i++)
        {
            if (def[i] > leaf.MaxDefinitionLevel || def[i] < 0) problems.Add($"def[{i}]={def[i]}>max{leaf.MaxDefinitionLevel}");
            if (rep[i] > leaf.MaxRepetitionLevel || rep[i] < 0) problems.Add($"rep[{i}]={rep[i]}>max{leaf.MaxRepetitionLevel}");
            if (def[i] == leaf.MaxDefinitionLevel) dense++;
        }
        if (rep.Count > 0 && rep[0] != 0) problems.Add("first level not at rep 0");
        if (dense != valueCount) problems.Add($"{dense} positions at max def but {valueCount} values");
        return problems.Count == 0 ? "levels OK" : "INVALID: " + string.Join("; ", problems.Take(6));
    }

    static string Rows(byte[] file)
    {
        var text = new StringBuilder();
        using var source = new MemoryReadSource(file);
        ParquetSchema schema;
        using (var reader = new ParquetReader(new ParquetReaderOptions { Strict = false }))
        {
            reader.Reset(source);
            schema = reader.Schema;
        }
        var descriptors = new RowApiColumnDescriptor[schema.LeafColumns.Length];
        for (var i = 0; i < descriptors.Length; i++)
            descriptors[i] = PlankReaderFuzzTarget.DescriptorFor(schema.LeafColumns[i], i) ?? throw new NotSupportedException("no descriptor");
        using var rows = new RowReaderCore(source, schema, descriptors, projection: null,
            new RowReaderOptions { Execution = new ParquetExecutionOptions { WorkerCount = 1 } }, schemaEvolution: null);
        var n = 0;
        Trace("row api start");
        while (rows.MoveNext())
        {
            Trace($"row {n}");
            for (var i = 0; i < descriptors.Length; i++)
            {
                var leaf = schema.LeafColumns[i];
                if (leaf.MaxRepetitionLevel == 0)
                    continue;
                text.Append($"[row {n} {leaf.Path}] ");
                text.AppendLine(descriptors[i] switch
                {
                    RowApiNestedColumnDescriptor<bool> d => One(rows.GetCurrentNested(d), leaf),
                    RowApiNestedColumnDescriptor<int> d => One(rows.GetCurrentNested(d), leaf),
                    RowApiNestedColumnDescriptor<long> d => One(rows.GetCurrentNested(d), leaf),
                    RowApiNestedColumnDescriptor<float> d => One(rows.GetCurrentNested(d), leaf),
                    RowApiNestedColumnDescriptor<double> d => One(rows.GetCurrentNested(d), leaf),
                    RowApiNestedColumnDescriptor<byte[]> d => One(rows.GetCurrentNested(d), leaf),
                    _ => "(not nested)"
                });
            }
            n++;
        }
        text.AppendLine($"[rowapi] {n} rows");
        return text.ToString();
    }

    static string One<T>(RowApiNestedLeafRow<T> row, LeafColumn leaf)
    {
        var rep = row.RepetitionLevels.ToArray().Select(static b => (int)b).ToList();
        var def = row.DefinitionLevels.ToArray().Select(static b => (int)b).ToList();
        var values = row.Values.ToArray().Select(static v => v is byte[] b ? Convert.ToHexString(b) : Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "").ToList();
        return $"rep=[{string.Join(',', rep)}] def=[{string.Join(',', def)}] vals=[{string.Join(',', values)}] | {Check(rep, def, values.Count, leaf)}";
    }
}
