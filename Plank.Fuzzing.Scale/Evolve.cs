using System.Text;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing.Scale;

/// <summary>
/// Schema evolution at scale through the generated row reader (workers, read-ahead, projections): files written with a
/// different schema than the row type — missing columns (MaterializeDefault), extra columns, other column order, required
/// file columns read into nullable properties, signed INT(32/64) annotations, and INT96 read as a TIMESTAMP property.
/// </summary>
public static class Evolve
{
    public static void Run(Rng rng, int tier, List<string> describe)
    {
        if (rng.Chance(30)) { Int96(rng, tier, describe); return; }
        var rows = tier == 0 ? rng.Pick(1L, 1025L, 2049L, 16385L, rng.Long(40_000)) : rng.Pick(100_000L, 300_000L);
        var specs = Writers.ScaleRowSpecs(rng, rows, allowHuge: false);
        // Which ScaleRow columns the file has; Id is always there so rows can be mapped.
        var present = specs.Select((_, i) => i == 0 || rng.Chance(70)).ToArray();
        // Optional properties (HighCard 2, Ratio 4, Payload 6) may be required in the file.
        var requiredInFile = new bool[8];
        foreach (var i in new[] { 2, 4, 6 })
            if (present[i] && rng.Chance(50)) { requiredInFile[i] = true; specs[i].Optional = false; }
        var annotate = rng.Chance(40);
        var fileCols = new List<ColSpec>();
        var defs = new List<ColumnDefinition>();
        for (var i = 0; i < 8; i++)
        {
            if (!present[i]) continue;
            fileCols.Add(specs[i]);
            defs.Add(Def(specs[i], annotate));
        }
        var extras = rng.Int(3);
        for (var x = 0; x < extras; x++)
        {
            var extra = ColSpec.Draw(rng, $"Extra{x}", (Kind)rng.Int(7), rng.Chance(50), rows, allowHuge: false);
            extra.Encodings = []; extra.Bloom = false; extra.Compression = null; extra.CompressionLevel = null;
            fileCols.Add(extra);
            defs.Add(extra.Definition());
        }
        // Shuffle the file's column order.
        var order = Enumerable.Range(0, fileCols.Count).OrderBy(_ => rng.Next()).ToArray();
        var cols = order.Select(i => fileCols[i]).ToArray();
        var schema = new ParquetSchema([.. order.Select(i => defs[i])]);
        var groups = Writers.DrawRowGroups(rng, rows);
        var options = Writers.DrawOptions(rng, rows, tier, rowApi: false, cols.Length);
        describe.Add($"evolve rows={rows} present={string.Join("", present.Select(p => p ? '1' : '0'))} requiredInFile={string.Join("", requiredInFile.Select(p => p ? '1' : '0'))} annotate={annotate} extras={extras} order={string.Join(",", order)}");
        describe.AddRange(cols.Select(c => c.ToString()));
        var output = new MemoryStream();
        using (var writer = schema.CreateWriter(output, options))
        {
            Writers.WriteGroups(writer, schema, cols, groups, 0, rng, options.InitialPageCapacity);
            writer.CloseFile();
        }
        var bytes = output.ToArray();
        var evolution = new ParquetSchemaEvolutionOptions
        {
            MissingColumns = MissingColumnEvolutionBehavior.MaterializeDefault,
            Repetition = rng.Chance(50) ? RepetitionEvolutionBehavior.AllowRequiredToOptional : RepetitionEvolutionBehavior.AllowRequiredToOptionalAndOptionalToRequired,
            LogicalTypes = SchemaTypeEvolutionBehavior.AllowCompatible,
            PhysicalTypes = rng.Chance(50) ? SchemaTypeEvolutionBehavior.AllowCompatible : SchemaTypeEvolutionBehavior.Reject,
        };
        foreach (var source in new IParquetReadSource[] { new MemoryReadSource(bytes), new JitterSource(bytes) })
        {
            var (projection, selected) = RowRead.DrawProjection(rng);
            var readOptions = RowRead.DrawOptions(rng);
            using var reader = ScaleRow.CreateRowReader(source, projection, readOptions, evolution);
            long r = 0;
            while (reader.MoveNext())
            {
                var row = reader.Current;
                var where = $"evolve rowreader (workers={readOptions.Execution.WorkerCount}) row {r}";
                if (selected[0] && row.Id != r) throw new Finding($"{where}: Id {row.Id}");
                if (selected[1]) Eq(where, "Category", row.Category, present[1] ? specs[1].Int32(r) : 0);
                if (selected[2]) Eq(where, "HighCard", row.HighCard, present[2] && !specs[2].IsNull(r) ? specs[2].Int64(r) : null);
                if (selected[3]) Eq(where, "Measure", BitConverter.DoubleToInt64Bits(row.Measure), present[3] ? BitConverter.DoubleToInt64Bits(specs[3].Double(r)) : 0L);
                if (selected[4]) Eq(where, "Ratio", row.Ratio is { } f ? BitConverter.SingleToInt32Bits(f) : (int?)null,
                    present[4] && !specs[4].IsNull(r) ? BitConverter.SingleToInt32Bits(specs[4].Float(r)) : null);
                if (selected[5]) Eq(where, "Flag", row.Flag, present[5] && specs[5].Bool(r));
                if (selected[6])
                {
                    var v = row.Payload;
                    var nul = !present[6] || specs[6].IsNull(r);
                    if (v.IsNull != nul) throw new Finding($"{where}: Payload null {v.IsNull}, expected {nul}");
                    if (!nul && !v.Value.SequenceEqual(Verify.ExpectedBytes(specs[6], r))) throw new Finding($"{where}: Payload differs");
                }
                if (selected[7])
                {
                    var label = row.Label;
                    if (present[7] ? label != specs[7].Str(r) : !string.IsNullOrEmpty(label))
                        throw new Finding($"{where}: Label {(label is null ? "null" : label.Length + " chars")}, expected {(present[7] ? specs[7].Str(r).Length + " chars" : "missing")}");
                }
                r++;
            }
            if (r != rows) throw new Finding($"evolve rowreader: {r} rows, expected {rows}");
        }
    }

    static void Eq<T>(string where, string name, T got, T want)
    {
        if (!EqualityComparer<T>.Default.Equals(got, want))
            throw new Finding($"{where}: {name} read {got}, expected {want}");
    }

    static ColumnDefinition Def(ColSpec s, bool annotate)
    {
        if (!annotate || s.Kind is not (Kind.Int32 or Kind.Int64))
            return s.Definition();
        var logical = new LogicalType.Int(s.Kind == Kind.Int32 ? (byte)32 : (byte)64, true);
        var options = new ColumnOptions();
        return s.Optional ? ColumnDefinition.OptionalLeaf(s.Name, s.Physical, options, logical)
                          : ColumnDefinition.RequiredLeaf(s.Name, s.Physical, options, logical);
    }

    /// <summary>A file whose "Stamp" column is INT96, read into ScaleTypes' TIMESTAMP(MICROS) property; all else missing.</summary>
    static void Int96(Rng rng, int tier, List<string> describe)
    {
        var rows = tier == 0 ? rng.Pick(1L, 2049L, 16385L) : 200_000L;
        var t = LType.Make(rng, "Stamp", LKind.Int96, false, rows);
        var id = RowTypes.IdSpec();
        describe.Add($"evolve-int96 rows={rows} {t}");
        var schema = new ParquetSchema([id.Definition(), ColumnDefinition.RequiredLeaf("Stamp", ParquetPhysicalType.Int96)]);
        var output = new MemoryStream();
        using (var writer = schema.CreateWriter(output))
        {
            Writers.WriteGroups(writer, schema, [id, t.Spec], Writers.DrawRowGroups(rng, rows), 0, rng);
            writer.CloseFile();
        }
        var evolution = new ParquetSchemaEvolutionOptions
        {
            MissingColumns = MissingColumnEvolutionBehavior.MaterializeDefault,
            PhysicalTypes = SchemaTypeEvolutionBehavior.AllowCompatible,
        };
        var options = RowRead.DrawOptions(rng);
        if (Environment.GetEnvironmentVariable("SCALE_KEEP") is { } keep)
        {
            Directory.CreateDirectory(keep);
            File.WriteAllBytes(Path.Combine(keep, "evolve-int96.parquet"), output.ToArray());
        }
        describe.Add($"read workers={options.Execution.WorkerCount} ahead={options.MaxReadAheadRowGroups}");
        using var reader = ScaleTypes.CreateRowReader(new MemoryReadSource(output.ToArray()), default, options, evolution);
        long r = 0;
        while (reader.MoveNext())
        {
            var row = reader.Current;
            var want = t.Int96Ticks(r);
            if (row.Id != r) throw new Finding($"evolve-int96 row {r}: Id {row.Id}");
            if (want is null || row.Stamp.Ticks != want.Value)
                throw new Finding($"evolve-int96 row {r}: Stamp {row.Stamp:O} ({row.Stamp.Ticks}), expected {want} (raw {Verify.Hex(t.Spec.Bytes(r))}, workers={options.Execution.WorkerCount})");
            // row.Key (required Guid) is not read: its generated getter throws for a missing column (fuzz/repros/guid-missing-default).
            if (row.Dec9 != 0 || row.MaybeKey is not null || row.Doc is not null || row.U32 != 0)
                throw new Finding($"evolve-int96 row {r}: a missing column did not materialize its default");
            r++;
        }
        if (r != rows) throw new Finding($"evolve-int96: {r} rows, expected {rows}");
    }
}
