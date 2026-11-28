using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;

namespace Plank.Fuzzing.Scale;

public static class RowRead
{
    public static long Rows;

    static readonly ScaleRow.Projection[] Single =
    [
        ScaleRow.Projection.Id, ScaleRow.Projection.Category, ScaleRow.Projection.HighCard, ScaleRow.Projection.Measure,
        ScaleRow.Projection.Ratio, ScaleRow.Projection.Flag, ScaleRow.Projection.Payload, ScaleRow.Projection.Label,
    ];

    public static (ScaleRow.Projection Projection, bool[] Selected) DrawProjection(Rng rng)
    {
        var selected = new bool[8];
        if (rng.Chance(40))
        {
            Array.Fill(selected, true);
            return (ScaleRow.Projection.All, selected);
        }
        ScaleRow.Projection p = default;
        var any = false;
        for (var i = 0; i < 8; i++)
        {
            if (!rng.Chance(50))
                continue;
            p = any ? p | Single[i] : Single[i];
            selected[i] = any = true;
        }
        if (!any)
        {
            var i = rng.Int(8);
            p = Single[i];
            selected[i] = true;
        }
        return (p, selected);
    }

    public static RowReaderOptions DrawOptions(Rng rng, int maxWorkers = 16)
        => new()
        {
            MaxReadAheadRowGroups = rng.Int(2),
            VerifyPageCrc = rng.Chance(20),
            Execution = new Plank.ParquetExecutionOptions
            {
                WorkerCount = Math.Min(maxWorkers, rng.Pick(1, 2, 3, 4, 8, 16)),
                OnWorkerStarted = rng.Chance(50) ? _ => Jitter.Maybe() : null,
            },
        };

    /// <summary>Generated row reader over a ScaleRow file; every selected property against the spec.</summary>
    public static void ScaleRows(IParquetReadSource source, Expected e, ScaleRow.Projection projection, bool[] selected,
        RowReaderOptions options, string where)
    {
        var s = e.Cols;
        using var reader = ScaleRow.CreateRowReader(source, projection, options);
        long i = 0;
        while (reader.MoveNext())
        {
            var row = reader.Current;
            var r = e.Row(i);
            if (selected[0] && row.Id != s[0].Int64(r)) Fail(where, i, "Id", row.Id, s[0].Int64(r));
            if (selected[1] && row.Category != s[1].Int32(r)) Fail(where, i, "Category", row.Category, s[1].Int32(r));
            if (selected[2])
            {
                var v = row.HighCard;
                if (v.HasValue == s[2].IsNull(r) || (v.HasValue && v.Value != s[2].Int64(r)))
                    Fail(where, i, "HighCard", v, s[2].IsNull(r) ? null : s[2].Int64(r));
            }
            if (selected[3] && BitConverter.DoubleToInt64Bits(row.Measure) != BitConverter.DoubleToInt64Bits(s[3].Double(r)))
                Fail(where, i, "Measure", row.Measure, s[3].Double(r));
            if (selected[4])
            {
                var v = row.Ratio;
                if (v.HasValue == s[4].IsNull(r) || (v.HasValue && BitConverter.SingleToInt32Bits(v.Value) != BitConverter.SingleToInt32Bits(s[4].Float(r))))
                    Fail(where, i, "Ratio", v, s[4].IsNull(r) ? null : s[4].Float(r));
            }
            if (selected[5] && row.Flag != s[5].Bool(r)) Fail(where, i, "Flag", row.Flag, s[5].Bool(r));
            if (selected[6])
            {
                var v = row.Payload;
                if (v.IsNull != s[6].IsNull(r))
                    Fail(where, i, "Payload.IsNull", v.IsNull, s[6].IsNull(r));
                if (!v.IsNull && !v.Value.SequenceEqual(Verify.ExpectedBytes(s[6], r)))
                    Fail(where, i, "Payload", Verify.Hex(v.Value) + $" ({v.Value.Length}B)", Verify.Hex(Verify.ExpectedBytes(s[6], r)));
            }
            if (selected[7])
            {
                var label = row.Label;
                var want = s[7].Str(r);
                if (!string.Equals(label, want, StringComparison.Ordinal))
                    Fail(where, i, "Label", label?.Length, want.Length);
            }
            i++;
        }
        if (i != e.Rows)
            throw new Finding($"{where}: row reader returned {i} rows, expected {e.Rows}");
        Rows += i;
    }

    static void Fail(string where, long i, string column, object? got, object? want)
        => throw new Finding($"{where}: row {i} {column}: read {got}, expected {want}");

    /// <summary>Generated typed columnar reader (ScaleRow.CreateReader) over the same file.</summary>
    public static void ScaleColumns(IParquetReadSource source, Expected e)
    {
        using var reader = ScaleRow.CreateReader(source);
        long start = 0;
        foreach (var group in reader.RowGroups)
        {
            long i = 0;
            foreach (ColumnBuffer<long> b in group.IdColumn)
                foreach (var v in b.Values)
                {
                    if (v != e.Cols[0].Int64(e.Row(start + i)))
                        throw new Finding($"typed reader rg{group.Index} Id row {start + i}: {v}");
                    i++;
                }
            if (i != (long)group.RowCount)
                throw new Finding($"typed reader rg{group.Index}: {i} Ids for {group.RowCount} rows");
            i = 0;
            foreach (ColumnBuffer<byte> b in group.LabelColumn)
                for (var k = 0; k < b.Count; k++, i++)
                    if (!b.GetValue(k).SequenceEqual(Verify.ExpectedBytes(e.Cols[7], e.Row(start + i))))
                        throw new Finding($"typed reader rg{group.Index} Label row {start + i}");
            start += (long)group.RowCount;
        }
        if (start != e.Rows)
            throw new Finding($"typed reader: {start} rows");
    }
}
