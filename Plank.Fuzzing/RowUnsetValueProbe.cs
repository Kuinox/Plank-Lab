namespace Plank.Fuzzing;

public static partial class PlankRowApiFuzzTarget
{
    static ReadOnlySpan<byte> UnsetValueProbeMagic => "RUS1"u8;

    /// <summary>
    /// Repro for the reuse contract gap: a value-type column that a later row never assigns reads back the value
    /// an earlier row group left in the reused slot, instead of the CLR default. Reference-typed columns and nested
    /// collections are cleared on reuse; scalar buffers are not. Not listed in the dictionary: it fails by design
    /// until the library either clears or documents that behaviour (fuzz/FINDINGS.md).
    /// </summary>
    static void RunUnsetValueProbe(ref Cursor c)
    {
        var stale = c.NextInt32() | 1;
        using var stream = new MemoryStream();
        var options = new Plank.Writing.ParquetWriterOptions
        {
            TargetRowGroupSizeBytes = 1,
            RowApiInitialRowCapacity = c.NextInt(1, 4),
            RowApiMaxParallelism = 1
        };
        using (var writer = RowFuzzFixed.CreateRowWriter(stream, options))
        {
            for (var i = 0; i < 30; i++)
            {
                var row = writer.GetRow();
                row.Flag = true;
                row.Sequence = i;
                row.Measure = 1.5;
                if (i % 3 != 2)
                    row.Id = stale + i; // every third row never assigns Id
            }
            writer.Complete();
        }

        using var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(FullValueOracle.Checked(stream.ToArray()), writable: false));
        var index = 0;
        while (reader.MoveNext())
        {
            var want = index % 3 != 2 ? stale + index : 0;
            Check(reader.Current.Id == want, $"unset Id read {reader.Current.Id}, expected {want}; Id", index);
            index++;
        }
        Check(index == 30, "unset probe row count", index);
    }
}
