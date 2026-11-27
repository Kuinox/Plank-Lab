using Plank.Reading;
using Plank.Writing;

namespace Plank.Fuzzing;

public static partial class PlankRowApiFuzzTarget
{
    static ReadOnlySpan<byte> MergeSchemaMagic => "RMS1"u8;

    /// <summary>
    /// Merges files written by the evolution-family schemas into a merger bound to another one of them. A merge only
    /// accepts files whose complete physical schema equals the merger's, so a different class must be refused and
    /// leave the merger exactly as it was: counters unchanged and the next compatible file still importable.
    /// </summary>
    static void RunMergeSchemas(ref Cursor c)
    {
        var classes = EvoClasses.All;
        var target = classes[c.NextInt(0, classes.Length)];
        var fileCount = c.NextInt(2, 6);
        var seq = 0;
        var expectedSeqs = new List<int>();
        var accepted = 1;

        var firstCount = c.NextInt(1, 12);
        var first = MakeMergeFile(target, ref c, firstCount, seq);
        expectedSeqs.AddRange(Enumerable.Range(seq, firstCount));
        seq += firstCount;
        var acceptedRows = firstCount;

        using var destination = new PlankMergerFuzzTarget.MemoryReadWriteSource();
        var merger = target.Schema.CreateMerger(new MemoryReadSource(first), destination, new ParquetMergeOptions());
        for (var f = 1; f < fileCount; f++)
        {
            var writer = c.NextBool() ? target : classes[c.NextInt(0, classes.Length)];
            var count = c.NextInt(1, 12);
            var bytes = MakeMergeFile(writer, ref c, count, seq);
            var compatible = ReferenceEquals(writer, target);
            try
            {
                merger.AppendFile(new MemoryReadSource(bytes));
                if (!compatible)
                    throw new RowApiRoundTripException($"Merger for {target.Name} accepted a file written by {writer.Name}.");
                expectedSeqs.AddRange(Enumerable.Range(seq, count));
                seq += count;
                accepted++;
                acceptedRows += count;
            }
            catch (Exception ex) when (!compatible && ex is ArgumentException or InvalidOperationException or NotSupportedException)
            {
            }

            if (merger.SourceFileCount != accepted || merger.RowCount != acceptedRows)
                throw new RowApiRoundTripException(
                    $"Merger counters {merger.SourceFileCount}/{merger.RowCount} after file {f} ({writer.Name} into {target.Name}); expected {accepted}/{acceptedRows}.");
        }

        merger.CloseFile();
        var seqs = target.ReadColumnar(destination.ToArray(), strict: true);
        if (!seqs.AsSpan().SequenceEqual(expectedSeqs.ToArray()))
            throw new RowApiRoundTripException($"Merged {target.Name} file has Seq values that differ from the accepted inputs.");
    }

    static byte[] MakeMergeFile(EvoClass writer, ref Cursor cursor, int count, int firstSeq)
    {
        var rows = new object?[count][];
        for (var i = 0; i < count; i++)
            rows[i] = writer.Generate(ref cursor, firstSeq + i);
        return writer.Write(rows, new Plank.Writing.ParquetWriterOptions
        {
            RowApiInitialRowCapacity = cursor.NextInt(1, 9),
            TargetRowGroupSizeBytes = (ulong)cursor.NextInt(1, 300),
            RowApiMaxParallelism = 1
        });
    }
}
