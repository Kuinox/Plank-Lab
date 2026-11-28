using Plank.Dataset;
using Plank.Fuzzing.RandomSchemas;
using Plank.Reading;
using Plank.Writing;

namespace Plank.Fuzzing;

public static partial class PlankRowApiFuzzTarget
{
    static ReadOnlySpan<byte> RandomDatasetMagic => "RRD1"u8;
    static ReadOnlySpan<byte> RandomEvolutionMagic => "RRE1"u8;

    static (RandomSchemaCase Case, ValueSource Source) PickRandomSchema(ref Cursor c)
    {
        var cases = RandomSchemaRegistry.All;
        var kase = cases[((c.NextByte() << 8) | c.NextByte()) % cases.Length];
        return (kase, null!);
    }

    static object[] DrawRows(RandomSchemaCase kase, ValueSource source, int count)
    {
        var rows = new object[count];
        for (var i = 0; i < rows.Length; i++)
        {
            rows[i] = Activator.CreateInstance(kase.RowType)!;
            source.Fill(rows[i]);
            kase.SetSeq(rows[i], i);
        }
        return rows;
    }

    /// <summary>
    /// The random schemas through the generated dataset writer: partitions, file pool, pending capacity, append options,
    /// file parts and an injected I/O fault (see the wide dataset route for the contract being checked).
    /// </summary>
    static void RunRandomDataset(ref Cursor c)
    {
        if (RandomSchemaRegistry.All.Length == 0)
            return;
        var (kase, _) = PickRandomSchema(ref c);
        var s = RowRouteSettings.Draw(ref c);
        var partitions = c.NextInt(1, 7);
        var createParts = c.NextBool();
        var ownedPath = c.NextBool();
        var poolSize = c.NextInt(1, 5);
        var pending = (uint)(c.NextInt(0, 4) == 0 ? 0 : c.NextInt(1, 12));
        var append = new ParquetAppendOptions
        {
            PreserveExistingMetadata = c.NextBool(),
            // Appending to the latest row group is unsupported for repeated columns and fails for converter columns
            // (fuzz/repros/dataset-append-latest-converter); only flat converter-free schemas draw it.
            AppendToLatestRowGroup = c.NextBool() && kase.AppendLatestSafe,
            WriterOptions = s.WriterOptions()
        };
        var failAt = c.NextInt(0, 3) == 0 ? c.NextInt(1, 40) : 0;
        var plan = new DatasetFaultPlan(failAt, c.NextInt(1, 64), c.NextBool());
        var source = new ValueSource(c.Rest.ToArray(), 0);
        var rows = DrawRows(kase, source, Math.Min(s.Count, 40));

        int PartitionOf(object row) => (int)((((uint)Seq(row) * 2654435761u) >> 8) % (uint)partitions);
        int Seq(object row) => (int)kase.Get(row, 0)!;

        var store = new InMemoryFileStore();
        var files = new FaultingDatasetFile[poolSize];
        for (var i = 0; i < files.Length; i++)
            files[i] = new FaultingDatasetFile(new InMemoryDatasetFile(store), plan);
        var options = new DatasetWriterOptions { AppendOptions = append, WriterOptions = append.WriterOptions, PendingRowCapacity = createParts ? 0 : pending };
        var describe = $"{kase.Name} parts={partitions} pool={poolSize} pending={pending} createParts={createParts} failAt={failAt} | {s}";
        try
        {
            RandomDatasetCore(kase, rows, options, files, store, plan, PartitionOf, partitions, createParts, ownedPath, s);
        }
        catch (RowApiRoundTripException ex)
        {
            throw new RowApiRoundTripException($"{ex.Message} | {describe}");
        }
        catch (Exception ex) when (RowRouteSettings.Trace(ex, s))
        {
            throw;
        }
    }

    static void RandomDatasetCore(RandomSchemaCase kase, object[] rows, DatasetWriterOptions options, FaultingDatasetFile[] files,
        InMemoryFileStore store, DatasetFaultPlan plan, Func<object, int> partitionOf, int partitions, bool createParts, bool ownedPath,
        RowRouteSettings s)
    {
        var writer = kase.CreateDataset(partitionOf, ownedPath, createParts, files, options);
        Exception? injected = null;
        try
        {
            foreach (var row in rows)
                writer.Queue(row);
        }
        catch (Exception ex) when (DatasetFaultPlan.IsInjected(ex))
        {
            injected = ex;
        }

        if (injected is not null)
        {
            // A failed dataset writer is permanently faulted: later calls rethrow the original failure,
            // and cleanup must not throw it again.
            try
            {
                writer.Queue(rows.Length > 0 ? rows[0] : Activator.CreateInstance(kase.RowType)!);
                throw new RowApiRoundTripException($"{kase.Name} dataset writer accepted a row after a failure.");
            }
            catch (IOException again) when (again.Message == injected.Message)
            {
            }
            writer.Dispose();
        }
        else
        {
            try
            {
                writer.Dispose();
            }
            catch (Exception ex) when (DatasetFaultPlan.IsInjected(ex))
            {
                injected = ex;
            }
        }

        try
        {
            writer.Dispose();
            throw new RowApiRoundTripException($"{kase.Name} dataset writer accepted a second Dispose.");
        }
        catch (InvalidOperationException)
        {
        }

        if (injected is not null)
        {
            if (!plan.Fired)
                throw new RowApiRoundTripException($"{kase.Name} dataset reported an injected fault that never fired.");
            return;
        }
        if (plan.Fired)
            throw new RowApiRoundTripException($"{kase.Name} dataset swallowed an injected fault.");

        var expected = Enumerable.Range(0, partitions).Select(static _ => new List<int>()).ToArray();
        foreach (var row in rows)
            expected[partitionOf(row)].Add((int)kase.Get(row, 0)!);
        var actual = Enumerable.Range(0, partitions).Select(static _ => new List<(ulong Part, List<int> Seqs)>()).ToArray();
        foreach (var (path, stream) in store.Files)
        {
            if (stream.Length == 0)
                continue;
            var partition = -1;
            for (var i = 0; i < partitions; i++)
                if (path.StartsWith($"part{i}", StringComparison.Ordinal) && (path.Length == 5 || path[5] == '-'))
                    partition = i;
            if (partition < 0)
                throw new RowApiRoundTripException($"{kase.Name} dataset file '{path}' names no partition.");
            var part = createParts && ulong.TryParse(path.AsSpan(path.LastIndexOf('-') + 1), out var index) ? index : 0;
            var seqs = kase.ReadSeqs(stream.ToArray(), rows, s.ReaderOptions());
            foreach (var seq in seqs)
                if (partitionOf(rows[seq]) != partition)
                    throw new RowApiRoundTripException($"{kase.Name} dataset row {seq} was written to '{path}' (partition {partition}).");
            actual[partition].Add((part, seqs));
        }

        for (var p = 0; p < partitions; p++)
        {
            var merged = actual[p].OrderBy(static x => x.Part).SelectMany(static x => x.Seqs).ToList();
            if (!merged.SequenceEqual(expected[p]))
                throw new RowApiRoundTripException(
                    $"{kase.Name} dataset partition {p} holds {merged.Count} rows in a different order or set than the {expected[p].Count} queued.");
        }
    }

    /// <summary>
    /// A random schema's file read through its mutated twin (and the reverse): the expectation is derived from the two
    /// schemas' column names, physical types and repetition with the same documented rules as the evolution family
    /// (RSE1): match by name, physical mismatch always rejected, required to optional only with the option,
    /// optional to required always rejected, missing columns default only with MaterializeDefault.
    /// </summary>
    static void RunRandomEvolution(ref Cursor c)
    {
        if (RandomSchemaRegistry.All.Length == 0)
            return;
        var (baseCase, _) = PickRandomSchema(ref c);
        var twin = baseCase.Twin!;
        var direction = c.NextInt(0, 4);
        var writer = direction is 0 or 1 ? baseCase : twin;
        var reader = direction is 0 or 2 ? baseCase : twin;
        var s = RowRouteSettings.Draw(ref c);
        var evolution = DrawEvolution(ref c);
        var source = new ValueSource(c.Rest.ToArray(), 0);
        var rows = DrawRows(writer, source, Math.Max(1, Math.Min(s.Count, 24)));
        var mask = c.NextInt32() & ((1 << reader.ColumnCount) - 1);
        var describe = $"{writer.Name} -> {reader.Name} ({baseCase.Mutations}) mask {mask:x} evo " +
            (evolution is null ? "strict" : $"miss={evolution.MissingColumns} rep={evolution.Repetition}");

        var throws = false;
        var expected = new object?[rows.Length][];
        for (var r = 0; r < rows.Length; r++)
            expected[r] = new object?[reader.ColumnCount];
        for (var col = 0; col < reader.ColumnCount; col++)
        {
            if ((mask & (1 << col)) == 0)
                continue;
            var wc = Array.IndexOf(writer.ColumnNames, reader.ColumnNames[col]);
            if (wc < 0)
            {
                if (evolution?.MissingColumns != MissingColumnEvolutionBehavior.MaterializeDefault)
                    throws = true;
                for (var r = 0; r < rows.Length; r++)
                    expected[r][col] = reader.DefaultOf(col);
                continue;
            }

            // Only root scalar columns are ever mutated, so any other column has an identical type on both sides;
            // a widened scalar differs in its base CLR type and therefore in its physical type.
            if (reader.Clr[col].TrimEnd('?') != writer.Clr[wc].TrimEnd('?'))
                throws = true;
            else if (reader.Optional[col] != writer.Optional[wc])
            {
                if (writer.Optional[wc] || !(evolution?.Repetition >= RepetitionEvolutionBehavior.AllowRequiredToOptional))
                    throws = true;
            }
            for (var r = 0; r < rows.Length; r++)
                expected[r][col] = writer.Get(rows[r], wc);
        }

        try
        {
            var bytes = FullValueOracle.Checked(writer.Write(rows, s.WriterOptions(), 0, 1));
            var threw = false;
            try
            {
                reader.CheckEvolved(bytes, expected, mask, evolution, s.ReaderOptions());
            }
            catch (InvalidOperationException) when (throws)
            {
                threw = true;
            }
            if (throws && !threw)
                throw new RowApiRoundTripException($"Evolution {describe} accepted an incompatible file.");
        }
        catch (RowApiRoundTripException ex)
        {
            throw new RowApiRoundTripException($"{ex.Message} | {describe} | {s}");
        }
        catch (Exception ex) when (TraceDescribed(ex, s, describe))
        {
            throw;
        }
    }

    static bool TraceDescribed(Exception ex, RowRouteSettings s, string describe)
    {
        if (Environment.GetEnvironmentVariable("PLANK_FUZZ_TRACE") == "1")
            Console.Error.WriteLine($"DESCRIBE {describe}");
        return RowRouteSettings.Trace(ex, s);
    }
}
