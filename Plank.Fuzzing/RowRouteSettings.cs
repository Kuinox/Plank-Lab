using Plank.RowApi;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>Which generated writer entry point a wide route drives.</summary>
internal enum RowWriteRoute
{
    PipelineStream,
    PipelineCursor,
    Rolling,
    DirectGroups,
    PipelineReset,
}

/// <summary>
/// Every knob the generated row writer and reader expose, each drawn independently
/// from the fuzz input. Nothing here is derived from another value, so capacity,
/// row-group size, file size, page size and row count meet at their extremes
/// (1, exact, exact±1, huge) rather than only at the combinations a fixed table
/// would offer.
/// </summary>
internal sealed class RowRouteSettings
{
    internal RowWriteRoute Route;
    internal int Count;
    internal int InitialCapacity;
    internal uint MaxParallelism;
    internal uint ExplicitParallelism;
    internal int WriterVariant;
    internal ulong TargetRowGroupSizeBytes;
    internal ulong TargetFileSizeBytes;
    internal uint DataPageSizeBytes;
    internal CompressionKind Compression;
    internal ParquetFileVersion FileVersion;
    internal ParquetDataPageVersion DataPageVersion;
    internal bool WritePageIndexes;
    internal bool WritePageCrc;
    internal int ReaderWorkers;
    internal int ReadAhead;
    internal bool VerifyPageCrc;
    internal bool ReadViaSource;
    internal bool ReuseReader;
    internal int ProjectionMode;
    internal int ProjectionSeed;
    internal int Groups;

    internal static RowRouteSettings Draw(ref PlankRowApiFuzzTarget.Cursor c)
    {
        var s = new RowRouteSettings();
        s.Route = (RowWriteRoute)c.NextInt(0, 5);
        // Mostly small, occasionally hundreds: growth from capacity 1 has to repeat many times.
        s.Count = c.NextInt(0, 8) == 0 ? c.NextInt(49, 400) : c.NextInt(0, 49);
        var capacityPick = c.NextInt(0, 9);
        s.InitialCapacity = capacityPick switch
        {
            0 => 1,
            1 => 2,
            2 => Math.Max(1, s.Count - 1),
            3 => Math.Max(1, s.Count),
            4 => s.Count + 1,
            5 => 1024,
            _ => c.NextInt(1, 17)
        };
        s.MaxParallelism = (uint)c.NextInt(0, 5);
        s.ExplicitParallelism = (uint)c.NextInt(1, 5);
        s.WriterVariant = c.NextInt(0, 4);
        s.TargetRowGroupSizeBytes = c.NextInt(0, 10) switch
        {
            0 => 1,
            1 => 8,
            2 => 64,
            3 => 200,
            4 => 1000,
            5 => 4096,
            6 => 65536,
            7 => 1UL << 20,
            8 => ulong.MaxValue,
            _ => 128UL * 1024 * 1024
        };
        s.TargetFileSizeBytes = c.NextInt(0, 6) switch
        {
            0 => 1,
            1 => 512,
            2 => 8192,
            3 => 1UL << 20,
            4 => ulong.MaxValue,
            _ => 512UL * 1024 * 1024
        };
        s.DataPageSizeBytes = c.NextInt(0, 6) switch
        {
            0 => 1,
            1 => 64,
            2 => 1000,
            3 => 4096,
            4 => 1024 * 1024,
            // int.MaxValue itself is accepted by validation but makes the buffer pool overflow:
            // fuzz/repros/rowapi-page-size-int-max. Kept out of the draw so it cannot mask other faults.
            _ => 1 << 29
        };
        // Lz4Legacy (6) is read-only by design: asking the writer for it is rejected input, not a bug.
        s.Compression = (CompressionKind)c.NextInt(0, 6);
        s.FileVersion = c.NextBool() ? ParquetFileVersion.V1 : ParquetFileVersion.V2;
        s.DataPageVersion = c.NextBool() ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2;
        s.WritePageIndexes = c.NextBool();
        s.WritePageCrc = c.NextBool();
        s.ReaderWorkers = c.NextInt(1, 5);
        s.ReadAhead = c.NextInt(0, 2);
        s.VerifyPageCrc = c.NextBool();
        s.ReadViaSource = c.NextBool();
        s.ReuseReader = c.NextBool();
        s.ProjectionMode = c.NextInt(0, 4);
        s.ProjectionSeed = c.NextInt32();
        s.Groups = c.NextInt(1, 4);
        return s;
    }

    public override string ToString()
        => $"route={Route} count={Count} cap={InitialCapacity} par={MaxParallelism}/{ExplicitParallelism} variant={WriterVariant} "
            + $"rg={TargetRowGroupSizeBytes} file={TargetFileSizeBytes} page={DataPageSizeBytes} comp={Compression} "
            + $"fv={FileVersion} pv={DataPageVersion} idx={WritePageIndexes} crc={WritePageCrc} workers={ReaderWorkers} "
            + $"ahead={ReadAhead} verify={VerifyPageCrc} source={ReadViaSource} reuse={ReuseReader} "
            + $"proj={ProjectionMode}/{ProjectionSeed:x} groups={Groups}";

    // PLANK_FUZZ_TRACE=2 prints the settings before the run, which is the only trace of a native crash.
    internal static void Announce(RowRouteSettings s)
    {
        if (Environment.GetEnvironmentVariable("PLANK_FUZZ_TRACE") == "2")
            Console.Error.WriteLine($"RUN {s}");
    }

    // Prints the full exception and the drawn settings when PLANK_FUZZ_TRACE=1, then lets it propagate.
    internal static bool Trace(Exception ex, RowRouteSettings s)
    {
        if (Environment.GetEnvironmentVariable("PLANK_FUZZ_TRACE") == "1")
            Console.Error.WriteLine($"TRACE {s}\n{ex}");
        return false;
    }

    internal ParquetWriterOptions WriterOptions()
        => new()
        {
            RowApiInitialRowCapacity = InitialCapacity,
            RowApiMaxParallelism = MaxParallelism,
            TargetRowGroupSizeBytes = TargetRowGroupSizeBytes,
            TargetFileSizeBytes = TargetFileSizeBytes,
            TargetDataPageSizeBytes = DataPageSizeBytes,
            Compression = Compression,
            FileVersion = FileVersion,
            DataPageVersion = DataPageVersion,
            WritePageIndexes = WritePageIndexes,
            WritePageCrc = WritePageCrc,
            Execution = new ParquetExecutionOptions { WorkerCount = Math.Max(1, (int)MaxParallelism) }
        };

    internal RowReaderOptions ReaderOptions()
        => new()
        {
            MaxReadAheadRowGroups = ReadAhead,
            VerifyPageCrc = VerifyPageCrc && WritePageCrc,
            Execution = new ParquetExecutionOptions { WorkerCount = ReaderWorkers }
        };

    /// <summary>Column mask for the read side: all columns, one, a random subset, or none beyond the row count.</summary>
    internal int ProjectionMask(int columnCount)
    {
        var all = (int)((1L << columnCount) - 1);
        return ProjectionMode switch
        {
            0 => all,
            1 => 1 << ((ProjectionSeed & int.MaxValue) % columnCount),
            2 => (ProjectionSeed & all) == 0 ? 1 : ProjectionSeed & all,
            _ => ProjectionSeed & all // may be empty: Projection.None must still yield every row
        };
    }
}
