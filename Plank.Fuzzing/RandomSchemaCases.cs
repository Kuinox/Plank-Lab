using Plank.Fuzzing.RandomSchemas;

namespace Plank.Fuzzing;

public static partial class PlankRowApiFuzzTarget
{
    static ReadOnlySpan<byte> RandomSchemaMagic => "RRS1"u8;

    /// <summary>
    /// Picks one of the randomly shaped generated schemas by input byte, writes fuzzer-drawn rows through one generated
    /// writer entry point with independently drawn options, runs the file through the full-value oracle (Arrow), and
    /// reads it back through the generated reader (projected, via stream or source, reused) comparing every value exactly.
    /// </summary>
    static void RunRandomSchema(ref Cursor c)
    {
        var cases = RandomSchemaRegistry.All;
        if (cases.Length == 0)
            return;
        var kase = cases[((c.NextByte() << 8) | c.NextByte()) % cases.Length];
        var settings = RowRouteSettings.Draw(ref c);
        var route = c.NextInt(0, 3);
        var groups = c.NextInt(1, 4);
        var mask = settings.ProjectionMask(kase.ColumnCount);
        if (settings.ProjectionMode == 0)
            mask = (1 << kase.ColumnCount) - 1;
        var source = new ValueSource(c.Rest.ToArray(), 0);
        var rows = new object[Math.Min(settings.Count, 24)];
        for (var i = 0; i < rows.Length; i++)
        {
            rows[i] = Activator.CreateInstance(kase.RowType)!;
            source.Fill(rows[i]);
            kase.SetSeq(rows[i], i);
            // Some rows leave columns unassigned: nullable reference columns, collections and maps must read null,
            // and an unassigned scalar has no defined value (it keeps what the reused slot held), so the comparison skips it.
            if (c.NextInt(0, 5) == 0)
                kase.ApplyUnset(rows[i], c.NextInt32());
        }

        try
        {
            var bytes = FullValueOracle.Checked(kase.Write(rows, settings.WriterOptions(), route, groups));
            // Self-test of the comparison: with PLANK_FUZZ_SELFTEST_RRS=1 the expected rows are redrawn after writing,
            // so every case with a projected column must report a mismatch.
            if (Environment.GetEnvironmentVariable("PLANK_FUZZ_SELFTEST_RRS") == "1" && rows.Length > 0)
                source.Fill(rows[0]);
            if (Environment.GetEnvironmentVariable("PLANK_FUZZ_TRACE") == "2")
                Console.Error.WriteLine($"RRS {kase.Name} rows={rows.Length} route={route} mask={mask:x} bytes={bytes.Length}");
            kase.Check(bytes, rows, mask, settings.ReaderOptions(), settings.ReadViaSource, settings.ReuseReader);
        }
        catch (RowApiRoundTripException ex)
        {
            throw new RowApiRoundTripException($"{ex.Message} | route={route} groups={groups} {settings}");
        }
        catch (Exception ex) when (RowRouteSettings.Trace(ex, settings))
        {
            throw;
        }
    }
}
