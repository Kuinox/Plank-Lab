using System.Globalization;
using Plank.Reading;
using Plank.RowApi;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>One schema of the evolution family (see fuzz/tools/gen_row_evo.py).</summary>
abstract class EvoClass
{
    internal abstract string Name { get; }
    internal abstract string[] Props { get; }
    internal abstract string[] ColumnNames { get; }
    internal abstract string[] Clr { get; }
    internal abstract ParquetSchema Schema { get; }
    internal abstract object?[] Generate(ref PlankRowApiFuzzTarget.Cursor c, int seq);
    internal abstract byte[] Write(object?[][] rows, ParquetWriterOptions options);
    internal abstract EvoReader Open(byte[] bytes, int mask, ParquetSchemaEvolutionOptions? evolution, RowReaderOptions options);
    internal abstract int[] ReadColumnar(byte[] bytes, bool strict);

    internal static bool IsOptional(string clr) => clr.EndsWith('?');

    internal static string Physical(string clr) => clr.TrimEnd('?') switch
    {
        "int" => "Int32", "long" => "Int64", "double" => "Double", "float" => "Float", "string" => "ByteArray",
        _ => throw new InvalidOperationException(clr)
    };
}

abstract class EvoReader : IDisposable
{
    internal abstract bool MoveNext();
    internal abstract void Reset(byte[] bytes, int mask, ParquetSchemaEvolutionOptions? evolution);
    internal abstract string[] Current(int mask);
    public abstract void Dispose();
}

/// <summary>Canonical text for a cell so values of different CLR widths compare exactly (floats by bit pattern).</summary>
static class EvoCanon
{
    internal static string Of(object? value) => value switch
    {
        null => "null",
        double d => "d" + BitConverter.DoubleToInt64Bits(d).ToString("x", CultureInfo.InvariantCulture),
        float f => "f" + BitConverter.SingleToInt32Bits(f).ToString("x", CultureInfo.InvariantCulture),
        string s => "s:" + s,
        _ => Convert.ToString(value, CultureInfo.InvariantCulture)!
    };

    // What a projected column that the file lacks must read as: the CLR default of the property type.
    internal static string DefaultOf(string clr) => clr switch
    {
        "int" or "long" => "0",
        "double" => Of(0.0),
        "float" => Of(0f),
        "string" => "null",
        _ => "null"
    };
}

public static partial class PlankRowApiFuzzTarget
{
    static ReadOnlySpan<byte> EvolutionMagic => "RSE1"u8;

    enum Fate { Ok, Missing, Throw }

    // The documented policy of the generated row reader (RowReaderCore.ResolveColumnOrdinal): columns are matched
    // by name, only projected columns are checked, a file column of a different physical type is always rejected,
    // required→optional needs Repetition >= AllowRequiredToOptional, optional→required is always rejected, and a
    // missing column is a default value only with MissingColumns = MaterializeDefault.
    static Fate Judge(EvoClass reader, int column, EvoClass writer, ParquetSchemaEvolutionOptions? evolution, out int writerColumn)
    {
        writerColumn = Array.IndexOf(writer.ColumnNames, reader.ColumnNames[column]);
        if (writerColumn < 0)
            return Fate.Missing;
        if (EvoClass.Physical(reader.Clr[column]) != EvoClass.Physical(writer.Clr[writerColumn]))
            return Fate.Throw;
        var readerOptional = EvoClass.IsOptional(reader.Clr[column]);
        var writerOptional = EvoClass.IsOptional(writer.Clr[writerColumn]);
        if (readerOptional == writerOptional)
            return Fate.Ok;
        if (!writerOptional)
            return evolution?.Repetition >= RepetitionEvolutionBehavior.AllowRequiredToOptional ? Fate.Ok : Fate.Throw;
        return Fate.Throw;
    }

    static void RunEvolution(ref Cursor c)
    {
        var classes = EvoClasses.All;
        var reader = classes[c.NextInt(0, classes.Length)];
        var fileCount = c.NextInt(1, 4);
        var evolution = ParquetSchemaEvolutionOptions.Default;

        EvoReader? open = null;
        try
        {
            for (var f = 0; f < fileCount; f++)
            {
                var writer = classes[c.NextInt(0, classes.Length)];
                var rows = new object?[c.NextInt(1, 21)][];
                for (var r = 0; r < rows.Length; r++)
                    rows[r] = writer.Generate(ref c, r);
                var writerOptions = new ParquetWriterOptions
                {
                    RowApiInitialRowCapacity = c.NextInt(1, 9),
                    TargetRowGroupSizeBytes = (ulong)c.NextInt(1, 200),
                    RowApiMaxParallelism = 1
                };
                var bytes = writer.Write(rows, writerOptions);
                var drawn = DrawEvolution(ref c);
                // A null policy on Reset keeps the previous one; the first open with null means strict.
                evolution = drawn ?? (f == 0 ? null : evolution);
                var mask = c.NextInt32() & ((1 << reader.Props.Length) - 1);
                var readerOptions = new RowReaderOptions
                {
                    MaxReadAheadRowGroups = c.NextInt(0, 2),
                    Execution = new ParquetExecutionOptions { WorkerCount = c.NextInt(1, 4) }
                };
                var describe = $"reader {reader.Name} <- writer {writer.Name} mask {mask:x} evo " +
                    (evolution is null ? "strict" : $"miss={evolution.MissingColumns} rep={evolution.Repetition}") + $" file {f}";

                // Expectation from the documented policy.
                var throws = false;
                var expected = new string[rows.Length][];
                for (var r = 0; r < rows.Length; r++)
                    expected[r] = [];
                var cells = new List<string>[rows.Length];
                for (var r = 0; r < rows.Length; r++)
                    cells[r] = [];
                for (var col = 0; col < reader.Props.Length; col++)
                {
                    if ((mask & (1 << col)) == 0)
                        continue;
                    var fate = Judge(reader, col, writer, evolution, out var wc);
                    if (fate == Fate.Throw || (fate == Fate.Missing && evolution?.MissingColumns != MissingColumnEvolutionBehavior.MaterializeDefault))
                        throws = true;
                    for (var r = 0; r < rows.Length; r++)
                        cells[r].Add(fate == Fate.Ok ? EvoCanon.Of(rows[r][wc]) : EvoCanon.DefaultOf(reader.Clr[col]));
                }

                var threw = false;
                try
                {
                    if (open is null)
                        open = reader.Open(bytes, mask, evolution, readerOptions);
                    else
                        open.Reset(bytes, mask, drawn);
                    var index = 0;
                    while (open.MoveNext())
                    {
                        if (index >= rows.Length)
                            throw new RowApiRoundTripException($"Evolution {describe} returned an extra row.");
                        var got = open.Current(mask);
                        if (!got.AsSpan().SequenceEqual(cells[index].ToArray()))
                            throw new RowApiRoundTripException(
                                $"Evolution {describe} row {index}: got [{string.Join(", ", got)}] expected [{string.Join(", ", cells[index])}].");
                        index++;
                    }
                    if (index != rows.Length)
                        throw new RowApiRoundTripException($"Evolution {describe} returned {index} of {rows.Length} rows.");
                }
                catch (InvalidOperationException) when (throws)
                {
                    threw = true;
                }
                if (Environment.GetEnvironmentVariable("PLANK_FUZZ_TRACE") == "2")
                    Console.Error.WriteLine($"EVO {describe} rows={rows.Length} expectThrow={throws} threw={threw}");
                if (throws && !threw)
                    throw new RowApiRoundTripException($"Evolution {describe} accepted an incompatible file.");

                RunColumnarEvolution(reader, writer, bytes, rows.Length, describe, ref c);
                if (threw)
                    return; // the reader's state after a rejected file is not specified
            }
        }
        finally
        {
            open?.Dispose();
        }
    }

    static ParquetSchemaEvolutionOptions? DrawEvolution(ref Cursor c)
    {
        if (c.NextInt(0, 5) == 0)
            return null;
        return new ParquetSchemaEvolutionOptions
        {
            MissingColumns = (MissingColumnEvolutionBehavior)c.NextInt(0, 2),
            Repetition = (RepetitionEvolutionBehavior)c.NextInt(0, 3),
            PhysicalTypes = (SchemaTypeEvolutionBehavior)c.NextInt(0, 2),
            LogicalTypes = (SchemaTypeEvolutionBehavior)c.NextInt(0, 2),
            MaterializedTypes = (SchemaTypeEvolutionBehavior)c.NextInt(0, 2)
        };
    }

    // The columnar reader validates the whole requested schema (not a projection) in Strict mode: every column
    // must exist with the same physical type, and an optional file column cannot satisfy a required one.
    static void RunColumnarEvolution(EvoClass reader, EvoClass writer, byte[] bytes, int rowCount, string describe, ref Cursor c)
    {
        var strict = c.NextBool();
        var accepts = true;
        for (var col = 0; col < reader.Props.Length && accepts; col++)
        {
            var wc = Array.IndexOf(writer.ColumnNames, reader.ColumnNames[col]);
            accepts = wc >= 0
                && EvoClass.Physical(reader.Clr[col]) == EvoClass.Physical(writer.Clr[wc])
                && !(EvoClass.IsOptional(writer.Clr[wc]) && !EvoClass.IsOptional(reader.Clr[col]));
        }

        try
        {
            var seqs = reader.ReadColumnar(bytes, strict);
            if (strict && !accepts)
                throw new RowApiRoundTripException($"Columnar strict reader accepted an incompatible file: {describe}.");
            if (accepts)
            {
                if (seqs.Length != rowCount || seqs.Where(static (s, i) => s != i).Any())
                    throw new RowApiRoundTripException($"Columnar reader changed the Seq column: {describe}.");
            }
        }
        catch (InvalidOperationException) when (!accepts)
        {
            // Rejected as the schema says it must be (or, non-strict, tolerated differently).
        }
        catch (CorruptParquetException) when (!accepts && !strict)
        {
        }
    }
}
