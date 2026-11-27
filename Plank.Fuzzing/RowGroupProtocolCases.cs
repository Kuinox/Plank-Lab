using System.Collections.Immutable;
using Plank.Reading.Logical;
using Plank.Schema;
using Plank.Writing;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Route 0xC3 "WRG1": the RowGroupWriter / ParquetWriter call protocol with fuzzer-chosen misuse interleaved between valid
/// calls. Every misuse has a documented refusal (InvalidOperationException) and the harness requires:
///   1. the refusal happens (an accepted misuse is a finding),
///   2. refusing is atomic: the correct call that follows still succeeds and the finished file holds exactly the rows
///      that were written correctly (a refusal that leaves half-written state shows up as a corrupt/wrong file),
///   3. the writer survives Reset to a fresh stream after misuse and writes a correct second file.
/// Misuse covered: columns written out of schema order, a column written twice, an unserialized column, a row count that
/// differs from the first column (n+1, n-1, 0), a column of another writer, StartRowGroup / CloseFile while a row group is
/// open, Write after the row group is complete, and writes after CloseFile.
/// </summary>
internal static class RowGroupProtocolCases
{
    internal const byte Marker = 0xC3;
    internal static ReadOnlySpan<byte> Magic => "WRG1"u8;

    static long _runs, _misuses, _groups;

    static RowGroupProtocolCases()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"WRG1 runs={_runs} misuses={_misuses} groups={_groups}");
    }

    sealed class Cur(ReadOnlySpan<byte> data)
    {
        readonly byte[] _d = data.ToArray();
        int _i;
        public byte Byte() => _d.Length == 0 ? (byte)0 : _d[_i++ % _d.Length];
        public int Int(int min, int maxExclusive)
        {
            uint v = Byte();
            v |= (uint)Byte() << 8;
            v |= (uint)Byte() << 16;
            v |= (uint)Byte() << 24;
            return min + (int)(v % (uint)(maxExclusive - min));
        }
        public T Pick<T>(params T[] choices) => choices[Int(0, choices.Length)];
    }

    static void Fail(string message) => throw new InvalidOperationException("WRG1: " + message);

    static PlankSchema MakeSchema(bool bloom, bool dictionary)
        => new([
            ColumnDefinition.RequiredLeaf("a", ParquetPhysicalType.Int32,
                new ColumnOptions(ParquetRepetition.Required, ImmutableArray.Create(dictionary ? EncodingKind.RleDictionary : EncodingKind.Plain))),
            ColumnDefinition.OptionalLeaf("b", ParquetPhysicalType.Int64,
                new ColumnOptions(ParquetRepetition.Optional, ImmutableArray.Create(EncodingKind.Plain),
                    bloomFilter: bloom ? ParquetBloomFilterOptions.Default : null)),
            ColumnDefinition.OptionalLeaf("c", ParquetPhysicalType.ByteArray,
                new ColumnOptions(ParquetRepetition.Optional, ImmutableArray.Create(EncodingKind.Plain)))
        ]);

    sealed record Rows(int[] A, long?[] B, byte[]?[] C);

    static Rows MakeRows(Cur c, int count, int salt)
    {
        var a = new int[count];
        var b = new long?[count];
        var cc = new byte[]?[count];
        for (var i = 0; i < count; i++)
        {
            a[i] = salt * 100000 + i % (c.Int(0, 3) == 0 ? 7 : 1000);
            b[i] = i % 4 == 3 ? null : (long)salt * 1000 + i;
            cc[i] = i % 5 == 4 ? null : System.Text.Encoding.ASCII.GetBytes($"s{salt}-{i % 13}");
        }

        return new Rows(a, b, cc);
    }

    static SerializedColumn<int> SerA(RowGroupWriter g, PlankSchema schema, int[] values)
    {
        var column = g.CreateSerializedColumn<int>(schema.LeafColumns[0]);
        column.Serialize(values);
        return column;
    }

    static SerializedColumn<long?> SerB(RowGroupWriter g, PlankSchema schema, long?[] values)
    {
        var column = g.CreateSerializedColumn<long?>(schema.LeafColumns[1]);
        column.Serialize(values);
        return column;
    }

    static SerializedColumn<ReadOnlyMemory<byte>?> SerC(RowGroupWriter g, PlankSchema schema, byte[]?[] values)
    {
        var column = g.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[2]);
        column.Serialize(values.Select(static v => v is null ? (ReadOnlyMemory<byte>?)null : v).ToArray());
        return column;
    }

    static void Expect<TException>(string what, Action action) where TException : Exception
    {
        _misuses++;
        Exception? error = null;
        try { action(); }
        catch (Exception e) { error = e; }
        if (error is not TException)
            Fail($"{what}: expected {typeof(TException).Name}, got {(error is null ? "success" : error.GetType().Name + ": " + error.Message)}.");
    }

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        _runs++;
        var c = new Cur(data);
        var schema = MakeSchema(c.Int(0, 3) == 0, c.Int(0, 3) == 0);
        var options = new ParquetWriterOptions
        {
            TargetDataPageSizeBytes = c.Pick(64u, 1000u, 1024u * 1024),
            WritePageIndexes = c.Int(0, 2) == 0,
            Compression = c.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Zstd),
            DataPageVersion = c.Int(0, 2) == 0 ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2
        };
        var expected = new List<Rows>();
        var groupTotal = c.Int(1, 4);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, options);
        var foreignSchema = MakeSchema(false, false);
        using var foreignStream = new MemoryStream();
        using var foreign = foreignSchema.CreateWriter(foreignStream);
        var foreignGroup = foreign.StartRowGroup();

        for (var g = 0; g < groupTotal; g++)
        {
            var n = c.Pick(1, 2, 7, 100, 1500);
            var rows = MakeRows(c, n, g + 1);
            var group = writer.StartRowGroup();
            if (c.Int(0, 2) == 0)
            {
                Expect<InvalidOperationException>("StartRowGroup while open", () => writer.StartRowGroup());
                Expect<InvalidOperationException>("CloseFile while a row group is open", () => writer.CloseFile());
            }

            for (var next = 0; next < 3; next++)
            {
                // Misuse before the correct write of column `next`.
                var misuses = c.Int(0, 3);
                for (var m = 0; m < misuses; m++)
                    switch (c.Int(0, 6))
                    {
                        case 0 when next < 2: // a later column first
                        {
                            var wrongOrdinal = c.Int(next + 1, 3);
                            Expect<InvalidOperationException>($"column {wrongOrdinal} written while {next} is next", () =>
                            {
                                if (wrongOrdinal == 1) group.Write(SerB(group, schema, rows.B));
                                else group.Write(SerC(group, schema, rows.C));
                            });
                            break;
                        }
                        case 1: // never serialized
                            Expect<InvalidOperationException>("Write of an unserialized column", () =>
                                group.Write(next switch
                                {
                                    0 => group.CreateSerializedColumn<int>(schema.LeafColumns[0]),
                                    _ => group.CreateSerializedColumn<int>(schema.LeafColumns[0])
                                }));
                            break;
                        case 2 when next > 0: // row count differs from the first column
                        {
                            var other = c.Pick(n + 1, Math.Max(0, n - 1), 0);
                            if (other == n)
                                other = n + 3;
                            var mismatched = MakeRows(c, other, 99);
                            Expect<InvalidOperationException>($"column {next} with {other} rows after {n}", () =>
                            {
                                if (next == 1) group.Write(SerB(group, schema, mismatched.B));
                                else group.Write(SerC(group, schema, mismatched.C));
                            });
                            break;
                        }
                        case 3: // a column from another writer
                            Expect<InvalidOperationException>("column of another writer", () =>
                            {
                                var column = foreignGroup.CreateSerializedColumn<int>(foreignSchema.LeafColumns[0]);
                                column.Serialize(rows.A);
                                group.Write(column);
                            });
                            break;
                        case 4 when next > 0: // the column before was already written
                            Expect<InvalidOperationException>("a column written twice", () =>
                            {
                                if (next == 1) group.Write(SerA(group, schema, rows.A));
                                else group.Write(SerB(group, schema, rows.B));
                            });
                            break;
                    }

                // The correct write must still succeed after every refusal above.
                switch (next)
                {
                    case 0: group.Write(SerA(group, schema, rows.A)); break;
                    case 1: group.Write(SerB(group, schema, rows.B)); break;
                    default: group.Write(SerC(group, schema, rows.C)); break;
                }
            }

            _groups++;
            expected.Add(rows);
            if (c.Int(0, 2) == 0)
                Expect<InvalidOperationException>("Write after the row group is complete", () => group.Write(SerA(group, schema, rows.A)));
        }

        writer.CloseFile();
        Expect<InvalidOperationException>("StartRowGroup after CloseFile", () => writer.StartRowGroup());

        Verify(stream.ToArray(), schema, expected, "first file");

        // The same writer instance must write a second, correct file after Reset.
        using var second = new MemoryStream();
        writer.Reset(second);
        var rows2 = MakeRows(c, c.Pick(1, 5, 300), 7);
        var group2 = writer.StartRowGroup();
        group2.Write(SerA(group2, schema, rows2.A));
        group2.Write(SerB(group2, schema, rows2.B));
        group2.Write(SerC(group2, schema, rows2.C));
        writer.CloseFile();
        Verify(second.ToArray(), schema, [rows2], "file after Reset");
        writer.Dispose();
    }

    static void Verify(byte[] file, PlankSchema schema, List<Rows> expected, string what)
    {
        using var reader = schema.CreateReader(new MemoryStream(file, writable: false));
        if (reader.RowGroups.Count != expected.Count)
            Fail($"{what}: {reader.RowGroups.Count} row groups, expected {expected.Count}.");
        for (var g = 0; g < expected.Count; g++)
        {
            var group = reader.RowGroups[g];
            if (group.RowCount != (ulong)expected[g].A.Length)
                Fail($"{what}: group {g} RowCount {group.RowCount} != {expected[g].A.Length}.");
            var a = PlankWriterFuzzTargetRead.All(group.Column<int>(schema.LeafColumns[0]));
            if (!a.SequenceEqual(expected[g].A))
                Fail($"{what}: group {g} column a differs.");
            var b = PlankWriterFuzzTargetRead.All(group.Column<long?>(schema.LeafColumns[1]));
            if (!b.SequenceEqual(expected[g].B))
                Fail($"{what}: group {g} column b differs.");
            var cValues = new List<byte[]?>();
            foreach (var buffer in group.Column<byte>(schema.LeafColumns[2]))
                for (var i = 0; i < buffer.Count; i++)
                    cValues.Add(buffer.IsNull(i) ? null : buffer.GetValue(i).ToArray());
            if (cValues.Count != expected[g].C.Length)
                Fail($"{what}: group {g} column c has {cValues.Count} rows.");
            for (var i = 0; i < cValues.Count; i++)
                if (!(cValues[i] is null && expected[g].C[i] is null)
                    && !(cValues[i] is not null && expected[g].C[i] is not null && cValues[i].AsSpan().SequenceEqual(expected[g].C[i])))
                    Fail($"{what}: group {g} column c row {i} differs.");
        }
    }
}

internal static class PlankWriterFuzzTargetRead
{
    internal static T[] All<T>(RowGroupColumn<T> buffers)
    {
        var values = new List<T>();
        foreach (var buffer in buffers)
            foreach (var value in buffer.Values)
                values.Add(value);
        return values.ToArray();
    }
}
