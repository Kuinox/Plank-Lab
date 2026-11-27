using System.Collections.Immutable;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Reading.Physical;
using Plank.RowApi;
using Plank.Schema;
using Plank.Writing;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Route 0xC1 "NST1":
/// <list type="number">
/// <item><b>geo</b> — <see cref="ParquetGeospatialStatistics"/> / <see cref="ParquetBoundingBox"/>. The writer never produces
///   geospatial statistics (they are only imported), so the harness encodes the Thrift compact struct itself: bounding box with any
///   subset of the 8 doubles (the four X/Y bounds are required), the geospatial-type list, plus unknown fields of every wire type
///   that must be skipped. A valid encoding must decode to exactly the encoded values; wrong wire types, missing required bounds and
///   oversized list counts must be CorruptParquetException; every truncation must be CorruptParquetException or a clean result,
///   nothing else. ParquetFileMetadata.ReadGeospatialStatistics ordinals are probed on a written file.</item>
/// <item><b>slices</b> — SerializedColumn.Serialize over offset/count slices of a nested list column (jagged int?[] rows with null rows,
///   empty rows and null elements): repetition levels, definition levels and values must equal the Dremel encoding of exactly the slice.</item>
/// <item><b>rowopts</b> — RowReaderOptions (read-ahead, workers, null pool, CRC) on the nested generated reader with drawn
///   row-group splits: valid combinations read back every nested value, invalid ones are rejected at creation.</item>
/// </list>
/// </summary>
internal static class NestedSurfaceCases
{
    internal const byte Marker = 0xC1;
    internal static ReadOnlySpan<byte> Magic => "NST1"u8;

    static long _runs, _geoValid, _geoInvalid, _geoTruncations, _slices, _nestedReads;

    static NestedSurfaceCases()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"NST1 runs={_runs} geoValid={_geoValid} geoInvalid={_geoInvalid} geoTruncations={_geoTruncations} sliceChecks={_slices} nestedReads={_nestedReads}");
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
        public bool Bool() => Int(0, 2) == 0;
        public bool OneIn(int n) => Int(0, n) == 0;
    }

    static void Fail(string message) => throw new InvalidOperationException("NST1: " + message);

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        _runs++;
        var c = new Cur(data);
        switch (c.Int(0, 3))
        {
            case 0: Geo(c); break;
            case 1: ListSlices(c); break;
            default: NestedReaderOptions(c); break;
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // geospatial statistics
    // ---------------------------------------------------------------------------------------------------------------

    const int TBoolTrue = 1, TBoolFalse = 2, TByte = 3, TI16 = 4, TI32 = 5, TI64 = 6, TDouble = 7, TBinary = 8, TList = 9, TMap = 11, TStruct = 12;

    static void Varint(List<byte> o, ulong v)
    {
        while (v >= 0x80)
        {
            o.Add((byte)(v | 0x80));
            v >>= 7;
        }

        o.Add((byte)v);
    }

    static void ZigZag32(List<byte> o, int v) => Varint(o, (uint)((v << 1) ^ (v >> 31)));

    static void Field(List<byte> o, ref int last, int id, int type)
    {
        var delta = id - last;
        if (delta is > 0 and <= 15)
            o.Add((byte)(delta << 4 | type));
        else
        {
            o.Add((byte)type);
            ZigZag32(o, id);
        }

        last = id;
    }

    static void Double(List<byte> o, double v) => o.AddRange(BitConverter.GetBytes(v));

    static void ListHeader(List<byte> o, int count, int elementType)
    {
        if (count < 15)
            o.Add((byte)(count << 4 | elementType));
        else
        {
            o.Add((byte)(0xF0 | elementType));
            Varint(o, (ulong)count);
        }
    }

    // One unknown field of a drawn wire type, which the decoder must skip.
    static void Unknown(List<byte> o, ref int last, int id, Cur c)
    {
        switch (c.Int(0, 10))
        {
            case 0: Field(o, ref last, id, TBoolTrue); break;
            case 1: Field(o, ref last, id, TBoolFalse); break;
            case 2: Field(o, ref last, id, TByte); o.Add(c.Byte()); break;
            case 3: Field(o, ref last, id, TI16); ZigZag32(o, c.Int(-300, 300)); break;
            case 4: Field(o, ref last, id, TI32); ZigZag32(o, c.Int(-100000, 100000)); break;
            case 5: Field(o, ref last, id, TI64); Varint(o, (ulong)c.Int(0, int.MaxValue)); break;
            case 6: Field(o, ref last, id, TDouble); Double(o, c.Int(0, 100) / 7.0); break;
            case 7:
            {
                Field(o, ref last, id, TBinary);
                var n = c.Int(0, 40);
                Varint(o, (ulong)n);
                for (var i = 0; i < n; i++) o.Add(c.Byte());
                break;
            }
            case 8:
            {
                Field(o, ref last, id, TList);
                var n = c.Int(0, 20);
                ListHeader(o, n, TI32);
                for (var i = 0; i < n; i++) ZigZag32(o, c.Int(-50, 50));
                break;
            }
            default:
            {
                Field(o, ref last, id, TStruct);
                var inner = 0;
                if (c.Bool()) { Field(o, ref inner, 1, TI32); ZigZag32(o, 5); }
                o.Add(0);
                break;
            }
        }
    }

    static void Geo(Cur c)
    {
        var o = new List<byte>();
        var valid = true;
        var last = 0;
        var wantBox = c.Int(0, 4) != 0;
        var values = new double?[8];
        if (wantBox)
        {
            Field(o, ref last, 1, TStruct);
            var inner = 0;
            for (var id = 1; id <= 8; id++)
            {
                if (c.Int(0, 6) == 0 && id <= 4)
                {
                    valid = false; // a required bound is missing
                    continue;
                }

                if (id > 4 && c.Bool())
                    continue;
                if (c.Int(0, 12) == 0)
                {
                    Field(o, ref inner, id, TI32); // wrong wire type for a double
                    ZigZag32(o, 3);
                    valid = false;
                    continue;
                }

                var v = c.Pick(0d, -0d, 1.5, -180d, 180d, double.NaN, double.PositiveInfinity, double.MaxValue, double.Epsilon);
                values[id - 1] = v;
                Field(o, ref inner, id, TDouble);
                Double(o, v);
                if (c.OneIn(8))
                    Unknown(o, ref inner, id + 10, c);
            }

            if (c.OneIn(4))
                Unknown(o, ref inner, 20, c);
            o.Add(0);
        }

        int[]? types = null;
        if (c.Int(0, 3) != 0)
        {
            var count = c.Pick(0, 1, 2, 14, 15, 16, 40);
            types = Enumerable.Range(0, count).Select(i => c.Pick(1, 2, 3, 1000, 2001, int.MinValue, int.MaxValue, -1)).ToArray();
            Field(o, ref last, 2, TList);
            if (c.OneIn(10))
            {
                ListHeader(o, count, TI64); // wrong element type
                valid = false;
            }
            else
                ListHeader(o, count, TI32);

            foreach (var t in types)
                ZigZag32(o, t);
        }

        if (c.OneIn(3))
            Unknown(o, ref last, 5 + c.Int(0, 3), c);
        o.Add(0);
        var bytes = o.ToArray();

        // The bytes must go through ParquetGeospatialStatistics.Read exactly as encoded.
        Exception? error = null;
        ParquetGeospatialStatistics? result = null;
        try { result = ParquetGeospatialStatistics.Read(bytes); }
        catch (Exception e) { error = e; }
        if (valid)
        {
            _geoValid++;
            if (error is not null)
                Fail($"valid geospatial statistics ({bytes.Length} bytes) rejected: {error.GetType().Name}: {error.Message}");
            if ((result!.BoundingBox is not null) != wantBox)
                Fail("bounding box presence differs.");
            if (wantBox)
            {
                var b = result.BoundingBox!;
                double?[] got = [b.XMin, b.XMax, b.YMin, b.YMax, b.ZMin, b.ZMax, b.MMin, b.MMax];
                for (var i = 0; i < 8; i++)
                    if (!(got[i] is null && values[i] is null) && !(got[i] is { } g && values[i] is { } w && BitConverter.DoubleToInt64Bits(g) == BitConverter.DoubleToInt64Bits(w)))
                        Fail($"bounding box value {i} is {got[i]}, expected {values[i]}.");
            }

            if ((result.GeospatialTypes is not null) != (types is not null) || (types is not null && !result.GeospatialTypes!.SequenceEqual(types)))
                Fail("geospatial type list differs.");
        }
        else
        {
            _geoInvalid++;
            if (error is not CorruptParquetException)
                Fail($"invalid geospatial statistics ({bytes.Length} bytes) gave {error?.GetType().Name ?? "success"} instead of CorruptParquetException: {error?.Message}");
        }

        // Truncations of the (possibly invalid) encoding: a defined rejection or a clean result, never another exception type.
        var step = Math.Max(1, bytes.Length / 24);
        for (var length = 0; length < bytes.Length; length += step)
        {
            _geoTruncations++;
            try { _ = ParquetGeospatialStatistics.Read(bytes.AsSpan(0, length)); }
            catch (CorruptParquetException) { }
            catch (Exception e) { Fail($"geospatial statistics truncated to {length}/{bytes.Length} bytes threw {e.GetType().Name}: {e.Message}"); }
        }

        // Random byte flips never produce a non-Corrupt exception either.
        if (bytes.Length > 0)
        {
            var mutated = (byte[])bytes.Clone();
            mutated[c.Int(0, mutated.Length)] ^= (byte)(1 << c.Int(0, 8));
            try { _ = ParquetGeospatialStatistics.Read(mutated); }
            catch (CorruptParquetException) { }
            catch (Exception e) { Fail($"mutated geospatial statistics threw {e.GetType().Name}: {e.Message}"); }
        }

        // The public accessor on a real file: absent statistics are null, ordinals are validated.
        var schema = new PlankSchema([ColumnDefinition.RequiredLeaf("a", ParquetPhysicalType.Int32), ColumnDefinition.RequiredLeaf("b", ParquetPhysicalType.Int32)]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream);
        var group = writer.StartRowGroup();
        for (var col = 0; col < 2; col++)
        {
            var sc = group.CreateSerializedColumn<int>(schema.LeafColumns[col]);
            sc.Serialize([1, 2, 3]);
            group.Write(sc);
        }

        writer.CloseFile();
        using var reader = new ParquetFileReader();
        reader.Reset(new MemoryStream(stream.ToArray(), writable: false));
        foreach (var rg in new[] { -1, 0, 1, int.MaxValue })
            foreach (var col in new[] { -1, 0, 1, 2, int.MaxValue })
            {
                var ok = rg == 0 && col is 0 or 1;
                Exception? e = null;
                ParquetGeospatialStatistics? stats = null;
                try { stats = reader.Metadata.ReadGeospatialStatistics(rg, col); }
                catch (Exception x) { e = x; }
                if (ok && (e is not null || stats is not null))
                    Fail($"ReadGeospatialStatistics({rg},{col}) on a column without them gave {(e is null ? "a value" : e.GetType().Name)}.");
                if (!ok && e is not ArgumentOutOfRangeException)
                    Fail($"ReadGeospatialStatistics({rg},{col}) with an invalid ordinal gave {e?.GetType().Name ?? "success"}.");
            }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // nested Serialize slices
    // ---------------------------------------------------------------------------------------------------------------

    static void ListSlices(Cur c)
    {
        var listOptional = c.Bool();
        var elementOptional = c.Bool();
        var total = c.Pick(1, 2, 9, 40, 130);
        var maxLength = c.Pick(0, 1, 3, 9);
        var elementLeaf = ColumnDefinition.Leaf("e", ParquetPhysicalType.Int32,
            new ColumnOptions(elementOptional ? ParquetRepetition.Optional : ParquetRepetition.Required,
                ImmutableArray.Create(c.Pick(EncodingKind.Plain, EncodingKind.DeltaBinaryPacked, EncodingKind.RleDictionary))));
        var schema = new PlankSchema([ColumnDefinition.List("l", elementLeaf, listOptional ? ParquetRepetition.Optional : ParquetRepetition.Required)]);
        var leaf = schema.LeafColumns[0];
        var maxDef = (listOptional ? 1 : 0) + 1 + (elementOptional ? 1 : 0);
        if (leaf.MaxRepetitionLevel != 1 || leaf.MaxDefinitionLevel != maxDef)
            Fail($"list schema levels {leaf.MaxRepetitionLevel}/{leaf.MaxDefinitionLevel}, expected 1/{maxDef}.");

        var rows = new int?[total][];
        var counter = 0;
        for (var i = 0; i < total; i++)
        {
            if (listOptional && c.OneIn(4))
            {
                rows[i] = null!;
                continue;
            }

            var n = c.Int(0, maxLength + 1);
            rows[i] = new int?[n];
            for (var j = 0; j < n; j++)
                rows[i][j] = elementOptional && c.OneIn(3) ? null : counter++;
        }

        var offset = c.Pick(0, 1, total / 2, Math.Max(0, total - 1), total);
        var count = Math.Max(0, Math.Min(c.Pick(0, 1, 2, total, total - offset), total - offset));
        var slice = rows.AsSpan(offset, count);
        var what = $"NST1 slice list(optional={listOptional}) elem(optional={elementOptional}) total={total} offset={offset} count={count}";
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream);
        var group = writer.StartRowGroup();
        if (elementOptional)
        {
            var col = group.CreateSerializedColumn<int?[]>(leaf);
            col.Serialize(slice);
            group.Write(col);
        }
        else
        {
            var required = new int[count][];
            for (var i = 0; i < count; i++)
                required[i] = slice[i] is null ? null! : slice[i].Select(static v => v ?? 0).ToArray();
            var col = group.CreateSerializedColumn<int[]>(leaf);
            col.Serialize(required.AsSpan());
            group.Write(col);
            for (var i = 0; i < count; i++)
                slice[i] = slice[i] is null ? null! : slice[i].Select(static v => (int?)(v ?? 0)).ToArray();
        }

        writer.CloseFile();
        _slices++;

        using var reader = schema.CreateReader(new MemoryStream(stream.ToArray(), writable: false));
        var rep = new List<int>();
        var def = new List<int>();
        var vals = new List<int>();
        var rowCount = 0;
        foreach (var rg in Enumerable.Range(0, reader.RowGroups.Count))
            foreach (var buffer in reader.RowGroups[rg].NestedColumn<int>(leaf))
            {
                rowCount += buffer.RowCount;
                vals.AddRange(buffer.Values.Values.ToArray());
                for (var i = 0; i < buffer.Count; i++)
                {
                    rep.Add(buffer.RepetitionLevels[i]);
                    def.Add(buffer.DefinitionLevels[i]);
                }
            }

        if (rowCount != count)
            Fail($"{what}: file has {rowCount} rows.");
        // Expected levels straight from the Dremel rules for one repeated level.
        var wantRep = new List<int>();
        var wantDef = new List<int>();
        var wantVals = new List<int>();
        var baseDef = listOptional ? 1 : 0; // definition level of "list present"
        for (var i = 0; i < count; i++)
        {
            var row = slice[i];
            if (row is null) { wantRep.Add(0); wantDef.Add(0); continue; }
            if (row.Length == 0) { wantRep.Add(0); wantDef.Add(baseDef); continue; }
            for (var j = 0; j < row.Length; j++)
            {
                wantRep.Add(j == 0 ? 0 : 1);
                if (row[j] is null) { wantDef.Add(baseDef + 1); }
                else { wantDef.Add(maxDef); wantVals.Add(row[j]!.Value); }
            }
        }

        if (!rep.SequenceEqual(wantRep) || !def.SequenceEqual(wantDef) || !vals.SequenceEqual(wantVals))
            Fail($"{what}: levels/values differ from the Dremel encoding of the slice (rep {rep.Count}/{wantRep.Count}, def {def.Count}/{wantDef.Count}, values {vals.Count}/{wantVals.Count}).");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // RowReaderOptions on the nested row type
    // ---------------------------------------------------------------------------------------------------------------

    static void NestedReaderOptions(Cur c)
    {
        var count = c.Pick(1, 2, 5, 30);
        var expected = new RowFuzzNested[count];
        for (var i = 0; i < count; i++)
        {
            var inner = c.Int(0, 4);
            expected[i] = new RowFuzzNested
            {
                Sequence = i,
                CorrelationId = Guid.NewGuid(),
                Label = "l" + i,
                Values = inner == 0 ? null : Enumerable.Range(0, inner).Select(k => k == 1 ? Array.Empty<int?>() : new int?[] { k, null, i }).ToArray(),
                Scores = inner < 2 ? null : new Dictionary<int, int?> { [1] = i, [2] = null },
                Items = inner == 3 ? [new RowFuzzEntry { Id = i, Amount = i * 5L }] : null
            };
        }

        using var stream = new MemoryStream();
        var writerOptions = new ParquetWriterOptions
        {
            RowApiInitialRowCapacity = c.Pick(1, 2, 3, 1024),
            TargetRowGroupSizeBytes = c.Pick(1UL, 64UL, 128UL * 1024 * 1024),
            WritePageCrc = c.Bool()
        };
        using (var writer = RowFuzzNested.CreateRowWriter(stream, writerOptions))
        {
            foreach (var want in expected)
            {
                var row = writer.GetRow();
                row.Sequence = want.Sequence;
                row.CorrelationId = want.CorrelationId;
                row.Label = want.Label;
                row.Values = want.Values;
                row.Scores = want.Scores;
                row.Items = want.Items;
            }

            writer.Complete();
        }

        var file = stream.ToArray();
        var readAhead = c.Pick(int.MinValue, -1, 0, 1, 2, int.MaxValue);
        var workers = c.Pick(int.MinValue, -1, 0, 1, 2, 4);
        var badPool = c.OneIn(6);
        var options = new RowReaderOptions { MaxReadAheadRowGroups = readAhead, Execution = new ParquetExecutionOptions { WorkerCount = workers }, VerifyPageCrc = c.Bool() };
        if (badPool)
            typeof(RowReaderOptions).GetProperty(nameof(RowReaderOptions.BufferPool))!.SetValue(options, null);
        var invalid = badPool || readAhead is < 0 or > 1 || workers <= 0;
        var what = $"NST1 nested readAhead={readAhead} workers={workers} nullPool={badPool} rows={count}";
        var created = false;
        Exception? error = null;
        var seen = 0;
        try
        {
            using var reader = RowFuzzNested.CreateRowReader(new MemoryStream(file, writable: false), options: options);
            created = true;
            while (reader.MoveNext())
            {
                var row = reader.Current;
                var want = expected[seen];
                if (row.Sequence != want.Sequence || row.CorrelationId != want.CorrelationId || row.Label != want.Label)
                    Fail($"{what}: scalar columns of row {seen} differ.");
                if ((row.Values?.Length ?? 0) != (want.Values?.Length ?? 0))
                    Fail($"{what}: Values of row {seen} differ.");
                if (row.Values is not null)
                    for (var k = 0; k < row.Values.Length; k++)
                        if ((row.Values[k] is null) != (want.Values![k] is null) || (row.Values[k] is not null && !row.Values[k]!.SequenceEqual(want.Values[k]!)))
                            Fail($"{what}: Values[{k}] of row {seen} differ.");
                if ((row.Scores?.Count ?? 0) != (want.Scores?.Count ?? 0) || (row.Scores is { Count: > 0 } sc && (sc[1] != want.Scores![1] || sc[2] != null)))
                    Fail($"{what}: Scores of row {seen} differ.");
                if ((row.Items?.Count ?? 0) != (want.Items?.Count ?? 0) || (row.Items is { Count: > 0 } items && (items[0].Id != want.Items![0].Id || items[0].Amount != want.Items[0].Amount)))
                    Fail($"{what}: Items of row {seen} differ.");
                seen++;
            }
        }
        catch (InvalidOperationException e) when (e.Message.StartsWith("NST1", StringComparison.Ordinal)) { throw; }
        catch (Exception e) { error = e; }

        if (invalid)
        {
            if (created)
                Fail($"{what}: invalid RowReaderOptions were not rejected at creation (later: {error?.GetType().Name ?? "no error"}).");
            if (error is not ArgumentException)
                Fail($"{what}: invalid RowReaderOptions gave {error?.GetType().Name ?? "success"}: {error?.Message}");
            return;
        }

        if (error is not null)
            Fail($"{what}: valid options failed: {error.GetType().Name}: {error.Message}");
        if (seen != count)
            Fail($"{what}: read {seen} of {count} rows.");
        _nestedReads++;
    }
}
