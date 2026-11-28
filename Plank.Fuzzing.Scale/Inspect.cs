using Plank.Reading.Physical;
using Ps = ParquetSharp;

namespace Plank.Fuzzing.Scale;

/// <summary>Triage helper: `inspect &lt;file&gt;` reads every column chunk with ParquetSharp separately and, for the
/// chunks it cannot read, prints both libraries' view of the chunk and Plank's page headers.</summary>
public static class Inspect
{
    public static int Run(string path)
    {
        using var plank = new ParquetFileReader();
        using var stream = File.OpenRead(path);
        plank.Reset(stream);
        var meta = plank.Metadata;
        using var arrow = new Ps.ParquetFileReader(path);
        var failures = 0;
        for (var g = 0; g < meta.RowGroupCount; g++)
        {
            using var group = arrow.RowGroup(g);
            for (var c = 0; c < meta.ColumnCount; c++)
            {
                string? error = null;
                try
                {
                    using var column = group.Column(c);
                    Drain(column);
                }
                catch (Exception ex) { error = ex.Message; }
                if (error is null)
                    continue;
                failures++;
                var chunk = meta.ColumnChunk(g, c);
                using var am = group.MetaData.GetColumnChunkMetaData(c);
                Console.WriteLine($"rg{g} col{c}: arrow: {error}");
                Console.WriteLine($"  plank chunk: data@{chunk.DataPageOffset} dict@{chunk.DictionaryPageOffset} compressed={chunk.TotalCompressedSize} uncompressed={chunk.TotalUncompressedSize} {chunk.Compression}");
                Console.WriteLine($"  arrow chunk: compressed={am.TotalCompressedSize} uncompressed={am.TotalUncompressedSize} values={am.NumValues} file_offset={am.FileOffset}");
                try
                {
                    var n = 0;
                    foreach (var page in plank.OpenPages(g, c))
                    {
                        var h = page.Header;
                        if (n++ < 12)
                            Console.WriteLine($"  page {n - 1}: {h.Type} header={h.HeaderLength} compressed={h.CompressedPageSize} uncompressed={h.UncompressedPageSize} values={h.ValueCount} rows={h.RowCount} enc={h.Encoding}");
                    }
                    Console.WriteLine($"  {n} pages");
                }
                catch (Exception ex) { Console.WriteLine($"  plank pages: {ex.GetType().Name}: {ex.Message}"); }
                if (failures > 20)
                    return 1;
            }
        }
        Console.WriteLine($"{failures} chunks Arrow cannot read");
        return failures == 0 ? 0 : 1;
    }

    static void Drain(Ps.ColumnReader column)
    {
        switch (column)
        {
            case Ps.ColumnReader<Ps.ByteArray> r: Drain(r); break;
            case Ps.ColumnReader<int> r: Drain(r); break;
            case Ps.ColumnReader<long> r: Drain(r); break;
            case Ps.ColumnReader<double> r: Drain(r); break;
            case Ps.ColumnReader<float> r: Drain(r); break;
            case Ps.ColumnReader<bool> r: Drain(r); break;
        }
    }

    static void Drain<T>(Ps.ColumnReader<T> r) where T : unmanaged
    {
        var v = new T[1024]; var d = new short[1024]; var rep = new short[1024];
        while (r.HasNext)
            r.ReadBatch(v.Length, d, rep, v, out _);
    }
}

/// <summary>Minimal repros for findings of this driver (`repro &lt;name&gt; &lt;dir&gt;`).</summary>
public static class Repros
{
    public static int Run(string name, string dir)
    {
        Directory.CreateDirectory(dir);
        switch (name)
        {
            case "page-header-untruncated-statistics":
            {
                // One required string column, one row whose value is 9 MB: Plank stores the whole value as the page's
                // min and max, so the data page header is ~18 MB. Arrow C++ refuses page headers above 16 MB.
                var path = Path.Combine(dir, "one-9mb-string.parquet");
                var schema = new Plank.Schema.ParquetSchema([Plank.Schema.ColumnDefinition.RequiredLeaf("s",
                    Plank.Schema.ParquetPhysicalType.ByteArray, logicalType: new Plank.Schema.LogicalType.String())]);
                using (var output = File.Create(path))
                using (var writer = schema.CreateWriter(output, new Plank.Writing.ParquetWriterOptions { Compression = Plank.Schema.CompressionKind.None }))
                {
                    var column = writer.CreateSerializedColumn<string>(schema.LeafColumns[0]);
                    var rg = writer.StartRowGroup();
                    column.Serialize([new string('x', 9 << 20)]);
                    rg.Write(column);
                    writer.CloseFile();
                }
                using (var plank = new ParquetFileReader())
                using (var stream = File.OpenRead(path))
                {
                    plank.Reset(stream);
                    foreach (var page in plank.OpenPages(0, 0))
                        Console.WriteLine($"Plank: {page.Header.Type} header {page.Header.HeaderLength} bytes, payload {page.Header.CompressedPageSize} bytes");
                    Console.WriteLine($"Plank: footer {plank.Metadata.FooterLength} bytes, file {stream.Length} bytes");
                }
                try
                {
                    using var arrow = new Ps.ParquetFileReader(path);
                    using var group = arrow.RowGroup(0);
                    using var column = (Ps.ColumnReader<Ps.ByteArray>)group.Column(0);
                    var values = new Ps.ByteArray[1];
                    column.ReadBatch(1, values, out var read);
                    Console.WriteLine($"Arrow: read {read} value of {values[0].Length} bytes");
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Arrow: {ex.GetType().Name}: {ex.Message.ReplaceLineEndings(" ")}");
                    return 1;
                }
            }
            case "serialized-column-per-row-group-retained":
            {
                // One int column, 1000 rows per row group. Variant A creates the SerializedColumn once (writer level);
                // variant B creates it from each RowGroupWriter. B's live memory (after a full GC, writer still open)
                // grows with every row group: the writer keeps every SerializedColumn it ever created.
                var schema = new Plank.Schema.ParquetSchema([Plank.Schema.ColumnDefinition.RequiredLeaf("v", Plank.Schema.ParquetPhysicalType.Int32)]);
                var values = Enumerable.Range(0, 1000).ToArray();
                var exit = 0;
                foreach (var perGroup in new[] { false, true })
                {
                    using var writer = schema.CreateWriter(Stream.Null, new Plank.Writing.ParquetWriterOptions());
                    Plank.Writing.SerializedColumn<int>? shared = perGroup ? null : writer.CreateSerializedColumn<int>(schema.LeafColumns[0]);
                    long first = 0;
                    for (var g = 1; g <= 2000; g++)
                    {
                        var rg = writer.StartRowGroup();
                        var column = shared ?? rg.CreateSerializedColumn<int>(schema.LeafColumns[0]);
                        column.Serialize(values);
                        rg.Write(column);
                        if (g is 10 or 500 or 1000 or 2000)
                        {
                            var live = GC.GetTotalMemory(forceFullCollection: true);
                            if (g == 10) first = live;
                            Console.WriteLine($"{(perGroup ? "per-row-group column" : "shared column")}: after {g} row groups, live managed memory {live >> 10} KB");
                            if (perGroup && g == 2000 && live > first * 8)
                                exit = 1;
                        }
                    }
                    writer.CloseFile();
                }
                return exit;
            }
            case "time-nanos-negative":
            {
                // TIME(NANOS) and TIME(MICROS) columns holding the same raw values; read as TimeOnly one value at a time.
                long[] raws = [-1, -5, -99, -100, -101, 0, 99, 86_399_999_999_999, 86_400_000_000_000, 86_400_000_000_099];
                var exit = 0;
                foreach (var unit in new[] { Plank.Schema.TimeUnit.Nanos, Plank.Schema.TimeUnit.Micros })
                    foreach (var raw in raws)
                    {
                        var schema = new Plank.Schema.ParquetSchema([Plank.Schema.ColumnDefinition.RequiredLeaf("t",
                            Plank.Schema.ParquetPhysicalType.Int64, logicalType: new Plank.Schema.LogicalType.Time(unit, false))]);
                        var output = new MemoryStream();
                        using (var writer = schema.CreateWriter(output))
                        {
                            var column = writer.CreateSerializedColumn<long>(schema.LeafColumns[0]);
                            var rg = writer.StartRowGroup();
                            column.Serialize([raw]);
                            rg.Write(column);
                            writer.CloseFile();
                        }
                        using var reader = new Plank.Reading.Logical.ParquetReader();
                        reader.Reset(new Plank.Reading.MemoryReadSource(output.ToArray()));
                        string result;
                        try
                        {
                            TimeOnly? got = null;
                            foreach (Plank.Reading.Logical.RowGroup g in reader.RowGroups)
                                foreach (var b in g.Column<TimeOnly>(reader.Schema.LeafColumns[0]))
                                    got = b.Values[0];
                            result = $"TimeOnly {got:HH:mm:ss.fffffff} ({got?.Ticks} ticks)";
                            var perDay = unit == Plank.Schema.TimeUnit.Nanos ? 86_400_000_000_000L : 86_400_000_000L;
                            if (raw < 0 || raw >= perDay) { result += "  <-- invalid time of day accepted"; exit = 1; }
                        }
                        catch (Exception ex) { result = $"{ex.GetType().Name}: {ex.Message}"; }
                        Console.WriteLine($"TIME({unit}) raw {raw,20}: {result}");
                    }
                return exit;
            }
            case "int96-negative-nanos":
            {
                // INT96 values with a valid Julian day (2440588 = 1970-01-01) and out-of-range nanoseconds of day.
                long[] nanos = [-1, -99, -100, -86_400_000_000_000, 0, 86_399_999_999_999, 86_400_000_000_000, long.MaxValue];
                var exit = 0;
                foreach (var n in nanos)
                {
                    var schema = new Plank.Schema.ParquetSchema([Plank.Schema.ColumnDefinition.RequiredLeaf("t", Plank.Schema.ParquetPhysicalType.Int96)]);
                    var output = new MemoryStream();
                    var raw = new byte[12];
                    System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(raw, n);
                    System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(8), 2440588);
                    using (var writer = schema.CreateWriter(output))
                    {
                        var column = writer.CreateSerializedColumn<byte[]>(schema.LeafColumns[0]);
                        var rg = writer.StartRowGroup();
                        column.Serialize([raw]);
                        rg.Write(column);
                        writer.CloseFile();
                    }
                    using var reader = new Plank.Reading.Logical.ParquetReader();
                    reader.Reset(new Plank.Reading.MemoryReadSource(output.ToArray()));
                    string result;
                    try
                    {
                        DateTime? got = null;
                        foreach (Plank.Reading.Logical.RowGroup g in reader.RowGroups)
                            foreach (var b in g.Column<DateTime>(reader.Schema.LeafColumns[0]))
                                got = b.Values[0];
                        result = $"DateTime {got:O}";
                        if (n < 0 || n >= 86_400_000_000_000L) { result += "  <-- nanoseconds outside the day accepted"; exit = 1; }
                    }
                    catch (Exception ex) { result = $"{ex.GetType().Name}: {ex.Message}"; }
                    Console.WriteLine($"INT96 day 2440588 nanos {n,20}: {result}");
                }
                return exit;
            }
            default:
                Console.Error.WriteLine("unknown repro " + name);
                return 2;
        }
    }
}

/// <summary>`memprobe &lt;file&gt;`: managed bytes allocated reading each column through each read source.</summary>
public static class MemProbe
{
    public static int Run(string path)
    {
        var bytes = File.ReadAllBytes(path);
        foreach (var kind in new[] { "memory", "file", "stream" })
        {
            using var reader = new Plank.Reading.Logical.ParquetReader();
            Plank.Reading.IParquetReadSource source = kind switch
            {
                "memory" => new Plank.Reading.MemoryReadSource(bytes),
                "file" => new Plank.Reading.FileReadSource(path),
                _ => new Plank.Reading.StreamReadSource(new MemoryStream(bytes)),
            };
            reader.Reset(source);
            foreach (var leaf in reader.Schema.LeafColumns)
            {
                var before = GC.GetTotalAllocatedBytes(true);
                long n = 0;
                foreach (Plank.Reading.Logical.RowGroup g in reader.RowGroups)
                    foreach (var b in Count(g, leaf))
                        n += b;
                var after = GC.GetTotalAllocatedBytes(true);
                Console.WriteLine($"{kind} {leaf.Path} {leaf.PhysicalType} {leaf.Options.Repetition}: {(after - before) >> 10} KB allocated, {n} values");
            }
        }
        return 0;
    }

    static IEnumerable<long> Count(Plank.Reading.Logical.RowGroup g, Plank.Schema.LeafColumn leaf)
    {
        var list = new List<long>();
        var optional = leaf.Options.Repetition == Plank.Schema.ParquetRepetition.Optional;
        switch (leaf.PhysicalType)
        {
            case Plank.Schema.ParquetPhysicalType.Boolean: if (optional) foreach (var b in g.Column<bool?>(leaf)) list.Add(b.Count); else foreach (var b in g.Column<bool>(leaf)) list.Add(b.Count); break;
            case Plank.Schema.ParquetPhysicalType.Int32: if (optional) foreach (var b in g.Column<int?>(leaf)) list.Add(b.Count); else foreach (var b in g.Column<int>(leaf)) list.Add(b.Count); break;
            case Plank.Schema.ParquetPhysicalType.Int64: if (optional) foreach (var b in g.Column<long?>(leaf)) list.Add(b.Count); else foreach (var b in g.Column<long>(leaf)) list.Add(b.Count); break;
            case Plank.Schema.ParquetPhysicalType.Float: if (optional) foreach (var b in g.Column<float?>(leaf)) list.Add(b.Count); else foreach (var b in g.Column<float>(leaf)) list.Add(b.Count); break;
            case Plank.Schema.ParquetPhysicalType.Double: if (optional) foreach (var b in g.Column<double?>(leaf)) list.Add(b.Count); else foreach (var b in g.Column<double>(leaf)) list.Add(b.Count); break;
            default: foreach (var b in g.Column<byte>(leaf)) list.Add(b.Count); break;
        }
        return list;
    }
}
