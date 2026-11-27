#!/usr/bin/env python3
"""Generates Plank.Fuzzing/RowFuzzWide.g.cs: wide row schemas (every scalar kind) and
the typed helpers (generate / set / compare) the row-API routes need.
Usage: python3 fuzz/tools/gen_row_wide.py > Plank.Fuzzing/RowFuzzWide.g.cs
"""
# name, clr (non-null), attribute args, value-kind
COLS = [
    ("Flag", "bool", "", "bool"),
    ("U8", "byte", "LogicalType = LogicalTypeKind.Integer", "u8"),
    ("U16", "ushort", "LogicalType = LogicalTypeKind.Integer", "u16"),
    ("U32", "uint", "LogicalType = LogicalTypeKind.Integer", "u32"),
    ("U64", "ulong", "LogicalType = LogicalTypeKind.Integer", "u64"),
    ("I32", "int", "Encodings = [EncodingKind.DeltaBinaryPacked]", "i32"),
    ("I64", "long", "Compression = CompressionKind.Zstd", "i64"),
    ("F32", "float", "Encodings = [EncodingKind.ByteStreamSplit]", "f32"),
    ("F64", "double", "Encodings = [EncodingKind.ByteStreamSplit], Compression = CompressionKind.Snappy", "f64"),
    ("F64Alp", "double", "Encodings = [EncodingKind.Alp]", "f64"),
    ("Dec32", "decimal", "Precision = 9, Scale = 2", "dec:9:2"),
    ("Dec64", "decimal", "Precision = 18, Scale = 4", "dec:18:4"),
    ("DecFixed", "decimal", "Precision = 28, Scale = 8", "dec:28:8"),
    ("DecBytes", "decimal", "ParquetPhysicalType.ByteArray, Precision = 20, Scale = 3", "dec:20:3"),
    ("Text", "string", "Encodings = [EncodingKind.DeltaByteArray]", "str"),
    ("Dict", "string", "Encodings = [EncodingKind.RleDictionary]", "strdict"),
    ("Blob", "byte[]", "Encodings = [EncodingKind.DeltaLengthByteArray], Compression = CompressionKind.Gzip, CompressionLevel = 3", "bytes"),
    ("Mem", "ReadOnlyMemory<byte>", "BloomFilter = true", "mem"),
    ("Uuid", "Guid", "BloomFilter = true", "guid"),
    ("Day", "DateOnly", "LogicalType = LogicalTypeKind.Date", "date"),
    ("Clock", "TimeOnly", "LogicalType = LogicalTypeKind.Time", "time"),
    ("Stamp", "DateTime", "LogicalType = LogicalTypeKind.Timestamp", "ts"),
    ("Instant", "DateTimeOffset", "LogicalType = LogicalTypeKind.Timestamp, Compression = CompressionKind.Lz4", "tso"),
    ("Tag", "RowFuzzId", "Converter = typeof(RowFuzzIdConverter)", "tag"),
    ("Odd", "int", r'"odd name.with\\back\u00e9\t\'q", FieldId = 77, BloomFilter = true', "i32"),
]
ALL_COLS = COLS
NO_CONVERTER = [c for c in COLS if c[3] != 'tag']
# An id column is added first and always set to the row index, so rows can be matched
# after reordering across files/partitions.

def clr(c, nullable):
    n = c[1]
    if not nullable:
        return n
    return n + "?"

def is_ref(c):
    return c[1] in ("string", "byte[]")

def gen_expr(kind):
    k = kind.split(":")
    t = k[0]
    return {
        "bool": "c.NextInt(0, 2) == 0",
        "u8": "(byte)c.NextInt32()",
        "u16": "(ushort)c.NextInt32()",
        "u32": "(uint)c.NextInt32()",
        "u64": "(ulong)c.NextInt64()",
        "i32": "c.NextInt32()",
        "i64": "c.NextInt64()",
        "f32": "BitConverter.Int32BitsToSingle(c.NextInt32())",
        "f64": "c.NextDouble()",
        "dec": f"c.NextDecimal({k[1] if t == 'dec' else 0}, {k[2] if t == 'dec' else 0})",
        "str": "c.NextLabel()",
        "strdict": "c.NextDictLabel()",
        "bytes": "c.NextBytes(MaxBinaryLength)",
        "mem": "new ReadOnlyMemory<byte>(c.NextBytes(MaxBinaryLength))",
        "guid": "c.NextGuid()",
        "date": "c.NextDate()",
        "time": "c.NextTime()",
        "ts": "c.NextTimestamp()",
        "tso": "c.NextTimestampOffset()",
        "tag": "new RowFuzzId(c.NextInt32())",
    }[t]

def eq_expr(kind, a, b, nullable, col):
    t = kind.split(":")[0]
    if t in ("f32",):
        core = lambda x, y: f"BitConverter.SingleToInt32Bits({x}) == BitConverter.SingleToInt32Bits({y})"
    elif t == "f64":
        core = lambda x, y: f"BitConverter.DoubleToInt64Bits({x}) == BitConverter.DoubleToInt64Bits({y})"
    elif t in ("str", "strdict"):
        core = lambda x, y: f"string.Equals({x}, {y}, StringComparison.Ordinal)"
    elif t == "bytes":
        core = lambda x, y: f"{x}.SequenceEqual({y})"
    elif t == "mem":
        core = lambda x, y: f"{x}.Span.SequenceEqual({y}.Span)"
    else:
        core = lambda x, y: f"{x} == {y}"
    return core

def emit_class(name, nullable, cols=None):
    COLS = cols if cols is not None else ALL_COLS
    o = []
    a = o.append
    a(f"[ParquetSchema(AllowAllocatingValues = true)]")
    a(f"public sealed partial class {name}")
    a("{")
    a("    public int Seq { get; set; }\n")
    for c in COLS:
        attr = f"[ParquetColumn({c[2]})]" if c[2] else ""
        if c[2].startswith("ParquetPhysicalType") or c[2].startswith('"'):
            attr = f"[ParquetColumn({c[2]})]"
        t = clr(c, nullable)
        if attr:
            a(f"    {attr}")
        init = ""
        if not nullable and c[1] == "string":
            init = " = string.Empty;"
        if not nullable and c[1] == "byte[]":
            init = " = [];"
        a(f"    public {t} {c[0]} {{ get; set; }}{init}\n")
    a("}\n")

    # helper class
    h = f"{name}Ops"
    a(f"static class {h}")
    a("{")
    a("    internal const int MaxBinaryLength = 24;")
    a(f"    internal const int ColumnCount = {len(COLS) + 1};\n")
    a(f"    internal static {name} Generate(ref PlankRowApiFuzzTarget.Cursor c, int seq)")
    a("    {")
    a(f"        var v = new {name} {{ Seq = seq }};")
    for col in COLS:
        e = gen_expr(col[3])
        if nullable:
            # Cast so the null arm is a real null: a bare `default` binds to the non-nullable
            # type and silently writes zero values instead of nulls.
            a(f"        v.{col[0]} = c.NextInt(0, 4) == 0 ? null : ({clr(col, True)})({e});")
        else:
            a(f"        v.{col[0]} = {e};")
    a("        return v;")
    a("    }\n")
    a(f"    internal static void Set({name}.Row r, {name} v)")
    a("    {")
    a("        r.Seq = v.Seq;")
    for col in COLS:
        a(f"        r.{col[0]} = v.{col[0]};")
    a("    }\n")
    a(f"    internal static void SetCursor(ref {name}.RowCursor r, {name} v)")
    a("    {")
    a("        r.NextRow();")
    a("        r.Seq = v.Seq;")
    for col in COLS:
        a(f"        r.{col[0]} = v.{col[0]};")
    a("    }\n")
    a(f"    internal static {name}.Projection Project(int mask)")
    a("    {")
    a(f"        var p = {name}.Projection.None;")
    a(f"        if ((mask & 1) != 0) p |= {name}.Projection.Seq;")
    for i, col in enumerate(COLS):
        a(f"        if ((mask & {1 << (i + 1)}) != 0) p |= {name}.Projection.{col[0]};")
    a("        return p;")
    a("    }\n")
    a(f"    // Returns the first column whose value differs from v, or null.")
    a(f"    internal static string? Compare({name}.ReadRow r, {name} v, int mask)")
    a("    {")
    a("        if ((mask & 1) != 0 && r.Seq != v.Seq) return \"Seq\";")
    for i, col in enumerate(COLS):
        t = col[3].split(":")[0]
        p = f"r.{col[0]}"
        w = f"v.{col[0]}"
        bit = 1 << (i + 1)
        if t == "bytes":
            if nullable:
                cond = f"({p}.IsNull != ({w} is null)) || (!{p}.IsNull && !{p}.Value.SequenceEqual({w}))"
            else:
                cond = f"!{p}.Value.SequenceEqual({w})"
        elif t == "mem":
            if nullable:
                cond = f"({p}.IsNull != !{w}.HasValue) || (!{p}.IsNull && !{p}.Value.SequenceEqual({w}.Value.Span))"
            else:
                cond = f"!{p}.Value.SequenceEqual({w}.Span)"
        elif t in ("f32", "f64"):
            bits = "SingleToInt32Bits" if t == "f32" else "DoubleToInt64Bits"
            if nullable:
                cond = f"({p} is null) != ({w} is null) || ({p} is {{ }} pv{i} && BitConverter.{bits}(pv{i}) != BitConverter.{bits}({w}!.Value))"
            else:
                cond = f"BitConverter.{bits}({p}) != BitConverter.{bits}({w})"
        elif t in ("str", "strdict"):
            cond = f"!string.Equals({p}, {w}, StringComparison.Ordinal)"
        else:
            cond = f"{p} != {w}"
        a(f"        if ((mask & {bit}) != 0 && ({cond})) return \"{col[0]}\";")
    a("        return null;")
    a("    }")
    a("}\n")
    return "\n".join(o)


ROUTES = r"""
static class @S@Routes
{
    internal static void Run(ref PlankRowApiFuzzTarget.Cursor c)
    {
        var s = RowRouteSettings.Draw(ref c);
        RowRouteSettings.Announce(s);
        try
        {
            RunCore(ref c, s);
        }
        catch (PlankRowApiFuzzTarget.RowApiRoundTripException ex)
        {
            throw new PlankRowApiFuzzTarget.RowApiRoundTripException(ex.Message + " | " + s);
        }
        catch (Exception ex) when (RowRouteSettings.Trace(ex, s))
        {
            throw;
        }
    }

    static void RunCore(ref PlankRowApiFuzzTarget.Cursor c, RowRouteSettings s)
    {
        var rows = new @S@[s.Count];
        for (var i = 0; i < rows.Length; i++)
            rows[i] = @S@Ops.Generate(ref c, i);
        var options = s.WriterOptions();
        switch (s.Route)
        {
            case RowWriteRoute.PipelineStream:
            case RowWriteRoute.PipelineCursor:
            {
                using var stream = new MemoryStream();
                var flushed = 0;
                using (var w = CreatePipeline(stream, s, options, n => flushed += n))
                {
                    if (s.Route == RowWriteRoute.PipelineCursor)
                    {
                        var cursor = w.CreateCursor();
                        foreach (var v in rows)
                            @S@Ops.SetCursor(ref cursor, v);
                    }
                    else
                    {
                        foreach (var v in rows)
                            @S@Ops.Set(w.GetRow(), v);
                    }
                    w.Complete();
                }
                if ((s.WriterVariant & 1) != 0 && flushed != rows.Length)
                    throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ flush callback saw {flushed} rows; expected {rows.Length}.");
                CheckFile(stream.ToArray(), rows, s, "@S@ pipeline");
                break;
            }
            case RowWriteRoute.PipelineReset:
            {
                var split = rows.Length / 2;
                using var first = new MemoryStream();
                using var second = new MemoryStream();
                using (var w = CreatePipeline(first, s, options, null))
                {
                    foreach (var v in rows.AsSpan(0, split))
                        @S@Ops.Set(w.GetRow(), v);
                    w.Complete();
                    w.Reset(second);
                    foreach (var v in rows.AsSpan(split))
                        @S@Ops.Set(w.GetRow(), v);
                    w.Complete();
                }
                CheckFile(first.ToArray(), rows[..split], s, "@S@ before reset");
                CheckFile(second.ToArray(), rows[split..], s, "@S@ after reset");
                break;
            }
            case RowWriteRoute.Rolling:
            {
                var store = new InMemoryFileStore();
                using var file = new InMemoryDatasetFile(store);
                ParquetFilePath path = (ulong index, IParquetBufferPool _, out ParquetBuffer? allocation) =>
                {
                    allocation = null;
                    return System.Text.Encoding.UTF8.GetBytes($"part-{index:D6}.parquet");
                };
                using (var w = @S@.CreateRowWriter(path, file, options))
                {
                    foreach (var v in rows)
                        @S@Ops.Set(w.GetRow(), v);
                    w.Complete();
                }
                var parts = store.Files.OrderBy(static f => f.Key, StringComparer.Ordinal).ToArray();
                var next = 0;
                for (var i = 0; i < parts.Length; i++)
                {
                    if (parts[i].Key != $"part-{i:D6}.parquet")
                        throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ rolling writer skipped a file index before '{parts[i].Key}'.");
                    var bytes = parts[i].Value.ToArray();
                    var count = ReadAll(bytes, rows, next, s, "@S@ rolling part " + i);
                    if (count == 0 && rows.Length > 0)
                        throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ rolling writer produced an empty file part {i}.");
                    next += count;
                }
                if (next != rows.Length)
                    throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ rolling writer kept {next} of {rows.Length} rows.");
                break;
            }
            case RowWriteRoute.DirectGroups:
            {
                // Several row groups per file, each with its own writer and an
                // independently drawn capacity; the groups are never the same size.
                using var stream = new MemoryStream();
                var sizes = new int[s.Groups];
                var left = rows.Length;
                for (var g = 0; g < sizes.Length; g++)
                {
                    sizes[g] = g == sizes.Length - 1 ? left : Math.Min(left, c.NextInt(0, rows.Length + 1));
                    left -= sizes[g];
                }
                using (var parquetWriter = @S@.Schema.CreateWriter(stream, options))
                {
                    var at = 0;
                    for (var g = 0; g < sizes.Length; g++)
                    {
                        var groupOptions = new ParquetWriterOptions
                        {
                            RowApiInitialRowCapacity = g == 0 ? s.InitialCapacity : c.NextInt(1, 6),
                            TargetRowGroupSizeBytes = options.TargetRowGroupSizeBytes,
                            TargetFileSizeBytes = options.TargetFileSizeBytes
                        };
                        var gw = @S@.CreateRowWriter(parquetWriter.StartRowGroup(), groupOptions);
                        for (var i = 0; i < sizes[g]; i++)
                            @S@Ops.Set(gw.GetRow(), rows[at++]);
                        gw.Write();
                    }
                    parquetWriter.CloseFile();
                }
                var bytes = stream.ToArray();
                using (var meta = @S@.Schema.CreateReader(new MemoryStream(bytes, writable: false)))
                {
                    if (meta.RowGroups.Count != sizes.Length)
                        throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ direct writer wrote {meta.RowGroups.Count} row groups; expected {sizes.Length}.");
                    for (var g = 0; g < sizes.Length; g++)
                        if (meta.RowGroups[g].RowCount != (ulong)sizes[g])
                            throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ direct row group {g} has {meta.RowGroups[g].RowCount} rows; expected {sizes[g]}.");
                }
                CheckFile(bytes, rows, s, "@S@ direct groups");
                break;
            }
        }
    }


    static readonly byte[][] DatasetKeys = [.. Enumerable.Range(0, 6).Select(static i => System.Text.Encoding.UTF8.GetBytes($"part{i}"))];

    static int PartitionOf(@S@ v, int partitions)
        => (int)((((uint)v.Seq * 2654435761u) >> 8) % (uint)partitions);

    // Routes generated rows through the generated dataset writer with independent pool size,
    // pending capacity, append options, rollover and (optionally) an injected I/O fault.
    internal static void RunDataset(ref PlankRowApiFuzzTarget.Cursor c)
    {
        var s = RowRouteSettings.Draw(ref c);
        RowRouteSettings.Announce(s);
        try
        {
            RunDatasetCore(ref c, s);
        }
        catch (PlankRowApiFuzzTarget.RowApiRoundTripException ex)
        {
            throw new PlankRowApiFuzzTarget.RowApiRoundTripException(ex.Message + " | " + s);
        }
        catch (Exception ex) when (RowRouteSettings.Trace(ex, s))
        {
            throw;
        }
    }

    static void RunDatasetCore(ref PlankRowApiFuzzTarget.Cursor c, RowRouteSettings s)
    {
        var partitions = c.NextInt(1, 7);
        var createParts = c.NextBool();
        var ownedPath = c.NextBool();
        var poolSize = c.NextInt(1, 5);
        var pending = (uint)(c.NextInt(0, 4) == 0 ? 0 : c.NextInt(1, 12));
        var append = new ParquetAppendOptions
        {
            PreserveExistingMetadata = c.NextBool(),
            // The Tag column uses a value converter, and appending to the latest row group of an
            // existing file fails on such columns (fuzz/repros/dataset-append-latest-converter),
            // so for the wide schemas that option is off unless PLANK_FUZZ_APPEND_LATEST_CONVERTER=1.
            AppendToLatestRowGroup = c.NextBool() && @APPENDLATEST@,
            WriterOptions = s.WriterOptions()
        };
        var failAt = c.NextInt(0, 3) == 0 ? c.NextInt(1, 40) : 0;
        var plan = new DatasetFaultPlan(failAt, c.NextInt(1, 64), c.NextBool());
        var rows = new @S@[s.Count];
        for (var i = 0; i < rows.Length; i++)
            rows[i] = @S@Ops.Generate(ref c, i);

        var store = new InMemoryFileStore();
        var files = new FaultingDatasetFile[poolSize];
        for (var i = 0; i < files.Length; i++)
            files[i] = new FaultingDatasetFile(new InMemoryDatasetFile(store), plan);
        var options = new DatasetWriterOptions
        {
            AppendOptions = append,
            WriterOptions = append.WriterOptions,
            PendingRowCapacity = createParts ? 0 : pending
        };
        @S@.Route route = (@S@ row, IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            var key = DatasetKeys[PartitionOf(row, partitions)];
            if (!ownedPath)
            {
                allocation = null;
                return key;
            }
            var owner = pool.Rent(checked((uint)(key.Length + 1)));
            allocation = owner;
            key.CopyTo(owner.Span[1..]);
            return owner.Span[1..(key.Length + 1)];
        };
        DatasetFilePath filePath = (ReadOnlySpan<byte> key, ulong index, IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return System.Text.Encoding.UTF8.GetBytes($"{System.Text.Encoding.UTF8.GetString(key)}-{index}");
        };

        var writer = createParts
            ? @S@.CreateDatasetWriter(route, filePath, files, options)
            : @S@.CreateDatasetWriter(route, files, options);
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
            // A failed dataset writer is permanently faulted: later calls rethrow the original failure.
            try
            {
                writer.Queue(rows.Length > 0 ? rows[0] : @S@Ops.Generate(ref c, 0));
                throw new PlankRowApiFuzzTarget.RowApiRoundTripException("@S@ dataset writer accepted a row after a failure.");
            }
            catch (IOException again) when (again.Message == injected.Message)
            {
            }
            // The failure was already reported to the caller, so cleanup must not throw it again.
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
            throw new PlankRowApiFuzzTarget.RowApiRoundTripException("@S@ dataset writer accepted a second Dispose.");
        }
        catch (InvalidOperationException)
        {
        }

        if (Environment.GetEnvironmentVariable("PLANK_FUZZ_TRACE") == "2")
            Console.Error.WriteLine($"DATASET rows={rows.Length} parts={partitions} files={store.Files.Count} pool={poolSize} pending={pending} createParts={createParts} failAt={failAt} fired={plan.Fired} injected={injected is not null}");
        if (injected is not null)
        {
            if (!plan.Fired)
                throw new PlankRowApiFuzzTarget.RowApiRoundTripException("@S@ dataset reported an injected fault that never fired.");
            return;
        }
        if (plan.Fired)
            throw new PlankRowApiFuzzTarget.RowApiRoundTripException("@S@ dataset swallowed an injected fault.");

        var expectedByPartition = Enumerable.Range(0, partitions).Select(static _ => new List<int>()).ToArray();
        foreach (var row in rows)
            expectedByPartition[PartitionOf(row, partitions)].Add(row.Seq);
        var actualByPartition = Enumerable.Range(0, partitions).Select(static _ => new List<(ulong Part, List<int> Seqs)>()).ToArray();
        foreach (var (path, stream) in store.Files)
        {
            if (stream.Length == 0)
                continue;
            var partition = -1;
            for (var i = 0; i < partitions; i++)
                if (path.StartsWith($"part{i}", StringComparison.Ordinal) && (path.Length == 5 || path[5] == '-'))
                    partition = i;
            if (partition < 0)
                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ dataset file '{path}' names no partition.");
            var part = createParts && ulong.TryParse(path.AsSpan(path.LastIndexOf('-') + 1), out var index) ? index : 0;
            actualByPartition[partition].Add((part, ReadSeqs(stream.ToArray(), rows, s, partition, partitions, path)));
        }
        for (var p = 0; p < partitions; p++)
        {
            var merged = actualByPartition[p].OrderBy(static x => x.Part).SelectMany(static x => x.Seqs).ToList();
            if (!merged.SequenceEqual(expectedByPartition[p]))
                throw new PlankRowApiFuzzTarget.RowApiRoundTripException(
                    $"@S@ dataset partition {p} holds {merged.Count} rows in a different order or set than the {expectedByPartition[p].Count} queued.");
        }
    }

    static List<int> ReadSeqs(byte[] bytes, @S@[] rows, RowRouteSettings s, int partition, int partitions, string path)
    {
        var seqs = new List<int>();
        using var reader = @S@.CreateRowReader(new MemoryStream(bytes, writable: false), default, s.ReaderOptions());
        while (reader.MoveNext())
        {
            var seq = reader.Current.Seq;
            if ((uint)seq >= (uint)rows.Length)
                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ dataset file '{path}' returned unknown Seq {seq}.");
            if (PartitionOf(rows[seq], partitions) != partition)
                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ dataset row {seq} was written to '{path}' (partition {partition}).");
            var diff = @S@Ops.Compare(reader.Current, rows[seq], (1 << @S@Ops.ColumnCount) - 1);
            if (diff is not null)
                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"@S@ dataset lost '{diff}' of row {seq} in '{path}'.");
            seqs.Add(seq);
        }
        return seqs;
    }


    // Writes several files with independently drawn writer settings (so each has its own
    // row-group layout, codec and page version), merges them with drawn merge options, and
    // checks the merged file holds exactly the concatenation, with consistent counters.
    internal static void RunMerge(ref PlankRowApiFuzzTarget.Cursor c)
    {
        var s = RowRouteSettings.Draw(ref c);
        RowRouteSettings.Announce(s);
        try
        {
            RunMergeCore(ref c, s);
        }
        catch (PlankRowApiFuzzTarget.RowApiRoundTripException ex)
        {
            throw new PlankRowApiFuzzTarget.RowApiRoundTripException(ex.Message + " | " + s);
        }
        catch (Exception ex) when (RowRouteSettings.Trace(ex, s))
        {
            throw;
        }
    }

    static void RunMergeCore(ref PlankRowApiFuzzTarget.Cursor c, RowRouteSettings s)
    {
        var fileCount = c.NextInt(1, 5);
        var all = new List<@S@>();
        var files = new byte[fileCount][];
        var groupCounts = new int[fileCount];
        for (var f = 0; f < fileCount; f++)
        {
            var fs = RowRouteSettings.Draw(ref c);
            var count = Math.Min(fs.Count, 40);
            var rows = new @S@[count];
            for (var i = 0; i < count; i++)
                rows[i] = @S@Ops.Generate(ref c, all.Count + i);
            all.AddRange(rows);
            using var stream = new MemoryStream();
            using (var w = CreatePipeline(stream, fs, fs.WriterOptions(), null))
            {
                foreach (var v in rows)
                    @S@Ops.Set(w.GetRow(), v);
                w.Complete();
            }
            files[f] = stream.ToArray();
            using var meta = @S@.Schema.CreateReader(new MemoryStream(files[f], writable: false));
            groupCounts[f] = meta.RowGroups.Count;
        }

        var options = new ParquetMergeOptions
        {
            PreserveFirstFileMetadata = c.NextBool(),
            WriterOptions = s.WriterOptions()
        };
        using var destination = new PlankMergerFuzzTarget.MemoryReadWriteSource();
        ParquetFileMerger merger;
        if (c.NextBool())
        {
            destination.Write(0, files[0]);
            merger = @S@.Schema.CreateMerger(destination, options);
        }
        else
        {
            merger = @S@.Schema.CreateMerger(new MemoryReadSource(files[0]), destination, options);
        }
        for (var f = 1; f < fileCount; f++)
            merger.AppendFile(new MemoryReadSource(files[f]));
        if (merger.SourceFileCount != fileCount || merger.RowCount != all.Count || merger.RowGroupCount != groupCounts.Sum())
            throw new PlankRowApiFuzzTarget.RowApiRoundTripException(
                $"@S@ merger counters {merger.SourceFileCount}/{merger.RowGroupCount}/{merger.RowCount}; expected {fileCount}/{groupCounts.Sum()}/{all.Count}.");
        merger.CloseFile();
        CheckFile(destination.ToArray(), all.ToArray(), s, "@S@ merged");
    }

    static @S@.PipelineWriter CreatePipeline(Stream stream, RowRouteSettings s, ParquetWriterOptions options, Action<int>? onFlush)
        => s.WriterVariant switch
        {
            0 => @S@.CreateRowWriter(stream, options),
            1 => @S@.CreateRowWriter(stream, onFlush, options),
            2 => @S@.CreateRowWriter(stream, s.ExplicitParallelism, options),
            _ => @S@.CreateRowWriter(stream, s.ExplicitParallelism, onFlush, options)
        };

    static void CheckFile(byte[] bytes, @S@[] rows, RowRouteSettings s, string what)
    {
        var count = ReadAll(bytes, rows, 0, s, what);
        if (count != rows.Length)
            throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{what} read back {count} rows; expected {rows.Length}.");
        using var meta = @S@.Schema.CreateReader(new MemoryStream(bytes, writable: false));
        ulong total = 0;
        foreach (var group in meta.RowGroups)
            total += group.RowCount;
        if (total != (ulong)rows.Length)
            throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{what} footer row groups sum to {total} rows; expected {rows.Length}.");
    }

    // Reads the whole file through the generated row reader (optionally projected, via
    // a read source, or on a reader reused across files) and compares every row from
    // rows[offset..] with the projected columns. Returns the rows read.
    static int ReadAll(byte[] bytes, @S@[] rows, int offset, RowRouteSettings s, string what)
    {
        var mask = s.ProjectionMask(@S@Ops.ColumnCount);
        var projection = s.ProjectionMode == 0 ? default : @S@Ops.Project(mask);
        var readerOptions = s.ReaderOptions();
        var index = 0;
        using var reader = Open(bytes, projection, readerOptions, s.ReadViaSource);
        var pass = 0;
        while (true)
        {
            while (reader.MoveNext())
            {
                if (offset + index >= rows.Length)
                    throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{what} returned an extra row {index}.");
                var diff = @S@Ops.Compare(reader.Current, rows[offset + index], mask);
                if (diff is not null)
                    throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{what} lost '{diff}' at row {offset + index} (mask {mask:x}).");
                index++;
            }
            if (!s.ReuseReader || pass++ > 0)
                break;
            // The same reader object re-opened on the same bytes must read the same rows.
            var first = index;
            if (s.ReadViaSource)
                reader.Reset(new MemoryReadSource(bytes), projection);
            else
                reader.Reset(new MemoryStream(bytes, writable: false), projection);
            var again = 0;
            while (reader.MoveNext())
            {
                if (offset + again >= rows.Length)
                    throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{what} reset reader returned an extra row {again}.");
                var diff = @S@Ops.Compare(reader.Current, rows[offset + again], mask);
                if (diff is not null)
                    throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{what} reset reader lost '{diff}' at row {offset + again}.");
                again++;
            }
            if (again != first)
                throw new PlankRowApiFuzzTarget.RowApiRoundTripException($"{what} reset reader returned {again} rows; first pass {first}.");
            break;
        }
        return index;
    }

    static @S@.RowReader Open(byte[] bytes, @S@.Projection projection, Plank.RowApi.RowReaderOptions options, bool viaSource)
        => viaSource
            ? @S@.CreateRowReader(new MemoryReadSource(bytes), projection, options)
            : @S@.CreateRowReader(new MemoryStream(bytes, writable: false), projection, options);
}
"""

print("""// <auto-generated by fuzz/tools/gen_row_wide.py; do not edit by hand. -->
#nullable enable
using Plank.Dataset;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

/// <summary>An int-backed value converted by a custom <see cref="ParquetValueConverter{TValue, TPhysical}"/>.</summary>
public readonly record struct RowFuzzId(int Value);

/// <summary>Maps <see cref="RowFuzzId"/> onto INT32 with a non-trivial transform, so identity bugs show.</summary>
public sealed class RowFuzzIdConverter : ParquetValueConverter<RowFuzzId, int>
{
    public override int ConvertToPhysical(RowFuzzId value) => value.Value ^ 0x5A5A5A5A;

    public override RowFuzzId ConvertFromPhysical(int value) => new(value ^ 0x5A5A5A5A);
}
""")
for n, nl in (("RowFuzzWide", False), ("RowFuzzWideNullable", True)):
    print(emit_class(n, nl))
    print(ROUTES.replace("@S@", n).replace("@APPENDLATEST@", 'Environment.GetEnvironmentVariable("PLANK_FUZZ_APPEND_LATEST_CONVERTER") == "1"'))
# A converter-free nullable copy, for the dataset appends that re-read the latest row group.
print(emit_class("RowFuzzFlatNullable", True, NO_CONVERTER))
print(ROUTES.replace("@S@", "RowFuzzFlatNullable").replace("@APPENDLATEST@", "true"))
# RowFuzzDeep is hand-written (RowFuzzDeep.cs); only its routes are generated.
# Appending to the latest row group is documented as unsupported for repeated columns (NotSupportedException).
print(ROUTES.replace("@S@", "RowFuzzDeep").replace("@APPENDLATEST@", "false"))
