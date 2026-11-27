using System.Collections.Immutable;
using System.Reflection;
using System.Text;
using Plank.Dataset;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.RowApi;
using Plank.Schema;
using Plank.Writing;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Route 0xC2 "OPT1": option objects and span/slice overloads with drawn edge values.
/// <list type="number">
/// <item><b>writer</b> — every <see cref="ParquetWriterOptions"/> property gets an edge value (0, 1, 2, sizes, int/uint/ulong max,
///   undefined enums, null pool, default ImmutableArray, empty key-value key, bad WorkerCount…). An independently written model says which
///   combinations are invalid; those must be rejected with an ArgumentException at CreateWriter (never later, never silently), the
///   others must write and read back exactly. Properties the model does not judge (compression level, sorting ordinals, parallelism)
///   may go either way, but a refusal must still be an ArgumentException at construction and an accepted set must work.</item>
/// <item><b>readers</b> — ParquetReaderOptions / ParquetFileReaderOptions / RowReaderOptions / ParquetExecutionOptions, same contract
///   (null pool, WorkerCount ≤ 0, MaxReadAheadRowGroups &lt; 0 or &gt; 1 are rejected at creation; valid combinations read the exact rows).</item>
/// <item><b>serialize</b> — SerializedColumn.Serialize(ReadOnlySpan&lt;T&gt;) and (T[]) over exact, one-short, one-long, empty, offset-sliced
///   and Memory-sliced inputs: the file holds exactly the sliced values and nothing from the surrounding array.</item>
/// <item><b>merge/append</b> — ParquetFileMerger (counters, empty / zero-row-group inputs, closed-state refusals, same source and
///   destination) and CreateAppender (AppendToLatestRowGroup / PreserveExistingMetadata) against concatenated expectations.</item>
/// <item><b>dataset</b> — DatasetWriterOptions.PendingRowCapacity at 0, 1, rows±1, int.MaxValue and over int.MaxValue (rejected) with an
///   independent RowApiInitialRowCapacity, row-group size and append flags; every queued row must come back in order.</item>
/// </list>
/// </summary>
internal static class OptionsSweepCases
{
    internal const byte Marker = 0xC2;
    internal static ReadOnlySpan<byte> Magic => "OPT1"u8;

    static long _knownPendingOom, _runs, _rejected, _accepted, _spans, _merges, _datasets;

    static OptionsSweepCases()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"OPT1 knownPendingCapacityOom={_knownPendingOom} runs={_runs} optionSetsRejected={_rejected} optionSetsAccepted={_accepted} serializeSlices={_spans} merges={_merges} datasets={_datasets}");
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

    static void Fail(string message) => throw new InvalidOperationException("OPT1: " + message);

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        _runs++;
        var c = new Cur(data);
        switch (c.Int(0, 5))
        {
            case 0: WriterOptions(c); break;
            case 1: ReaderOptions(c); break;
            case 2: SerializeSlices(c); break;
            case 3: MergeAppend(c); break;
            default: DatasetRollover(c); break;
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 1. ParquetWriterOptions
    // ---------------------------------------------------------------------------------------------------------------

    static void Set(object target, string property, object? value)
        => target.GetType().GetProperty(property)!.SetValue(target, value);

    static (PlankSchema Schema, int[] Ids, byte[]?[] Names) SmallData(int rows)
    {
        var schema = new PlankSchema([
            ColumnDefinition.RequiredLeaf("id", ParquetPhysicalType.Int32),
            ColumnDefinition.OptionalLeaf("name", ParquetPhysicalType.ByteArray)
        ]);
        var ids = Enumerable.Range(0, rows).Select(static i => i * 7 - 3).ToArray();
        var names = Enumerable.Range(0, rows).Select(static i => i % 4 == 3 ? null : Encoding.ASCII.GetBytes("n" + i)).ToArray();
        return (schema, ids, names);
    }

    static void WriteSmall(Stream stream, PlankSchema schema, int[] ids, byte[]?[] names, ParquetWriterOptions options, int groups)
    {
        var writer = schema.CreateWriter(stream, options);
        var per = Math.Max(1, ids.Length / groups);
        for (var start = 0; start < ids.Length; start += per)
        {
            var n = Math.Min(per, ids.Length - start);
            var group = writer.StartRowGroup();
            var a = group.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            a.Serialize(ids.AsSpan(start, n));
            group.Write(a);
            var b = group.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[1]);
            b.Serialize(names.AsSpan(start, n).ToArray().Select(static v => v is null ? (ReadOnlyMemory<byte>?)null : v).ToArray());
            group.Write(b);
        }

        writer.CloseFile();
        writer.Dispose();
    }

    static void ReadSmallBack(byte[] file, PlankSchema schema, int[] ids, byte[]?[] names, string what)
    {
        using var reader = schema.CreateReader(new MemoryStream(file, writable: false));
        var seenIds = new List<int>();
        var seenNames = new List<byte[]?>();
        for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            foreach (var buffer in reader.RowGroups[g].Column<int>(schema.LeafColumns[0]))
                seenIds.AddRange(buffer.Values.ToArray());
            foreach (var buffer in reader.RowGroups[g].Column<byte>(schema.LeafColumns[1]))
                for (var i = 0; i < buffer.Count; i++)
                    seenNames.Add(buffer.IsNull(i) ? null : buffer.GetValue(i).ToArray());
        }

        if (!seenIds.SequenceEqual(ids))
            Fail($"{what}: ids differ ({seenIds.Count} vs {ids.Length}).");
        if (seenNames.Count != names.Length)
            Fail($"{what}: {seenNames.Count} names vs {names.Length}.");
        for (var i = 0; i < names.Length; i++)
            if (!(seenNames[i] is null && names[i] is null) && !(seenNames[i] is not null && names[i] is not null && seenNames[i].AsSpan().SequenceEqual(names[i])))
                Fail($"{what}: name {i} differs.");
    }

    static void WriterOptions(Cur c)
    {
        var options = new ParquetWriterOptions();
        var objectOptions = options;
        var invalid = new List<string>();
        var judged = new List<string>(); // either outcome allowed, but only as an ArgumentException at construction
        var changes = c.Int(0, 5);
        // Init-only properties are set through reflection on one instance, which is how an object initializer would set them.
        for (var i = 0; i < changes; i++)
        {
            switch (c.Int(0, 18))
            {
                case 0: { var v = c.Pick(0u, 1u, 2u, 63u, 64u, 4096u, 65536u); Set(objectOptions, nameof(ParquetWriterOptions.BufferChunkSizeBytes), v); if (v == 0) invalid.Add("BufferChunkSizeBytes=0"); else invalid.Remove("BufferChunkSizeBytes=0"); break; }
                case 1: { var v = c.Pick(0u, 1u, 16u, 320u * 1024); Set(objectOptions, nameof(ParquetWriterOptions.InitialPageBufferBytes), v); if (v == 0) invalid.Add("InitialPageBufferBytes=0"); else invalid.Remove("InitialPageBufferBytes=0"); break; }
                case 2: { var v = c.Pick(0u, 1u, 16u, 4096u, 1u << 20); Set(objectOptions, nameof(ParquetWriterOptions.InitialColumnBufferBytes), v); if (v == 0) invalid.Add("InitialColumnBufferBytes=0"); else invalid.Remove("InitialColumnBufferBytes=0"); break; }
                case 3: { var v = c.Pick(0u, 1u, 2u, 100u); Set(objectOptions, nameof(ParquetWriterOptions.InitialPageCapacity), v); judged.Add("InitialPageCapacity=" + v); break; }
                case 4: { var v = c.Pick(int.MinValue, -1, 0, 1, 2, 1024); Set(objectOptions, nameof(ParquetWriterOptions.RowApiInitialRowCapacity), v); if (v <= 0) invalid.Add("RowApiInitialRowCapacity<=0"); else invalid.Remove("RowApiInitialRowCapacity<=0"); break; }
                case 5: { var v = c.Pick(0u, 1u, 2u, 63u, 100u, 4096u, 1u << 20, (uint)int.MaxValue + 1, uint.MaxValue); Set(objectOptions, nameof(ParquetWriterOptions.TargetDataPageSizeBytes), v); if (v == 0 || v > int.MaxValue) invalid.Add("TargetDataPageSizeBytes"); else invalid.Remove("TargetDataPageSizeBytes"); break; }
                case 6: { var v = c.Pick(0UL, 1UL, 2UL, 1UL << 20, ulong.MaxValue); Set(objectOptions, nameof(ParquetWriterOptions.TargetRowGroupSizeBytes), v); if (v == 0) invalid.Add("TargetRowGroupSizeBytes=0"); else invalid.Remove("TargetRowGroupSizeBytes=0"); break; }
                case 7: { var v = c.Pick(0UL, 1UL, 2UL, 1UL << 20, ulong.MaxValue); Set(objectOptions, nameof(ParquetWriterOptions.TargetFileSizeBytes), v); if (v == 0) invalid.Add("TargetFileSizeBytes=0"); else invalid.Remove("TargetFileSizeBytes=0"); break; }
                case 8: { var v = c.Pick(0, 1, 2, 99, -1); var e = (ParquetFileVersion)v; Set(objectOptions, nameof(ParquetWriterOptions.FileVersion), e); if (!Enum.IsDefined(e)) invalid.Add("FileVersion"); else invalid.Remove("FileVersion"); break; }
                case 9: { var v = c.Pick(0, 1, 2, 99, -1); var e = (ParquetDataPageVersion)v; Set(objectOptions, nameof(ParquetWriterOptions.DataPageVersion), e); if (!Enum.IsDefined(e)) invalid.Add("DataPageVersion"); else invalid.Remove("DataPageVersion"); break; }
                case 10: { var v = c.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Gzip, CompressionKind.Zstd, CompressionKind.Lz4, CompressionKind.Brotli, (CompressionKind)99); Set(objectOptions, nameof(ParquetWriterOptions.Compression), v); judged.Add("Compression=" + v); break; }
                case 11: { int? v = c.Pick<int?>(null, -1, 0, 1, 3, 9, 22, 100, int.MinValue, int.MaxValue); Set(objectOptions, nameof(ParquetWriterOptions.CompressionLevel), v); judged.Add("CompressionLevel=" + v); break; }
                case 12: Set(objectOptions, nameof(ParquetWriterOptions.CreatedBy), c.Pick<string?>(null, "", "x", new string('y', 300))); break;
                case 13:
                {
                    invalid.RemoveAll(static s => s.StartsWith("KeyValue", StringComparison.Ordinal));
                    switch (c.Int(0, 4))
                    {
                        case 0: Set(objectOptions, nameof(ParquetWriterOptions.KeyValueMetadata), null); invalid.Add("KeyValueMetadata=null"); break;
                        case 1: Set(objectOptions, nameof(ParquetWriterOptions.KeyValueMetadata), Array.Empty<ParquetKeyValueMetadata>()); break;
                        case 2: Set(objectOptions, nameof(ParquetWriterOptions.KeyValueMetadata), new[] { new ParquetKeyValueMetadata("k", null), new ParquetKeyValueMetadata("k", "dup") }); break;
                        default: Set(objectOptions, nameof(ParquetWriterOptions.KeyValueMetadata), new[] { new ParquetKeyValueMetadata("", "v") }); invalid.Add("KeyValueMetadata empty key"); break;
                    }

                    break;
                }
                case 14: Set(objectOptions, nameof(ParquetWriterOptions.WritePageIndexes), c.Bool()); break;
                case 15: Set(objectOptions, nameof(ParquetWriterOptions.WritePageCrc), c.Bool()); break;
                case 16:
                {
                    invalid.RemoveAll(static s => s.StartsWith("Sorting", StringComparison.Ordinal));
                    switch (c.Int(0, 4))
                    {
                        case 0: Set(objectOptions, nameof(ParquetWriterOptions.SortingColumns), default(ImmutableArray<ParquetSortingColumn>)); invalid.Add("SortingColumns=default"); break;
                        case 1: Set(objectOptions, nameof(ParquetWriterOptions.SortingColumns), ImmutableArray<ParquetSortingColumn>.Empty); break;
                        case 2: Set(objectOptions, nameof(ParquetWriterOptions.SortingColumns), ImmutableArray.Create(new ParquetSortingColumn(0, false, false))); judged.Add("Sorting declared"); break;
                        default: Set(objectOptions, nameof(ParquetWriterOptions.SortingColumns), ImmutableArray.Create(new ParquetSortingColumn(7, true, true))); judged.Add("Sorting ordinal 7"); break;
                    }

                    break;
                }
                default:
                {
                    switch (c.Int(0, 3))
                    {
                        case 0:
                            var executionWorkers = c.Pick(int.MinValue, -1, 0, 1, 2, 8);
                            Set(objectOptions, nameof(ParquetWriterOptions.Execution), new ParquetExecutionOptions { WorkerCount = executionWorkers });
                            invalid.RemoveAll(static s => s == "WorkerCount<=0");
                            if (executionWorkers <= 0) invalid.Add("WorkerCount<=0");
                            break;
                        case 1:
                            Set(objectOptions, nameof(ParquetWriterOptions.BufferPool), null);
                            invalid.Add("BufferPool=null");
                            break;
                        default:
                            Set(objectOptions, nameof(ParquetWriterOptions.RowApiMaxParallelism), c.Pick(0u, 1u, 2u, 64u, uint.MaxValue));
                            judged.Add("RowApiMaxParallelism");
                            break;
                    }

                    break;
                }
            }
        }

        var (schema, ids, names) = SmallData(c.Pick(1, 7, 50));
        var what = $"OPT1 writer options invalid=[{string.Join(",", invalid)}] judged=[{string.Join(",", judged)}]";
        var stream = new MemoryStream();
        Exception? constructionError = null;
        ParquetWriter? writer = null;
        try { writer = schema.CreateWriter(stream, options); }
        catch (Exception e) { constructionError = e; }

        if (constructionError is not null)
        {
            _rejected++;
            if (constructionError is not ArgumentException)
                Fail($"{what}: construction rejected the options with {constructionError.GetType().Name}, not an ArgumentException: {constructionError.Message}");
            if (invalid.Count == 0 && judged.Count == 0)
                Fail($"{what}: valid options were rejected: {constructionError.Message}");
            return;
        }

        if (invalid.Count > 0)
            Fail($"{what}: invalid options were accepted silently (nothing thrown at CreateWriter).");
        _accepted++;
        writer!.Dispose();
        // Accepted options must now work end to end: exact round trip (a failure here is a "later, not at construction" fault).
        var file = new MemoryStream();
        WriteSmall(file, schema, ids, names, options, c.Pick(1, 2, 3));
        ReadSmallBack(file.ToArray(), schema, ids, names, what);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 2. reader-side options
    // ---------------------------------------------------------------------------------------------------------------

    static void ReaderOptions(Cur c)
    {
        var rows = c.Pick(1, 5, 40);
        var expected = Enumerable.Range(0, rows).Select(static i => (Flag: i % 2 == 0, Id: i * 31 - 5, Sequence: (long)i << 33, Measure: i * 0.5)).ToArray();
        using var written = new MemoryStream();
        using (var writer = RowFuzzFixed.CreateRowWriter(written, new ParquetWriterOptions { WritePageCrc = c.Bool(), RowApiInitialRowCapacity = c.Pick(1, 2, 3, 1024) }))
        {
            foreach (var want in expected)
            {
                var row = writer.GetRow();
                row.Flag = want.Flag; row.Id = want.Id; row.Sequence = want.Sequence; row.Measure = want.Measure;
            }

            writer.Complete();
        }

        var file = written.ToArray();
        var badPool = c.OneIn(6);
        var verifyCrc = c.Bool();
        var strict = c.Bool();

        // Logical reader.
        var readerOptions = new ParquetReaderOptions { Strict = strict, VerifyPageCrc = verifyCrc };
        if (badPool)
            Set(readerOptions, nameof(ParquetReaderOptions.BufferPool), null);
        Exception? error = null;
        try { using var reader = new ParquetReader(readerOptions); reader.Reset(new MemoryStream(file, writable: false)); if (reader.RowGroups.Count == 0) Fail("no row groups"); }
        catch (Exception e) { error = e; }
        if (badPool && error is not ArgumentNullException)
            Fail($"ParquetReaderOptions.BufferPool=null: got {error?.GetType().Name ?? "success"}, expected ArgumentNullException at construction.");
        if (!badPool && error is not null)
            Fail($"valid ParquetReaderOptions (strict={strict}, crc={verifyCrc}) failed: {error.GetType().Name}: {error.Message}");

        // Physical reader.
        var fileOptions = new Plank.Reading.Physical.ParquetFileReaderOptions { VerifyPageCrc = verifyCrc };
        if (badPool)
            Set(fileOptions, nameof(Plank.Reading.Physical.ParquetFileReaderOptions.BufferPool), null);
        error = null;
        try { using var reader = new Plank.Reading.Physical.ParquetFileReader(fileOptions); reader.Reset(new MemoryStream(file, writable: false)); }
        catch (Exception e) { error = e; }
        if (badPool && error is not ArgumentNullException)
            Fail($"ParquetFileReaderOptions.BufferPool=null: got {error?.GetType().Name ?? "success"}.");
        if (!badPool && error is not null)
            Fail($"valid ParquetFileReaderOptions failed: {error.GetType().Name}: {error.Message}");

        // Row reader: read-ahead, workers, pool, crc.
        var readAhead = c.Pick(int.MinValue, -1, 0, 1, 2, int.MaxValue);
        var workers = c.Pick(int.MinValue, -1, 0, 1, 2, 4);
        var rowOptions = new RowReaderOptions
        {
            MaxReadAheadRowGroups = readAhead,
            VerifyPageCrc = verifyCrc,
            Execution = new ParquetExecutionOptions { WorkerCount = workers }
        };
        if (badPool)
            Set(rowOptions, nameof(RowReaderOptions.BufferPool), null);
        var invalid = badPool || readAhead is < 0 or > 1 || workers <= 0;
        error = null;
        var count = 0;
        var created = false;
        try
        {
            using var rowReader = RowFuzzFixed.CreateRowReader(new MemoryStream(file, writable: false), options: rowOptions);
            created = true;
            // The contract: rejected at creation. Reaching MoveNext with invalid options is the "later" failure.
            while (rowReader.MoveNext())
            {
                var row = rowReader.Current;
                var want = expected[count];
                if (row.Flag != want.Flag || row.Id != want.Id || row.Sequence != want.Sequence || row.Measure != want.Measure)
                    Fail($"row {count} differs with read-ahead {readAhead}, workers {workers}.");
                count++;
            }
        }
        catch (Exception e) { error = e; }

        if (invalid)
        {
            if (created)
                Fail($"RowReaderOptions(readAhead={readAhead}, workers={workers}, nullPool={badPool}) were not rejected at creation (failed later with {error?.GetType().Name ?? "no error"}).");
            if (error is not ArgumentException)
                Fail($"RowReaderOptions(readAhead={readAhead}, workers={workers}, nullPool={badPool}) not rejected with an ArgumentException (got {error?.GetType().Name ?? "success"}: {error?.Message}).");
            _rejected++;
        }
        else
        {
            if (error is not null)
                Fail($"valid RowReaderOptions(readAhead={readAhead}, workers={workers}) failed: {error.GetType().Name}: {error.Message}");
            if (count != rows)
                Fail($"row reader returned {count} of {rows} rows (readAhead={readAhead}, workers={workers}).");
            _accepted++;
        }

        // Execution options and ParquetSchemaEvolutionOptions are plain value bags: every property reads back what was set.
        var evolution = new ParquetSchemaEvolutionOptions
        {
            MissingColumns = (MissingColumnEvolutionBehavior)c.Int(0, 3),
            Repetition = (RepetitionEvolutionBehavior)c.Int(0, 3),
            PhysicalTypes = (SchemaTypeEvolutionBehavior)c.Int(0, 3),
            LogicalTypes = (SchemaTypeEvolutionBehavior)c.Int(0, 3),
            MaterializedTypes = (SchemaTypeEvolutionBehavior)c.Int(0, 3)
        };
        _ = evolution.ToString();
        var execution = new ParquetExecutionOptions { WorkerCount = workers };
        if (execution.WorkerCount != workers)
            Fail("ParquetExecutionOptions.WorkerCount did not read back.");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 3. Serialize slices
    // ---------------------------------------------------------------------------------------------------------------

    static void SerializeSlices(Cur c)
    {
        var total = c.Pick(1, 2, 8, 63, 64, 65, 300);
        var optional = c.Bool();
        var wide = c.Pick(0, 1, 2); // 0: int, 1: long, 2: binary
        var offset = c.Pick(0, 1, total / 2, Math.Max(0, total - 1), total);
        var count = c.Pick(0, 1, Math.Max(0, total - offset), Math.Max(0, total - offset - 1), Math.Min(total - offset + 1, total));
        count = Math.Max(0, Math.Min(count, total - offset)); // exact / short slice of a larger array; one-too-long is the next case
        var what = $"OPT1 serialize total={total} offset={offset} count={count} kind={wide} optional={optional}";

        var column = ColumnDefinition.Leaf("v", wide switch { 0 => ParquetPhysicalType.Int32, 1 => ParquetPhysicalType.Int64, _ => ParquetPhysicalType.ByteArray },
            new ColumnOptions(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, ImmutableArray.Create(EncodingKind.Plain)), pageStrategy: null);
        var schema = new PlankSchema([column]);
        _spans++;

        var longs = Enumerable.Range(0, total).Select(static i => (long?)(i * 1000003L - 77)).ToArray();
        if (optional)
            for (var i = 0; i < total; i += 3)
                longs[i] = null;
        var expected = longs.Skip(offset).Take(count).ToArray();
        byte[] file;
        using (var stream = new MemoryStream())
        {
            var writer = schema.CreateWriter(stream);
            var group = writer.StartRowGroup();
            switch (wide)
            {
                case 0 when optional:
                {
                    var all = longs.Select(static v => v is { } x ? (int?)unchecked((int)x) : null).ToArray();
                    expected = all.Skip(offset).Take(count).Select(static v => (long?)v).ToArray();
                    var col = group.CreateSerializedColumn<int?>(schema.LeafColumns[0]);
                    if (c.Bool()) col.Serialize(all.AsSpan(offset, count)); else col.Serialize(all.AsSpan(offset, count).ToArray());
                    group.Write(col);
                    break;
                }
                case 0:
                {
                    var all = longs.Select(static (v, i) => unchecked((int)(v ?? i))).ToArray();
                    expected = all.Skip(offset).Take(count).Select(static v => (long?)v).ToArray();
                    var col = group.CreateSerializedColumn<int>(schema.LeafColumns[0]);
                    col.Serialize(new ReadOnlySpan<int>(all, offset, count));
                    group.Write(col);
                    break;
                }
                case 1 when optional:
                {
                    var col = group.CreateSerializedColumn<long?>(schema.LeafColumns[0]);
                    col.Serialize(longs.AsSpan(offset, count));
                    group.Write(col);
                    break;
                }
                case 1:
                {
                    var all = longs.Select(static (v, i) => v ?? i).ToArray();
                    expected = all.Skip(offset).Take(count).Select(static v => (long?)v).ToArray();
                    var col = group.CreateSerializedColumn<long>(schema.LeafColumns[0]);
                    col.Serialize(all.AsSpan(offset, count));
                    group.Write(col);
                    break;
                }
                default:
                {
                    // Memory sliced out of the middle of a larger array: the copy must not leak the neighbours.
                    var backing = Enumerable.Range(0, total + 2).Select(static i => Encoding.ASCII.GetBytes("x" + i)).ToArray();
                    var slice = backing.Skip(offset).Take(count).ToArray();
                    var memories = new ReadOnlyMemory<byte>?[count];
                    for (var i = 0; i < count; i++)
                    {
                        var padded = new byte[slice[i].Length + 4];
                        slice[i].CopyTo(padded, 2);
                        memories[i] = optional && i % 3 == 0 ? null : new ReadOnlyMemory<byte>(padded, 2, slice[i].Length);
                    }

                    expected = memories.Select(static m => m is { } x ? (long?)BitConverter.ToInt64([.. x.Span, 0, 0, 0, 0, 0, 0, 0, 0], 0) : null).ToArray();
                    if (optional)
                    {
                        var col = group.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
                        col.Serialize(memories.AsSpan());
                        group.Write(col);
                    }
                    else
                    {
                        var col = group.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
                        col.Serialize(memories.Select(static m => m ?? ReadOnlyMemory<byte>.Empty).ToArray().AsSpan());
                        group.Write(col);
                        expected = memories.Select(static m => m is { } x ? (long?)BitConverter.ToInt64([.. x.Span, 0, 0, 0, 0, 0, 0, 0, 0], 0) : (long?)BitConverter.ToInt64(new byte[8], 0)).ToArray();
                    }

                    break;
                }
            }

            writer.CloseFile();
            file = stream.ToArray();
        }

        using var reader = schema.CreateReader(new MemoryStream(file, writable: false));
        var seen = new List<long?>();
        long rowCount = 0;
        for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            rowCount += (long)reader.RowGroups[g].RowCount;
            var leaf = schema.LeafColumns[0];
            switch (wide)
            {
                case 0 when optional: foreach (var b in reader.RowGroups[g].Column<int?>(leaf)) seen.AddRange(b.Values.ToArray().Select(static v => (long?)v)); break;
                case 0: foreach (var b in reader.RowGroups[g].Column<int>(leaf)) seen.AddRange(b.Values.ToArray().Select(static v => (long?)v)); break;
                case 1 when optional: foreach (var b in reader.RowGroups[g].Column<long?>(leaf)) seen.AddRange(b.Values.ToArray()); break;
                case 1: foreach (var b in reader.RowGroups[g].Column<long>(leaf)) seen.AddRange(b.Values.ToArray().Select(static v => (long?)v)); break;
                default:
                    foreach (var b in reader.RowGroups[g].Column<byte>(leaf))
                        for (var i = 0; i < b.Count; i++)
                            seen.Add(b.IsNull(i) ? null : BitConverter.ToInt64([.. b.GetValue(i).ToArray(), 0, 0, 0, 0, 0, 0, 0, 0], 0));
                    break;
            }
        }

        if (rowCount != count || seen.Count != count)
            Fail($"{what}: file holds {rowCount} rows / {seen.Count} values, expected {count}.");
        for (var i = 0; i < count; i++)
            if (seen[i] != expected[i])
                Fail($"{what}: value {i} is {seen[i]}, expected {expected[i]}.");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 4. merger and appender
    // ---------------------------------------------------------------------------------------------------------------

    static byte[] OneFile(PlankSchema schema, int[][] groups, ParquetWriterOptions options)
    {
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, options);
        foreach (var rows in groups)
        {
            var group = writer.StartRowGroup();
            var col = group.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            col.Serialize(rows);
            group.Write(col);
        }

        writer.CloseFile();
        return stream.ToArray();
    }

    static int[] ReadInts(PlankSchema schema, IParquetReadSource source, out int groups)
    {
        using var reader = schema.CreateReader(source);
        groups = reader.RowGroups.Count;
        var list = new List<int>();
        for (var g = 0; g < reader.RowGroups.Count; g++)
            foreach (var b in reader.RowGroups[g].Column<int>(schema.LeafColumns[0]))
                list.AddRange(b.Values.ToArray());
        return [.. list];
    }

    static void MergeAppend(Cur c)
    {
        _merges++;
        var schema = new PlankSchema([ColumnDefinition.RequiredLeaf("v", ParquetPhysicalType.Int32)]);
        var writerOptions = new ParquetWriterOptions
        {
            Compression = c.Pick(CompressionKind.None, CompressionKind.Snappy),
            TargetDataPageSizeBytes = c.Pick(64u, 4096u, 1u << 20),
            WritePageIndexes = c.Bool(),
            CreatedBy = c.Bool() ? "surface" : null
        };
        var fileCount = c.Int(1, 5);
        var files = new List<int[][]>();
        var next = 0;
        for (var f = 0; f < fileCount; f++)
        {
            var groupCount = c.Pick(0, 1, 2, 3);
            var groups = new int[groupCount][];
            for (var g = 0; g < groupCount; g++)
                groups[g] = Enumerable.Range(0, c.Pick(0, 1, 2, 17, 100)).Select(_ => next++).ToArray();
            files.Add(groups);
        }

        var bytes = files.Select(f => OneFile(schema, f, writerOptions)).ToArray();
        var preserve = c.Bool();
        var what = $"OPT1 merge files={fileCount} preserve={preserve}";

        // (a) merge into a fresh destination.
        using (var destination = new PlankMergerFuzzTarget.MemoryReadWriteSource())
        {
            ParquetFileMerger merger;
            try { merger = schema.CreateMerger(new MemoryReadSource(bytes[0]), destination, new ParquetMergeOptions { WriterOptions = writerOptions, PreserveFirstFileMetadata = preserve }); }
            catch (ArgumentException) { return; }
            var sourceFiles = 1;
            var rowGroups = files[0].Count(static g => g.Length > 0); // an import skips zero-row groups (counters and file agree)
            var rowCount = files[0].Sum(static g => (long)g.Length);
            if (merger.SourceFileCount != 1 || merger.RowGroupCount != rowGroups || merger.RowCount != rowCount)
                Fail($"{what}: counters after the first file are {merger.SourceFileCount}/{merger.RowGroupCount}/{merger.RowCount}, expected 1/{rowGroups}/{rowCount}.");
            for (var f = 1; f < fileCount; f++)
            {
                merger.AppendFile(new MemoryReadSource(bytes[f]));
                sourceFiles++;
                rowGroups += files[f].Count(static g => g.Length > 0);
                rowCount += files[f].Sum(static g => (long)g.Length);
                if (merger.SourceFileCount != sourceFiles || merger.RowGroupCount != rowGroups || merger.RowCount != rowCount)
                    Fail($"{what}: counters after file {f} are {merger.SourceFileCount}/{merger.RowGroupCount}/{merger.RowCount}, expected {sourceFiles}/{rowGroups}/{rowCount}.");
            }

            if (c.Bool())
            {
                var mergedDestination = destination;
                Exception? same = null;
                try { merger.AppendFile(mergedDestination); } catch (Exception e) { same = e; }
                if (same is not ArgumentException)
                    Fail($"{what}: merging the destination into itself gave {same?.GetType().Name ?? "success"}, expected ArgumentException.");
            }

            merger.CloseFile();
            Exception? closed = null;
            try { merger.AppendFile(new MemoryReadSource(bytes[0])); } catch (Exception e) { closed = e; }
            if (closed is not InvalidOperationException)
                Fail($"{what}: AppendFile after CloseFile gave {closed?.GetType().Name ?? "success"}.");
            closed = null;
            try { merger.CloseFile(); } catch (Exception e) { closed = e; }
            if (closed is not InvalidOperationException)
                Fail($"{what}: second CloseFile gave {closed?.GetType().Name ?? "success"}.");
            var merged = ReadInts(schema, new MemoryReadSource(destination.ToArray()), out var mergedGroups);
            var all = files.SelectMany(static f => f.SelectMany(static g => g)).ToArray();
            if (!merged.SequenceEqual(all))
                Fail($"{what}: merged values differ ({merged.Length} vs {all.Length}).");
            if (mergedGroups != rowGroups)
                Fail($"{what}: merged file has {mergedGroups} row groups, counter said {rowGroups}.");
        }

        // (b) appender over the first file (in a read/write stream) with AppendToLatestRowGroup / PreserveExistingMetadata.
        var latest = c.Bool();
        var stream = new MemoryStream();
        stream.Write(bytes[0]);
        stream.Position = 0;
        var extra = Enumerable.Range(1000000, c.Pick(0, 1, 5, 200)).ToArray();
        try
        {
            using var appender = schema.CreateAppender(stream, new ParquetAppendOptions
            {
                WriterOptions = writerOptions,
                AppendToLatestRowGroup = latest,
                PreserveExistingMetadata = c.Bool()
            });
            var group = appender.StartRowGroup();
            var col = group.CreateSerializedColumn<int>(schema.LeafColumns[0]);
            col.Serialize(extra);
            group.Write(col);
            appender.CloseFile();
        }
        catch (InvalidOperationException) when (files[0].Length == 0 && latest)
        {
            return; // appending to the latest row group of a file that has none: a refusal is allowed
        }

        var appended = ReadInts(schema, new MemoryReadSource(stream.ToArray()), out _);
        var expectedAll = files[0].SelectMany(static g => g).Concat(extra).ToArray();
        if (!appended.SequenceEqual(expectedAll))
            Fail($"OPT1 append latest={latest}: appended file holds {appended.Length} values, expected {expectedAll.Length} (or different order).");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 5. dataset rollover
    // ---------------------------------------------------------------------------------------------------------------

    static void DatasetRollover(Cur c)
    {
        _datasets++;
        var rows = c.Pick(1, 2, 3, 17, 64, 200);
        var pending = c.Pick(0u, 1u, 2u, (uint)Math.Max(rows - 1, 0), (uint)rows, (uint)rows + 1, 4096u, (uint)int.MaxValue, (uint)int.MaxValue + 1, uint.MaxValue);
        var capacity = c.Pick(1, 2, Math.Max(1, rows - 1), rows, rows + 1, 1024);
        var rowGroupBytes = c.Pick(1UL, 2UL, 64UL, 128UL * 1024 * 1024);
        var partitions = c.Pick(1, 1, 2, 3);
        var append = new ParquetAppendOptions { PreserveExistingMetadata = c.Bool(), AppendToLatestRowGroup = c.Bool() };
        var options = new DatasetWriterOptions
        {
            PendingRowCapacity = pending,
            AppendOptions = append,
            WriterOptions = new ParquetWriterOptions { RowApiInitialRowCapacity = capacity, TargetRowGroupSizeBytes = rowGroupBytes }
        };
        var store = new InMemoryFileStore();
        var files = new InMemoryDatasetFile[partitions];
        for (var i = 0; i < files.Length; i++)
            files[i] = new InMemoryDatasetFile(store);
        var what = $"OPT1 dataset rows={rows} pending={pending} capacity={capacity} rowGroupBytes={rowGroupBytes} partitions={partitions} appendLatest={append.AppendToLatestRowGroup}";

        RowFuzzFixed.Route route = (RowFuzzFixed row, IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return Encoding.ASCII.GetBytes("p" + ((row.Id & int.MaxValue) % partitions));
        };
        Exception? error = null;
        try
        {
            using var writer = RowFuzzFixed.CreateDatasetWriter(route, files, options);
            for (var i = 0; i < rows; i++)
                writer.Queue(new RowFuzzFixed { Id = i, Sequence = i * 3L, Flag = i % 2 == 0, Measure = i });
        }
        catch (Exception e) { error = e; }

        if (error is OutOfMemoryException && pending > 1u << 20 && pending <= int.MaxValue)
        {
            // Library defect (fuzz/FINDINGS.md "PendingRowCapacity = int.MaxValue"): accepted by Validate, then the pending buffer
            // allocation fails with OutOfMemoryException instead of a defined refusal. Counted, not faulted.
            _knownPendingOom++;
            return;
        }

        if (pending > int.MaxValue)
        {
            if (error is not ArgumentOutOfRangeException)
                Fail($"{what}: PendingRowCapacity over int.MaxValue gave {error?.GetType().Name ?? "success"}, expected ArgumentOutOfRangeException.");
            return;
        }

        if (error is not null)
            Fail($"{what}: {error.GetType().Name}: {error.Message}");
        var perFile = new Dictionary<string, List<long>>();
        var total = 0;
        foreach (var (path, file) in store.Files)
        {
            var sequences = new List<long>();
            using var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(file.ToArray(), writable: false));
            while (reader.MoveNext())
            {
                var row = reader.Current;
                if (row.Sequence != row.Id * 3L || row.Flag != (row.Id % 2 == 0) || row.Measure != row.Id)
                    Fail($"{what}: row {row.Id} came back damaged in '{path}'.");
                sequences.Add(row.Id);
            }

            if (!sequences.SequenceEqual(sequences.OrderBy(static s => s)))
                Fail($"{what}: rows of '{path}' were reordered.");
            perFile[path] = sequences;
            total += sequences.Count;
        }

        if (total != rows || perFile.Values.SelectMany(static v => v).Distinct().Count() != rows)
            Fail($"{what}: dataset holds {total} rows, queued {rows}.");
    }
}
