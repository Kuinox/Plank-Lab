using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Text;
using Plank.Dataset;
using Plank.Reading;
using Plank.Reading.Logical;
using Plank.Reading.Physical;
using Plank.Schema;
using Plank.Writing;
using Plank.Writing.PageStrategy;
using PlankSchema = Plank.Schema.ParquetSchema;

namespace Plank.Fuzzing;

/// <summary>
/// Route 0xC0 "LIF1": lifetimes, concurrency and strategy hooks — the places where a bug corrupts data silently.
/// <list type="number">
/// <item><b>retain</b> — ColumnBuffer.Retain / NestedColumnBuffer.RetainLevels over a pool that poisons every returned payload with
///   0xDD and quarantines it (so a use-after-return reads poison, never plausible data) and counts returns. Buffers are retained
///   while the enumerator advances, is abandoned early (Dispose), the reader is Reset to another file and Disposed, and the pool
///   keeps being used; at the end every retained buffer must still equal its snapshot, DangerousGetAddress must be stable, and after
///   everything is disposed the pool must have every allocation back exactly once.</item>
/// <item><b>threads</b> — 2–4 threads write and read back through writers/readers/dataset writers that share one buffer pool
///   (the default pool or the poisoning pool) and one schema instance, with drawn start jitter; every thread must read back exactly
///   its own rows once. (DatasetWriter itself is not documented as thread-safe, so each thread owns its writer.)</item>
/// <item><b>rollover</b> — row writer with ParquetFilePath rollover under drawn TargetFileSizeBytes, and a merger over 2–5 sources each
///   written with its own compression / page size / CRC / page version, into a destination with yet other options.</item>
/// <item><b>logical</b> — Geometry/Geography CRS strings and edge algorithms, Variant specification versions: either rejected as
///   ArgumentException when the schema is built, or exactly preserved in the logical and physical metadata.</item>
/// <item><b>strategy</b> — a custom IPageStrategy returning edge values (page size 0/1/huge/varying, row counts 0/1/huge/varying,
///   dictionary decisions that change per call): either a defined refusal or a file that reads back exactly, never a hang.</item>
/// </list>
/// </summary>
internal static class LifetimeSurfaceCases
{
    internal const byte Marker = 0xC0;
    internal static ReadOnlySpan<byte> Magic => "LIF1"u8;

    static long _runs, _retained, _threads, _rolled, _merged, _logical, _strategies, _strategyRefusals;

    static LifetimeSurfaceCases()
    {
        if (Environment.GetEnvironmentVariable("PLANK_ORACLE_COUNTERS") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"LIF1 runs={_runs} retainedBuffers={_retained} threadRuns={_threads} rollovers={_rolled} merges={_merged} logical={_logical} strategies={_strategies} strategyRefusals={_strategyRefusals}");
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

    static void Fail(string message) => throw new InvalidOperationException("LIF1: " + message);

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        _runs++;
        var c = new Cur(data);
        switch (c.Int(0, 5))
        {
            case 0: Retain(c); break;
            case 1: Threads(c); break;
            case 2: Rollover(c); break;
            case 3: Logical(c); break;
            default: Strategy(c); break;
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // poisoning pool
    // ---------------------------------------------------------------------------------------------------------------

    internal sealed class PoisonPool : IParquetBufferPool, IDisposable
    {
        const int PayloadOffset = 64;
        const int Guard = 64;
        const byte Canary = 0xCD, Fresh = 0xA5, Dead = 0xDD;
        readonly object _gate = new();
        readonly Dictionary<nint, int> _live = [];
        readonly List<nint> _quarantine = [];
        int _rented, _returned;

        public int Outstanding { get { lock (_gate) return _live.Count; } }
        public int Rented => _rented;

        public ParquetBuffer Rent(uint minimumByteLength)
        {
            if (minimumByteLength == 0)
                return default;
            if (minimumByteLength > 1 << 28)
                throw new ArgumentOutOfRangeException(nameof(minimumByteLength));
            var length = (int)minimumByteLength;
            var total = PayloadOffset + length + Guard;
            var allocation = GuardMemory.AllocHGlobal(total);
            Fill(allocation, 0, PayloadOffset, Canary);
            Fill(allocation, PayloadOffset, length, Fresh);
            Fill(allocation, PayloadOffset + length, Guard, Canary);
            lock (_gate)
            {
                _live[allocation] = length;
                _rented++;
            }

            return ParquetBuffer.Create(allocation, total, PayloadOffset, length, Return);
        }

        void Return(nint allocation)
        {
            lock (_gate)
            {
                if (!_live.Remove(allocation, out var length))
                    throw new InvalidOperationException("PoisonPool: an allocation was returned twice or was never rented.");
                _returned++;
                // Poison the payload and keep the memory: a later read of a returned buffer sees 0xDD, not recycled data.
                Fill(allocation, PayloadOffset, length, Dead);
                for (var i = 0; i < Guard; i++)
                    if (Marshal.ReadByte(allocation, PayloadOffset + length + i) != Canary)
                        throw new InvalidOperationException($"PoisonPool: trailing guard byte {i} of a {length}-byte buffer was overwritten.");
                _quarantine.Add(allocation);
            }
        }

        static void Fill(nint allocation, int offset, int count, byte value)
        {
            if (count <= 0)
                return;
            var bytes = new byte[count];
            Array.Fill(bytes, value);
            Marshal.Copy(bytes, 0, allocation + offset, count);
        }

        public void Dispose()
        {
            lock (_gate)
            {
                foreach (var allocation in _quarantine)
                    GuardMemory.FreeHGlobal(allocation);
                _quarantine.Clear();
                foreach (var allocation in _live.Keys)
                    GuardMemory.FreeHGlobal(allocation);
                _live.Clear();
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 1. retained buffers
    // ---------------------------------------------------------------------------------------------------------------

    sealed record Snapshot(string Name, ParquetBuffer Buffer, byte[] Bytes, nint Address);

    static byte[] RetainFile(Cur c, out int rows)
    {
        rows = c.Pick(1, 7, 100, 700);
        var schema = new PlankSchema([
            ColumnDefinition.RequiredLeaf("a", ParquetPhysicalType.Int64),
            ColumnDefinition.OptionalLeaf("b", ParquetPhysicalType.Int64),
            ColumnDefinition.OptionalLeaf("s", ParquetPhysicalType.ByteArray),
            ColumnDefinition.List("l", ColumnDefinition.OptionalLeaf("e", ParquetPhysicalType.Int32), ParquetRepetition.Optional)
        ]);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream, new ParquetWriterOptions
        {
            TargetDataPageSizeBytes = c.Pick(32u, 128u, 1000u, 1u << 20),
            Compression = c.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Zstd),
            WritePageCrc = c.Bool()
        });
        var groups = c.Pick(1, 2, 3);
        for (var g = 0; g < groups; g++)
        {
            var group = writer.StartRowGroup();
            var a = group.CreateSerializedColumn<long>(schema.LeafColumns[0]);
            a.Serialize(Enumerable.Range(0, rows).Select(i => (long)i * (g + 3)).ToArray());
            group.Write(a);
            var b = group.CreateSerializedColumn<long?>(schema.LeafColumns[1]);
            b.Serialize(Enumerable.Range(0, rows).Select(i => i % 3 == 0 ? null : (long?)(i + g)).ToArray());
            group.Write(b);
            var s = group.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[2]);
            s.Serialize(Enumerable.Range(0, rows).Select(i => i % 4 == 0 ? (ReadOnlyMemory<byte>?)null : Encoding.ASCII.GetBytes("v" + (i % 17) + new string('z', i % 5))).ToArray());
            group.Write(s);
            var l = group.CreateSerializedColumn<int?[]>(schema.LeafColumns[3]);
            l.Serialize(Enumerable.Range(0, rows).Select(i => i % 5 == 0 ? null! : new int?[i % 4].Select((_, k) => k % 2 == 0 ? (int?)(i + k) : null).ToArray()).ToArray());
            group.Write(l);
        }

        writer.CloseFile();
        return stream.ToArray();
    }

    static PlankSchema RetainSchema() => new([
        ColumnDefinition.RequiredLeaf("a", ParquetPhysicalType.Int64),
        ColumnDefinition.OptionalLeaf("b", ParquetPhysicalType.Int64),
        ColumnDefinition.OptionalLeaf("s", ParquetPhysicalType.ByteArray),
        ColumnDefinition.List("l", ColumnDefinition.OptionalLeaf("e", ParquetPhysicalType.Int32), ParquetRepetition.Optional)
    ]);

    static void Retain(Cur c)
    {
        var file = RetainFile(c, out var rows);
        var other = RetainFile(c, out _);
        using var pool = new PoisonPool();
        var snapshots = new List<Snapshot>();
        var order = c.Pick(0, 1, 2);
        var what = $"LIF1 retain rows={rows}";
        var schema = RetainSchema();
        var reader = new ParquetReader(new ParquetReaderOptions { BufferPool = pool, VerifyPageCrc = c.Bool() });
        reader.Reset(new MemoryStream(file, writable: false));
        for (var g = 0; g < reader.RowGroups.Count; g++)
        {
            var group = reader.RowGroups[g];
            for (var column = 0; column < 4; column++)
            {
                var stopAfter = c.OneIn(3) ? c.Int(0, 3) : int.MaxValue; // abandon the enumeration early (enumerator Dispose)
                var seen = 0;
                var leaf = reader.Schema.LeafColumns[column];
                switch (column)
                {
                    case 0:
                        foreach (var buffer in group.Column<long>(leaf))
                        {
                            if (seen++ >= stopAfter) break;
                            Take(snapshots, $"{what} a/{g}/{seen}", buffer.Retain(), MemoryMarshal.AsBytes(buffer.Values).ToArray());
                        }

                        break;
                    case 1:
                        foreach (var buffer in group.Column<long?>(leaf))
                        {
                            if (seen++ >= stopAfter) break;
                            Take(snapshots, $"{what} b/{g}/{seen}", buffer.Retain(), null);
                        }

                        break;
                    case 2:
                        foreach (var buffer in group.Column<byte>(leaf))
                        {
                            if (seen++ >= stopAfter) break;
                            // Variable-length: the retained slice holds the descriptors; the payload they point into must stay alive too.
                            var retained = buffer.Retain();
                            var values = new List<byte[]?>();
                            for (var i = 0; i < buffer.Count; i++)
                                values.Add(buffer.IsNull(i) ? null : buffer.GetValue(i).ToArray());
                            Take(snapshots, $"{what} s/{g}/{seen}", retained, null);
                            _ = values;
                        }

                        break;
                    default:
                        foreach (var buffer in group.NestedColumn<int>(leaf))
                        {
                            if (seen++ >= stopAfter) break;
                            var levels = buffer.RetainLevels();
                            var expectedLevels = new List<int>();
                            expectedLevels.AddRange(buffer.RepetitionLevels.ToArray());
                            expectedLevels.AddRange(buffer.DefinitionLevels.ToArray());
                            if (levels.Length != 0)
                            {
                                var span = levels.AsSpan<int>();
                                var interleaved = new List<int>();
                                for (var i = 0; i < buffer.Count; i++) { interleaved.Add(buffer.RepetitionLevels[i]); interleaved.Add(buffer.DefinitionLevels[i]); }
                                if (!span.SequenceEqual(expectedLevels.ToArray()) && !span.SequenceEqual(interleaved.ToArray()))
                                    Fail($"{what}: RetainLevels of nested buffer {g}/{seen} does not hold the repetition/definition levels.");
                            }

                            Take(snapshots, $"{what} levels/{g}/{seen}", levels, null);
                            Take(snapshots, $"{what} nested values/{g}/{seen}", buffer.Values.Retain(), MemoryMarshal.AsBytes(buffer.Values.Values).ToArray());
                        }

                        break;
                }
            }

            if (c.OneIn(3))
                CheckAll(snapshots, what + " (mid-scan)");
        }

        // Reset to another file while buffers are retained, then dispose the reader: retained data must survive both.
        if (c.Bool())
        {
            reader.Reset(new MemoryStream(other, writable: false));
            for (var g = 0; g < reader.RowGroups.Count; g++)
                foreach (var buffer in reader.RowGroups[g].Column<long>(reader.Schema.LeafColumns[0]))
                    _ = buffer.Values.Length;
        }

        if (order != 0)
            reader.Dispose();
        // Churn the pool: rent and return unrelated buffers.
        for (var i = 0; i < c.Int(0, 8); i++)
        {
            using var scratch = pool.Rent((uint)c.Pick(1, 64, 4096, 100000));
            scratch.Span.Fill(0x11);
        }

        CheckAll(snapshots, what + " (after reset/dispose)");
        if (order == 0)
            reader.Dispose();

        // Disposal order is drawn; nothing may be returned to the pool while a retained buffer is alive.
        var indices = Enumerable.Range(0, snapshots.Count).ToList();
        if (c.Bool()) indices.Reverse();
        foreach (var index in indices)
        {
            var snap = snapshots[index];
            if (pool.Outstanding == 0 && snap.Buffer.Length != 0)
                Fail($"{what}: the pool had every allocation back while '{snap.Name}' was still retained.");
            snap.Buffer.Dispose(); // value-type copies: exactly one release per Retain()
        }

        if (pool.Outstanding != 0)
            Fail($"{what}: {pool.Outstanding} allocations were never returned after the reader and every retained buffer were disposed.");
        _ = schema;
    }

    static void Take(List<Snapshot> list, string name, ParquetBuffer retained, byte[]? expectedBytes)
    {
        _retained++;
        var bytes = retained.Length == 0 ? [] : retained.Span.ToArray();
        if (expectedBytes is not null && !bytes.AsSpan().SequenceEqual(expectedBytes))
            Fail($"{name}: Retain() content differs from the buffer's values at the time of retention.");
        nint address = 0;
        if (retained.Length != 0)
        {
            address = retained.DangerousGetAddress();
            if (address == 0 || address != retained.DangerousGetAddress())
                Fail($"{name}: DangerousGetAddress is zero or not stable.");
        }

        list.Add(new Snapshot(name, retained, bytes, address));
    }

    static void CheckAll(List<Snapshot> snapshots, string when)
    {
        foreach (var snap in snapshots)
        {
            if (snap.Buffer.Length == 0)
                continue;
            if (!snap.Buffer.Span.SequenceEqual(snap.Bytes))
                Fail($"{when}: retained buffer '{snap.Name}' changed (use after return / overwritten pool memory).");
            if (snap.Buffer.DangerousGetAddress() != snap.Address)
                Fail($"{when}: DangerousGetAddress of '{snap.Name}' moved.");
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 2. threads
    // ---------------------------------------------------------------------------------------------------------------

    static void Threads(Cur c)
    {
        var threadCount = c.Int(2, 5);
        var rows = c.Pick(1, 17, 300);
        var usePoison = c.Bool();
        using var poison = new PoisonPool();
        IParquetBufferPool pool = usePoison ? poison : DefaultParquetBufferPool.Shared;
        var kind = c.Int(0, 3);
        var pending = c.Pick(0u, 1u, 5u, 4096u);
        var groupBytes = c.Pick(1UL, 64UL, 128UL * 1024 * 1024);
        var capacity = c.Pick(1, 3, 1024);
        var jitter = Enumerable.Range(0, threadCount).Select(_ => c.Int(0, 200)).ToArray();
        var schema = new PlankSchema([ColumnDefinition.RequiredLeaf("id", ParquetPhysicalType.Int64)]); // shared by every thread
        var errors = new List<Exception>();
        using var barrier = new Barrier(threadCount);
        var workers = new Thread[threadCount];
        _threads++;
        for (var t = 0; t < threadCount; t++)
        {
            var index = t;
            workers[t] = new Thread(() =>
            {
                try
                {
                    barrier.SignalAndWait();
                    for (var spin = 0; spin < jitter[index]; spin++)
                        Thread.SpinWait(20);
                    OneThread(index, kind, rows, pool, schema, pending, groupBytes, capacity);
                }
                catch (Exception e)
                {
                    lock (errors)
                        errors.Add(e);
                }
            });
            workers[t].Start();
        }

        foreach (var worker in workers)
            if (!worker.Join(TimeSpan.FromSeconds(60)))
                Fail($"threads: a worker did not finish within 60 s (kind {kind}, {threadCount} threads) — deadlock.");
        if (errors.Count > 0)
            Fail($"threads kind={kind} threads={threadCount} pool={(usePoison ? "poison" : "default")}: {errors[0].GetType().Name}: {errors[0].Message}");
        if (usePoison)
        {
            // Everything the threads rented must be back (readers/writers all disposed).
            if (poison.Outstanding != 0)
                Fail($"threads: {poison.Outstanding} pool allocations leaked across {threadCount} threads.");
        }
    }

    static void OneThread(int t, int kind, int rows, IParquetBufferPool pool, PlankSchema schema, uint pending, ulong groupBytes, int capacity)
    {
        var baseId = (long)(t + 1) * 1_000_000;
        var expected = Enumerable.Range(0, rows).Select(i => baseId + i).ToArray();
        switch (kind)
        {
            case 0:
            {
                using var stream = new MemoryStream();
                var writer = schema.CreateWriter(stream, new ParquetWriterOptions { BufferPool = pool, TargetDataPageSizeBytes = 64 });
                var group = writer.StartRowGroup();
                var column = group.CreateSerializedColumn<long>(schema.LeafColumns[0]);
                column.Serialize(expected);
                group.Write(column);
                writer.CloseFile();
                writer.Dispose();
                using var reader = schema.CreateReader(new MemoryStream(stream.ToArray(), writable: false), new ParquetReaderOptions { BufferPool = pool });
                var read = new List<long>();
                foreach (var buffer in reader.RowGroups[0].Column<long>(schema.LeafColumns[0]))
                    read.AddRange(buffer.Values.ToArray());
                if (!read.SequenceEqual(expected))
                    throw new InvalidOperationException($"thread {t}: plain round trip returned other rows ({read.Count} vs {rows}).");
                break;
            }
            case 1:
            {
                using var stream = new MemoryStream();
                using (var writer = RowFuzzFixed.CreateRowWriter(stream, new ParquetWriterOptions { BufferPool = pool, RowApiInitialRowCapacity = capacity }))
                {
                    foreach (var id in expected)
                    {
                        var row = writer.GetRow();
                        row.Id = (int)(id & 0x7FFFFFFF); row.Sequence = id; row.Flag = true; row.Measure = id;
                    }

                    writer.Complete();
                }

                using var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(stream.ToArray(), writable: false), options: new Plank.RowApi.RowReaderOptions { BufferPool = pool });
                var index = 0;
                while (reader.MoveNext())
                {
                    if (reader.Current.Sequence != expected[index])
                        throw new InvalidOperationException($"thread {t}: row API row {index} is {reader.Current.Sequence}, expected {expected[index]}.");
                    index++;
                }

                if (index != rows)
                    throw new InvalidOperationException($"thread {t}: row API returned {index} of {rows} rows.");
                break;
            }
            default:
            {
                var store = new InMemoryFileStore();
                var file = new InMemoryDatasetFile(store);
                RowFuzzFixed.Route route = (RowFuzzFixed row, IParquetBufferPool p, out ParquetBuffer? allocation) =>
                {
                    allocation = null;
                    return "p"u8;
                };
                using (var writer = RowFuzzFixed.CreateDatasetWriter(route, [file], new DatasetWriterOptions
                {
                    PendingRowCapacity = pending,
                    WriterOptions = new ParquetWriterOptions { BufferPool = pool, RowApiInitialRowCapacity = capacity, TargetRowGroupSizeBytes = groupBytes }
                }))
                    foreach (var id in expected)
                        writer.Queue(new RowFuzzFixed { Id = (int)(id & 0x7FFFFFFF), Sequence = id, Flag = true, Measure = id });
                var total = 0;
                foreach (var (_, bytes) in store.Files)
                {
                    using var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(bytes.ToArray(), writable: false), options: new Plank.RowApi.RowReaderOptions { BufferPool = pool });
                    while (reader.MoveNext())
                    {
                        if (reader.Current.Sequence != expected[total])
                            throw new InvalidOperationException($"thread {t}: dataset row {total} is {reader.Current.Sequence}, expected {expected[total]}.");
                        total++;
                    }
                }

                if (total != rows)
                    throw new InvalidOperationException($"thread {t}: dataset returned {total} of {rows} rows.");
                break;
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 3. rollover and multi-source merge
    // ---------------------------------------------------------------------------------------------------------------

    static void Rollover(Cur c)
    {
        var rows = c.Pick(1, 5, 40, 300);
        var fileBytes = c.Pick(1UL, 2UL, 64UL, 500UL, 4000UL, 512UL * 1024 * 1024);
        var groupBytes = c.Pick(1UL, 64UL, 128UL * 1024 * 1024);
        var store = new InMemoryFileStore();
        var file = new InMemoryDatasetFile(store);
        ParquetFilePath select = (ulong index, IParquetBufferPool pool, out ParquetBuffer? allocation) =>
        {
            allocation = null;
            return Encoding.ASCII.GetBytes($"part-{index:D6}.parquet");
        };
        var written = new List<long>();
        using (var writer = RowFuzzFixed.CreateRowWriter(select, file, new ParquetWriterOptions
        {
            TargetFileSizeBytes = fileBytes,
            TargetRowGroupSizeBytes = groupBytes,
            RowApiInitialRowCapacity = c.Pick(1, 2, 1024)
        }))
        {
            for (var i = 0; i < rows; i++)
            {
                var row = writer.GetRow();
                row.Id = i; row.Sequence = i * 11L; row.Flag = i % 2 == 0; row.Measure = i;
                written.Add(i * 11L);
            }

            writer.Complete();
        }

        _rolled++;
        var read = new List<long>();
        foreach (var (path, bytes) in store.Files.OrderBy(static f => f.Key, StringComparer.Ordinal))
        {
            var before = read.Count;
            using var reader = RowFuzzFixed.CreateRowReader(new MemoryStream(bytes.ToArray(), writable: false));
            while (reader.MoveNext())
                read.Add(reader.Current.Sequence);
            if (read.Count == before && rows > 0 && store.Files.Count > 1)
                Fail($"rollover (fileBytes={fileBytes}): '{path}' is an empty part among {store.Files.Count}.");
        }

        if (!read.SequenceEqual(written))
            Fail($"rollover rows={rows} fileBytes={fileBytes} groupBytes={groupBytes}: read {read.Count} rows in {store.Files.Count} files, order/values differ from the {written.Count} written.");

        // Multi-source merge with per-file options.
        var schema = new PlankSchema([ColumnDefinition.RequiredLeaf("v", ParquetPhysicalType.Int32)]);
        var sources = c.Int(2, 6);
        var all = new List<int>();
        var files = new List<byte[]>();
        var next = 0;
        for (var f = 0; f < sources; f++)
        {
            var options = new ParquetWriterOptions
            {
                Compression = c.Pick(CompressionKind.None, CompressionKind.Snappy, CompressionKind.Gzip, CompressionKind.Zstd, CompressionKind.Lz4),
                TargetDataPageSizeBytes = c.Pick(32u, 500u, 1u << 20),
                WritePageCrc = c.Bool(),
                WritePageIndexes = c.Bool(),
                DataPageVersion = c.Bool() ? ParquetDataPageVersion.V1 : ParquetDataPageVersion.V2
            };
            var groups = new List<int[]>();
            for (var g = 0; g < c.Int(1, 4); g++)
            {
                var values = Enumerable.Range(0, c.Pick(1, 3, 50)).Select(_ => next++).ToArray();
                groups.Add(values);
                all.AddRange(values);
            }

            using var stream = new MemoryStream();
            var writer = schema.CreateWriter(stream, options);
            foreach (var values in groups)
            {
                var group = writer.StartRowGroup();
                var column = group.CreateSerializedColumn<int>(schema.LeafColumns[0]);
                column.Serialize(values);
                group.Write(column);
            }

            writer.CloseFile();
            files.Add(stream.ToArray());
        }

        using var destination = new PlankMergerFuzzTarget.MemoryReadWriteSource();
        var merger = schema.CreateMerger(new MemoryReadSource(files[0]), destination, new ParquetMergeOptions
        {
            PreserveFirstFileMetadata = c.Bool(),
            WriterOptions = new ParquetWriterOptions { Compression = c.Pick(CompressionKind.None, CompressionKind.Zstd), WritePageCrc = c.Bool(), TargetDataPageSizeBytes = c.Pick(64u, 1u << 20) }
        });
        for (var f = 1; f < sources; f++)
            merger.AppendFile(new MemoryReadSource(files[f]));
        merger.CloseFile();
        _merged++;
        using var mergedReader = schema.CreateReader(new MemoryReadSource(destination.ToArray()));
        var merged = new List<int>();
        for (var g = 0; g < mergedReader.RowGroups.Count; g++)
            foreach (var buffer in mergedReader.RowGroups[g].Column<int>(schema.LeafColumns[0]))
                merged.AddRange(buffer.Values.ToArray());
        if (!merged.SequenceEqual(all))
            Fail($"merge of {sources} sources: {merged.Count} values read back, expected {all.Count} (or order differs).");
        if (merger.SourceFileCount != sources || merger.RowCount != all.Count)
            Fail($"merge counters {merger.SourceFileCount}/{merger.RowCount}, expected {sources}/{all.Count}.");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 4. logical-type metadata
    // ---------------------------------------------------------------------------------------------------------------

    static void Logical(Cur c)
    {
        _logical++;
        var kind = c.Int(0, 3);
        var crs = c.Pick<string?>(null, "", "OGC:CRS84", "EPSG:4326", new string('c', 300), "ключ-координат", "a\0b", "projjson:{\"id\":1}");
        LogicalType logical;
        switch (kind)
        {
            case 0: logical = new LogicalType.Geometry(crs); break;
            case 1: logical = new LogicalType.Geography(crs, c.Pick<EdgeInterpolationAlgorithm?>(null, (EdgeInterpolationAlgorithm)0, (EdgeInterpolationAlgorithm)1, (EdgeInterpolationAlgorithm)2, (EdgeInterpolationAlgorithm)3, (EdgeInterpolationAlgorithm)4, (EdgeInterpolationAlgorithm)99)); break;
            default: logical = new LogicalType.Variant(c.Pick<sbyte?>(null, 0, 1, 2, -1, sbyte.MaxValue)); break;
        }

        PlankSchema schema;
        try
        {
            schema = kind == 2
                ? new PlankSchema([ColumnDefinition.RequiredGroup("v", logical,
                    ColumnDefinition.RequiredLeaf("metadata", ParquetPhysicalType.ByteArray), ColumnDefinition.RequiredLeaf("value", ParquetPhysicalType.ByteArray))])
                : new PlankSchema([ColumnDefinition.RequiredLeaf("g", ParquetPhysicalType.ByteArray, logicalType: logical)]);
        }
        catch (ArgumentException)
        {
            return; // a refusal while the schema is built is the documented place
        }

        var rows = c.Pick(1, 4);
        using var stream = new MemoryStream();
        var writer = schema.CreateWriter(stream);
        var group = writer.StartRowGroup();
        for (var col = 0; col < schema.LeafColumns.Length; col++)
        {
            var sc = group.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[col]);
            sc.Serialize(Enumerable.Range(0, rows).Select(i => (ReadOnlyMemory<byte>)new byte[] { 1, (byte)i, (byte)col }).ToArray());
            group.Write(sc);
        }

        writer.CloseFile();
        var bytes = stream.ToArray();
        using var reader = schema.CreateReader(new MemoryStream(bytes, writable: false));
        var definition = reader.Schema.Definitions[0];
        if (!Equals(definition.LogicalType, logical))
            Fail($"logical type {logical} was read back as {definition.LogicalType}.");
        using var physical = new ParquetFileReader();
        physical.Reset(new MemoryStream(bytes, writable: false));
        var info = physical.Metadata.SchemaNodes[1].LogicalType; // node 0 is the schema root
        if (logical is LogicalType.Variant variant && info.SpecificationVersion != variant.SpecificationVersion)
            Fail($"Variant version {variant.SpecificationVersion} read back as {info.SpecificationVersion}.");
        if (logical is LogicalType.Geometry or LogicalType.Geography)
        {
            var wantCrs = logical is LogicalType.Geometry g ? g.Crs : ((LogicalType.Geography)logical).Crs;
            if (info.HasCrs != (wantCrs is not null))
                Fail($"HasCrs={info.HasCrs} but the written CRS was {(wantCrs is null ? "null" : "set")}.");
            var gotCrs = physical.Metadata.ColumnLogicalTypeCrsUtf8(0);
            if (wantCrs is not null && !gotCrs.SequenceEqual(Encoding.UTF8.GetBytes(wantCrs)))
                Fail($"CRS '{wantCrs}' read back as {gotCrs.Length} different bytes.");
            if (wantCrs is null && !gotCrs.IsEmpty)
                Fail("a null CRS was read back as bytes.");
            if (logical is LogicalType.Geography geography && info.Algorithm != geography.Algorithm)
                Fail($"Geography algorithm {geography.Algorithm} read back as {info.Algorithm}.");
        }

        var nodeCount = physical.Metadata.SchemaNodeCount;
        if (nodeCount < 2 || physical.Metadata.SchemaNodes.Length != nodeCount)
            Fail($"SchemaNodeCount {nodeCount} / SchemaNodes {physical.Metadata.SchemaNodes.Length}.");
        for (var n = 0; n < nodeCount; n++)
        {
            var node = physical.Metadata.SchemaNodes[n];
            if (node.Ordinal != n || (n > 0 && (node.ParentOrdinal < 0 || node.ParentOrdinal >= n)) || physical.Metadata.SchemaNodeNameUtf8(n).IsEmpty && n > 0)
                Fail($"schema node {n}: ordinal/parent/name inconsistent (parent {node.ParentOrdinal}).");
            if (node.Kind == NodeKind.Group && node.ChildCount <= 0)
                Fail($"group node {n} has no children.");
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // 5. custom page strategy
    // ---------------------------------------------------------------------------------------------------------------

    sealed class FuzzStrategy(int dictionaryMode, int sizeMode, int rowMode, int dropMode) : IPageStrategy
    {
        int _calls;

        public DictionaryMode GetDictionaryMode() => (DictionaryMode)dictionaryMode;

        public bool ShouldDropDictionary(uint uniqueCount, uint totalRowCount, uint rowsSeen)
            => dropMode switch { 0 => false, 1 => true, 2 => (_calls++ & 1) == 0, _ => uniqueCount > rowsSeen / 2 };

        public bool TryGetTargetDataPageSizeBytes(out uint sizeBytes)
        {
            sizeBytes = sizeMode switch
            {
                1 => 0u,
                2 => 1u,
                3 => uint.MaxValue,
                4 => (uint)int.MaxValue + 1,
                5 => (uint)(1 + (_calls++ % 5) * 100),
                6 => 64u,
                _ => 0u
            };
            return sizeMode != 0;
        }

        public uint GetNextDataPageRowCount(uint totalRowCount, uint rowsWritten)
            => rowMode switch
            {
                0 => totalRowCount - rowsWritten,
                1 => 1,
                2 => 0,
                3 => uint.MaxValue,
                4 => Math.Max(1, (totalRowCount - rowsWritten) / 2),
                5 => (uint)(1 + (_calls++ % 7)),
                6 => totalRowCount - rowsWritten + 1,
                _ => unchecked((uint)-1)
            };
    }

    static void Strategy(Cur c)
    {
        var rows = c.Pick(1, 2, 9, 100, 1500);
        var optional = c.Bool();
        var binary = c.Bool();
        var dictionaryMode = c.Int(0, 3);
        var sizeMode = c.Int(0, 7);
        var rowMode = c.Int(0, 8);
        var dropMode = c.Int(0, 4);
        var encoding = c.Pick(EncodingKind.Plain, EncodingKind.RleDictionary, EncodingKind.DeltaBinaryPacked);
        if (binary && encoding == EncodingKind.DeltaBinaryPacked)
            encoding = EncodingKind.DeltaLengthByteArray;
        var strategy = new FuzzStrategy(dictionaryMode, sizeMode, rowMode, dropMode);
        var what = $"LIF1 strategy rows={rows} dict={dictionaryMode} size={sizeMode} rowMode={rowMode} drop={dropMode} optional={optional} binary={binary} {encoding}";
        var values = Enumerable.Range(0, rows).Select(i => optional && i % 4 == 3 ? null : (long?)(i % 37)).ToArray();
        var schema = new PlankSchema([ColumnDefinition.Leaf("v", binary ? ParquetPhysicalType.ByteArray : ParquetPhysicalType.Int64,
            new ColumnOptions(optional ? ParquetRepetition.Optional : ParquetRepetition.Required, ImmutableArray.Create(encoding)), pageStrategy: strategy)]);
        _strategies++;
        byte[]? file = null;
        Exception? error = null;
        var worker = new Thread(() =>
        {
            try
            {
                using var stream = new MemoryStream();
                var writer = schema.CreateWriter(stream, new ParquetWriterOptions { TargetDataPageSizeBytes = c.Pick(64u, 1u << 20) });
                var group = writer.StartRowGroup();
                if (binary && optional)
                {
                    var column = group.CreateSerializedColumn<ReadOnlyMemory<byte>?>(schema.LeafColumns[0]);
                    column.Serialize(values.Select(static v => v is { } x ? (ReadOnlyMemory<byte>?)BitConverter.GetBytes(x) : null).ToArray());
                    group.Write(column);
                }
                else if (binary)
                {
                    var column = group.CreateSerializedColumn<ReadOnlyMemory<byte>>(schema.LeafColumns[0]);
                    column.Serialize(values.Select(static v => (ReadOnlyMemory<byte>)BitConverter.GetBytes(v!.Value)).ToArray());
                    group.Write(column);
                }
                else if (optional)
                {
                    var column = group.CreateSerializedColumn<long?>(schema.LeafColumns[0]);
                    column.Serialize(values);
                    group.Write(column);
                }
                else
                {
                    var column = group.CreateSerializedColumn<long>(schema.LeafColumns[0]);
                    column.Serialize(values.Select(static v => v!.Value).ToArray());
                    group.Write(column);
                }

                writer.CloseFile();
                file = stream.ToArray();
            }
            catch (Exception e) { error = e; }
        }) { IsBackground = true };
        worker.Start();
        if (!worker.Join(TimeSpan.FromSeconds(30)))
            Fail($"{what}: writing did not finish within 30 s (hang with a custom page strategy).");
        if (error is not null)
        {
            _strategyRefusals++;
            if (rowMode is 0 or 1 or 4 && sizeMode is 0 or 6)
                Fail($"{what}: a well-formed custom strategy (page rows within 1..remaining, sane page size) was refused: {error.GetType().Name}: {error.Message}");
            if (error is not (ArgumentException or InvalidOperationException or NotSupportedException or OverflowException or CorruptParquetException))
                Fail($"{what}: custom strategy gave {error.GetType().Name}: {error.Message}");
            return;
        }

        using var reader = schema.CreateReader(new MemoryStream(file!, writable: false));
        var seen = new List<long?>();
        foreach (var rg in Enumerable.Range(0, reader.RowGroups.Count))
        {
            var leaf = schema.LeafColumns[0];
            if (binary)
                foreach (var b in reader.RowGroups[rg].Column<byte>(leaf))
                    for (var i = 0; i < b.Count; i++)
                        seen.Add(b.IsNull(i) ? null : BitConverter.ToInt64(b.GetValue(i)));
            else if (optional)
                foreach (var b in reader.RowGroups[rg].Column<long?>(leaf))
                    seen.AddRange(b.Values.ToArray());
            else
                foreach (var b in reader.RowGroups[rg].Column<long>(leaf))
                    seen.AddRange(b.Values.ToArray().Select(static v => (long?)v));
        }

        if (!seen.SequenceEqual(values))
            Fail($"{what}: {seen.Count} values read back, expected {values.Length} (or values differ) — the strategy changed the data.");
    }
}
