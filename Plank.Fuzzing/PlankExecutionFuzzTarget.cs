using System.Runtime.InteropServices;
using Plank.Reading;
using Plank.Schema;
using Plank.Writing;

namespace Plank.Fuzzing;

// Buffer-pool and execution-layer target. Routed from the writer target behind
// marker 0xDD + magic "EXEC"; the byte after the magic selects the mode and the
// rest is a stream of fuzzer choices (see Cursor).
//
//   0  pool sequence     DefaultParquetBufferPool / tracking pool driven by a
//                        fuzzer-chosen list of Rent / Rent<T> / Dispose (any
//                        order, double dispose) / Retain / RetainSlice / AsSpan<T>
//                        / Trim / pool Dispose / memory pressure toggles. Every
//                        live buffer holds a pattern; a global ownership map
//                        proves buffers never overlap and are never too small.
//   1  pool concurrent   the same from several threads against one shared pool.
//   2  schedule round trip
//                        row writer + row reader with fuzzer-chosen options (worker
//                        counts, parallelism, row-group/page/initial capacities,
//                        compression), a tracking pool (guards, quarantine, leak
//                        check), output streams that throw at byte/call N or are
//                        non-seekable, read sources with short reads or that throw
//                        at call N, a throwing OnWorkerStarted callback ("cancel at
//                        the Nth callback"), and different Complete/Dispose orders.
//                        Written data must read back identically; an injected fault
//                        must surface and must not leak, hang or be swallowed.
//   3  reader lifecycle  abandon / double dispose / use after dispose / Reset.
//
// A failed check throws ExecutionFuzzException, which no caller treats as expected.
internal static class PlankExecutionFuzzTarget
{
    internal sealed class ExecutionFuzzException(string message, Exception? inner = null)
        : Exception(message, inner);

    /// <summary>The synthetic failure injected by streams, sources, pools and callbacks.</summary>
    sealed class InjectedFault(string message) : Exception(message);

    static readonly int[] Outcomes = new int[8];

    static PlankExecutionFuzzTarget()
    {
        if (Environment.GetEnvironmentVariable("PLANK_FUZZ_TRACE") == "1")
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"EXEC outcomes: pool-seq={Outcomes[0]} pool-conc={Outcomes[1]} write-ok={Outcomes[2]} write-injected-surfaced={Outcomes[3]} read-ok={Outcomes[4]} read-injected-surfaced={Outcomes[5]} invalid-opts-rejected={Outcomes[6]}");
    }

    internal static void Execute(ReadOnlySpan<byte> data)
    {
        var cursor = new Cursor(data);
        switch (cursor.Byte() % 4)
        {
            case 0:
                PoolSequence(cursor);
                break;
            case 1:
                PoolConcurrent(cursor);
                break;
            case 2:
                ScheduleRoundTrip(cursor, readerLifecycle: false);
                break;
            default:
                ScheduleRoundTrip(cursor, readerLifecycle: true);
                break;
        }
    }

    // ---------------------------------------------------------------- cursor

    sealed class Cursor(ReadOnlySpan<byte> data)
    {
        readonly byte[] _data = data.ToArray();
        int _position;

        internal byte Byte()
            => _position < _data.Length ? _data[_position++] : (byte)0;

        internal bool Bool()
            => (Byte() & 1) != 0;

        /// <summary>Returns a value in [minimum, maximum].</summary>
        internal int Int(int minimum, int maximum)
        {
            var span = (uint)(maximum - minimum) + 1;
            if (span <= 1)
                return minimum;
            var raw = (uint)Byte() | (uint)Byte() << 8;
            if (span > 65536)
                raw |= (uint)Byte() << 16;
            return minimum + (int)(raw % span);
        }

        internal T Pick<T>(params T[] choices)
            => choices[Byte() % choices.Length];

        internal bool Exhausted => _position >= _data.Length;
    }

    // ------------------------------------------------------------ pool model

    // Pattern held by every live allocation (shared by Retain/RetainSlice aliases).
    sealed class Group
    {
        internal required int Id;
        internal required nint Address;
        internal required int Length;
        internal int Aliases;
        internal bool Registered;

        internal byte Expected(int index)
            => unchecked((byte)(Id * 131 + index * 17 + (index >> 8) * 29 + 1));
    }

    sealed class Live
    {
        internal ParquetBuffer Buffer;
        internal required Group Group;
        internal int Offset;
        internal int Length;
        internal bool Disposed;
    }

    // Address-range registry over every live allocation of every thread.
    sealed class Ownership
    {
        readonly object _gate = new();
        readonly List<(nint Start, nint End, int Id)> _ranges = [];

        internal void Register(Group group)
        {
            lock (_gate)
            {
                var start = group.Address;
                var end = start + group.Length;
                foreach (var range in _ranges)
                    if (start < range.End && range.Start < end)
                        throw new ExecutionFuzzException(
                            $"Pool handed out overlapping buffers: new [{start:x},{end:x}) id {group.Id} vs live [{range.Start:x},{range.End:x}) id {range.Id}.");
                _ranges.Add((start, end, group.Id));
                group.Registered = true;
            }
        }

        internal void Unregister(Group group)
        {
            lock (_gate)
            {
                var index = _ranges.FindIndex(r => r.Id == group.Id && r.Start == group.Address);
                if (index < 0)
                    throw new ExecutionFuzzException($"Ownership map lost buffer {group.Id}.");
                _ranges.RemoveAt(index);
                group.Registered = false;
            }
        }
    }

    sealed class PoolWorld
    {
        internal required IParquetBufferPool Pool;
        internal DefaultParquetBufferPool? Default;
        internal required Ownership Ownership;
        internal volatile bool Pressure;
        internal int MinimumAlignment = 1;
        internal bool Exact;
        internal bool Disposed;
        internal int NextId;
    }

    static readonly uint[] InterestingSizes =
    [
        0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025,
        4095, 4096, 4097, 65535, 65536, 65537, (1u << 20) - 1, 1u << 20, (1u << 20) + 1, (1u << 22) - 1, 1u << 22
    ];

    static PoolWorld CreatePoolWorld(Cursor cursor)
    {
        var world = new PoolWorld { Pool = null!, Ownership = new Ownership() };
        var policy = cursor.Bool() ? ParquetBufferRetentionPolicy.Adaptive : ParquetBufferRetentionPolicy.ZeroAllocation;
        var max = cursor.Pick(long.MaxValue, 0L, 1L, 63L, 64L, 4096L, 100_000L, 1L << 22, 1L << 40);
        switch (cursor.Byte() % 4)
        {
            case 0:
                world.Default = new DefaultParquetBufferPool(policy, max);
                world.MinimumAlignment = 64;
                break;
            case 1:
                // Pressure callback under the fuzzer's control, checked after every return.
                world.Default = new DefaultParquetBufferPool(policy, max, () => world.Pressure, 0, 0);
                world.MinimumAlignment = 64;
                break;
            case 2:
                world.Default = new DefaultParquetBufferPool(policy);
                world.MinimumAlignment = 64;
                break;
            default:
                world.Pool = new ExactFitBufferPool(poison: cursor.Bool());
                world.Exact = true;
                return world;
        }
        world.Pool = world.Default;
        return world;
    }

    // ------------------------------------------------------ sequence of ops

    static void PoolSequence(Cursor cursor)
    {
        Interlocked.Increment(ref Outcomes[0]);
        var world = CreatePoolWorld(cursor);
        var lives = new List<Live>();
        var operations = cursor.Int(1, 160);
        try
        {
            for (var i = 0; i < operations && !cursor.Exhausted; i++)
                PoolStep(world, lives, cursor, threadId: 0);

            // Drain in a fuzzer-chosen order, then check nothing was disturbed.
            VerifyAll(lives);
            while (lives.Count > 0)
                ReturnOne(world, lives, cursor.Int(0, lives.Count - 1));
            if (world.Default is { } pool)
            {
                CheckRetention(pool);
                if (!world.Disposed)
                {
                    pool.Trim();
                    if (pool.RetainedBytes != 0)
                        throw new ExecutionFuzzException($"Trim left {pool.RetainedBytes} retained bytes.");
                }
            }
        }
        finally
        {
            foreach (var live in lives)
                if (!live.Disposed)
                    live.Buffer.Dispose();
            (world.Pool as IDisposable)?.Dispose();
        }
    }

    static void PoolConcurrent(Cursor cursor)
    {
        Interlocked.Increment(ref Outcomes[1]);
        var world = CreatePoolWorld(cursor);
        var threadCount = cursor.Int(2, 4);
        var plans = new Cursor[threadCount];
        var operationCounts = new int[threadCount];
        for (var t = 0; t < threadCount; t++)
        {
            // Every thread replays its own slice of the input so the schedule is data-driven.
            var length = cursor.Int(1, 48);
            var slice = new byte[length];
            for (var j = 0; j < slice.Length; j++)
                slice[j] = cursor.Byte();
            plans[t] = new Cursor(slice);
            operationCounts[t] = cursor.Int(1, 120);
        }

        var disposePoolAt = cursor.Bool() ? cursor.Int(0, 60) : -1;
        var errors = new List<Exception>();
        var threads = new Thread[threadCount];
        var start = new ManualResetEventSlim(false);
        for (var t = 0; t < threadCount; t++)
        {
            var id = t + 1;
            var plan = plans[t];
            var count = operationCounts[t];
            threads[t] = new Thread(() =>
            {
                var lives = new List<Live>();
                try
                {
                    start.Wait();
                    for (var i = 0; i < count; i++)
                    {
                        if (id == 1 && i == disposePoolAt)
                            DisposePoolOnce(world);
                        PoolStep(world, lives, plan, id);
                    }
                    VerifyAll(lives);
                    while (lives.Count > 0)
                        ReturnOne(world, lives, 0);
                }
                catch (Exception error)
                {
                    lock (errors)
                        errors.Add(error);
                }
                finally
                {
                    foreach (var live in lives)
                        if (!live.Disposed)
                        {
                            try
                            {
                                live.Buffer.Dispose();
                            }
                            catch (Exception)
                            {
                                // The primary failure is already recorded.
                            }
                        }
                }
            }) { IsBackground = true };
            threads[t].Start();
        }

        start.Set();
        foreach (var thread in threads)
            if (!thread.Join(TimeSpan.FromSeconds(60)))
                throw new ExecutionFuzzException("Concurrent pool operations did not finish within 60 s (deadlock?).");
        if (errors.Count > 0)
            throw new ExecutionFuzzException($"Concurrent pool operation failed: {errors[0].Message}", errors[0]);
        if (world.Default is { } pool)
        {
            CheckRetention(pool);
            pool.Dispose();
            if (pool.RetainedBytes != 0)
                throw new ExecutionFuzzException($"A disposed pool still retains {pool.RetainedBytes} bytes.");
        }
    }

    static void DisposePoolOnce(PoolWorld world)
    {
        if (world.Pool is IDisposable disposable)
        {
            world.Disposed = true;
            disposable.Dispose();
        }
    }

    static void CheckRetention(DefaultParquetBufferPool pool)
    {
        var retained = pool.RetainedBytes;
        if (retained < 0 || retained > pool.MaximumRetainedBytes)
            throw new ExecutionFuzzException(
                $"Pool retains {retained} bytes with a limit of {pool.MaximumRetainedBytes}.");
    }

    static void PoolStep(PoolWorld world, List<Live> lives, Cursor cursor, int threadId)
    {
        switch (cursor.Byte() % 12)
        {
            case 0:
            case 1:
            case 2:
                Rent(world, lives, cursor, threadId);
                break;
            case 3:
            case 4:
                if (lives.Count > 0)
                    ReturnOne(world, lives, cursor.Int(0, lives.Count - 1));
                break;
            case 5:
                if (lives.Count > 0)
                {
                    var live = lives[cursor.Int(0, lives.Count - 1)];
                    DisposeTwice(live, world);
                }
                break;
            case 6:
                if (lives.Count > 0)
                    RetainAlias(world, lives, cursor);
                break;
            case 7:
                if (lives.Count > 0)
                    RetainSlice(world, lives, cursor);
                break;
            case 8:
                if (world.Default is { } pool)
                {
                    pool.Trim();
                    CheckRetention(pool);
                    if (threadId == 0 && !world.Disposed && pool.RetainedBytes != 0)
                        throw new ExecutionFuzzException($"Trim left {pool.RetainedBytes} retained bytes.");
                }
                break;
            case 9:
                VerifyAll(lives);
                break;
            case 10:
                if (lives.Count > 0)
                    Project(lives[cursor.Int(0, lives.Count - 1)], cursor);
                break;
            default:
                world.Pressure = cursor.Bool();
                if (threadId == 0 && cursor.Byte() % 16 == 0)
                    DisposePoolOnce(world);
                break;
        }
    }

    static void Rent(PoolWorld world, List<Live> lives, Cursor cursor, int threadId)
    {
        var kind = cursor.Byte() % 10;
        // The size table, plus exact powers of two +/-1 and arbitrary values.
        var count = kind switch
        {
            < 5 => cursor.Pick(InterestingSizes),
            5 => (uint)cursor.Int(0, 1 << 18),
            6 => (uint)1 << cursor.Int(0, 22),
            7 => ((uint)1 << cursor.Int(0, 22)) + (uint)cursor.Pick(-1, 0, 1),
            8 => cursor.Pick(uint.MaxValue, (uint)int.MaxValue + 1, (uint)int.MaxValue + 2, 0x80000001u),
            _ => cursor.Pick(0x20000000u, 0x40000000u, 0x10000001u)
        };
        var elementKind = cursor.Byte() % 6;
        var elementSize = elementKind switch { 0 => 1, 1 => 2, 2 => 4, 3 => 8, 4 => 16, _ => 1 };
        var bytes = (ulong)count * (ulong)(elementKind == 5 ? 1 : elementSize);
        var generic = elementKind != 5;

        // Anything above 2^22 bytes that would really be allocated is skipped: the
        // point is the boundary behaviour, not committing gigabytes in a fuzz loop.
        if (bytes <= int.MaxValue && bytes > (1UL << 22) && !PlankExecutionLimits.AllowHugeRent)
            return;

        ParquetBuffer buffer = default;
        try
        {
            buffer = generic
                ? elementKind switch
                {
                    0 => world.Pool.Rent<byte>(count),
                    1 => world.Pool.Rent<short>(count),
                    2 => world.Pool.Rent<int>(count),
                    3 => world.Pool.Rent<long>(count),
                    _ => world.Pool.Rent<Guid>(count)
                }
                : world.Pool.Rent(count);
        }
        catch (ObjectDisposedException) when (world.Disposed)
        {
            return;
        }
        catch (OverflowException) when (generic && bytes > uint.MaxValue)
        {
            return;
        }
        catch (ArgumentOutOfRangeException) when (bytes > int.MaxValue)
        {
            return;
        }
        catch (OutOfMemoryException)
        {
            return;
        }

        if (bytes > uint.MaxValue)
        {
            buffer.Dispose();
            throw new ExecutionFuzzException($"Rent<T> accepted {bytes} bytes, which overflows uint.");
        }

        if (bytes > int.MaxValue)
        {
            buffer.Dispose();
            throw new ExecutionFuzzException($"Rent accepted {bytes} bytes, above int.MaxValue.");
        }

        if (bytes == 0)
        {
            if (!buffer.IsEmpty || buffer.Length != 0 || buffer.Span.Length != 0)
                throw new ExecutionFuzzException("A zero-length rent returned a non-empty buffer.");
            buffer.Dispose();
            return;
        }

        if (buffer.Length < (int)bytes || (world.Exact && buffer.Length != (int)bytes))
            throw new ExecutionFuzzException(
                $"Rent({bytes}) returned a buffer of {buffer.Length} bytes.");
        if (buffer.Span.Length != buffer.Length)
            throw new ExecutionFuzzException("Span length differs from buffer length.");
        var address = buffer.DangerousGetAddress();
        if (world.MinimumAlignment > 1 && address % world.MinimumAlignment != 0)
            throw new ExecutionFuzzException($"Rent returned a misaligned buffer at {address:x}.");

        var group = new Group
        {
            Id = Interlocked.Increment(ref world.NextId) * 8 + threadId,
            Address = address,
            Length = buffer.Length,
            Aliases = 1
        };
        world.Ownership.Register(group);
        var live = new Live { Buffer = buffer, Group = group, Offset = 0, Length = buffer.Length };
        Fill(live);
        lives.Add(live);
    }

    static void Fill(Live live)
    {
        var span = live.Buffer.Span;
        for (var i = 0; i < span.Length; i++)
            span[i] = live.Group.Expected(live.Offset + i);
    }

    static void Verify(Live live)
    {
        if (live.Disposed)
            return;
        var span = live.Buffer.Span;
        if (span.Length != live.Length)
            throw new ExecutionFuzzException($"Buffer {live.Group.Id} changed length from {live.Length} to {span.Length}.");
        for (var i = 0; i < span.Length; i++)
            if (span[i] != live.Group.Expected(live.Offset + i))
                throw new ExecutionFuzzException(
                    $"Buffer {live.Group.Id} byte {live.Offset + i} was overwritten (another owner, or use after return).");
    }

    static void VerifyAll(List<Live> lives)
    {
        foreach (var live in lives)
            Verify(live);
    }

    static void ReturnOne(PoolWorld world, List<Live> lives, int index)
    {
        var live = lives[index];
        lives.RemoveAt(index);
        Verify(live);
        ReleaseAlias(live, world);
        AssertDisposed(live);
    }

    static void ReleaseAlias(Live live, PoolWorld world)
    {
        if (live.Disposed)
            return;
        live.Disposed = true;
        // Unregister before the last dispose: afterwards the pool may legitimately reuse the range.
        if (Interlocked.Decrement(ref live.Group.Aliases) == 0)
            world.Ownership.Unregister(live.Group);
        live.Buffer.Dispose();
    }

    static void DisposeTwice(Live live, PoolWorld world)
    {
        // Disposing the same ParquetBuffer variable again must be a no-op (the struct clears itself).
        // Only possible when it is already disposed; otherwise this is the single real release.
        if (!live.Disposed)
        {
            Verify(live);
            ReleaseAlias(live, world);
        }
        live.Buffer.Dispose();
        live.Buffer.Dispose();
        AssertDisposed(live);
    }

    static void AssertDisposed(Live live)
    {
        if (live.Buffer.Length != 0 || live.Buffer.Span.Length != 0 || !live.Buffer.IsEmpty)
            throw new ExecutionFuzzException("A disposed buffer still exposes storage.");
        try
        {
            _ = live.Buffer.AsSpan<byte>();
        }
        catch (ObjectDisposedException)
        {
            goto retain;
        }

        throw new ExecutionFuzzException("AsSpan on a disposed buffer did not throw ObjectDisposedException.");
    retain:
        try
        {
            _ = live.Buffer.Retain();
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        throw new ExecutionFuzzException("Retain on a disposed buffer did not throw ObjectDisposedException.");
    }

    static void RetainAlias(PoolWorld world, List<Live> lives, Cursor cursor)
    {
        var source = lives[cursor.Int(0, lives.Count - 1)];
        if (source.Disposed)
            return;
        Interlocked.Increment(ref source.Group.Aliases);
        var alias = new Live
        {
            Buffer = source.Buffer.Retain(),
            Group = source.Group,
            Offset = source.Offset,
            Length = source.Length
        };
        Verify(alias);
        lives.Add(alias);
    }

    static void RetainSlice(PoolWorld world, List<Live> lives, Cursor cursor)
    {
        var source = lives[cursor.Int(0, lives.Count - 1)];
        if (source.Disposed)
            return;
        var offset = cursor.Int(-1, source.Length + 1);
        var length = cursor.Pick(0, 1, source.Length - offset, source.Length - offset + 1,
            cursor.Int(-1, source.Length + 1));
        var valid = offset >= 0 && offset <= source.Length && length >= 0 && length <= source.Length - offset;
        Live? slice = null;
        try
        {
            Interlocked.Increment(ref source.Group.Aliases);
            slice = new Live
            {
                Buffer = source.Buffer.RetainSlice(offset, length),
                Group = source.Group,
                Offset = source.Offset + offset,
                Length = length
            };
        }
        catch (ArgumentOutOfRangeException) when (!valid)
        {
            Interlocked.Decrement(ref source.Group.Aliases);
            return;
        }

        if (!valid)
        {
            slice.Buffer.Dispose();
            throw new ExecutionFuzzException($"RetainSlice({offset},{length}) of {source.Length} bytes was accepted.");
        }

        Verify(slice);
        lives.Add(slice);
    }

    static void Project(Live live, Cursor cursor)
    {
        if (live.Disposed)
            return;
        var type = cursor.Byte() % 5;
        var size = type switch { 0 => 1, 1 => 2, 2 => 4, 3 => 8, _ => 16 };
        try
        {
            var length = type switch
            {
                0 => live.Buffer.AsSpan<byte>().Length,
                1 => live.Buffer.AsSpan<short>().Length,
                2 => live.Buffer.AsSpan<int>().Length,
                3 => live.Buffer.AsSpan<long>().Length,
                _ => live.Buffer.AsSpan<Guid>().Length
            };
            if (live.Length % size != 0 || length != live.Length / size)
                throw new ExecutionFuzzException($"AsSpan returned {length} elements for {live.Length} bytes / {size}.");
        }
        catch (InvalidOperationException) when (live.Length % size != 0)
        {
        }

        try
        {
            _ = live.Buffer.AsSpan<string>();
            throw new ExecutionFuzzException("AsSpan<string> over unmanaged storage was accepted.");
        }
        catch (InvalidOperationException)
        {
        }
    }

    // --------------------------------------------------------- tracking pool

    /// <summary>
    /// Pool for the writer/reader round trip: exact-fit (or slack-rounded) native buffers
    /// with guard bytes, quarantine of returned memory (a write after return is caught
    /// when the pool is closed), double-return and leak detection, and optional rent failure.
    /// </summary>
    sealed class TrackingPool(int slackMode, int failRentAt, Func<bool>? onRentFault) : IParquetBufferPool
    {
        const int PayloadOffset = 64;
        const int Guard = 64;
        const byte Canary = 0xCD;
        const byte Dead = 0xDD;

        readonly object _gate = new();
        readonly Dictionary<nint, (int Length, int Capacity)> _live = [];
        readonly List<(nint Allocation, int Length)> _quarantine = [];
        readonly List<string> _violations = [];
        int _rents;

        internal int Outstanding
        {
            get { lock (_gate) return _live.Count; }
        }

        internal bool Faulted { get; private set; }

        public ParquetBuffer Rent(uint minimumByteLength)
        {
            if (minimumByteLength == 0)
                return default;
            if (minimumByteLength > int.MaxValue - PayloadOffset - Guard)
                throw new ArgumentOutOfRangeException(nameof(minimumByteLength));
            lock (_gate)
            {
                if (failRentAt >= 0 && ++_rents == failRentAt + 1)
                {
                    Faulted = true;
                    onRentFault?.Invoke();
                    throw new InjectedFault("rent failure");
                }
            }

            var requested = (int)minimumByteLength;
            var length = slackMode switch
            {
                1 => (requested + 63) & ~63,
                2 => (int)System.Numerics.BitOperations.RoundUpToPowerOf2((uint)requested),
                3 => requested + 1 + (requested & 7),
                _ => requested
            };
            if (length < requested || length > int.MaxValue - PayloadOffset - Guard)
                length = requested;
            var total = PayloadOffset + length + Guard;
            var allocation = GuardMemory.AllocHGlobal(total);
            Fill(allocation, 0, PayloadOffset, Canary);
            Fill(allocation, PayloadOffset, length, 0);
            Fill(allocation, PayloadOffset + length, Guard, Canary);
            lock (_gate)
                _live[allocation] = (requested, length);
            return ParquetBuffer.Create(allocation, total, PayloadOffset, length, Return);
        }

        void Return(nint allocation)
        {
            lock (_gate)
            {
                if (!_live.Remove(allocation, out var entry))
                {
                    _violations.Add($"allocation {allocation:x} returned twice or never rented");
                    return;
                }

                // The header sits in the last 32 bytes of the front guard.
                var bad = Mismatch(allocation, 0, PayloadOffset - 32)
                          ?? Mismatch(allocation, PayloadOffset + entry.Capacity, Guard);
                if (bad is { } at)
                    _violations.Add($"guard byte at {at} of a {entry.Length}-byte buffer was overwritten");
                Fill(allocation, PayloadOffset, entry.Capacity, Dead);
                _quarantine.Add((allocation, entry.Capacity));
            }
        }

        /// <summary>Verifies quarantined memory and frees everything. Throws on any violation.</summary>
        internal void Close(bool requireNoLeaks)
        {
            string? failure = null;
            lock (_gate)
            {
                foreach (var (allocation, length) in _quarantine)
                {
                    for (var i = 0; i < length; i++)
                        if (Marshal.ReadByte(allocation, PayloadOffset + i) != Dead)
                        {
                            _violations.Add($"a returned {length}-byte buffer was written to after return (byte {i})");
                            break;
                        }

                    GuardMemory.FreeHGlobal(allocation);
                }

                _quarantine.Clear();
                if (_violations.Count > 0)
                    failure = _violations[0];
                else if (requireNoLeaks && _live.Count > 0)
                    failure = $"{_live.Count} rented buffer(s) were never returned";
                foreach (var allocation in _live.Keys)
                    GuardMemory.FreeHGlobal(allocation);
                _live.Clear();
            }

            if (failure is not null)
                throw new ExecutionFuzzException($"Buffer pool contract violated: {failure}.");
        }

        static int? Mismatch(nint allocation, int offset, int count)
        {
            for (var i = 0; i < count; i++)
                if (Marshal.ReadByte(allocation, offset + i) != Canary)
                    return offset + i;
            return null;
        }

        static void Fill(nint allocation, int offset, int count, byte value)
        {
            if (count <= 0)
                return;
            var bytes = new byte[count];
            if (value != 0)
                Array.Fill(bytes, value);
            Marshal.Copy(bytes, 0, allocation + offset, count);
        }
    }

    // --------------------------------------------------------- stream doubles

    sealed class FaultState
    {
        internal volatile bool Triggered;

        internal InjectedFault Trigger(string what)
        {
            Triggered = true;
            return new InjectedFault(what);
        }
    }

    sealed class FaultingOutputStream(Stream inner, bool seekable, long failAtByte, int failAtCall,
        bool failOnFlush, int yieldEvery, FaultState state) : Stream
    {
        long _written;
        int _calls;

        public override bool CanRead => false;
        public override bool CanSeek => seekable;
        public override bool CanWrite => true;

        public override long Length
            => seekable ? inner.Length : throw new NotSupportedException();

        public override long Position
        {
            get => seekable ? inner.Position : throw new NotSupportedException();
            set
            {
                if (!seekable)
                    throw new NotSupportedException();
                inner.Position = value;
            }
        }

        public override void Flush()
        {
            if (failOnFlush)
                throw state.Trigger("flush failure");
            inner.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin)
            => seekable ? inner.Seek(offset, origin) : throw new NotSupportedException();

        public override void SetLength(long value)
        {
            if (!seekable)
                throw new NotSupportedException();
            inner.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
            => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            _calls++;
            if (yieldEvery > 0 && _calls % yieldEvery == 0)
                Thread.Yield();
            if (failAtCall >= 0 && _calls > failAtCall)
                throw state.Trigger("write call failure");
            if (failAtByte >= 0 && _written + buffer.Length > failAtByte)
            {
                var allowed = (int)Math.Max(0, failAtByte - _written);
                inner.Write(buffer[..allowed]);
                _written += allowed;
                throw state.Trigger("write byte failure");
            }

            inner.Write(buffer);
            _written += buffer.Length;
        }
    }

    /// <summary>Seekable read stream returning fuzzer-chosen short reads and optionally failing.</summary>
    sealed class ShortReadStream(byte[] bytes, int[] chunks, int failAtRead, FaultState state) : Stream
    {
        readonly MemoryStream _inner = new(bytes, writable: false);
        int _reads;

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (buffer.IsEmpty)
                return 0;
            var call = _reads++;
            if (failAtRead >= 0 && call >= failAtRead)
                throw state.Trigger("read failure");
            var chunk = chunks.Length == 0 ? buffer.Length : chunks[call % chunks.Length];
            return _inner.Read(buffer[..Math.Min(buffer.Length, Math.Max(1, chunk))]);
        }

        public override long Seek(long offset, SeekOrigin origin)
            => _inner.Seek(offset, origin);

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();
    }

    sealed class FaultingReadSource(byte[] bytes, int failAtCall, long failAtOffset, FaultState state)
        : IParquetReadSource
    {
        readonly MemoryReadSource _inner = new(bytes);
        int _calls;

        public ulong Length => _inner.Length;

        public void ReadExactly(ulong offset, Span<byte> destination)
        {
            var call = Interlocked.Increment(ref _calls) - 1;
            if (failAtCall >= 0 && call >= failAtCall)
                throw state.Trigger("source call failure");
            if (failAtOffset >= 0 && offset + (ulong)destination.Length > (ulong)failAtOffset)
                throw state.Trigger("source offset failure");
            _inner.ReadExactly(offset, destination);
        }

        public void Dispose()
            => _inner.Dispose();
    }

    // ------------------------------------------------------ schedule round trip

    sealed record Expected(int Id, string Label, byte[] Payload);

    sealed class WorkerLog(int configuredWorkers)
    {
        readonly object _gate = new();
        readonly HashSet<int> _indexes = [];
        int _started;

        internal int Started => Volatile.Read(ref _started);
        internal string? Problem;

        internal void Record(ParquetWorkerContext context)
        {
            lock (_gate)
            {
                _started++;
                if (context.WorkerCount < 1 || context.WorkerCount > configuredWorkers
                    || (uint)context.WorkerIndex >= (uint)context.WorkerCount
                    || string.IsNullOrEmpty(context.Name)
                    || !_indexes.Add(context.WorkerIndex))
                    Problem ??= $"worker context {context} is inconsistent (configured {configuredWorkers}).";
            }
        }
    }

    static ParquetExecutionOptions MakeExecution(int workers, WorkerLog log, int faultAtCallback, FaultState state,
        int jitter)
    {
        var seen = 0;
        return new ParquetExecutionOptions
        {
            WorkerCount = workers,
            OnWorkerStarted = context =>
            {
                log.Record(context);
                var index = Interlocked.Increment(ref seen) - 1;
                // Shuffle the interleaving a little, deterministically per input.
                var spin = (index * 7 + jitter) % 5;
                for (var i = 0; i < spin; i++)
                    Thread.Yield();
                if (faultAtCallback >= 0 && index == faultAtCallback)
                    throw state.Trigger("worker callback failure");
            }
        };
    }

    static Expected[] CreateRows(Cursor cursor)
    {
        var count = cursor.Pick(0, 1, 2, 3, 5, 8, 17, 33, 100, cursor.Int(0, 400), cursor.Int(0, 3000));
        var seed = cursor.Int(0, ushort.MaxValue) * 65537 + cursor.Byte();
        var random = new Random(seed);
        var sizeMode = cursor.Byte() % 4;
        var rows = new Expected[count];
        for (var i = 0; i < count; i++)
        {
            var length = sizeMode switch
            {
                0 => 0,
                1 => random.Next(0, 24),
                2 => random.Next(0, 600),
                _ => random.Next(0, 40) == 0 ? random.Next(20_000, 90_000) : random.Next(0, 90)
            };
            var payload = new byte[length];
            random.NextBytes(payload);
            var label = random.Next(4) == 0
                ? $"é{i}-{random.Next()}"
                : new string((char)('a' + random.Next(26)), random.Next(0, 12));
            rows[i] = new Expected(random.Next(int.MinValue, int.MaxValue), label, payload);
        }

        return rows;
    }

    static void ScheduleRoundTrip(Cursor cursor, bool readerLifecycle)
    {
        var rows = CreateRows(cursor);
        var injectFaults = cursor.Byte() % 3 != 0;

        // ---- pool
        var poolKind = cursor.Byte() % 6;
        var slackMode = cursor.Byte() % 4;
        var rentFailure = injectFaults && cursor.Byte() % 5 == 0 ? cursor.Int(0, 40) : -1;
        var state = new FaultState();
        IParquetBufferPool pool;
        TrackingPool? tracking = null;
        DefaultParquetBufferPool? defaultPool = null;
        switch (poolKind)
        {
            case 0:
            case 1:
            case 2:
                tracking = new TrackingPool(slackMode, rentFailure, () => { state.Triggered = true; return true; });
                pool = tracking;
                break;
            case 3:
                defaultPool = new DefaultParquetBufferPool(
                    cursor.Bool() ? ParquetBufferRetentionPolicy.Adaptive : ParquetBufferRetentionPolicy.ZeroAllocation,
                    cursor.Pick(0L, 4096L, 1L << 20, long.MaxValue));
                pool = defaultPool;
                break;
            case 4:
                var pressure = true;
                defaultPool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.Adaptive, long.MaxValue,
                    () => pressure, 0, 0);
                pool = defaultPool;
                break;
            default:
                pool = DefaultParquetBufferPool.Shared;
                break;
        }

        // ---- writer options
        var workers = cursor.Pick(1, 1, 2, 3, 4, 8);
        var invalidWorkers = cursor.Byte() % 24 == 0;
        var parallelism = cursor.Pick(0, 0, 1, 2, 3, 8);
        var writerLog = new WorkerLog(Math.Max(workers, parallelism));
        var faultWriterCallback = injectFaults && cursor.Byte() % 3 == 0 ? cursor.Int(0, workers) : -1;
        var writerExecution = MakeExecution(invalidWorkers ? cursor.Pick(0, -1, int.MinValue) : workers,
            writerLog, faultWriterCallback, state, cursor.Byte());
        var compression = cursor.Pick(CompressionKind.None, CompressionKind.None, CompressionKind.Snappy,
            CompressionKind.Gzip, CompressionKind.Zstd, CompressionKind.Lz4);
        // BufferWriter allocates initial/chunk segment slots per page, and tiny pages mean many pages:
        // a 1-byte chunk with a 64 KiB initial buffer is a user-chosen multi-GB allocation, not a bug.
        var chunkBytes = cursor.Pick(1u, 7u, 64u, 4096u, 64u * 1024);
        var pageInitial = cursor.Pick(1u, 100u, 4096u, 64u * 1024);
        var columnInitial = cursor.Pick(1u, 100u, 4096u, 1u << 20);
        chunkBytes = Math.Max(chunkBytes, Math.Max(pageInitial, columnInitial) / 128);
        var writerOptions = new ParquetWriterOptions
        {
            BufferPool = pool,
            Execution = writerExecution,
            RowApiMaxParallelism = (uint)parallelism,
            RowApiInitialRowCapacity = cursor.Pick(1, 1, 2, 3, 7, 64, 1000),
            TargetRowGroupSizeBytes = cursor.Pick(1UL, 64UL, 1000UL, 64UL * 1024, 1UL << 20, ulong.MaxValue),
            TargetDataPageSizeBytes = cursor.Pick(1u, 64u, 1024u, 1u << 20),
            BufferChunkSizeBytes = chunkBytes,
            InitialPageBufferBytes = pageInitial,
            InitialColumnBufferBytes = columnInitial,
            InitialPageCapacity = cursor.Pick(0u, 1u, 4u),
            Compression = compression,
            DataPageVersion = cursor.Bool() ? ParquetDataPageVersion.V2 : ParquetDataPageVersion.V1,
            WritePageIndexes = cursor.Bool(),
            WritePageCrc = cursor.Bool()
        };

        // ---- output stream
        var backing = new MemoryStream();
        var seekable = cursor.Bool();
        long failBytes = -1;
        var failCall = -1;
        var failFlush = false;
        if (injectFaults)
        {
            switch (cursor.Byte() % 5)
            {
                case 0:
                    failBytes = cursor.Pick(0L, 1L, 3L, 4L, 5L, 8L, 100L, 1000L, 65536L, cursor.Int(0, 200_000));
                    break;
                case 1:
                    failCall = cursor.Int(0, 12);
                    break;
                case 2:
                    failFlush = true;
                    break;
            }
        }

        var stream = new FaultingOutputStream(backing, seekable, failBytes, failCall, failFlush,
            cursor.Pick(0, 0, 1, 3), state);
        var ending = cursor.Byte() % 5;
        var useFlushCallback = cursor.Bool();

        // ---- write phase
        var flushed = 0;
        Exception? writeError = null;
        var completed = false;
        RunGuarded("write", () =>
        {
            try
            {
                using var writer = useFlushCallback
                    ? RowFuzzBinary.CreateRowWriter(stream, count => Interlocked.Add(ref flushed, count), writerOptions)
                    : RowFuzzBinary.CreateRowWriter(stream, writerOptions);
                foreach (var want in rows)
                {
                    var row = writer.GetRow();
                    row.Id = want.Id;
                    row.Label = want.Label;
                    row.Payload = want.Payload;
                }

                switch (ending)
                {
                    case 0:
                        writer.Complete();
                        completed = true;
                        break;
                    case 1:
                        writer.Complete();
                        completed = true;
                        try
                        {
                            writer.Complete();
                        }
                        catch (Exception e) when (e is InvalidOperationException or ObjectDisposedException)
                        {
                        }

                        try
                        {
                            _ = writer.GetRow();
                            throw new ExecutionFuzzException("GetRow after Complete was accepted.");
                        }
                        catch (Exception e) when (e is InvalidOperationException or ObjectDisposedException)
                        {
                        }

                        break;
                    default:
                        // Dispose without Complete: the output is incomplete by design.
                        break;
                }
            }
            catch (ExecutionFuzzException)
            {
                throw;
            }
            catch (Exception error)
            {
                writeError = error;
            }
        });

        if (writerLog.Problem is { } workerProblem)
            throw new ExecutionFuzzException(workerProblem);
        var writerFaulted = state.Triggered;
        var outputLegitimatelyDefective = ending >= 2 && !completed;

        if (invalidWorkers)
        {
            // A negative WorkerCount with the default RowApiMaxParallelism overflows in the checked
            // uint conversion before validation runs (OverflowException instead of ArgumentOutOfRange): see FINDINGS.
            if (writeError is not (ArgumentOutOfRangeException or OverflowException))
                throw new ExecutionFuzzException(
                    $"WorkerCount <= 0 was not rejected with ArgumentOutOfRangeException ({Describe(writeError)}).", writeError);
            Interlocked.Increment(ref Outcomes[6]);
            FinishPool(tracking, defaultPool, requireNoLeaks: true);
            return;
        }

        if (writeError is not null)
        {
            // Dispose-without-Complete may legitimately report the incomplete file.
            var tolerated = outputLegitimatelyDefective && writeError is InvalidOperationException;
            if (!writerFaulted && !tolerated)
                throw new ExecutionFuzzException($"Row writer failed on a valid sequence: {Describe(writeError)}", writeError);
            if (writerFaulted && !ContainsInjected(writeError) && !tolerated)
                throw new ExecutionFuzzException(
                    $"Injected failure was replaced by an unrelated exception: {Describe(writeError)}", writeError);
            if (writerFaulted)
                Interlocked.Increment(ref Outcomes[3]);
            FinishPool(tracking, defaultPool, requireNoLeaks: true);
            return;
        }

        if (writerFaulted && completed)
            throw new ExecutionFuzzException(
                "An injected write failure was swallowed: Complete and Dispose both returned normally.");

        if (outputLegitimatelyDefective || writerFaulted)
        {
            FinishPool(tracking, defaultPool, requireNoLeaks: true);
            return;
        }

        if (useFlushCallback && Volatile.Read(ref flushed) != rows.Length && completed)
            throw new ExecutionFuzzException(
                $"Flush callback reported {flushed} rows; {rows.Length} were written.");

        Interlocked.Increment(ref Outcomes[2]);
        var bytes = backing.ToArray();
        // A non-seekable sink got the bytes through a plain forward stream; same file expected.
        ReadBack(cursor, bytes, rows, pool, tracking, readerLifecycle);
        FinishPool(tracking, defaultPool, requireNoLeaks: true);
        if (defaultPool is not null)
            CheckRetention(defaultPool);
    }

    static void FinishPool(TrackingPool? tracking, DefaultParquetBufferPool? defaultPool, bool requireNoLeaks)
    {
        tracking?.Close(requireNoLeaks);
        defaultPool?.Dispose();
    }

    static void ReadBack(Cursor cursor, byte[] bytes, Expected[] rows, IParquetBufferPool pool,
        TrackingPool? tracking, bool readerLifecycle)
    {
        var state = new FaultState();
        var inject = cursor.Byte() % 3 != 0;
        var workers = cursor.Pick(1, 1, 2, 3, 4, 8);
        var log = new WorkerLog(workers);
        var faultCallback = inject && cursor.Byte() % 3 == 0 ? cursor.Int(0, workers) : -1;
        var readAhead = cursor.Pick(0, 1, 1, 2, 5, -1);
        var readAheadValid = readAhead is 0 or 1;
        var options = new RowApi.RowReaderOptions
        {
            BufferPool = pool,
            Execution = MakeExecution(workers, log, faultCallback, state, cursor.Byte()),
            MaxReadAheadRowGroups = readAhead,
            VerifyPageCrc = cursor.Bool()
        };

        var sourceKind = cursor.Byte() % 4;
        var chunkCount = cursor.Int(0, 6);
        var chunks = new int[chunkCount];
        for (var i = 0; i < chunks.Length; i++)
            chunks[i] = cursor.Pick(1, 1, 2, 3, 7, 8, 100, 4096, cursor.Int(1, 70_000));
        var failRead = inject && cursor.Byte() % 3 == 0 ? cursor.Int(0, 30) : -1;
        var failOffset = inject && cursor.Byte() % 3 == 0
            ? cursor.Pick(0L, 3L, 4L, bytes.Length / 2, bytes.Length - 8L, bytes.Length - 1L, bytes.Length + 1L)
            : -1L;
        IParquetReadSource? source = null;
        Stream? readStream = null;
        switch (sourceKind)
        {
            case 0:
                source = FullValueOracle.Source(bytes);
                break;
            case 1:
                source = new FaultingReadSource(bytes, failRead, failOffset, state);
                break;
            case 2:
                readStream = new ShortReadStream(bytes, chunks, failRead, state);
                break;
            default:
                readStream = new MemoryStream(bytes, writable: false);
                break;
        }

        var abandonAfter = readerLifecycle ? cursor.Int(0, rows.Length) : int.MaxValue;
        var lifecycle = cursor.Byte() % 6;
        var restartRows = readerLifecycle && cursor.Bool();
        var seen = 0;
        Exception? readError = null;
        RunGuarded("read", () =>
        {
            try
            {
                using var reader = source is not null
                    ? RowFuzzBinary.CreateRowReader(source, options: options)
                    : RowFuzzBinary.CreateRowReader(readStream!, options: options);
                for (var pass = 0; pass < (restartRows ? 2 : 1); pass++)
                {
                    seen = 0;
                    while (seen < abandonAfter && reader.MoveNext())
                    {
                        if (seen >= rows.Length)
                            throw new ExecutionFuzzException("Reader returned more rows than were written.");
                        var actual = reader.Current;
                        var want = rows[seen];
                        if (actual.Id != want.Id || !string.Equals(actual.Label, want.Label, StringComparison.Ordinal)
                            || !actual.Payload.Value.SequenceEqual(want.Payload))
                            throw new ExecutionFuzzException(
                                $"Row {seen} read back differently from what was written (pass {pass}, workers {workers}).");
                        seen++;
                    }

                    if (pass == 0 && restartRows)
                    {
                        // Re-read the same file through Reset; rows must match again.
                        if (source is not null)
                            reader.Reset(source);
                        else
                        {
                            readStream!.Position = 0;
                            reader.Reset(readStream);
                        }
                    }
                }

                if (abandonAfter == int.MaxValue || abandonAfter >= rows.Length)
                {
                    if (seen != rows.Length)
                        throw new ExecutionFuzzException($"Reader returned {seen} rows; {rows.Length} were written.");
                    if (reader.MoveNext())
                        throw new ExecutionFuzzException("Reader returned a row past the end.");
                }

                if (lifecycle == 1)
                    reader.Dispose();
            }
            catch (ExecutionFuzzException)
            {
                throw;
            }
            catch (Exception error)
            {
                readError = error;
            }
        });

        if (log.Problem is { } problem)
            throw new ExecutionFuzzException(problem);
        var readFaulted = state.Triggered || tracking?.Faulted == true;
        if (!readAheadValid)
        {
            if (readError is not ArgumentOutOfRangeException)
                throw new ExecutionFuzzException($"MaxReadAheadRowGroups={readAhead} was not rejected ({Describe(readError)}).", readError);
            return;
        }

        if (readError is not null)
        {
            if (!readFaulted)
                throw new ExecutionFuzzException($"Row reader failed on a valid file: {Describe(readError)}", readError);
            if (!ContainsInjected(readError))
                throw new ExecutionFuzzException(
                    $"Injected read failure was replaced by an unrelated exception: {Describe(readError)}", readError);
            Interlocked.Increment(ref Outcomes[5]);
        }
        else if (!readFaulted)
            Interlocked.Increment(ref Outcomes[4]);
        if (readError is null && readFaulted && (abandonAfter == int.MaxValue || abandonAfter >= rows.Length) && !restartRows)
        {
            throw new ExecutionFuzzException("An injected read failure was swallowed: all rows came back correct.");
        }
    }

    static bool ContainsInjected(Exception? error)
    {
        for (var current = error; current is not null; current = current.InnerException)
        {
            if (current is InjectedFault)
                return true;
            if (current is AggregateException aggregate && aggregate.InnerExceptions.Any(ContainsInjected))
                return true;
        }

        return false;
    }

    static string Describe(Exception? error)
        => error is null
            ? "no exception"
            : Environment.GetEnvironmentVariable("PLANK_FUZZ_TRACE") == "1"
                ? error.ToString()
                : $"{error.GetType().Name}: {error.Message}";

    // Hangs are findings: every scheduled operation must finish.
    static void RunGuarded(string what, Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception error)
            {
                failure = error;
            }
        }) { IsBackground = true };
        thread.Start();
        if (!thread.Join(TimeSpan.FromSeconds(60)))
            throw new ExecutionFuzzException($"The {what} phase did not finish within 60 s (deadlock after a failure?).");
        if (failure is not null)
            throw failure is ExecutionFuzzException ? failure : new ExecutionFuzzException($"{what} phase threw {Describe(failure)}", failure);
    }
}

static class PlankExecutionLimits
{
    // Rents above 4 MiB are never really allocated unless this is set; off in every fuzz loop.
    internal static bool AllowHugeRent
        => Environment.GetEnvironmentVariable("PLANK_FUZZ_ALLOW_HUGE_RENT") == "1";
}
