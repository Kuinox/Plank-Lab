// Page-guard allocator: a poor man's ASan for .NET, shared (as a linked source file) by the Plank library shim
// (built into Plank.dll by Directory.Build.targets, see PlankNativeMemoryShim.cs) and by Plank.Fuzzing.
//
// Every allocation gets its own mapping, [RW pages][PROT_NONE page] (end) or [PROT_NONE page][RW pages] (start),
// with the usable bytes placed so that they touch the guard page:
//   PLANK_FUZZ_GUARD=end (or 1): the bytes end exactly at the trailing guard page -> any overrun faults;
//   PLANK_FUZZ_GUARD=start:      the bytes (plus any header that must precede them) start right after the leading
//                                guard page -> any underrun past the header faults.
// The rest of the RW window is filled with a canary that is verified on release (catches writes on the unguarded
// side), the whole window is poisoned and made PROT_NONE on release and kept in a quarantine (use after release
// faults). A fault outside the null page in managed code is a fatal AccessViolationException with the managed stack;
// in native code (zlib) a plain SIGSEGV. PLANK_FUZZ_GUARD_TRACE=1 logs every allocation and release to stderr.
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#if PLANK_GUARD_SHIM
namespace Plank.GuardShim;
#else
namespace Plank.Fuzzing.Guard;
#endif

internal enum GuardMode
{
    Off,
    End,
    Start,
}

internal sealed class GuardViolationException(string message) : Exception(message);

internal sealed class GuardRegion
{
    internal nint MapBase;
    internal nuint MapLength;
    internal nint RwStart;
    internal int RwLength;
    internal nint Data;
    internal int Length;
    internal int Prefix;
    internal GuardMode Mode;
    internal string Owner = "";
    internal int Released;
    internal bool Unguarded;

    internal unsafe Span<byte> Span
        => new((void*)Data, Length);

    public override string ToString()
        => $"{Owner} data=[0x{Data:x}..0x{Data + Length:x}) len={Length} mode={Mode}";
}

internal static unsafe class GuardCore
{
    const int ProtNone = 0;
    const int ProtRead = 1;
    const int ProtWrite = 2;
    const int MapPrivate = 0x02;
    const int MapAnonymous = 0x20;
    internal const byte Canary = 0xCD;
    internal const byte Poison = 0xDB;
    const long QuarantineLimitBytes = 64L * 1024 * 1024;
    const int QuarantineLimitCount = 1024;

    internal static readonly int PageSize = Environment.SystemPageSize;
    internal static readonly GuardMode Mode = ParseMode(Environment.GetEnvironmentVariable("PLANK_FUZZ_GUARD"));
    internal static readonly bool Trace = Environment.GetEnvironmentVariable("PLANK_FUZZ_GUARD_TRACE") == "1";

    // PLANK_FUZZ_GUARD_SLACK=n (0..64, default 0): end-mode buffers end n bytes before the guard page. For
    // DOTNET_EnableHWIntrinsic=0 only: there the JIT copies a struct whose size is 4 mod 8 (Plank's 92-byte
    // ParquetSchemaNodeInfo) passed by value with an 8-byte load that reads 4 bytes past its end, which faults on an
    // exactly placed buffer (a runtime issue, reproduced without Plank: fuzz/repros/dotnet-jit-struct-overread/).
    static readonly int Slack = ParseSlack(Environment.GetEnvironmentVariable("PLANK_FUZZ_GUARD_SLACK"));

    static int ParseSlack(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return 0;
        var slack = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
        if (slack < 0 || slack > 64)
            throw new InvalidOperationException("PLANK_FUZZ_GUARD_SLACK must be 0..64.");
        return slack;
    }

    static readonly ConcurrentDictionary<nint, GuardRegion> LiveByData = new();
    static readonly Queue<GuardRegion> Quarantine = new();
    static readonly object QuarantineGate = new();
    static long _quarantineBytes;
    static long _allocations;

    internal static bool Enabled
        => Mode != GuardMode.Off;

    internal static long Allocations
        => Interlocked.Read(ref _allocations);

    internal static int LiveCount
        => LiveByData.Count;

    static GuardMode ParseMode(string? value)
        => value?.Trim().ToLowerInvariant() switch
        {
            null or "" or "0" or "off" => GuardMode.Off,
            "1" or "end" => GuardMode.End,
            "start" => GuardMode.Start,
            _ => throw new InvalidOperationException($"PLANK_FUZZ_GUARD must be off, end or start, not '{value}'."),
        };

    [DllImport("libc", EntryPoint = "mmap", SetLastError = true)]
    static extern nint Mmap(nint address, nuint length, int protection, int flags, int fd, nint offset);

    [DllImport("libc", EntryPoint = "mprotect", SetLastError = true)]
    static extern int Mprotect(nint address, nuint length, int protection);

    [DllImport("libc", EntryPoint = "munmap", SetLastError = true)]
    static extern int Munmap(nint address, nuint length);

    /// <summary>
    /// Maps <paramref name="length"/> usable bytes preceded by <paramref name="prefix"/> RW bytes (a header that
    /// must sit right before the data). End mode: data ends at the trailing guard page, rounded down so the data
    /// start is a multiple of <paramref name="alignment"/>. Start mode: the prefix starts at the first RW byte.
    /// </summary>
    internal static GuardRegion Allocate(long length, int prefix, int alignment, GuardMode mode, string owner)
    {
        if (length < 0 || length > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(length));
        if (mode == GuardMode.Off)
            mode = GuardMode.End;
        if (alignment <= 0 || (alignment & (alignment - 1)) != 0 || alignment > PageSize)
            throw new ArgumentOutOfRangeException(nameof(alignment));

        if (LiveByData.Count >= MaxLiveGuarded)
            return AllocateUnguarded(length, prefix, alignment, mode, owner);

        long page = PageSize;
        long rwBytes = (prefix + length + Slack + (alignment - 1) + page - 1) / page * page;
        if (rwBytes == 0)
            rwBytes = page;
        // One guard page, on the guarded side only: two VMAs per buffer (vm.max_map_count is 65530 by default and a
        // writer with many column buffers alive hit it with guards on both sides).
        var total = rwBytes + page;
        var map = MapWithRetry((nuint)total);
        var rw = mode == GuardMode.End ? map : map + (nint)page;
        if (Mprotect(rw, (nuint)rwBytes, ProtRead | ProtWrite) != 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            FlushQuarantine();
            if (Mprotect(rw, (nuint)rwBytes, ProtRead | ProtWrite) != 0)
            {
                Munmap(map, (nuint)total);
                throw new OutOfMemoryException(
                    $"guard mprotect failed (errno {errno}; {LiveByData.Count} live guard buffers, vm.max_map_count?)");
            }
        }

        nint data;
        if (mode == GuardMode.End)
        {
            data = rw + (nint)rwBytes - (nint)(length + Slack);
            data &= ~(nint)(alignment - 1);
        }
        else
        {
            data = rw + prefix;
            data = (data + (alignment - 1)) & ~(nint)(alignment - 1);
        }

        // Canary everything, the data included: pooled and native memory is never zero, and a decoder that relies
        // on zeroed memory should be seen doing it.
        new Span<byte>((void*)rw, (int)rwBytes).Fill(Canary);

        var region = new GuardRegion
        {
            MapBase = map,
            MapLength = (nuint)total,
            RwStart = rw,
            RwLength = (int)rwBytes,
            Data = data,
            Length = (int)length,
            Prefix = prefix,
            Mode = mode,
            Owner = owner,
        };
        LiveByData[data] = region;
        Interlocked.Increment(ref _allocations);
        if (Trace)
            Console.Error.WriteLine($"GUARD-ALLOC\t{region}\tmap=[0x{map:x}..0x{map + (nint)total:x})");
        return region;
    }

    // Two VMAs per guarded buffer; vm.max_map_count is 65530 by default and the runtime needs its own. Inputs that
    // keep more buffers than this alive at once (e.g. a fuzzed 16-byte BufferChunkSizeBytes over a large column)
    // get canary-only heap memory past this point instead of failing (logged once per process).
    const int MaxLiveGuarded = 12_000;
    static int _degradedWarned;

    static GuardRegion AllocateUnguarded(long length, int prefix, int alignment, GuardMode mode, string owner)
    {
        if (Interlocked.Exchange(ref _degradedWarned, 1) == 0)
            Console.Error.WriteLine($"GUARD-DEGRADED\t{MaxLiveGuarded} guard buffers alive: further ones are canary-only heap memory");
        const int Tail = 64;
        var rwBytes = (int)(prefix + length + alignment + Tail);
        var rw = (nint)System.Runtime.InteropServices.NativeMemory.AlignedAlloc((nuint)rwBytes, 64);
        if (rw == 0)
            throw new OutOfMemoryException();
        new Span<byte>((void*)rw, rwBytes).Fill(Canary);
        var data = (rw + prefix + (alignment - 1)) & ~(nint)(alignment - 1);
        var region = new GuardRegion
        {
            MapBase = rw, MapLength = (nuint)rwBytes, RwStart = rw, RwLength = rwBytes, Data = data,
            Length = (int)length, Prefix = prefix, Mode = mode, Owner = owner + " (unguarded)", Unguarded = true,
        };
        LiveByData[data] = region;
        Interlocked.Increment(ref _allocations);
        return region;
    }

    static nint MapWithRetry(nuint total)
    {
        var map = Mmap(0, total, ProtNone, MapPrivate | MapAnonymous, -1, 0);
        if (map != -1)
            return map;
        FlushQuarantine();
        map = Mmap(0, total, ProtNone, MapPrivate | MapAnonymous, -1, 0);
        if (map == -1)
            throw new OutOfMemoryException(
                $"guard mmap of {total} bytes failed (errno {Marshal.GetLastPInvokeError()}; {LiveByData.Count} live guard buffers)");
        return map;
    }

    static void FlushQuarantine()
    {
        lock (QuarantineGate)
        {
            while (Quarantine.Count > 0)
            {
                var old = Quarantine.Dequeue();
                _ = Munmap(old.MapBase, old.MapLength);
            }

            _quarantineBytes = 0;
        }
    }

    internal static GuardRegion? FindLive(nint data)
        => LiveByData.TryGetValue(data, out var region) ? region : null;

    /// <summary>Checks canaries, poisons, PROT_NONEs and quarantines the region.</summary>

    internal static void Release(GuardRegion region)
    {
        if (Interlocked.Exchange(ref region.Released, 1) != 0)
            throw new GuardViolationException($"double release of guard buffer {region}");
        LiveByData.TryRemove(region.Data, out _);
        if (Trace)
            Console.Error.WriteLine($"GUARD-FREE\t{region}");

        var violation = CheckCanaries(region);
        if (region.Unguarded)
        {
            System.Runtime.InteropServices.NativeMemory.AlignedFree((void*)region.RwStart);
            if (violation is not null)
                Report(violation);
            return;
        }

        new Span<byte>((void*)region.RwStart, region.RwLength).Fill(Poison);
        if (Mprotect(region.RwStart, (nuint)region.RwLength, ProtNone) != 0)
            throw new InvalidOperationException($"guard mprotect failed (errno {Marshal.GetLastPInvokeError()})");

        lock (QuarantineGate)
        {
            Quarantine.Enqueue(region);
            _quarantineBytes += (long)region.MapLength;
            while ((_quarantineBytes > QuarantineLimitBytes || Quarantine.Count > QuarantineLimitCount) &&
                   Quarantine.Count > 0)
            {
                var old = Quarantine.Dequeue();
                _quarantineBytes -= (long)old.MapLength;
                _ = Munmap(old.MapBase, old.MapLength);
            }
        }

        if (violation is not null)
            Report(violation);
    }

    static string? CheckCanaries(GuardRegion region)
    {
        var rw = new ReadOnlySpan<byte>((void*)region.RwStart, region.RwLength);
        var dataOffset = (int)(region.Data - region.RwStart);
        var headerOffset = dataOffset - region.Prefix;
        var bad = rw[..headerOffset].IndexOfAnyExcept(Canary);
        if (bad >= 0)
            return $"underrun write at data{bad - dataOffset} (byte 0x{rw[bad]:x2}) of guard buffer {region}";
        var after = rw[(dataOffset + region.Length)..];
        bad = after.IndexOfAnyExcept(Canary);
        if (bad >= 0)
            return $"overrun write at data+{region.Length + bad} (byte 0x{after[bad]:x2}) of guard buffer {region}";
        return null;
    }

    /// <summary>A guard violation is memory corruption: print it and kill the process (no catch can hide it).</summary>
    internal static void Report(string violation)
    {
        Console.Error.WriteLine($"GUARD-VIOLATION\t{violation}");
        Console.Error.WriteLine(Environment.StackTrace);
        Console.Error.Flush();
        Environment.FailFast($"GUARD-VIOLATION {violation}");
    }

    // ---- fake managed arrays over guarded memory ----------------------------------------------------------------
    //
    // A T[] whose element storage ends (or starts) at a guard page, so even code that borrows the caller's array
    // (MemoryMarshal.TryGetArray, Unsafe.Add over GetReference) is checked. The object lives outside the GC heap:
    // the GC never marks, moves or frees it (verified: forced compacting gen2 GCs with such arrays referenced from
    // heap objects, including after they were made PROT_NONE). Layout (64-bit): [sync block 8][MethodTable* 8]
    // [length 4 + pad 4][elements].

    const int ArrayHeader = 24;

    internal static T[] AllocateArray<T>(int count, GuardMode mode, string owner, out GuardRegion region)
        // No constraint: Nullable<T> must be allowed; references are refused at run time.
    {
        if (IntPtr.Size != 8)
            throw new PlatformNotSupportedException("guard arrays need a 64-bit runtime");
        if (RuntimeHelpers.IsReferenceOrContainsReferences<T>())
            throw new ArgumentException($"{typeof(T)} contains references: the GC must see its elements.");
        var elementSize = Unsafe.SizeOf<T>();
        region = Allocate((long)count * elementSize, ArrayHeader, Math.Min(8, elementSize), mode, owner + $" {typeof(T).Name}[{count}]");
        var objectStart = region.Data - 16;
        *(long*)(region.Data - 24) = 0;
        *(nint*)objectStart = typeof(T[]).TypeHandle.Value;
        *(long*)(region.Data - 8) = count;
        return Unsafe.As<nint, T[]>(ref objectStart);
    }

    internal static void ReleaseArray<T>(T[] array, GuardRegion region)
    {
        var typeHandle = *(nint*)(region.Data - 16);
        var length = *(long*)(region.Data - 8);
        if (typeHandle != typeof(T[]).TypeHandle.Value || length != region.Length / Unsafe.SizeOf<T>())
            Report($"guard array header overwritten (underrun write?) mt=0x{typeHandle:x} length={length} {region}");
        GC.KeepAlive(array);
        Release(region);
    }
}
