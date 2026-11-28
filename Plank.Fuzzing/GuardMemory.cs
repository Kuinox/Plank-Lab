using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Plank.Fuzzing.Guard;

namespace Plank.Fuzzing;

/// <summary>
/// Harness side of the page-guard allocator (<see cref="GuardCore"/>, Plank.Fuzzing.Guard/README.md). Everything
/// here is a no-op passthrough unless PLANK_FUZZ_GUARD=end|start.
/// </summary>
public static class GuardMemory
{
    public static bool Enabled
        => GuardCore.Enabled;

    /// <summary>"end", "start" or "off", for logs.</summary>
    public static string ModeName
        => GuardCore.Mode.ToString().ToLowerInvariant();

    public static long Allocations
        => GuardCore.Allocations;

    public static int Live
        => GuardCore.LiveCount;

    /// <summary>
    /// Copies <paramref name="bytes"/> into a byte[] whose elements end (or start) at a guard page. The array is a
    /// real byte[] (MemoryMarshal.TryGetArray succeeds, MemoryReadSource borrows it), so the zero-copy paths are
    /// guarded too. Without guard mode it is a plain <c>ToArray()</c>. Register the returned scope to release it.
    /// </summary>
    public static byte[] ToArray(ReadOnlySpan<byte> bytes, GuardScope? scope = null)
    {
        if (!GuardCore.Enabled)
            return bytes.ToArray();
        var array = GuardCore.AllocateArray<byte>(bytes.Length, GuardCore.Mode, "input", out var region);
        bytes.CopyTo(array);
        (scope ?? GuardScope.Current)?.Add(() => GuardCore.ReleaseArray(array, region));
        return array;
    }

    /// <summary>
    /// Same as <see cref="ToArray(ReadOnlySpan{byte}, GuardScope?)"/> for value types without references (including
    /// nullable primitives), for writer inputs.
    /// </summary>
    public static T[] ToArray<T>(ReadOnlySpan<T> values, GuardScope? scope = null)
    {
        if (!GuardCore.Enabled)
            return values.ToArray();
        var array = GuardCore.AllocateArray<T>(values.Length, GuardCore.Mode, "values", out var region);
        values.CopyTo(array);
        (scope ?? GuardScope.Current)?.Add(() => GuardCore.ReleaseArray(array, region));
        return array;
    }

    /// <summary>
    /// Marshal.AllocHGlobal for the harness's own canary pools: in guard mode the block ends at a guard page (its
    /// trailing canary bytes then sit right before it, so a read past them faults).
    /// </summary>
    public static nint AllocHGlobal(int byteLength)
        => GuardCore.Enabled
            ? GuardCore.Allocate(byteLength, 0, 16, GuardCore.Mode, "harness-pool").Data
            : Marshal.AllocHGlobal(byteLength);

    public static void FreeHGlobal(nint allocation)
    {
        if (GuardCore.Enabled && GuardCore.FindLive(allocation) is { } region)
            GuardCore.Release(region);
        else
            Marshal.FreeHGlobal(allocation);
    }

    /// <summary>
    /// A <see cref="ReadOnlyMemory{T}"/> over guarded native memory through a <see cref="MemoryManager{T}"/>
    /// (TryGetArray fails, so readers take their copying path into pool buffers).
    /// </summary>
    public static ReadOnlyMemory<byte> NativeCopy(ReadOnlySpan<byte> bytes, GuardScope? scope = null)
    {
        if (!GuardCore.Enabled)
            return bytes.ToArray();
        var manager = new GuardedMemoryManager(bytes.Length, "input-native");
        bytes.CopyTo(manager.GetSpan());
        (scope ?? GuardScope.Current)?.Add(((IDisposable)manager).Dispose);
        return manager.Memory;
    }
}

/// <summary>
/// Releases the guard allocations registered while it is current (the end of one fuzz input): the memory is
/// poisoned and made PROT_NONE, so anything still holding it faults on the next access.
/// </summary>
public sealed class GuardScope : IDisposable
{
    [ThreadStatic] static GuardScope? _current;
    readonly GuardScope? _previous;
    readonly List<Action> _releases = [];

    GuardScope()
    {
        _previous = _current;
        _current = this;
    }

    public static GuardScope? Current
        => _current;

    /// <summary>Opens a scope when guard mode is on, else returns null (so <c>using var _ = GuardScope.Begin();</c>).</summary>
    public static GuardScope? Begin()
        => GuardCore.Enabled ? new GuardScope() : null;

    internal void Add(Action release)
    {
        lock (_releases)
            _releases.Add(release);
    }

    public void Dispose()
    {
        _current = _previous;
        List<Action> releases;
        lock (_releases)
        {
            releases = [.. _releases];
            _releases.Clear();
        }

        foreach (var release in releases)
            release();
    }
}

internal sealed unsafe class GuardedMemoryManager : MemoryManager<byte>
{
    readonly GuardRegion _region;
    int _disposed;

    internal GuardedMemoryManager(int length, string owner)
        => _region = GuardCore.Allocate(length, 0, 1, GuardCore.Mode, owner);

    public override Span<byte> GetSpan()
        => _region.Span;

    public override MemoryHandle Pin(int elementIndex = 0)
        => new((byte*)_region.Data + elementIndex);

    public override void Unpin()
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            GuardCore.Release(_region);
    }
}

/// <summary>
/// An <see cref="IParquetBufferPool"/> that serves every rent from its own guard mapping with exactly the requested
/// length (no power-of-two bucket slack, unlike DefaultParquetBufferPool), filled with 0xCD, and poisons and
/// PROT_NONEs it on return, so overruns (End mode), underruns (Start mode) and use-after-return all fault.
/// </summary>
public sealed unsafe class GuardBufferPool : IParquetBufferPool, IDisposable
{
    // Plank's ParquetBuffer header (ParquetBufferHeader, internal) sits immediately before the payload.
    static readonly int HeaderSize = Marshal.SizeOf(
        typeof(ParquetBuffer).Assembly.GetType("Plank.ParquetBufferHeader", throwOnError: true)!);

    readonly GuardMode _mode;
    readonly Action<nint> _return;
    readonly ConcurrentDictionary<nint, GuardRegion> _rented = new();
    long _rents;

    public GuardBufferPool()
        : this(GuardCore.Mode)
    {
    }

    internal GuardBufferPool(GuardMode mode)
    {
        _mode = mode == GuardMode.Off ? GuardMode.End : mode;
        _return = Return;
    }

    /// <summary>A new guard pool in guard mode, else <paramref name="fallback"/>.</summary>
    public static IParquetBufferPool OrElse(IParquetBufferPool fallback)
        => GuardCore.Enabled ? new GuardBufferPool() : fallback;

    public long Rents
        => Interlocked.Read(ref _rents);

    /// <summary>Buffers rented and not yet returned.</summary>
    public int Outstanding
        => _rented.Count;

    public ParquetBuffer Rent(uint minimumByteLength)
    {
        if (minimumByteLength == 0)
            return default;
        if (minimumByteLength > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(minimumByteLength), minimumByteLength,
                $"Buffer length must be <= {int.MaxValue}.");

        var length = (int)minimumByteLength;
        var owner = GuardCore.Trace ? $"pool-rent {Environment.StackTrace.Replace('\n', '|')}" : "pool-rent";
        var region = GuardCore.Allocate(length, HeaderSize, 1, _mode, owner);
        _rented[region.RwStart] = region;
        Interlocked.Increment(ref _rents);
        // ParquetBuffer.Create writes the header at allocation + payloadOffset - HeaderSize.
        return ParquetBuffer.Create(region.RwStart, region.RwLength, (int)(region.Data - region.RwStart), length,
            _return);
    }

    void Return(nint allocation)
    {
        if (!_rented.TryRemove(allocation, out var region))
        {
            GuardCore.Report($"return of an allocation this guard pool does not own (double return?): 0x{allocation:x}");
            return;
        }

        // Header layout: int ReferenceCount, int Capacity, int BucketIndex, int AllocationByteLength,
        // nint Allocation, ParquetBufferHeader* NextFree. Capacity..NextFree must still describe this buffer
        // (NextFree stays null: this pool never chains buffers).
        var header = (int*)(region.Data - HeaderSize);
        if (header[1] != region.Length || header[2] != -1 || header[3] != region.RwLength ||
            *(nint*)(header + 4) != region.RwStart || *(nint*)(header + 6) != 0)
            GuardCore.Report($"ParquetBuffer header overwritten (underrun write?) capacity={header[1]} " +
                             $"bucket={header[2]} allocLen={header[3]} next=0x{*(nint*)(header + 6):x} in {region}");
        GuardCore.Release(region);
    }

    /// <summary>Nothing to free: every buffer is released on its own return.</summary>
    public void Dispose()
    {
    }
}
