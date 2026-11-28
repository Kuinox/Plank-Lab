// Compiled INTO the Plank library only by `-p:PlankCheckedAccess=true` builds (see Plank-Lab's
// Directory.Build.targets and Plank.Fuzzing.Checked/README.md). The build-time rewriter
// (Plank.Fuzzing.Checked/Rewriter) routes every unchecked access of the library copy through the
// methods below: MemoryMarshal.GetReference/GetArrayDataReference/CreateSpan, `fixed`, `ref span[i]`
// and `new Span<T>(void*, int)` register the logical span [start, start + length) of the ref they
// produce; Unsafe.Add/Subtract/...ByteOffset forming a derived ref carry that span along; every
// read/write (Unsafe.Add used as a value, ReadUnaligned/WriteUnaligned, Unsafe.As used as a value,
// Vector*.LoadUnsafe/StoreUnsafe, pointer dereferences, gathers, CopyBlock) is checked against the
// span its base came from. An access outside it throws PlankOobReadException, even when the memory
// beyond the span is valid (a page slice inside a larger buffer), which no guard page can see.
//
// Provenance is tracked by address in small per-thread tables, so it is best effort:
// - "strong" match: the access's base ref is exactly a registered span start or a ref derived from one
//   (hint table). Violations throw (and Environment.FailFast with PLANK_CHECKED_FAILFAST=1, for AFL).
// - "weak" match: only a region containing the base was found (a ref the table cannot attribute, e.g.
//   passed through a helper's parameter after its hint was evicted). Violations are logged to stderr as
//   PLANK-OOB-WEAK, and throw only with PLANK_CHECKED_WEAK=throw.
// - no match: unchecked (counted). Managed buffers can move during a GC, so every entry is tagged with
//   GC.CollectionCount(0) and ignored once a GC happened (run replays with a large DOTNET_GCgen0size).
// PLANK_CHECKED=0 turns every check off (same binary, for overhead comparisons).
#nullable enable
#pragma warning disable CS1591, CA1502, CA1505, CA1506, CA2201, CA1810, CA1305, CA1307, CA1062
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using SU = System.Runtime.CompilerServices.Unsafe;
using SMM = System.Runtime.InteropServices.MemoryMarshal;

namespace Plank.CheckedAccess;

/// <summary>An access through an unchecked ref/pointer left the logical span it was derived from.</summary>
public sealed class PlankOobReadException : Exception
{
    public PlankOobReadException(string message, string site, string kind) : base(message)
    {
        Site = site;
        Kind = kind;
    }

    public string Site { get; }
    public string Kind { get; }
}

/// <summary>Region table and violation reporting.</summary>
public static class PlankChecked
{
    internal struct Region
    {
        public nuint Key;
        public nuint Lo;
        public nuint Hi;
        public int Epoch;
        public bool Weak;
        public long Seq;
        public string Site;
    }

    const int RingSize = 128;
    const int HintSize = 16;

    [ThreadStatic] static Region[]? t_ring;
    [ThreadStatic] static int t_ringPos;
    [ThreadStatic] static Region[]? t_hints;
    [ThreadStatic] static int t_hintPos;
    static long s_seq;
    // Native (unmovable) roots: ParquetBuffer views and payload areas inside them. Global: a ColumnBuffer is filled on
    // a worker thread and read on another. Exact-key lookups only; the newest registration of an address wins.
    static readonly Dictionary<nuint, Region> s_native = new();
    static readonly object s_nativeLock = new();

    public static readonly bool Enabled = Environment.GetEnvironmentVariable("PLANK_CHECKED") != "0";
    static readonly bool FailFast = Environment.GetEnvironmentVariable("PLANK_CHECKED_FAILFAST") == "1";
    static readonly bool WeakThrows = Environment.GetEnvironmentVariable("PLANK_CHECKED_WEAK") == "throw";
    static readonly bool Stats = Environment.GetEnvironmentVariable("PLANK_CHECKED_STATS") == "1";

    public static long Checked;
    public static long CheckedWeak;
    public static long Unknown;
    public static long Violations;
    public static long WeakViolations;
    static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> s_weakSites = new();

    /// <summary>Last strong violation message (harnesses may poll it in case a broad catch swallowed the throw).</summary>
    public static string? LastViolation;

    static PlankChecked()
    {
        if (Stats)
            AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.Error.WriteLine(
                $"PLANK-CHECKED-STATS checked={Checked} weak={CheckedWeak} unknown={Unknown} violations={Violations} weakViolations={WeakViolations}");
    }

    static int Epoch => GC.CollectionCount(0);

    internal static void Register(nuint lo, nuint bytes, string site)
    {
        if (lo == 0)
            return;
        var ring = t_ring ??= new Region[RingSize];
        var epoch = Epoch;
        // Re-registering a live identical region (a loop calling GetReference each turn) refreshes it in place.
        for (var i = 0; i < RingSize; i++)
        {
            ref var r = ref ring[i];
            if (r.Key == lo && r.Lo == lo && r.Hi == lo + bytes && r.Epoch == epoch && r.Site is not null)
            {
                r.Seq = Interlocked.Increment(ref s_seq);
                return;
            }
        }

        if (bytes != 0)
            Supersede(ring, t_hints, lo, lo + bytes);
        ref var slot = ref ring[t_ringPos++ & (RingSize - 1)];
        slot.Key = lo;
        slot.Lo = lo;
        slot.Hi = lo + bytes;
        slot.Epoch = epoch;
        slot.Weak = false;
        slot.Seq = Interlocked.Increment(ref s_seq);
        slot.Site = site;
    }

    /// <summary>A new view of [lo, hi) retires this thread's older entries overlapping it: memory reused by a pool (or a
    /// stack frame) must not keep the bounds of its previous life.</summary>
    static void Supersede(Region[] ring, Region[]? hints, nuint lo, nuint hi)
    {
        for (var i = 0; i < ring.Length; i++)
        {
            ref var r = ref ring[i];
            if (r.Site is not null && r.Lo < hi && lo < r.Hi && !(r.Lo == lo && r.Hi == hi))
                r.Site = null;
        }

        if (hints is null)
            return;
        for (var i = 0; i < hints.Length; i++)
        {
            ref var h = ref hints[i];
            if (h.Site is not null && h.Lo < hi && lo < h.Hi && !(h.Lo == lo && h.Hi == hi))
                h.Site = null;
        }
    }

    internal static void RegisterNative(nuint lo, nuint bytes, string site)
    {
        if (lo == 0 || !Enabled)
            return;
        if (t_ring is { } ring && bytes != 0)
            Supersede(ring, t_hints, lo, lo + bytes);
        lock (s_nativeLock)
        {
            if (s_native.Count > 1 << 16)
                s_native.Clear();
            s_native[lo] = new Region { Key = lo, Lo = lo, Hi = lo + bytes, Epoch = -1, Seq = Interlocked.Increment(ref s_seq), Site = site };
        }
    }

    static void RegisterDerived(nuint key, in Region parent, bool keep)
    {
        if (keep)
        {
            var ring = t_ring ??= new Region[RingSize];
            ref var slot = ref ring[t_ringPos++ & (RingSize - 1)];
            slot = parent;
            slot.Key = key;
            slot.Seq = Interlocked.Increment(ref s_seq);
        }
        else
        {
            var hints = t_hints ??= new Region[HintSize];
            ref var slot = ref hints[t_hintPos++ & (HintSize - 1)];
            slot = parent;
            slot.Key = key;
            slot.Seq = Interlocked.Increment(ref s_seq);
        }
    }

    static bool Find(nuint key, out Region region)
    {
        // Exact start match: the newest entry (hint or ring) whose key is the base address wins.
        var epoch = Epoch;
        var found = false;
        region = default;
        var hints = t_hints;
        if (hints is not null)
        {
            for (var i = 0; i < HintSize; i++)
            {
                ref var h = ref hints[i];
                if (h.Key == key && (h.Epoch == epoch || h.Epoch == -1) && h.Site is not null && (!found || h.Seq > region.Seq))
                {
                    region = h;
                    found = true;
                }
            }
        }

        lock (s_nativeLock)
        {
            if (s_native.TryGetValue(key, out var native) && (!found || native.Seq > region.Seq))
            {
                region = native;
                found = true;
            }
        }

        var ring = t_ring;
        if (ring is null)
            return found;
        {
            for (var i = 0; i < RingSize; i++)
            {
                ref var r = ref ring[i];
                if (r.Key == key && (r.Epoch == epoch || r.Epoch == -1) && r.Site is not null && (!found || r.Seq > region.Seq))
                {
                    region = r;
                    found = true;
                }
            }

            if (found)
                return true;

            for (var i = 1; i <= RingSize; i++)
            {
                ref var r = ref ring[(t_ringPos - i) & (RingSize - 1)];
                if (r.Lo <= key && key < r.Hi && (r.Epoch == epoch || r.Epoch == -1) && r.Site is not null)
                {
                    region = r;
                    region.Weak = true;
                    return true;
                }
            }
        }

        region = default;
        return false;
    }

    /// <summary>Checks an access of <paramref name="size"/> bytes at <paramref name="address"/> made through a ref derived from <paramref name="baseAddress"/>.</summary>
    internal static void Access(nuint baseAddress, nuint address, nuint size, string kind, string site)
    {
        if (!Enabled)
            return;
        if (!Find(baseAddress, out var region))
        {
            Unknown++;
            return;
        }

        if (region.Weak)
            CheckedWeak++;
        else
            Checked++;
        if (address < region.Lo || address + size > region.Hi || address + size < address)
            Violation(kind, site, address, size, region);
    }

    /// <summary>Like <see cref="Access"/>, with the base looked up among native roots only (named buffer bases).</summary>
    internal static void AccessNative(nuint baseAddress, nuint address, nuint size, string kind, string site)
    {
        if (!Enabled)
            return;
        Region region;
        bool found;
        lock (s_nativeLock)
            found = s_native.TryGetValue(baseAddress, out region);
        if (!found)
        {
            Unknown++;
            return;
        }

        Checked++;
        if (address < region.Lo || address + size > region.Hi || address + size < address)
            Violation(kind, site, address, size, region);
    }

    /// <summary>Forms a ref <paramref name="result"/> from <paramref name="baseAddress"/>: one past the end is allowed.</summary>
    internal static void Form(nuint baseAddress, nuint result, string site, bool keep)
    {
        if (!Enabled)
            return;
        if (!Find(baseAddress, out var region))
        {
            Unknown++;
            return;
        }

        if (result < region.Lo || result > region.Hi)
            Violation("form-ref", site, result, 0, region);
        RegisterDerived(result, region, keep);
    }

    static void Violation(string kind, string site, nuint address, nuint size, in Region region)
    {
        var offset = (long)address - (long)region.Lo;
        var length = (long)(region.Hi - region.Lo);
        var message =
            $"{kind} of {size} byte(s) at offset {offset} of a {length}-byte span (span from {region.Site}) at {site}" +
            (offset + (long)size > length ? $": {offset + (long)size - length} byte(s) past its end" : offset < 0 ? ": before its start" : "");
        if (region.Weak)
        {
            WeakViolations++;
            var n = s_weakSites.AddOrUpdate(site, 1, static (_, c) => c + 1);
            if (n <= 3 || WeakThrows)
                Console.Error.WriteLine("PLANK-OOB-WEAK " + message);
            if (!WeakThrows)
                return;
        }
        else
        {
            Violations++;
            LastViolation = message;
            Console.Error.WriteLine("PLANK-OOB " + message);
            if (FailFast)
                Environment.FailFast("PLANK-OOB " + message);
        }

        throw new PlankOobReadException(message, site, kind);
    }

    internal static unsafe nuint Addr<T>(ref T value) => (nuint)SU.AsPointer(ref value);
    internal static unsafe nuint AddrRO<T>(ref readonly T value) => (nuint)SU.AsPointer(ref SU.AsRef(in value));
}

/// <summary>Checked equivalents the rewriter calls instead of the unchecked APIs (one extra trailing site argument).</summary>
[SuppressMessage("Design", "CA1045")]
public static unsafe class C
{
    static nuint Size<T>() => (nuint)SU.SizeOf<T>();

    // ---- span registration ----------------------------------------------------------------------
    public static ref T GetReference<T>(Span<T> span, string site)
    {
        ref var r = ref SMM.GetReference(span);
        PlankChecked.Register(PlankChecked.Addr(ref r), (nuint)span.Length * Size<T>(), site);
        return ref r;
    }

    public static ref T GetReference<T>(ReadOnlySpan<T> span, string site)
    {
        ref var r = ref SMM.GetReference(span);
        PlankChecked.Register(PlankChecked.Addr(ref r), (nuint)span.Length * Size<T>(), site);
        return ref r;
    }

    public static ref T GetArrayDataReference<T>(T[] array, string site)
    {
        ref var r = ref SMM.GetArrayDataReference(array);
        PlankChecked.Register(PlankChecked.Addr(ref r), (nuint)array.Length * Size<T>(), site);
        return ref r;
    }

    public static ref T ElemRef<T>(Span<T> span, int index, string site)
    {
        ref var r = ref span[index];
        PlankChecked.Register(PlankChecked.Addr(ref SMM.GetReference(span)), (nuint)span.Length * Size<T>(), site);
        PlankChecked.Form(PlankChecked.Addr(ref SMM.GetReference(span)), PlankChecked.Addr(ref r), site, keep: false);
        return ref r;
    }

    public static ref readonly T ElemRef<T>(ReadOnlySpan<T> span, int index, string site)
    {
        ref readonly var r = ref span[index];
        PlankChecked.Register(PlankChecked.Addr(ref SMM.GetReference(span)), (nuint)span.Length * Size<T>(), site);
        PlankChecked.Form(PlankChecked.Addr(ref SMM.GetReference(span)), PlankChecked.AddrRO(in r), site, keep: false);
        return ref r;
    }

    public static ref T ElemRef<T>(T[] array, int index, string site)
    {
        ref var r = ref array[index];
        PlankChecked.Register(PlankChecked.Addr(ref SMM.GetArrayDataReference(array)), (nuint)array.Length * Size<T>(), site);
        PlankChecked.Form(PlankChecked.Addr(ref SMM.GetArrayDataReference(array)), PlankChecked.Addr(ref r), site, keep: false);
        return ref r;
    }

    public static Span<T> CreateSpan<T>(ref T reference, int length, string site)
    {
        var a = PlankChecked.Addr(ref reference);
        PlankChecked.Access(a, a, (nuint)(uint)length * Size<T>(), "create-span", site);
        var span = SMM.CreateSpan(ref reference, length);
        PlankChecked.Register(a, (nuint)(uint)length * Size<T>(), site);
        return span;
    }

    public static ReadOnlySpan<T> CreateReadOnlySpan<T>(ref readonly T reference, int length, string site)
    {
        var a = PlankChecked.AddrRO(in reference);
        PlankChecked.Access(a, a, (nuint)(uint)length * Size<T>(), "create-span", site);
        var span = SMM.CreateReadOnlySpan(in reference, length);
        PlankChecked.Register(a, (nuint)(uint)length * Size<T>(), site);
        return span;
    }

    // `new Span<T>(void*, int)` builds a view from a raw pointer with no ref provenance (stale registrations at the
    // same address would only produce false positives): registered, not checked. Sites with a known base are hand-rewritten.
    public static Span<T> NewSpan<T>(void* pointer, int length, string site)
    {
        var span = new Span<T>(pointer, length);
        PlankChecked.Register((nuint)pointer, (nuint)(uint)length * Size<T>(), site);
        return span;
    }

    public static ReadOnlySpan<T> NewReadOnlySpan<T>(void* pointer, int length, string site)
    {
        var span = new ReadOnlySpan<T>(pointer, length);
        PlankChecked.Register((nuint)pointer, (nuint)(uint)length * Size<T>(), site);
        return span;
    }

    // ---- hand-rewritten roots (Plank.Fuzzing.Checked/hand-rewrites.txt) ------------------------------------
    /// <summary>A native buffer's own view: registers [pointer, pointer + length) as the authoritative bound.</summary>
    public static void RegisterRoot(byte* pointer, int length, string site)
        => PlankChecked.RegisterNative((nuint)pointer, (nuint)(uint)length, site);

    public static Span<byte> RootSpan(byte* pointer, int length, string site)
    {
        PlankChecked.RegisterNative((nuint)pointer, (nuint)(uint)length, site);
        return new Span<byte>(pointer, length);
    }

    /// <summary>The address <paramref name="offset"/> bytes into a native buffer of <paramref name="length"/> bytes at
    /// <paramref name="data"/>, registered as the region [data + offset, data + length) (e.g. the binary payload area after
    /// the value descriptors).</summary>
    public static nint NativePayload(nint data, int length, int offset, string site)
    {
        PlankChecked.AccessNative((nuint)data, (nuint)(data + offset), 0, "payload-offset", site);
        if ((uint)offset <= (uint)length)
            PlankChecked.RegisterNative((nuint)(data + offset), (nuint)(uint)(length - offset), site);
        return data + offset;
    }

    /// <summary>A span of <paramref name="length"/> bytes at <paramref name="offset"/> into the buffer starting at <paramref name="baseAddress"/>.</summary>
    public static ReadOnlySpan<byte> SpanAt(nint baseAddress, int offset, int length, string site)
    {
        PlankChecked.AccessNative((nuint)baseAddress, (nuint)(baseAddress + offset), (nuint)(uint)length, "create-span", site);
        return new ReadOnlySpan<byte>((void*)(baseAddress + offset), length);
    }

    /// <summary>RowReaderCore.GetCurrent fast path: element <paramref name="offset"/> of a batch of <paramref name="length"/> values.</summary>
    public static ref T RowBatch<T>(nint address, int length, int offset, string site)
    {
        if (length >= 0)
        {
            PlankChecked.Register((nuint)address, (nuint)(uint)length * Size<T>(), site);
            if (PlankChecked.Enabled)
                PlankChecked.Access((nuint)address, (nuint)address + (nuint)(uint)offset * Size<T>(), Size<T>(), "row-batch", site);
        }

        return ref SU.AsRef<T>((void*)address);
    }

    public static void RegisterFixed<T>(T* pointer, Span<T> span, string site) where T : unmanaged
        => PlankChecked.Register((nuint)pointer, (nuint)span.Length * (nuint)sizeof(T), site);

    public static void RegisterFixed<T>(T* pointer, ReadOnlySpan<T> span, string site) where T : unmanaged
        => PlankChecked.Register((nuint)pointer, (nuint)span.Length * (nuint)sizeof(T), site);

    public static void RegisterFixed<T>(T* pointer, T[]? array, string site) where T : unmanaged
        => PlankChecked.Register((nuint)pointer, (nuint)(array?.Length ?? 0) * (nuint)sizeof(T), site);

    public static void RegisterFixed(char* pointer, string? text, string site)
        => PlankChecked.Register((nuint)pointer, (nuint)(text?.Length ?? 0) * sizeof(char), site);

    public static void RegisterFixed(byte* pointer, Span<byte> span, string site)
        => PlankChecked.Register((nuint)pointer, (nuint)span.Length, site);

    public static void RegisterFixed(byte* pointer, ReadOnlySpan<byte> span, string site)
        => PlankChecked.Register((nuint)pointer, (nuint)span.Length, site);

    public static void RegisterFixed(byte* pointer, byte[]? array, string site)
        => PlankChecked.Register((nuint)pointer, (nuint)(array?.Length ?? 0), site);

    // ---- Unsafe: ref formation (one past the end allowed) and value access ----------------------------------
    static ref T Form<T>(ref T source, ref T result, string site, bool keep)
    {
        PlankChecked.Form(PlankChecked.Addr(ref source), PlankChecked.Addr(ref result), site, keep);
        return ref result;
    }

    static ref T Value<T>(ref T source, ref T result, string site)
    {
        PlankChecked.Access(PlankChecked.Addr(ref source), PlankChecked.Addr(ref result), Size<T>(), "access", site);
        return ref result;
    }

    public static ref T Add<T>(ref T source, int offset, string site) => ref Form(ref source, ref SU.Add(ref source, offset), site, false);
    public static ref T Add<T>(ref T source, nint offset, string site) => ref Form(ref source, ref SU.Add(ref source, offset), site, false);
    public static ref T Add<T>(ref T source, nuint offset, string site) => ref Form(ref source, ref SU.Add(ref source, offset), site, false);
    public static ref T AddKeep<T>(ref T source, int offset, string site) => ref Form(ref source, ref SU.Add(ref source, offset), site, true);
    public static ref T AddKeep<T>(ref T source, nint offset, string site) => ref Form(ref source, ref SU.Add(ref source, offset), site, true);
    public static ref T AddKeep<T>(ref T source, nuint offset, string site) => ref Form(ref source, ref SU.Add(ref source, offset), site, true);
    public static ref T AddV<T>(ref T source, int offset, string site) => ref Value(ref source, ref SU.Add(ref source, offset), site);
    public static ref T AddV<T>(ref T source, nint offset, string site) => ref Value(ref source, ref SU.Add(ref source, offset), site);
    public static ref T AddV<T>(ref T source, nuint offset, string site) => ref Value(ref source, ref SU.Add(ref source, offset), site);

    public static void* Add<T>(void* source, int offset, string site)
    {
        var result = SU.Add<T>(source, offset);
        PlankChecked.Form((nuint)source, (nuint)result, site, false);
        return result;
    }

    public static ref T Subtract<T>(ref T source, int offset, string site) => ref Form(ref source, ref SU.Subtract(ref source, offset), site, false);
    public static ref T Subtract<T>(ref T source, nint offset, string site) => ref Form(ref source, ref SU.Subtract(ref source, offset), site, false);
    public static ref T Subtract<T>(ref T source, nuint offset, string site) => ref Form(ref source, ref SU.Subtract(ref source, offset), site, false);
    public static ref T SubtractKeep<T>(ref T source, int offset, string site) => ref Form(ref source, ref SU.Subtract(ref source, offset), site, true);
    public static ref T SubtractKeep<T>(ref T source, nint offset, string site) => ref Form(ref source, ref SU.Subtract(ref source, offset), site, true);
    public static ref T SubtractKeep<T>(ref T source, nuint offset, string site) => ref Form(ref source, ref SU.Subtract(ref source, offset), site, true);
    public static ref T SubtractV<T>(ref T source, int offset, string site) => ref Value(ref source, ref SU.Subtract(ref source, offset), site);
    public static ref T SubtractV<T>(ref T source, nint offset, string site) => ref Value(ref source, ref SU.Subtract(ref source, offset), site);
    public static ref T SubtractV<T>(ref T source, nuint offset, string site) => ref Value(ref source, ref SU.Subtract(ref source, offset), site);

    public static ref T AddByteOffset<T>(ref T source, nint offset, string site) => ref Form(ref source, ref SU.AddByteOffset(ref source, offset), site, false);
    public static ref T AddByteOffset<T>(ref T source, nuint offset, string site) => ref Form(ref source, ref SU.AddByteOffset(ref source, offset), site, false);
    public static ref T AddByteOffsetKeep<T>(ref T source, nint offset, string site) => ref Form(ref source, ref SU.AddByteOffset(ref source, offset), site, true);
    public static ref T AddByteOffsetKeep<T>(ref T source, nuint offset, string site) => ref Form(ref source, ref SU.AddByteOffset(ref source, offset), site, true);
    public static ref T AddByteOffsetV<T>(ref T source, nint offset, string site) => ref Value(ref source, ref SU.AddByteOffset(ref source, offset), site);
    public static ref T AddByteOffsetV<T>(ref T source, nuint offset, string site) => ref Value(ref source, ref SU.AddByteOffset(ref source, offset), site);
    public static ref T SubtractByteOffset<T>(ref T source, nint offset, string site) => ref Form(ref source, ref SU.SubtractByteOffset(ref source, offset), site, false);
    public static ref T SubtractByteOffset<T>(ref T source, nuint offset, string site) => ref Form(ref source, ref SU.SubtractByteOffset(ref source, offset), site, false);
    public static ref T SubtractByteOffsetKeep<T>(ref T source, nint offset, string site) => ref Form(ref source, ref SU.SubtractByteOffset(ref source, offset), site, true);
    public static ref T SubtractByteOffsetKeep<T>(ref T source, nuint offset, string site) => ref Form(ref source, ref SU.SubtractByteOffset(ref source, offset), site, true);
    public static ref T SubtractByteOffsetV<T>(ref T source, nint offset, string site) => ref Value(ref source, ref SU.SubtractByteOffset(ref source, offset), site);
    public static ref T SubtractByteOffsetV<T>(ref T source, nuint offset, string site) => ref Value(ref source, ref SU.SubtractByteOffset(ref source, offset), site);

    /// <summary>Unsafe.As&lt;TFrom, TTo&gt;(ref x) used as a value (read or written): sizeof(TTo) bytes at x.</summary>
    public static ref TTo AsV<TFrom, TTo>(ref TFrom source, string site)
    {
        var a = PlankChecked.Addr(ref source);
        PlankChecked.Access(a, a, Size<TTo>(), "as-access", site);
        return ref SU.As<TFrom, TTo>(ref source);
    }

    public static T ReadUnaligned<T>(ref byte source, string site)
    {
        var a = PlankChecked.Addr(ref source);
        PlankChecked.Access(a, a, Size<T>(), "read", site);
        return SU.ReadUnaligned<T>(ref source);
    }

    public static T ReadUnaligned<T>(ref readonly byte source, string site, bool _ = false)
    {
        var a = PlankChecked.AddrRO(in source);
        PlankChecked.Access(a, a, Size<T>(), "read", site);
        return SU.ReadUnaligned<T>(in source);
    }

    public static T ReadUnaligned<T>(void* source, string site)
    {
        PlankChecked.Access((nuint)source, (nuint)source, Size<T>(), "read", site);
        return SU.ReadUnaligned<T>(source);
    }

    public static void WriteUnaligned<T>(ref byte destination, T value, string site)
    {
        var a = PlankChecked.Addr(ref destination);
        PlankChecked.Access(a, a, Size<T>(), "write", site);
        SU.WriteUnaligned(ref destination, value);
    }

    public static void WriteUnaligned<T>(void* destination, T value, string site)
    {
        PlankChecked.Access((nuint)destination, (nuint)destination, Size<T>(), "write", site);
        SU.WriteUnaligned(destination, value);
    }

    public static T Read<T>(void* source, string site)
    {
        PlankChecked.Access((nuint)source, (nuint)source, Size<T>(), "read", site);
        return SU.Read<T>(source);
    }

    public static void Write<T>(void* destination, T value, string site)
    {
        PlankChecked.Access((nuint)destination, (nuint)destination, Size<T>(), "write", site);
        SU.Write(destination, value);
    }

    public static void CopyBlock(ref byte destination, ref readonly byte source, uint byteCount, string site)
    {
        var d = PlankChecked.Addr(ref destination);
        var s = PlankChecked.AddrRO(in source);
        PlankChecked.Access(s, s, byteCount, "copy-read", site);
        PlankChecked.Access(d, d, byteCount, "copy-write", site);
        SU.CopyBlock(ref destination, in source, byteCount);
    }

    public static void CopyBlockUnaligned(ref byte destination, ref readonly byte source, uint byteCount, string site)
    {
        var d = PlankChecked.Addr(ref destination);
        var s = PlankChecked.AddrRO(in source);
        PlankChecked.Access(s, s, byteCount, "copy-read", site);
        PlankChecked.Access(d, d, byteCount, "copy-write", site);
        SU.CopyBlockUnaligned(ref destination, in source, byteCount);
    }

    public static void CopyBlock(void* destination, void* source, uint byteCount, string site)
    {
        PlankChecked.Access((nuint)source, (nuint)source, byteCount, "copy-read", site);
        PlankChecked.Access((nuint)destination, (nuint)destination, byteCount, "copy-write", site);
        SU.CopyBlock(destination, source, byteCount);
    }

    public static void CopyBlockUnaligned(void* destination, void* source, uint byteCount, string site)
    {
        PlankChecked.Access((nuint)source, (nuint)source, byteCount, "copy-read", site);
        PlankChecked.Access((nuint)destination, (nuint)destination, byteCount, "copy-write", site);
        SU.CopyBlockUnaligned(destination, source, byteCount);
    }

    public static void InitBlock(ref byte destination, byte value, uint byteCount, string site)
    {
        var d = PlankChecked.Addr(ref destination);
        PlankChecked.Access(d, d, byteCount, "init", site);
        SU.InitBlock(ref destination, value, byteCount);
    }

    public static void InitBlockUnaligned(ref byte destination, byte value, uint byteCount, string site)
    {
        var d = PlankChecked.Addr(ref destination);
        PlankChecked.Access(d, d, byteCount, "init", site);
        SU.InitBlockUnaligned(ref destination, value, byteCount);
    }

    public static void MemoryCopy(void* source, void* destination, long destinationSizeInBytes, long bytesToCopy, string site)
    {
        PlankChecked.Access((nuint)source, (nuint)source, (nuint)bytesToCopy, "copy-read", site);
        PlankChecked.Access((nuint)destination, (nuint)destination, (nuint)bytesToCopy, "copy-write", site);
        Buffer.MemoryCopy(source, destination, destinationSizeInBytes, bytesToCopy);
    }

    // ---- pointers ---------------------------------------------------------------------------------
    /// <summary>`*p` / `p->f`: sizeof(T) bytes at p.</summary>
    public static T* P<T>(T* pointer, string site) where T : unmanaged
    {
        PlankChecked.Access((nuint)pointer, (nuint)pointer, (nuint)sizeof(T), "deref", site);
        return pointer;
    }

    /// <summary>`p[i]`: sizeof(T) bytes at p + i, checked against p's span.</summary>
    public static T* At<T>(T* pointer, long index, string site) where T : unmanaged
    {
        var result = pointer + index;
        PlankChecked.Access((nuint)pointer, (nuint)result, (nuint)sizeof(T), "index", site);
        return result;
    }

    public static T* At<T>(T* pointer, ulong index, string site) where T : unmanaged
    {
        var result = pointer + index;
        PlankChecked.Access((nuint)pointer, (nuint)result, (nuint)sizeof(T), "index", site);
        return result;
    }

    public static T* At<T>(T* pointer, nint index, string site) where T : unmanaged => At(pointer, (long)index, site);
    public static T* At<T>(T* pointer, nuint index, string site) where T : unmanaged => At(pointer, (ulong)index, site);

    /// <summary>A pointer handed to a SIMD load/store of <paramref name="width"/> bytes.</summary>
    public static T* Width<T>(T* pointer, int width, string kind, string site) where T : unmanaged
    {
        PlankChecked.Access((nuint)pointer, (nuint)pointer, (nuint)width, kind, site);
        return pointer;
    }

    // ---- gathers: every lane is checked against the base pointer's span ------------------------------
    static void Lanes<TIndex>(nuint basePointer, ReadOnlySpan<TIndex> indexes, int count, int scale, int elementSize, string site)
        where TIndex : unmanaged, IBinaryInteger<TIndex>
    {
        for (var lane = 0; lane < count; lane++)
        {
            var index = long.CreateTruncating(indexes[lane]);
            var address = (nuint)((nint)basePointer + (nint)(index * scale));
            PlankChecked.Access(basePointer, address, (nuint)elementSize, "gather", site);
        }
    }

    static ReadOnlySpan<TIndex> AsSpan<TIndex, TVector>(ref TVector vector) where TIndex : unmanaged
        => SMM.CreateReadOnlySpan(ref SU.As<TVector, TIndex>(ref vector), SU.SizeOf<TVector>() / SU.SizeOf<TIndex>());

    // GatherVectorN(T* base, indexes, scale) loads (N / 8 / sizeof(T)) lanes, indexed by the first lanes of `indexes`;
    // the rewriter passes the result width in bytes.
    public static T* Gather<T>(T* basePointer, Vector128<int> indexes, byte scale, int resultBytes, string site) where T : unmanaged
    {
        if (PlankChecked.Enabled)
            Lanes((nuint)basePointer, AsSpan<int, Vector128<int>>(ref indexes), resultBytes / sizeof(T), scale, sizeof(T), site);
        return basePointer;
    }

    public static T* Gather<T>(T* basePointer, Vector128<long> indexes, byte scale, int resultBytes, string site) where T : unmanaged
    {
        if (PlankChecked.Enabled)
            Lanes((nuint)basePointer, AsSpan<long, Vector128<long>>(ref indexes), Math.Min(2, resultBytes / sizeof(T)), scale, sizeof(T), site);
        return basePointer;
    }

    public static T* Gather<T>(T* basePointer, Vector256<int> indexes, byte scale, int resultBytes, string site) where T : unmanaged
    {
        if (PlankChecked.Enabled)
            Lanes((nuint)basePointer, AsSpan<int, Vector256<int>>(ref indexes), resultBytes / sizeof(T), scale, sizeof(T), site);
        return basePointer;
    }

    public static T* Gather<T>(T* basePointer, Vector256<long> indexes, byte scale, int resultBytes, string site) where T : unmanaged
    {
        if (PlankChecked.Enabled)
            Lanes((nuint)basePointer, AsSpan<long, Vector256<long>>(ref indexes), Math.Min(4, resultBytes / sizeof(T)), scale, sizeof(T), site);
        return basePointer;
    }

    public static T* Gather<T>(T* basePointer, Vector512<int> indexes, byte scale, int resultBytes, string site) where T : unmanaged
    {
        if (PlankChecked.Enabled)
            Lanes((nuint)basePointer, AsSpan<int, Vector512<int>>(ref indexes), resultBytes / sizeof(T), scale, sizeof(T), site);
        return basePointer;
    }

    public static T* Gather<T>(T* basePointer, Vector512<long> indexes, byte scale, int resultBytes, string site) where T : unmanaged
    {
        if (PlankChecked.Enabled)
            Lanes((nuint)basePointer, AsSpan<long, Vector512<long>>(ref indexes), Math.Min(8, resultBytes / sizeof(T)), scale, sizeof(T), site);
        return basePointer;
    }

    // ---- vector loads/stores: the whole vector width is checked -----------------------------------------
    static void VecAccess<T>(ref readonly T source, nuint elementOffset, nuint width, string kind, string site)
    {
        var a = PlankChecked.AddrRO(in source);
        PlankChecked.Access(a, a + elementOffset * Size<T>(), width, kind, site);
    }

    public static Vector64<T> V64LoadUnsafe<T>(ref readonly T source, string site) { VecAccess(in source, 0, 8, "load64", site); return Vector64.LoadUnsafe(in source); }
    public static Vector64<T> V64LoadUnsafe<T>(ref readonly T source, nuint elementOffset, string site) { VecAccess(in source, elementOffset, 8, "load64", site); return Vector64.LoadUnsafe(in source, elementOffset); }
    public static Vector128<T> V128LoadUnsafe<T>(ref readonly T source, string site) { VecAccess(in source, 0, 16, "load128", site); return Vector128.LoadUnsafe(in source); }
    public static Vector128<T> V128LoadUnsafe<T>(ref readonly T source, nuint elementOffset, string site) { VecAccess(in source, elementOffset, 16, "load128", site); return Vector128.LoadUnsafe(in source, elementOffset); }
    public static Vector256<T> V256LoadUnsafe<T>(ref readonly T source, string site) { VecAccess(in source, 0, 32, "load256", site); return Vector256.LoadUnsafe(in source); }
    public static Vector256<T> V256LoadUnsafe<T>(ref readonly T source, nuint elementOffset, string site) { VecAccess(in source, elementOffset, 32, "load256", site); return Vector256.LoadUnsafe(in source, elementOffset); }
    public static Vector512<T> V512LoadUnsafe<T>(ref readonly T source, string site) { VecAccess(in source, 0, 64, "load512", site); return Vector512.LoadUnsafe(in source); }
    public static Vector512<T> V512LoadUnsafe<T>(ref readonly T source, nuint elementOffset, string site) { VecAccess(in source, elementOffset, 64, "load512", site); return Vector512.LoadUnsafe(in source, elementOffset); }
    public static Vector<T> VLoadUnsafe<T>(ref readonly T source, string site) { VecAccess(in source, 0, (nuint)Vector<byte>.Count, "loadV", site); return Vector.LoadUnsafe(in source); }
    public static Vector<T> VLoadUnsafe<T>(ref readonly T source, nuint elementOffset, string site) { VecAccess(in source, elementOffset, (nuint)Vector<byte>.Count, "loadV", site); return Vector.LoadUnsafe(in source, elementOffset); }

    public static void StoreUnsafe<T>(Vector64<T> v, ref T destination, string site) { VecAccess(in destination, 0, 8, "store64", site); v.StoreUnsafe(ref destination); }
    public static void StoreUnsafe<T>(Vector64<T> v, ref T destination, nuint elementOffset, string site) { VecAccess(in destination, elementOffset, 8, "store64", site); v.StoreUnsafe(ref destination, elementOffset); }
    public static void StoreUnsafe<T>(Vector128<T> v, ref T destination, string site) { VecAccess(in destination, 0, 16, "store128", site); v.StoreUnsafe(ref destination); }
    public static void StoreUnsafe<T>(Vector128<T> v, ref T destination, nuint elementOffset, string site) { VecAccess(in destination, elementOffset, 16, "store128", site); v.StoreUnsafe(ref destination, elementOffset); }
    public static void StoreUnsafe<T>(Vector256<T> v, ref T destination, string site) { VecAccess(in destination, 0, 32, "store256", site); v.StoreUnsafe(ref destination); }
    public static void StoreUnsafe<T>(Vector256<T> v, ref T destination, nuint elementOffset, string site) { VecAccess(in destination, elementOffset, 32, "store256", site); v.StoreUnsafe(ref destination, elementOffset); }
    public static void StoreUnsafe<T>(Vector512<T> v, ref T destination, string site) { VecAccess(in destination, 0, 64, "store512", site); v.StoreUnsafe(ref destination); }
    public static void StoreUnsafe<T>(Vector512<T> v, ref T destination, nuint elementOffset, string site) { VecAccess(in destination, elementOffset, 64, "store512", site); v.StoreUnsafe(ref destination, elementOffset); }
    public static void StoreUnsafe<T>(Vector<T> v, ref T destination, string site) { VecAccess(in destination, 0, (nuint)Vector<byte>.Count, "storeV", site); v.StoreUnsafe(ref destination); }
    public static void StoreUnsafe<T>(Vector<T> v, ref T destination, nuint elementOffset, string site) { VecAccess(in destination, elementOffset, (nuint)Vector<byte>.Count, "storeV", site); v.StoreUnsafe(ref destination, elementOffset); }
}
