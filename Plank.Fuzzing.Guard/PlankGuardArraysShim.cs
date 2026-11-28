// Compiled INTO the Plank library (Directory.Build.targets). With -p:PlankGuardArrays=true the build also rewrites
// `new T[n]` and `Array.Resize(ref x, n)` in the row-API buffer files (Plank/RowApi/*.cs, Dataset/DatasetBufferSlot.cs;
// copies in obj/, no library file is edited) to these methods. They behave exactly like the originals unless
// PLANK_FUZZ_GUARD=end|start is set and T has no references: then the array is a zeroed, page-guarded fake array
// (GuardCore.AllocateArray), so the generated row code's Unsafe.Add(ref GetArrayDataReference(column), index)
// writes past a slot's capacity fault (Plank #276 is the positive control). The arrays are released, and made
// PROT_NONE, when the harness ends the input (Plank.Fuzzing.GuardScope -> ReleaseScoped).
using System.Runtime.CompilerServices;

namespace Plank.GuardShim;

internal static class GuardArrays
{
    static readonly List<(object Array, GuardRegion Region, Action<object, GuardRegion> Release)> Scoped = [];
    static readonly object Gate = new();

    internal static int Outstanding
    {
        get
        {
            lock (Gate)
                return Scoped.Count;
        }
    }

    // Open harness scopes (Plank.Fuzzing.GuardScope). Memory allocated outside any scope has no end of input to be
    // released at (e.g. a seed parsed once and mutated many times), so it stays an ordinary array.
    static int _scopeDepth;

    internal static void EnterScope()
        => Interlocked.Increment(ref _scopeDepth);

    internal static void ExitScope()
        => Interlocked.Decrement(ref _scopeDepth);

    static bool Guarding<T>(int length)
        => GuardCore.Enabled && Volatile.Read(ref _scopeDepth) > 0 && length > 0 &&
           !RuntimeHelpers.IsReferenceOrContainsReferences<T>() && !InTypeInitializer();

    // Arrays built for static fields (e.g. `static readonly ulong[] Table = CreateTable();`) outlive the input whose
    // scope would release them, and the JIT reads static readonly arrays when it folds constants: a released one
    // crashed the JIT. Anything allocated under a static constructor stays an ordinary array.
    static bool InTypeInitializer()
    {
        var frames = new System.Diagnostics.StackTrace(2, false).GetFrames();
        foreach (var frame in frames)
            if (frame.GetMethod() is System.Reflection.ConstructorInfo { IsStatic: true })
                return true;
        return false;
    }

    public static T[] New<T>(int length)
    {
        if (!Guarding<T>(length))
            return new T[length];
        var owner = GuardCore.Trace ? $"plank-array {Environment.StackTrace.Replace('\n', '|')}" : "plank-array";
        var array = GuardCore.AllocateArray<T>(length, GuardCore.Mode, owner, out var region);
        array.AsSpan().Clear();
        lock (Gate)
            Scoped.Add((array, region, static (a, r) => GuardCore.ReleaseArray((T[])a, r)));
        return array;
    }

    public static void Resize<T>(ref T[]? array, int newSize)
    {
        if (!Guarding<T>(newSize))
        {
            Array.Resize(ref array, newSize);
            return;
        }

        var resized = New<T>(newSize);
        if (array is not null)
            array.AsSpan(0, Math.Min(array.Length, newSize)).CopyTo(resized);
        // Like Array.Resize the old array stays valid for whoever still holds it; it is released with the scope.
        array = resized;
    }

    /// <summary>
    /// Rewritten "grow only" checks (<c>buffer.Length &lt; needed</c>): in guard mode a buffer is re-rented whenever its
    /// length differs, so it always ends exactly where the data does and a read past it hits the guard page.
    /// </summary>
    public static bool Regrow(int currentLength, int neededLength)
        => GuardCore.Enabled ? currentLength != neededLength : currentLength < neededLength;

    /// <summary>Rewritten growth policies: the exact size in guard mode, the original capacity otherwise.</summary>
    public static int Capacity(int originalCapacity, int exactLength)
        => GuardCore.Enabled ? exactLength : originalCapacity;

    /// <summary>
    /// MemoryReadSource.TryBorrow: in guard mode the borrowed range is copied into its own exactly sized guarded array
    /// (released with the input), so a decoder reading past a page or section faults instead of reading the next
    /// page or the footer of the file.
    /// </summary>
    public static ReadOnlyMemory<byte> ExactBorrow(ReadOnlyMemory<byte> borrowed)
    {
        if (!GuardCore.Enabled || borrowed.IsEmpty || Volatile.Read(ref _scopeDepth) == 0)
            return borrowed;
        var owner = GuardCore.Trace ? $"plank-borrow {Environment.StackTrace.Replace('\n', '|')}" : "plank-borrow";
        var array = GuardCore.AllocateArray<byte>(borrowed.Length, GuardCore.Mode, owner, out var region);
        borrowed.Span.CopyTo(array);
        lock (Gate)
            Scoped.Add((array, region, static (a, r) => GuardCore.ReleaseArray((byte[])a, r)));
        return array;
    }

    /// <summary>Releases (PROT_NONE) every guarded array allocated since the last call: the end of a fuzz input.</summary>
    internal static void ReleaseScoped()
    {
        List<(object Array, GuardRegion Region, Action<object, GuardRegion> Release)> released;
        lock (Gate)
        {
            if (Scoped.Count == 0)
                return;
            released = [.. Scoped];
            Scoped.Clear();
        }

        foreach (var (array, region, release) in released)
            release(array, region);
    }
}
