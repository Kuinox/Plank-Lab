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

    static bool Guarding<T>(int length)
        => GuardCore.Enabled && length > 0 && !RuntimeHelpers.IsReferenceOrContainsReferences<T>();

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
