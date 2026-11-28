// Compiled INTO the Plank library by Plank-Lab's Directory.Build.targets (no library file is edited).
// C# looks a simple name up in the enclosing namespaces before the using directives, so every
// `NativeMemory.AlignedAlloc/AlignedFree` written inside `namespace Plank...` binds to this class instead of
// System.Runtime.InteropServices.NativeMemory. With PLANK_FUZZ_GUARD unset it forwards to the real one; with
// PLANK_FUZZ_GUARD=end|start every native allocation the library makes itself (DefaultParquetBufferPool, including
// DefaultParquetBufferPool.Shared that every option object defaults to) gets its own page-guarded mapping.
// Members that are not shimmed fail to compile here, which is the signal to add them.
using Plank.GuardShim;

namespace Plank;

internal static unsafe class NativeMemory
{
    public static void* AlignedAlloc(nuint byteCount, nuint alignment)
    {
        if (!GuardCore.Enabled)
            return System.Runtime.InteropServices.NativeMemory.AlignedAlloc(byteCount, alignment);
        var owner = GuardCore.Trace ? $"plank-native {Environment.StackTrace.Replace('\n', '|')}" : "plank-native";
        return (void*)GuardCore.Allocate((long)byteCount, 0, (int)alignment, GuardCore.Mode, owner).Data;
    }

    public static void AlignedFree(void* pointer)
    {
        if (pointer == null)
            return;
        if (GuardCore.Enabled && GuardCore.FindLive((nint)pointer) is { } region)
        {
            GuardCore.Release(region);
            return;
        }

        System.Runtime.InteropServices.NativeMemory.AlignedFree(pointer);
    }
}
