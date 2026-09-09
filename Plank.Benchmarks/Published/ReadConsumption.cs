using System.Runtime.CompilerServices;

namespace Plank.Benchmarks;

static class ReadConsumption
{
    // The opaque call makes the decoded storage escape the caller without walking
    // it. Keep this non-inlined: an inlined empty body would allow dead-code removal.
    // Call only after driving the reader to produce the entire buffer.
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static void Consume<T>(ReadOnlySpan<T> values) { }
}
