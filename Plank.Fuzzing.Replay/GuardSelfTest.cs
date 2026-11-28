using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Plank.Reading;

namespace Plank.Fuzzing.Replay;

// `Plank.Fuzzing.Replay guard-selftest <case>` under PLANK_FUZZ_GUARD=end|start: each case makes one deliberate
// out-of-bounds access through one guard layer and must kill the process (AccessViolation or GUARD-VIOLATION).
// "ok" must survive. fuzz/tools/guard-selftest.sh runs them all.
static class GuardSelfTest
{
    public static int Run(string which)
    {
        if (!GuardMemory.Enabled)
        {
            Console.Error.WriteLine("guard-selftest needs PLANK_FUZZ_GUARD=end|start");
            return 2;
        }

        var end = GuardMemory.ModeName == "end";
        Console.WriteLine($"guard-selftest {which} mode={GuardMemory.ModeName}");
        Console.Out.Flush();
        switch (which)
        {
            case "ok":
            {
                // Every layer used within bounds, released, and a GC: must survive.
                using (var scope = GuardScope.Begin())
                {
                    var input = GuardMemory.ToArray(new byte[] { 1, 2, 3, 4, 5 });
                    using var source = new MemoryReadSource(input);
                    Span<byte> dst = stackalloc byte[5];
                    source.ReadExactly(0, dst);
                    var pool = new GuardBufferPool();
                    using var buffer = pool.Rent(13);
                    buffer.Span.Fill(7);
                    using var shared = DefaultParquetBufferPool.Shared.Rent(100);
                    shared.Span.Fill(9);
                    GC.Collect(2, GCCollectionMode.Forced, true, true);
                }
                GC.Collect(2, GCCollectionMode.Forced, true, true);
                Console.WriteLine($"ok: {GuardMemory.Allocations} guard allocations, {GuardMemory.Live} live");
                return 0;
            }
            case "pool":
            {
                using var buffer = new GuardBufferPool().Rent(13);
                Console.WriteLine(Peek(buffer.Span, end ? 13 : -33));
                break;
            }
            case "pool-write":
            {
                // Start mode puts the header before the data: a small underrun write lands in it, caught on return.
                var buffer = new GuardBufferPool().Rent(13);
                Poke(buffer.Span, end ? 13 : -1);
                buffer.Dispose();
                break;
            }
            case "shim":
            {
                // DefaultParquetBufferPool.Shared, through the library shim: 100 bytes round up to the 128 bucket.
                using var buffer = DefaultParquetBufferPool.Shared.Rent(100);
                Console.WriteLine($"capacity {buffer.Length}");
                Console.WriteLine(Peek(buffer.Span, end ? buffer.Length : -65));
                break;
            }
            case "input":
            {
                using var scope = GuardScope.Begin();
                var input = GuardMemory.ToArray(new byte[] { 1, 2, 3 });
                Console.WriteLine(Peek(input, end ? 3 : -25));
                break;
            }
            case "borrow":
            {
                // Needs -p:PlankGuardArrays=true: a borrowed range of an ordinary file array becomes an exact guarded
                // copy, so reading one byte past the range (into what would be the next page) faults.
                using var scope = GuardScope.Begin();
                using var source = new MemoryReadSource(new byte[100]);
                var tryBorrow = typeof(MemoryReadSource).GetMethod("TryBorrow",
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
                object?[] args = [10UL, 5, null];
                tryBorrow.Invoke(source, args);
                var borrowed = (ReadOnlyMemory<byte>)args[2]!;
                var span = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(borrowed.Span), borrowed.Length);
                Console.WriteLine(Peek(span, end ? 5 : -25));
                break;
            }
            case "uar":
            {
                var buffer = new GuardBufferPool().Rent(64);
                var span = buffer.Span;
                ref var first = ref MemoryMarshal.GetReference(span);
                buffer.Dispose();
                Console.WriteLine(first);
                break;
            }
            default:
                Console.Error.WriteLine($"unknown self-test {which}");
                return 2;
        }

        Console.WriteLine($"SELFTEST-SURVIVED {which}: the guard did not fire");
        return 1;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static byte Peek(Span<byte> span, int index)
        => Unsafe.Add(ref MemoryMarshal.GetReference(span), index);

    [MethodImpl(MethodImplOptions.NoInlining)]
    static void Poke(Span<byte> span, int index)
        => Unsafe.Add(ref MemoryMarshal.GetReference(span), index) = 0x42;
}
