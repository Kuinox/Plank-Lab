using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
// 92 bytes, like Plank's ParquetSchemaNodeInfo: ints, a nullable int and a nested struct with nullables.
readonly struct Inner { public readonly int A; public readonly int? B; public readonly sbyte? C; public readonly bool D; public readonly int E, F; }
readonly struct S { public readonly int O, P; public readonly byte K, R; public readonly int? T; public readonly uint L; public readonly Inner I; public readonly int N, M, C; public readonly int? F; }
readonly struct Plain92 { public readonly long A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10; public readonly int Tail; }
unsafe static class P {
  [DllImport("libc")] static extern nint mmap(nint a, nuint l, int p, int f, int fd, nint o);
  [DllImport("libc")] static extern int mprotect(nint a, nuint l, int p);
  [MethodImpl(MethodImplOptions.NoInlining)] static int UseS(S s) => s.N + s.M;
  [MethodImpl(MethodImplOptions.NoInlining)] static long UseP(Plain92 s) => s.A0 + s.Tail;
  static nint EndOfPage(int size) { var m = mmap(0, 8192, 3, 0x22, -1, 0); mprotect(m + 4096, 4096, 0); return m + 4096 - size; }
  static void Main(string[] a) {
    Console.WriteLine($"sizeof S={sizeof(S)} Plain92={sizeof(Plain92)}"); Console.Out.Flush();
    if (a[0] == "s") { var p = EndOfPage(sizeof(S)); var span = new ReadOnlySpan<S>((void*)p, 1); Console.WriteLine(UseS(span[0])); }
    else { var p = EndOfPage(sizeof(Plain92)); var span = new ReadOnlySpan<Plain92>((void*)p, 1); Console.WriteLine(UseP(span[0])); }
    Console.WriteLine("survived");
  }
}
