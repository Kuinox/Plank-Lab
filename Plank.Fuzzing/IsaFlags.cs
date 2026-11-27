using System.Reflection;
using System.Reflection.Emit;

namespace Plank.Fuzzing;

/// <summary>
/// Flips the library's plain <c>static readonly bool</c> dispatch flags at run time, so both sides of
/// each CPU/layout decision are fuzzed on a single machine.
/// </summary>
/// <remarks>
/// Two kinds of hardware-gated dispatch exist in Plank. <c>Avx2.IsSupported</c>,
/// <c>Vector128.IsHardwareAccelerated</c> and friends are JIT intrinsics: they are folded to constants
/// at JIT time and only the <c>DOTNET_Enable*</c> environment variables change them (see
/// fuzz/notes/isa-dispatch.md). The flags listed here are ordinary static fields initialised by
/// the type initializer (CPUID model checks, "canonical nullable layout" probes), which the harness can
/// overwrite. The fields are <c>initonly</c>, so reflection refuses; a DynamicMethod that emits
/// <c>stsfld</c> is not subject to that check.
///
/// Caveat: the JIT folds the value of an initialised static readonly field into the compiled code. Tier 0 re-reads the
/// field, but methods marked AggressiveOptimization (most reader kernels) and promoted tier-1 methods keep the value they were
/// compiled with, so a flip inside a running process reaches only the methods still in tier 0. Prefer one mask per process
/// (<c>PLANK_FUZZ_ISA_MASK</c>, applied before anything is compiled, see <see cref="PrepareAggressivelyOptimizedMethods"/>) and
/// treat in-process flipping as best effort. Measured: an unpinned corpus run lost 18/18 lines of
/// <c>DecodeNullableInt32DictionaryNineBit</c> because some kernel's first call happened while a flag was inverted.
/// </remarks>
public static class IsaFlags
{
    sealed record Flag(string Name, FieldInfo Field, Action<bool> Set, bool Default);

    static readonly Flag[] Flags = Discover();

    public static int Count => Flags.Length;

    public static IReadOnlyList<string> Names => [.. Flags.Select(static f => $"{f.Field.DeclaringType!.Name}.{f.Name}")];

    static Flag[] Discover()
    {
        var assembly = typeof(Plank.Reading.Logical.ParquetReader).Assembly;
        (string Type, string Field)[] wanted =
        [
            ("Plank.Reading.Logical.Internal.ColumnChunkReader", "NullableDateTimeHasCanonicalLayout"),
            ("Plank.Reading.Logical.Internal.ColumnChunkReader", "NullableInt32HasCanonicalLayout"),
            ("Plank.Reading.Logical.Internal.ColumnChunkReader", "NullableInt64HasCanonicalLayout"),
            ("Plank.Reading.Logical.Internal.ColumnChunkReader", "NullableDoubleHasCanonicalLayout"),
            ("Plank.Reading.Logical.Internal.ColumnChunkReader", "UseScalarWideInt64Gather"),
            ("Plank.Reading.Logical.Internal.X86DecodeCapabilities", "UsePdep"),
            ("Plank.Writing.Encoding.Encoding", "HasCanonicalNullableInt64Layout"),
            ("Plank.Writing.Encoding.Encoding", "HasCanonicalNullableDoubleLayout"),
            ("Plank.Writing.Encoding.Encoding", "HasCanonicalNullableInt32Layout"),
        ];
        var result = new List<Flag>();
        foreach (var (typeName, fieldName) in wanted)
        {
            var type = assembly.GetType(typeName)
                ?? throw new InvalidOperationException($"IsaFlags: type {typeName} no longer exists; update the registry.");
            var field = type.GetField(fieldName, BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException($"IsaFlags: {typeName}.{fieldName} no longer exists; update the registry.");
            System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(type.TypeHandle);
            var method = new DynamicMethod($"set_{fieldName}", typeof(void), [typeof(bool)], type.Module, skipVisibility: true);
            var il = method.GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Stsfld, field);
            il.Emit(OpCodes.Ret);
            result.Add(new Flag(fieldName, field, method.CreateDelegate<Action<bool>>(), (bool)field.GetValue(null)!));
        }
        return [.. result];
    }

    static int current;

    /// <summary>The mask currently applied (bit i set = flag i inverted from its machine default).</summary>
    public static int Current => current;

    public static int AllMask => (1 << Flags.Length) - 1;

    /// <summary>Sets every flag to its default XOR the mask bit. Returns the previous mask.</summary>
    public static int Apply(int mask)
    {
        var previous = current;
        for (var i = 0; i < Flags.Length; i++)
            Flags[i].Set(Flags[i].Default ^ ((mask >> i) & 1) != 0);
        current = mask;
        return previous;
    }

    /// <summary>Applies <paramref name="mask"/> until disposed, then restores the previous mask.</summary>
    public static Scope Flip(int mask) => new(Apply(mask & AllMask));

    public readonly struct Scope(int previous) : IDisposable
    {
        public void Dispose() => Apply(previous);
    }

    /// <summary>
    /// Compiles every non-generic <c>AggressiveOptimization</c> method of the reader's decoder types now, with the flags as
    /// currently applied, so their folded flag values do not depend on which input happens to call them first.
    /// Generic instantiations cannot be prepared without a type argument and are still compiled lazily.
    /// </summary>
    public static void PrepareAggressivelyOptimizedMethods()
    {
        var assembly = typeof(Plank.Reading.Logical.ParquetReader).Assembly;
        foreach (var typeName in (string[])["Plank.Reading.Logical.Internal.ColumnChunkReader",
                     "Plank.Reading.Logical.Internal.DeltaBinaryPackedDecoder", "Plank.Reading.Logical.Internal.AlpDecoder",
                     "Plank.Reading.Logical.Internal.BooleanBitUnpacker"])
        {
            var type = assembly.GetType(typeName);
            if (type is null)
                continue;
            foreach (var method in type.GetMethods(BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public
                         | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            {
                if (method.IsGenericMethodDefinition || method.ContainsGenericParameters || method.IsAbstract
                    || !method.GetMethodImplementationFlags().HasFlag(MethodImplAttributes.AggressiveOptimization))
                    continue;
                try { System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod(method.MethodHandle); }
                catch (Exception) { /* a method that cannot be prepared is compiled lazily */ }
            }
        }
    }
}
