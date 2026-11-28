# Checked-access build (`-p:PlankCheckedAccess=true`)

Guard pages (Plank.Fuzzing.Guard) catch an access that leaves an *allocation*. They cannot see an over-read that
stays inside a larger valid buffer: past the end of a page payload inside a column-chunk buffer, past a slice of a
pooled buffer (pool buckets round sizes up), past a dictionary inside a bigger scratch array, past a vector's
logical end inside its padding. This build makes those throw.

Nothing is committed into `library/Plank`. At build time the Roslyn tool `Rewriter/` (run by Plank-Lab's
`Directory.Build.targets` just before the library's `CoreCompile`) builds a semantic model of the library sources,
runs `Plank.InternalGen` itself (so its generated delta-bit-unpacking decoder is rewritten too; the compiler then
stops running that generator), applies `hand-rewrites.txt`, rewrites every unchecked access and compiles the copies
(`obj/<cfg>/net10.0/checked-access/`, with `#line` directives so stack traces and sites keep library file:line).
`Runtime/` is its own assembly (`Plank.CheckedAccess.dll`, referenced by the checked library only): `C` (the checked
calls), `PlankChecked` (the region table), `PlankOobReadException`. Separate so SharpFuzz, which instruments
`Plank.dll`, does not instrument the region table's state-dependent loops (AFL would see unstable edges).

## What is rewritten

| Site | Becomes |
|---|---|
| `MemoryMarshal.GetReference(span)`, `GetArrayDataReference(array)`, `ref span[i]`/`ref array[i]` (primitive elements), `fixed (T* p = span/array/string)` | registers the logical span `[start, start + length)` of the ref/pointer |
| `MemoryMarshal.CreateSpan/CreateReadOnlySpan(ref r, n)` | checked: `n` elements from `r` must fit in `r`'s span; then registered |
| `Unsafe.Add/Subtract/AddByteOffset/SubtractByteOffset` forming a ref (`ref Unsafe.Add(...)`, a `ref` argument) | checked against the base's span, one-past-the-end allowed; the derived ref inherits the span |
| the same used as a value (`x = Unsafe.Add(ref r, i)`, `Unsafe.Add(ref r, i) = v`) | checked: `sizeof(T)` bytes |
| `Unsafe.ReadUnaligned/WriteUnaligned/Read/Write<T>`, `Unsafe.As<TFrom,TTo>(ref x)` used as a value | checked: `sizeof(T)` / `sizeof(TTo)` bytes |
| `Vector64/128/256/512/Vector.LoadUnsafe/StoreUnsafe` (static and extension forms) | checked for the whole vector width |
| pointer `*p`, `p[i]` (primitive pointee), X86 `Load*/Store*` taking pointers | checked for the element / vector width |
| `Avx2.GatherVector*` | every lane's address is checked against the base pointer's span |
| `Unsafe.CopyBlock*/InitBlock*`, `Buffer.MemoryCopy` | both ranges checked |
| `new Span<T>(void*, int)` | registered only (raw pointer: no provenance) |

Hand rewrites (`hand-rewrites.txt`, exact text, same line count, fail the build when they stop matching):
`ParquetBuffer` views register the buffer's own `_length` (the root of every native buffer and of every
`RetainSlice`), the binary payload address computations register the payload area so `BinaryValueDescriptor.GetSpan`
is checked against it, and the row-API `GetCurrent<T>` fast path carries and checks its batch length.

The rewriter's per-site report is `obj/.../checked-access/sites.tsv` (site, API, action, argument);
`fuzz/notes/unchecked-access-sites.md` is the reviewed inventory, including what is *not* checked.

## How spans are tracked (and the limits)

A `ref T` carries no length, so the runtime keeps per-thread tables keyed by address: registrations (ring of 128),
derived refs handed straight to a checked call (hints), and a global table of native roots (ParquetBuffer views,
payload areas). The newest exact-start match of an access's *base* ref wins. Then:

- strong match: violation -> `PLANK-OOB <message>` on stderr and `PlankOobReadException` (with
  `PLANK_CHECKED_FAILFAST=1`, `Environment.FailFast`, which is what AFL needs to see a crash);
- weak match (only a region *containing* the base was found): `PLANK-OOB-WEAK` on stderr, thrown only with
  `PLANK_CHECKED_WEAK=throw` (triage aid: these can be stale registrations);
- no match: not checked (counted; `PLANK_CHECKED_STATS=1` prints checked/weak/unknown/violation counts at exit).

Managed buffers can move in a GC, so managed registrations are tagged with `GC.CollectionCount(0)` and ignored after a
GC: run with a large gen0 budget (`DOTNET_GCgen0size=0x10000000`) to keep most accesses checked.
`PLANK_CHECKED=0` disables every check in the same binary.

## Running

```
agents-style build: dotnet build Plank.Fuzzing.Replay -c Release -p:PlankCheckedAccess=true -p:RunAnalyzers=false
bash fuzz/tools/checked-campaign.sh <replay.tgz> <out> <tier> <reader-mutants> <writer-mutants> <seed-base>
```

AFL: build `Plank.Fuzzing.Reader.Target` / `Plank.Fuzzing.Target` with `-p:PlankCheckedAccess=true` and run them with
`PLANK_CHECKED_FAILFAST=1 DOTNET_GCgen0size=0x10000000`: a violation is `Environment.FailFast` (SIGABRT), an AFL crash,
with the `PLANK-OOB` message on stderr. Replaying a saved crash through `checked-replay.py` prints the same line.

Positive control: `fuzz/tools/checked-positive-control.patch` (applied to a throwaway copy of library/Plank only)
adds one deliberate +1 over-read; the control seeds must report `PLANK-OOB`.
