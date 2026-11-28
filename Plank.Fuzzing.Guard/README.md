# Guard-page allocator (a poor man's ASan for Plank)

.NET has no AddressSanitizer, and Plank's hot paths use `Unsafe.Add`, `MemoryMarshal.GetReference`, pointers and
native memory, where a bounds bug neither throws nor (in the small cases the oracles check) changes decoded values.
`PLANK_FUZZ_GUARD` makes such bugs fault deterministically.

```
PLANK_FUZZ_GUARD=end     # (or 1) every guarded buffer ENDS exactly at a PROT_NONE page   -> overruns fault
PLANK_FUZZ_GUARD=start   # every guarded buffer STARTS right after a PROT_NONE page       -> underruns fault
PLANK_FUZZ_GUARD_TRACE=1 # log GUARD-ALLOC / GUARD-FREE (address range, length, owner stack) to stderr
```

Each allocation is its own `mmap`, with one PROT_NONE page on the guarded side: `[RW][guard]` (end) or `[guard][RW]` (start). The unguarded side of the RW window
is filled with a canary (0xCD) that is checked on release (catches small writes on that side); the data itself also
starts as 0xCD (never zero). On release the window is poisoned (0xDB), made PROT_NONE and kept in a 64 MiB / 4096
entry quarantine, so use-after-release faults. A fault in managed code is a fatal
`System.AccessViolationException` with the managed stack (no `catch` can swallow it); in native code (zlib) a
SIGSEGV. A canary or header violation prints `GUARD-VIOLATION ...` and FailFasts. The replay driver prints
`GUARD-INPUT <file>` before each input, the AFL harness writes the current input to
`/tmp/plank-fuzz-<target>-guard-current.bin` first, so the culprit is always known.

## What is guarded

| Memory | How | Exact? |
|---|---|---|
| Every `DefaultParquetBufferPool` allocation, including `DefaultParquetBufferPool.Shared` that every options object defaults to | `PlankNativeMemoryShim.cs` is compiled **into Plank.dll** by `../Directory.Build.targets` (no library file is edited): C# binds `NativeMemory.AlignedAlloc/AlignedFree` inside `namespace Plank` to `Plank.NativeMemory` before the `using`. Off when the env var is unset (forwards to the real one). `-p:PlankGuardShim=false` leaves the library untouched. | Ends at the bucket **capacity** (power of two), which is the buffer's real `Length`; buffers the pool retains stay RW (pool reuse is not use-after-free) |
| Reader target pool (`PlankReaderFuzzTarget.Execute`), `ExactFitBufferPool`, `WriterFuzzPool` (all kinds) | `GuardBufferPool`: every rent is a fresh mapping of exactly the requested length, header right before it; on return the header is checked, the buffer poisoned and PROT_NONE'd | Exact (end mode) |
| Harness canary pools `TrackingPool` (execution target), `PoisonPool` (lifetime cases) | `GuardMemory.AllocHGlobal`: the whole block (incl. its 64 trailing canary bytes) ends at the guard page | Past the 64-byte canary |
| Reader input file bytes (`data[1..]`, every probe's `payload`/`fileBytes` copy) and the replay/AFL input itself | `GuardMemory.ToArray`: a **real `byte[]`** whose elements end (start) at the guard page, built outside the GC heap (sync block + MethodTable + length written by hand). `MemoryMarshal.TryGetArray` succeeds, so `MemoryReadSource`'s zero-copy borrow path is guarded too. Released at the end of the input (`GuardScope`) | Exact |
| Writer value inputs of the generic writer route (`PlankWriterFuzzTarget.SerializeColumn`: `bool/int/long/float/double` and their nullables, `IntBox/LongBox?/DoubleBox?`, and every `byte[]` value of `byte[][]`) | `GuardMemory.ToArray<T>`: guarded fake arrays (any value type without references, `Nullable<T>` included) | Exact |
| Native-memory sources | `GuardMemory.NativeCopy`: `ReadOnlyMemory<byte>` over a `MemoryManager<byte>` (forces the copy path) | Exact |

The fake arrays were checked against forced compacting gen-2 GCs while referenced from heap objects, also after
being made PROT_NONE: the GC never touches objects outside its heap ranges.

## What is not guarded (and why)

- Managed arrays Plank allocates itself: `new byte[n]` fallbacks next to `stackalloc` (ColumnChunkReader,
  BloomFilterBuilder, ByteStreamSplitEncoding, DeltaBinaryPackedEncoding, PhysicalSchemaBinder),
  `ParquetDecompressor` (`new byte[expectedLength]`), and all `stackalloc` buffers (~60 sites, all fixed small sizes or
  `<= 256` guards). The CLR bounds-checks safe span indexing; only `Unsafe`/pointer access past them goes unseen.
- Value arrays the ~270 other `Serialize(...)` call sites in the writer case files build (only the generic writer
  route's `SerializeColumn` is wired); `string[]`/`object` values (references cannot live outside the GC heap).
- Writer output read back from `MemoryStream.ToArray()` by writer/merger/dataset round trips (reads of it go
  through pool buffers, which are guarded; the borrow path over those arrays is not).
- K4os.Compression.LZ4's own state (`Mem.Alloc` = AllocHGlobal, `ArrayPool<byte>.Shared`); its decoders read and
  write Plank's (guarded) buffers.
- Underruns of fewer than `sizeof(ParquetBufferHeader)` (32) bytes in start mode: they land in the header, which is
  checked on return (writes only).

## Self-test

`fuzz/tools/guard-selftest.sh <replay bin dir>` makes one deliberate out-of-bounds access per layer and mode and
expects each to kill the process (`ok` must survive).

## Running it

Replay (any route, any seed or queue directory; survives deaths and resumes after the culprit):

```
python3 -I fuzz/tools/guard-replay.py <replay bin dir> <out dir> <reader|writer|merger|both> <end|start> \
    <default|avx2|sse|scalar|isaflip> <dir-or-file>...
bash fuzz/tools/guard-campaign.sh <replay.tgz> <out> <end|start> <tier> <reader mutants> <writer mutants> <seed base>
```

Deaths land in `<out>/deaths/<target>-<mode>-<tier>-<hash>/` (`input.bin`, `log.txt` with the AccessViolation stack).
Routes of the known #276 bug (`RWG1/RWN1/RWW1/RWD1`) are skipped: they corrupt memory even without guard mode.

AFL (`Plank.Fuzzing.Target`, `Plank.Fuzzing.Reader.Target` built from this tree): export `PLANK_FUZZ_GUARD=end`
(or `start`) and `PLANK_FUZZ_GUARD_TAG=<worker name>`. Before each execution the harness writes the input to
`/tmp/plank-fuzz-<target>-<tag>-guard-current.bin` and empties it afterwards. A guard fault kills the worker (AFL
reports the fork server gone and the job loop restarts it); on start-up a non-empty file is saved to
`PLANK_FUZZ_CRASH_DIR` as `guard-<target>-<hash>.bin` (`GUARD-DEATH-RECOVERED` on stderr). Hangs that AFL kills
mid-input land there too: replay to tell them apart. Expect 2-5x slower executions (one mmap/mprotect per buffer).

Inputs that keep more than 25,000 buffers alive at once (vm.max_map_count is 65,530; each guarded buffer is two
mappings) get canary-only heap memory past that point: `GUARD-DEGRADED` on stderr, once per process.

## Known false positive: the JIT with hardware intrinsics off

With `DOTNET_EnableHWIntrinsic=0`, the JIT over-reads a by-value struct whose size is 4 mod 8 (Plank's 92-byte
`ParquetSchemaNodeInfo`) by 4 bytes, which faults on an exactly placed buffer. Reproduced without Plank in
`fuzz/repros/dotnet-jit-struct-overread/`. `guard-replay.py`'s scalar tier therefore sets `PLANK_FUZZ_GUARD_SLACK=8` (overruns of up to 8 bytes go unseen in that tier).
