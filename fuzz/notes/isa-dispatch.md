# Hardware-gated dispatch in Plank (2026-11-27)

Code that only runs on some CPUs is invisible to a campaign on one machine. Our machines: **ovh** (x64, AVX2 + BMI2, **no AVX512**, Intel family 6
model 158, so `UseScalarWideInt64Gather` is true there), **nas** (x64, no AVX512), **s10e** (arm64 phone, kernel 4.14; no .NET toolchain worth running).
This note inventories every dispatch decision under `library/Plank/Plank`, says which side each tier reaches, and which side no available machine reaches.

## Two kinds of decision

| kind | examples | who can flip it | how |
|---|---|---|---|
| **JIT intrinsic** (folded to a constant at JIT time) | `Avx2.IsSupported`, `Avx512F.IsSupported`, `Bmi2.X64.IsSupported`, `AdvSimd.IsSupported`, `Vector128/256/512.IsHardwareAccelerated`, `Vector.IsHardwareAccelerated`, `Vector<T>.Count` | the **process environment only** | `DOTNET_EnableAVX2=0`, `DOTNET_EnableBMI2=0`, `DOTNET_EnableAVX512F=0`, `DOTNET_EnableHWIntrinsic=0`, `DOTNET_PreferredVectorBitWidth=128` (a restart per tier) |
| **plain `static readonly bool`** (set by a type initializer, CPUID probe or layout probe) | the 9 flags in `Plank.Fuzzing/IsaFlags.cs` | the harness, per input | `IsaFlags.Flip(mask)` (a `DynamicMethod` emitting `stsfld`, because reflection refuses `initonly`) |
| platform constants | `BitConverter.IsLittleEndian`, `RuntimeInformation.ProcessArchitecture/OSDescription` | nobody here | big-endian and non-x64/arm64 branches are unreachable |

**JIT caveat for `IsaFlags` (measured).** The JIT folds the value of an initialised static readonly into compiled code. Tier 0 re-reads it, but methods
marked `[MethodImpl(AggressiveOptimization)]` (18 in `ColumnChunkReader.EncodedBatching.cs`, 23 in `ColumnChunkReader.cs`, 9 in `DeltaBinaryPackedDecoder.cs`) are compiled once, fully
optimised, at their first call and keep whatever the flag was at that moment; promoted tier-1 methods likewise. A per-input flip therefore reaches only methods still in
tier 0, and which ones those are depends on history — an unpinned run lost `DecodeNullableInt32DictionaryNineBit` (18/18 lines) that way. Hence:

* the flag mask is **per process**: `PLANK_FUZZ_ISA_MASK=<hex>|all` is applied before anything is compiled, and the non-generic AggressiveOptimization methods are compiled
  immediately under it (`IsaFlags.PrepareAggressivelyOptimizedMethods`); give each AFL worker / coverage tier its own mask (default `0`, plus `all`);
* `PLANK_FUZZ_ISA_RANDOM=1` re-enables per-input random flips (diagnostic only: coverage becomes history-dependent);
* `IsaDifferential` (default flags vs all inverted, same input, every file-schema run) is best effort for the same reason: it is exact for tier-0 methods and for whatever
  the process mask selected, and compares two identical decodes otherwise, which cannot produce a false positive.

Verified on `gen-gap-i64-dictopt-full-300000.bin`: with mask `0` only `DecodeDictionaryLiteralInt64IndexesWideScalar` runs (20/31 lines), with mask `all` only
`DecodeDictionaryLiteralInt64IndexesWide` runs (20/31 lines).

## The 9 flippable flags (all `static readonly bool`)

| flag | file | machine default (ovh) | `false`/inverted side | what flips |
|---|---|---|---|---|
| `NullableDateTimeHasCanonicalLayout` | `Reading/Logical/Internal/ColumnChunkReader.cs:18` | true | vector DateTime expand kernels off (`Avx2` 974, `Vector128` 993/1590, 1545) | scalar fallback for optional DateTime |
| `NullableInt32HasCanonicalLayout` | same :19 | true | nullable Int32 vector expand (948), RLE 8/9-bit dictionary byte unpackers (EncodedBatching 997/630) | scalar |
| `NullableInt64HasCanonicalLayout` | same :20 | true | Int64 nullable expand AVX2/Vector128 (1416/1443) | scalar |
| `NullableDoubleHasCanonicalLayout` | same :21 | true | Double nullable expand | scalar |
| `UseScalarWideInt64Gather` | same :22 (`HasIntelFamily6Model158`) | **true on ovh** (model 158) | **false** reaches `DecodeDictionaryLiteralInt64IndexesWide` (19/20-bit gather) | AVX2 gather vs scalar gather |
| `X86DecodeCapabilities.UsePdep` | `Reading/Logical/Internal/X86DecodeCapabilities.cs:9` | true (Intel) | false = the AMD Zen1/2 "slow PDEP" side | PDEP bit-extract vs non-PDEP unpack in the Delta decoder and 11-bit dictionary paths |
| `Encoding.HasCanonicalNullableInt64Layout` | `Writing/Encoding/Encoding.cs:24` | true | scalar nullable Int64 write | writer |
| `Encoding.HasCanonicalNullableDoubleLayout` | same :25 | true | scalar nullable Double write | writer |
| `Encoding.HasCanonicalNullableInt32Layout` | same :26 | true | scalar nullable Int32 write | writer |

The reader target applies the process mask (`PLANK_FUZZ_ISA_MASK`), and on the file-schema route additionally decodes each flat column twice — all flags at default, then all inverted — and requires identical values and the same
verdict on corruption (`IsaDifferential`, reported as a "Decoded value mismatch (ISA flags)"). `PLANK_FUZZ_ISA_MASK=<hex>|all` selects the side for a whole process (replay/coverage, or one AFL worker). The three writer flags are in the registry but the writer target does not use them yet (writer owner: call
`IsaFlags.Flip(mask)` around `PlankWriterFuzzTarget.Execute` and write the same table with both settings; the bytes must be identical).

## Environment-gated intrinsics: which tier reaches which side

`D` = host default (AVX2+BMI2, no AVX512), `A` = `DOTNET_EnableAVX2=0`, `S` = `DOTNET_EnableHWIntrinsic=0`, `B` = `DOTNET_EnableBMI2=0`, `V` = `DOTNET_PreferredVectorBitWidth=128`.
"never" = no tier on ovh/nas reaches it.

### Reader

| decision | site | true side | reached by | false side reached by |
|---|---|---|---|---|
| `Avx2.IsSupported` (+ `Bmi2.X64`, `UsePdep`) | `DeltaBinaryPackedDecoder.cs` 364–461, 1085–1136 (PDEP/AVX2 mini-block unpackers) | AVX2 kernels | D | A, S, B (BMI2 gating), `UsePdep` inverted |
| `Avx2.IsSupported && Bmi2.X64` | `ColumnChunkReader.cs` 3801, 3814, 3965, 4060; `EncodedBatching.cs` 344, 630 (RLE/dictionary index unpack) | PDEP kernels | D | A, B, S |
| `Avx2.IsSupported` | `ColumnChunkReader.cs` 3166, 3843 (BSS, wide gather) | AVX2 | D | A, S |
| `Avx512F.IsSupported` | `ColumnChunkReader.cs` 3151, 3258 (BSS float/double interleave) | **AVX512 kernels: never** | — | D |
| `Vector512.IsHardwareAccelerated` | `BooleanBitUnpacker.cs` 55 | **never** | — | D |
| `Vector256.IsHardwareAccelerated` | `BooleanBitUnpacker.cs` 75; `DeltaBinaryPackedDecoder.cs` 1260; `ColumnChunkReader.cs` 3283 | AVX2 width | D | V (falls to Vector128), A, S |
| `Vector128.IsHardwareAccelerated` | `BooleanBitUnpacker.cs` 93; `DeltaBinaryPackedDecoder.cs` 1282; `ColumnChunkReader.cs` 1108, 3181, 3814 | SSE/NEON width | D, V, A | S |
| `Vector.IsHardwareAccelerated` / `Vector<T>.Count` | `ColumnChunkReader.cs` 948, 3281–3463; `.Timestamps.cs` 132 | 256-bit (`Vector<T>` = 32 bytes on AVX2) | D | V (16 bytes), S |
| `System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported` | `EncodedBatching.cs` 1012 (+ `ColumnChunkReader.cs` ARM branches) | **ARM64 kernels: never** (s10e is arm64 but has no usable toolchain) | — | D |
| `X86Base.IsSupported` + CPUID | `ColumnChunkReader.HasIntelFamily6Model158`, `X86DecodeCapabilities.HasSlowPdep` | CPU-model decisions | now **both sides** via `IsaFlags` | |
| `SplitBlockBloomFilter.cs:39 Avx2.IsSupported` | bloom insert/probe | AVX2 | D | A, S |
| `BitConverter.IsLittleEndian` | ~20 sites in `ColumnChunkReader.cs`, `DeltaBinaryPackedDecoder.cs:992` | little-endian fast paths | D | **big-endian side: never** (all the `ReverseEndianness` branches) |
| `RuntimeInformation` | `Compression/ZlibLibraryResolver.cs` 38/136/137 | host OS/arch lookup paths | D (Linux x64) | **other OS/arch candidate lists: never** (`GetSystemLibraryCandidates`, Windows/macOS/arm64 RID probing) |

### Writer (inventory only; the writer target is not mine)

`Avx512F` (PlainEncoding 173/221, DeltaBinaryPackedEncoding 160/202/242/501, ByteStreamSplitEncoding 345/408), `Vector512` (RleBitPackingHybridEncoding 207/247/283/335,
EncodingPrimitives 226) — **never**. `AdvSimd`/`AdvSimd.Arm64` (PlainEncoding 414/518/560, Encoding.cs 249/264/1083/1108/1143/1804/1847) — **never**. `Avx2`/`Vector256`/
`Vector128`/`Vector<T>` sides are reached by D, A, S, V as for the reader; `!Vector256.IsHardwareAccelerated && Vector128` (RleBitPackingHybrid 309/361, EncodingPrimitives 241,
ByteStreamSplitEncoding 322/381) needs V or A. `Encoding.Has*Layout` — flippable (above). `MinMaxScan` 44/115, `TimestampConversion` 177 — Vector256: D vs A/S.
`ParquetExecutionOptions.WorkerCount = Environment.ProcessorCount` — differs per machine; fuzz targets pin it (1) on purpose, so the multi-worker scheduling is only
covered by the `PLANK_FUZZ_ENABLE_ROW_WORKERS=1` probes.

## What the coverage tiers measured

Reader replay (14,564 inputs: generated gap corpus, reader-corpus, pyarrow, footer, parquet-testing seeds), branch coverage of Reading + BloomFilters +
Compression on library 3a6a28a, coverlet, one run per tier; 0 faults and 0 oracle/ISA-differential mismatches in every tier.

| tier | env | branches |
|---|---|---|
| default (AVX2+BMI2) | — | 74.7 % |
| flags inverted | `PLANK_FUZZ_ISA_MASK=all` | 73.0 % |
| AVX2 off (SSE/Vector128) | `DOTNET_EnableAVX2=0` | 71.1 % |
| AVX2 off + flags inverted | both | 70.7 % |
| 128-bit vectors | `DOTNET_PreferredVectorBitWidth=128` | 74.7 % |
| scalar | `DOTNET_EnableHWIntrinsic=0` | 69.8 % |
| scalar + flags inverted | both | 69.6 % |
| **union of the env tiers only** | | **75.4 %** |
| **union of everything** | | **75.8 %** |

The flags tiers add 0.4 points that no environment tier reaches: `DecodeDictionaryLiteralInt64IndexesWide` (the 19/20-bit AVX2 gather that `UseScalarWideInt64Gather`
hides on model 158), `DecodeInt64MiniBlockBmi2` / the non-PDEP side of the Delta unpackers, and the scalar nullable-layout fallbacks with AVX2 still on.
`DOTNET_EnableBMI2=0` changes nothing (74.4 % = default): the switch is ignored on .NET 10, as `run-fleet.sh` already noted.

## Still unreachable on our hardware (ovh/nas x64 AVX2, no AVX512; phone arm64 has no usable toolchain)

* **AVX-512 kernels** — `Avx512F.IsSupported` / `Vector512.IsHardwareAccelerated`: reader `ColumnChunkReader.cs` ~3151 and ~3258 (byte-stream-split interleave) and
  `BooleanBitUnpacker.cs` 55; writer `PlainEncoding`, `DeltaBinaryPackedEncoding`, `ByteStreamSplitEncoding`, `RleBitPackingHybridEncoding`, `EncodingPrimitives`.
  `DOTNET_EnableAVX512F=0` can only turn them *off*; nothing here turns them on.
* **ARM64 / AdvSimd kernels** — `EncodedBatching.cs` ~1012 (nullable dictionary unpack), reader/writer `ExtractOptionalDoubleValuesAdvSimd`-style helpers, `PlainEncoding` 414/518/560,
  `Encoding.cs` 249/264/1083/1108/1143/1804/1847.
* **Big-endian branches** — every `!BitConverter.IsLittleEndian` / `ReverseEndianness` arm (~40 sites).
* **`ZlibLibraryResolver.GetSystemLibraryCandidates` and the non-Linux/non-x64 RID lists** — host-OS dependent.
* **`DecodeNullableInt32DictionaryNineBitPortable` (43 lines) and `DecodeDictionaryLiteral11BitPortable`** — still 0/43 in every tier including scalar; the call site is gated on
  `System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported` (EncodedBatching ~1012), i.e. ARM64 only.
* **`DecodeNullableInt32MiniBlockAvx2` (0/9)** — guarded by a layout/ISA combination no tier produced; looks like dead code behind `NullableInt32HasCanonicalLayout && Avx2` with a non-PDEP side
  that needs inverted `UsePdep` *and* the nullable path, worth a targeted seed.
* **AMD Zen 1/2 PDEP behaviour itself** — only the *code side* is reachable now (`UsePdep` inverted); the microarchitecture performance reason is irrelevant to correctness.
* Not hardware gated but still zero: `TryDecodeConvertedRequired*` (probably dead), `IsIndexedEmptyDataPage` (Arrow GH-54533 file), `GetPlainBinaryBatchEncodedLength`, `SplitBlockBloomFilter.InsertHash`.

## Fleet

`fuzz/run-fleet.sh` now gives worker-04 `DOTNET_EnableAVX512=0 PLANK_FUZZ_ISA_MASK=all`, and the rotation tiers (`PLANK_FUZZ_ROTATE_ISA`) gained the two flags-inverted tiers.

## AVX-512 tier (kuinox-desktop, Ryzen 9 7900X) — pending

Not measured yet: the desktop was in use, interactive commands there were killed, and the Kueue queue `kuinox-desktop-worker` reported "inactive" / "insufficient unused quota",
so `job-24574813-reader-avx512-039359` (2 cpu, 5 Gi; the queue caps memory at 6 Gi) was still queued when this was written. The job is restart-safe: `fuzz/tools-reader-coverage/avx512-job.sh`
(copy it with the replay build under `agents/reader-c/rp-avx`, adjust the paths at the top) skips finished tiers, and writes to `agents/reader-c/avx512/`:

* `dg-avx512.txt`, `dg-avx512-flagsall.txt`, `dg-avx2.txt` (AVX-512 switched off), `dg-scalar.txt` — one `input-hash<TAB>decode-digest` line per file-schema input
  (`PLANK_FUZZ_DIGEST_FILE`, `IsaDifferential.AppendDigest`);
* `cov-avx512.xml`, `cov-avx512-flagsall.xml`, `cov-avx2.xml` — coverlet reports for the reader replay.

When it finishes: `fuzz/tools-reader-coverage/digest-compare.sh dg-avx512.txt dg-scalar.txt` (and `dg-avx2.txt`) must print no `DIFF` lines — that is the scalar-vs-AVX-512
differential for every kernel gated on `Avx512F.IsSupported` / `Vector512.IsHardwareAccelerated`; `covunion.py` on the cobertura files against the ovh tiers gives the AVX-512-only methods
(expected: the byte-stream-split interleave around `ColumnChunkReader.cs` 3151/3258 and `BooleanBitUnpacker.cs` 55). Fill the numbers in here.
The same digest files also give a cross-ISA differential on ovh today: the existing AVX2/scalar tiers can be compared with `PLANK_FUZZ_DIGEST_FILE` runs.

### Cross-ISA differential measured on ovh (digest files)

`PLANK_FUZZ_DIGEST_FILE` replays of the same 14,562-input corpus under five environments, compared with `digest-compare.sh` against the native AVX2 run
(2,884 distinct file contents decoded through the file-schema route, flat columns as `T` and `T?`, values via invariant formatting): **no differing digest** for
`DOTNET_EnableAVX2=0`, `DOTNET_EnableHWIntrinsic=0` (scalar), `DOTNET_PreferredVectorBitWidth=128` and `PLANK_FUZZ_ISA_MASK=all`. So the SSE, scalar, 128-bit-vector
and inverted-flag decoders agree with the AVX2/PDEP ones on everything we have. The same replays report 10 *oracle* mismatches in every tier (statistics "Plank lost a min/max
Arrow reads" on parquet-testing decimal/string/nested seeds, `repeated_no_annotation` row count) — those come from the full-value oracle (another agent's), are ISA-independent, and are not
caused by this work; they surfaced because `fuzz/reader-pqt-seeds/` is now committed.
