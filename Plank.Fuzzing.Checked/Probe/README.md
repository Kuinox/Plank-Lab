# Canary probe — checked build positive control for the dictionary literal-decoder over-read

The planted canary (revealed 2026-11-28) is an integer overflow in
`ColumnChunkReader.DecodeDictionaryIndexesIntoBuffer<T>` (the generic whole-page dictionary path, reached for
nested / nullable / converter-declined columns): `literalCount = (header >> 1) * 8U` and `literalCount * bitWidth`
are computed in **unchecked uint**, so a huge bit-packed literal group count wraps `literalByteCount` to a few
bytes while `literalCopyLength` stays large. The literal slice `payload[..literalByteCount]` is then a handful of
bytes, but `DecodeDictionaryLiteralIndexes<T>` decodes the full value count from it — reading far past the slice,
**inside the larger page buffer** (a silent over-read that does not crash; guard pages at allocation boundaries
cannot see it).

`CanaryProbe.cs` is a `partial` of `ColumnChunkReader` compiled into the library only by
`-p:PlankCheckedCanaryProbe=true` (library sources unedited). It exposes `DecodeLiteralCanary`, which calls the
private `DecodeDictionaryLiteralIndexes<long>` over a 5-byte payload with value count 4096 and bitWidth 11 —
exactly the post-overflow state — so the checked build can be proven to catch the over-read directly, independent
of which read route reaches it (Plank's own writer does not emit dictionary-encoded nested columns, so a
from-Plank file cannot drive the whole-page path; the reader must still handle such files from other writers).

## Result (checked build, `-p:PlankCheckedAccess=true -p:PlankCheckedCanaryProbe=true`)

Driver: a tiny console that references the checked Plank build and reflection-invokes `DecodeLiteralCanary`
(`agents/checked/mkcanary`, mode `canary`). Per ISA tier:

| tier (env) | outcome | why |
|---|---|---|
| default (AVX2+PDEP) | **`PLANK-OOB read of 8 byte(s) at offset 0 of a 5-byte span` at `ColumnChunkReader.cs:4073`** | `DecodeDictionaryLiteralInt64Indexes11BitCore` reads `Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref GetReference(payload), …))` — the silent over-read; the checked build throws `PlankOobReadException` |
| no-AVX512 (`DOTNET_EnableAVX512F=0`) | same `PLANK-OOB` | same AVX2 core path |
| SSE (`DOTNET_EnableAVX2=0`) | `ArgumentOutOfRangeException` | the portable path uses `payload.Slice(i/8*11, 11)` — runtime-bounds-checked |
| scalar (`DOTNET_EnableHWIntrinsic=0`) | `IndexOutOfRangeException` | the generic scalar loop uses `payload[byteIndex++]` — runtime-bounds-checked |

The silent memory-unsafety exists **only on the AVX2 vector cores** (which use `Unsafe` on the payload ref with no
bound); the checked build reports it there as `PLANK-OOB`, and with `PLANK_CHECKED_FAILFAST=1` the process aborts
(SIGABRT, rc 134) — an AFL crash. On the non-AVX2 tiers the library already indexes/slices the span, so the
runtime throws a bounds exception (not silent): a normal fuzzer sees those as crashes. So a complete campaign of the
checked AFL targets catches the canary on the exact tier where it is otherwise invisible.

The same `Unsafe`-on-payload pattern (and `Avx2.GatherVector256`) is used by the bitWidth 1/2/8/9 INT32 core
(`DecodeDictionaryLiteralInt32IndexesSmall`) and the INT32 11-bit core; the rewriter checks all of them
(`sites.tsv`: "checked" reads and "checked (every lane)" gathers), so they are caught the same way.

## Run

```
# from a checked build with the probe compiled in (see agents/checked/scripts/canary2.sh):
dotnet build <proj referencing Plank> -p:PlankCheckedAccess=true -p:PlankCheckedCanaryProbe=true -c Release
PLANK_CHECKED_FAILFAST=1 dotnet <driver> canary          # -> PLANK-OOB + SIGABRT on AVX2
DOTNET_EnableHWIntrinsic=0 dotnet <driver> canary        # -> IndexOutOfRange (portable, safe)
```
