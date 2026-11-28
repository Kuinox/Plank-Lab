# THE canary: dictionary literal-run group count overflows in the generic index decoder

Externally reported by **CurtHagenlocher**; revealed by the owner on 2026-11-28 as the planted canary, then
**re-found by the fuzzer on its own**: `StructuredPageMutator` (`hybrid-overflow` mutation, arithmetic-overflow
boundary values) reported it at the 156th structured mutant of an ordinary run over the committed
`fuzz/reader-pyarrow-seeds` + `fuzz/reader-gap-generated` seeds (no hand-made input; 5 reports in the first
2,580 mutants, every one this bug).

## The defect (Plank master 3a6a28a)

`ColumnChunkReader.DecodeDictionaryIndexesIntoBuffer<T>` (the generic overload, used by the typed required,
nullable, converted and nested page decoders for every non-binary dictionary column) computes

```
var literalCount     = (header >> 1) * 8U;                      // uint, unchecked
var literalByteCount = ((literalCount * bitWidth) + 7) >> 3;    // uint, unchecked
```

For a bit-packed run header with a huge group count both products wrap: e.g. width 2, 268,435,460 groups →
literalCount = 2,147,483,680, ×2 = 2^32 + 64 → literalByteCount = 8. The 8-byte literal slice passes the
"enough bytes" check, `literalCopyLength = min(literalCount, remaining)` stays large, and
`DecodeDictionaryLiteralIndexes<T>` reads the remaining indices from past the slice. Depending on the path and
the bytes that follow, that surfaces as `IndexOutOfRangeException` / `ArgumentOutOfRangeException` (as here) or
silently decodes indices from bytes outside the run (out-of-bounds read, wrong values, no exception). The
`int` overload used for binary dictionaries guards `literalGroupCount > uint.MaxValue / 8` and computes in `ulong`.

## Files

- `mutant.parquet`: the fuzzer's mutant (pyarrow seed `pa-nested-deep-c0-dp2.0-d1-r04.bin`, row group 0,
  column 0, page 1: dictionary-index stream, width 2, a bit-packed header of 268,435,460 groups, 18 bytes present).
- `reader-input.bin`: the same file behind reader-target selector `0x00`.

```
Plank.Fuzzing.Replay reader fuzz/repros/dictionary-literal-group-overflow/reader-input.bin
# CRASH ... System.ArgumentOutOfRangeException at ColumnChunkReader.DecodeDictionaryLiteralIndexes[T]
#   <- DecodeDictionaryIndexesIntoBuffer[T] <- TryDecodeNestedPageIntoNative[T]
```

## Why the fuzzers missed it before, and what changed (generic, not special-cased)

Every count the structured mutator wrote was plausible (a group count matching the data, a run cut short), and
whole-file byte mutation cannot keep the page envelope (sizes, compression, CRC) valid while planting a 5-byte
varint with a precise value. The new arithmetic-overflow boundary values (`StructuredPageMutator.Overflow.cs`)
give every rewritten count/length field the values whose products with the format's multipliers (×8 groups,
×bit width, ×bytes per value, ×element size) wrap 32/64 bits to 0, to 1..64 or to just under the payload, and
the oracle decides impossibility with exact (BigInteger) arithmetic: a run claiming more bytes than the stream
holds must be rejected with `CorruptParquetException`; returning values for it, or throwing anything else, is a
finding. The twin-path oracle (`StructuredPageMutator.Twins.cs`) additionally requires every Plank decode path
of the same column (T, T?, converter, pruner, borrow options, nested, binary, row reader) to agree.
