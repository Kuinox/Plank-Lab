# Guard allocator vs the canary: an in-buffer over-read it cannot see (guard agent, 2026-11-28)

The canary (owner-revealed): in `ColumnChunkReader.DecodeDictionaryIndexesIntoBuffer<T>` the uint products
`(header >> 1) * 8U` / `literalCount * bitWidth` wrap for a huge bit-packed group count, so the literal payload slice
becomes almost empty (5 bytes in the positive control) while the literal decoder still decodes up to the value count
(4096 x 11 bits = 5,632 bytes). The read runs past the slice **into the rest of the same page**.

## Positive control under the guard build

Inputs: `agents/checked/canary/canary-{valid,oob}.bin` (checked agent's generator: required/repeated INT64, 11-bit
dictionary, one UNCOMPRESSED data page V2 that is also the last page before the footer). Driver: a probe that reads
the leaf with `RowGroup.NestedColumn<long>` (the only path reaching the unchecked generic overload; the flat/batched
path validates the RLE run), against `replay-v13` (`-p:PlankGuardArrays=true`: every borrowed range an exact guarded
copy, page payload / decompression buffers re-rented at exact size, exact-length guard pool).

| file | source | guard off | `end` | `start` |
|---|---|---|---|---|
| canary-valid | memory (borrow) / stream (copy) | 4096 values | same | same |
| canary-oob | memory (borrow) / stream (copy) | `CorruptParquetException: Dictionary index 1152 is out of range ...` | same, **no fault** | same, **no fault** |

The over-read happens (it decodes garbage indexes, then the dictionary bounds check rejects the page), but no guard
fires, with the page in its own exact guarded buffer and with it in the exact page buffer.

## Why the guard cannot catch it

Page geometry (`canary-oob.bin`): data page payload `[8894, 14529)`, patched literal-run header at 8894, literal slice
`[8899, 8904)`. The decoder reads forward from 8899 over the page's own remaining bytes; the dictionary-index check
stops it well before the page end. Every byte it touches is inside the page buffer, which is valid, readable memory
the reader legitimately owns. A page-granular guard (exact per-request reads, exact page and decompression buffers,
exact pool rents) only sees reads that leave the *buffer*; this one leaves only a *logical sub-slice* of it (the
literal run's bytes). It would fault only if the page ended before the decoded bits did, i.e. if the run were the
page's last bytes and the decoder got that far without tripping the index check. In the middle of a file, without
exact borrows, the same over-read lands in the next page; with them it stays inside the page. Either way: valid memory.

Detecting this class needs sub-slice bounds, not memory protection: the checked-access build (every
`Unsafe`/`MemoryMarshal` access checked against the span it was derived from), a twin-path consistency oracle
(generic vs `int` overload, nested vs flat decoder on the same page), and overflow-boundary values in structured
mutation (group counts near 2^29, 2^32/(8*bitWidth)). The guard work stops here for this class; it still covers
buffer-level overruns, underruns, use-after-release and the #276 class (managed slot arrays).
