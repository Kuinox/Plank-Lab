# Out-of-bounds hunt on the reader's unsafe decoders (reader agent, 2026-11-27)

What it is: `fuzz/mutate-decoder-seeds.py` makes structure-aware mutants of the reader seeds (length/count/width fields set to 0, 1, 31..65, 0x7f/0x80/0xff, 2^31-1, 2^32-1, len±1; Thrift/RLE
varint runs; deleted and duplicated spans; mostly in the page region), and `fuzz/tools-reader-coverage/oob-hunt.sh` replays them in restart-safe chunks of 4000 under three pools:
`PLANK_FUZZ_POOL=1` (exact-fit, zero payload, guard bytes before the header and after the payload, checked when a buffer is returned), `=2` (same, payload poisoned 0xA5, so a read past
the length changes decoded values and trips the Arrow/Parquet.Net/ParquetSharp oracles) and `=0` (default pool). Inputs that fault, mismatch or kill the process are kept as `hit-*` / `died-*`.

Run so far (job-24574813-reader-oob-2e685d on ovh): 49 chunks x 4000 = ~196,000 mutants x 3 pools, library master 3a6a28a, 1 GiB heap cap.
Result: **no guard-byte overrun, no crash, no unexpected exception type.** Only noise: 165 faults from the row-API `NestedRowMaterializer` ("Empty/null collection marker", an
intentionally unswallowed consistency check on corrupted nested levels — owner: rowapi/triage) and 6 ParquetSharp "Unexpected end of stream" rejections of BOOLEAN RLE pages whose
length prefix is shorter than the page (Plank reads the 300 declared values from the run and ignores the trailing bytes; the values are right — lenient, not corrupting).

Limits of this method: the pool canaries see only writes into pool buffers (and reads of poisoned bytes through the oracle). Reads past the end of the *input* span (`MemoryReadSource` over a managed
array) and past managed `byte[]`s are invisible without a guard-page allocator. Agent `guard` is building one (mmap + PROT_NONE); when it lands, replay every reader seed directory
and the mutants under it: `oob-hunt.sh` takes any replay build, and the mutants are reproducible (`mutate-decoder-seeds.py <dir> <count> <seed> <seed dirs>` with seeds 1000..1059).
