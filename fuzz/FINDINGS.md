# Historical fuzz findings on Plank `a9c93f4`

Baseline audited 2026-11-11 20:13 CET; reachability updates continue through
2026-11-13 against that library revision. The six confirmed library defects
below were subsequently fixed on Plank `master` in [#214](https://github.com/Kuinox/Plank/pull/214),
[#215](https://github.com/Kuinox/Plank/pull/215), [#216](https://github.com/Kuinox/Plank/pull/216),
[#217](https://github.com/Kuinox/Plank/pull/217), [#218](https://github.com/Kuinox/Plank/pull/218),
and [#219](https://github.com/Kuinox/Plank/pull/219). The observations and
coverage counts in this file are historical and have not been rerun against
current `master`. Large raw queue, temporary diagnostic, and Coverlet files
referenced below were retained in the original fuzz worktree and are not part
of this source snapshot. Branch coverage over time is in
`fuzz/coverage-branch-history.html`.

| Status | Issue | Evidence |
|---|---|---|
| Fixed on Plank master (#216) | Malformed DELTA_BINARY_PACKED batches escape with `ArgumentOutOfRangeException` in INT32 and INT64 readers | Both exact saved queue inputs below reproduce on the current Reader.Target build; latest four-tier reader replay still records the same 12 input failures. |
| Fixed on Plank master (#219) | A sorted FLOAT/DOUBLE append drops sorting metadata | Two small finite monotonic inputs below start with one sorting column and end with zero; strict writer replay still fails. |
| Fixed on Plank master (#215) | Decimal columns accepted with Bloom options fail during serialization | The checked-in four-way repro succeeds for required/optional Decimal(9,2) without Bloom and throws `NotSupportedException` for both with Bloom enabled. |
| Fixed on Plank master (#214) | An invalid `DefaultParquetBufferPool` constructor can later terminate the process on its finalizer | A standalone one-call repro at `fuzz/repros/buffer-pool-partial-ctor/` catches the expected constructor exception, then `GC.WaitForPendingFinalizers()` terminates with `NullReferenceException` in `Trim` (line 169). The constructor throws before `_buckets` is initialized, but the finalizer still calls `Dispose(false)` and `Trim`. |
| Fixed on Plank master (#217) | Optional fixed-length binary written from `ReadOnlyMemory<byte>?` is length-prefixed and cannot be read back | The public writer accepts an optional FIXED_LEN_BYTE_ARRAY column and closes the file, but the public Plank reader throws `CorruptParquetException: PlainBinary payload contains 8 trailing bytes`. PyArrow 26 accepts the same file but decodes shifted values (first value `04 00 00 00` instead of `10 20 30 40`). `PlainEncoding.WriteOptionalValues` sends the memory row shape to `WriteLengthPrefixedPayloads` after its `byte[]` branch; fixed-length PLAIN values require no prefix. The standalone repro under `fuzz/repros/optional-fixed-memory-plain/` was rerun on Nov 12. |
| Fixed on Plank master (#218) | Appending to the latest row group fails for a valid DECIMAL column | An independent public API repro writes and reads FixedLenByteArray DECIMAL(28,0) values `[-2, 0, 3]`, creates an appender with `AppendToLatestRowGroup = true`, then `CreateSerializedColumn<decimal>` throws `NotSupportedException: Cannot append binary values as 'System.Decimal'`. `LatestRowGroupValues.ConvertBinary<T>` cannot materialize the stored binary values as decimal. Repro: `fuzz/.coverage-work/append-decimal-carrier-negative-control/Program.cs`. |
| Fixed fuzz-harness defect | One-byte `FA` input indexed `data[1]` | Saved input `fuzz/crashes/writer-aa7225e7d5b0a255.bin` now replays with zero unexpected throws. |
| Fixed fuzz-harness defect | `0x26`/`0x2E` logical-type probe collided with unrelated reader queue inputs | The first `20261111i` reader attempt produced 843 false faults per tier. A marker and schema gate now restrict the probe; the corrected four-tier attempt has the prior 12 known delta failures per tier. |
| Partially diagnosed fuzz-signal issue | Reader AFL stability near 60% | The shared adaptive buffer pool changes one seed's calibration bitmap. A separate same-process probe found that a pending Parquet.Net oracle task also changes one input's bitmap; the full live deficit remains unquantified. Skipping Parquet.Net did not help (live run returned to 59.31%); the normal oracle was restored. |
| Untriaged differential results | Independent-reader acceptance disagreements | The `20261111ae` four-tier reader replay logged 2,439–3,041 mismatches per tier. Many are malformed-file acceptance or oracle capability differences; these counts are not confirmed Plank defects. |
| Instrumented replay count anomaly | Writer coverage replays sometimes report extra faulting inputs | `ab` yielded 107–128 per tier, `ac` yielded 65 per tier, and `ad` yielded 66 per tier. A normal full replay of the exact retained `ad` input tree in the coverage script's directory order logged 65 faults, every one the known floating append metadata loss, and zero other faults or mismatches. The `ab` input tree was not retained and neither coverage run logged per-input faults, so their extra counts remain unexplained; they are not classified as new library defects. The replay driver now logs fault path, type, and message for future snapshots. |
| Invalidated coverage attempt | Four concurrent writer Coverlet replays exhausted memory near 80,000 inputs in the first `ae` attempt | Its reports were excluded; the same retained 88,132 inputs completed in all four ISA tiers when run two at a time, with no OOM and only the known 65 sorting failures per tier. |
| Invalidated coverage attempt | The `20261112ah` writer replay included two invalid buffer-pool constructor seeds | AVX-512 and AVX2 exited near 30,000 inputs when the pool finalizer threw; their partial Coverlet reports are invalid and were moved to `fuzz/.coverage-work/invalidated-20261112ah/`. The two seeds are staged at `fuzz/staged-crash-seeds/buffer-api-validation/` for focused reproduction and excluded from bulk replay. |

## Current complete coverage snapshot (Nov 12)

The complete `20261112ai` four-ISA reader and writer replay covers
**11,075/13,680 library branch outcomes (81.0%)**, up 74 exact outcomes from
`20261112ag`'s 11,001/13,680 (80.4%). All 13,680 source/line/IL-offset/path/
ordinal keys match; 74 formerly unhit keys are now hit, and none were lost.
The current queue is `fuzz/unhit-20261112ai.tsv`, generated by
`python3 fuzz/unhit-branch-inventory.py 20261112ai`: 2,605 unhit outcomes,
1,330 carrying narrow source-backed labels and 1,275 still `unreviewed`.
The canonical assembly and all eight report hashes are recorded in
`fuzz/coverage/history/20261112ai-manifest.txt`; the history HTML includes
this complete tag. The older `ag` and `ae` queues remain historical records.

The 18 missed `TryGetNullableFloatMinMax` and
`TryGetNullableDoubleMinMax` outcomes are preempted on the public writer
route. A retained nullable float/double seed exercises nulls, NaNs, signed
zeros, and finite extremes, but present values use DataV2 page statistics
before these fallback helpers. The all-null fallback reaches only the
opposite null-loop outcome. Four isolated ISA replays found no hits for the
18 exact outcomes; this classification adds no coverage percentage.
Three retained repeated INT32/INT64 seeds replay cleanly and enter their
statistics accumulators. A focused canonical report leaves 22 exact missed
conversion outcomes at zero. The repeated writer accepts only `int[]`/
`int?[]` for INT32 and `long[]`/`long?[]` for INT64, so those other boxed
leaf conversion arms are preempted by the caller's type dispatch. This adds
22 narrow classifications and no coverage percentage.
An empty optional INT64 dictionary seed hits one exact `ai` miss in a
canonical focused report. The other ten misses in that encoder slice remain
zero-hit: seven entry guards are preempted by public caller constraints, and
three progress checks cannot fail after the page and present-count guards.
These are route or invariant classifications, not a removal decision.
Five retained row-group validation seeds exercise a foreign serialized
column, missing serialized data, an already completed group, wrong column
order, and mismatched row counts. All five replay cleanly; isolated canonical
Coverlet hits their five exact `ai` misses once each. The four other missed
`RowGroupWriter.Write` outcomes are preempted on public writes: the unknown
internal page kind, absent page or column statistics, and a dictionary page
without any data page. Public V1/V2, empty, all-null, and forced-dictionary
controls hit the valid sibling branches but none of these four misses.
All 30 exact `AppendSortingOrder.CompareNonNull` misses now have caller-backed
classifications. Twenty-four require an unsupported or mismatched CLR carrier
for one typed column; three require invalid logical annotations; the three
decimal-carrier outcomes are preempted by the confirmed latest-row-group
append failure above. The decimal negative controls are staged outside bulk
fuzz replay because they fault before the comparator.
The public merger schema seed hits 15 of 21 exact misses in
`MutationSchemaValidator.ValidateNode` and `ValidateNodeHeader`. Reader
projection rejects four mismatch outcomes before this validator, and the
validated node tree preempts one node-count guard. The remaining annotated
wrapper outcome needs a legacy LIST/MAP file produced outside Plank's
canonical writer; it remains hard to reach rather than declared dead.
The 51 missed physical-type dispatch comparisons in the reader are labeled
hard to reach, not dead. Public fallback controls reach the nullable Decimal
and converted required INT32 helpers, but only their previously covered arms.
Normal compatible projections take fixed-width or encoded batching first;
targeted non-INT32 converter probes either batch or fail schema binding.
No new exact miss was hit, and no broad impossibility claim is made.
All 16 missed `ColumnBuffer` constructor guards remain zero-hit in a focused
public reader control, which exercises the valid constructor counterparts.
Internal callers enforce descriptor type, nonempty borrowed payload,
array-backed borrowing, positive fixed-width batch, and in-range offsets
before construction. These outcomes are caller-preempted for public reads;
the constructors themselves are still live.
The 12 repeated timestamp conversion misses are preempted by repeated INT64
type dispatch. Public repeated serialization accepts `long[]`/`long?[]`
leaves and rejects `DateTime[]`/`DateTimeOffset[]` before their statistics
accumulator runs; the tick-conversion overload has no other caller. The
existing repeated-accumulator controls leave all 12 exact outcomes at zero.
One nested BYTE_STREAM_SPLIT UTC timestamp sample read as
`NestedColumn<DateTimeOffset>` hits exact reader miss
`(2831,691,path 0,ordinal 28)`. The other 16 misses in the same native
decoder are preempted by encoding compatibility, earlier batch decoding, or
validated physical/CLR type mappings on public reads. The retained reader
seed checks two values and replays with no unexpected fault.
The optional flat BYTE_ARRAY target-page seed reaches four previously missed
exact outcomes through public `byte[]` and nullable `ReadOnlyMemory<byte>`
writer carriers. It also hits one sibling already covered in the `ai` queue.
Eight other misses in that helper are preempted by its dictionary-buffer
return contract or by row-carrier types the public writer never passes.
All 13 missed `GetEncodedDecoderKind` selector outcomes are marked hard to
reach. A public reader control mutates and reparses page-header encodings,
replays without unexpected faults, and enters the selector, but hits none of
the 13 exact misses. Fixed-width batching can run earlier; the individual
selector gates still need stronger per-tuple reachability proof.
For the BYTE_STREAM_SPLIT fixed-width slice decoder, a valid GUID and Decimal
sample hits six exact missed outcomes, including the valid side of the
16-byte GUID length check and both GUID lane-loop outcomes. Its invalid-length
side is preempted by schema validation. Three Decimal type-mismatch outcomes
remain zero-hit under validated fixed-width caller dispatch; one exact
outcome remains `unreviewed` pending IL/caller mapping.
The optional serialized-column sample hits five exact misses, including
duplicate-Serialize guards, an all-null binary statistics fallback, and a
multi-page Decimal statistics path. Six remaining failure arms are preempted
by helper output contracts or disabled Decimal extrema tracking.
The public INT32 delta generic-dispatch sample round-trips five CLR types
but hits none of its ten exact misses. Public serialization widens byte,
ushort, and uint to int before this helper; the remaining decimal carrier
uses its own branch. These ten outcomes are caller-preempted.
An empty required `ReadOnlyMemory<byte>` writer sample hits the pooled
`ColumnStatistics.CreateMemory` empty-span outcome. Eight other misses in
its unpooled overload have no public memory writer caller: required and
optional memory writes use the reusable-buffer statistics overloads.
The all-present small-double dictionary seed hits nine exact misses,
including duplicate lookup, new index, and capacity fallback outcomes.
Its one remaining helper guard is preempted because the only caller invokes
the helper only while small indexes are enabled.
The optional PLAIN INT64 seed hits five exact misses through public invalid
carrier/projection checks and an empty valid column. Four option/strategy
guard misses cannot pass the only public caller's PLAIN, default strategy,
dictionary-disabled, no-bloom requirements.
The public empty optional-column seed hits one `EncodeOptional` reference
overload early-return miss; eight other misses are preempted by earlier
required/nested/repeated and type dispatch checks in `SerializedColumn`.
The optional DELTA INT64 seed hits four validation misses for required or
nested carrier misuse. Five helper misses are preempted by the caller's
strategy/encoding requirements or its present-value guard.
The optional memory target-page samples hit eight exact page-sizing and
min/max decisions. The remaining zero-run guard is preempted because the
helper always receives a nonempty suffix and admits its first row.
The all-null optional INT32 control enters `CreateNullableInt32` but leaves
its eight present-value misses at zero. Any present value sends the public
writer through `SerializeOptionalConverted` and page statistics first.
Ten `TryDecodeNullableValues` misses were also audited: valid supported
pages take earlier fixed-width or encoded batching; nine remain hard to
reach through malformed-page routes, and one mismatched-type outcome is
preempted by the outer nullable decode gate. No saved malformed sample hit
an exact miss.
An all-null optional INT64 Bloom control enters `CreateNullableInt64` but
leaves its eight present-value misses at zero. Public present values take
specialized or converted page-statistics paths first. A required DELTA
BYTE_ARRAY control exercises both precomputed page writer overloads; their
nine missed count/negative-length guards are preempted by the callers'
matching spans and nonnegative suffix totals.
Eight `Avx2UnpackControls.Create` misses are host-preempted, not dead. A
33-value public DELTA INT32 seed decodes cleanly and reaches the mini-block
dispatch, but this Ryzen host selects the BMI2/PDEP kernel; the AVX2 unpack
table is never initialized. A host selecting that kernel can exercise it.
The optional DateTime predicate matrix hits six exact misses through public
writer schemas and options. The two remaining physical/repetition mismatch
outcomes are preempted by earlier timestamp schema and optionality checks.
The generated nullable byte-array row sample hits one exact row-size
estimator miss for a null `byte[]`. Seven other misses require `Memory<byte>`
or unsupported arbitrary reference rows that the source generator rejects.
The binary `CountPresent` matrix hits six exact misses through public
required/optional byte and memory carriers. Its remaining generic byte-array
type-check arm is bypassed by specialized public byte-array counting.
The nullable INT32 dictionary RLE batch control reaches the decoder and
round-trips 300 values but hits none of nine exact misses. Two malformed RLE
guard outcomes and three SIMD-layout outcomes remain hard to reach; four
AdvSimd outcomes are unavailable on this x86 host. Rejected malformed-page
probes were not retained as reproducing seeds.
Fixed-length BYTE_STREAM_SPLIT controls hit three exact writer validation
misses: a ReadOnlyMemory carrier rejection, null byte-array rejection, and
wrong-width payload rejection. Four other misses require an empty page that
the caller omits or a GUID width that public schema validation rejects.
The forced optional INT32 dictionary seed hits three exact validation
outcomes. Four helper misses are preempted by the caller's forced-strategy
and present-value guards. An initial focused report used a stale copied DLL;
the fresh report matches the canonical assembly hash and exact IL offsets.
The forced optional INT64 dictionary seeds hit three exact required/nested
validation outcomes. Four other misses contradict the public caller's
force-strategy or present-value guards. A PLAIN INT32 seed hits one exact
unsupported bool-carrier rejection; six narrow integer carrier branches
are preempted because public serialization converts byte, ushort, and uint
to int before calling the encoder.
A 40,003-value fixed DELTA_BYTE_ARRAY Decimal seed, requested required and
optional GUID-converter seeds, and an oversized fixed-width metadata probe
together hit seven exact batch-decoder misses, including previous-value
copying, GUID materialization, and the >256-byte width guard. One invalid
CLR-type outcome is preempted by decoder selection.
Three row groups of forced required BYTE_ARRAY dictionary writes hit six
exact sort-transition misses. The remaining sort-break outcome is preempted
because Unsorted state delegates to the map helper at entry. A FLOAT/Decimal
dictionary seed hits two exact `TryCompareForSort` misses; five Boolean or
narrow unsigned carrier outcomes are bypassed by specialized writing or
conversion before that helper.
The forced required BYTE_ARRAY dictionary map seed hits all three exact
null-carrier guards at map entry, cycle closure, and mismatch tail; the
expected public writer rejections are caught by the replay case.
Two latest-row-group append seeds hit five exact reader branches: repeated
column rejection plus optional Boolean, INT32, FLOAT, and DOUBLE handling.
The >Int32.MaxValue row-count guard remains hard to reach; the undefined
physical-type switch default is preempted for valid schema metadata.
Seven `DecodeFixedWidthBatch` misses are preempted by the decoder-kind,
dictionary, and physical-type gates before their branches. The eighth is a
big-endian path; a valid optional timestamp sample hits its little-endian
sibling on this x86 host.
Eight `TryDecodeDeltaByteArrayIntoNative` misses are preempted by public
reader dispatch: fixed GUID/Decimal DELTA_BYTE_ARRAY pages take encoded
batching first, and parse errors there do not retry this fallback. Repeated
and nested projection gates also reject the alternate route.
Reparsed footer mutations sent through the public importer hit five exact
`ValidateImportChunk` guards. Two remaining outcomes are preempted by the
definition of chunk start as the minimum page offset and by signed Thrift
offset-index length parsing before import validation.
Seven latest-row-group replacement-offset misses now have clean public
appender samples. Plank-generated files cover absent indexes; PyArrow and
reparsed external layouts cover prior index/Bloom ranges, zero-length Bloom
metadata, and prior-chunk overlap. All seven exact canonical keys hit.
Public append seeds hit four exact `AppendSortingOrder.Compare` logical
type outcomes for INT96, Unknown, Geometry, and Geography. The converter
outcome is preempted by earlier latest-row-group value materialization;
Variant is group-only and cannot be a leaf sort key.
The Decimal zero-comparison seed hits all six exact outcomes, including
the final loop exit when an empty zero payload is compared with `[0x00]`.
Seven fixed-width batch-starter misses are preempted by public projection,
dictionary-page, encoding, or count guards before those comparisons run.
Malformed missing-dictionary input was rejected by the preceding reader
guard, and the focused report hit none of these exact outcomes.
Six `ByteStreamSplitEncoding.WriteInt32Lanes` misses are preempted because
public byte, ushort, and uint serialization converts values to int before
the lane writer. The existing alternate-numeric control enters its valid
int and Decimal arms but leaves these six exact outcomes at zero.

Each writer tier replayed 88,428 frozen inputs after the two buffer-pool
crash seeds were staged out. Every tier reported the same 65 known append
sorting faults and zero oracle mismatches. Each reader tier replayed 191,770
inputs and reported 12 faulting inputs, the same count as `ag`; reader
acceptance-oracle mismatches remain untriaged. The writer half alone hit 83
formerly unhit outcomes, nine of which the `ag` reader reports already hit.
Post-snapshot focused samples hit 277 unique exact `ai` misses across canonical
binary reports; those gains are not
yet counted in the complete percentage. The first focused report at
`fuzz/.coverage-work/focused-new-writer...json` hit eight exact `ai` misses:
four signedness-dependent `AppendSortingOrder` arms and four empty unsigned
`ColumnStatistics` guards. The two optional INT32 encoding samples hit no new
outcomes. IL inspection showed that their remaining line-1032
`(offset 193, path 0, ordinal 24)` branch is the ARM AdvSimd fallthrough,
unavailable on this x86 host.

The final alternate numeric seed
`fuzz/corpus/encoding-coverage-alternate-numeric.bin` exercises public
ByteStreamSplit and DELTA writer routes for alternate widths, a 300-byte
fixed decimal, and the DELTA 64-bit mask case. Canonical-assembly focused
Coverlet in `fuzz/.coverage-work/bss-alt-numeric/report/` hits 25 exact
`ai` misses across default, AVX2, portable, and scalar tiers. Two of those
outcomes were added after the first report: ByteStreamSplit's large fixed
value threshold and DELTA's 64-bit packing mask. Selectors 31 through 34
replay with zero unexpected throws. Other BSS and DELTA misses include
host-endian branches, caller-preempted type/length guards, and the internal
`WritePackedUnsignedValues` helper, which has no production call site.

The two unhit argument throws at `MinMaxScan.CopyAndCompute` lines 104/106
are caller-preempted: its only production callers are the INT32 and INT64
PLAIN page-statistics writers. Both return for zero values, then obtain a
destination span sized from the same input length. These guards are useful
defensive checks but are not reachable through those public writer routes.

A 68-input append-comparator replay, including the signed/unsigned carrier
controls and two new binary controls, completed without unexpected throws or
mismatches. The canonical assembly and exact OpenCover report at
`fuzz/.coverage-work/append-comparator-audit/append-comparator.opencover.xml`
confirmed the same four post-snapshot signedness outcomes already counted
above at `AppendSortingOrder.CompareNonNull` lines 97–100. The other 30 exact `ai`
outcomes in that method stayed unhit, even though the method ran; they remain
unreviewed at the tuple level rather than being called dead.

The 26 unhit `MinMaxScan.ComputeVector128Bulk` and
`CopyAndComputeVector128Bulk` outcomes are host-gated writer routes. Their
sole production callers are `ArmInt32PlainPageWriter` and
`ArmInt64PlainPageWriter`, selected only under
`AdvSimd.Arm64.IsSupported`. The Copy helper additionally requires
little-endian; the Compute helper requires big-endian. A 301-row public PLAIN writer sample at
`fuzz/corpus/writer-minmaxscan-vector128-copy.bin` passed value and statistics
readback. Focused x86 Coverlet at
`fuzz/.coverage-work/minmax-arm64-route/x86-control.cobertura.xml` hit none
of the 26, consistent with the caller gate. Keep the sample for a
little-endian ARM64 coverage run; the Compute helper needs a big-endian ARM64
environment. These outcomes are not removal candidates based on x86 results.

The 30 remaining `BloomFilterBuilder.InsertObject` outcomes are preempted by
the typed value paths on supported public writes. Required, optional, and
repeated values use `InsertValues` or `InsertOptionalValues` after repeated
shapes and physical leaf types have been validated; narrow and unsigned
values are normalized before Bloom construction. The existing Decimal Bloom
repro reaches `InsertObject`'s default unsupported-value throw, confirmed by
focused Coverlet at
`fuzz/.coverage-work/bloom-insertobject-audit/decimal-fallback.json`.
The repeated fixed-binary control did not enter `InsertObject`; its typed
array path handled the values. These 30 successes or alternate physical-type
guards are not valid public fuzz targets under the current serialization
contracts.

The seven unhit outcomes on `RowGroup.ValidatePhysicalType` line 229 are a
narrow dead-code candidate. That condition can return for a CLR `byte[]`
projected onto FIXED_LEN_BYTE_ARRAY or INT96 only after resolving the CLR type
as BYTE_ARRAY. The preceding guard throws for `byte[]` and `string`, the
only two CLR types that resolve to BYTE_ARRAY, so no successful public call
can enter the line-229 condition. The remaining outcomes in this method are
being audited separately.

One other `RowGroup.ValidatePhysicalType` outcome is reachable: the public
`RowGroup.Column<object>` call on a valid DATE file takes the unsupported CLR
type throw at line 225. The guarded
`fuzz/reader-corpus/reader-rowgroup-unsupported-clr-date.bin` sample replays
with zero unexpected faults or mismatches, and exact Coverlet at
`fuzz/.coverage-work/rowgroup-validate-audit/rowgroup-unsupported-clr-date.json`
hits `(225,734,path 0,ordinal 42)`. Converter guards in this method remain
unreviewed: requested-schema public routes exist, so the absence of hits
alone does not prove they are unreachable.

Three public writer controls under `fuzz/corpus/writer-decimal-binary-statistics-*.bin`
write BYTE_ARRAY Decimal columns from raw byte payloads, including empty,
positive, negative, and different-length values. All three close and pass
footer min/max assertions with zero Replay faults. Canonical focused Coverlet
at `fuzz/.coverage-work/decimal-binary-statistics/report.json` hits all ten
previously unhit exact outcomes in `ColumnStatistics.CompareDecimalBytes`.
This method is live; those outcomes were hard to reach with the earlier
decimal-value corpus.

The public reader control `fuzz/reader-corpus/reader-nullable-decimal-bytearray.bin`
round-trips optional BYTE_ARRAY Decimal values and passes the Arrow and
logical checks. Its focused report under
`fuzz/.coverage-work/nullable-reader-release-20261113/` enters
`TryDecodeNullableValuesByPhysicalType` and takes the Decimal arm, but
hits zero of that method's 24 residual exact `ai` outcomes. Those rows
remain unreviewed pending a route for each physical-type arm; this control
prevents mistaking the whole method for dead code.

Eleven direct public-constructor controls under
`fuzz/writer-gap-seeds/nested-descriptor-validation/` exercise the nested
row descriptor's null, repetition, definition-threshold, array-rank, and
element-type checks. Release Replay passed all eleven with zero unexpected
faults. Canonical focused Coverlet at
`fuzz/.coverage-work/nested-descriptor-validation/report.json` hit all nine
remaining exact `RowApiNestedColumnDescriptor` constructor outcomes. These
were reachable API validation paths, not dead code.

The 13 residual `GetEncodedDecoderKind` outcomes were mapped to binary
encoding switch arms, physical-type guards, and dictionary/ALP/DELTA
fallthroughs. The 1,703 existing generated PAR1 reader fixtures exercised
the method but hit none of those exact `ai` tuples. Its caller does not
validate encoding/physical-type compatibility before dispatch, so malformed
combinations may still reach these guards. They remain unreviewed pending
targeted file samples rather than being labeled dead.

Eight optional DOUBLE dictionary controls under
`fuzz/writer-gap-seeds/optional-double-dict-*.bin` replayed with no
unexpected faults or mismatches. Canonical Coverlet at
`fuzz/.coverage-work/optional-double-dict-ai-final-validated/focused.json`
hits three exact `ai` misses: empty values, a required-column nullable-type
rejection, and the all-NaN statistics path. Ten more outcomes have narrow
caller, default-strategy, host/layout, or page-progress explanations. Six
sort/nested-projection outcomes remain unreviewed.

Six saved D6/RRC1 writer controls under
`fuzz/writer-gap-seeds/repeated-rows-coverage/`, together with the existing
optional INT32 Bloom control, exercise flat and nested repeated rows,
including expected rejection of undefined physical-type enum values.
Release Replay passed all seven without unexpected faults or mismatches;
the six newly saved inputs also replayed independently with zero faults.
Canonical Coverlet at
`fuzz/.coverage-work/repeated-rows-ai/repeated-rows-v3..json` hit 14 of
the 17 exact `EncodeRepeatedRows` misses from `ai`. The three
`ReadOnlyMemory<byte>[][]` match/optional-element outcomes remain
unreviewed; a correctly shaped one-level memory sample reached the type
check but took its mismatch arm. The two switch defaults are publicly
reachable because `ColumnDefinition` accepts an undefined physical-type
enum with PLAIN encoding before the writer rejects it.

The `ParquetWriter` constructor's nine residual outcomes split into four
reachable validation/empty-schema paths and five schema-projection
invariants. Two D4/PWC1 seeds under
`fuzz/writer-gap-seeds/parquet-writer-constructor/` replay cleanly.
Canonical Coverlet at
`fuzz/.coverage-work/parquet-writer-constructor/report.json` hits the
empty-schema leaf-path, projection-info, and zero-column branches plus
the null append-source throw. The other five require default or
length-mismatched arrays that `ParquetSchema`'s constructor never exposes.

The ENCG selector-35 optional `ReadOnlyMemory<byte>` seed at
`fuzz/optional-dictionary-index-seeds/optional-memory-maybe-and-forced.bin`
replays cleanly and hits all 14 exact `BuildOptionalDictionaryIndexes`
misses in canonical
`fuzz/.coverage-work/optional-dictionary-indexes-exact-20261113/report.json`.
It exercises retained, dropped, and forced dictionary modes with present and
null rows. The ENCG selector-36 memory-backed DELTA_BYTE_ARRAY seed at
`fuzz/writer-gap-seeds/delta-byte-array-readonly-memory/delta-byte-array-memory.bin`
also replays cleanly; canonical
`fuzz/.coverage-work/delta-bytearray-readonly-memory/report.json` hits
all 12 exact `DeltaByteArrayEncoding.WritePayloads` misses.

Three D5/CSB1 binary statistics controls at
`fuzz/corpus/writer-columnstats-binary-{bytearray,memory,empty}.bin`
exercise required and optional
`byte[]` plus optional `ReadOnlyMemory<byte>` columns, including zero-row
and all-null cases. Replay passes all three. Canonical focused Coverlet at
`fuzz/.coverage-work/columnstats-binary-audit-20261113d/targeted..json`
hits 14 exact `ai` misses in the pooled
`CreateByteArray`, `CreateOptionalByteArray`, and
`CreateNullableMemory` overloads. Two required-byte-array null throws are
preempted by encoding validation, and the nullable-memory all-null return
is preempted by `SerializedColumn`'s earlier empty shortcut. The 36
unpooled overload outcomes have no public typed binary writer caller:
public serialization uses reusable buffers and their fallback calls
unpooled methods only for different types.

Five additional `ColumnChunkReader.DecodeAllPresentPlainInt32Batch` misses
are now classified. Two line-918 throw edges are preempted on the public
reader path: `TryStartFixedWidthPageBatches` validates the full PLAIN payload
before recording page state, and each later batch stays within that validated
physical count. The three line-924/926 outcomes are the big-endian loop;
the production caller passes `BitConverter.IsLittleEndian`, so they require a
big-endian host. A valid 70,000-row optional INT32 PLAIN sample at
`fuzz/reader-gap-seeds/reader-nullable-int32-all-present-70000.bin` entered the
decoder and read back all 70,000 values, but AVX-512 Coverlet gained zero exact
outcomes from `ag` because the normal-path edges were already covered. It was
moved out of the bulk corpus after the frozen `ai` reader replay.

Two further public reader controls at `fuzz/reader-fixedwidth-samples/`
exercise a nested optional INT32 LIST V2 page and a required INT32 V2
dictionary page. Both replayed with zero faults or Arrow mismatches (16 values
total). Focused JSON Coverlet at
`fuzz/.coverage-work/focused-reader-fixedwidth...json` hit zero exact `ai`
misses, so these remain control samples rather than evidence that the listed
unhit outcomes are reachable. The nested decoder's line-216 missing-dictionary
return is preempted by the sole caller's earlier
`TryDecodeDictionaryPageIntoNative` check, which throws before dispatch.

### Reachable writer-option validation outcomes

All 13 previously unreviewed `Writing/ParquetWriterOptions.cs` outcomes in
`20261112ag` are reachable through public inputs. Fourteen isolated seeds at
`fuzz/writer-gap-seeds/writer-options-validation/option-00.bin` through
`option-13.bin` exercise the zero/oversized option guards, undefined page/file
versions, default sorting array, empty metadata key, and both
`RowApiMaxParallelism` getter arms. The exact-magic `E1 PWOV` writer route
asserts the expected public exception parameter for each invalid option.
Release Replay completed all 14 inputs with zero unexpected faults or oracle
mismatches. A canonical-binary targeted Coverlet report at
`fuzz/.coverage-work/writer-options-validation/options14..json` hit all 13
exact source/line/offset/path/ordinal tuples from the `ag` queue. These are
hard-to-reach validation branches, not dead code; they are included in the
complete `ai` snapshot.

### Split-block Bloom-filter validation outcomes

The two unhit `SplitBlockBloomFilter.ValidateBitset` outcomes at line 66 are
the two edges into its invalid-length throw: bitset shorter than 32 bytes
`(offset 9, path 1, ordinal 1)` and length not divisible by 32
`(offset 21, path 0, ordinal 2)`. Compiled IL destinations and Coverlet
`EndOffset` values establish that mapping. The public reader rejects both
sizes while reading the Bloom-filter header, before constructing the filter;
the public writer allocates only valid power-of-two sizes. The existing
`library/Plank/Plank.Tests/Writer/BloomFilterTests.cs` malformed 33-byte
header test demonstrates reader preemption. These are defensive guards with
no public file or writer route to the lower-level throw, not evidence that
the Bloom-filter feature is dead.

### Bloom-filter option validation and sizing

Nine exact-magic `E0 BOV1` inputs in
`fuzz/writer-gap-seeds/bloom-options-validation/` exercise public
`ColumnOptions` construction with invalid Bloom settings and public INT32
Bloom writes at two bitset-sizing extremes. Release Replay completed all
nine with zero unexpected faults or oracle mismatches. Canonical-binary
targeted Coverlet at `fuzz/.coverage-work/bloom-options-validation/options..json`
hit 11 of the 13 exact `ParquetBloomFilterOptions` tuples still missing from
`ag`: all nine validation outcomes and both line-52 sizing exits. These are
reachable paths and are included in the complete `ai` snapshot.

The other two outcomes, line 57 `(offset 134, path 1, ordinal 7)` and
`(offset 140, path 1, ordinal 9)`, lead to the final `MaximumBytes` fallback
when `RoundUpToPowerOf2` returns zero or exceeds the maximum bit count.
`ColumnOptions` validates `MaximumBytes` as a power of two from 32 to 128 MiB
before the writer calls `GetBitsetSize`. The preceding line-52 guard returns
when `bitCount` is nonfinite or at least `MaximumBytes * 8`; otherwise
`requestedBits` is between 256 and that power-of-two maximum. Rounding it
up therefore cannot produce zero or exceed the maximum. These are defensive
internal bounds, preempted for valid public options, rather than sample
targets.

### Timestamp expected-kind fallback

Two exact `TimestampConversion` misses, `ConvertScaled` line 141
`(offset 17, path 1, ordinal 1)` and `TryGetKindBits` line 252
`(offset 5, path 0, ordinal 2)`, are the same internal fallback for an
expected `DateTimeKind.Local`. The compiled switch exits through that branch
for Local or another non-UTC/non-Unspecified value. The public timestamp
writer call sites derive expected kind only from `IsAdjustedToUtc`: UTC or
Unspecified (`SerializedColumn.cs` and `Encoding.cs`). A Local input is
rejected as a kind mismatch; it does not make Local the expected kind.
These two outcomes are preempted on current public writer routes. The other
timestamp conversion misses remain unreviewed pending exact replay samples.

### Buffer and pool API boundary

The exact-magic `DF PBAP` route now makes direct public buffer and pool calls
that cannot be encoded in Parquet file bytes. Seventeen saved inputs were
used in the focused run; 15 remain at
`fuzz/writer-gap-seeds/buffer-api-validation/`, while the two invalid
constructor inputs are staged outside bulk replay. They cover invalid `AsSpan<T>` and
`RetainSlice` calls, `ParquetBuffer.Create` arguments, disposed buffers,
pool constructor/rent validation, `Trim`, repeated dispose, and a zero-byte
retention limit. A focused Release Replay processed all 17 without a synchronous
fault or oracle mismatch, but later garbage collection of either invalid
constructor object crashes the process; bulk replay therefore excludes those
two inputs. Canonical-binary targeted Coverlet at
`fuzz/.coverage-work/buffer-api-validation/options..json` hit 22 exact `ag`
misses: 12 in `ParquetBuffer` and 10 in `DefaultParquetBufferPool`.
The existing `fuzz/reader-corpus/reader-retain-buffer-levels-v1.bin` still
exercises live retention through the public reader. Remaining buffer/pool
misses include internal caller invariants and memory-pressure or native OOM
states; those stay unreviewed pending exact edge evidence. The complete
`ai` coverage includes the 15 noncrashing buffer API seeds.

### Schema construction API samples

The exact-magic `DE SAPI` route has 28 saved inputs in
`fuzz/writer-gap-seeds/schema-api-validation/`. It constructs malformed
caller-provided schemas, calls the public writer/appender/merger overloads
with null sources or destinations, and exercises invalid logical annotations
including a Variant metadata leaf with no physical type. Additional inputs
exercise repeated, unsupported, mismatched, and wrong-width custom
converters plus a large fixed-length decimal bound. Release Replay completed
all 28 with zero unexpected faults or oracle mismatches.
Canonical-binary targeted Coverlet at
`fuzz/.coverage-work/schema-api-validation/options28..json` hit 30 exact
`ag` misses: 16 in `ParquetSchema`, 12 in `ColumnDefinition`, and two in
`ParquetTypeMap`. The
Variant metadata sample specifically hit the previously unreviewed
line-319 `(offset 256, path 1, ordinal 17)` condition. These are reachable
API paths, not dead code.

The remaining `ColumnDefinition.ValidateConverter` nullable physical-type
throw at line 183 `(offset 51, path 0, ordinal 4)` has no current external
converter route. `ParquetValueConverter` has internal abstract methods, so
external implementations use `ParquetValueConverter<TValue,TPhysical>`; its
`unmanaged` physical-type constraint rejects `int?` with compiler error
CS8377. All checked-in converter implementations use that generic base.
This is an internal defensive guard, preempted for public custom converters.
The one remaining `ParquetSchema.TryCreate` miss at line 36
`(offset 7, path 1, ordinal 1)` is its default-`ImmutableArray` normalization.
The sole internal caller, `PhysicalSchemaBinder.BuildSchema`, creates a builder
and passes `MoveToImmutable()`, which yields a nondefault array, including
when empty. The public constructor has a separate default-array path already
covered by the direct API sample. This `TryCreate` outcome is preempted by
the internal caller's construction; all `ParquetSchema` misses from `ag`
are now classified.

### Dataset failure and capacity routes

Two already identified generated dataset routes now have checked-in replay
inputs: `fuzz/corpus/dataset-operational-disposed-guard.bin` and
`fuzz/corpus/dataset-operational-parked-copy-failure.bin`. Together with the
existing rollover seed, Release Replay completed three inputs with zero
unexpected throws and zero oracle mismatches. A focused Coverlet run also
executed the dataset writer, but other `ai` unreviewed capacity and
failure-cleanup outcomes remain unclassified. Several cleanup branches require
a throwing public write source.
Other guards look like private state invariants; those need targeted proof
before being labeled dead or preempted.

The public `IParquetWriteSource.Open` failure route is now captured by
`fuzz/corpus/dataset-operational-promotion-open-retry.bin`. It throws before
`PromotePendingPartition` enters its cleanup block, leaving the parked pool
full; retrying `QueueRow` reaches the previously missing full-pool arm.
Canonical focused Coverlet at
`fuzz/.coverage-work/focused-dataset-open-retry..json` confirms three exact
`ai` misses, including `DatasetWriterBase.QueueRow` line 197. The replay
has zero unexpected throws. This edge is hard to reach, not dead.

`fuzz/corpus/dataset-pending-multikey.bin` is a small public dataset route
with four partition keys and pending capacity three. Replay passed; it
exercised both `AddPendingKey` used-key outcomes, which were already hit in
`ai`. The remaining line-324 loop-exhaustion throw is preempted by the
capacity invariant: each used pending key has at least one parked row, and
`QueueRow` promotes a partition before calling `AddPendingKey` when parked
rows reach the key-array length.

Two `RowWriterBase.Rollover` null-throw outcomes are also preempted on the
public path. The sole caller runs only while `_rolloverPending` is true; only
the rolling constructor can set that flag, and it assigns both `_rollingFile`
and `_filePath` as readonly fields. The nonrolling constructor leaves the
flag false, so neither null throw is a fuzz seed target.

Five `RWP1` row API controls under `fuzz/writer-gap-seeds/row-api-pipeline-controls/`
now replay cleanly. A public 64-byte row-group target lets two fixed-width
rows stay in one group and reaches the `RowBufferSlot.TryAdvanceBefore`
capacity arm that earlier 1–3-byte fuzz options could not. Canonical-binary
focused Coverlet at `fuzz/.coverage-work/focused-row-api-canonical...json`
hit three exact `ai` misses: that arm plus one each in
`PipelineRowWriterBase` and `RowWriterBase`. A private build had different
branch keys, so only this canonical report was used for classification.

## Historical `ae` reachability audit

The reproducible branch-level audit queue is
`fuzz/unhit-20261111ae.tsv`, generated by
`python3 fuzz/unhit-branch-inventory.py 20261111ae`. It contains all 2,809
unhit source/line/offset/path/ordinal tuples from the complete eight-report
union, with class and method names. Narrow source-backed labels classify 407
tuples; 2,402 remain `unreviewed`, meaning reachability has not yet been
established. The status must not be interpreted as dead code. The script
requires all four ISA reports for both reader and writer before exporting.

### DELTA_LENGTH_BYTE_ARRAY residual tuples

The replayable `fuzz/corpus/encoding-delta-length-byte-array-shapes.bin`
selects the existing `ENCG` case 25, which writes required and optional
BYTE_ARRAY columns using both `byte[]` and `ReadOnlyMemory<byte>` shapes,
including zero-payload values. Release replay passed with zero unexpected
faults or mismatches. A private Coverlet report on this single input confirmed
that the encoding paths execute, but the four exact residual outcomes listed
below remained unhit; do not infer reachability solely from a nearby hit.

`(20,79,path 1,ordinal 3)` is preempted for the public `byte[]` route: the
preceding `typeof(T) == typeof(byte[])` arm returns before the later
`ReadOnlyMemory<byte>` test can take its non-memory outcome. The `byte[]`
specialization itself is exercised by the case sample. `(85,72,path 1,ordinal
3)` is the generic optional-row fallthrough after the specialized
nullable-memory and `byte[]` arms. Both supported public row shapes return from
their specialized arm; the focused report hit the `byte[]` arm but not this
fallthrough. The generic `TRow`/`TRowAccess` fallback is internal-only for the
current supported public writer shapes. `(246,7,path 0,ordinal 0)` is
preempted for public writers by `EncodingCompatibility`, which requires
`DeltaLengthByteArray` to use physical `ByteArray` before the encoding
dispatcher can call `RequireByteArrayColumn`. `(46,68,path 0,ordinal 0)` remains
unreviewed: the focused report did not hit it, and source inspection did not
establish whether this specific payload-size outcome is public, preempted, or
internal-only.

### Required timestamp dictionary encoder

The complete eight-report `20261111ae` union has six unhit outcomes in
`Encoding.EncodeRequiredDateTimeDictionary`. Its normal public route is
`SerializedColumn<DateTime>.Serialize` -> `TrySerializeRequiredDateTimeDictionary`
-> `EncodeRequiredDateTimeDictionary`. Three bounded `WMD1` probes now cover
the still-reachable outcomes: `fuzz/corpus/writer-metadata-required-timestamp-empty.bin`
hits the empty-span return `(150,141,path 0,ordinal 6)`;
`fuzz/corpus/writer-metadata-required-timestamp-singleton.bin` hits the zero-bit
dictionary width `(163,235,path 1,ordinal 11)`; and
`fuzz/corpus/writer-metadata-required-timestamp-wrong-physical.bin` supplies an
INT32 column annotated as Timestamp and serializes DateTime, asserting the
publicly reachable encoder rejection at `(141,56,path 0,ordinal 2)`. The schema
logical-type validator does not constrain Timestamp physical type, and the
serialized-column fast-path guards allow this case to reach the internal
required-INT64 check. All three probes passed Release Replay with zero
unexpected faults. Separate targeted Coverlet reports for these seeds, compared
tuple-by-tuple with the full eight-report union, hit exactly those three
previously unhit outcomes.

The other three exact outcomes are preempted by the public caller or helper
invariants: `(141,47,path 1,ordinal 1)` rejects non-Required repetition before
the caller invokes this method; `(145,98,path 0,ordinal 4)` is precluded by the
caller's `DictionaryMode.Forced` guard; and `(154,171,path 0,ordinal 8)` is the
dictionary-page failure path, which cannot occur for nonempty values with
Forced mode (`TryWriteDictionaryPage` returns false only for empty input,
Disabled mode, or a Maybe-mode drop). The inventory labels only these six exact
tuples as `reachable_required_timestamp_dictionary_boundary_sample` or
`preempted_required_timestamp_dictionary_guard`.

### Buffer chunk capacity guard

Two `BufferWriter` constructor bounds are reachable through public
`ParquetWriterOptions`: `chunkSizeBytes > int.MaxValue` at
`(21,67,path 0,ordinal 4)` and `initialBufferBytes > int.MaxValue` at
`(24,145,path 0,ordinal 6)`. Exact-gated `0xE2 + BWOV + mode` samples in
`fuzz/buffer-capacity-seeds/` construct a one-column writer with either
`BufferChunkSizeBytes` or `InitialPageBufferBytes` set to `uint.MaxValue` and
assert the corresponding `ArgumentOutOfRangeException` before allocation.
Release Replay passed both inputs with zero unexpected faults; separate
private Coverlet runs hit those two exact, previously unhit combined `ae`
tuples. These are public validation paths, not dead code.

The constructor's zero-size guards at `(15,12,path 0,ordinal 0)` and
`(18,37,path 0,ordinal 2)` have no normal library caller route.
`BufferWriterFactory` is the constructor's only production caller and rejects
zero chunk, page, column, and metadata sizes when it is created, before any
`Create*BufferWriter` method passes them through. They remain defensive
internal guards; no file seed can reach them through the public writer.

`BufferWriter.Reset`'s uninitialized `_segments is null` return
`(98,6,path 0,ordinal 0)` is also excluded by the public writer lifecycle:
`ParquetWriter` constructs both metadata buffers before calling `Reset`, and
`OpenFile` recreates a disposed buffer when `IsInitialized` is false before
its `Reset` branch. Direct callers can still use the defensive internal
return; it is not a file-input target.

`BufferWriter.Truncate` is reachable through public merger rollback. The
five-byte `fuzz/writer-gap-seeds/merger-import-rollback-mtr1.bin` sample imports
one good file, then injects an `IParquetReadSource.ReadExactly` failure at the
second row group's chunk offset of a two-group file. The first group appends
metadata before the failure, so `ParquetWriter.ImportFile` must truncate it
back to the prior metadata length. The merger counters and final readable
destination remain equal to the first file. Release Replay passed with zero
unexpected faults; isolated Coverlet versus the complete raw `ae` inventory
hit nine exact previously unhit `BufferWriter.Truncate` tuples:
`(111,2,0,0)`, `(111,11,1,3)`, `(114,90,0,4)`, `(114,99,1,7)`,
`(120,192,0,12)`, `(120,192,1,13)`, `(126,167,1,9)`, `(126,170,0,10)`,
and `(132,195,1,15)`. With a 64-byte metadata chunk, the same rollback
also reaches `(126,170,1,11)` when the appended metadata spans segments.
A six-byte companion
`fuzz/writer-gap-seeds/merger-initial-rollback-mtr1.bin` injects the same
failure while constructing the merger's first file. It verifies that the
aborted destination remains a valid empty Parquet file and reaches two more
exact outcomes: `(126,167,0,8)` and `(132,195,0,14)`. A third six-byte
sample, `fuzz/writer-gap-seeds/merger-before-metadata-rollback-mtr1.bin`,
fails on the first imported chunk before metadata grows; it reaches the
equal-length early return `(114,99,0,6)`. All three focused samples passed
Release Replay; the other `Truncate` outcomes remain unreviewed.
The invalid-length outcomes `(111,2,1,1)` and `(111,11,0,2)` have no public
merger route: `ParquetWriter.ImportFile` is the sole `Truncate` caller and
passes a nonnegative `WrittenLength` snapshot; inside its import `try`, row
group metadata is appended or left as-is, never shortened. The disposed
segment outcome `(114,90,1,5)` is likewise preempted because that metadata
buffer remains initialized throughout import and rollback. These are
defensive internal checks, not removal recommendations.

Six further `BufferWriter` segment-management outcomes have no normal caller
route. `EnsureCurrentSegment` is private and its only two callers in
`EnsureWritable` have already checked that both `_segments` and `_pool` are
non-null, excluding `(281,6,1,1)` and `(281,14,0,2)`. They call it only when
`_currentSegmentIndex == _segmentCount`, excluding its existing-segment return
`(285,53,0,4)`; the nested `EnsureSegmentCapacity` null check
`(296,6,0,0)` is preempted for the same reason. Constructor inputs are
positive and at most `int.MaxValue`, so
`(initialBufferBytes + chunkSizeBytes - 1) / chunkSizeBytes` is between 1 and
`int.MaxValue` without `uint` overflow. This excludes both the initial
segment-count overflow `(312,13,0,0)` and the zero-length segment-table
fallback `(301,38,1,5)`. These are defensive internal guards, not file
mutation targets.

Nine `BufferWriter` content guards are also preempted by their production
callers. `TryGetSingleWrittenSpan` is called on initialized page or compression
buffers, excluding its null-segment arm `(66,6,1,1)`; with positive
`WrittenLength`, `Advance` has recorded written bytes in a segment, excluding
the no-data fallback `(86,80,0,10)`. Its sole caller is compression, which
is entered only for positive page content or positive V2 value bytes, excluding
the empty-content arm `(66,14,0,2)`. The only `WriteTo` route is
`ParquetWriter.WriteBuffer`, whose page and metadata buffers are initialized
before writing, excluding `(146,17,1,1)`. Both `CopyTo` callers supply a
destination of at least `WrittenLength` and an initialized source, excluding
`(161,13,0,0)` and `(163,37,1,3)`; the same positive-content compression
guard excludes `(163,45,0,4)`. Page CRC calculation receives
initialized page content, excluding `(181,8,1,1)`. The three `CopyFrom`
source routes use an initialized compressed-values buffer, an initialized
file row-group metadata buffer, or a freshly constructed ALP vectors buffer,
excluding `(207,6,1,1)`. These are defensive
internal conditions; other BufferWriter outcomes are still unreviewed.

### Nullable decimal statistics fallback

The two unhit outcomes at `ColumnStatistics.CreateNullableDecimal` line 646
belong to the private overload that allocates fresh byte arrays. Its only
source call is from `CreateOptional<T>`; that method is reached from the
reusable-buffer dispatcher, which selects the other `CreateNullableDecimal`
overload for `decimal` before the fallback. A complete production call-site
search found no direct caller of `CreateOptional<T>`. The public optional
DECIMAL control (`0xEB + ODBG`) replayed cleanly and reached the reusable
overload, adding no new `ae` tuples. The two line-646 outcomes have no current
public writer route; they are narrow dead-code candidates, while other
`ColumnStatistics` misses remain unreviewed.

### Optional statistics fallback dispatchers

The nullable generic `CreateOptional<T>` dispatch outcomes at
`(236,220,path 0,ordinal 10)` for decimal and `(238,260,path 0,ordinal 12)`
for `ReadOnlyMemory<byte>`, plus both outcomes of the class overload at
`(247,25,path 0/1,ordinal 0/1)` for `byte[]`, are internal fallback routes.
The full call graph has only one production caller of nullable
`CreateOptional<T>`: the non-binary fallback in
`CreateOptionalWithReusableBinaryBuffers<T>`. That dispatcher selects decimal
and nullable memory into their reusable overloads before its fallback. The
class reusable dispatcher selects `byte[]` directly into
`CreateOptionalByteArray`; it does not call the class `CreateOptional<T>` for
that type.

The apparent nullable-primitive route also does not reach this fallback from a
public writer. `SerializedColumn.SerializeOptionalCore<TValue>` routes nullable
bool/int/long/float/double through fused PLAIN/dictionary paths and obtains
statistics from encoded pages, or compacts present values before
`SerializeOptionalConverted`. A focused WMD1 public-writer sample for all five
primitive types replayed cleanly, but private Coverlet showed zero hits in the
`CreateOptional` overloads; the sampled primitive statistics came from the
encoding/page-statistics path. No supported public writer type remains that can
select the fallback call. The four exact tuples are therefore marked
`internal_optional_statistics_fallback_no_public_route`; this does not classify
other `ColumnStatistics` misses.

### Default data-page statistics guard

The writer metadata slice has one classified unhit outcome at
`ParquetMetadataThriftWriter.WriteStatistics` line 872 (branch
`(872,6,0,0)`). It is the early return for `!statistics.HasStatistics`, and
the normal public writer path cannot pass a default `ColumnStatistics` there:
`RowGroupWriter` copies populated statistics or replaces missing statistics
with `ColumnStatistics.Empty(nullCount)`, whose constructors set
`HasStatistics=true`. Data page headers receive statistics produced by the
encoding path; dictionary page headers do not call `WriteStatistics`. Thus a
file-shaped input cannot select this guard, and no fuzz sample was added. The
other zero-hit `ColumnStatistics` and metadata tuples remain unreviewed; this
classification does not generalize to them.

### Native zlib platform branches

The audit queue contains 38 unhit outcomes in `ZlibLibraryResolver` and five
in `ZlibNative`. These are a mix of Linux x64 host restrictions and loader
failure/environment cases, not dead code. `GetCurrentPlatform` checks Android,
Windows, Linux, and macOS from the process OS; Parquet bytes cannot alter the
result. `ZlibNative` chooses Windows versus Unix stream layouts on the same
host property. The resolver's pure candidate builders, however, can be called
with synthetic platforms and architectures. Existing
`Plank.Tests/Compression/ZlibLibraryResolverTests.cs` already supplies those
samples for all shipped platform/architecture pairs, unsupported architectures,
and unknown platforms. These are API-test routes rather than fuzz-file routes.
The remaining `Resolve`/`TryLoadRuntimeAsset` misses include absent native
assets and failed system-library fallback; reproduce them in a deliberately
isolated loader test environment if needed, not by mutating Parquet inputs.

The combined `ae` reader inventory also has 18 uncovered outcomes in
`ColumnChunkReader.DecodeNullableInt32DictionaryNineBitPortable`. This is an
ARM AdvSimd implementation: its only call site in
`ColumnChunkReader.DecodeNullableInt32DictionaryRleBatch` is guarded by
`AdvSimd.IsSupported`, in addition to the canonical nullable layout, 9-bit
width, and eight-value-length checks. The four `ae` reports were collected on
Linux x64 (`x86_64`), where that ISA guard is false and no Parquet input can
enter this implementation. These tuples are host-specific, not unresolved
reader-input gaps; classify them as `arm_adv_simd_guard` and measure them on
ARM64 if coverage of the portable kernel is needed.

Another 28 exact tuples are the unhit side of a direct
`BitConverter.IsLittleEndian` check (`if` or ternary) in
`ColumnChunkReader`, `DeltaBinaryPackedDecoder`, `DeltaBinaryPackedEncoding`, `Encoding`, and
`PlainEncoding`. For each tuple, the opposite outcome at the same source line
and IL offset was hit in the eight-report `ae` union. This campaign host is
little-endian, so no input can take the other side here. The inventory labels
only those direct checks `big_endian_host_only`; compound conditions and whole
methods that were never entered remain unreviewed. These are portability
branches, not dead-code removal candidates. A big-endian runtime is needed to
execute them.

### Bloom-filter expected-count branch gap

Two `BloomFilterBuilder` sizing outcomes were unhit in the combined `ae`
inventory: `Build` `(19,46,path 1,ordinal 5)` and
`BuildOptionalReferences` `(54,32,path 1,ordinal 3)`. They select a caller's
`ExpectedDistinctValueCount` instead of counting values. The bounded
`0xF3` samples in `fuzz/bloom-estimate-seeds/` exercise a repeated FLOAT column
and an optional BYTE_ARRAY column with that option set. Release Replay passed
both inputs with zero unexpected faults or mismatches; a private Coverlet run
hit exactly those two previously unhit combined tuples. These branches are
reachable and the samples are held for a later fuzzing run.

An optional LIST with a null row has two additional reachable Bloom paths.
`fuzz/writer-gap-seeds/bloom-nullable-list-nbm2.bin` (`0xF0 + NBM2`) writes
nullable INT32 elements across present, null, and empty list rows; it checks
row count, flattened values, and Bloom membership on readback. Release Replay
passed with zero unexpected faults. Isolated Coverlet versus the complete raw
`ae` inventory hit exact `BloomFilterBuilder` tuples `(105,1,path 0,ordinal 0)`
and `(147,1,path 0,ordinal 0)` for counting and inserting a null repeated row.
These are valid public writer paths, not dead code.

### Public schema-options equality branch gap

`Schema/ColumnOptions.cs` has 20 unhit `Equals` outcomes and two unhit
`GetHashCode` outcomes in the complete `ae` union. `ColumnOptions` is a public
record with a hand-written value comparer; the normal file-shaped writer plan
constructs options but does not compare them. This is an API-route gap, not dead
code. The exact-gated `0xE4 + COEQ + mode` route and eleven six-byte samples in
`fuzz/schema-equality-seeds/` exercise identity, null, every field mismatch,
encoding count and element mismatches, and a distinct equal copy. Targeted
Release replay processed all 11 with zero faults or mismatches. A private
Coverlet JSON run on the same 11 samples measured 20/20 `Equals` outcomes and
2/2 `GetHashCode` outcomes covered. The samples are staged separately from the
live corpus so a later fuzzing run can decide whether this public API belongs
in the campaign; the historical `ae` coverage numbers remain unchanged.

### Dataset pending-row capacity guard

The combined `ae` inventory leaves four public dataset construction guards
unhit: `DatasetWriterOptions.Validate` capacity `(27,65,path 0,ordinal 0)`
and `DatasetWriterBase` empty files `(76,81,0,2)`, null file `(105,376,0,8)`,
and duplicate source `(109,447,0,14)`. The exact-gated `0xE3 + DWOV + mode`
route in `fuzz/dataset-options-seeds/` supplies four five/six-byte samples.
It asserts the expected argument exception and parameter for each invalid
public construction. Targeted Release Replay processed all four with zero
unexpected faults; private Coverlet hit each of those four exact `ae`-unhit
tuples once. A fifth six-byte sample constructs a valid dataset writer and
queues a null row; its expected `ArgumentNullException` hits the previously
uncovered `DatasetWriterBase.QueueRow` tuple `(165,12,path 0,ordinal 0)`.
These are input-validation branches, not dead code. The samples are staged
separately for later fuzzing.

The adjacent `DatasetWriterBase` check that a file source is also an
`IParquetReadSource` (line 106, offset 405, path 0, ordinal 12) has no generated
public route. `CreateDatasetWriter(route, files, options)` requires `TFile` to
implement both read and write source interfaces at compile time. The overload
that accepts write-only sources also requires a non-null `DatasetFilePath`, so
its `createFileParts` condition skips this check. A write-only-source probe
failed to compile against the read/write overload (`CS0311`), confirming the
generated constraint. Keep this as a defensive internal guard; no file seed
can exercise it through the generated API.

The additional `DatasetWriterBase` audit traced constructor guards at
`(61,11,path 0,ordinal 0)` and `(73,54,0,0)`: the first is preempted by the
generated factory's `filePath ?? throw` before the protected base constructor
is entered, and the second receives a source-generated positive row-buffer
capacity. They are tagged `internal_guard_generated_constraint`. For the
public queue guard, the bounded `0xFE + DBR1` sample in
`fuzz/dataset-operational-seeds/empty-path.bin` returns an empty partition
path and locally asserts the exact `InvalidOperationException` message. Release
Replay passed one input with zero unexpected faults or oracle mismatches.
Isolated Coverlet comparison against all eight raw `20261111ae` reports reached
exactly the previously unhit tuple `(172,56,path 0,ordinal 2)`; no other
`DatasetWriterBase` tuple changed. The remaining lifecycle and cleanup tuples
need fault-injection or state-transition probes before assigning a reachability
label.

The generated dataset writer also exposes two reachable lifecycle guards.
`fuzz/writer-gap-seeds/dataset-disposed-guards-dbr1.bin` (`0xFE + DBR1 + D1`)
constructs an empty writer, disposes it, and verifies that a second `Dispose`
throws the expected `InvalidOperationException` and a later `Queue` throws
`ObjectDisposedException`. Release Replay passed with zero unexpected faults.
Isolated Coverlet against the frozen eight-report `ae` union reached exact
previously unhit tuples `(236,6,path 0,ordinal 0)` and
`(802,25,path 0,ordinal 2)`. These are public lifecycle checks, not dead code.

Two adjacent guards have no route through the generated dataset writer:
`InitializeSlots`'s already-initialized throw `(147,6,path 0,ordinal 0)` and
`ThrowIfUnavailable`'s uninitialized throw `(800,6,path 0,ordinal 0)`.
Both flat and nested source generators emit sealed writers whose constructors
call `InitializeSlots` exactly once before returning. They expose `Queue` and
`Dispose`, not the protected initializer. A custom subclass of the public
unstable `DatasetWriterBase<T>` could call the protected methods differently,
so these are defensive subclass API checks rather than dead-code candidates
or file-input fuzz targets.

`fuzz/writer-gap-seeds/writer-lifecycle-wlc1.bin` (`0xE2 + WLC1`) checks public
`ParquetWriter` state transitions: a second `StartRowGroup` and `CloseFile`
while a row group is open, then `StartRowGroup` after closing and after
disposing, plus idempotent disposal. Release Replay passed with zero unexpected
faults. Isolated Coverlet against the frozen `ae` union newly reached five
exact tuples in `ParquetWriter.cs`: `(281,12,0,0)`, `(319,6,0,0)`,
`(330,12,0,0)`, `(342,12,0,0)`, and `(348,6,0,0)`. These are reachable public
state checks, not dead code.

The earlier complete `ae` snapshot covers 10,871/13,680 library branches
(79.5%); 2,809 raw branch records remain unhit. **That count is not a count of
dead branches.** The largest unhit slices are writer value encoding and
serialization (824), writer schema/statistics/metadata (482), and reader column
chunk decoding (495). Valid input shapes may still reach some of these; the
`af` writer snapshot was stopped before all four tiers completed at the user's
request, although its first two tiers measured 11 additional writer tuples.

High-confidence limits identified by source and targeted probes:

| Code | Why ordinary valid corpus inputs do not reach it | Treatment |
|---|---|---|
| `ColumnChunkReader.TryDecodeBinaryDataPage` decoding body | Supported flat binary pages take the earlier encoded-batch dispatcher; 16 valid V1/V2 controls left the body unhit. | Removal candidate after the compatibility matrix and full saved-corpus check below. |
| `PlainEncoding.WriteOptionalFixedLengthPayloads` call | The preceding `byte[]` branch returns, and the only remaining call guard also requires `byte[]`. | Narrow removal candidate after writer round trips. |
| `DeltaBinaryPackedEncoding.WritePackedUnsignedValues` | Repository-wide source search finds calls only in `Plank.Tests/Reading/DeltaBinaryPackedDecoderTests.cs`; production encoding uses other packers. | Removal or test-helper relocation candidate after checking external internal access contracts. |
| `ColumnChunkReader.ReadUnsignedVarInt` final over-five-byte throw | The fifth-byte high-nibble check rejects a continuation before control can reach the final throw. | Defensive cleanup, not a fuzz seed target. |
| `PageIndex` constructor null-array fallbacks | The public row-group writer calls `EnsurePageIndexCapacity` before passing arrays to the internal constructor. | Keep defensive guards; no valid public writer route. |
| ARM AdvSimd, big-endian, and alternate zlib loader arms | This campaign runs on Linux x64; these outcomes depend on host ISA, byte order, or platform rather than file bytes. | Test on the relevant host; do not count as removable code. |
| Invalid footer sorting/path ordinals, page-index bounds, and impossible batch sizes | Earlier strict metadata validation rejects the malformed structure before the later decoder/cursor guards. | Keep corruption guards; target with focused malformed-input tests only where the public parser can reach them. |
| `RleBitPackingHybridEncoding.WriteBitPackedRunUnchecked` residual 3 outcomes | The public writer never passes empty literal spans, bit width 32 uses an earlier byte-aligned path, and eight-value padding ends with zero buffered bits. | Keep internal guards; the 17-bit valid route covers the other ten previously missing outcomes. |

The source-level evidence, current branch IDs, and removal validation plan are
in the sections below. These examples explain part of the remaining 2,809;
they do not establish that all unhit branches are unreachable.

The first `20261111i` reader replay was invalidated: a newly added logical-type
probe used selector bytes already present in unrelated AFL queue inputs and
raised 843 false harness faults per ISA tier. Its logs were kept under
`fuzz/coverage/history/invalidated-20261111i-reader/`. The probe now requires
an `RAPI` marker and the exact four-column signed-INTEGER schema before its
strict assertions run. A full plain Replay of the current reader corpus and
findings processed 184,113 inputs with exactly the prior 12 delta failures;
the corrected four-tier coverage replay is included in the HTML report. Live
reader fuzzing has resumed. The extra faults were harness defects, not library
defects.

The `20261111ae` reader replay covered 191,617 frozen inputs per tier, recorded
the same 12 malformed DELTA failures per tier, and stayed at 5,628/6,774
reader branches (83.1%). Its frozen input tree was retained under
`fuzz/.coverage-work/snapshot-reader-20261111ae`.
The `20261111ad` reader replay covered 191,009 frozen inputs per tier, recorded
the same 12 malformed DELTA failures per tier, and reached 5,628/6,774
reader branches (83.1%), up one from `ac`. The exact-gated nullable DATE
type-rejection route below accounted for the new branch in a private four-tier
comparison. Its frozen input tree was retained under
`fuzz/.coverage-work/snapshot-reader-20261111ad`.
The `20261111ac` reader replay covered 190,919 frozen inputs per tier, recorded
the same 12 malformed DELTA failures per tier, and stayed at 5,627/6,774
reader branches (83.1%). Its frozen input tree was retained under
`fuzz/.coverage-work/snapshot-reader-20261111ac`.
A subsequent private four-tier probe adds one `RowGroup.ValidatePhysicalType`
branch tuple through the public `RowGroup.Column<ReadOnlyMemory<byte>?>` type
rejection on a strict, valid nullable INT32 DATE file. The exact-gated `0x6C` +
`RGVT` route checks the schema and values, requires `NotSupportedException`,
then runs ordinary strict/Arrow readback. Each private tier replay processed
one seed with zero unexpected throws or oracle mismatches and compared 1 column
/ 2 values with Arrow; the same tuple was new against each `ac` tier. The seed
was copied to the active reader corpus for the next shared snapshot.
The `20261111ab` reader replay covered 190,321 frozen inputs per ISA tier,
recorded 12 strict faulting inputs per tier, and reached 5,627/6,774 reader
branches (83.1%), up one from `aa`. The bounded `PMOR` route covered the
previously unhit public footer-ordinal guard while preserving strict file and
Arrow readback.
The `20261111aa` reader replay covered 190,187 frozen inputs per ISA tier,
recorded 12 strict faulting inputs per tier, and stayed at 5,626/6,774 reader
branches (83.1%). Its exact frozen input tree was retained under
`fuzz/.coverage-work/snapshot-reader-20261111aa` for per-input provenance.
The `20261111z` reader replay covered 190,109 frozen inputs per ISA tier,
recorded 12 strict faulting inputs per tier, and stayed at 5,626/6,774 reader
branches (83.1%). The 39-file valid BSS/plain audit below found no additional
raw reader branch tuples; no new reader route was added in `z`.

A physical-footer audit of the four raw `reader-20261111z-{scalar,sse,avx2,avx512}..json` reports found four uncovered `PhysicalMetadataThriftReader` branch records (356/360 covered): out-of-range sorting ordinals (`ReadRowGroup` 603), sorting-list capacity overflow (623), duplicate sorting ordinals (631), and out-of-range column-chunk ordinal (`ReadAndValidatePath` 916). These are corruption guards; the valid PyArrow two-column sorting seed already exercises the successful sorting path. No strict valid footer can hit those guards. A bounded `0x6E` + `PMOR` route now probes the public physical metadata API with a valid PyArrow two-column sorting file, calls `ColumnSchema(ColumnCount)`, and requires exactly `ArgumentOutOfRangeException` with `ParamName=columnOrdinal` and `ActualValue=ColumnCount`. It then performs the ordinary strict file-schema and Arrow readback. Targeted Release Replay passed: one input, zero unexpected throws or oracle mismatches, 2 columns / 6 values checked. Private Coverlet confirms branch tuple `(ParquetFileMetadata.ValidateOrdinal, line 202, offset 2, outcome true)` is covered by the seed; it remained at 0 hits in all reader-aa raw tiers before this route. This is a valid-file public API boundary outcome, not metadata-format coverage. The private raw probe and shared Release builds were performed after the writer-aa snapshot completed.
The `20261111y` reader replay covered 190,007 frozen inputs per ISA tier,
recorded 12 strict faulting inputs per tier, and reached 5,626/6,774 reader
branches (83.1%), up two from `x` as the live queue grew; no new reader route
was added for this snapshot.
The `20261111x` reader replay covered 189,476 frozen inputs per ISA tier,
recorded 12 strict faulting inputs per tier, and reached 5,624/6,774 reader
branches (83.0%), up one from `w`. A valid no-`created_by` concatenated-gzip
fixture checks 513 values with Arrow and reaches the absent-metadata getter
branch. Its targeted Release replay had zero faults or mismatches.
The `20261111w` reader replay covered 188,528 frozen inputs per ISA tier,
recorded 12 strict faulting inputs per tier, and reached 5,623/6,774 reader
branches (83.0%), up 15 from `v`. The new `RSTR` route uses two small required
INT32 files to exercise RowReader stream reset, source ownership, generated
read-ahead, and missing-column defaults with strict values and ParquetSharp
checks. The existing `PMEN` route now exercises idempotent cursor disposal
and retains normal strict file-schema/Arrow readback. Targeted Release replay
of all three active seeds completed with zero unexpected faults or mismatches.
The `20261111v` reader replay covered 188,397 frozen inputs per ISA tier,
recorded the same count of 12 strict faulting inputs per tier, and reached
5,608/6,774 reader branches (82.8%), up one from `u`. The newly hit outcome
is nested dictionary page decoding in `ColumnChunkReader`. Two valid
selector-0 fixtures for nested maps and list columns passed targeted strict
replay; the other apparent private branch gains were already present in the
full reader union and are not credited to this run.
The `20261111u` reader replay covered 187,765 frozen inputs per ISA tier,
recorded 12 strict faulting inputs per tier, and raised reader-only coverage to
5,607/6,774 (82.8%), up nine branches from `t`. The new valid buffer-retention
seed checks borrowed INT32 values, nested BYTE_ARRAY values, and nested levels
after disposing the reader and overwriting source bytes. Its targeted replay
passed with zero faults or oracle mismatches. The full snapshot adds one more
branch outcome than the eight data-route outcomes isolated by the private
probe, so the additional outcome is not attributed to that seed.
The `20261111t` reader replay covered 187,758 frozen inputs per ISA tier and
found the same 12 known DELTA exceptions; coverage stayed at 5,598/6,774
(82.6%) despite live queue growth.
The first `20261111ae` writer attempt was invalidated: four parallel Coverlet
replays reached roughly 80,000 of 88,132 frozen inputs before three aborted
following `OutOfMemoryException` and native termination; the fourth emitted
no valid coverage report. The failed logs are under
`fuzz/coverage/history/invalidated-20261111ae-writer-oom/`. The runner now
supports retained-snapshot reuse and a concurrency cap. Retrying the same
frozen input tree two tiers at a time completed all four tiers: 88,132 inputs,
65 faulting inputs and zero oracle mismatches per tier. Every fault line in
all four logs is the already confirmed floating append sorting-metadata
assertion. Writer-only coverage reached 5,195/6,906 (75.2%), up exactly 16
from `ad`: five nullable DOUBLE dictionary outcomes, ten optional UUID Bloom
and serialized-column outcomes, and one distinct write-source reset outcome.
The raw combined library union reached 10,871/13,680 (79.5%); cumulative
ever-observed coverage reached 10,877/13,680. The writer input tree was
retained under `fuzz/.coverage-work/snapshot-writer-20261111ae`.
### Writer schema/statistics/metadata and page-index gap audit

I audited the raw `20261111ae` four-tier reports, focusing on
`ParquetMetadataThriftWriter`, `ColumnStatistics`, `PageIndex`, and the public
`RowGroupWriter` route. This slice's 482 unhit branch records are a mix of
unexplored valid shapes and guards that normal public construction cannot
reach; they are not evidence of 482 dead branches. Existing focused writer
metadata controls exercise schema MAP/LIST/LOGICAL shapes, statistics
(including unsigned, nullable, floating, binary/memory, and decimal cases),
V1/V2 page indexes, and dictionary page shapes, but do not establish that all
corresponding branch outcomes are covered. `PageIndex`'s three unhit null-array
fallbacks (constructor lines 7–9) are unreachable from the public writer:
`RowGroupWriter.Write` calls `EnsurePageIndexCapacity` before constructing it
(lines 85–90, 172, 246–268), which allocates all three arrays. Classify these
as defensive internal fallbacks, not a seed target. Likewise, the
`WriteColumnIndex` statistics/null-page length mismatch throw (line 90) is
internal and the public caller supplies both arrays from the same page count.

Reachable raw `ae` gaps include imported metadata with absent column statistics:
`WriteImportedStatistics` returns at line 904 when `EncodedStatistics.HasValues`
is false. The 387-byte focused seed
`fuzz/writer-gap-seeds/imported-missing-statistics-ims1.bin` reaches this
public merger route and verifies strict output values/footer plus ParquetSharp
readback; it is deliberately new after `ae`, so the branch remains unhit in
that frozen snapshot pending a complete later snapshot. Targeted Release
Replay of this seed passed with zero unexpected faults or oracle mismatches.
The existing compact metadata seeds
`writer-metadata-page-stats-v1.bin`, `writer-metadata-page-stats-v2.bin`,
`writer-metadata-map-basic.bin`, and `writer-metadata-map-nested-list.bin`
also passed together in targeted Release Replay (4 inputs, zero faults or
mismatches). These are the replayable controls for the reachable page-index,
schema, and statistics routes. Source evidence: `RowGroupWriter.Write` lines
85–90 / 170–174 creates indexes only after capacity is ensured;
`ParquetMetadataThriftWriter.WriteColumnIndex` serializes one statistics
entry per supplied null-page flag (lines 87–115), and `WriteImportedStatistics`
handles each optional imported statistics field independently (lines
901–923). More fixture-specific unhit schema/statistics arms need private
source probes before being labeled unreachable; this audit does not classify
them as dead.

### Imported chunk Bloom metadata branch

One additional `ae`-unhit outcome is reachable when the merger imports a file
that actually carries a Bloom filter. `ParquetWriter.ImportRowGroup` checks
`sourceChunk.HasBloomFilter` and copies a non-empty filter (lines 695–701); the
rewritten chunk metadata then takes the positive `relocated.BloomFilterLength`
branch in `ParquetMetadataThriftWriter.WriteImportedColumnChunk` (line 841,
offset 192, path 0). These are valid imported-file metadata paths, not dead
guards. The existing IMS1 control has no Bloom filter, so it cannot reach them.

The new exact `IMX1` route builds a small required-INT32 source with Bloom
filter and page indexes, merges it through the public API, and verifies all
values, index lengths, Bloom-filter presence, and independent ParquetSharp
readback. Replayable seed: `fuzz/writer-gap-seeds/imported-indexes-bloom-imx1.bin`.
Targeted Release Replay passed (1 input, zero unexpected faults or oracle
mismatches). A private Coverlet replay compared with the `ae` scalar report
measured three newly hit tuples: `ParquetWriter.ImportRowGroup` `(695,268,0)`
and `(698,293,0)`, plus `ParquetMetadataThriftWriter.WriteImportedColumnChunk`
`(841,192,0)`. This establishes the metadata outcome on the current build; the
private probe is one tier, not a replacement for a complete four-tier snapshot.

### Invalid timestamp-unit metadata guard

The `ae` unhit TSV also contains `ParquetMetadataThriftWriter.WriteTimeUnit`
branch `(line 762, offset 8, path 0, ordinal 0)`. The three defined units
already take the normal switch arms; this outcome is the default throw for an
undefined `TimeUnit`. It is reachable through the public schema API because
`LogicalType.Timestamp` accepts the enum value and `ColumnDefinition` checks
the physical type but does not validate the enum range. The failure occurs
when the public writer serializes the footer. This is a hard-to-reach
invalid-configuration guard, not dead code or a malformed-file route.

The new `writer-metadata-invalid-timeunit.bin` seed selects a bounded
`WriterMetadataCases` route that builds an INT64 timestamp column with
`(TimeUnit)99`, closes the writer, and requires the documented
`ArgumentOutOfRangeException` (`ParamName == "unit"`, matching `ActualValue`).
Targeted Release Replay passed (1 input, zero unexpected faults or oracle
mismatches). Private Coverlet replay hit exactly the missing switch outcome:
`WriteTimeUnit` `(762,8,path 0)` had one hit; the valid Millis/Micros/Nanos
arms were not entered by this negative control.

The `20261111ad` writer replay covered 88,101 frozen inputs per tier, recorded
66 strict faulting inputs and zero oracle mismatches in each ISA tier, and
reached 5,179/6,906 writer branches (75.0%), up 34 from `ac`. Private exact
tuple comparisons attributed 27 writer outcomes to the temporary optional
Decimal/Bloom known-defect probe, six to bounded variable-width Row API slot
growth, and one to same-stream writer reset. The raw combined library union
reached 10,855/13,680 (79.3%), up 36; the additional one combined outcome
beyond the 35 targeted reader/writer outcomes is not attributed to a seed.
Cumulative ever-observed coverage reached 10,861/13,680. The writer input tree
was retained under `fuzz/.coverage-work/snapshot-writer-20261111ad`.
The one-input strict-fault increase from `ac` appeared only in the instrumented
run. A normal full replay of the exact retained `ad` tree logged 65 faults,
all the known append-sorting assertion, and zero other faults or mismatches;
the per-input log is `fuzz/.scratch/writer-ad-fault-detail.log`. The 486 newly
named inputs and nine changed queue inputs also replayed cleanly in isolation.
The instrumented count difference is not a new confirmed library defect.
A subsequent bounded `0xE9` + `ODDC` writer route writes two all-present
nullable DOUBLE dictionary shapes through the default page strategy:
ascending values and descending values with duplicates. Plank and
ParquetSharp check all 1,024 values per shape. Targeted strict Replay passed
both inputs with zero faults or oracle mismatches. Private Coverlet replay of
the actual new route added five exact `TryEncodeOptionalDoubleDictionary`
branch tuples over the four-tier `ad` union, with no buffer-pool pressure
branches. The two six-byte seeds are in `fuzz/writer-gap-seeds`; this is a
focused result, pending the next full snapshot.
A separate exact-gated `0xE7` + `RDS1` route resets an open writer onto a
distinct public `IParquetWriteSource`, verifies closure of the old stream and
new source, and reads back the replacement file's exact rows. Its gap-only seed
passed targeted private Replay with zero faults or oracle mismatches. Four-tier
private Coverlet comparison against the `ad` union isolated one new
`ParquetWriter.Reset(IParquetWriteSource)` branch tuple (line 218, offset 43,
path 1); this focused result is pending the next full snapshot.
A bounded `0xE6` + `IMS1` route imports a PyArrow-written required INT32 file
whose column-chunk statistics field is absent. It checks the public merger
counters, strict Plank row values and footer, plus ParquetSharp value readback
and `IsStatsSet == false`. The merged output also passed an independent
PyArrow value/footer check. Private actual-route Coverlet hit one new
`ParquetMetadataThriftWriter.WriteImportedStatistics` tuple (line 904, offset
6, path 0); this tuple has zero hits in every raw `ae` writer tier and is
pending the next full snapshot. The 387-byte fixture is in
`fuzz/writer-gap-seeds/imported-missing-statistics-ims1.bin`; generation and
verification details are in its companion README.
The `20261111ac` writer replay covered 87,616 frozen inputs per tier, recorded
65 strict faulting inputs and zero oracle mismatches in each ISA tier, and
reached 5,145/6,906 writer branches (74.5%), up one from `ab`. A six-byte
encoding-route seed writes 32,768 required INT32 values through a dictionary
drop checkpoint and checks every value on readback. Private Coverlet comparison
identified the same new `DefaultStrategy.ShouldDropDictionary` branch tuple in
all four tiers. The raw combined library union reached 10,819/13,680 (79.1%),
and cumulative ever-observed coverage reached 10,825/13,680. The writer input
tree was retained under `fuzz/.coverage-work/snapshot-writer-20261111ac`.
A narrowly gated `SSR1` route writes stale rows, resets the open writer onto the
same seekable stream, then checks the replacement file's exact values and
single-row-group shape. Targeted four-tier Release replay passed with zero
throws or oracle mismatches; private Coverlet comparison against the `ac` four-tier
union isolated one new `ParquetWriter.Reset(Stream)` branch tuple (line 189,
same-stream outcome) and zero new Dataset-writing tuples. Private build and
coverage artifacts are under `fuzz/.coverage-work/writer-same-stream-private`;
this focused result is not a new full-snapshot total.
The `20261111ab` writer replay covered 87,608 frozen inputs per tier, with
zero oracle mismatches. Its writer-only union remained 5,144/6,906 (74.5%);
the raw combined library union rose one branch to 10,818/13,680 (79.1%).
The tier-dependent strict fault increase did not recur, as noted above.
The `ab` reader gained one public metadata ordinal guard, bringing
its union to 5,627/6,774 (83.1%).
The `20261111aa` writer replay covered 87,601 frozen inputs per ISA tier,
counted 65 strict faulting inputs per tier, and recorded zero oracle
mismatches. The writer-only union reached 5,144/6,906 (74.5%), up 68 from
`z`. A 28-case public converter matrix covered all legal required and
nullable physical CLR mappings with exact logical, converter-free physical,
null-position, and footer checks. Private four-tier exact-tuple comparison
isolated the same 68 writer gains, 52 in the two converter dispatch methods.
The raw combined library union reached 10,817/13,680 (79.1%), up 79 from
`z`; cumulative ever-observed coverage reached 10,823/13,680. The full
current-Release replay of 87,582 saved writer inputs with only the confirmed
FLOAT/DOUBLE sorting-loss bypass enabled found **zero other faults or oracle
mismatches**. The frozen writer input tree was retained under
`fuzz/.coverage-work/snapshot-writer-20261111aa`.
The `20261111z` writer replay covered 87,041 frozen inputs per ISA tier,
counted 64 strict faulting inputs per tier, and recorded zero oracle
mismatches. The writer-only union reached 5,076/6,906 (73.5%), up 24 from
`y`: a four-value required fixed-width BYTE_ARRAY byte-stream-split route
added 13 exact writer outcomes, and a Decimal(9,2) INT32 DELTA_BINARY_PACKED
route added 11. Both pass strict logical/raw values and footer statistics.
The raw combined library union reached 10,738/13,680 (78.5%); cumulative
ever-observed coverage reached 10,744/13,680. A full current-Release replay
of 86,689 saved writer inputs with only the known FLOAT/DOUBLE sorting-loss
bypass enabled found **zero other faults or oracle mismatches** before the
frozen coverage run.
The `20261111y` writer replay covered 86,326 frozen inputs per ISA tier,
counted 63 strict faulting inputs per tier, and recorded zero oracle
mismatches. The writer-only union reached 5,052/6,906 (73.2%), up ten from
`x`, including nine Row API/buffering outcomes from the bounded direct
`RowGroupWriter` route. The seed strictly checks three fixed rows, an empty
second row group, and three binary rows with empty and non-ASCII values.
The raw combined library union reached 10,714/13,680 (78.3%); cumulative
ever-observed coverage reached 10,720/13,680. A full current-Release replay
of 86,080 saved writer inputs with only the known FLOAT/DOUBLE sorting-loss
bypass enabled found **zero other faults or oracle mismatches**.
The `20261111x` writer replay covered 85,716 frozen inputs per ISA tier,
counted 62 strict faulting inputs per tier, and recorded zero oracle
mismatches. Its writer-only union reached 5,042/6,906 (73.0%), up 32 from
`w`; file and stream writing rose by 27 branches to 289/428. The bounded
five-byte merger route strictly verifies zero-row-group skips, CreatedBy and
key/value metadata merge, append-to-latest page-index/Bloom layout, no-op
append restore, and incompatible integer sorting metadata. It accounted for
those 27 area outcomes in a private exact-tuple comparison; the additional
five outcomes in the full union are not attributed to that route. The raw
combined library union reached 10,700/13,680 (78.2%); cumulative
ever-observed coverage reached 10,706/13,680. A full current-Release replay
of 85,176 saved writer inputs with the known FLOAT/DOUBLE sorting-loss bypass
enabled found **zero other faults or oracle mismatches** before the frozen
coverage run; the strict count grows with live queue inputs.
The `20261111w` writer replay covered 85,088 frozen inputs per ISA tier,
counted 58 strict faulting inputs per tier, and recorded zero oracle
mismatches. Its writer-only union reached 5,010/6,906 (72.5%), up one from
`v`: the optional one-byte `ReadOnlyMemory<byte>` PLAIN route with alternating
nulls covered the remaining null-run outcome. Targeted strict readback passed
for the six-row seed. The raw combined library union reached 10,668/13,680
(78.0%), up 14 from `v`; cumulative ever-observed coverage reached
10,674/13,680. A full current-Release replay of 85,149 saved writer inputs
with only the confirmed FLOAT/DOUBLE sorting-loss bypass enabled found
**zero other faults or oracle mismatches**.
The `20261111v` writer replay covered 84,249 frozen inputs per ISA tier,
counted 56 strict faulting inputs per tier, and recorded zero oracle
mismatches. The writer-only union reached 5,009/6,906 (72.5%), up 17 from
`u`; Dataset writing reached 227/296, up 10, while non-seekable gzip output
and writer reset supplied the other seven writer-only outcomes. The raw
combined library union reached 10,654/13,680 (77.9%), up 18 from `u`,
including the new reader nested-dictionary outcome. Cumulative ever-observed
library coverage reached 10,660/13,680. A current-Release replay of 84,245
saved writer inputs with only the confirmed FLOAT/DOUBLE sorting-loss bypass
enabled counted **zero other faults or oracle mismatches**. Both new routes
also passed targeted strict readback.

The `20261111u` writer replay covered 84,213 frozen inputs per ISA tier and
counted 56 strict faulting inputs per tier, with zero oracle mismatches. Its
writer-only union stayed at 4,992/6,906: the Release replay binary copied for
that snapshot predated the new Dataset route, which had first been built in
Debug. The route's two seeds were therefore present but did not exercise it.
Before the Release rebuild, a full replay of 84,193 saved writer inputs with
only the confirmed FLOAT/DOUBLE sorting-loss bypass enabled counted zero other
faults or oracle mismatches; it did not validate the new routes. The `20261111t`
writer replay covered 83,720 frozen inputs per ISA tier and counted 52 strict
faulting inputs per tier.
Counts across runs differ because AFL continues adding queue inputs while the
frozen coverage snapshot runs.

The `20261111t` writer-only union reached 4,992/6,906 (72.3%), up 21
branches from `s`; the raw combined library union reached 10,629/13,680
(77.7%), up 21. The cumulative ever-observed union reached 10,635/13,680.
New strict routes exercise nullable temporal statistics and optional DOUBLE
dictionary handling of signed zero, NaN, and nulls.

The `20261111s` writer-only union reached 4,971/6,906 (72.0%), up 37
branches from `r`; the raw combined library union reached 10,608/13,680
(77.5%), up 43. The cumulative ever-observed union reached 10,614/13,680.
The new valid routes include a nested repeated LIST Bloom filter, required
INT96 plain values, and optional one-byte `ReadOnlyMemory<byte>` payloads.
Each passed exact readback, and the nested Bloom route also checked its page
indexes and membership without false negatives.

The `20261111r` writer-only union reached 4,934/6,906 (71.4%), up 43
branches from `q`; the raw combined library union reached 10,565/13,680
(77.2%), up 48. The cumulative ever-observed union reached 10,571/13,680.
The new `RWP1` route covers bounded rolling files, stream reset, and flush
callbacks with exact value readback across every written file and stream.
It added the Row API pipeline and file-writing branches measured in `r`.

The `20261111q` writer-only union reached 4,891/6,906 (70.8%), up 123
branches from `p`; the raw combined library union reached 10,517/13,680
(76.9%), up 124. The cumulative ever-observed union reached 10,523/13,680.
Boolean RLE run shapes, Int32/Int64 byte-stream split, repeated unsigned
statistics, and required DateTime dictionary statistics account for the
targeted routes. All passed exact readback and footer checks where present.

The `20261111p` writer-only union reached 4,768/6,906 (69.0%), up 161
branches from `o`; the raw combined library union reached 10,393/13,680
(76.0%), up 168. The cumulative ever-observed union reached 10,399/13,680.
The writer gains include forced required byte-array dictionary sorted/cyclic
indexes, optional DOUBLE small dictionary indexes across row groups, an
all-null/no-index merger import, and nested-binary dataset snapshots. All
new named routes pass targeted exact readback; the full saved-corpus replay
found no new fault beyond the known sorting metadata loss.

The `20261111o` writer-only union reached 4,607/6,906 (66.7%), up 128
branches from `n`; the raw combined library union reached 10,225/13,680
(74.7%), up 134. The writer additions include optional Decimal statistics
and bounded generated nested-row Map/List/record writes. The cumulative
ever-observed union reached 10,231/13,680. Private probes isolated 42
writer-classified branch gains from Decimal statistics and 63 from two
nested-row seeds against `n`. The bounded generated-row route is selected by
the exact `0xFF` + `NRW1` marker and writes 4–16 rows across nested lists, maps,
and records. Both private seeds completed exact readback checks for every
field. In the `o` snapshot only `rowapi-nested-collections-maps.bin` was valid;
`rowapi-nested-low-capacity.bin` had been overwritten by a hex dump and
contributed nothing there. It was restored from the validated private binary
afterward. A focused Coverlet replay of the restored input completed cleanly
and added zero writer branch IDs over the `o` four-tier union.
The full snapshot remains authoritative for the combined gain because live
AFL queue growth and route interactions also contribute.

The `20261111n` coverage snapshot added one reader-only and 97 writer-only
branches over `m`. Reader branch coverage reached 5,578/6,774, writer-only
4,479/6,906, and the raw combined library union reached 10,091/13,680. The
cumulative ever-observed union for the unchanged branch set reached 10,097.
The reader gain is the constant-ALP DOUBLE zero-bit-width path. The writer
gains include public MAP/LIST schema metadata, nullable/unsigned statistics,
serialized-column paths, and append comparator cases; some live queue inputs
also contributed. A focused audit found that the two remaining
`SplitBlockBloomFilter.ValidateBitset` branches are preempted through public
file reads by `BloomFilterReader.ReadHeader`, which rejects undersized or
non-32-byte-multiple bitsets first. The strict writer fault count is affected
by expanded fuzz-target selector routing; it is not evidence that the
FLOAT/DOUBLE library defect is fixed. Both small original repros still fail
in strict Replay.


For the buffer-pool probe, AFL classified the same 234-byte valid seed as
variable from a cold process (`1 variable`, 2,124 map bits), stable after one
prewarm execution and a bitmap reset (`0 variable`, 2,124 bits), then variable
again after `DefaultParquetBufferPool.Shared.Trim()` (`1 variable`, 2,124
bits). This isolates one real source of bitmap instability to retained pool
buffers. The short probe's aggregate stability percentages stayed around 91%
because its new mutations dominated them; it does not establish how much of
the 59% full-corpus stability this mechanism explains.

A paired 180-second isolated AFL run on six identical seeds found 7,532 edges
with a fresh pool per testcase versus 7,488 with the shared pool, despite 4.4%
fewer executions. Variable queue entries fell from 150 to 29; aggregate
stability was 63.22% versus 63.69%, so this is a coverage signal improvement,
not a full stability fix. Both runs had zero crashes and hangs. A fuzz-only
fresh-pool entry point was enabled in the live reader fleet at 10:04 CET for a
trial; ordinary Replay and Plank's production default remain on the shared
pool. The live effect still needs observation.

A private 65,536-byte SharpFuzz bitmap probe found another per-input source:
the saved 2,769-byte seed
`fuzz/reader-findings/main/queue/id:033121,src:033113,time:43714109,execs:635240087,op:havoc,rep:3,+cov`
(SHA256 `2072ab6b74fcfba34074d8fb4c6905517d4963e406ba1db01100ad92618dc8bb`,
selector `0x64`) took 0.41 seconds in five fresh-process runs. With the same
empty-input and stable-seed warm-up, its first bitmap had 2,385 nonzero bytes
(`86632D…`); repeating the identical input while
`ReaderAcceptanceOracle._overrunningParquetNet` was pending had 2,312
(`E50415…`). After that task faulted with
`NotSupportedException: can't read page type INDEX_PAGE`, the same input
started another comparison and had 2,370 (`69412D…`). This identifies the
instrumented early-return branch for an outstanding oracle task as a separate
source of same-input bitmap variation; it is not the shared adaptive pool.
The following 204-byte `schema0-i32-plain` input had the same bitmap (2,139
nonzero bytes, `04A16B…`) while that task was pending, and we observed no
cross-input writes from the task in this current build. The trigger appeared
in one of 500 randomly sampled eligible live-queue files and none of 965
eligible checked-in reader-corpus files. This probe does not quantify a
meaningful share of fleet instability. No shared fix was made: the existing
global Parquet.Net-skip trial did not improve live stability, and skipping only
files with this unsupported page type would need a separate coverage trial.

A bounded mismatch review reproduced three Parquet.Net value disagreements,
but Plank and Arrow agreed on all 522 values compared in those examples. A
newer saved disagreement at
`fuzz/reader-findings/worker-16/queue/id:004030,sync:main,src:028965,+cov`
reports Plank=7 and Parquet.Net=5 at row 2; PyArrow reads the five values as
`5, 5, 7, 5, 7`, agreeing with Plank on that row. This is not evidence of a
Plank value error. Two current saved value disagreements under
`fuzz/disagreements/9bb2c06423d443e8/53da5c4576bbbc1e.bin` and
`fuzz/disagreements/fb7c56f42734c2e5/df89a517362f2c77.bin` likewise
reproduce against Parquet.Net, while PyArrow materializes the required DOUBLE
and BOOLEAN values matching Plank. These `.bin` files have a one-byte fuzz
selector before the `PAR1` body; the selector must be removed for direct
PyArrow inspection. A
saved Boolean Plank/Arrow disagreement at
`fuzz/disagreements/505e141bc13a0a95/d4f66b839319d74b.bin` is not a
confirmed valid-file bug: PyArrow fails to deserialize its page header, and
its required Boolean column footer reports two nulls despite maximum
definition level zero. These findings leave the broader disagreement backlog
open for triage without counting every mismatch as a Plank defect.

A further bounded review of 100 saved Arrow-backed disagreements found no
confirmed valid-file value mismatch: PyArrow rejected 90 page headers; the 10
files it opened materialized zero rows despite nonzero footer row counts. A
read-only sweep found no saved example with a successful, nonempty PyArrow
decode and a comparable value mismatch. One representative malformed input,
`fuzz/disagreements/0087bfec1e9c44d0/4ad3c13a953b4927.bin`, starts with
`dPAR1` rather than the standard `PAR1` header and materializes zero Arrow
rows. This does not establish a new Plank decoding defect.

A fresh sample of the newest four saved value-mismatch inputs (14:28–14:34
CET, Nov 11) also produced no confirmed Plank defect. Replay preserved and
honored each input's one-byte selector prefix; all four reported a
Parquet.Net/Plank mismatch while Arrow comparison completed without a
Plank/Arrow value mismatch. For example,
`fuzz/disagreements/05c607bef13d9c31/ae5eb7989983ef5f.bin` (selector `0x04`)
replays as Plank `1` vs Parquet.Net `5.30656815E-315` at row 0 for a PLAIN
DOUBLE column; after removing only the selector, PyArrow reads all five values
as `[1.0, 2.0, 3.0, 4.0, 5.0]`. The stripped file has `PAR1` at both ends and
footer metadata for one required DOUBLE column, five values, zero nulls, and
min/max 1/5. Likewise,
`fuzz/disagreements/1612ea828e4c6b0d/1d79452bd4663a83.bin` (selector `0x18`)
reports PLAIN BOOLEAN Plank `False` vs Parquet.Net `True` at row 2; PyArrow
materializes `[False, True, False, False, True]`, agreeing with Plank on all
five values. These are Arrow-accepted oracle divergences, not Plank defects
established by this sample. PyArrow acceptance and successful materialization
do not by themselves prove formal Parquet conformance of mutated page streams.

The reader compression area still has 129/174 branches covered in snapshot `k`.
Most of the 45 misses are in zlib native-library resolution: platform/path
alternatives and one-time registration cannot be selected by mutating a
Parquet input on this Linux x86 host. Two `GzipInflater.Decompress` misses
require native initialization failure or stream-end without input progress.
They are environment or native-state probes, not useful corpus targets here.

A bounded reader logical-conversion audit found no new corpus seed to add.
The public reader's footer binder rejects invalid decimal precision/scale
before the `LogicalType.Decimal` constructor's argument-error branches, and
the inspected `RowGroup.ValidatePhysicalType` misses are caller-type
rejections for API combinations outside the current typed drain route. This
is a routing or API-test gap, not evidence that valid-file conversion is dead.

The remaining `RowApiNestedColumnDescriptor` constructor validation branches
need caller-supplied malformed descriptors. The byte-stream fuzz route builds
collection levels from file metadata, so its descriptors cannot have those
inconsistent level sequences. `RowSchema` and `RowSchemaColumn` construct
writer schemas and belong outside the reader-only coverage denominator's
reachable surface. `RowReaderCore.ValidateMaterializedType`'s physical-mismatch
arm is preceded by `ValidatePhysicalType`, which rejects a mismatched physical
type first. These are routing/API-test gaps, not dead-code removal candidates.

## Dead-code removal audit

`ColumnChunkReader.TryDecodeBinaryDataPage` is a removal candidate for
**supported valid flat binary pages**, pending a compatibility check. Its only
two callers are the optional and required `BinaryValueDescriptor` branches in
`library/Plank/Plank/Reading/Logical/Internal/ColumnChunkReader.cs` (lines
1327-1330 and 1706-1709). `ColumnBufferEnumerable.MoveNext` dispatches dictionary
pages, fixed-width batching, and then `TryStartEncodedPageBatches` before either
caller. The batch decoder accepts the same supported binary value encodings as
the legacy method: PLAIN, dictionary, BYTE_STREAM_SPLIT for FIXED_LEN_BYTE_ARRAY,
DELTA_LENGTH_BYTE_ARRAY for BYTE_ARRAY, and DELTA_BYTE_ARRAY for BYTE_ARRAY or
FIXED_LEN_BYTE_ARRAY. `EncodingCompatibility` rejects other encodings for these
physical types before fallback dispatch; dictionary data pages without an
initialized dictionary are also rejected before batching. Thus no supported
flat binary page should reach the fallback body.

This conclusion is limited to the post-guard decoding body. The public reader
can encounter a non-data IndexPage in a binary column chunk and enter the
helper's initial page-type guard. The saved malformed-file sample
`fuzz/reader-gap-seeds/index-page-binary-rejection.bin` places an IndexPage
before the data page and disables page indexes in its footer. The reader
rejects it with `NotSupportedException` from `ColumnBufferEnumerable.MoveNext`.
Canonical-binary targeted Coverlet confirms four line-1953 guard outcomes
hit; all four were already hit in the complete `ag` union. No new exact branch
outcome was added. The earlier attempt had placed IndexPage after the only
data page and never requested it; a second attempt kept stale page-index
locations and failed in `PageMetadataReader` before column decoding. The
corrected sample resolves the caller question but leaves the six still-unhit
line-1953 outcomes `unreviewed`; only the 36 post-guard misses retain
`dead_candidate_dispatch_bypass`. Removing the helper must preserve this
IndexPage rejection path as well as valid data-page decoding.

The dispatch boundary matters: flat projection validation rejects leaves with
`MaxRepetitionLevel != 0`; nested repeated values use
`NestedColumnBufferEnumerable` and `TryDecodeNestedPageIntoNative`, not this
helper. BOOLEAN reads use `T=bool`, while this helper is selected only for
`BinaryValueDescriptor`, and BOOLEAN is not an `IsBinaryPhysicalType`. It is a
useful control probe, not a route into this method.

On the `20261111s` coverage snapshot, all four ISA-tier reports agree: the
method has 46 branches, with 4 covered, all on the initial guard at line 1953;
no decoding-body line is hit. Each special-case call-site condition has four
branch outcomes and all four are covered. Removing both call sites and the
method would mechanically remove 54 branch records, 12 currently covered,
projecting the s union from 5,598/6,774 to 5,586/6,720 (83.125%), if all other
instrumentation remains fixed. This is a projection, not a measured
post-removal coverage result.

An isolated probe replay copied 16 existing seeds to a temporary directory and
ran the prebuilt Reader.Target `--replay` successfully. Direct PyArrow 26.0.0
readback of the selector-stripped Parquet files succeeded for all 16: required
and optional ByteArray PLAIN, dictionary, DELTA_LENGTH_BYTE_ARRAY, and
DELTA_BYTE_ARRAY across DataPage V1/V2; required and optional BOOLEAN V1/V2; and
nested repeated binary V1/V2. Flat cases each contained five rows and nested
cases two rows. The selector-0 target route also compares physical traces with
ParquetSharp; replay raised no mismatch. This validates those probes, not every
malformed-file compatibility edge.

Removal plan: in an isolated change, remove both special-case calls and the
private method; remove helpers only after checking all call sites. Run the
library tests and complete saved reader corpus across all four ISA tiers, and
compare decoded physical values and definition levels with Arrow for required
and optional ByteArray/FIXED_LEN_BYTE_ARRAY plus required Int96 (including
dictionary and plain, byte-stream-split where supported, delta-length for
ByteArray, and delta-byte for ByteArray/FIXED_LEN_BYTE_ARRAY), DataPage V1/V2,
repetition-free binary, Boolean control cases, and nested repeated binary.
Review changes in acceptance and exception categories for malformed inputs.
Keep the current implementation until that compatibility check passes.

Other low-hit code is not a removal recommendation. Optional timestamp and
forced dictionary encoders have explicit public writer dispatch and are now
reached by new seeds; vectorized readers depend on CPU capabilities and input
shape. `DatasetBufferSlot.SnapshotMemory.Pin` has no direct textual caller
because `MemoryManager<byte>` requires the override. Coverage alone does not
justify deleting any of those paths.

The writer's `WriteLogicalType` switch now reaches 39 of 40 branch outcomes
with valid public logical types. Its remaining `NotSupportedException` fallback
is unreachable through the current `LogicalType` API (`private protected` base
constructor and sealed variants), but it is a defensive guard rather than an
immediate removal recommendation.

`PlainEncoding.WriteOptionalFixedLengthPayloads` is a narrow dead-code
candidate. Its only call is guarded at line 1079 by `typeof(TRow) == typeof(byte[])`,
but the immediately preceding check at lines 1068-1072 handles every `byte[]`
instantiation and returns after `WriteOptionalByteArrayPayloads`; for any other
`TRow`, the line-1079 type test is false. No public writer input can reach the
call at line 1082. Keep this as a removal candidate pending the focused writer
round-trip suite; no production deletion is included in the fuzz-route change.
Compiled IL confirms the preceding branch returns at `IL_002f`; the later
type comparison at `IL_004b` can only take its false exit. The six still-unhit
line-1079 outcomes at IL offsets 75, 86, 90, and 101 are now labeled as the
same narrow dead-code candidate in the `ai` inventory.

Twenty `PlainEncoding` misses are host-gated, not dead: the INT32/INT64
Vector128 page writers and their `CanUse...` helpers are called only after
`AdvSimd.Arm64.IsSupported` in `Encoding.TryWritePlainPrimitiveDataPages`;
the optional-double AdvSimd extractor is called only after
`AdvSimd.IsSupported`. None can execute in this x86 coverage run, even with
larger public writer samples.
The INT32/INT64 plain writers also have 16 exact missed outcomes inside
`BitConverter.IsLittleEndian` false arms or their byte-swapping loops. Two
already carried a big-endian label; the other 14 are now classified the same
way. Their byte/ushort/uint/ulong type-dispatch checks remain separate
reachability questions.
The page-stat writers have four empty-input guards preempted by
`WritePlainPrimitiveDataPages` passing only nonempty slices (and, for optional
INT64, an explicit `presentCount > 0` check). Their swap loops and the
optional INT32 AdvSimd extraction loop contain further host-only outcomes.
This audit classified 13 additional exact `ai` misses; it does not imply that
the type-specific writer methods themselves are dead.

Two exact-magic `ENCG` optional binary samples now demonstrate another
public route. Selector 29 writes optional `byte[]` FIXED_LEN_BYTE_ARRAY,
INT96, and BYTE_ARRAY columns with PLAIN encoding; selector 30 uses a public
`IPageStrategy` that picks one page by row count and declines a byte target.
Both replay with correct value and null readback. Focused canonical-binary
reports `fuzz/.coverage-work/focused-optional-fixed...json` and
`fuzz/.coverage-work/focused-rowcount-binary...json` together hit 15 exact
`ai` misses: six `ColumnStatistics`, three `Encoding`, and six
`PlainEncoding`. These are hard-to-reach public paths, not dead code; the
seeds are under `fuzz/writer-gap-seeds/` and remain outside the `ai` count.

Three additional `WMD1` metadata seeds exercise nullable numeric statistics.
Selectors 9 and 16 replayed cleanly but hit no exact `ai` misses: their
all-null and NaN-only paths were already represented. Selector 17 writes
optional unsigned values that descend then ascend and replays with correct
readback. Focused Coverlet at
`fuzz/.coverage-work/focused-stats-unsigned..json` hit six exact `ai`
`ColumnStatistics` misses in nullable UInt16/UInt32/UInt64 min/max updates.

`ColumnChunkReader.ReadUnsignedVarInt` has a smaller unreachable diagnostic:
its fifth-byte high-nibble check rejects any continuation bit before the loop
can fall through to the final "exceeds five bytes" throw. A private malformed
varint probe hit the method without reaching that final branch. This can be
cleaned up with the method if its control flow is simplified, but it is not a
coverage target or a reason to change the parser now.

An additional valid 1,024-row nullable INT32 RLE_DICTIONARY probe with 300
distinct values did not reach `DecodeNullableInt32DictionaryNineBitPortable`:
its source gate requires ARM AdvSimd, unavailable on this x86 host. A valid
256-row required BYTE_ARRAY V2 probe also left the legacy whole-page decoder
unreached. These are host and routing limits, not evidence that the inputs
failed to exercise the public reader.

## DELTA_BINARY_PACKED required-column definition-level mismatch

The 12 strict reader replay failures share one condition, not 12 distinct
DELTA decoder defects. A private instrumented source copy at
`/tmp/delta-diag.HC33XA` replayed every crash input individually. Each starts
with a page logical value count of 1,024 and a decoded physical count of 878,
while the selected schema column says `Required`. Its DELTA stream count is
878, matching the physical count. The reader therefore starts
`BatchState(ValueCount=878, ValuesRead=0)` and then the exact-type required
projection requests a 1,024-element destination; the guard in
`ReadInt32Batch`/`ReadInt64Batch` throws because only 878 encoded values remain.
The first call reports `offset=6`, block size 128 in the representative Int32
input and `offset=6`, block size 128 in the Int64 input.

The schema/level invariant is already broken before DELTA decoding: required
columns have no definition-level stream, but these files carry a 128-byte
stream whose levels produce 878 present values out of 1,024. The page planner
accepts and retains that count (as `PhysicalCount`), and the exact-type fast
path at `ColumnChunkReader.EncodedBatching.cs:603-607` decodes directly into
the logical-sized destination instead of rejecting the required-column level
inconsistency. `StartBatch` correctly verifies the DELTA stream count against
878 (`DeltaBinaryPackedDecoder.cs:121-123`); batch planning does not cause this
mismatch. A valid required-column file cannot contain this definition-level
stream, so this specific failure condition is malformed-file-only. Strict
replay of generated valid required INT32 and INT64 DELTA files, both small and
large, completed successfully.

Private diagnostics were added only under `/tmp/delta-diag.HC33XA` (including
`DELTA-NUMERIC`, `DELTA-CALL`, and `DELTA-GUARD` traces); the shared library,
harness, and build were not changed. Individual strict `--replay` runs of all
12 inputs reproduced the same 1024/878 mismatch: 10 INT32 and 2 INT64 inputs.
The IDs are:

- INT64: worker-01 `id:006970`; worker-05 `id:006429`.
- INT32: worker-02 `id:007680`, `id:007808`, `id:007810`, `id:007844`,
  `id:007845`; worker-03 `id:006414`; worker-05 `id:006741`, `id:006742`,
  `id:006820`, `id:007035`.

The complete queue filenames and the scalar replay records are in
`fuzz/reader-findings/worker-*/queue/` and
`fuzz/coverage/history/run-reader-20261111u-scalar.txt` respectively. For
example, strict replay of worker-02 `id:007680` logs
`physicalPage=878 physicalOffset=0 request=1024 count=878 read=0` immediately
before the guard reports `remaining=878 requested=1024`; worker-01 `id:006970`
logs the same values through `ReadInt64Batch`. The queue inputs are characterized
by the shared structural condition above, but they are not byte-minimized.

### Remaining DELTA_BINARY_PACKED reader branches

The `20261111q` four-tier JSON union has 388 distinct branch IDs in
`DeltaBinaryPackedDecoder.cs` (including its nested state/control types);
35 outcomes remain unhit in that source file. A bounded source and
input audit found no additional public-reader coverage gain or new defect:
private PyArrow DELTA_BINARY_PACKED INT32/INT64 files with 12,000 values,
nullable INT32 files with and without nulls, and an unsigned INT16 file all
passed independent PyArrow readback and the Reader acceptance oracle. A
12,000-value DELTA_BYTE_ARRAY file also passed both. Isolated Coverlet reports
for these inputs added zero decoder branch IDs over the q union.

Eighteen misses are host-selected: eight edges in the lazily initialized AVX2
unpack-control table, six edges in the three AVX2 mini-block kernels, three
AVX2 alternatives to the selected BMI2/PDEP dispatch, and the
non-little-endian arm of `ReadPackedWordBmi2`. The q host is an AMD Ryzen 9
7900X (family 25); the decoder deliberately selects PDEP there, so input
values cannot select those AVX2 alternatives. The remaining 17 are three
empty-destination edges in batch methods (the public page reader does not
submit empty batches); four `ReadNullableInt32Core` edges and four allocating
`ReadInt64Core` edges, whose convenience paths are not used by the public
page reader; the empty-count and unsupported-generic-type guards in
`ReadNarrowInt32Core`; the zero-count span `ReadInt64Core` case; the
noninitial-call state edge in `ReadNullableInt32Batch` (not reached by the
bounded 12,000-value page probes); the nullable-batch overrun branch; and the
`BatchState.NextBatchCount` early-return arm, preempted by the caller's
remaining-versus-target check in `PlanEncodedPhysicalBatch` for consistent
page state. These are not confirmed library defects. The nullable-batch
overrun remains a malformed-input probe candidate; the existing 12 INT32/
INT64 exceptions above are separate failures and must not be counted as new
findings.

## Floating append loses sorting metadata

`fuzz/writer-gap-findings/append-floating-sort-metadata/` contains two small
inputs for the `0xF8` writer target route: finite monotonic DOUBLE ascending
and FLOAT descending. Each initial file has the requested sorting column.
Appending preserves every value and the row count, but the resulting row group
has zero sorting columns. The finding folder includes exact controls and
expected value sequences. AFL also saved mutated variants in `fuzz/crashes/`.

Run `dotnet Plank.Fuzzing.Replay/bin/Release/net10.0/Plank.Fuzzing.Replay.dll writer <input>`
from the fuzz worktree. Ordinary replay reports a failure. The live writer
fleet sets `PLANK_FUZZ_BYPASS_KNOWN_FLOAT_SORT_LOSS=1` only for this confirmed
FLOAT/DOUBLE metadata loss so it can continue past saved variants. That bypass
does not change Plank or strict replay behavior.

### Append sorting branch follow-up

The four-tier writer reports for `r` and `s` have the same `AppendSortingOrder`
branch set: 132/178 branches covered, with no `s`-only branch. A private matrix
of 408 F8 public-append scenarios (all selector and flag combinations, omitting
only finite ordered FLOAT/DOUBLE cases that hit the finding above) passed the
strict value and sorting-metadata readback checks and added zero branch IDs over
the `s` union. The matrix is in `/tmp/append-valid-scenarios`; it was not added
to the shared corpus.

The remaining comparator guards are constrained by append/API invariants. The
`retained.Length == 0` arm in `CompareIncoming` (combined `ae` tuple
`(23,29,path 0,ordinal 2)`) cannot run for
`AppendToLatestRowGroup`: `OpenAppendFile` selects that route only when the
latest row group has a nonzero row count (`ParquetWriter.cs:479-486`). The
null/mismatched comparison-array return in `GetVerifiedColumns` requires a
missing sorted column or different per-column row counts, which a complete
valid append does not produce (`AppendSortingOrder.cs:49-51`; row-group
completion validates its columns). The invalid `TimeUnit` fallback is excluded
by schema validation; the false-length Float16 arm is excluded by its
fixed-length schema. A direct CLR `decimal` append probe failed before the
comparator, while materializing retained values: `LatestRowGroupValues`
currently converts INT32/INT64/BYTE_ARRAY values only to its listed target CLR
types and throws for `decimal` (`LatestRowGroupValues.cs:111-165`). This is an
append materialization limitation, not evidence of a sorting-comparison defect.
The known finite FLOAT/DOUBLE metadata-loss inputs still fail under strict
Replay; the audit did not enable the bypass for them.

## Decimal columns fail with Bloom enabled

`fuzz/writer-gap-findings/decimal-bloom/DecimalBloomRepro.csproj` is a minimal
public-API repro. From this worktree, run
`dotnet run -c Release --project fuzz/writer-gap-findings/decimal-bloom/DecimalBloomRepro.csproj -v:q`.
It writes required and optional Int32-backed Decimal(9,2) values successfully
without Bloom. With `ColumnOptions(bloomFilter: ...)`, both cases throw
`NotSupportedException` during `SerializedColumn.Serialize`: `BloomFilterBuilder`
has no decimal conversion in `InsertValues` or its optional fallback
`InsertObject`. The schema accepts the Bloom option, so failure is deferred
until writing. The repro uses no fuzz-target bypass and was verified against
the current `a9c93f4` library checkout. The relevant production source is
`library/Plank/Plank/Writing/BloomFilterBuilder.cs` around lines 258 and 348.

A separate bounded `0xEB` + `ODBG` writer-gap route and seed,
`fuzz/writer-gap-seeds/optional-decimal-bloom-odbg.bin`, specifically exercise
the optional Decimal(9,2)/INT32 Bloom fallback. The route catches only the exact
known `NotSupportedException` message above. It also writes the same four
optional values without Bloom and verifies them with ParquetSharp; if Bloom
serialization starts succeeding in a future library version, the route instead
requires complete output, Bloom membership, and ParquetSharp readback. Private
four-tier Coverlet comparison against raw `20261111ac` writer coverage adds 27
exact branch tuples: 22 in `BloomFilterBuilder.InsertObject`, 3 in
`InsertOptionalValues`, and 2 in nullable-decimal statistics. The seed remains
in `writer-gap-seeds`, outside the live corpus. This is a temporary
known-defect coverage bypass, not a fix for decimal Bloom support.

## Optional UUID Bloom writer route (Nov 11)

The exact-gated `0xE8` + `OUB1` route and its V1/V2+CRC seeds exercise a valid
optional `Guid?`/UUID public-writer input with Bloom and page indexes enabled.
The route checks all four nullable values, canonical fixed-length UUID bytes,
ParquetSharp `Guid?` readback, row-group/value counts, Bloom membership for
every present GUID, and footer metadata. It requires the Bloom filter and
OffsetIndex; UUID page statistics are unavailable, so the expected ColumnIndex
is absent. Both targeted seeds passed private Release Replay with no unexpected
throws or oracle mismatches. Coverlet in a private source/output copy, compared
by exact source-relative branch tuple against the four raw `20261111ad` writer
reports, adds 10 branches: five in `BloomFilterBuilder.InsertOptionalValues`
and five in nullable UUID serialization/statistics. It adds no page-index
writer branches.

The remaining three `PageIndex` constructor branches are its
`statistics ?? []`, `nullPages ?? []`, and `locations ?? []` fallbacks. The
sole explicit construction in `RowGroupWriter.Write` passes arrays populated
after `EnsurePageIndexCapacity` whenever page indexes are enabled; with page
indexes disabled the constructor is not called. Those null inputs are not
reachable through valid public writer calls. The internal constructor remains
unchanged.

A private public-writer probe also wrote optional BYTE/UINT16/UINT32/UINT64
columns with Bloom filters and checked every Bloom membership result plus
ParquetSharp logical readback; all four cases passed. Exact four-tier Coverlet
comparison against raw `20261111ac` added zero branch tuples. Although
`InsertOptionalValues` has fallback handling for these CLR types, the public
serializers normalize them before reaching it: nullable byte/ushort/uint become
INT32 values and nullable ulong becomes INT64, then the compacted present values
go through `BloomFilterBuilder.Build` and `InsertValues`. Consequently the
successful narrow/unsigned `InsertObject` arms were not reached by these valid
public inputs. No defect or seed was indicated.

## ALP decoder branch reachability

The four-tier reader union reached 93/106 `AlpDecoder` branches in snapshot
`n`. The public-writer ALP64 seed added one branch (`PackedValueReader.Read`,
the `bitWidth == 64` arm), bringing snapshot `o` to 94/106. Private public-
writer FLOAT/DOUBLE probes for exceptions, multiple vectors, partial-byte
packing, FLOAT width 32, and a 65,537-value FLOAT page all passed exact
bitwise readback, but added no branches over `o`.

Twelve branches remain. One is `BatchState.NextBatchCount`'s
`remaining <= targetCount` arm: `PlanEncodedPhysicalBatch` invokes it only
after its own identical `remaining > targetCount` check, so this arm cannot
be reached through a valid reader call. The other eleven are defensive or
routing cases: two `ReadPageHeader` checks reject trailing bytes on an empty
payload or guard the final offset after every offset was already bounded;
four legacy `TryDecode` branches are bypassed by the public reader's batched
path; two `TryDecodeBatch` branches reject an empty/oversized destination;
two cover physical-type/CLR-type mismatch dispatch that a well-typed ALP
column does not take; and `GetVector`'s end-before-start error is precluded by
the header's monotone-offset validation. These are malformed-input,
caller-invariant, or legacy/API-routing paths. The valid public-writer probes
did not justify removing any guard.

## Page-index reader branch reachability

The valid optional INT32 V2 page-index seed added three `PageMetadataReader`
branches in reader snapshot `p`; PyArrow and Plank agreed on all 3,723
non-null values. A further bounded audit of 39 dictionary variants, six
list/map variants, all-null page-index files, and a no-column-index fallback
found no new branch IDs or value defects. A malformed offset index with a
zero compressed-size page reached an already-covered corruption guard while
PyArrow still decoded the unchanged values.

The inspected remaining page-index branches are constrained by earlier
validation: `MergeCount` rejects a null-count mismatch before the later
`ParseColumnIndex` check; required `null_pages` and
`PageLocation.first_row_index` fields are checked before downstream flags
and row counts are used; and location bounds/order checks reject the
remaining invalid row-count cases. The huge-gap guard requires a span above
`Int32.MaxValue`, outside the current 8 KB fuzz input cap. These are not
removal recommendations without a separate API and compatibility audit.

For the combined eight-report `20261111ae` inventory, ten remaining
`PageMetadataReader` tuples stay `unreviewed`; the bounded audit above did not
prove those exact branches unreachable. The `ValidateLocationGap` size guard
at `(403, 26, path 0, ordinal 0)` is classified
`fuzzer_input_cap_precludes_large_gap`: its call follows `ValidateLocations`,
which bounds `chunkEnd` by `reader.Source.Length`, and the reader AFL target
caps inputs at 1 MiB (`fuzz/run-fleet.sh`). Therefore `end - offset` cannot
exceed `Int32.MaxValue` for that target. This is a target-input constraint,
not a claim about arbitrary API callers. The already-recorded valid V2 page-
index seed and zero-size offset-index control remain the reachable controls;
no new seed was needed for this source-proven guard.

## RLE Boolean writer branch reachability

The p writer-coverage union plus the private case14 probe reached 17/18
`WriteBooleans` branches, 18/20 `CountBooleanRunLength` branches, 23/26
`SkipDistinctAdjacentBooleanValues` branches, and 1/2
`WriteBooleanBitPackedRun` branches. The remaining outcomes are empty-span
guards and false `Vector128<byte>.IsSupported`, `Vector256<byte>.IsSupported`,
or `Vector512<byte>.IsSupported` checks. The four private ISA-tier case14
replays passed strict readback; on this host, these valid-file probes exhausted
the reachable branches in these helpers. This is limited to the measured paths
and is not a removal recommendation.

## Logical-conversion reader branch reachability

Seven isolated selector-0 fixtures written and exactly read back with PyArrow
covered `time32-ms` (INT32), `time64-us`, `timestamp-ms/us`, and DECIMAL
INT32, INT64, and FIXED_LEN_BYTE_ARRAY. The private Release Replay under
Coverlet reported zero unexpected throws and zero oracle mismatches across all
21 logical values. Comparing exact branch tuples with the four-tier reader
union from `20261111r` found zero new branch IDs. All four valid DECIMAL
physical carriers (INT32, INT64, BYTE_ARRAY, FIXED_LEN_BYTE_ARRAY) are already
covered; the remaining decimal-switch IDs are fallback outcomes for unsupported
physical types. The remaining `DecodeTime` IDs are logical-type mismatch
defaults, and the `DecodePlainDateTimes` miss is the big-endian host guard on
this little-endian machine. No defect or corpus addition was indicated.

## Plain and ByteStreamSplit native-reader branch reachability (Nov 11)

Private PyArrow fixtures covered PLAIN/ByteStreamSplit dispatch for float32,
float64, fixed-byte DECIMAL, UUID, date32, time32-ms, time64-us, timestamp-us
with and without UTC, and signed/unsigned 8- and 16-bit integers. Strict
Release Replay processed 39 route-prefixed files (36 columns, 1,776 Arrow
values and 1,032 logical values) with zero unexpected throws or oracle
mismatches. Copied Replay/Coverlet comparisons against the `20261111y`
baseline found zero new raw branch tuples in `TryDecodePlainIntoNative` and
`TryDecodeByteStreamSplitIntoNative` on all four ISA tiers.

The remaining plain misses include the short-boolean-payload guard, Guid
fixed-byte width mismatch, and decimal physical-type dispatch outcomes. The
remaining ByteStreamSplit misses include logical-type and fixed-byte width
guards, physical-type/conversion dispatch outcomes, and decimal width paths.
Some are invalid-input guards or unsupported dispatch combinations; this
probe does not establish that every unhit outcome is unreachable. No defect or
coverage gain was found, so these private fixtures were not promoted.

## ByteStreamSplit DateTimeOffset slice route (Nov 12)

The 485-byte active seed `fuzz/reader-corpus/reader-bss-timestamp-offset.parquet-input`
contains selector 0 plus a two-row PyArrow Parquet file with optional
`timestamp[ms, tz=UTC]`, BYTE_STREAM_SPLIT encoding, and no compression or
dictionary. Targeted Release Replay processed one input with zero unexpected
throws or oracle mismatches; Arrow comparison checked 1 column / 2 values and
the reader checked 4 logical values. Against the raw four-tier `20261111ae`
**reader-only** union, isolated Coverlet found 12 newly reached tuples in
`ColumnChunkReader.TryDecodeByteStreamSplitSliceIntoNative` (the generic-type
gate and Int64 `ulong`, `TimeOnly`, `DateTime`, and `DateTimeOffset` dispatch
checks). The key tuple is `(line 3598, offset 702, path 0, ordinal 30)`, which
confirms the `DateTimeOffset` arm. The writer target had already reached those
12 tuples in the eight-report combined union, so this seed improves reader
coverage but does not reduce the combined 2,809 misses. This is a valid
public-reader route; no production code changed.

## DELTA narrow-value helper has no public reader route (Nov 12)

The combined `fuzz/unhit-20261111ae.tsv` inventory leaves two outcomes in
`DeltaBinaryPackedDecoder.ReadNarrowInt32Core`: `(1044, 52, path 0, ordinal 2)`
and `(1054, 234, path 0, ordinal 6)`. Source search finds no production caller
of the internal `ReadNarrowInt32` wrapper beyond its declaration; it alone
forwards to this core method (`DeltaBinaryPackedDecoder.cs:286-288`). The
public page reader has no route to either the unsupported-destination-type
guard at line 1044 or the zero-value-count arm at line 1054. These remain
internal decoder API coverage gaps, not valid or malformed file-seed
opportunities. The combined inventory generator classifies these exact tuples
as `internal_decoder_api_no_reader_route`.

## Generated DELTA fast-integer reachability (Nov 12)

All 184 missed per-width outcomes in generated
`DeltaBinaryPackedDecoder.FastInteger.g.cs` are big-endian swap arms on this
little-endian host: 80 INT32, 80 nullable INT32, and 24 INT64. The source
generator emits one `if (!BitConverter.IsLittleEndian)
wordN = BinaryPrimitives.ReverseEndianness(wordN)` per 64-bit load. Each
inventory tuple has path 0 and an even ordinal; the corresponding path 1
is hit. Retained IL confirms that path 0 falls through into the swap while
path 1 skips it. A complete join of the 183 previously unreviewed tuples to
the retained Coverlet JSON found zero exceptions. The fourth INT64 W1 tuple
had been mislabeled as a fixed-loop exit; IL shows its group-loop branch has
a separate line and offset. The previous `reachable_generated_fixed_loop_exit_coverlet_gap`
label has been corrected to `big_endian_host_only`.

Valid public-file seeds do enter these generated helpers: the saved INT64
width-1 seed checks 1,024 values against Arrow and the private large INT32
probe checks 300,000. Neither input can change host endianness, so no further
Parquet seed can hit these exact 184 outcomes on this machine. Three separate
generated switch-default outcomes remain labeled
`internal_guard_generated_constraint`: public width validation and zero-width
handling prevent them before dispatch. No production code changed.

## Nested Row API evolution probe (Nov 11)

A private public `RowReaderCore` probe requested an optional nested INT32 LIST
column absent from a valid 445-byte file containing required INT32 `other`
values `[7,11,19]`. With `MissingColumns=MaterializeDefault`, all three
requested nested rows were null; PyArrow independently confirmed the physical
source values. Exact Coverlet comparison with the four-tier `20261111z` reader
union added zero raw branch tuples. The valid missing-column path is reached,
but `SetMissingValue` installs the default directly and the base state skips
`RowApiNestedColumnReadState.AdvanceBuffer` for it. Remaining `Materialize`
misses include entry count, dense value count, nonnullable null leaf, and
shape guards; this one valid evolution probe did not reach them. No defect or
corpus addition was indicated.

## Row API nested null-leaf shape probe (Nov 11)

The exact-gated `0x70` + `RNSH` active seed
`fuzz/reader-corpus/reader-rowapi-null-leaf-shape.bin` contains a valid
four-row optional LIST of optional INT32 values:
`[[1,null,2], null, [], [3]]`. PyArrow independently read the values. Strict
file-schema decoding returned dense values `[1,2,3]`, definition levels
`[3,2,3,0,1,3]`, and repetition levels `[0,1,1,0,0,0]`; the matching nullable
Row API descriptor returned all four nested shapes, and Arrow compared one
column / three values with zero mismatch. A second exact-schema Row API read
uses `int[]` for the optional leaf and requires the precise
`CorruptParquetException` that says a null leaf cannot be materialized as
`System.Int32`. This is a CLR shape rejection on a valid file, not a decoder
defect. Private actual-route Coverlet comparison with the four-tier
`20261111ae` reader union added exactly one tuple:
`RowApiNestedColumnReadState.Materialize` `(142,227,path 0,ordinal 10)`; no
other tuples were new.

## Converted-value fallback dispatchers (Nov 11)

The `20261111v` four-tier raw branch tuples for
`TryDecodeNullableValuesByPhysicalType` (30 outcomes) were
`(0,158)` ×5, `(158,0)`, then `(0,0)` ×9; for
`TryDecodeConvertedRequiredByPhysicalType` (28 outcomes) they were
`(65,0)`, then `(0,0)` ×13. These are ordered Coverlet branch tuples, not
proof that every unhit arm is unreachable.

The page reader checks dictionary compatibility, fixed-width batches, and
encoded batches before either fallback (`ColumnBufferEnumerable.cs:139-177`;
`ColumnChunkReader.cs:369-389` and `ColumnChunkReader.EncodedBatching.cs:289-307`).
However, a valid public optional `BYTE_ARRAY` Decimal(9,2) PLAIN column read as
`decimal?` reaches the nullable fallback: strict logical values and an
independent raw physical-byte interpretation matched. Thus this dispatcher is
live. A finding input also reached it with Decimal(9,0), but its payload
contained `null` as text and was rejected for exceeding decimal range.

A private first-hit trace over the frozen `20261111aa` snapshot invoked both
dispatchers. The trace scanned 190,175 inputs; it excluded only the 12 known
DELTA crash inputs listed above. Required hit:
`findings/main/queue/id:030363,src:030186,time:33615873,execs:512499637,op:havoc,rep:1,+cov`
(SHA-256 `5f40d840dec7734fae243899e40c70744d7fd3abcf5822597c8653d2892a7a49`).
The Parquet file itself has optional INT64/ByteStreamSplit data with five
8-byte values, but the selector requested a non-strict Int32 `IntBoxConverter`
projection. The physical `long?` read succeeded; that mismatched converter
projection failed because its 40-byte payload cannot hold five 4-byte values.
A separate matching-schema required/optional Int32 converter probe read
correctly through the batch path and called neither fallback.

Nullable hit:
`findings/main/queue/id:054047,sync:worker-08,src:006464,+cov`
(SHA-256 `dbd8a4a49e2773db97c6972f057836546f7364aa20b191372615dfd49a08a353`).
It is optional BYTE_ARRAY Decimal(9,0) PLAIN; the page contains the text bytes
`null` as a value and Plank rejects it as out of decimal range. This specific
seed is semantically malformed, but a separate valid public optional
BYTE_ARRAY Decimal(9,2) PLAIN read as `decimal?` reached the same fallback and
matched both strict expected values and an independent raw physical-byte
interpretation. Historical aggregate branch hits without preserved inputs
remain un-attributed beyond these first traced examples.

These are dead-code candidates only for the still-unexplained required fallback
arms. Do not remove either dispatcher on this evidence. Before considering a
change, preserve the non-strict mismatched-projection error behavior, reproduce
the historical hit with a saved input, and cover matching custom-converter
reads across supported physical types and encodings. The nullable decimal
BYTE_ARRAY path must remain supported.

### Reader-ab nullable follow-up (Nov 11)

The four-tier `reader-20261111ab` replay reports the same 30 raw branch
outcomes in `TryDecodeNullableValuesByPhysicalType`: `(0,158)` ×5,
`(158,0)`, then `(0,0)` ×9. The valid optional BYTE_ARRAY Decimal PLAIN
projection above remains the identified nullable fallback reach; this replay
found no additional valid branch gain.

`ColumnBufferEnumerable` tries fixed-width batches and then encoded batches
before the nullable fallback. Those dispatches cover supported fixed-width
nullable projections for PLAIN and dictionary pages, plus supported boolean
RLE, DELTA_BINARY_PACKED, ALP, and fixed-binary DELTA_BYTE_ARRAY projections.
This precedence explains why those inputs do not exercise the fallback, but
does not establish that every cold physical-type arm or fallback outcome is
unreachable. No defect or new fixture was indicated by this probe.

## Nullable temporal writer coverage (Nov 11, 15:29 CET)

Private Coverlet probes for `DateOnly?`, `TimeOnly?`, and `DateTimeOffset?`
added 18 exact `SerializedColumn<T>` branch edges over both four-tier `r` and
`s` unions. New sites are `SerializeValues` line/offset/path/ordinal
295/1324/0/64, 319/1484/0/72, 331/1564/0/76; `SerializeNullableDateOnly`
531/148/1/3, 531/148/0/2, 532/84/0/0, 532/84/1/1;
`SerializeNullableTimeOnly` 874/18/1/1, 874/35/1/3, 897/355/1/11,
897/355/0/10, 898/292/0/8, 898/292/1/9;
`ConvertNullableDateTimeOffsets` 1980/1/3/3; and
`ConvertNullableDateTimeOffsetsNanos` 2003/93/1/3, 2003/93/0/2,
2004/27/0/0, 2004/27/1/1. The route and named active/gap seeds are
`fuzz/corpus/encoding-nullable-temporal-active.bin` and
`fuzz/writer-gap-seeds/encoding-nullable-temporal-gap.bin`.

Each public-writer case checks exact values and null positions, one-row-group
shape, and exact footer min/max bytes and null count. The targeted replay and
full saved writer replay passed; the latter processed 83,526 inputs with zero
unexpected faults or oracle mismatches under the narrow known sorting-loss
bypass. Four-tier writer snapshot `t` covered 4,992/6,906 writer branches
(+21 vs `s`; the other three gains came from a separate probe); 52 expected
strict faults per tier, zero oracle mismatches. No defect was found.

## MinMaxScan public-writer reachability probe (Nov 11)

A private ordinary public-writer case used optional INT32/PLAIN with 64 rows,
crossing the Vector256 lane and four-vector unroll thresholds. Release Replay
completed with zero unexpected faults. Exact raw Coverlet comparison against
the four-tier `20261111z` writer union added zero branch tuples in
`MinMaxScan` and `ColumnStatistics`. The union already reaches both the
production `Compute` vector and unrolled paths and `CopyAndCompute` vector
path. Remaining `MinMaxScan` misses are internal Vector128 bulk helpers and
the empty-input/short-destination exception guards; public writer files cannot
reach the internal helpers, and valid inputs cannot take those guards. This
coverage-only private probe did not independently verify footer statistics,
so it was not promoted. No defect or corpus addition was indicated.

## Page index and Bloom flush reachability (Nov 11)

Three private strict public-writer probes covered an empty required INT32 row group, NaN-only required FLOAT pages, and an optional all-null INT32 column with Bloom enabled. Readback and footer checks passed: the empty column has no pages or indexes; NaN pages retain the OffsetIndex while omitting ColumnIndex; the all-null column retains both indexes and a readable Bloom filter. Copied Release Coverlet comparison against all four raw `20261111aa` writer reports added zero branch tuples in `RowGroupWriter`, `PageIndex`, or writer Bloom paths. `PageIndex`'s null-array fallback branches remain unreachable through the public writer because `RowGroupWriter.Write` calls `EnsurePageIndexCapacity` before constructing the index. No defect or corpus addition was indicated.

## Gzip large-page reachability (Nov 11)

A private public-writer probe wrote 100,000 random INT32 values with Gzip level
zero and checked every value on Plank readback. The page required seven native
deflate output iterations, exercising the loop continuation and stream-end
outcomes. Exact raw Coverlet comparison against the four-tier `20261111ac`
writer union added zero tuples. The remaining `GzipDeflater` outcomes are its
empty-input branch and native zlib error guards; ordinary nonempty pages do
not reach them. The private probe is under
`fuzz/.coverage-work/gzip-large-private` and was not added to the corpus.

A separate valid reader probe with 2,049 INT32 values and 25-bit DELTA deltas
passed Arrow readback but added zero branch outcomes over the four-tier `ac`
reader union. Cardinality-one and cardinality-256 dictionary probes likewise
passed readback and added zero outcomes. The nullable nine-bit dictionary
portable method is gated by ARM AdvSimd on this x86 host; zero-value-count
DELTA exits need degenerate encoded content. These are not current valid-file
seed opportunities.

The `20261111ae` reader union still leaves the fixed-width batch row-count
guard at `ColumnChunkReader.TryStartFixedWidthPageBatches` line 380 unhit in
all four tiers. The exact combined-inventory tuple
`(line 380, offset 354, path 0, ordinal 46)` is classified
`preempted_by_row_group_metadata_validation`: a private 3-row PyArrow INT32 PLAIN file with footer
`RowGroup.num_rows` changed from 3 to 2 was rejected earlier by
`PhysicalMetadataThriftReader` (`Non-repeated column 0 has 3 values but row
group 0 has 2 rows`). This malformed metadata cannot reach the later batch
guard through the strict public file path; this is not a confirmed defect.

A 234-byte valid optional INT32 ByteStreamSplit V2 cross-path fixture was
replayed as a control (`0x04` reader selector; five values agreed with Arrow).
Its targeted Coverlet report added zero exact `ColumnChunkReader.cs` tuples
over the saved reader reports. The 68-file BSS cross-path subset and the
1,705-file generated reader matrix also added zero exact tuples, so no
redundant seed was added. This bounded pass does not classify the remaining
ColumnChunkReader outcomes.

## 17-bit dictionary-index writer path (Nov 11)

The exact-gated `0xE5` + `R17B` public-writer route writes 65,537 distinct
required INT32 values through forced RLE_DICTIONARY encoding. The contiguous
index sequence has no adjacent repeats, producing a 17-bit literal-index run.
Plank and ParquetSharp both read back all values exactly. The five-byte seed is
`fuzz/writer-gap-seeds/required-int32-dictionary-17-bit.bin`. Four sequential
private Release Coverlet replays add the same 10 exact branch tuples to
`RleBitPackingHybridEncoding.WriteBitPackedRunUnchecked` over the raw
`20261111ae` four-tier union, increasing that method from 13/26 to 23/26
outcomes. Three residual outcomes are unreachable through the valid public
writer: empty literals (line 391) are excluded by the caller; bit width 32 at
the general packer (line 432) returns earlier through the byte-aligned path;
and the `bufferedBits > 0` final flush (line 451) is false because the writer
pads each run to a whole number of eight-value groups. No defect was indicated.

## RLE hybrid writer residual branch audit (Nov 12)

For the combined eight-report `20261111ae` inventory, the other
`RleBitPackingHybridEncoding.cs` tuples were traced by helper and caller.
`ValidateValues`' 16 tuples are classified
`no_public_writer_callsite_validation`: its validated `Write` and
`WriteWithBitWidthPrefix` entry points have no library call sites. The exact
tuples at `(line, offset, path, ordinal)` `(64,7,0,0)`, `(123,3,0,0)`,
`(134,3,0,0)`, `(391,7,0,0)`, `(432,198,1,17)`,
`(451,332,0,24)`, and `(575,7,0,0)` are classified
`public_writer_invariant_excludes_outcome`: empty boolean and literal spans
are filtered by their callers, dictionary bit widths stay in range, width 32
returns through the earlier byte-aligned arm, and packed runs are padded to
eight values. These are retained as defensive internal guards.

The existing 17-bit public dictionary seed was replayed under private
Coverlet again. It hit ten exact tuples from the raw `ae` inventory, including
`(432,198,0,16)` and `(451,332,1,25)`; these two had previously been
misclassified as unreachable. They are now labeled
`reachable_17bit_dictionary_sample`. The other 15 tuples remain `unreviewed`.
They belong to vector run detection / distinct-adjacent scans and the
byte-aligned literal copier; input shape and ISA can affect those paths.

## ALP writer exception encoding (Nov 12)

`AlpEncodingPrimitives.TryEncode` still had one unhit range-check outcome for
FLOAT and one for DOUBLE in all four raw `20261111ae` writer reports:
`AlpEncodingPrimitives.cs:39` `(offset 76, path 1)` and line 56
`(offset 82, path 1)`. These are reachable from the public writer: ALP's
`WriteFloatVector`/`WriteDoubleVector` call `TryEncode` for every present value
and emit the exact original bits in the exception payload when encoding fails.
The gap seed `fuzz/writer-gap-seeds/encoding-alp-exception-path.bin` drives a
1,024-value FLOAT and DOUBLE column containing finite values, NaN, infinities,
negative zero, and each type's maximum finite value. Targeted Release Replay
passed with zero unexpected faults or oracle mismatches; the deterministic
route asserts bitwise Plank writer/readback equality for all values. A private
Coverlet replay added exactly those two previously unhit branch tuples over
the four-tier `ae` union. No production code changed.

## Encoded reader batching cluster (Nov 12)

The 86 zero-hit outcomes in `ColumnChunkReader.EncodedBatching.cs` from the
`20261111ae` reader union remain unreviewed. The caller route is concrete:
`ColumnBufferEnumerable.MoveNext` at
`library/Plank/Plank/Reading/Logical/Internal/ColumnBufferEnumerable.cs:154`
tries `TryStartEncodedPageBatches` after dictionary-page and fixed-width
dispatch, then falls back to nullable and required decoders only when batching
returns false. The batching selector in
`library/Plank/Plank/Reading/Logical/Internal/ColumnChunkReader.EncodedBatching.cs:105`
accepts supported flat DataPage V1/V2 encodings, rejects repeated columns and
reference-containing targets, and validates physical/null counts before
decoding. `DecodeNextEncodedBatch` continues page state through the same
enumerable at `ColumnBufferEnumerable.cs:119`.

This establishes only that the method can be entered through an ordinary
reader route; it does not prove any particular uncovered branch outcome. The
cluster spans decoder selection, nullable dictionary specializations, binary
payload planning, and exception guards, so no exact tuple was promoted in
this pass outside the narrow subset below. No seed or production code was
changed. The neighboring
`ColumnChunkReader.cs` outcomes were not assigned a blanket status because
their methods have separate caller and ISA guards.

One narrow nine-tuple subset is now source-classified:
`GetPlainBinaryBatchEncodedLength` tuples `(1674,7,1,1)`, `(1678,281,0,8)`,
`(1678,281,1,9)`, `(1680,42,0,2)`, `(1680,42,1,3)`, `(1684,90,0,4)`,
`(1684,90,1,5)`, `(1688,185,0,6)`, and `(1688,185,1,7)` (line, IL offset,
path, ordinal) are tagged `preempted_byte_array_plain_batch_length_parser`.
The method's `ByteArray` path is not selected by the public reader: when
`DecodeNextEncodedBatch` sees `PlainBinary` with `ByteArray` and no borrowed
payload, it dispatches to `DecodeNextOwnedPlainBinaryBatch` and returns before
`DecodeBinaryBatch`; with borrowed bytes, `DecodeBinaryBatch` parses lengths
through `DecodeBorrowedPlainBinaryBatch` instead. `GetPlainBinaryBatchEncodedLength`
is therefore reached only for non-`ByteArray` binary types, where its first
condition returns `GetFixedBinaryPayloadLength` before the byte-array length
loop. This accounts for the zero-hit `ByteArray` branch and its eight loop
outcomes without classifying adjacent outcomes in the batching file. No
reader-corpus seed was added because no public input can enter these exact
paths under the current dispatch.

## Fixed-binary ByteStreamSplit writer routes (Nov 12)

The `ae` writer union left the fixed-length ByteStreamSplit branches for
`Guid` and `decimal` serializers uncovered. These are reachable public routes:
`SerializedColumn<T>` dispatches `EncodingKind.ByteStreamSplit` to
`ByteStreamSplitEncoding.WriteValues`, which dispatches
`FIXED_LEN_BYTE_ARRAY` to `WriteFixedLengthByteArrayValues`; its `Guid` arm
requires length 16 and scatters big-endian UUID bytes across lanes, and its
Decimal arm encodes each value to fixed big-endian bytes before scattering.
The exact-gated seed `fuzz/writer-gap-seeds/encoding-fixed-bss-guid-decimal.bin`
uses three values in each column (UUID and `Decimal(28,6)`, length 16). Targeted
Release Replay passed with zero unexpected throws or oracle mismatches. The
route verifies UUID physical bytes and Decimal logical values on Plank
readback. Private Coverlet comparison with the four raw `20261111ae` writer
tiers added 12 exact branch tuples in `ByteStreamSplitEncoding`, including the
Guid and Decimal arms and lane-scatter loop exits. No production code changed.

## ReadOnlyMemory dictionary key paths (Nov 12)

The combined eight-report `20261111ae` union left two `ReusableDictionaryState<T>`
specializations unhit: `HashKey`'s `ReadOnlyMemory<byte>` arm (line 220) and
`KeysEqual`'s matching arm (line 264). Both are reachable through the public
writer: forced `RLE_DICTIONARY` on a required BYTE_ARRAY serialized column uses
`ReusableDictionaryState<ReadOnlyMemory<byte>>` to index the dictionary. The
focused seed `fuzz/writer-gap-seeds/encoding-required-rom-dictionary.bin`
selects that route with duplicate equal byte contents stored in distinct
memory instances. Release Replay processed the seed with no unexpected throws
or oracle mismatches; its explicit readback assertion checks each byte value
and insertion order. Private Release Coverlet replay against the combined
eight raw `20261111ae` reports added 10 branch tuples overall, including these
two previously unhit dictionary specializations. The inventory classifier now
marks only those two tuples as `reachable_readonly_memory_dictionary_sample`.
No production code changed.

## Empty required timestamp dictionary statistics (Nov 12)

The saved `20261111ae` inventory has four exact unhit outcomes in the empty
required timestamp dictionary path:
`SerializedColumn.cs` `(696,294,0,18)`, `(705,7,0,0)`, `(1790,77,0,2)`, and
`(1800,87,1,5)`. The existing `WMD1\x0C` seed
`fuzz/corpus/writer-metadata-required-timestamp-empty.bin` takes the public
forced-dictionary writer route with an empty DateTime span. It returns empty
column statistics, emits no data pages, and the page-statistics loop covers
zero of zero rows. Targeted Release Replay passed (one input, zero unexpected
throws or oracle mismatches). A private one-tier Coverlet report over the
three exact timestamp boundary controls added these four tuples over the raw
`20261111ae` inventory. The classifier labels only these four outcomes
`reachable_empty_required_datetime_statistics_sample`; neighboring timestamp
statistics branches remain unreviewed. No production code changed.

## Required timestamp dictionary dispatch fallback (Nov 12)

The combined `20261111ae` inventory has an unhit outcome at
`SerializedColumn<T>.TrySerializeRequiredDateTimeDictionary` `(line 682,
offset 173, path 0, ordinal 14)`. A required INT64 timestamp column with the
default page strategy reaches the public `CreateSerializedColumn<DateTime>` /
`Serialize` route, enters `SerializeDateTime`, then declines the direct
dictionary path because the strategy does not force dictionaries. The new
`WMD1\x0A` control in
`fuzz/writer-gap-seeds/writer-metadata-required-timestamp-plain.bin` checks
serialized values and footer min/max after that fallback. Release Replay
passed with zero unexpected throws or oracle mismatches. A private Release
Coverlet replay compared against the full combined eight-report `20261111ae`
union added exactly that one branch tuple in `SerializedColumn.cs`; the
inventory classifier labels only that exact tuple
`reachable_required_datetime_plain_sample`. No production code changed.

## Required timestamp statistics DateTime-kind boundaries (Nov 12)

The three exact unhit outcomes in `CreateRequiredDateTimeStatistics` are
reachable from the public writer. New `WMD1\x0E` controls select an adjusted
UTC timestamp with valid UTC values, a required timestamp whose first value
has `DateTimeKind.Local`, or one whose later value has `DateTimeKind.Local`.
The checked-in seeds are
`writer-metadata-required-timestamp-utc-kind.bin`,
`writer-metadata-required-timestamp-first-kind-error.bin`, and
`writer-metadata-required-timestamp-later-kind-error.bin` under
`fuzz/writer-gap-seeds/`. Release Replay passed all three with zero unexpected
throws or oracle mismatches. A private scalar Release Coverlet replay hit
exactly the three previously unhit combined-`ae` outcomes:
`(708,23,path 1,ordinal 3)`, `(710,52,path 0,ordinal 4)`, and
`(718,177,path 0,ordinal 6)`. The classifier labels only these exact tuples
`reachable_required_datetime_kind_boundary_sample`. No production code
changed.

## Intel model-specific decoder dispatch (Nov 12)

The six unhit tuples at `ColumnChunkReader.HasIntelFamily6Model158` (line 29,
offsets 42/50/58, and line 34, offset 101) describe host CPU identification
branches used to select a specialized wide INT64 gather. Source checks first
require x86 support, then the `GenuineIntel` vendor string, family 6, and model
158. This replay host reports `AuthenticAMD`, family 25, model 97 (`lscpu`), so
the model-specific true outcome is preempted on this host and cannot be reached
by changing a Parquet seed. The inventory now marks only these six exact tuples
`preempted_cpu_not_intel_family6_model158`; no coverage replay or production
change was needed.

## DELTA_LENGTH_BYTE_ARRAY writer shapes (Nov 12)

The exact-gated six-byte `0xF1 + ENCG + 25` seed at
`fuzz/writer-gap-seeds/encoding-delta-length-rom-shapes.bin` drives required
and optional BYTE_ARRAY columns through the public writer using both
`ReadOnlyMemory<byte>` and `byte[]`. It includes null runs, empty payloads, and
nonempty payloads; readback checks the full byte sequences and row-group shape.
Release Replay completed with zero unexpected throws or oracle mismatches.

A private scalar Release Coverlet replay of this seed was compared by exact
source/line/offset/path/ordinal key with the 31 still-unreviewed tuples for
`DeltaLengthByteArrayEncoding.cs` in the full eight-report raw `20261111ae`
queue. It hit 27 of those tuples, which are individually marked
`reachable_delta_length_byte_array_shapes_sample` in the inventory. Four
outcomes remain `unreviewed`; this probe does not classify them. No production
code changed.

A second bounded `0xF1 + ENCG + 25` control at
`fuzz/corpus/encoding-delta-length-byte-array-shapes.bin` replayed cleanly,
but did not hit any of those four residual outcomes. Source call paths exclude
three from supported public writer inputs: `WriteValues<T>` returns through
its `byte[]` specialization before the non-`ReadOnlyMemory<byte>` arm
`(20,79,1,3)`; optional `ReadOnlyMemory<byte>?` and `byte[]` rows return through
their specialized arms before the generic fallback `(85,72,1,3)`; and
`EncodingCompatibility` rejects non-BYTE_ARRAY physical types before
`RequireByteArrayColumn`'s throw `(246,7,0,0)`. These remain defensive
internal branches. The fourth residual `(46,68,0,0)` remains `unreviewed`.

## Optional DECIMAL empty statistics (Nov 12)

The six-byte `fuzz/writer-gap-seeds/columnstats-optional-decimal-empty.bin`
seed selects the existing exact-gated ODBG optional DECIMAL writer probe with
an empty value span. `SerializedColumn.SerializeOptional` calls
`CreateOptionalWithReusableBinaryBuffers` for this supported public type; its
DECIMAL specialization reaches the reusable `CreateNullableDecimal` overload.
Release Replay completed with zero unexpected throws or oracle mismatches.

A private scalar Release Coverlet replay of this seed hit the exact combined
`20261111ae` tuple `(659,12,path 0,ordinal 0)`, the empty or all-null result
branch in `CreateNullableDecimal`. The nonempty sibling seed
`fuzz/writer-gap-seeds/columnstats-optional-decimal.bin` reaches the same
public route and exercises the nonempty branch. The inventory labels only the
empty-result tuple `reachable_optional_decimal_empty_statistics_seed`; other
`ColumnStatistics` tuples remain unclassified by this probe. No production
code changed.

## Parked dataset row copy failure (Nov 12)

`fuzz/writer-gap-seeds/dataset-parked-copy-failure-dbr1.bin` (`0xFE + DBR1
+ D2`) uses the generated public `RowFuzzDatasetBinary.CreateDatasetWriter`
API with one file and two pending-row slots. It first occupies the active file
with partition `p0`, then queues a row for `p1` whose required `Payload` is
null. Generated row copying raises the expected `ArgumentNullException` in
the parked-row path. The probe does this once before any `p1` row is parked,
and once after a valid `p1` row is parked; it then queues valid rows and checks
the round-tripped IDs and payloads. This exercises both `QueueRow` catch
outcomes at `(218,251,path 0,ordinal 18)` and
`(218,251,path 1,ordinal 19)`, plus the corresponding empty-key and
preserved-key outcomes at `ReleaseEmptyPendingKey` `(371,19,path 0,ordinal 0)`
and `(371,27,path 1,ordinal 3)`. Release Replay passed one input with zero
unexpected throws or oracle mismatches. A focused Release Coverlet report
compared exact source/line/offset/path/ordinal keys against the eight raw
`20261111ae` reports: these four were the only previously unhit
`DatasetWriterBase` tuples reached by the probe. The inventory classifier
marks only those four outcomes; the neighboring full-capacity promotion
outcomes remain unreviewed. No production code changed.

## INT32 byte/ushort widening helpers (Nov 12)

The 20261111ae inventory has 30 unhit tuples in the private
`PlainEncoding.WriteByteValuesAsUInt32` (12 tuples) and
`WriteUInt16ValuesAsUInt32` (18 tuples) helpers. A focused Coverlet replay of
the existing public custom-converter samples
`fuzz/corpus/writer-converter-matrix-01` and `-02` completed with zero faults,
but showed zero hits in these helpers and in `PlainEncoding.WriteInt32Values`.
That result is consistent with the public write path: `SerializedColumn`'s
`SerializeByte` and `SerializeUInt16` widen their values into `int` scratch
buffers before calling `SerializeTyped`. Repeated INT32 paths also select
`int`/`int?` explicitly in `Encoding.EncodeRepeatedRows`; the nested-repeated
INT32 path instantiates `EncodeRepeatedRowsNestedCore<int, T>`. The PLAIN
dispatcher therefore receives INT32 values as `int` for these public routes,
so the byte/ushort type tests and their widening helpers are preempted.

The inventory labels only the exact 30 helper tuples
`preempted_public_int32_byte_ushort_coercion`. This is a public-call-path
classification, not a claim that the private helpers cannot be called from
inside the assembly. No production code changed.

## Row API materialized-type check preemption (Nov 12)

`RowReaderCore.ResolveColumnOrdinal` always calls `ValidatePhysicalType` before
`ValidateMaterializedType`. When physical types match, the first check returns;
when they differ, it throws for either physical-type evolution policy before
the materialized-type check is reached. Therefore the mismatch path in
`ValidateMaterializedType` is preempted on the public generated-row-reader
route. The inventory marks only its five exact `20261111ae` tuples:
`(637,12,1,1)`, `(639,22,0,2)`, `(639,22,1,3)`, `(639,36,0,4)`, and
`(639,36,1,5)`.

The route is exercised by `rowapi-workers-empty-leading-rowgroup-0x22.bin`:
selector `0x22` selects the Row API and generated-row probe, and the probe
uses generated readers whose constructors call `RowReaderCore`. A one-file
targeted Coverlet replay completed with zero faults and zero oracle mismatches.
The unreachable mismatch outcomes are source-proven; this seed is a public
route control, not evidence that those outcomes were hit. No production code
changed.

## Repeated INT64 row encoder focused probe (Nov 12)

The eight-byte public writer seed `fuzz/writer-gap-seeds/encoding-repeated-int64-required.bin`
selects the required flat INT64 repeated-row path (`0xFA`, typed INT64,
required elements). Release Replay completed with one input, zero unexpected
throws, and zero oracle mismatches. A private scalar Release Coverlet replay
entered `Encoding.EncodeRepeatedRows`, `EncodeRepeatedRowsCore`, and
`WriteRepeatedDefinitionLevels`. Exact comparison with the combined raw
`20261111ae` reports reached zero of the 22 still-unreviewed tuples in those
three methods. This sample therefore does not classify any of them; they stay
`unreviewed` in the inventory. No production code changed.


## Fixed-width boolean page-size overflow guard (Nov 12)

The exact residual `Encoding.TryGetFixedWidthRowsPerPage` outcome `(811,23,path 1,ordinal 5)` is reachable through the public writer. `EncodingCoverageWriterCases` case 26 writes both required INT32 and BOOLEAN columns with `TargetDataPageSizeBytes = 300,000,000`; the BOOLEAN path takes the large-target arm (`targetPageBytes > int.MaxValue / 8`) and clamps rows per page to `int.MaxValue`. The seed is `fuzz/corpus/encoding-fixedwidth-target-pages.bin`. Single-input Release Replay completed with zero unexpected faults or mismatches. A targeted single-input Coverlet report recorded the exact branch at line 811, offset 23, path 1, ordinal 5 with one hit; the sibling path 0 had zero hits. Only this exact tuple was reclassified in `unhit-20261111ae.tsv`; neighboring fixed-width and encoding tuples remain unreviewed. No production code changed.

## Wide INT64 dictionary scalar gather host guard (Nov 12)

Twelve exact `20261111ae` `ColumnChunkReader` tuples remain unhit in the
wide INT64 dictionary scalar fallback: `(4231,58,path 0,ordinal 0)`,
`(4231,58,1,1)`, `(4233,244,0,2)`, `(4233,244,1,3)`,
`(4249,451,0,4)`, `(4249,451,1,5)`, `(4285,17,0,0)`,
`(4285,17,1,1)`, `(4287,42,0,2)`, `(4287,42,1,3)`,
`(4290,79,0,4)`, and `(4290,79,1,5)`. The public INT64 dictionary route
reaches this helper only when `UseScalarWideInt64Gather` is true; that flag
requires CPUID vendor `GenuineIntel`, family 6, model 158. This host reports
`AuthenticAMD`, so the flag is false and eligible AVX2 inputs take the regular
gather branch instead. The inventory labels only these twelve exact outcomes
`preempted_wide_int64_scalar_cpu_model`; other dictionary decoder tuples remain
unreviewed.

## Repeated INT64 statistics probe comparability (Nov 12)

The public writer seed `fuzz/.coverage-work/columnstats-repeated-probe/seeds/repeated-int64-required.bin`
(`0xFA 0x10 ...`) replays cleanly and enters `ColumnStatistics.CreateRepeated`
and `RepeatedAccumulator.AddInt64Leaf`. Focused reports are retained at
`fuzz/.coverage-work/columnstats-repeated-probe/stats..json` and
`fuzz/.coverage-work/columnstats-repeated-probe/baseline..json`; the latter
used a separate Release build from submodule commit `dad7b5d` to check the
historical source revision. Those private builds cannot be compared to the
exact `20261111ae` inventory: for example, the raw writer reports at
`fuzz/coverage/history/writer-20261111ae-{avx512,avx2,sse,scalar}..json`
record `AddInt64Leaf` branches at `(1683,34,0,4)` and `(1683,51,0,6)`, while
the focused current-source report records `(1681,28,1,1)` and
`(1681,49,1,3)` for the same method. The raw reader reports under
`fuzz/coverage/history/reader-20261111ae-{avx512,avx2,sse,scalar}..json`
share the historical coordinates. A subsequent targeted Coverlet replay copied
the canonical `Plank.Fuzzing.Replay/bin/Release/net10.0` build instead. Its
report at `fuzz/.coverage-work/columnstats-repeated-probe/canonical..json` has all 730 exact
`ColumnStatistics` branch keys in common with `ae`, including line 1683
offsets 34/51. The repeated-INT64 seed still adds zero exact outcomes among
the 221 unreviewed statistics tuples; the earlier drift was isolated to the
private build. The completed `20261112ag` writer reports likewise have all
13,680 exact writer-union keys in common with `ae`. No classifier entries were
changed for this probe; the 221 statistics tuples remain unreviewed. No
production code changed.
