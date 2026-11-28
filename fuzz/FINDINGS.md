# Fuzz findings

What fuzzing Plank has found, and what is still open. Status as of 2026-11-18,
against Plank `master` at `3a6a28a`.

The detailed coverage and reachability notes that used to live here are in
[`notes/coverage-audit-2026-11.md`](notes/coverage-audit-2026-11.md). They are
lab notes, not findings; see [About the notes](#about-the-notes) before relying
on them.

## Library defects

All found by the reader/writer fuzz targets or their oracles, all fixed.

| Defect | Fixed in | Repro |
|---|---|---|
| Malformed DELTA_BINARY_PACKED batches escape as `ArgumentOutOfRangeException` from the INT32 and INT64 readers instead of `CorruptParquetException` | [#216](https://github.com/Kuinox/Plank/pull/216) | Saved queue inputs, not committed |
| DECIMAL columns with Bloom filters enabled throw `NotSupportedException` when written | [#215](https://github.com/Kuinox/Plank/pull/215) | [`writer-gap-findings/decimal-bloom/`](writer-gap-findings/decimal-bloom/) |
| A `DefaultParquetBufferPool` whose constructor throws crashes the process later, from its finalizer | [#214](https://github.com/Kuinox/Plank/pull/214) | [`repros/buffer-pool-partial-ctor/`](repros/buffer-pool-partial-ctor/) |
| Optional FIXED_LEN_BYTE_ARRAY values written from `ReadOnlyMemory<byte>?` get length prefixes: Plank can't read the file back, PyArrow reads shifted values | [#217](https://github.com/Kuinox/Plank/pull/217) | [`repros/optional-fixed-memory-plain/`](repros/optional-fixed-memory-plain/) |
| Appending to the latest row group fails for a valid DECIMAL column | [#218](https://github.com/Kuinox/Plank/pull/218) | Not committed |
| Snappy blocks whose literal overruns the declared length are accepted (bug in Snappier 1.3.1) | [#220](https://github.com/Kuinox/Plank/pull/220) | `SnappyCorruptionTests` in Plank |
| Row-group row writer (`CreateRowWriter(RowGroupWriter)`) writes past its column buffers when `GetRow()` is called more than `RowApiInitialRowCapacity` times (heap corruption, then `No more row slots are available.`). Missed for weeks because the `RWG1` direct route always set the capacity to the row count; found once they were drawn independently (2026-11-27) | [#276](https://github.com/Kuinox/Plank/pull/276) (open) | [`corpus/rowapi-direct-rowgroup.bin`](corpus/rowapi-direct-rowgroup.bin) |

An earlier campaign (Nov 2–5) found a series of page-header and metadata
validation gaps: wrong Thrift wire types, missing required fields, quadratic
header probing. Their fixes landed as #169 and #171, and in reworked form as
#177, #179, #181, #182 and #184.

## Open

- **Not a library bug: "append drops FLOAT/DOUBLE sort metadata" (triaged 2026-11-27).** The two
  writer-gap seeds were a harness error: cases 3/4 of the append-sorting route derived `incoming` from
  `retained[^1]` in the same loop that filled `retained`, so the appended values were out of order and dropping
  the metadata was correct. Harness fixed; repro and explanation in
  [`repros/append-floating-sort-metadata/`](repros/append-floating-sort-metadata/). Plank #219 is unrelated.
- **Reader disagreements are untriaged.** The `20261111ae` replay logged
  2,439–3,041 inputs per CPU tier where Plank and an independent reader
  (Arrow, Parquet.Net) disagree. Most are expected to be malformed-file
  acceptance differences, but the Snappy defect came from this pile and it has
  not been worked through. The saved inputs (`fuzz/disagreements/`) are not
  committed.
- **Dead-code candidate: `ColumnChunkReader.TryDecodeBinaryDataPage`.** Every
  supported flat binary page is handled by batch decoding before this method is
  reached. It is still on master; the removal plan and the compatibility check
  it needs first are in the notes ("Dead-code removal audit").
- **Reader AFL stability is about 60%.** Partly explained by the shared adaptive
  buffer pool and a pending Parquet.Net oracle task; the rest is unknown.
- **Writer coverage replays sometimes report extra faults** (runs `ab`, `ac`,
  `ad`). A plain replay of the retained `ad` inputs only shows the known, now
  fixed, sorting defect; the `ab` inputs were not kept. Not classified as a
  library defect.

## Open library defects found by the wide row-API routes (rowapi agent, 2026-11-27)

- **`TargetDataPageSizeBytes = int.MaxValue` overflows the buffer pool.** `ParquetWriterOptions.Validate` accepts it
  (the limit is `<= int.MaxValue`), but the first byte-array page then throws `OverflowException` from
  `DefaultParquetBufferPool.Rent` (`BufferWriter.EnsureCurrentSegment` → `Rent`). Repro:
  [`repros/rowapi-page-size-int-max/`](repros/rowapi-page-size-int-max/) (an `RWW1` row-API input). The wide routes cap the
  drawn page size at 2^29 so this does not mask other faults.
- **Dataset append with `AppendToLatestRowGroup = true` fails for a column with a value converter.** Re-opening an existing
  partition file reaches `LatestRowGroupValues.ReadFixed<int>` which throws `InvalidOperationException: Column 'Tag' uses a
  converter for 'RowFuzzId' and cannot be read as 'Int32'` (`ParquetWriter.OpenAppendFile`). Repro:
  [`repros/dataset-append-latest-converter/`](repros/dataset-append-latest-converter/) (an `RDN1` input; replay it with
  `PLANK_FUZZ_APPEND_LATEST_CONVERTER=1`, the option is off for the converter-bearing wide schemas by default).
- **A column a row never assigns keeps the previous row group's value (row API slot reuse).** `RowApiColumnWriteState<T>.ResetForReuse`
  clears only reference-typed buffers, so after a row group is written the reused slot still holds the earlier rows' scalar
  values (and records' scalar leaves). A later row that skips such a column is written with that stale value; reference columns
  (null) and nested collections (`RowApiNestedLeafBuffer`: an unassigned row is written as a null collection) behave correctly.
  Nothing documents "assign every column of every row". Repro: [`repros/rowapi-unset-column-stale-value/`](repros/rowapi-unset-column-stale-value/)
  (`RUS1`, fails: `unset Id read 7, expected 0`). The wide routes leave columns unassigned only where the behaviour is defined
  (reference columns, nullable collections) and skip the comparison for unassigned scalar columns.
- **Source generator emits uncompilable code for a column name containing `"`.** `Escape()` in `ParquetRowGenerator` and
  `NestedParquetRowEmitter` uses `SymbolDisplay.FormatLiteral(value, quote: false)`, which does not escape the double quote.
  `[ParquetColumn("a\"b")]` yields `Leaf("a"b", ...)`. (A compile-time defect; no fuzz seed.)
- **Negative `Execution.WorkerCount` gives `OverflowException` from the row writer** (found by the
  `0xDD EXEC` route, `PlankExecutionFuzzTarget`). With `RowApiMaxParallelism` unset,
  `ParquetWriterOptions.RowApiMaxParallelism` evaluates `checked((uint)Execution.WorkerCount)`; the generated
  `CreateRowWriter(stream, options)` reads it before `Validate()` runs, so `WorkerCount = -1` (or `int.MinValue`)
  surfaces as `OverflowException` instead of the documented `ArgumentOutOfRangeException(WorkerCount)`.
  Low severity (invalid input is rejected either way). The harness accepts both types.

## Open library defects found by the full-value oracle (oracle agent, 2026-11-27)

Both are symmetric in Plank's writer and reader (Plank and Arrow read the written metadata back
unchanged), so no round trip could see them; `FullValueOracle.VerifyWritten` recomputes the
metadata from Arrow-decoded values.

- **`distinct_count = 0` for columns without a defined sort order.** INT96, INTERVAL, GEOMETRY and
  GEOGRAPHY chunks get `statistics { null_count, distinct_count: 0 }` whatever their values (no min/max,
  which is right). Repro: [`repros/statistics-distinct-count-zero-unordered/`](repros/statistics-distinct-count-zero-unordered/)
  (13 writer seeds hit it, e.g. `corpus/encoding-plain-int96.bin`).
- **`uint`/`ulong` written to an unannotated (signed) INT32/INT64 column get statistics in unsigned order.**
  `CreateSerializedColumn<uint>` on `Leaf(..., Int32)` with no logical type is accepted and writes
  `min_value = 0, max_value = -1` for values `{0, 1, 65536, 1000000, 0xFFFFFFFF}`: min > max in the column's
  signed order, so `col < 0` pruning skips a chunk containing -1. Repro:
  [`repros/statistics-uint-in-signed-int32-order/`](repros/statistics-uint-in-signed-int32-order/)
  (`writer-gap-seeds/delta-binary-packed-int32/public-generic-dispatch.bin`).

- **Narrow unsigned reads wrap silently (read-API matrix).** `RowGroup.Column<byte|ushort|uint>` (and `<T?>`,
  `NestedColumn<T>`, row-reader descriptors) on *any* INT32 column — unannotated, DATE, TIME, INT(16, signed),
  INT(32, unsigned) — and `<ulong>` on INT64 return the value truncated to the CLR width (unchecked cast): DATE
  2019-04-15 (day 18000) reads as `byte` 80, -300 as 212. `sbyte`/`short` are refused (`NotSupportedException`), so
  this is not a deliberate "raw bits" contract. Repro: [`repros/narrow-unsigned-reads-wrap/`](repros/narrow-unsigned-reads-wrap/)
  (explicit test `Repro_NarrowUnsignedReadsWrapSilently`). The matrix excludes exactly this wrap shape unless
  `PLANK_FUZZ_STRICT_NARROWING=1`.
- **Minor spec deviation: precision/scale without any annotation read as DECIMAL.** A FIXED_LEN_BYTE_ARRAY schema
  element with `precision = 9, scale = 0` but neither `converted_type` nor `logicalType` is exposed by Plank as
  `LogicalType.Decimal(9, 0)`; the specification (and Arrow) leave it unannotated. Seeds:
  `reader-footer-seeds/footer-legacy-both-dropped-r00.bin`, `-r04.bin`. The reader oracle excludes exactly this shape.

Replays on ovh (2026-11-27, Plank 3a6a28a, `agents/oracle/chunked.sh`, chunks of 400 so a segfault loses one chunk):
writer target over every writer seed dir (1,004 inputs) + 18.8k random mutants: 14.8k Plank-written files checked
(828k chunk statistics, 453k pages of column/offset index, 33.5k Bloom values, 2k nested logical values) — every
mismatch is one of the two findings above. Reader target over every reader seed dir, the 8.5k-file generated corpus and
47k mutants: 9.5k accepted files fully compared (schema, counts, statistics vs raw footer, KV, sorting, Bloom probes,
13k nested logical values) — no mismatch left after the triage below. Segfaults seen only on `0xFF RWG1/RWN1` row-group
row-writer inputs and their mutants (the known #276 overrun; they crash with the oracle disabled too).
Harness hang noticed (surface-owned, not fixed here): the 6-byte writer input `C5 50 48 59 31 33` (`PHY1` + one
control byte) spins forever in `PhysicalReaderSurfaceCases.Execute` (stack: `Cur.Int` / `SortedSet.AddIfNotPresent`, no
library frame; same with both oracles off): with a one-byte control stream every draw is the same value, so a
draw-until-new loop never ends. 3 of 300 writer-mutant chunks hit the 30-minute timeout on such inputs.
Read-API matrix scale results (2026-11-28, Plank 3a6a28a): 106k writer mutants → 81.7k Plank-written files, 11.4M
column reads + 446k row-reader passes, 344M values; ≥90k cross-writer mutants → ≈75k Arrow-written files through every
read API; 202k reader mutants + 8k seeds. No value mismatch on any read API beyond the findings above; writer mutants
also re-hit the append-sorting −0/+0 harness bug already fixed in 6dbfcbd (the binary predated it).
Harness bug noticed (writer-owned, not fixed here): `DecimalBinaryStatisticsCoverageCase` picks the `_` value set for
any control byte ≥ 2 but expects the `order == 2` statistics only for exactly 2, so mutated `DBS1` inputs fault with
"Decimal binary statistics changed." although Plank's statistics are right (the oracle checks them).

Reader-side disagreements with Arrow classified as not Plank defects (replay of all reader seed dirs + 17k mutants):
Plank ignores deprecated-only `min`/`max` statistics (parquet-testing `int32_decimal`, `nested_lists`, impala files...)
where Arrow reads them for signed-order columns — a missed pruning opportunity, never a wrong value; where a footer has
both `min`/`min_value` and they differ, Plank uses `min_value` (spec) and Arrow the deprecated one, so the oracle checks
Plank's statistics against an independent raw Thrift parse of the footer (`RawFooter.cs`); a footer `num_rows` that
disagrees with the row groups' sum (parquet-testing `repeated_no_annotation` has 0) is an acceptance difference:
that file (parquet-rs 0.3.0) writes `FileMetaData.num_rows = 0` but `RowGroup.num_rows = 6`, and its data holds 6
records (pyarrow decodes 6; Plank's 6 rows match Arrow value for value), so nothing is lost or invented — the footer
field is the writer's bug. The deprecated-only statistics files (parquet-mr 1.8.x `int32_decimal`, `int64_decimal`,
`fixed_length_decimal(_legacy)`, `datapage_v2`, `nested_lists`, `nested_maps`, `nonnullable.impala`) carry only
fields 1/2 and no `column_orders`; those fields were computed with signed byte order for every type (PARQUET-686), so
they are wrong for strings and unreliable for FLBA decimals. Ignoring them is the safe choice; for signed ints it only
loses pruning. Reader-target replays built before 21e876a still report these 10 as "Plank lost a min/max" and
"file row count differs"; from 21e876a on, reader-pqt-seeds replays with 0 mismatches.

Not defects (checked by the same oracle): Plank's Bloom writer hashes -0.0 and NaN payloads by their
plain bytes as the spec says, and its typed `MightContain(±0.0)` also answers true for the other zero
(an allowed false positive; `Plank.Lab.Tests/FullValueOracleTests`). `ParquetWriterOptions.SortingColumns`
is the caller's declaration and is not validated by Plank, so the generic route declaring an order over
unsorted rows is not a defect; the oracle checks declared orders only on the append-sorting route.
## Open library defects found by the API-surface routes (surface agent, 2026-11-27)

- **`ParquetColumnChunkInfo.Equals` throws `NotSupportedException` on the first call per process.** The public record struct's generated
  equality reaches `ParquetColumnChunkEncodings` (inline-array storage, no custom equality); later calls succeed. Repro:
  [`repros/chunk-info-equality/`](repros/chunk-info-equality/). Found by route `PHY1` (marker 0xC5, `PhysicalReaderSurfaceCases`),
  which otherwise passes (page cursor, chunk layout, per-page CRC, Bloom no-false-negative, ordinal probes, stale handles).
- **`default(...)` of public handle structs throws `NullReferenceException`.** `default(NestedRowGroupColumn<T>).GetEnumerator()` and
  `default(<its Enumerator>).MoveNext()` (found by route `SRF1`, `SurfaceReflectionCases`, counted not faulted; set
  `PLANK_FUZZ_STRICT_DEFAULT_STRUCTS=1`). Low severity: a defined `InvalidOperationException` would be expected for an unusable default.
- Routes `PRN1` (page pruner vs unfiltered read), `WRG1` (RowGroupWriter protocol misuse is refused atomically), `SRF1`
  (value-type laws over every public type, default structs, ColumnBuffer/RowGroups index edges, MemoryReadSource/StreamReadSource/FileReadSource
  offset+length boundaries) found no further defect in ~1200 random inputs each.

## Open library defect found by hand-rewritten footers (reader agent, 2026-11-27)

- **Decimal inferred from `precision`/`scale` without a DECIMAL annotation.** A schema element with `precision`/`scale` but no `logicalType` and no `converted_type`
  is read as `LogicalType.Decimal(p, s)`; Arrow and ParquetSharp report no logical type. Repro: `fuzz/repros/decimal-precision-without-annotation/` (seed made by `fuzz/footer-seeds.py`,
  flagged by the full-value oracle's metadata comparison). Low severity (leniency, no memory unsafety).
- Also surfaced by the full-value oracle on an existing seed: `fuzz/reader-corpus/file-schema-nested-maps-dictionary-snappy.bin` — "statistics: Plank lost a min/max Arrow reads" for the nested map key column
  (`a.key_value.value.key_value.key`, Int32); owner: oracle agent.
## Open library defect found by the writer statistics oracle (writer agent, 2026-11-27)

- **`ulong` written to an unannotated (signed) INT64 column gets statistics in unsigned order** (64-bit sibling of the
  `uint` / INT32 finding above): min/max follow the CLR type, so min > max in the column's order for values above
  `long.MaxValue`. All encodings, required and optional. The 32-bit `uint` form (oracle agent's finding) also reproduces through `WTM1` (PLAIN, PLAIN_DICTIONARY, ...). Repro: [`repros/statistics-ulong-in-signed-int64-order/`](repros/statistics-ulong-in-signed-int64-order/).
  The same defect shows through value converters whose PHYSICAL CLR type is `uint`/`ulong` on an unannotated column (`WTM1` converter-unsigned-physical, all encodings). The earlier oracle keyed min/max by CLR type, which is why it could not see either bug; it now keys by the column's
  physical + logical type.

## Writer-route observations (writer agent, 2026-11-27) - limitations, not defects

Found while adding `WTM1` / `WNS1` / `WGS1`. Each is asserted by the route that found it, so a change in behaviour
(either way) shows up as a fault.

| Observation | Where |
|---|---|
| The writer always writes `boundary_order = UNORDERED` in the column index, even for monotonic page bounds. Valid, but readers cannot use the ordering. The oracle (`WriterStatisticsOracle`) fails if the field is missing, and fails if the writer ever claims ASCENDING/DESCENDING for bounds that are not ordered. | `Writing/Thrift/ParquetMetadataThriftWriter.cs:113` |
| A CLR `decimal` column inside a repeated structure (list, map) cannot be written: `Array type 'System.Decimal[]' is incompatible with column ...` (`InvalidOperationException`). The same decimal is fine in a flat column or in a non-repeated group. | `Writing/Encoding/RepeatedPageValues.cs:44`; asserted in `WriterGroupCases` |
| `NestedColumn<decimal>` cannot be read (`NotSupportedException: ... cannot be decoded into pooled values of type 'System.Decimal'`) even for non-repeated nested columns; decimals are compared through their physical form (`int`/`long`/bytes). | `Reading/Logical/Internal/NestedColumnBufferEnumerable.cs` |
| Optional BYTE_STREAM_SPLIT binary and FLBA DELTA_BYTE_ARRAY are rejected with explicit `NotSupportedException`s. | asserted in `WriterTypeMatrixCases.Binary` |
| `AppendToLatestRowGroup` on a column with a value converter fails with `InvalidOperationException: Column ... uses a converter for ... and cannot be read as ...` (the retained values are read back as the CLR type). New row groups and merges work. | asserted in `WriterTypeMatrixCases.AppendMergeVariant` |
| The internal LZ4 compressor throws `InvalidOperationException("LZ4 compression failed.")` for an EMPTY buffer (`LZ4Codec.Encode` returns 0), while snappy, gzip, zstd and brotli emit a valid empty stream. Not reachable through a real write (a zero-row column with `Lz4` writes and reads back correctly), so an observation. | `Writing/Compression/Lz4Compression.cs`; asserted in `WriterCodecCases.Direct` |
| `InitialColumnBufferBytes > int.MaxValue` is accepted by `ParquetWriterOptions.Validate`; it is only rejected when a column buffer is first rented. | `BufferWriterCapacityCases` |
- **`DatasetWriterOptions.PendingRowCapacity = int.MaxValue` is accepted by `Validate` and then fails with `OutOfMemoryException`**
  ("Array dimensions exceeded supported range") on the first queued row, instead of a defined refusal at construction (same class as
  the `TargetDataPageSizeBytes = int.MaxValue` finding above). Found by route `OPT1` mode 4 (`OptionsSweepCases`); counted as
  `knownPendingCapacityOom`, not faulted. Values above int.MaxValue are correctly rejected with `ArgumentOutOfRangeException`.
- Route `OPT1` (0xC2) otherwise found no defect in 2,600 inputs: every `ParquetWriterOptions` property with edge values (invalid ones are
  rejected with `ArgumentException` at `CreateWriter`, valid ones round-trip), `ParquetReaderOptions` / `ParquetFileReaderOptions` /
  `RowReaderOptions` (null pool, `WorkerCount <= 0`, `MaxReadAheadRowGroups` -1/2/int.Max rejected at creation), `Serialize` over exact /
  empty / offset-sliced / Memory-sliced inputs, merger counters and closed-state refusals, appender with `AppendToLatestRowGroup`.
  Behaviour note, not a defect: importing a file into a merger skips zero-row groups, and the merger's `RowGroupCount` agrees with the file.
- Route `NST1` (0xC1, `NestedSurfaceCases`) found no defect in 1,500 inputs: `ParquetGeospatialStatistics.Read` on hand-encoded Thrift
  compact structs (valid encodings decode exactly; wrong wire types, missing X/Y bounds and a mistyped type list are
  `CorruptParquetException`; ~13k truncations and bit flips never throw anything else), `ReadGeospatialStatistics` ordinal probes,
  `Serialize` offset/count slices of nested list columns against the Dremel levels, and `RowReaderOptions` on the nested row reader.

## Open library defect found by the resource-budget seeds (reader agent, 2026-11-27)

- **`PageMetadataReader.ScanPageLocations` throws `OverflowException` for a page header with `compressed_page_size = int.MaxValue`** (via `ParquetColumnChunkMetadata.OpenPages()`),
  where `CorruptParquetException` is required. Repro: `fuzz/repros/page-metadata-scan-overflow/`. The other ~1,900 declared-huge-size/count/list-length/binary-length/page-header seeds
  (`fuzz/reader-resource-seeds/`, made by `fuzz/resource-seeds.py`) were all rejected cleanly within the allocation/time budget (`ResourceBudget`), and every prefix of 86 valid files through
  four source flavours (`fuzz/reader-truncation-seeds/`, route `TRNC`) was rejected with `CorruptParquetException`.
- Route `LIF1` (0xC0, `LifetimeSurfaceCases`) found no library defect in 5,500 inputs: `ColumnBuffer.Retain` / `NestedColumnBuffer.RetainLevels`
  (also on borrowed and variable-length buffers) stay intact across enumerator advance, early enumerator Dispose, reader `Reset`, reader
  `Dispose` and pool churn, over a pool that poisons returned payloads with 0xDD, with every allocation returned exactly once and
  `DangerousGetAddress` stable; 2–4 threads sharing one pool and one schema (plain writer/reader, row API, dataset writer; the dataset writer is not
  documented thread-safe, so each thread owns its writer) read back exactly their own rows; `TargetFileSizeBytes` rollover (1 B … 512 MB)
  and 2–5-source mergers with per-file options preserve all rows in order; Geometry/Geography CRS, Geography algorithm and Variant version
  survive the logical and physical metadata; custom `IPageStrategy` implementations (page size 0/1/huge/varying, row counts 0/1/huge/varying,
  dictionary decisions changing per call) either fail with a defined `InvalidOperationException` ("Page strategy returned N rows for a page with M rows remaining")
  or write exact data, never hang (30 s watchdog).

## Open library defect found by triaging the NestedRowMaterializer faults (reader agent, 2026-11-28)

- **Nested (repeated) columns accept impossible level pairs.** A position with repetition level >= 1 (a continuation of a list) whose definition level is below that list's element level (e.g. `rep=1, def=0` in a required list of required elements)
  is accepted by the columnar nested reader and the row API and handed out as a row such as `rep=[0,1] def=[1,0] values=[2]`; Arrow rejects the file ("Length spanned by list offsets (4) larger than values array"). Only "first repetition level
  must be 0", "levels <= maxima" and the dense count are validated. 61 distinct mutants of the nested seeds hit this (all faulted in `NestedRowMaterializer`, which is right for required elements).
  Repro: `fuzz/repros/nested-levels-row-count-mismatch/levels-continuation-with-empty-def.bin` (+ README). Also noted there: the columnar reader returns more rows than the row group declares (373 vs 200), the row API truncates.

## Fuzz-harness defects (fixed)

- `DecimalBinaryStatisticsCoverageCase` (`DBS1`): any control byte >= 2 drew the third value set but the expectation was only
  applied for exactly 2, so mutated inputs (AFL found control `04`) faulted with "Decimal binary statistics changed." on a
  correct library. The control byte is now normalised once. Seed: `corpus/writer-decimal-binary-statistics-control-4.bin`.
- Append-sorting route (`0xF8`, kinds 3/4, double/float): the "ambiguous" `-0/+0` case built ascending retained rows
  even when the declared sort was descending, so the file violated its own `sorting_columns`
  ("rows violate the declared sorting_columns ... -2 then -1", found by AFL as 23 distinct inputs once the oracle began
  checking declared orders). Descending now mirrors the data and puts the order inversion at `-0 -> +0`.
  Seeds: `corpus/writer-append-sorting-zero-ambiguous-desc-{double,float}.bin`. Not a library defect.
- AFL-only: a long-lived persistent worker under a container memory cap runs out of heap on drawn multi-GB buffer
  options (`OutOfMemoryException` in `BufferWriter..ctor`); passes in a fresh process. Counted as `writer-oom-memory-cap`
  by `PLANK_FUZZ_KNOWN_FINDINGS`, not a library defect.
- A one-byte `FA` writer input indexed `data[1]`
  (`crashes/writer-aa7225e7d5b0a255.bin`).
- The `0x26`/`0x2E` logical-type probe collided with unrelated reader inputs,
  producing 843 false faults per tier. It is now gated by a marker and schema.

## Coverage

Run `20261112ai`, all four ISA tiers, reader and writer: **11,075 of 13,680
library branch outcomes (81.0%)**. The 2,605 unhit outcomes are listed in
[`unhit-20261112ai.tsv`](unhit-20261112ai.tsv) (regenerate with
`python3 fuzz/unhit-branch-inventory.py 20261112ai`); 1,275 of them are not yet
reviewed. Coverage over time: [`coverage-branch-history.html`](coverage-branch-history.html).

## About the notes

[`notes/coverage-audit-2026-11.md`](notes/coverage-audit-2026-11.md) is the
unedited log of the Nov 11–13 coverage work. Read it with three caveats:

- It was measured against Plank `a9c93f4` (Nov 8) and has not been rerun on
  current master. Some of it is already stale: `ReadNarrowInt32` now has
  callers, and `PlainEncoding.WriteOptionalFixedLengthPayloads` no longer
  exists.
- Line and IL-offset tuples such as `(1044, 52, path 0, ordinal 2)` refer to
  that revision.
- 64 of the 129 `fuzz/` paths it cites (queues, `.coverage-work/`,
  `disagreements/`) stayed in the original fuzz worktree and are not in this
  repository.
