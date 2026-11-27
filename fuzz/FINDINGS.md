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
Harness bug noticed (writer-owned, not fixed here): `DecimalBinaryStatisticsCoverageCase` picks the `_` value set for
any control byte ≥ 2 but expects the `order == 2` statistics only for exactly 2, so mutated `DBS1` inputs fault with
"Decimal binary statistics changed." although Plank's statistics are right (the oracle checks them).

Reader-side disagreements with Arrow classified as not Plank defects (replay of all reader seed dirs + 17k mutants):
Plank ignores deprecated-only `min`/`max` statistics (parquet-testing `int32_decimal`, `nested_lists`, impala files...)
where Arrow reads them for signed-order columns — a missed pruning opportunity, never a wrong value; where a footer has
both `min`/`min_value` and they differ, Plank uses `min_value` (spec) and Arrow the deprecated one, so the oracle checks
Plank's statistics against an independent raw Thrift parse of the footer (`RawFooter.cs`); a footer `num_rows` that
disagrees with the row groups' sum (parquet-testing `repeated_no_annotation` has 0) is an acceptance difference.

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

## Open library defect found by hand-rewritten footers (reader agent, 2026-11-27)

- **Decimal inferred from `precision`/`scale` without a DECIMAL annotation.** A schema element with `precision`/`scale` but no `logicalType` and no `converted_type`
  is read as `LogicalType.Decimal(p, s)`; Arrow and ParquetSharp report no logical type. Repro: `fuzz/repros/decimal-precision-without-annotation/` (seed made by `fuzz/footer-seeds.py`,
  flagged by the full-value oracle's metadata comparison). Low severity (leniency, no memory unsafety).
- Also surfaced by the full-value oracle on an existing seed: `fuzz/reader-corpus/file-schema-nested-maps-dictionary-snappy.bin` — "statistics: Plank lost a min/max Arrow reads" for the nested map key column
  (`a.key_value.value.key_value.key`, Int32); owner: oracle agent.
## Open library defect found by the writer statistics oracle (writer agent, 2026-11-27)

- **`ulong` written to an unannotated (signed) INT64 column gets statistics in unsigned order** (64-bit sibling of the
  `uint` / INT32 finding above): min/max follow the CLR type, so min > max in the column's order for values above
  `long.MaxValue`. All encodings. Repro: [`repros/statistics-ulong-in-signed-int64-order/`](repros/statistics-ulong-in-signed-int64-order/).
  The earlier oracle keyed min/max by CLR type, which is why it could not see either bug; it now keys by the column's
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
| `InitialColumnBufferBytes > int.MaxValue` is accepted by `ParquetWriterOptions.Validate`; it is only rejected when a column buffer is first rented. | `BufferWriterCapacityCases` |

## Fuzz-harness defects (fixed)

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
