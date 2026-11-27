# Fuzz findings

What fuzzing Plank has found, and what is still open. Status as of 2026-11-18,
against Plank `master` at `127b567`.

The detailed coverage and reachability notes that used to live here are in
[`notes/coverage-audit-2026-11.md`](notes/coverage-audit-2026-11.md). They are
lab notes, not findings; see [About the notes](#about-the-notes) before relying
on them.

## Library defects

All found by the reader/writer fuzz targets or their oracles, all fixed.

| Defect | Fixed in | Repro |
|---|---|---|
| Malformed DELTA_BINARY_PACKED batches escape as `ArgumentOutOfRangeException` from the INT32 and INT64 readers instead of `CorruptParquetException` | [#216](https://github.com/Kuinox/Plank/pull/216) | Saved queue inputs, not committed |
| Appending to a sorted FLOAT/DOUBLE file drops its sorting metadata | [#219](https://github.com/Kuinox/Plank/pull/219) | [`writer-gap-findings/append-floating-sort-metadata/`](writer-gap-findings/append-floating-sort-metadata/) |
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
