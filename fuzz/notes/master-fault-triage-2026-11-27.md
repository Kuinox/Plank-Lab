# Triage of the replay faults that appeared with the bump to Plank master 3a6a28a (2026-11-27)

Method: each seed was replayed on master 3a6a28a (current harness) and on the old pin 127b567 with the
pre-bump harness e1fe916. The writer case files (`EncodingCoverageWriterCases.cs`,
`RepeatedRowsCoverageCases.cs`, `RepeatedAccumulatorCoverageCase.cs`, `PlankDatasetOperationalFuzzTarget.cs`)
are identical in both harnesses, so every writer difference is a library behaviour change; every seed below
passed on the old pin except `rowapi-direct-rowgroup.bin` (#276). The commit that changed each behaviour was found by
`git log -S` on the new message/code path and confirmed by reading the commit's code and tests.
#276 was checked by applying its one-line fix (`if (_slot.IsFull && !_slot.Grow()) throw ...` in
`RowGroupWriterCore.GetSlotForRow`) in a scratch copy of the submodule (never committed).

| Seed | Master behaviour | Class | Root cause / justification | Plank commit |
|---|---|---|---|---|
| `writer-gap-seeds/repeated-rows-coverage/memory.bin` | `ReadOnlyMemory<byte>[][]` rows for a required-element list are accepted | intended | `SerializeRepeated` added a single-level ROM route. Harness now checks that the ROM rows encode the same levels and values as the same rows as `byte[][]` (they do) | 80578da (#224) |
| `.../repeated-rows-coverage/memory-optional.bin` | still rejected, message now "has optional list elements; use a nullable row element type" | intended (message) | `RepeatedPageValues.Flatten` replaced the row-carrier check | 80578da (#224) |
| `.../repeated-rows-coverage/unknown-flat.bin`, `unknown-nested.bin` | still rejected, message now "Unsupported repeated physical type '255'" (before any nesting check) | intended (message) | physical-type switch in `SerializeRepeated` | 80578da (#224) |
| `writer-gap-seeds/repeated-accumulator/time-only.bin` | `TimeOnly[]` rows still rejected before statistics, message now "Array type 'System.TimeOnly[]' is incompatible with column" | intended (message) | `RepeatedPageValues.Flatten` | 80578da (#224) |
| `writer-gap-seeds/encode-optional/public-empty-optional-columns.bin` | flat `int?` rows on a list column still rejected, message now "Array type 'System.Nullable`1[System.Int32]' is incompatible" | intended (message) | same | 80578da (#224) |
| `writer-gap-seeds/fixed-bss/read-only-memory-rejected.bin` | FIXED_LEN_BYTE_ARRAY + BYTE_STREAM_SPLIT now accepts `ReadOnlyMemory<byte>` | intended | "Support fixed-width binary memory values in all encodings". Harness now round-trips ROM values (including offset slices) and compares them | 2ecda7b (#229) |
| `corpus/dataset-operational-promotion-open-retry.bin` | after the injected Open failure the next `Queue` rethrows the same IOException | intended | "Fault dataset writers permanently after errors": a failed Queue faults the writer, open parts are aborted, parked rows are not drained (see the library's `FailedPartOpenOrSelectorFaultsWriterAndAbortsOpenParts`). Harness now expects the rethrow and checks that finalized parts hold only pre-failure rows, each once | 974f6c3 (#274) |
| `corpus/dataset-operational-parked-copy-failure.bin`, `writer-gap-seeds/dataset-parked-copy-failure-dbr1.bin` (CRASH, ArgumentNullException 'bytes') | the null-payload row faults the writer and the next `Queue` rethrows ArgumentNullException | intended | same (`NullRowFaultsWriterAndAbortsOpenPart`, `FailedRowCopyAbortsCreatePartsAndDoesNotPromoteParkedRows`) | 974f6c3 (#274) |
| reader `reader-corpus/` + `reader-focused-seeds/nested-gap-map-{string,binary}-v{1,2}-rowapi` (8) | "Empty/null collection marker at position 1." | **harness bug** | `PlankReaderFuzzTarget.NestedCollectionLevels` (added with the bump in 823d4d7, when Plank moved nested materialization into generated code) assumed every collection's element sits at the leaf's max definition level. A MAP with an optional value has a null value at the entry level (def 2 of 3), which `NestedRowMaterializer` then read as an empty-collection marker. Only the optional-value seeds fault; the `-required` ones pass. Fixed: levels are now derived from the schema tree (each optional/repeated node +1, LIST/MAP add their implicit repeated group), with the old guess only as a fallback | harness 823d4d7 |
| `corpus/writer-converter-matrix-13`, `-27` (reported by rowapi: ArgumentException "Logical type 'Time(Millis)' requires physical type 'Int32'") | not reproducible on current master + current harness (32 converter-matrix/timestamp-metadata seeds × writer/merger/reader × default/avx2off/scalar/row-workers: 0 faults) | intended change, already adapted | `ColumnDefinition` now rejects invalid logical/physical pairs at definition time (spec: TIME(MILLIS) annotates INT32 only). Reproduced exactly by reverting Plank-Lab 699c5c5 on master; the reporting clone (`agents/rowapi`, HEAD 6b94e7b) predates that commit. 699c5c5 moved case 13 to Time(Micros)/INT64; Time(Millis)/INT32 stays covered in `LogicalMetadataWriterCases` | Plank 5a044a9 (#233); harness fix Plank-Lab 699c5c5 |
| `corpus/writer-metadata-required-timestamp-wrong-physical.bin` (same report: ArgumentException "Timestamp requires INT64 or a 12-byte FIXED_LEN_BYTE_ARRAY") | same: the INT32 Timestamp column is now rejected by `ColumnDefinition.Leaf` (ArgumentException, ParamName physicalType) instead of later by the encoder | intended change, already adapted | the spec does not allow TIMESTAMP on INT32; 699c5c5 expects the eager rejection | Plank 5a044a9 (#233); harness fix 699c5c5 |
| `corpus/rowapi-direct-rowgroup.bin` | "No more row slots are available." | known library bug | Plank #276 | — |
| `corpus/rowapi-deep-3.bin`, `rowapi-deep-4.bin` (CRASH, ArgumentOutOfRange "Row index is outside the buffer slot", RWD1 route) | direct row-group writer with fuzzed capacity < row count | known library bug (#276) | pass with the #276 fix applied | — |
| `corpus/rowapi-wide-direct-groups-1.bin`, `rowapi-wide-nullable-direct-groups-{1,2}.bin` (SIGSEGV, exit 139) | the generated wide-row slot overruns its buffers | known library bug (#276) | exit 0 and no FAULT with the #276 fix. The old pin "passing" means nothing here: these RWW1/RWN1 routes were added after the bump (4f73291). Keep them in `coverage-skip.txt` until #276 lands | — |

With the #276 fix applied, the whole writer replay (920 inputs, including the 3 quarantined seeds) and the merger replay
(817) report 0 FAULT/CRASH. Without it, after these harness updates: writer 3 (the #276 seeds above, plus the 3 quarantined
segfaults), reader 0 of 134, merger 0. The two append-sort repros (`fuzz/repros/append-floating-sort-metadata/*.bin`) and
both `append-no-sorting-empty-guard.bin` seeds pass.

No new library bug among these faults: none of them is the canary.
