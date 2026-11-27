# append-floating-sort-metadata: harness bug, NOT a library bug

Seeds (replay: `Plank.Fuzzing.Replay writer <file>`; both faulted with "Append sorting route wrote 0 sorting columns; expected 1"
before the harness fix):

- `double-ascending.bin`: `F8 03 00 02 02 80`
- `float-descending.bin`: `F8 04 01 03 04 80`

## Root cause

In `ExerciseAppendSortingCase` cases 3 (double) and 4 (float) filled `retained[i]` and `incoming[i]` in the *same* loop, with
`incoming[i] = retained[^1] + ...`. During the loop `retained[^1]` is still 0, so `incoming` was
`1.75, 3.5, 5.25, 7, 8.75` (double-ascending) after `retained = 0, 1.75, ..., 7`: the first incoming rows are
**below** the last retained row, i.e. the append really is out of order. `AppendSortingOrder` correctly compares
`retained[^1]` (7) with `incoming[0]` (1.75), gets a positive comparison and the writer correctly drops the sorting columns.
(The old README's "incoming continue from 8.75" was wrong.) Same for the float-descending seed. The integer, uint, etc. cases
already used two loops, which is why only floating point cases faulted. Not related to zero, NaN, page size, page indexes, CRC or
encoding: with correctly ordered values the library keeps the metadata for every combination tried (default/Plain/BYTE_STREAM_SPLIT/
dictionary encoding, paged 64/128 byte options or defaults).

Plank #219 (signed zeros) is unrelated; the finding was never a library bug.

## Fix / tests

Harness fixed (two separate loops in cases 3 and 4). Tests in `Plank.Lab.Tests/AppendFloatingSortMetadataTests.cs`:
`OrderedAppend_KeepsSortingMetadata` (public-API repro, library correct), `UnorderedAppend_DropsSortingMetadata` (the values the old
harness generated), `ReproSeeds_NoLongerFault`.
