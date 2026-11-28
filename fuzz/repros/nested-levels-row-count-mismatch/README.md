# Nested pages: impossible definition/repetition level pairs are accepted and handed out

**Finding (library, missing validation).** For a repeated column, Plank validates that the first repetition level is 0 (`Nested column ... starts with a non-zero repetition level`), that levels are <= the
schema maxima and that the dense value count matches — but not that a *continuation* (`rep >= 1`) is paired with a definition level at or above that repetition's element level.
`levels-continuation-with-empty-def.bin` (route 0x00; `list<int32 not null> not null`, rows `[1] [2,3] [4]` with the level stream `rep=[0,0,1,0] def=[1,1,0,1]`, three dense values) is accepted by
both the columnar nested reader and the row API: row 1 comes back as `rep=[0,1] def=[1,0] values=[2]` — a list that both continues (rep 1) and is empty (def 0). Arrow/ParquetSharp reject it
("Length spanned by list offsets (4) larger than values array (length 3)"); `levels-valid-control.bin` (the same file with valid levels) is read identically by all. Generated rows from such levels are
garbage (the generated row code would build a list whose length disagrees with its values).

Origin: 61 distinct mutated seeds (`m1000-729.bin`, `m1002-1199.bin` here are two; found by `fuzz/mutate-decoder-seeds.py`) — all contain `(rep=1, def=0)` positions in a required-list/required-element column (51) or the 2-level variant (10); the
harness's `NestedRowMaterializer` ("Empty/null collection marker at position N") is the check that caught them, so those faults are **true positives** for required-element lists (its level model is wrong for lists with *optional* elements,
which is a separate harness issue). Plank's columnar reader additionally returns `RowCount` 373 for a row group that declares 200 rows (the row API silently keeps the first 200).

Observation (lenient, not a defect on its own): when the footer/page header declares *fewer* rows than the repetition levels define (`list-4rows-declared2/3-*`), Plank's columnar reader returns all 4 rows, the row API the declared prefix — pyarrow also returns the prefix.
Declared *more* rows than the levels define: Plank rejects (`Repeated column 0 has 7 values but row group 0 has 100 rows` / `ended before the row group was complete`); pyarrow is lenient for V1 pages.

Regenerate: `uv run --with pyarrow python -I make-repros.py <dir>`. Diagnose: `Plank.Fuzzing.Reader.Target --triage-nested <dir>` prints columnar and row-API levels/values side by side.
