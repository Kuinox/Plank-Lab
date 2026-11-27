# Reader differential-fuzzing oracle

## Campaign reports

- [Branch coverage over time](coverage-branch-history.html) shows the four-ISA reader and writer percentages for each completed snapshot.
- [Fuzz findings](FINDINGS.md) lists the library defects fuzzing found, their fixes and repros, and what is still open. The full November 2026 coverage and reachability log is in [notes/coverage-audit-2026-11.md](notes/coverage-audit-2026-11.md).

To add a comparable four-ISA snapshot, build the Release replay driver, run
writer and reader with the same tag, then regenerate the HTML report:

```bash
dotnet build Plank.Fuzzing.Replay/Plank.Fuzzing.Replay.csproj -c Release
tag="$(date +%Y%m%d%H%M%S)"
PLANK_FUZZ_MAX_PARALLEL=2 PLANK_FUZZ_KEEP_SNAPSHOT=1 bash fuzz/coverage-tiers.sh "$tag" writer
PLANK_FUZZ_MAX_PARALLEL=2 PLANK_FUZZ_KEEP_SNAPSHOT=1 bash fuzz/coverage-tiers.sh "$tag" reader
python3 fuzz/coverage-branch-history.py
```

Use `PLANK_FUZZ_REUSE_SNAPSHOT=1` with the same tag to retry a failed run on
its retained input tree. Two tiers at a time avoided the memory failure seen
with four concurrent writer replays; incomplete runs are excluded from the
HTML history.

The reader target drains Plank's decoders and then uses ParquetSharp as an independent acceptance oracle. For flat, required primitive columns using PLAIN, RLE, or dictionary encodings, it also compares every decoded value with Parquet.Net. A value mismatch is always a finding; the exceptions below apply only to the named acceptance or oracle-capability differences.

## Existing exceptions

| Exception or condition | Scope | Reason / treatment |
|---|---|---|
| Damaged opening `PAR1` with a readable footer and trailing magic | Skip independent-reader comparisons | Deliberate Plank behavior: eager header validation is wasteful and adds little when the footer is checked. |
| ParquetSharp reports encoding 10 as `Undefined` | Skip that ParquetSharp column | ParquetSharp 24 does not expose the preview ALP encoding; this is an oracle capability gap. |
| ParquetSharp reports `Dictionary encoding not implemented for boolean type.` | Suppress that ParquetSharp rejection | Its physical reader cannot decode dictionary-encoded booleans accepted by Plank. |
| `ArgumentOutOfRangeException`, parameter `footerLength` | Suppress ParquetSharp mismatch | Existing bounded-footer acceptance difference for a negative or truncated footer length. |
| ParquetSharp RLE diagnostic containing `RLE` and `run` | Suppress ParquetSharp mismatch | Existing short-RLE-run acceptance difference. |
| `Deserializing page header failed` with `TProtocolException: Invalid data` | Suppress ParquetSharp mismatch | Known malformed-page-header acceptance difference; includes the unknown Thrift field/type 13 case. |
| `Unknown encoding type for levels.` | Suppress ParquetSharp mismatch | Known level-encoding acceptance difference. |
| ParquetSharp `NotSupportedException` while draining | Stop that oracle check without a finding | The oracle cannot judge an unsupported feature. |
| Parquet.Net `NotSupportedException` | Stop that oracle check without a finding | The oracle cannot judge an unsupported feature. |
| Parquet.Net `InvalidOperationException` mentioning `dictionary` | Suppress Parquet.Net mismatch | Its generic primitive reader rejects some dictionary-backed chunks despite advertising dictionary support. |
| Parquet.Net `IOException` while opening | Skip Parquet.Net comparison | It validates the file envelope before columns; this is not a decoded-value comparison. |

The suppression predicates intentionally match specific diagnostics. New exceptions, new value mismatches, crashes, hangs, and resource-limit failures remain findings.

## Full-value oracle (`Plank.Fuzzing/FullValueOracle.cs`)

Plank→Plank round trips cannot see a defect that is symmetric in the writer and reader. Two hooks:

- **Reader target** (file-schema route, after the Arrow value comparison): `VerifyAccepted` compares what Plank
  exposes about the footer with Arrow's reading of the same footer: every leaf's path, max levels, physical type,
  FLBA length and logical type (all parameters: decimal precision/scale, time/timestamp unit and isAdjustedToUTC,
  int width/sign, string/enum/json/bson/uuid/float16/interval/unknown); row-group and file row counts; chunk
  `num_values`; statistics null_count, distinct_count and min/max bytes; key/value metadata; row-group sorting
  columns; and every Bloom probe: `MightContainHash` must equal a spec SBBF lookup over the bitset, typed
  `MightContain` overloads must not miss a value the spec XXH64 of its plain encoding finds.
- **Writer routes** (every `new MemoryReadSource(...)`/`new MemoryStream(x.ToArray(), writable: false)` read-back in
  the writer, row-API, dataset, merger and *Cases routes goes through `FullValueOracle.Source`/`Checked`; the generic
  route calls `VerifyWritten`): a file Plank wrote and reads in full must be opened and decoded by Arrow; Plank's
  levels and physical values must equal Arrow's for every column (any type, encoding, nesting); flat logical values are
  checked by `LogicalOracle`; then all metadata is recomputed from Arrow-decoded values: row-group rows and chunk
  `num_values` from the levels, chunk statistics (null_count, distinct_count, min/max with the column's type-defined
  order — signed/unsigned ints, numeric floats/float16 without NaN and with ±0 equal, signed big-endian decimals,
  unsigned bytes; undefined for INT96/INTERVAL; inexact bounds only have to bound), offset index (first_row_index from 0,
  increasing, page row counts), column index per page (null_count, null_pages, min/max, boundary_order), Bloom
  membership of every present value with the specification's hash, and — on the append-sorting route only, where Plank
  decides it — declared sorting columns against the rows. Files Plank itself rejects are left to the route.
  `PLANK_FUZZ_ORACLE_DUMP=<dir>` saves each mismatching written file; `PLANK_FUZZ_FULL_ORACLE=0` disables both hooks.

Oracle capability gaps (narrow, by name; value and metadata mismatches are never suppressed): encoding 10 (ALP) columns
and pages, dictionary-encoded BOOLEAN (Arrow cannot decode them); logical types ParquetSharp 24 has no class for
(GEOMETRY, GEOGRAPHY, VARIANT: no logical-type comparison); key/value pairs with NUL or invalid UTF-8, or duplicate keys
(ParquetSharp marshals a dictionary of C strings); Arrow's own min/max only compared when it reports `HasMinMax`; Arrow
reports an absent null/distinct count as 0, so presence is compared one way only. Page indexes and Bloom filters are not
exposed by ParquetSharp 24, so those are checked against Arrow-decoded values (writer side) and the spec (both sides).

## Running

Build the instrumented target, generate the corpus, install the pinned AFL++ 4.x binaries, and run `fuzz/verify-harness.sh reader` before starting a campaign. AFL++ 5.x is incompatible with the current persistent harness: it can report very high throughput while treating the whole coverage map as already covered.

Each AFL worker needs its own `AFL_TMPDIR`; sharing one temporary directory prevents secondary workers from starting. Use `-x fuzz/parquet.dict` and set `PLANK_FUZZ_CRASH_DIR` to a durable crash directory.

## Generated reader seeds

`Plank.Fuzzing.Reader.Target --generate-corpus <dir>` writes the full generated corpus (≈8.5k seeds, `gen-*`);
only a bounded subset is committed: `fuzz/reader-gap-generated/` (boundary-size, nested-leaf, logical×encoding,
nullable-dictionary, multi-page seeds from `Plank.Fuzzing/ReaderGapSeedCases.cs`, files ≤ 8 KB) and the
`gen-codec-*` decompressor seeds in `fuzz/reader-corpus/` (every block codec × size × level × destination length ±1).
Coverage runs must replay the generated corpus too: the committed `reader-*` dirs alone miss most of the reader.

## Seeds from other writers

- `fuzz/pyarrow-reader-seeds.py` (pyarrow: version 1.0/2.6, v1/v2 pages, every codec, DELTA_*/BYTE_STREAM_SPLIT on every width incl. FLBA, INT96,
  bloom filters, page indexes, checksums, legacy and compliant nested layouts) -> `fuzz/reader-pyarrow-seeds/` (routes 0x00/0x04 kept).
- `fuzz/footer-seeds.py` (hand-rewritten Thrift: unknown fields of every type in footer and page headers, bloom length missing, location gaps,
  geospatial statistics/logical types, legacy-only converted types) -> `fuzz/reader-footer-seeds/`.
- `fuzz/reader-pqt-seeds/`: `import-parquet-testing-seeds.sh` output (≤ 8 KB files of the pinned parquet-testing submodule), committed here so coverage runs include it.
- `fuzz/reader-converter-seeds/`: inputs for the `CVRT` route (`ConverterDeclineProbe`): each flat leaf read through value converters of every plausible physical type.
- Coverage summarising helpers: `fuzz/tools-reader-coverage/` (`covunion.py PATTERN cobertura...`).

### Writer AFL and threads (`PLANK_FUZZ_SINGLE_THREAD`, `PLANK_FUZZ_SURVIVE_CRASH`)

SharpFuzz keeps the previous-location state in a static, so any code running on another thread scribbles
on the coverage map and the same input maps different edges on every run. Symptoms in `fuzzer_stats`:
`stability` of a few percent, `var_byte_count` near 65k, `edges_found == total_edges`, and a corpus that
grows with junk. The row-API pipeline always starts worker threads, so set `PLANK_FUZZ_SINGLE_THREAD=1`
for AFL runs (row routes then draw `MaxParallelism`/`ExplicitParallelism`/`ReaderWorkers` as usual but pin
them to 1). That is not sufficient on its own: the RowApi (`0xFF`) and dataset (`0xFE`) routes were still
nondeterministic, so campaigns used a filtered corpus/dictionary without them.
Check `afl-showmap` twice on a seed before trusting a route under AFL.

`PLANK_FUZZ_SURVIVE_CRASH=1` makes the harness report a managed exception to AFL as a crash (wait status
11) and keep serving instead of FailFast-ing, so AFL records crashes and does not re-dry-run the queue on
restart. Native crashes still kill the worker; run workers in a restart loop (see `jobworker` pattern).

`PLANK_FUZZ_KNOWN_FINDINGS=all` (or a comma list of ids: `276`, `distinct-count-zero-unordered`,
`uint-ulong-signed-stats`, `chunk-info-equality`, `decimal-without-annotation`, `page-size-int-max`,
`dataset-append-latest-converter`, `stale-scalar-slot-reuse`, `negative-workercount`) makes the AFL harness
treat a fault that matches a documented finding's narrow signature (`Plank.Fuzzing.Harness/KnownFindings.cs`,
matched against the full exception text) as a pass: it is not an AFL crash and no crash file is saved; the
counts go to `$PLANK_FUZZ_CRASH_DIR/known-findings-<target>-<pid>.txt`. It is off by default and the replay
driver never uses it. Remove an id's signature when the library bug is fixed so a regression shows up again.
