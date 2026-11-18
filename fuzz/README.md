# Reader differential-fuzzing oracle

## Campaign reports

- [Branch coverage over time](coverage-branch-history.html) shows the four-ISA reader and writer percentages for each completed snapshot.
- [Historical findings and reachability audit](FINDINGS.md) records the November 2026 snapshot, defect repros, differential results, and removal candidates. Its six confirmed Plank defects have since been fixed on Plank `master`.

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

## Running

Build the instrumented target, generate the corpus, install the pinned AFL++ 4.x binaries, and run `fuzz/verify-harness.sh reader` before starting a campaign. AFL++ 5.x is incompatible with the current persistent harness: it can report very high throughput while treating the whole coverage map as already covered.

Each AFL worker needs its own `AFL_TMPDIR`; sharing one temporary directory prevents secondary workers from starting. Use `-x fuzz/parquet.dict` and set `PLANK_FUZZ_CRASH_DIR` to a durable crash directory.
