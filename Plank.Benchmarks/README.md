# Benchmarks

Published Plank write cases use one reusable `CreateCursor()` / `NextRow()` cursor
when the checked-out Plank source includes `Plank.SourceGen/RowCursorEmitter.cs`.
Older revisions use `GetRow()`, so PR comparisons compile both versions without
reflection in the timed loop. Writer construction and worker startup remain in
setup; the timed method includes cursor creation, row assignments, and completion.
Pass `-p:PlankUseRowCursor=false` when building to compare the compatibility API
on the same Plank revision.

## Encoding regression suite

`--encoding-regression` measures every encoder path in `Plank.Writing.Encoding` and records a
SHA-256 of each encoded file alongside the timings.

```bash
dotnet run -c Release --project Plank.Benchmarks -- --encoding-regression --label baseline
dotnet run -c Release --project Plank.Benchmarks -- --encoding-regression --label current
dotnet run -c Release --project Plank.Benchmarks -- --encoding-regression-compare \
  artifacts/benchmarks/encoding-regression-baseline.json \
  artifacts/benchmarks/encoding-regression-current.json
```

The encoded-byte comparison is the exact signal; timings are a coarse regression net. Override the
defaults with `--rows`, `--warmups`, `--iterations`, or `--output`.

## Metadata regression suite

The metadata suite uses only Plank public APIs and loads fixture bytes into memory before timing.
Build it against the **reader revision under test**, but generate the files only once with a fixed
Plank writer revision and reuse the same directory for every reader. Never regenerate the fixtures
between revisions. `--generate-fixtures` refuses a nonempty directory. For example, from the repo root:

```bash
# PLANK_ROOT is an absolute path to a detached checkout of the desired Plank revision.
dotnet build -c Release Plank.Benchmarks -p:PlankRoot="$PLANK_ROOT"
dotnet Plank.Benchmarks/bin/Release/net10.0/Plank.Benchmarks.dll \
  --metadata-regression --generate-fixtures --fixtures artifacts/metadata-fixtures
# Optional, small real-world examples; first initialise the parquet-testing submodule.
cp library/Plank/third_party/parquet-testing/data/{alltypes_plain.parquet,nested_lists.snappy.parquet,nested_maps.snappy.parquet} artifacts/metadata-fixtures/
# Calibrate once on the baseline build, then use this exact file for all comparisons.
DOTNET_TieredCompilation=0 DOTNET_gcConcurrent=0 taskset -c 20 \
  dotnet Plank.Benchmarks/bin/Release/net10.0/Plank.Benchmarks.dll --metadata-regression \
  --calibrate --fixtures artifacts/metadata-fixtures --output artifacts/metadata-calibration.json
DOTNET_TieredCompilation=0 DOTNET_gcConcurrent=0 taskset -c 20 \
  dotnet Plank.Benchmarks/bin/Release/net10.0/Plank.Benchmarks.dll \
  --metadata-regression --fixtures artifacts/metadata-fixtures --label baseline --revision "$PLANK_SHA" \
  --calibration artifacts/metadata-calibration.json
dotnet Plank.Benchmarks/bin/Release/net10.0/Plank.Benchmarks.dll \
  --metadata-regression-compare artifacts/benchmarks/metadata-regression-baseline.json \
  artifacts/benchmarks/metadata-regression-current.json \
  --noise-baseline artifacts/metadata-results/noise-a.json --noise-current artifacts/metadata-results/noise-b.json
```

Choose an allowed, otherwise idle core (including its SMT sibling); `20` is just an example.
`--quick` selects smaller generated fixtures and three samples/one warmup for harness validation;
it is not a performance result. `--iterations`, `--warmups`, `--output`, `--fixtures` and
`--revision` override defaults. Each case is calibrated by doubling its operation count until the
fastest of three batches takes at least 1 ms (up to 65,536 operations); operations already taking
1 ms or longer remain single-invocation. Use `--calibrate --output FILE` once, then pass
`--calibration FILE` to every run; otherwise each run calibrates independently and the comparer
rejects incompatible operation counts. Calibration is tied to fixture hashes. Reports contain
per-operation time, exact batch allocated-byte totals and operation counts, and Linux one-minute
load. The runner pauses on load over 10; it does not require privileged isolation. The optional
`scripts/run_metadata_matrix.py --core 20 --calibration artifacts/metadata-calibration.json` runs
A/B/A/B processes and preserves raw rounds. It determines each PR's merge-base with master and
expects separate `artifacts/metadata-worktrees/{master,prN,base-SHA}` checkouts and matching
`artifacts/metadata-builds/{master,prN,base-SHA}` binaries (master itself is used when it is the
merge-base). Build each with a fresh restore/rebuild and a separate `-o` directory, initialise
required submodules, and use one shared fixture directory.

Cases include 1,200 columns × 3 row groups, 1,200 row groups × 3 columns, nested lists and maps
with a date logical type and key-value metadata, and V1/V2 chunks with small pages, statistics,
indexes and bloom filters. Optional parquet-testing files add independently produced nested and
flat schemas. An untimed SHA-256 of a canonical public-metadata dump and the fixture byte SHA-256
are recorded for every case/operation. This is a regression signal, not proof that every private
field was decoded identically. A missing case, changed fixture or changed digest is reported.

Operations separately cover physical footer reset, logical reader reset (which also decodes the
footer; public API does not expose binding alone), pre-opened logical metadata walking, first-chunk
physical page cursor scanning, first-chunk logical `OpenPages()` where both indexes exist,
bloom-filter opening when present, and out-of-place merging to an in-memory destination. The public
physical cursor also loads and may decompress page payloads; it is not a header-only API. Page
header statistic bytes are not public; logical chunk and page-index statistic bytes are included in
the digest. Merge includes copying/rebuilding the file, not a metadata-only public operation.
Open/index/bloom/merge allocations include their setup and disposal. Digests are computed outside
timing. Allocation batch totals are exact for the measuring thread, not process-wide totals; the
comparer divides them by the operation count using exact fractions (a batch average, not an
individual-operation measurement). All raw samples are retained. Time is normalized per operation
and reported as min/median/p90, with the p10–p90 spread. A timing
verdict requires both master/master snapshots and a delta exceeding the larger of their measured
median shift, their p10–p90 spreads, and the compared runs' spreads. Without noise snapshots time is
unclassified; small samples, JIT, GC, CPU frequency and contention can still dominate results.

## Published direct benchmarks

The homepage results come from the BenchmarkDotNet cases in `Published/Cases`. Every data type and
encoding has a separate source file, and every library has its own direct `Write` and `Read` benchmark
methods. The timed paths do not pass through the old generic adapters, per-cell type switches, or a
shared row helper.

The full run uses zero warmups and 100 ordered measured iterations in **one process per case**.
The ColdStart strategy skips workload JIT pre-runs, pilot iterations and overhead calibration;
forced per-iteration GC and outlier removal are disabled. Automatic GC remains enabled.
Sample 1 is the first operation after setup; samples 2–100 show subsequent behavior. This is
not a measurement of process startup or constructor/setup costs, and not 100 cold process launches.

```bash
dotnet build -c Release Plank.Benchmarks/Plank.Benchmarks.csproj
sudo python3 Plank.Benchmarks/scripts/run_cpu_isolated.py -- \
  dotnet Plank.Benchmarks/bin/Release/net10.0/Plank.Benchmarks.dll --published
```

PR CI can opt into `--published --pr-comparison`: each child uses Throughput with
20 warmups and 50 measured iterations. Tiered compilation is disabled so every
method is fully optimized on first use, and concurrent GC is disabled so background
collections cannot overlap measurements. Invocation count stays at one because
readers/writers require resetting between calls. Forced collections keep each
iteration's starting state comparable, overhead evaluation is skipped for these
millisecond-scale operations, and all measured samples are retained. The default
bare-metal profile above is unchanged. Explicit BenchmarkDotNet count arguments
override the PR counts.

Adding `--measurement-time-ms 500` selects the adaptive CI profile. Each case is
calibrated independently and uses enough measured iterations to target 500 ms of
total measured work, bounded to 15–1000 iterations. This gives short cases more
samples while reducing long, stable cases. An explicit BenchmarkDotNet
`--iterationCount` becomes the minimum.

Use a focused quick run while changing the harness:

```bash
dotnet run -c Release --project Plank.Benchmarks -- \
  --published --quick --filter '*SyntheticInt32Plain*'
```

`--published-write` and `--published-read` remain aliases for running only that direct method across
the suite. Use `--rows`, `--taxi-rows`, or `--data-file` to override input. The default taxi path is
`Plank.Benchmarks/nyc-data/yellow_tripdata_2024-01.parquet`.

Synthetic cases use 1,000,000 flat rows and 22 columns and produce 22 row groups. Taxi-derived cases
use all 2,964,624 rows and produce three row groups. Column inputs are transposed into typed arrays
outside timing. Streams, capacities, reusable Plank writer/reader setup, worker startup, and pinning
stay outside the timed method where the API permits it. Plank's multi-column read schedules PLINQ
workers inside the timed method. Single column cases remain sequential. Wide schemas additionally
generate `ColumnMulti` adapters: Plank serializes independent columns in parallel before ordered
schema emission. Plank reads every row-group/column pair through PLINQ using the available CPU count;
ParquetSharp reads columns in parallel through one reader/source per column. ParquetSharp multi write
and all Parquet.Net multi cases are intentionally unavailable.

Read and write have separate targeted global setups, neither of which invokes the timed method.
Before launching measurements, preparation processes build one shared read fixture per selected
schema and determine each selected writer's output capacity. These run-scoped temporary artifacts
are removed when the command finishes; there is no persistent fixture cache. The preparers cannot
warm the benchmark processes. Read cases load only the prepared bytes, not millions of source row
objects. Write cases still construct their input row objects once per process and reuse them for
all measurements. Preparation retains each required row representation only within its schema's
preparation process. Writer output sizes are validated outside timing on every iteration. Output backing arrays are
allocated once in global setup and reused across iterations for every library. Each iteration opens
an empty stream over the same array, so library-owned stream closure does not discard the buffer.
The first write can incur first-touch page costs; later writes reuse the populated output memory.

MemoryDiagnoser runs an additional operation **after** the measured series to collect allocation
statistics; those statistics describe post-series behavior, not allocations during first use.
The JSON reports preserve all samples in execution order and expose the first iteration separately
from the median of subsequent iterations. Effective job settings are read from the log rather than
hard-coded. Old warmed-up snapshots are not directly comparable to this first-use protocol.

The isolation runner reserves housekeeping CPUs, moves movable threads and IRQs away from the
benchmark CPUs, and restores the exact original affinity state when the command exits or is killed.
On asymmetric CPUs it keeps lower-capacity cores in the housekeeping set.

Convert one complete isolated log into a write/read snapshot pair:

```bash
python3 Plank.Benchmarks/scripts/publish_results.py \
  --log artifacts/benchmarks/full.log \
  --matrix Plank.Benchmarks/Published/Cases/matrix.json \
  --generated Plank.Benchmarks/Published/Cases \
  --cpu 'AMD Ryzen 9 7900X' \
  --operating-system 'Linux' \
  --commit "$(git rev-parse HEAD)" \
  --write-output artifacts/benchmarks/write.json \
  --read-output artifacts/benchmarks/read.json
```

The publisher rejects incomplete logs, including any supported method without the exact measured
sample count in the effective job configuration,
missing allocation data, or missing write output sizes. All measured allocation values, including
nonzero Plank write allocations, are preserved as report data from the separate post-series
diagnostic invocation. Publish multiple
machines with `scripts/publish_matrix.py`; it checks that each write/read pair came from the same CPU
and commit before copying it to `docs/benchmarks`.

Column reads consume each fully decoded buffer through a shared non-inlined span
helper and validate the total element count. They do not traverse values to compute
a timed checksum. Plank buffer enumeration, ParquetSharp `ReadBatch`, and awaited
Parquet.Net `ReadAsync` still drive decoding; binary payloads use the same span
consumption. Row benchmarks still access every measured field. Full column
checksums live in untimed `VerifyRead` methods, exercised against row fixtures and
column-writer output by `ColumnWorkloadTests`. `ColumnMulti` cleanup emits
`BENCHMARK_THREADS|type|operation|workerCount|observedThreads`; the publisher stores both
`workerCount` and `observedThreads` (and uses the latter for the UI thread label), rather than
inferring execution from CPU affinity. Regenerate the column adapters with
`python3 Plank.Benchmarks/scripts/generate_column_cases.py`.
