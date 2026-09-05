# Benchmarks

## S3 footer reads

Compare **Plank, Parquet.Net, and ParquetSharp** opening the same Parquet object and reading its
footer metadata through a local S3 emulator:

```sh
dotnet run -c Release --project Plank.Benchmarks -- --s3-footer
dotnet run -c Release --project Plank.Benchmarks -- --s3-footer --iterations 20 --latency-ms 25
```

The [benchmark website](https://kuinox.github.io/Plank-Lab/s3-footer.html) displays a measured taxi
run automatically, with 25 ms added latency per request. To inspect your own run, choose
`artifacts/benchmarks/s3-footer.json` with **Load another run**. The viewer also works from disk at
[`docs/s3-footer.html`](../docs/s3-footer.html). It shows:

- elapsed footer-read time, HTTP request count, transferred body bytes, and unique file bytes;
- one request timeline per library, aligned at the start of each independent operation;
- a file-range map with footer/trailer boundaries, full-file and footer-context views;
- linked request selection across both views and an exact inclusive byte-range table;
- first-use timings separately from the median of successful subsequent iterations.

Each result preserves every trial, request start/duration, method, Range header, status, bytes
received, metadata counts, and failures. The viewer accepts partial results and excludes failed
trials from medians. `--output PATH` selects another JSON destination; for a checked-in snapshot,
use `--output docs/benchmarks/s3-footer.json` and review it before publishing. No snapshot is
required: the viewer can load any local result JSON. `?data=relative/result.json` loads a different
served result.

### Taxi fixture

The default dataset is **NYC yellow taxi, January 2024**, from
[NYC TLC](https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2024-01.parquet).
If `Plank.Benchmarks/nyc-data/yellow_tripdata_2024-01.parquet` exists, it is used as a full file.
Otherwise preparation downloads only the trailer and footer using validated HTTP ranges,
then builds a temporary sparse object with the original header, file size and footer offsets.
Data-page bytes are zero-filled: this **metadata-only** fixture is for footer reads, not row reads.
Read-ahead into that region still transfers and counts those bytes. Preparation/download is outside
timing; the temporary fixture is removed afterwards. The footer SHA-256 and fixture mode are recorded.

Use `--data-file PATH` to serve an existing complete Parquet file instead. The benchmark never
rewrites that input. Remote fixture preparation needs internet access; measurements themselves use
only loopback HTTP. There is no Docker or cloud account requirement.

### What is measured

The emulator implements the read-only, path-style S3 **HEAD Object / GET Object** HTTP subset,
including closed, open-ended and suffix byte ranges. It binds to a dynamic loopback port. It does
not implement authentication, writes, listing, TLS or the complete S3 service. `--latency-ms` adds
the specified delay before every response, including HEAD; it does not model bandwidth or a real
cloud network.

All three readers use the same seekable, unbuffered HTTP range stream. A fresh stream lazily issues
one HEAD to discover length, then one exact GET per nonempty read. The adapter does not prefetch,
cache body bytes, retry, or tell readers the fixture length out of band. Each library keeps its
own default footer-read policy, so additional library read-ahead remains visible. This compares
the libraries' stream APIs; it does not compare native S3 SDK integrations.

Timing starts before constructing the stream and public reader, and ends after footer parsing and
extracting row, row-group and leaf-column counts. HEAD/GET requests are inside that interval.
Reader disposal, fixture preparation, client construction, validation and JSON output are outside.
Request durations are measured at the client through complete response-body consumption. The sum
of request durations is not the total footer-read time. Bytes mean response payload bytes consumed,
excluding HTTP headers, TCP overhead and HEAD's advertised object size. Repeated reads count again;
unique file bytes are the union of fully successful GET ranges.

There are zero warmups and ten iterations per library by default, in one process, with the library
order rotated each iteration. Each trial constructs a fresh reader, stream, HTTP client and
connection pool. Iteration 1 includes first-use effects; it is not a cold process launch, and later
trials may reuse JIT state, OS caches and library buffer pools. The report preserves these distinctions.
Cross-library and cross-iteration metadata counts must agree. Failures retain their traces and
make the command exit nonzero (`1` for failures, `2` for invalid options).

## Writer cursor compatibility

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

Use a focused quick run while changing the harness:

```bash
dotnet run -c Release --project Plank.Benchmarks -- \
  --published --quick --filter '*SyntheticInt32Plain*'
```

`--published-write` and `--published-read` remain aliases for running only that direct method across
the suite. Use `--rows`, `--taxi-rows`, or `--data-file` to override input. The default taxi path is
`Plank.Benchmarks/nyc-data/yellow_tripdata_2024-01.parquet`.

Synthetic cases use 1,000,000 flat rows and 22 columns and produce 22 row groups. Taxi-derived cases
use all 2,964,624 rows and produce three row groups. Inputs are not pre-split into library-specific
column buffers. Streams, capacities, reusable Plank writer/reader setup, worker startup, and pinning
stay outside the timed method. Each library otherwise uses its public API and default worker count.

Read and write have separate targeted global setups, neither of which invokes the timed method.
Before launching measurements, preparation processes build one shared read fixture per selected
schema and determine each selected writer's output capacity. These run-scoped temporary artifacts
are removed when the command finishes; there is no persistent fixture cache. The preparers cannot
warm the benchmark processes. Read cases load only the prepared bytes, not millions of source row
objects. Write cases still construct their input row objects once per process and reuse them for
all measurements. Preparation retains each required row representation only within its schema's
preparation process. Writer output sizes are validated outside timing on every iteration.

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

The publisher rejects incomplete logs, including any supported method without exactly 100 samples,
missing allocation data, or missing write output sizes. All measured allocation values, including
nonzero Plank write allocations, are preserved as report data from the separate post-series
diagnostic invocation. Publish multiple
machines with `scripts/publish_matrix.py`; it checks that each write/read pair came from the same CPU
and commit before copying it to `docs/benchmarks`.
