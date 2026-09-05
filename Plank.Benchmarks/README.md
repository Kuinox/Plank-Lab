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

## Published direct benchmarks

The homepage results come from the BenchmarkDotNet cases in `Published/Cases`. Every data type and
encoding has a separate source file, and every library has its own direct `Write` and `Read` benchmark
methods. The timed paths do not pass through the old generic adapters, per-cell type switches, or a
shared row helper.

The full run uses 80 warmups and 100 measured iterations:

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
missing allocation data, or a Plank write that allocates inside the timed method. Publish multiple
machines with `scripts/publish_matrix.py`; it checks that each write/read pair came from the same CPU
and commit before copying it to `docs/benchmarks`.
