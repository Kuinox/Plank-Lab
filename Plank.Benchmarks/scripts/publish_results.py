#!/usr/bin/env python3
"""Convert one complete BenchmarkDotNet log into the website's read/write JSON files."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
from pathlib import Path


LIBRARIES = {
    "Plank": ("plank-single", "Plank (library default)"),
    "ParquetSharp": ("parquetsharp-single", "ParquetSharp (library default)"),
    "Parquet.Net": ("parquetnet-single", "Parquet.Net (library default)"),
}

MULTI_LIBRARIES = {
    "Plank": ("plank-multi", "Plank (column-parallel)"),
    "ParquetSharp": ("parquetsharp-multi", "ParquetSharp (column-parallel)"),
    "Parquet.Net": ("parquetnet-multi", "Parquet.Net (column-parallel)"),
}

# Match the more specific multi suffixes first. The parsed stem intentionally
# remains the single-column stem (for example SyntheticInt32PlainColumn), so
# single and multi measurements land in the same report case. Keep the legacy
# mapping available to callers that use it to build fixture class names.
CLASS_SUFFIXES = {
    "PlankBenchmarks": "Plank",
    "ParquetSharpBenchmarks": "ParquetSharp",
    "ParquetNetBenchmarks": "Parquet.Net",
}
CLASS_VARIANTS = (
    ("MultiPlankBenchmarks", "Plank", "multi"),
    ("MultiParquetSharpBenchmarks", "ParquetSharp", "multi"),
    ("MultiParquetNetBenchmarks", "Parquet.Net", "multi"),
    ("PlankBenchmarks", "Plank", "single"),
    ("ParquetSharpBenchmarks", "ParquetSharp", "single"),
    ("ParquetNetBenchmarks", "Parquet.Net", "single"),
)

ENCODING_LABELS = {
    "plain": "Plain",
    "dictionary": "Dictionary",
    "rle": "RLE",
    "delta_binary_packed": "Delta binary packed",
    "byte_stream_split": "Byte stream split",
    "delta_length_byte_array": "Delta length byte array",
    "delta_byte_array": "Delta byte array",
}


def percentile(values: list[float], fraction: float) -> float:
    values = sorted(values)
    position = (len(values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    return values[lower] * (upper - position) + values[upper] * (position - lower)


def parse_cpu_list(value: str) -> list[int]:
    result: list[int] = []
    for part in value.split(","):
        bounds = [int(item) for item in part.strip().split("-")]
        result.extend(range(bounds[0], bounds[-1] + 1))
    return result


def split_class(class_name: str) -> tuple[str, str, str]:
    for suffix, library, variant in CLASS_VARIANTS:
        if class_name.endswith(suffix):
            return class_name.removesuffix(suffix), library, variant
    raise ValueError(f"unknown benchmark class {class_name}")


def parse_log(path: Path) -> tuple[dict[tuple[str, str, str, str], dict], dict[tuple[str, str], int], str]:
    text = path.read_text()
    results: dict[tuple[str, str, str, str], dict] = {}
    output_bytes: dict[tuple[str, str], int] = {}
    thread_markers: dict[tuple[str, str], tuple[int, int]] = {}
    current: dict | None = None

    benchmark_re = re.compile(r"^// Benchmark: ([A-Za-z0-9_]+)\.(Write|Read):")
    actual_re = re.compile(r"^WorkloadActual\s+\d+:\s+\d+ op,\s+([\d.]+) ns")
    gc_re = re.compile(r"^// GC:\s+\d+\s+\d+\s+\d+\s+(\d+)\s+\d+")
    marker_re = re.compile(r"BENCHMARK_FILE\|([^|]+)\|([^|]+)\|(\d+)")
    # New markers carry configured worker count and observed managed-thread
    # count. Accept the original four-field form while old logs are still
    # useful; it records the observed count as both values.
    thread_re = re.compile(r"BENCHMARK_THREADS\|([^|]+)\|(write|read)\|(\d+)(?:\|(\d+))?")

    for line in text.splitlines():
        marker = marker_re.search(line)
        if marker:
            output_bytes[(marker.group(1), marker.group(2))] = int(marker.group(3))

        thread = thread_re.search(line)
        if thread:
            worker_count = int(thread.group(3))
            observed_threads = int(thread.group(4) or thread.group(3))
            marker_key = (thread.group(1), thread.group(2))
            previous = thread_markers.get(marker_key)
            thread_markers[marker_key] = (
                max(worker_count, previous[0]) if previous else worker_count,
                max(observed_threads, previous[1]) if previous else observed_threads,
            )

        benchmark = benchmark_re.match(line)
        if benchmark:
            class_name = benchmark.group(1)
            stem, library, variant = split_class(class_name)
            key = (stem, library, benchmark.group(2).lower(), variant)
            current = results.setdefault(key, {"samples": [], "allocated": None,
                                               "className": class_name,
                                               "threads": None,
                                               "workerCount": None})
            continue

        if current is None:
            continue
        sample = actual_re.match(line)
        if sample:
            current["samples"].append(float(sample.group(1)) / 1_000_000)
            continue
        gc = gc_re.match(line)
        if gc:
            current["allocated"] = int(gc.group(1))

    benchmark_cpus = re.search(r"^benchmark CPUs:\s+(.+)$", text, re.MULTILINE)
    if not benchmark_cpus:
        raise ValueError("benchmark CPU set is missing from the log")

    for (class_name, mode), counts in thread_markers.items():
        stem, library, variant = split_class(class_name)
        entry = results.get((stem, library, mode, variant))
        if entry is not None:
            entry["workerCount"], entry["threads"] = counts

    return results, output_bytes, benchmark_cpus.group(1).strip()


def unavailable_reason(case: dict, mode: str) -> str:
    encoding = case["encoding"]
    if mode == "write":
        return f"Parquet.Net 6.0.3 cannot request {encoding} without falling back."
    return f"Parquet.Net 6.0.3 cannot decode {encoding} for this data type."


def measurement_configuration(text: str) -> dict:
    """Read effective jobs, not command defaults (CLI overrides are supported)."""
    jobs = re.findall(r"^// Benchmark: .+$", text, re.MULTILINE)
    if not jobs:
        raise ValueError("no benchmark jobs in log")
    configurations = []
    for job in jobs:
        def setting(name: str, default: str | None = None) -> str:
            match = re.search(rf"\b{name}=([^,)]+)", job)
            if match:
                return match.group(1).strip()
            if default is not None:
                return default
            raise ValueError(f"missing {name} in benchmark job")
        configurations.append({
            "warmups": int(setting("WarmupCount")),
            "iterations": int(setting("IterationCount")),
            "launches": int(setting("LaunchCount", "1")),
            "invocationsPerIteration": int(setting("InvocationCount")),
            "runStrategy": setting("RunStrategy", "Throughput"),
            "forcedGc": setting("Force", "True") == "True",
            "evaluateOverhead": setting("EvaluateOverhead", "True") == "True",
            "outlierMode": setting("OutlierMode", "RemoveUpper"),
            "sampleOrder": "execution order; no samples removed",
        })
    if any(config != configurations[0] for config in configurations):
        raise ValueError("mixed benchmark configurations in log")
    return configurations[0]


def _parsed_entry(parsed: dict, case: dict, library: str, mode: str, variant: str) -> dict | None:
    """Find a measurement, accepting the pre-multi three-field test fixture keys."""
    exact = parsed.get((case["stem"], library, mode, variant))
    if exact is not None:
        return exact
    if variant == "single":
        return parsed.get((case["stem"], library, mode))
    return None


def measurement(case: dict, library: str, mode: str, parsed: dict, output_bytes: dict,
                expected_samples: int = 100, variant: str = "single") -> dict:
    implementations = MULTI_LIBRARIES if variant == "multi" else LIBRARIES
    implementation_id, label = implementations[library]
    supported = library != "Parquet.Net" or case[f"parquetNet{mode.title()}"]
    if variant == "multi" and (library == "Parquet.Net" or
                                (library == "ParquetSharp" and mode == "write")):
        supported = False
    base = {
        "implementationId": implementation_id,
        "label": label,
        "variant": variant,
        "threads": 1 if variant == "single" else None,
        "workerCount": 1 if variant == "single" else None,
        "observedThreads": 1 if variant == "single" else None,
        "available": supported,
    }
    if not supported:
        base["unavailableReason"] = (
            "No independent ParquetSharp column writer is available."
            if variant == "multi" and library == "ParquetSharp" and mode == "write"
            else "Parquet.Net multi-threaded column adapters are intentionally unavailable."
            if variant == "multi"
            else unavailable_reason(case, mode))
        base["samplesMilliseconds"] = []
        return base

    entry = _parsed_entry(parsed, case, library, mode, variant)
    key = (case["stem"], library, mode, variant)
    if entry is None or not entry["samples"]:
        raise ValueError(f"missing measurements for {key}")
    values = entry["samples"]
    if len(values) != expected_samples:
        raise ValueError(f"expected {expected_samples} samples for {key}, found {len(values)}")
    if variant == "multi":
        if entry.get("threads") is None or entry.get("workerCount") is None:
            raise ValueError(f"missing thread marker for {key}")
        base["threads"] = entry["threads"]
        base["workerCount"] = entry["workerCount"]
        base["observedThreads"] = entry["threads"]
    median = percentile(values, 0.5)
    p25 = percentile(values, 0.25)
    p75 = percentile(values, 0.75)
    rounded = [round(value, 4) for value in values]
    base.update({
        "medianMilliseconds": round(median, 3),
        "p25Milliseconds": round(p25, 3),
        "p75Milliseconds": round(p75, 3),
        "samplesMilliseconds": rounded,
        "firstIterationMilliseconds": rounded[0],
        "subsequentMedianMilliseconds": round(percentile(values[1:] or values, 0.5), 3),
        "allocatedBytes": entry["allocated"],
        "allocationMeasurement": "separate diagnostic invocation after the timed series; not first-use allocations",
        "variationPercent": (p75 - p25) / median * 100,
        "throughput": case["valueCount"] / (median / 1000) / 1_000_000,
    })
    if mode == "write":
        base["outputBytes"] = output_bytes.get((case["stem"], library))
    if base["allocatedBytes"] is None:
        raise ValueError(f"missing allocation result for {key}")
    if mode == "write" and base["outputBytes"] is None:
        raise ValueError(f"missing output size for {key}")
    return base


def method_source(path: Path, class_name: str, method: str) -> str:
    source = path.read_text()
    class_at = source.index(f"public class {class_name}")
    benchmark_at = source.index("    [Benchmark]", class_at)
    while True:
        next_at = source.find("    [Benchmark]", benchmark_at + 1)
        block_end = source.find("\n    [", benchmark_at + 1)
        candidate_end = min(item for item in (next_at, block_end) if item >= 0)
        candidate = source[benchmark_at:candidate_end].strip()
        if re.search(rf"\b{method}\s*\(", candidate):
            return candidate.replace("    ", "", 1)
        benchmark_at = next_at
        if benchmark_at < 0:
            raise ValueError(f"method {class_name}.{method} not found")


def benchmark_code(generated: Path, mode: str, workload: str = "row") -> list[dict]:
    stem = "SyntheticInt32Plain" + ("Column" if workload == "column" else "")
    snippets = []
    classes = [
        (f"{stem}PlankBenchmarks", "Plank", "single"),
        (f"{stem}ParquetSharpBenchmarks", "ParquetSharp", "single"),
        (f"{stem}ParquetNetBenchmarks", "Parquet.Net", "single"),
    ]
    if workload == "column":
        classes.append((f"{stem}MultiPlankBenchmarks", "Plank", "multi"))
        if mode == "read":
            classes.append((f"{stem}MultiParquetSharpBenchmarks", "ParquetSharp", "multi"))
    for class_name, library, variant in classes:
        source_name = f"{stem}{'Multi' if variant == 'multi' else ''}.cs"
        source = generated / source_name
        snippets.append({
            "label": f"{library} · {mode.title()}" + (" · Multi" if variant == "multi" else ""),
            "workload": workload,
            "variant": variant,
            "source": method_source(source, class_name, mode.title()),
        })
    return snippets


def create_report(args: argparse.Namespace, mode: str, matrix: list[dict], parsed: dict,
                  output_bytes: dict, benchmark_cpus: str) -> dict:
    configuration = measurement_configuration(args.log.read_text())
    workloads = [workload for workload in ("row", "column")
                 if any(key[2] == mode and key[0].endswith("Column") == (workload == "column")
                        for key in parsed)]
    if not workloads:
        raise ValueError(f"No {mode} results in log")
    matrix = [{**case, "workload": workload,
               "stem": case["stem"] + ("Column" if workload == "column" else "")}
              for case in matrix for workload in workloads]
    suites = []
    for suite_id, suite_label in (("real-world", "Real-world data"), ("synthetic", "Synthetic")):
        cases = []
        for item in (case for case in matrix if case["suite"] == suite_id):
            label = item["label"]
            if suite_id == "synthetic":
                label = f"{item['dataTypes'][0]} · {ENCODING_LABELS[item['encoding']]}"
            measurements = [measurement(item, library, mode, parsed, output_bytes,
                                        configuration["iterations"])
                            for library in LIBRARIES]
            if item["workload"] == "column":
                measurements.extend(
                    measurement(item, library, mode, parsed, output_bytes,
                                configuration["iterations"], variant="multi")
                    for library in MULTI_LIBRARIES)
            available = [value for value in measurements if value["available"]]
            winner = min(available, key=lambda value: value["medianMilliseconds"])
            plank = next(value for value in available if value["implementationId"] == "plank-single")
            competitors = [
                value for value in available if value["implementationId"] != "plank-single"
            ]
            cases.append({
                "id": item["id"],
                "workload": item["workload"],
                "label": label,
                "encoding": item["encoding"],
                "dataTypes": item["dataTypes"],
                "rowCount": item["rowCount"],
                "valueCount": item["valueCount"],
                "columnCount": item["columnCount"],
                "rowGroupCount": item["expectedRowGroupCount"],
                "throughputUnit": "million values/s",
                "winnerId": winner["implementationId"],
                "plankSpeedup": min(value["medianMilliseconds"] for value in competitors)
                                / plank["medianMilliseconds"],
                "measurements": measurements,
            })
        suites.append({"id": suite_id, "label": suite_label, "cases": cases})

    housekeeping = re.search(r"^housekeeping CPUs:\s+(.+)$", args.log.read_text(), re.MULTILINE)
    isolation = (f"The run reserved CPUs {housekeeping.group(1).strip()} for housekeeping and confined the "
                 f"benchmark to CPUs {benchmark_cpus}. Movable threads and IRQs were moved away, Plank workers "
                 "were pinned to benchmark CPUs, and the machine settled for five seconds before launch.")
    return {
        "schemaVersion": 1,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "environment": {
            "cpu": args.cpu,
            "logicalProcessors": len(parse_cpu_list(benchmark_cpus)),
            "operatingSystem": args.operating_system,
            "dotNetVersion": ".NET 10.0.10",
            "commit": args.commit,
            "libraries": {
                "Plank": "local source",
                "ParquetSharp": "24.0.0",
                "Parquet.Net": "6.0.3",
                "BenchmarkDotNet": "0.15.8",
            },
        },
        "configuration": {
            **measurement_configuration(args.log.read_text()),
            "compression": "none",
            "dataPageVersion": "V2 for Plank and ParquetSharp; V1 for Parquet.Net",
            "statistics": "Full min/max/null-count statistics exposed by each library; column-chunk and page statistics for Plank and ParquetSharp, column-chunk statistics for Parquet.Net",
            "pageIndexes": "Plank and ParquetSharp only",
            "bloomFilters": False,
            "format": "No compression or Bloom filters; full statistics; requested encoding per case. Plank and ParquetSharp use Data Page V2 with page indexes. Parquet.Net uses Data Page V1 without page indexes.",
            "data": "Synthetic cases use 1,000,000 deterministic flat row objects with 22 columns. Real-world cases use all 2,964,624 rows and the selected columns from the January 2024 NYC yellow-taxi file. Row workloads use row objects. Column workloads transpose the same values into typed column arrays during untimed setup.",
            "quick": False,
            "rowGroupBoundaries": "Row workloads receive flat rows; column workloads receive column batches with matching row counts per row group. Synthetic cases produce 22 row groups; taxi-derived cases produce 3. No worker count is selected, so each library uses its default.",
            "timingBoundary": "Only the library write/read operation is timed, not process startup. Each case runs its measured iterations in one process. With ColdStart and zero warmups, the first operation is not pre-invoked by setup or JIT calibration; later samples show its evolution. Read fixtures and write output capacities are prepared in separate processes once per run. Data, schemas, options, capacities, streams, reusable writer/reader setup, worker startup, and worker pinning remain outside timing where the public API permits it. ColumnMulti cases parallelize independent column work and record configured workerCount plus observedThreads in each measurement. " + isolation,
        },
        "suites": suites,
        "benchmarkCode": [snippet for workload in workloads for snippet in benchmark_code(args.generated, mode, workload)],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--generated", required=True, type=Path)
    parser.add_argument("--cpu", required=True)
    parser.add_argument("--operating-system", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--write-output", type=Path)
    parser.add_argument("--read-output", type=Path)
    args = parser.parse_args()

    if args.write_output is None and args.read_output is None:
        parser.error("Provide --write-output or --read-output.")
    matrix = json.loads(args.matrix.read_text())
    parsed, output_bytes, benchmark_cpus = parse_log(args.log)
    for mode, output in (("write", args.write_output), ("read", args.read_output)):
        if output is None:
            continue
        report = create_report(args, mode, matrix, parsed, output_bytes, benchmark_cpus)
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"wrote {output} ({sum(len(suite['cases']) for suite in report['suites'])} cases)")


if __name__ == "__main__":
    main()
