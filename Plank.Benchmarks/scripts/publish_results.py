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

CLASS_SUFFIXES = {
    "PlankBenchmarks": "Plank",
    "ParquetSharpBenchmarks": "ParquetSharp",
    "ParquetNetBenchmarks": "Parquet.Net",
}

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


def split_class(class_name: str) -> tuple[str, str]:
    for suffix, library in CLASS_SUFFIXES.items():
        if class_name.endswith(suffix):
            return class_name.removesuffix(suffix), library
    raise ValueError(f"unknown benchmark class {class_name}")


def parse_log(path: Path) -> tuple[dict[tuple[str, str, str], dict], dict[tuple[str, str], int], str]:
    text = path.read_text()
    results: dict[tuple[str, str, str], dict] = {}
    output_bytes: dict[tuple[str, str], int] = {}
    current: dict | None = None

    benchmark_re = re.compile(r"^// Benchmark: ([A-Za-z0-9_]+)\.(Write|Read):")
    actual_re = re.compile(r"^WorkloadActual\s+\d+:\s+\d+ op,\s+([\d.]+) ns")
    gc_re = re.compile(r"^// GC:\s+\d+\s+\d+\s+\d+\s+(\d+)\s+\d+")
    marker_re = re.compile(r"BENCHMARK_FILE\|([^|]+)\|([^|]+)\|(\d+)")

    for line in text.splitlines():
        marker = marker_re.search(line)
        if marker:
            output_bytes[(marker.group(1), marker.group(2))] = int(marker.group(3))

        benchmark = benchmark_re.match(line)
        if benchmark:
            stem, library = split_class(benchmark.group(1))
            key = (stem, library, benchmark.group(2).lower())
            current = results.setdefault(key, {"samples": [], "allocated": None})
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
    return results, output_bytes, benchmark_cpus.group(1).strip()


def unavailable_reason(case: dict, mode: str) -> str:
    encoding = case["encoding"]
    if mode == "write":
        return f"Parquet.Net 6.0.3 cannot request {encoding} without falling back."
    return f"Parquet.Net 6.0.3 cannot decode {encoding} for this data type."


def measurement(case: dict, library: str, mode: str, parsed: dict, output_bytes: dict) -> dict:
    implementation_id, label = LIBRARIES[library]
    supported = library != "Parquet.Net" or case[f"parquetNet{mode.title()}"]
    base = {
        "implementationId": implementation_id,
        "label": label,
        "threads": None,
        "available": supported,
    }
    if not supported:
        base["unavailableReason"] = unavailable_reason(case, mode)
        base["samplesMilliseconds"] = []
        return base

    key = (case["stem"], library, mode)
    if key not in parsed or not parsed[key]["samples"]:
        raise ValueError(f"missing measurements for {key}")
    values = parsed[key]["samples"]
    if len(values) != 100:
        raise ValueError(f"expected 100 samples for {key}, found {len(values)}")
    median = percentile(values, 0.5)
    p25 = percentile(values, 0.25)
    p75 = percentile(values, 0.75)
    rounded = [round(value, 4) for value in values]
    base.update({
        "medianMilliseconds": round(median, 3),
        "p25Milliseconds": round(p25, 3),
        "p75Milliseconds": round(p75, 3),
        "samplesMilliseconds": rounded,
        "allocatedBytes": parsed[key]["allocated"],
        "variationPercent": (p75 - p25) / median * 100,
        "throughput": case["valueCount"] / (median / 1000) / 1_000_000,
    })
    if mode == "write":
        base["outputBytes"] = output_bytes.get((case["stem"], library))
    if base["allocatedBytes"] is None:
        raise ValueError(f"missing allocation result for {key}")
    if mode == "write" and base["outputBytes"] is None:
        raise ValueError(f"missing output size for {key}")
    if library == "Plank" and mode == "write" and base["allocatedBytes"] != 0:
        raise ValueError(f"Plank allocated {base['allocatedBytes']} bytes for {case['id']}")
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


def benchmark_code(generated: Path, mode: str) -> list[dict]:
    source = generated / "SyntheticInt32Plain.cs"
    return [
        {
            "label": f"{library} · {mode.title()}",
            "source": method_source(source, f"SyntheticInt32Plain{suffix}", mode.title()),
        }
        for suffix, library in (
            ("PlankBenchmarks", "Plank"),
            ("ParquetSharpBenchmarks", "ParquetSharp"),
            ("ParquetNetBenchmarks", "Parquet.Net"),
        )
    ]


def create_report(args: argparse.Namespace, mode: str, matrix: list[dict], parsed: dict,
                  output_bytes: dict, benchmark_cpus: str) -> dict:
    suites = []
    for suite_id, suite_label in (("real-world", "Real-world data"), ("synthetic", "Synthetic")):
        cases = []
        for item in (case for case in matrix if case["suite"] == suite_id):
            label = item["label"]
            if suite_id == "synthetic":
                label = f"{item['dataTypes'][0]} · {ENCODING_LABELS[item['encoding']]}"
            measurements = [
                measurement(item, library, mode, parsed, output_bytes)
                for library in LIBRARIES
            ]
            available = [value for value in measurements if value["available"]]
            winner = min(available, key=lambda value: value["medianMilliseconds"])
            plank = next(value for value in available if value["implementationId"] == "plank-single")
            competitors = [
                value for value in available if value["implementationId"] != "plank-single"
            ]
            cases.append({
                "id": item["id"],
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
            "warmups": 80,
            "iterations": 100,
            "compression": "none",
            "dataPageVersion": "V2 for Plank and ParquetSharp; V1 for Parquet.Net",
            "statistics": "Full min/max/null-count statistics exposed by each library; column-chunk and page statistics for Plank and ParquetSharp, column-chunk statistics for Parquet.Net",
            "pageIndexes": "Plank and ParquetSharp only",
            "bloomFilters": False,
            "format": "No compression or Bloom filters; full statistics; requested encoding per case. Plank and ParquetSharp use Data Page V2 with page indexes. Parquet.Net uses Data Page V1 without page indexes.",
            "data": "Synthetic cases use 1,000,000 deterministic flat row objects with 22 columns. Real-world cases use all 2,964,624 rows and the selected columns from the January 2024 NYC yellow-taxi file. Input is never pre-split into columns or row groups.",
            "quick": False,
            "rowGroupBoundaries": "Every writer receives flat rows. Synthetic cases produce 22 row groups; taxi-derived cases produce 3. No worker count is selected, so each library uses its default.",
            "timingBoundary": "Only the library write/read operation is timed. Data, schemas, options, capacities, streams, and reusable reader setup are outside timing. Plank's generated writer is stack-bound, so its writer construction, worker startup, and worker pinning are included in the write measurement. " + isolation,
        },
        "suites": suites,
        "benchmarkCode": benchmark_code(args.generated, mode),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--generated", required=True, type=Path)
    parser.add_argument("--cpu", required=True)
    parser.add_argument("--operating-system", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--write-output", required=True, type=Path)
    parser.add_argument("--read-output", required=True, type=Path)
    args = parser.parse_args()

    matrix = json.loads(args.matrix.read_text())
    parsed, output_bytes, benchmark_cpus = parse_log(args.log)
    for mode, output in (("write", args.write_output), ("read", args.read_output)):
        report = create_report(args, mode, matrix, parsed, output_bytes, benchmark_cpus)
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"wrote {output} ({sum(len(suite['cases']) for suite in report['suites'])} cases)")


if __name__ == "__main__":
    main()
