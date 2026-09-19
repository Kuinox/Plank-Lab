import importlib.util
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("publish_results", Path(__file__).parents[1] / "publish_results.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PublisherTests(unittest.TestCase):
    def test_effective_configuration(self):
        log = "// Benchmark: SyntheticInt32PlainPlankBenchmarks.Write: Job-X(Force=False, EvaluateOverhead=False, OutlierMode=DontRemove, RunStrategy=ColdStart, LaunchCount=1, WarmupCount=0, IterationCount=100, InvocationCount=1)"
        config = publisher.measurement_configuration(log)
        self.assertEqual(config["warmups"], 0)
        self.assertEqual(config["iterations"], 100)
        self.assertEqual(config["launches"], 1)
        self.assertEqual(config["runStrategy"], "ColdStart")
        self.assertFalse(config["forcedGc"])
        self.assertFalse(config["evaluateOverhead"])
        with self.assertRaisesRegex(ValueError, "mixed"):
            publisher.measurement_configuration(log + "\n" + log.replace("WarmupCount=0", "WarmupCount=8"))

    def test_samples_preserve_first_use_and_execution_order(self):
        lines = ["benchmark CPUs: 1-3", "// Benchmark: SyntheticInt32PlainPlankBenchmarks.Write: Job-X", "BENCHMARK_FILE|SyntheticInt32Plain|Plank|42"]
        samples = [500.0] + [float(x) for x in range(99, 0, -1)]
        lines += [f"WorkloadActual {i}: 1 op, {value * 1_000_000:.1f} ns" for i, value in enumerate(samples, 1)]
        lines += ["// GC: 0 0 0 0 1"]
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "run.log"
            log.write_text("\n".join(lines))
            parsed, sizes, cpus = publisher.parse_log(log)
        case = {"stem": "SyntheticInt32Plain", "id": "test", "valueCount": 128}
        result = publisher.measurement(case, "Plank", "write", parsed, sizes)
        self.assertEqual(result["samplesMilliseconds"], samples)
        self.assertEqual(result["firstIterationMilliseconds"], 500)
        self.assertEqual(result["subsequentMedianMilliseconds"], 50)
        self.assertEqual(result["outputBytes"], 42)

    def test_column_and_row_measurements_remain_distinct_with_ten_samples(self):
        lines = ["benchmark CPUs: 1-3"]
        for stem, time in (("SyntheticInt32Plain", 1), ("SyntheticInt32PlainColumn", 2)):
            lines += [f"// Benchmark: {stem}PlankBenchmarks.Write: Job-X",
                      f"BENCHMARK_FILE|{stem}|Plank|42"]
            lines += [f"WorkloadActual {i}: 1 op, {time * 1000000} ns" for i in range(10)]
            lines += ["// GC: 0 0 0 0 1"]
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "run.log"
            log.write_text("\n".join(lines))
            parsed, sizes, _ = publisher.parse_log(log)
        self.assertEqual(len(parsed), 2)
        for stem, time in (("SyntheticInt32Plain", 1), ("SyntheticInt32PlainColumn", 2)):
            case = {"stem": stem, "id": "int32-plain", "valueCount": 128}
            result = publisher.measurement(case, "Plank", "write", parsed, sizes, expected_samples=10)
            self.assertEqual(result["samplesMilliseconds"], [time] * 10)
            with self.assertRaisesRegex(ValueError, "expected 100"):
                publisher.measurement(case, "Plank", "write", parsed, sizes)

    def test_multi_marker_preserves_worker_and_observed_thread_identity(self):
        stem = "SyntheticInt32PlainColumn"
        class_name = f"{stem}MultiPlankBenchmarks"
        lines = ["benchmark CPUs: 1-22",
                 f"// Benchmark: {class_name}.Write: Job-X",
                 f"BENCHMARK_FILE|{stem}|Plank|42"]
        lines += [f"WorkloadActual {i}: 1 op, 2000000 ns" for i in range(10)]
        lines += ["// GC: 0 0 0 288 1",
                  f"BENCHMARK_THREADS|{class_name}|write|22|17"]
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "run.log"
            log.write_text("\n".join(lines))
            parsed, sizes, _ = publisher.parse_log(log)
        case = {"stem": stem, "id": "int32-plain", "valueCount": 128,
                "parquetNetWrite": True, "parquetNetRead": True}
        result = publisher.measurement(case, "Plank", "write", parsed, sizes,
                                       expected_samples=10, variant="multi")
        self.assertEqual(result["implementationId"], "plank-multi")
        self.assertEqual(result["variant"], "multi")
        self.assertEqual(result["workerCount"], 22)
        self.assertEqual(result["observedThreads"], 17)
        self.assertEqual(result["threads"], 17)
        unavailable = publisher.measurement(case, "ParquetSharp", "write", parsed, sizes,
                                            expected_samples=10, variant="multi")
        self.assertFalse(unavailable["available"])
        self.assertIn("writer", unavailable["unavailableReason"])

    def test_column_report_groups_single_and_multi_measurements_by_case(self):
        stem = "SyntheticInt32PlainColumn"
        classes = [
            (f"{stem}PlankBenchmarks", "Plank"),
            (f"{stem}ParquetSharpBenchmarks", "ParquetSharp"),
            (f"{stem}ParquetNetBenchmarks", "Parquet.Net"),
            (f"{stem}MultiPlankBenchmarks", "Plank"),
            (f"{stem}MultiParquetSharpBenchmarks", "ParquetSharp"),
        ]
        lines = ["benchmark CPUs: 1-22", "housekeeping CPUs: 0"]
        for class_name, library in classes:
            lines += [
                f"// Benchmark: {class_name}.Read: Job-X(WarmupCount=0, IterationCount=2, LaunchCount=1, InvocationCount=1)",
                "WorkloadActual 1: 1 op, 1000000 ns",
                "WorkloadActual 2: 1 op, 1000000 ns",
                "// GC: 0 0 0 288 1",
            ]
            if "Multi" in class_name:
                lines.append(f"BENCHMARK_THREADS|{class_name}|read|22|17")
        matrix = [{"suite": "synthetic", "id": "int32-plain", "stem": "SyntheticInt32Plain",
                   "label": "int32 · plain", "encoding": "plain", "dataTypes": ["int32"],
                   "rowCount": 128, "valueCount": 2816, "columnCount": 22,
                   "expectedRowGroupCount": 1, "parquetNetWrite": True, "parquetNetRead": True}]
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            log = directory / "run.log"
            log.write_text("\n".join(lines))
            parsed, sizes, cpus = publisher.parse_log(log)
            args = SimpleNamespace(log=log,
                                   generated=Path(__file__).parents[2] / "Published" / "Cases",
                                   cpu="test", operating_system="test", commit="test")
            report = publisher.create_report(args, "read", matrix, parsed, sizes, cpus)
        item = report["suites"][1]["cases"][0]
        self.assertEqual(item["workload"], "column")
        self.assertEqual([measurement["implementationId"] for measurement in item["measurements"]],
                         ["plank-single", "parquetsharp-single", "parquetnet-single",
                          "plank-multi", "parquetsharp-multi", "parquetnet-multi"])
        self.assertEqual(item["measurements"][3]["threads"], 17)
        self.assertEqual(item["measurements"][3]["workerCount"], 22)
        self.assertFalse(item["measurements"][5]["available"])
        self.assertEqual([snippet["variant"] for snippet in report["benchmarkCode"]],
                         ["single", "single", "single", "multi", "multi"])

    def test_incomplete_series_rejected(self):
        case = {"stem": "SyntheticInt32Plain", "id": "test", "valueCount": 128}
        key = (case["stem"], "Plank", "write")
        for count in (1, 99, 101):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "expected 100"):
                publisher.measurement(case, "Plank", "write", {key: {"samples": [1] * count}}, {})

    def test_measured_allocations_preserved(self):
        case = {"stem": "TaxiDictionary", "id": "taxi-dictionary", "valueCount": 128,
                "parquetNetWrite": True, "parquetNetRead": True}
        for library in publisher.LIBRARIES:
            suffix = next(suffix for suffix, name in publisher.CLASS_SUFFIXES.items() if name == library)
            for mode in ("write", "read"):
                for allocated in (0, 288, 123456789):
                    with self.subTest(library=library, mode=mode, allocated=allocated):
                        lines = ["benchmark CPUs: 1-3",
                                 f"// Benchmark: TaxiDictionary{suffix}.{mode.title()}: Job-X",
                                 f"BENCHMARK_FILE|TaxiDictionary|{library}|42"]
                        lines += [f"WorkloadActual {i}: 1 op, 1000000 ns" for i in range(1, 101)]
                        lines += [f"// GC: 0 0 0 {allocated} 1"]
                        with tempfile.TemporaryDirectory() as directory:
                            log = Path(directory) / "run.log"
                            log.write_text("\n".join(lines))
                            parsed, sizes, _ = publisher.parse_log(log)
                        result = publisher.measurement(case, library, mode, parsed, sizes)
                        self.assertEqual(result["allocatedBytes"], allocated)
                        self.assertEqual(result["allocationMeasurement"],
                                         "separate diagnostic invocation after the timed series; not first-use allocations")

    def test_missing_measurements_rejected(self):
        case = {"stem": "TaxiDictionary", "id": "taxi-dictionary", "valueCount": 128}
        key = (case["stem"], "Plank", "write")
        for parsed in ({}, {key: {"samples": [], "allocated": 288}}):
            with self.subTest(parsed=parsed), self.assertRaisesRegex(ValueError, "missing measurements"):
                publisher.measurement(case, "Plank", "write", parsed, {})

    def test_missing_allocations_rejected(self):
        case = {"stem": "TaxiDictionary", "id": "taxi-dictionary", "valueCount": 128}
        for mode in ("write", "read"):
            key = (case["stem"], "Plank", mode)
            parsed = {key: {"samples": [1] * 100, "allocated": None}}
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "missing allocation result"):
                publisher.measurement(case, "Plank", mode, parsed, {(case["stem"], "Plank"): 42})

    def test_missing_write_output_size_rejected(self):
        case = {"stem": "TaxiDictionary", "id": "taxi-dictionary", "valueCount": 128}
        key = (case["stem"], "Plank", "write")
        parsed = {key: {"samples": [1] * 100, "allocated": 288}}
        with self.assertRaisesRegex(ValueError, "missing output size"):
            publisher.measurement(case, "Plank", "write", parsed, {})


if __name__ == "__main__":
    unittest.main()
