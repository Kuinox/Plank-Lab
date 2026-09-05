import importlib.util
from pathlib import Path
import tempfile
import unittest

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
