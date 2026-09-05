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
        with self.assertRaisesRegex(ValueError, "expected 100"):
            publisher.measurement(case, "Plank", "write", {key: {"samples": [1]}}, {})


if __name__ == "__main__":
    unittest.main()
