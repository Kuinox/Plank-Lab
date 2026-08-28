from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "run_cpu_isolated.py"
SPEC = importlib.util.spec_from_file_location("run_cpu_isolated", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class CpuLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.sys_cpu = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_cpu(self, cpu: int, *, siblings: str | None = None,
                  capacity: int | None = None, maximum_frequency: int | None = None) -> None:
        cpu_path = self.sys_cpu / f"cpu{cpu}"
        if siblings is not None:
            topology = cpu_path / "topology"
            topology.mkdir(parents=True, exist_ok=True)
            (topology / "thread_siblings_list").write_text(siblings, encoding="ascii")
        if capacity is not None:
            cpu_path.mkdir(parents=True, exist_ok=True)
            (cpu_path / "cpu_capacity").write_text(str(capacity), encoding="ascii")
        if maximum_frequency is not None:
            cpufreq = cpu_path / "cpufreq"
            cpufreq.mkdir(parents=True, exist_ok=True)
            (cpufreq / "cpuinfo_max_freq").write_text(str(maximum_frequency), encoding="ascii")

    def test_m2_capacity_keeps_efficiency_cpus_out_of_benchmark_set(self) -> None:
        allowed = set(range(10))
        for cpu in allowed:
            self.write_cpu(cpu, siblings=str(cpu), capacity=756 if cpu < 4 else 1024)

        actual_allowed, housekeeping, benchmark, source = RUNNER.choose_layout(
            None, allowed, self.sys_cpu)

        self.assertEqual(actual_allowed, allowed)
        self.assertEqual(housekeeping, {0, 1, 2, 3})
        self.assertEqual(benchmark, {4, 5, 6, 7, 8, 9})
        self.assertEqual(source, "cpu_capacity")

    def test_maximum_frequency_is_used_when_capacity_is_unavailable(self) -> None:
        allowed = set(range(6))
        for cpu in allowed:
            self.write_cpu(cpu, siblings=str(cpu),
                           maximum_frequency=2_400_000 if cpu < 2 else 3_600_000)

        _, housekeeping, benchmark, source = RUNNER.choose_layout(None, allowed, self.sys_cpu)

        self.assertEqual(housekeeping, {0, 1})
        self.assertEqual(benchmark, {2, 3, 4, 5})
        self.assertEqual(source, "cpuinfo_max_freq")

    def test_homogeneous_smt_keeps_existing_physical_core_layout(self) -> None:
        allowed = set(range(8))
        for cpu in allowed:
            core = cpu % 4
            self.write_cpu(cpu, siblings=f"{core},{core + 4}", capacity=1024)

        _, housekeeping, benchmark, source = RUNNER.choose_layout(None, allowed, self.sys_cpu)

        self.assertEqual(housekeeping, {0, 4})
        self.assertEqual(benchmark, {1, 2, 3, 5, 6, 7})
        self.assertIsNone(source)

    def test_small_maximum_frequency_difference_is_not_a_hybrid_split(self) -> None:
        allowed = {0, 1, 2, 3}
        frequencies = {0: 4_500_000, 1: 4_600_000, 2: 4_500_000, 3: 4_600_000}
        for cpu in allowed:
            self.write_cpu(cpu, siblings=str(cpu), maximum_frequency=frequencies[cpu])

        _, housekeeping, benchmark, source = RUNNER.choose_layout(None, allowed, self.sys_cpu)

        self.assertEqual(housekeeping, {0})
        self.assertEqual(benchmark, {1, 2, 3})
        self.assertIsNone(source)

    def test_explicit_performance_cpu_reserves_its_whole_smt_core(self) -> None:
        allowed = set(range(8))
        siblings = {0: "0", 1: "1", 2: "2", 3: "3", 4: "4,6", 5: "5,7", 6: "4,6", 7: "5,7"}
        for cpu in allowed:
            self.write_cpu(cpu, siblings=siblings[cpu], capacity=700 if cpu < 4 else 1024)

        _, housekeeping, benchmark, source = RUNNER.choose_layout(4, allowed, self.sys_cpu)

        self.assertEqual(housekeeping, {0, 1, 2, 3, 4, 6})
        self.assertEqual(benchmark, {5, 7})
        self.assertEqual(source, "cpu_capacity")

    def test_incomplete_capacity_data_falls_back_to_complete_frequency_data(self) -> None:
        allowed = {0, 1, 2, 3}
        for cpu in allowed:
            self.write_cpu(cpu, siblings=str(cpu),
                           capacity=700 if cpu == 0 else None,
                           maximum_frequency=2_000_000 if cpu < 2 else 3_000_000)

        _, housekeeping, benchmark, source = RUNNER.choose_layout(None, allowed, self.sys_cpu)

        self.assertEqual(housekeeping, {0, 1})
        self.assertEqual(benchmark, {2, 3})
        self.assertEqual(source, "cpuinfo_max_freq")

    def test_explicit_cpu_must_be_allowed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "outside this process's allowed set"):
            RUNNER.choose_layout(7, {0, 1}, self.sys_cpu)


if __name__ == "__main__":
    unittest.main()
