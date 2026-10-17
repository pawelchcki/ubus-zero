"""Measurement oracles: concurrent wall time, exact samples and safe report rendering."""

import csv
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("benchmark", Path(__file__).resolve().parents[1] / "tools/ubus-benchmark.py")
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class BenchmarkTests(unittest.TestCase):
    def sample(self):
        return {"schema_version": 1, "broker": "rust", "workload": "echo", "clients": 4,
                "payload_bytes": 4096, "iterations": 2, "warmup": 1, "operations": 8,
                "elapsed_ns": 1_000_000_000, "latency_ns": [500_000_000] * 8,
                "broker_cpu_ns": 800_000, "broker_rss_bytes": 1024, "broker_lifetime_peak_rss_bytes": 2048}

    def test_concurrent_throughput_uses_wall_time_instead_of_summed_latencies(self):
        sample = self.sample()
        benchmark.validate(sample, "rust", ("echo", 4, 4096), 2, 1)
        stats = benchmark.summarize([sample])
        self.assertEqual(stats["operations_per_second"], 8)
        self.assertEqual(stats["p99_us"], 500_000)

    def test_repeated_throughput_uses_median_and_percentiles_retain_tail(self):
        sample = self.sample()
        samples = [sample, {**sample, "elapsed_ns": 2_000_000_000},
                   {**sample, "elapsed_ns": 4_000_000_000}]
        self.assertEqual(benchmark.summarize(samples)["operations_per_second"], 4)
        self.assertEqual(benchmark.percentile(list(range(1, 101)), 99), 99)
        self.assertEqual(benchmark.percentile([1, 2, 100], 99), 100)

    def test_missing_wrong_arm_or_impossible_samples_are_rejected(self):
        for change in ({"broker": "upstream"}, {"clients": True}, {"operations": 7},
                       {"latency_ns": [1]}, {"latency_ns": [0] * 8},
                       {"elapsed_ns": 0}, {"elapsed_ns": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                benchmark.validate({**self.sample(), **change}, "rust", ("echo", 4, 4096), 2, 1)

    def test_reports_include_provenance_and_escape_metadata(self):
        stats = benchmark.summarize([self.sample()])
        result = {"metadata": {"commit": "<script>unsafe</script>"},
                  "configuration": {"samples": 1, "iterations": 2},
                  "comparisons": [{"workload": "echo", "clients": 4, "payload_bytes": 4096,
                                   "iterations_per_client": 2,
                                   "rust": stats, "upstream": stats}]}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            benchmark.write_reports(output, result)
            report = (output / "report.html").read_text()
            self.assertNotIn("<script>", report)
            self.assertIn("&lt;script&gt;", report)
            self.assertIn("not a timing gate", report)
            self.assertEqual(json.loads((output / "performance.json").read_text()), result)
            self.assertEqual(len((output / "summary.csv").read_text().splitlines()), 3)

    def test_report_columns_and_per_workload_counts_agree(self):
        class Tables(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tables = []

            def handle_starttag(self, tag, attrs):
                if tag == "table":
                    self.tables.append([])
                elif tag == "tr":
                    self.tables[-1].append(0)
                elif tag in {"th", "td"}:
                    self.tables[-1][-1] += 1

        stats = benchmark.summarize([self.sample()])
        result = {"metadata": {"commit": "current", "binaries": {"rust": {"bytes": 1024}}},
                  "configuration": {"samples": 1, "iterations": 5000},
                  "comparisons": [{"workload": name, "clients": 1, "payload_bytes": 0,
                                   "iterations_per_client": count, "rust": stats, "upstream": stats}
                                  for name, count in [("ping", 5000), ("ping-pipeline", 200000),
                                                      ("lookup-many", 200)]]}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            benchmark.write_reports(output, result)
            report = (output / "report.html").read_text()
            tables = Tables()
            tables.feed(report)
            self.assertEqual(tables.tables, [[10] * 7, [2, 2]])
            for label in ("Iterations/client", "Broker CPU µs/op", "RSS KiB", "vs C (95% interval)"):
                self.assertIn(f"<th>{label}</th>", report)
            for count in ("5,000", "200,000", "200"):
                self.assertIn(f"<td>{count}</td>", report)
                self.assertIn(f"| {count} |", (output / "report.md").read_text())
            with (output / "summary.csv").open() as handle:
                self.assertEqual([int(row["iterations_per_client"]) for row in csv.DictReader(handle)],
                                 [5000, 5000, 200000, 200000, 200, 200])

    def test_profile_matrix_changes_only_the_broker_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "ubusd"
            executable.write_bytes(b"broker")
            observed = []

            def cargo(args, environment, capture_stdout):
                config = next(value for value in args if value.startswith("profile.release.package.ubusd.opt-level="))
                level = str(json.loads(config.split("=", 1)[1]))
                core_level = environment["CARGO_PROFILE_RELEASE_OPT_LEVEL"]
                observed.append((level, core_level))
                artifacts = [{"reason": "compiler-artifact", "target": {"name": name, "kind": [kind]},
                              "executable": str(executable) if name == "ubusd" else None,
                              "profile": {"opt_level": opt}}
                             for name, kind, opt in [("ubusd", "bin", level), ("ubus", "lib", core_level)]]
                return subprocess.CompletedProcess(args, 0, stdout="\n".join(map(json.dumps, artifacts)))

            with patch.dict(os.environ, {"CARGO_PROFILE_RELEASE_OPT_LEVEL": "s"}), \
                 patch.object(benchmark.processes, "run_cargo", side_effect=cargo):
                arms, provenance = benchmark.build_profile_matrix(root / "matrix")
            self.assertEqual(observed, [(level, "s") for level in ("z", "s", "2", "3")])
            self.assertEqual(len(arms), 4)
            for arm in provenance.values():
                self.assertEqual(arm["dependency_artifact_profiles"]["ubus"]["opt_level"], "s")

    def test_broker_counter_units_and_invalid_measurements(self):
        stats = benchmark.summarize([self.sample()])
        self.assertEqual(stats["broker_cpu_us_per_operation"], 100)
        self.assertEqual(stats["broker_rss_kib"], 1)
        self.assertEqual(stats["broker_lifetime_peak_rss_kib"], 2)
        for change in ({"broker_cpu_ns": -1}, {"broker_cpu_ns": True},
                       {"broker_rss_bytes": None}, {"broker_lifetime_peak_rss_bytes": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                benchmark.validate({**self.sample(), **change}, "rust", ("echo", 4, 4096), 2, 1)

    def test_paired_bootstrap_retains_a_constant_trial_ratio(self):
        self.assertEqual(benchmark.bootstrap_ratio([2, 200, 20], [1, 100, 10]), (2, 2))
        self.assertEqual(benchmark.bootstrap_ratio([2], [1]), (None, None))
        with self.assertRaises(ValueError):
            benchmark.bootstrap_ratio([1, 2], [1])

    def test_pipeline_depth_is_part_of_the_measurement_contract(self):
        sample = {**self.sample(), "workload": "ping-pipeline", "payload_bytes": 0,
                  "pipeline_depth": 32}
        benchmark.validate(sample, "rust", ("ping-pipeline", 4, 0), 2, 1)
        for depth in (None, 1, 31, 32.0):
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                benchmark.validate({**sample, "pipeline_depth": depth}, "rust",
                                   ("ping-pipeline", 4, 0), 2, 1)

    def test_before_after_reports_preserve_all_three_arms(self):
        stats = benchmark.summarize([self.sample()])
        brokers = ["upstream", "baseline", "rust"]
        result = {"metadata": {"commit": "current", "baseline_rust_source": {"commit": "previous"}},
                  "configuration": {"samples": 1, "iterations": 2, "brokers": brokers},
                  "comparisons": [{"workload": "echo", "clients": 4, "payload_bytes": 4096,
                                   "iterations_per_client": 2,
                                   **{broker: stats for broker in brokers}}]}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            benchmark.write_reports(output, result)
            report = (output / "report.html").read_text()
            for broker in brokers:
                self.assertIn(f"<td>{broker}</td>", report)
            self.assertEqual(len((output / "summary.csv").read_text().splitlines()), 4)
            self.assertEqual(json.loads((output / "performance.json").read_text()), result)

    def test_baseline_arm_uses_its_exact_binary_with_the_same_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {name: root / name for name in ("upstream", "rust", "baseline", "driver")}
            for name, path in paths.items():
                path.write_text(name)
            invocations = []

            def worker(args, env):
                invocations.append((args[:], env.copy()))
                return {"schema_version": 1, "broker": args[1], "workload": "ping", "clients": 1,
                        "payload_bytes": 0, "iterations": 2, "warmup": 0, "operations": 2,
                        "elapsed_ns": 10, "latency_ns": [2, 3], "broker_cpu_ns": 2,
                        "broker_rss_bytes": 1024, "broker_lifetime_peak_rss_bytes": 2048}

            provenance = {"binaries": {name: benchmark.identity(paths[name])
                                      for name in ("upstream", "rust", "driver")},
                          "reference_shared_libraries": {}}
            args = SimpleNamespace(baseline_ref="previous", iterations=2, samples=1,
                                   warmup=0, smoke=True, output=root / "report")
            with patch.object(benchmark, "build", return_value=(
                    {"ubusd": paths["rust"], "ubus-bench": paths["driver"]}, {})), \
                 patch.object(benchmark, "build_baseline", return_value=(paths["baseline"], {"commit": "previous"})), \
                 patch.object(benchmark, "metadata", return_value=provenance), \
                 patch.object(benchmark, "run_worker", side_effect=worker), \
                 patch.object(benchmark, "CASES", [("ping", 1, 0)]), \
                 patch.object(benchmark, "write_reports") as reports:
                benchmark.measure(args, paths["upstream"], root)
            self.assertEqual([call[0][0] for call in invocations], [str(paths["driver"])] * 3)
            self.assertEqual([call[0][1] for call in invocations], ["upstream", "rust", "rust"])
            self.assertEqual(invocations[1][1]["UBUS_ZERO_UBUSD_RS"], str(paths["baseline"]))
            self.assertEqual(invocations[2][1]["UBUS_ZERO_UBUSD_RS"], str(paths["rust"]))
            result = reports.call_args.args[1]
            self.assertEqual(result["configuration"]["brokers"], ["upstream", "baseline", "rust"])
            self.assertEqual(result["comparisons"][0]["iterations_per_client"], 2)
            self.assertEqual(result["metadata"]["baseline_rust_source"]["commit"], "previous")

    def test_full_run_keeps_fast_scaling_cases_long_and_records_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "binary"
            executable.write_bytes(b"binary")
            args = SimpleNamespace(baseline_ref=None, iterations=5000, pipeline_iterations=200000,
                                   scaling_iterations=200, samples=1, warmup=100,
                                   smoke=False, output=root / "report")
            cases = [(name, 1, 0) for name in ("ping", "ping-pipeline", "lookup-many", "lookup-prefix",
                                              "acl-lookup", "event-fanout", "notify-fanout")]

            def worker(invocation, environment):
                count = int(invocation[3])
                return {"operations": count, "elapsed_ns": 1_000_000_000, "iterations": count}

            with patch.object(benchmark, "build", return_value=({"ubusd": executable, "ubus-bench": executable}, {})), \
                 patch.object(benchmark, "metadata", return_value={"binaries": {}, "reference_shared_libraries": {}}), \
                 patch.object(benchmark, "CASES", cases), \
                 patch.object(benchmark, "run_worker", side_effect=worker), \
                 patch.object(benchmark, "validate") as validate, \
                 patch.object(benchmark, "summarize", return_value={"operations_per_second": 1}), \
                 patch.object(benchmark, "write_reports") as reports:
                benchmark.measure(args, executable, root)
            counts = [5000, 200000, 200, 5000, 5000, 5000, 5000]
            self.assertEqual([call.args[3] for call in validate.call_args_list],
                             [count for count in counts for _ in range(2)])
            self.assertEqual([case["iterations_per_client"] for case in reports.call_args.args[1]["comparisons"]], counts)

    @unittest.skipUnless(sys.platform == "linux", "Linux process sessions")
    def test_timeout_reaps_the_benchmark_worker(self):
        original = subprocess.Popen
        pids = []

        def start(*args, **kwargs):
            process = original(*args, **kwargs)
            pids.append(process.pid)
            return process

        with patch.object(benchmark.processes.subprocess, "Popen", side_effect=start):
            with self.assertRaises(subprocess.TimeoutExpired):
                benchmark.run_worker([sys.executable, "-c", "import time; time.sleep(30)"],
                                     os.environ.copy(), timeout=.5)
        self.assertEqual(len(pids), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)


if __name__ == "__main__":
    unittest.main()
