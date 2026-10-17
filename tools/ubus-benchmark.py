#!/usr/bin/env python3
"""Verified C/Rust broker comparisons; timings are observations, never CI thresholds."""

import argparse
import csv
import datetime
import hashlib
import html
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import signal
import statistics
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("benchmark_processes", ROOT / "tools/ubus-compat-check.py")
processes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(processes)
CASES = [
    ("connect", 1, 0), ("ping", 1, 0), ("ping-pipeline", 1, 0), ("lookup", 1, 0),
    ("echo", 1, 64), ("echo", 1, 4096), ("echo", 1, 32768), ("echo", 4, 4096),
    ("lookup-many", 1, 0), ("lookup-prefix", 1, 0), ("acl-lookup", 1, 0),
    ("registry-churn", 1, 0), ("ping-idle", 1, 0), ("event-fanout", 1, 0), ("notify-fanout", 1, 0),
]


def command(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, **kwargs)


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def identity(path):
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def build_baseline(reference, directory):
    commit = command(["git", "rev-parse", "--verify", "--end-of-options", reference + "^{commit}"],
                     stdout=subprocess.PIPE).stdout.strip()
    with tempfile.TemporaryFile() as archive:
        command(["git", "archive", "--format=tar", commit], stdout=archive)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as source:
            source.extractall(directory, filter="data")
    fixtures = directory / ".dep/bin"
    fixtures.parent.mkdir(parents=True, exist_ok=True)
    fixtures.symlink_to(ROOT / ".dep/bin", target_is_directory=True)
    result = processes.run_cargo(
        ["cargo", "build", "--release", "--locked", "--manifest-path", str(directory / "Cargo.toml"),
         "--target-dir", str(directory / "target"), "-p", "ubusd", "-p", "ubus-testkit", "--bins", "--message-format=json"],
        os.environ.copy(), capture_stdout=True)
    result.check_returncode()
    for line in result.stdout.splitlines():
        artifact = json.loads(line)
        if (artifact.get("reason") == "compiler-artifact" and artifact.get("executable")
                and artifact["target"]["name"] == "ubusd"):
            return Path(artifact["executable"]).resolve(), {
                "commit": commit, "cargo_artifact_profile": artifact["profile"],
                "release_profile": tomllib.loads((directory / "Cargo.toml").read_text())["profile"]["release"],
            }
    raise ValueError("Cargo did not report the baseline broker executable")


def cargo_artifacts(arguments, environment=None, include_libraries=False):
    result = processes.run_cargo(["cargo", "build", "--locked", *arguments, "--message-format=json"],
                                environment or os.environ.copy(), capture_stdout=True)
    result.check_returncode()
    binaries, profiles = {}, {}
    for line in result.stdout.splitlines():
        artifact = json.loads(line)
        if artifact.get("reason") == "compiler-artifact":
            name = artifact["target"]["name"]
            if artifact.get("executable"):
                binaries[name] = Path(artifact["executable"]).resolve()
                profiles[name] = artifact["profile"]
            elif include_libraries and "custom-build" not in artifact["target"]["kind"]:
                profiles[name] = artifact["profile"]
    return binaries, profiles


def build():
    binaries, profiles = cargo_artifacts(["--release", "-p", "ubusd", "--bin", "ubusd"])
    driver, driver_profiles = cargo_artifacts(["--profile", "bench-driver", "-p", "ubus-testkit", "--bin", "ubus-bench"])
    binaries.update(driver)
    profiles.update(driver_profiles)
    if not {"ubusd", "ubus-bench"} <= binaries.keys():
        raise ValueError("Cargo did not report both benchmark executables")
    return binaries, profiles


def build_profile_matrix(directory):
    directory.mkdir(parents=True, exist_ok=True)
    arms, provenance = {}, {}
    dependency_profiles = None
    for level in ("z", "s", "2", "3"):
        binaries, profiles = cargo_artifacts(
            ["--release", "--target-dir", str(directory / "target"), "-p", "ubusd", "--bin", "ubusd",
             "--config", "profile.release.package.ubusd.opt-level=" + json.dumps(int(level) if level.isdigit() else level)],
            os.environ.copy(), include_libraries=True)
        if profiles["ubusd"]["opt_level"] != level:
            raise ValueError("Cargo did not honor the requested broker optimization level")
        dependencies = {name: profile for name, profile in profiles.items() if name != "ubusd"}
        if dependency_profiles is not None and dependencies != dependency_profiles:
            raise ValueError("dependency profiles changed between broker optimization arms")
        dependency_profiles = dependencies
        name = "profile-" + level
        path = directory / ("ubusd-" + level)
        shutil.copy2(binaries["ubusd"], path)
        arms[name] = path
        provenance[name] = {"opt_level": level, "cargo_artifact_profile": profiles["ubusd"],
                            "dependency_artifact_profiles": dependencies}
    return arms, provenance


def percentile(values, percent):
    """Nearest-rank percentile, with no interpolation of observed latencies."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def validate(sample, broker, case, iterations, warmup):
    workload, clients, payload_bytes = case
    expected = {"schema_version": 1, "broker": broker, "workload": workload,
                "clients": clients, "payload_bytes": payload_bytes,
                "iterations": iterations, "warmup": warmup, "operations": iterations * clients}
    if workload == "ping-pipeline":
        expected["pipeline_depth"] = 32
    for key, value in expected.items():
        if type(sample.get(key)) is not type(value) or sample[key] != value:
            raise ValueError(f"invalid worker result: {key}")
    if type(sample.get("elapsed_ns")) is not int or sample["elapsed_ns"] <= 0:
        raise ValueError("invalid worker elapsed time")
    for field in ("broker_cpu_ns", "broker_rss_bytes", "broker_lifetime_peak_rss_bytes"):
        if type(sample.get(field)) is not int or sample[field] < 0:
            raise ValueError(f"invalid broker counter: {field}")
    if sample["broker_lifetime_peak_rss_bytes"] < sample["broker_rss_bytes"]:
        raise ValueError("broker peak RSS is smaller than current RSS")
    latencies = sample.get("latency_ns")
    if not isinstance(latencies, list) or len(latencies) != expected["operations"]:
        raise ValueError("incomplete latency samples")
    if any(type(value) is not int or value <= 0 for value in latencies):
        raise ValueError("invalid latency sample")
    if max(latencies) > sample["elapsed_ns"]:
        raise ValueError("latency exceeds measured wall time")


def bootstrap_ratio(numerator, denominator, trials=2000):
    """Paired-trial percentile interval for the ratio of median sample rates."""
    if len(numerator) != len(denominator) or not numerator:
        raise ValueError("bootstrap needs matched, nonempty trial sets")
    if len(numerator) < 2:
        return None, None
    rng = random.Random(0)
    ratios = []
    for _ in range(trials):
        indices = [rng.randrange(len(numerator)) for _ in numerator]
        ratios.append(statistics.median(numerator[i] for i in indices) /
                      statistics.median(denominator[i] for i in indices))
    return percentile(ratios, 2.5), percentile(ratios, 97.5)


def summarize(samples):
    latency = [value for sample in samples for value in sample["latency_ns"]]
    rates = [sample["operations"] * 1e9 / sample["elapsed_ns"] for sample in samples]
    return {"operations_per_second": statistics.median(rates),
            "min_operations_per_second": min(rates), "max_operations_per_second": max(rates),
            "p50_us": percentile(latency, 50) / 1000,
            "p95_us": percentile(latency, 95) / 1000,
            "p99_us": percentile(latency, 99) / 1000,
            "broker_cpu_us_per_operation": statistics.median(sample["broker_cpu_ns"] / sample["operations"] / 1000 for sample in samples),
            "broker_rss_kib": statistics.median(sample["broker_rss_bytes"] / 1024 for sample in samples),
            "broker_lifetime_peak_rss_kib": max(sample["broker_lifetime_peak_rss_bytes"] / 1024 for sample in samples),
            "short_samples": sum(sample["elapsed_ns"] < 100_000_000 for sample in samples),
            "observations": len(latency)}


def label(case):
    workload, clients, payload_bytes = case
    workload = {"ping-pipeline": "ping (32 outstanding)",
                "lookup-many": "list 1000 objects", "lookup-prefix": "prefix 100 of 1000 objects",
                "acl-lookup": "100 objects / 100 ACL rules", "registry-churn": "register/remove",
                "ping-idle": "ping with 200 idle peers", "event-fanout": "event / 50 listeners",
                "notify-fanout": "notify / 50 subscribers"}.get(workload, workload)
    suffix = f" {payload_bytes} B" if payload_bytes else ""
    return f"{workload}{suffix}, {clients} client{'s' if clients != 1 else ''}"


def run_worker(invocation, environment, timeout=300):
    # Reuse the strict runner's tested session cleanup, including orphaned children.
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        with processes.managed_process(invocation, environment, stdout=output) as process:
            status = process.wait(timeout=timeout)
        if status:
            raise ValueError(f"benchmark worker exited {status}")
        output.seek(0)
        return json.load(output)


def metadata(binaries, profiles, upstream):
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), platform.machine())
    pins = {}
    for line in (ROOT / "tools/ubusd-builder/Dockerfile").read_text().splitlines():
        if line.startswith(("ARG LIBUBOX_REV=", "ARG UBUS_REV=")):
            key, value = line.removeprefix("ARG ").split("=", 1)
            pins[key] = value
    return {
        "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commit": command(["git", "rev-parse", "HEAD"], stdout=subprocess.PIPE).stdout.strip(),
        "dirty": bool(command(["git", "status", "--porcelain"], stdout=subprocess.PIPE).stdout.strip()),
        "host": {"kernel": platform.release(), "architecture": platform.machine(), "cpu": cpu,
                 "available_cpus": len(os.sched_getaffinity(0)), "affinity_cpus": sorted(os.sched_getaffinity(0)),
                 "load_average": os.getloadavg()},
        "rustc": command(["rustc", "-Vv"], stdout=subprocess.PIPE).stdout.strip(),
        "rust_release_profile": tomllib.loads((ROOT / "Cargo.toml").read_text())["profile"]["release"],
        "cargo_artifact_profiles": profiles,
        "reference_recipe_pins": pins,
        "reference_build_profile": "CMake Release in the checked-in builder; custom binaries may differ",
        "reference_recipe_sha256": digest(ROOT / "tools/ubusd-builder/Dockerfile"),
        "binaries": {"upstream": identity(upstream), "rust": identity(binaries["ubusd"]),
                     "driver": identity(binaries["ubus-bench"])},
        "reference_shared_libraries": {path.name: identity(path) for path in sorted(upstream.parent.glob("*.so*"))
                                       if path.is_file()},
        "method": "Same Rust client/provider and child-local root-credential shim; direct Unix sockets; "
                  "no wire tap or I/O fault injection. Only acl-lookup evaluates non-root ACLs, "
                  "using the same child-local credential/stat/NSS fixtures and 100 access rules; other cases use root credentials. Payload sizes count string "
                  "contents, excluding blobmsg/protocol overhead. Fresh broker per sample, warmed connections, "
                  "rotating broker order. End-to-end operations include client/provider work and "
                  "reply validation; connect includes socket connect, HELLO and close. "
                  "Pipelined ping keeps up to 32 requests outstanding; each latency runs from its send "
                  "through the validated DATA and STATUS replies, including queueing. "
                  "Throughput uses concurrent wall time including barrier/join overhead. "
                  "Percentiles pool all measured operations; throughput is the median sample rate. "
                  "Broker CPU is process user+system CPU over the timed window; RSS is sampled afterward, "
                  "and peak RSS covers the broker lifetime, including setup. Driver uses opt-level=3 and "
                  "64 KiB read buffers on persistent endpoints; connect uses 2 KiB. "
                  "Ratios include deterministic paired-trial 95% percentile bootstrap intervals (2000 resamples); "
                  "these describe sample uncertainty on this host, not hardware portability.",
    }


def write_reports(output, result):
    output.mkdir(parents=True, exist_ok=True)
    brokers = result["configuration"].get("brokers", ["upstream", "rust"])
    rows = []
    for comparison in result["comparisons"]:
        for broker in brokers:
            rows.append({"workload": comparison["workload"], "clients": comparison["clients"],
                         "payload_bytes": comparison["payload_bytes"], "broker": broker,
                         "iterations_per_client": comparison["iterations_per_client"],
                         **comparison[broker]})
    with (output / "summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output / "performance.json").write_text(json.dumps(result, indent=2) + "\n")
    table = ["| Workload | Broker | Iterations/client | ops/s | p50 µs | p95 µs | p99 µs | broker CPU µs/op | RSS KiB | vs C (95% interval) |",
             "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |"]
    body = []
    for comparison in result["comparisons"]:
        name = label((comparison["workload"], comparison["clients"], comparison["payload_bytes"]))
        maximum = max(comparison[broker]["operations_per_second"] for broker in brokers)
        for broker in brokers:
            stats = comparison[broker]
            values = [f'{stats[key]:,.2f}' for key in ("operations_per_second", "p50_us", "p95_us", "p99_us")]
            values += [f'{stats["broker_cpu_us_per_operation"]:,.2f}', f'{stats["broker_rss_kib"]:,.0f}']
            ratio = stats.get("throughput_ratio_to_c")
            low, high = stats.get("ratio_to_c_ci95_low"), stats.get("ratio_to_c_ci95_high")
            interval = (f"{ratio:.3f}x [{low:.3f}, {high:.3f}]" if low is not None else
                        f"{ratio:.3f}x [insufficient trials]" if ratio is not None else "—")
            values.append(interval)
            iterations = comparison["iterations_per_client"]
            table.append(f"| {name} | {broker} | {iterations:,} | " + " | ".join(values) + " |")
            body.append(f'<tr><th>{html.escape(name)}</th><td>{broker}</td><td>{iterations:,}</td>'
                        f'<td><meter min="0" max="{maximum}" value="{stats["operations_per_second"]}"></meter> '
                        + values[0] + '</td>' + ''.join(f'<td>{value}</td>' for value in values[1:]) + '</tr>')
    size_md, size_html = [], []
    for broker in brokers:
        binary = result["metadata"].get("binaries", {}).get(broker)
        if binary:
            size = f"{binary['bytes'] / 1024:,.1f}"
            size_md.append(f"| {broker} | {size} |")
            size_html.append(f"<tr><th>{html.escape(broker)}</th><td>{size}</td></tr>")
    build_markdown = ("\n\n### Executable sizes\n\n| Broker | KiB |\n| --- | ---: |\n" + "\n".join(size_md)
                      + "\n\nExecutable files only; the C broker also loads the shared libraries listed in provenance.\n") if size_md else ""
    build_html = ('<h2>Executable sizes</h2><table><thead><tr><th>Broker</th><th>KiB</th></tr></thead><tbody>'
                  + ''.join(size_html) + '</tbody></table><p><small>Executable files only; C also loads the shared libraries in provenance.</small></p>') if size_html else ""
    notice = ("Informational end-to-end timings and separately sampled broker process CPU/memory, not a timing gate. "
              "Shared-host load and the client/provider affect results. PR smoke runs validate the harness, "
              "not performance. Trials shorter than 100 ms are counted as short_samples in the data; use longer trials for conclusions. See metadata for build profiles, binary hashes and measurement settings.")
    if result["configuration"].get("smoke"):
        notice = "SMOKE RUN: harness verification only; these timings are not performance results. " + notice
    (output / "report.md").write_text("## ubusd performance comparison\n\n" + notice + "\n\n" +
                                     "\n".join(table) + "\n" + build_markdown)
    (output / "report.html").write_text('''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ubusd performance comparison</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:3rem auto;padding:0 1rem;color:#17212b}
h1{letter-spacing:-.04em}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:.65rem;text-align:right;border-bottom:1px solid #dce2e7}th:first-child{text-align:left}
meter{width:7rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#52616d}
.scroll{overflow-x:auto}details{margin-top:2rem}</style><h1>ubusd performance comparison</h1>'''
        + f'<p>{html.escape(notice)}</p><p><small>Commit {html.escape(result["metadata"]["commit"])} · '
        + f'{result["configuration"]["samples"]} samples per broker/workload · '
        + 'iterations per client per sample are shown per row</small></p>'
        + '<div class="scroll"><table><thead><tr><th>Workload</th><th>Broker</th><th>Iterations/client</th><th>ops/s</th>'
        + '<th>p50 µs</th><th>p95 µs</th><th>p99 µs</th>'
        + '<th>Broker CPU µs/op</th><th>RSS KiB</th><th>vs C (95% interval)</th></tr></thead><tbody>' + ''.join(body)
        + '</tbody></table></div>' + build_html + '<details><summary>Method, machine and build provenance</summary><pre>'
        + html.escape(json.dumps({"configuration": result["configuration"], **result["metadata"]}, indent=2))
        + '</pre></details></html>')


def main():
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    if sys.platform != "linux":
        raise ValueError("broker benchmarks currently require Linux")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--samples", type=int, default=6)
    parser.add_argument("--pipeline-iterations", type=int, default=200000,
                        help="operations/client in full pipelined samples (default: 200000)")
    parser.add_argument("--scaling-iterations", type=int, default=200,
                        help="operations/client in 1000-object list trials (default: 200)")
    parser.add_argument("--profile-matrix", action="store_true",
                        help="also compare Rust release opt-level z, s, 2 and 3 with the same speed-optimized driver")
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--smoke", action="store_true", help="20 operations/client, two samples, five warmups")
    parser.add_argument("--baseline-ref", help="also build this Git commit/ref and compare its Rust broker using the current driver/toolchain")
    parser.add_argument("--workload", action="append", choices=sorted({case[0] for case in CASES}),
                        help="select workload(s); repeat to compare a focused subset")
    parser.add_argument("--upstream", type=Path, default=ROOT / ".dep/bin/ubusd")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/benchmarks")
    args = parser.parse_args()
    if args.smoke:
        args.iterations, args.samples, args.warmup = 20, 2, 5
    if not 1 <= args.scaling_iterations <= 1_000_000:
        parser.error("scaling iterations must be 1..1000000")
    if not 1 <= args.pipeline_iterations <= 1_000_000:
        parser.error("pipeline iterations must be 1..1000000")
    if not 1 <= args.iterations <= 1_000_000 or not 1 <= args.samples <= 100 or not 0 <= args.warmup <= 1_000_000:
        parser.error("iterations must be 1..1000000, samples 1..100, warmup 0..1000000")
    upstream = args.upstream.resolve()
    if not upstream.is_file():
        parser.error("build the pinned reference first: tools/ubusd-builder/build.sh")
    with tempfile.TemporaryDirectory(prefix="ubus-benchmark-base-") as directory:
        measure(args, upstream, Path(directory))


def measure(args, upstream, baseline_directory):
    binaries, profiles = build()
    brokers = {"upstream": upstream}
    if args.baseline_ref:
        baseline, baseline_source = build_baseline(args.baseline_ref, baseline_directory)
        brokers["baseline"] = baseline
    brokers["rust"] = binaries["ubusd"]
    matrix_profiles = {}
    if getattr(args, "profile_matrix", False):
        matrix, matrix_profiles = build_profile_matrix(baseline_directory / "profiles")
        brokers.update(matrix)
    # Capture starting load and provenance after every compilation has finished.
    provenance = metadata(binaries, profiles, upstream)
    if args.baseline_ref:
        provenance["binaries"]["baseline"] = identity(baseline)
        provenance["baseline_rust_source"] = baseline_source
    provenance["profile_matrix"] = matrix_profiles
    for name, path in brokers.items():
        provenance["binaries"][name] = identity(path)
    environment = {**os.environ, "UBUS_ZERO_UBUSD": str(upstream), "UBUS_ZERO_UBUSD_RS": str(binaries["ubusd"])}
    comparisons = []
    cases = [case for case in CASES if not getattr(args, "workload", None) or case[0] in args.workload]
    for case_index, case in enumerate(cases):
        samples = {broker: [] for broker in brokers}
        workload, clients, payload_bytes = case
        iterations = (getattr(args, "pipeline_iterations", args.iterations)
                      if workload == "ping-pipeline" and not args.smoke else args.iterations)
        if workload == "lookup-many" and not args.smoke:
            iterations = getattr(args, "scaling_iterations", args.iterations)
        for repeat in range(args.samples):
            order = list(brokers)
            offset = (repeat + case_index) % len(order)
            order = order[offset:] + order[:offset]
            for broker in order:
                print(f"{label(case)}: {broker}, sample {repeat + 1}/{args.samples}", file=sys.stderr, flush=True)
                worker_broker = "upstream" if broker == "upstream" else "rust"
                environment["UBUS_ZERO_UBUSD_RS"] = str(brokers[broker])
                invocation = [str(binaries["ubus-bench"]), worker_broker, workload, str(iterations),
                              str(args.warmup), str(clients), str(payload_bytes)]
                sample = run_worker(invocation, environment)
                validate(sample, worker_broker, case, iterations, args.warmup)
                samples[broker].append(sample)
        stats = {broker: summarize(arm) for broker, arm in samples.items()}
        rates = {broker: [sample["operations"] * 1e9 / sample["elapsed_ns"] for sample in arm]
                 for broker, arm in samples.items()}
        for broker in stats:
            low, high = bootstrap_ratio(rates[broker], rates["upstream"])
            stats[broker].update({"throughput_ratio_to_c": stats[broker]["operations_per_second"] / stats["upstream"]["operations_per_second"],
                                 "ratio_to_c_ci95_low": low, "ratio_to_c_ci95_high": high})
        comparisons.append({"workload": workload, "clients": clients, "payload_bytes": payload_bytes,
                            "iterations_per_client": iterations,
                            **stats, "samples": samples})
    for measured_file in [*provenance["binaries"].values(), *provenance["reference_shared_libraries"].values()]:
        if digest(Path(measured_file["path"])) != measured_file["sha256"]:
            raise ValueError("a measured executable or reference library changed during the run")
    result = {"schema_version": 1, "configuration": {"iterations": args.iterations, "samples": args.samples,
              "warmup": args.warmup, "smoke": args.smoke, "brokers": list(brokers),
              "pipeline_iterations": getattr(args, "pipeline_iterations", args.iterations),
              "scaling_iterations": getattr(args, "scaling_iterations", args.iterations), "cases": cases},
              "metadata": provenance, "comparisons": comparisons}
    write_reports(args.output, result)
    print(f"Reports: {args.output.resolve()}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"benchmark failed: {error}") from None
    except KeyboardInterrupt:
        raise SystemExit(130) from None
