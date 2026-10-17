# Broker performance comparisons

The benchmark runs identical, verified operations against pinned OpenWrt C
`ubusd` and the Rust broker over local Unix sockets. It reports end-to-end
latency/throughput, broker process CPU time, and broker resident memory. Results
characterize the measured host and workloads; they are not language-level speed
claims or measurements of router hardware.

## Run

On Linux, with Python 3.12+, the pinned Rust toolchain, a C compiler and Docker Buildx:

```sh
tools/ubusd-builder/build.sh
python3 tools/ubus-benchmark.py
```

Reports under `dist/benchmarks/` are `report.html` (standalone, no external assets),
`performance.json` (raw latency samples, CPU/memory counters and provenance),
`summary.csv` and `report.md`.

```sh
python3 tools/ubus-benchmark.py --smoke
python3 tools/ubus-benchmark.py --baseline-ref origin/main
python3 tools/ubus-benchmark.py --profile-matrix --workload ping --workload echo
python3 tools/ubus-benchmark.py --samples 12 --pipeline-iterations 200000
cargo run --release -p ubusd --example footprint
```

`--iterations` counts operations per client per sample (default 5,000).
Pipelined trials use `--pipeline-iterations` (200,000), and the 1,000-object
list uses `--scaling-iterations` (200). Prefix, ACL and fanout trials use the
ordinary 5,000 iterations. Each report row records its actual count. `--samples`
defaults to six and `--warmup` to 100. Repeat
`--workload` to select a subset. `--upstream` selects an exact reference binary;
`--output` selects the report directory. Missing fixtures or failed builds fail
rather than skip or fall back to debug executables.

`--smoke` uses 20 operations/client, two trials and five warmups for every case.
Its report is marked as harness validation, not a performance result.

`--baseline-ref` archives and builds that resolved Git commit before measuring.
The baseline uses its own manifest/lockfile, the current toolchain and the same
pinned fixtures. All arms use the same current driver. Fetch the ref first.
The report records baseline revision, build settings, executable hash and size.
Temporary baseline sources and executables are removed after reporting.

The production broker uses `opt-level=3` for the `ubusd` package; the public
`no_std` library keeps the workspace's size-oriented `opt-level=z`. Other release
settings, including fat LTO, remain shared. The private driver
uses the separate `bench-driver` profile (`opt-level=3`), so size-oriented client
code does not unnecessarily limit broker comparisons. Persistent client/provider
endpoints reserve 64 KiB read buffers outside timing; connect uses 2 KiB reads.
Send backpressure waits for writable readiness instead of fixed sleeps.
Cargo's executable paths and actual artifact profiles are read from its JSON
output; `CARGO_TARGET_DIR` is honored.

`--profile-matrix` additionally builds Rust brokers at `opt-level=z`, `s`, `2`
and `3`, changing only the `ubusd` package override. Dependency profiles and
the driver stay fixed; differing dependency profiles fail the run. Every arm's
actual Cargo profiles (including dependencies), SHA-256 and executable size are
recorded. Compilation finishes before host load/provenance capture and before trials. Temporary matrix
binaries are removed after reporting. Choose enough trials to balance starting
positions: multiples of the number of arms (two normally, three with a baseline,
six with the matrix, seven with both).

## Workloads and verification

| Workload | Setup | Verification per operation |
| --- | --- | --- |
| Connect | Fresh connection | Nonzero HELLO identity, close |
| Ping | Persistent connection | Successful reply |
| Pipelined ping | Up to 32 outstanding | Exact DATA then STATUS(0), sequence and address on every request |
| Lookup | One registered object | Exact object ID |
| Echo | 64 / 4,096 / 32,768-byte string; one client, plus four-client 4,096-byte case | Exact returned blobmsg including client and request sequence |
| Registry list | 1,000 typed objects | Every ID, path and signature in exact order |
| Prefix lookup | 100 matches among 1,000 objects | Exact ordered matching objects/signatures |
| Non-root ACL lookup | 100 objects and 100 access rules | Exact visible objects and signatures |
| Registration churn | Repeated named register/remove | Assigned identity and exact removal response |
| Ping with idle peers | 200 other connected clients | Successful ping |
| Event fanout | 50 listeners | Every destination, method, payload and per-listener sequence progression |
| NOTIFY fanout | 50 subscribers, NoReply enabled | Every destination, publisher address, sequence, method, payload and NoReply flag |

Payload sizes count string contents, excluding protocol overhead. Echo/lookup
use the same Rust provider for all arms. The single provider and client-side
validation can limit end-to-end throughput; broker CPU counters help expose
changes hidden by that shared work. Fanout operations include draining and
verifying all 50 deliveries; they count as one operation, not 50 operations.

Each trial starts a fresh broker. Registration, connections and warmup finish
before timing. Streaming DATA resets the client idle budget, while silent or
unrelated traffic still times out. Connect includes its own handshake and close. Pipeline warmup
fully drains before timing; an untimed ping first drains the normal client's
redundant HELLO status before direct transport reads. Per-request pipeline
latency runs from send through both validated replies, including queueing.
These are closed-loop workloads, not fixed-arrival-rate latency tests.

Both brokers get the same child-local credential shim. Only the ACL workload
uses non-root credentials plus the compatibility suite's stat/NSS fixtures;
other workloads use the root fast path. Wire taps, injected faults and ambient
preload/test-identity overrides are excluded from measurement.

## Interpret the report

- Throughput is the median of trial rates: total completed operations divided
  by concurrent wall time, including barrier, joins and connection cleanup.
- p50/p95/p99 use nearest-rank percentiles across measured operations. Warmup
  is excluded. End-to-end times include serialization, IPC, provider execution,
  parsing and validation.
- Broker CPU uses Linux's process CPU clock (user plus system time) over the
  measured window, divided by operations. It excludes client/provider CPU.
  This is not hardware instructions or cycles, and includes any broker cleanup
  occurring in that window.
- RSS is sampled after the operations while the broker is alive. Peak RSS is
  its **lifetime** high-water mark, including registration and warmup, not an
  isolated timed-window peak. Memory counters are bytes in JSON and KiB in tables.
- Throughput ratios to C include deterministic paired-trial percentile bootstrap
  intervals (2,000 resamples, 95%). An interval is absent with fewer than two
  trials. With few trials these estimates are coarse; they do not establish
  portable significance or account for every shared-host effect. Overlapping
  observed ranges alone do not prove that an effect is noise.
- Trials below 100 ms are counted in `short_samples`. Use longer trials and
  more repetitions before drawing conclusions from small deltas.
- Arm order rotates across trials/workloads. CPU model, available affinity,
  kernel, starting load, compiler, profiles, source/dirty state, executable and
  shared-library hashes/sizes, and pinned recipe revisions are recorded.
  Binaries/libraries are rehashed afterward to reject changes during a run.

The Linux broker uses level-triggered epoll keyed by monotonic peer IDs, with
write readiness armed only while bytes are queued. Other platforms use poll;
a native test also checks that fallback. Descriptor-free consecutive replies
can share a send; monitor traffic preserves individual frame boundaries. The
receive shortcut drains to EOF on HUP and retains header/body FD boundaries.

The C fixture uses CMake Release; Rust's exact settings are reported. These are
not guaranteed identical optimization policies. User-supplied C binaries are
identified by hash; the checked-in recipe pins do not authenticate their origin.
Run on a quiet machine and keep CPU placement, affinity, power settings, fixtures,
toolchain and settings fixed. Use separate, untimed profiler runs for allocation
tracing, syscall counts or `perf` hardware counters; profiler timings should not
be mixed into ordinary results.

## Allocation and retained-memory diagnostic

The `footprint` example installs a tracking allocator, warms up and verifies
10,000 ping and invoke-forward dispatches, and reports allocation/reallocation
calls. It also repeatedly registers/removes a named object and reports live
allocated bytes after 1,000, 2,000 and 4,000 cycles, with no live objects.
Dropping that registry should release its measured retained bytes.

This diagnostic covers Rust routing only: socket I/O, codec and broker-loop
allocations are excluded. It is not a timing benchmark or a C comparison.
Run the same example against the desired baseline to compare source changes.
The instrumentation itself adds overhead and belongs outside timing runs.

## CI

The **Broker performance** workflow verifies every workload in a short PR smoke
run. Main changes, weekly runs and manual dispatches use full defaults. Manual
inputs can select a baseline ref and enable the compiler-profile matrix. Reports
and raw samples are uploaded as `broker-performance`; the table also appears in
the Actions summary.

Wrong replies, missing fixtures, invalid CPU/memory counters and broken runs fail
CI. Timing has no pass/fail thresholds. Strict compatibility and fault-profile
checks independently establish protocol correctness.
