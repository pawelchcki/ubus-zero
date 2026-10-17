# Changelog

## [0.3.0](https://github.com/no-std-rs/ubus-zero/compare/ubus-zero-v0.2.0...ubus-zero-v0.3.0) (2026-10-16)


### Features

* publish C3 firmware and add a GitHub Pages USB flasher ([#21](https://github.com/no-std-rs/ubus-zero/issues/21)) ([89422c0](https://github.com/no-std-rs/ubus-zero/commit/89422c0c9e36b25e2de9bd9279e9167f304f4177))
* add no_std ESP32-C3 OpenWrt router dashboard ([#20](https://github.com/no-std-rs/ubus-zero/issues/20)) ([8babfbb](https://github.com/no-std-rs/ubus-zero/commit/8babfbbe3b341250989affa1097ad83c27b2db92))

### Bug Fixes

* **ci:** isolate Cargo artifacts for concurrent fault profiles ([#23](https://github.com/no-std-rs/ubus-zero/issues/23)) ([051b507](https://github.com/no-std-rs/ubus-zero/commit/051b507b5a41a7207385381e498202516bb8094d))
* **release:** capture released versions without mirroring their crates.io entries ([#18](https://github.com/no-std-rs/ubus-zero/issues/18)) ([36109d2](https://github.com/no-std-rs/ubus-zero/commit/36109d260675c6d0af0b680ab15944e856519bd2))

All notable changes to `ubus-zero` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Broker CPU/RSS counters, trial uncertainty intervals, compiler-profile and
  allocation diagnostics, and verified registry/ACL/idle-peer/fanout benchmarks.
- A verified 32-request pipelined ping benchmark to cover broker batching, and
  same-machine comparisons of C, baseline Rust and current Rust using a Git ref.
- Reproducible Rust/OpenWrt broker benchmarks with verified protocol workloads,
  latency percentiles, throughput, raw samples and standalone comparison reports.

- Public ESP32-C3 factory firmware builds, Runnerless artifact publication, and
  a GitHub Pages USB flasher with browser-local configuration and checksums.
- A `no_std` ESP32-C3 round-display example for live OpenWrt statistics over
  uhttpd's ubus bridge, with read-only rpcd setup and touch-controlled pages.
- Optional portable atomics for shared-buffer transports on targets such as
  ESP32-C3 without native pointer-width atomics.
- Parallel compatibility coverage for ACL identities and reloads, descriptor
  passing, daemon lifecycle, upstream and Rust CLIs, and real rpcd/UCI/file
  consumers, with isolated per-process fixtures.
- Full-workspace upstream drift checks and concurrent fault-profile runs.

### Fixed

- Verify relay descriptor closure with per-pipe EOF instead of process-wide FD
  counts that race parallel tests.
- Reset the request idle budget on accepted DATA so long object listings do
  not time out while progressing; silence and unrelated traffic remain bounded.
- Bound named-object history to live registrations and preserve last-valid
  duplicate protocol attributes like the pinned OpenWrt parser.
- Use Linux epoll for active-peer dispatch and optimize the host daemon at
  release level 3 while keeping the public no_std library size-oriented.
- Reduce broker credential copies, frame allocations, buffer compaction and
  descriptor-free reply syscalls; index path/owner/event lookups and reuse
  NOTIFY encoding while retaining FD, monitor and backpressure behavior.

- Reduce large-message broker receive syscalls with a shared adaptive buffer,
  while preserving batching and descriptor boundaries.
- Preserve ubus frame and descriptor boundaries across fragmented and pipelined
  socket reads, including disposal of descriptors outside the header window.
- Keep fragmented Unix client replies buffered until the outer blob header
  arrives instead of prematurely accepting eight-byte header fragments.
- Match pinned OpenWrt ACL file safety, identity resolution, supplementary
  groups, mixed-type entries, and method visibility during lookup, while
  unresolved identity names remain denied.
- Replace duplicate ACL JSON keys using the final value in the original key
  position, including permission revocation and privilege tables.
- Read complete supplementary-group records so long lines cannot truncate GIDs
  into incorrect ACL grants or drop valid groups below the 64-group limit.
- Match ACL grants once per object when filtering non-root lookup replies,
  avoiding repeated registry scans for every declared method.
- Register malformed object signatures as untyped objects like upstream.
- Reject unexpected replies or trailing bytes during golden transcript replay.

## [0.2.0] - 2026-10-13

### Added

- Installable `ubus-client` with discovery, calls, events, subscriptions,
  monitoring, deadlines, JSON Lines batches and shell-backed object providers.
- Optional `json` and Linux `unix` library adapters extracted from Cellctl.
- Client APIs for object signatures, multiple replies and buffered asynchronous
  traffic.
- Embedded Runnerless release-please publishing for the public workspace crates.
- Runl setup for the three-crate publishing destination and Production environment.

### Changed

- Expose the Rust broker as the `ubusd` crate and executable.
- Support explicit OpenWrt library/header discovery for packaged FFI bindings.

## [0.1.0] - 2026-07-29

### Added

- Initial public release of the pure-Rust `no_std + alloc` ubus protocol
  library.
- Synchronous object lookup and method invocation.
- Object registration, method dispatch, replies, and removal.
- OpenWrt-compatible wire, blob, blobmsg, and envelope codecs.
- Runtime-neutral transport trait.
- Differential compatibility suite backed by a private Rust broker and pinned
  OpenWrt reference builds.

[Unreleased]: https://github.com/no-std-rs/ubus-zero/compare/ubus-zero-v0.2.0...HEAD
[0.2.0]: https://github.com/no-std-rs/ubus-zero/compare/ubus-zero-v0.1.0...ubus-zero-v0.2.0
[0.1.0]: https://github.com/no-std-rs/ubus-zero/releases/tag/ubus-zero-v0.1.0
