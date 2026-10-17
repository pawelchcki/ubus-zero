<p align="center">
  <img src="https://raw.githubusercontent.com/no-std-rs/ubus-zero/main/assets/ubus-zero.svg" width="720" alt="ubus-zero — pure Rust building blocks for OpenWrt ubus">
</p>

<p align="center">
  <a href="https://github.com/no-std-rs/ubus-zero/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/no-std-rs/ubus-zero/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/no-std-rs/ubus-zero/blob/main/LICENSE"><img alt="Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <img alt="no_std + alloc" src="https://img.shields.io/badge/no__std-alloc-6e40c9">
</p>

`ubus-zero` is a `no_std + alloc` Rust implementation of the
[OpenWrt ubus](https://openwrt.org/docs/techref/ubus) wire protocol: a
synchronous client, an object provider, and blob/blobmsg codecs. All I/O goes
through a small `Transport` trait, so the protocol core has no dependency on
Linux, sockets, executors or logging. An allocator is required.

The workspace also includes a Linux broker,
[`ubusd`](https://github.com/no-std-rs/ubus-zero/blob/main/crates/ubusd/README.md),
and a CLI,
[`ubus-client`](https://github.com/no-std-rs/ubus-zero/blob/main/crates/ubus-client/README.md).

## Compatibility and testing

On supported protocol paths, the Rust `ubusd` matches pinned OpenWrt
reference behavior (ubus `24864e7`, libubox `17f527f`) **byte for byte**.
A shared canonicalizer replaces broker-assigned object, peer and type IDs
with placeholders in order of first appearance. Headers, attribute order,
padding, lengths, names, payloads and status codes must match exactly.
Scenarios without broker-assigned IDs are compared as raw bytes.

| Evidence | What it covers |
| --- | --- |
| 186 checked-in golden transcripts | 109 ACL and 77 protocol scenarios recorded from the pinned C broker; replayed against Rust without OpenWrt fixtures |
| Live differential matrix | The same scenarios run against both brokers. Live runs also check that the goldens still match the pinned binaries. |
| Real OpenWrt consumers | The `ubus` CLI, libubus callers and providers, rpcd sessions, UCI and the rpcd file plugin |
| Fault profiles | Fragmented client streams and injected `EINTR` across the strict suite, plus file-descriptor passing at framing boundaries |
| Differential fuzzing | Both brokers must stay alive and keep answering. Fixed bugs and strict-close cases are kept as a regression corpus. |
| CI | Formatting, Clippy with `-D warnings`, the workspace tests and the strict pinned-reference suite on every PR. A weekly, non-blocking job runs the suite against upstream `master` to catch drift. |

Arbitrary malformed input is outside the byte-parity contract: the Rust broker
may close a connection where upstream returns an error status. The Rust API is
independent of the C `libubus` API and remains pre-1.0. See
[Compatibility testing](https://github.com/no-std-rs/ubus-zero/blob/main/docs/compatibility.md)
for the full contract and test procedures.

[Performance comparisons](https://github.com/no-std-rs/ubus-zero/blob/main/docs/performance.md)
measure verified workloads against both brokers, with latency percentiles,
throughput and raw samples.

## Library

The Cargo package is `ubus-zero`; the library crate is `ubus`.

```toml
[dependencies]
ubus = { package = "ubus-zero", git = "https://github.com/no-std-rs/ubus-zero", default-features = false }
```

| Feature | Provides |
| --- | --- |
| *(none)* | Protocol, client, provider and codecs over your own `Transport`. Opens no sockets. |
| `json` | `ubus::json::{json_to_blobmsg, blobmsg_to_json}`, still `alloc` without `std` |
| `unix` | `ubus::unix::UnixUbusTransport` for Linux Unix sockets via rustix, with monotonic deadlines |
| `portable-atomic` | Shared-buffer helpers and the spin mutex on targets without pointer-width atomics (e.g. ESP32-C3) |

Given a connected transport and a service providing `system.board`:

```rust
extern crate alloc;

use alloc::vec::Vec;
use ubus::client::UbusClient;
use ubus::{BlobMsgTable, Transport};

fn board<T: Transport>(transport: T) -> ubus::Result<Vec<u8>> {
    let mut client = UbusClient::connect(transport)?;
    let system = client.lookup("system")?;
    client.invoke(system, "board", &BlobMsgTable::empty())
}
```

`invoke` returns the last DATA reply as blobmsg table contents. `invoke_many`
returns every DATA reply. `request` and the methods built on it buffer
unrelated frames for `recv_frame`. `lookup` and `invoke` do not, so use the
request-based methods when you mix calls with events or subscriptions.

Provide an object:

```rust
use ubus::server::UbusConnection;
use ubus::{BlobMsgTable, Transport, UbusObject};

fn register_echo<T: Transport>(transport: T) -> ubus::Result<UbusConnection<T>> {
    let object = UbusObject::new("example.echo").method("ping", |_request| {
        Ok(BlobMsgTable::build(|reply| {
            reply.put_str(Some("message"), "pong");
        }))
    });
    UbusConnection::connect_and_register(transport, object)
}
```

Registering an object does not dispatch requests on its own. Keep the
connection alive and call `poll_one()` from your event loop. Each call handles
at most one frame. `DispatchOutcome::Idle` means no complete frame is
available, so wait or yield before polling again.

With `unix` enabled, `UnixUbusTransport::connect("/tmp/ubus.sock")` gives you a
ready transport. Call `set_deadline` before each request on a reused connection.
On targets without pointer-width atomics, configure `portable-atomic`'s
appropriate fallback; the ESP32 example demonstrates a single-core setup.
Some APIs were adapted from Cellctl; see the
[Cellctl imports](https://github.com/no-std-rs/ubus-zero/blob/main/docs/cellctl-imports.md).

## Broker and CLI

```sh
cargo install --git https://github.com/no-std-rs/ubus-zero ubusd
cargo install --git https://github.com/no-std-rs/ubus-zero ubus-client

ubusd --socket /tmp/ubus.sock                  # terminal 1
ubus-client -s /tmp/ubus.sock list             # terminal 2
```

A fresh standalone broker has no services. It only routes requests between
connected clients, so `list` starts empty and `system` is not available. To
register a provider, use `ubus-client serve`.

Non-root clients need ACL grants to register named objects, call methods,
subscribe, or send and listen for events. Without `--acl-dir`, all of these are
denied. Root bypasses ACLs, and monitoring requires root. The
[daemon guide](https://github.com/no-std-rs/ubus-zero/blob/main/crates/ubusd/README.md#access-control)
has a working ACL and provider example. The
[CLI guide](https://github.com/no-std-rs/ubus-zero/blob/main/crates/ubus-client/README.md)
covers calls, events, subscriptions, JSON Lines batches and program-backed
providers.

## ESP32 router display

A [`no_std` firmware example](https://github.com/no-std-rs/ubus-zero/blob/main/examples/esp32c3-router-display/README.md)
turns the GUITION ESP32-2424S012 round display into a live OpenWrt dashboard.
It shows traffic, load, memory, Wi-Fi and router identity, read through
uhttpd's `/ubus` bridge with a read-only rpcd account. The
[browser USB installer](https://no-std-rs.github.io/ubus-zero/) can flash the
firmware from a desktop browser with Web Serial.

## Development

On Linux, with the pinned Rust toolchain and a C compiler:

```sh
cargo build -p ubusd --features testing       # broker for the test harness
cargo test --workspace --all-features          # Rust tests + golden replay
tools/ubusd-builder/build.sh                   # pinned OpenWrt fixtures (Docker Buildx)
python3 tools/ubus-compat-check.py             # strict live suite
```

Without the fixtures, reference-backed tests print `SKIP`. The strict runner
fails instead. See
[CONTRIBUTING.md](https://github.com/no-std-rs/ubus-zero/blob/main/CONTRIBUTING.md)
for the full checklist and the
[security policy](https://github.com/no-std-rs/ubus-zero/blob/main/SECURITY.md)
for reporting vulnerabilities.

## License

[Apache License, Version 2.0](https://github.com/no-std-rs/ubus-zero/blob/main/LICENSE).
