//! `UbusdHarness` — start/stop a ubus broker (upstream `ubusd` or
//! the in-tree `ubusd-rs`) for matrix tests.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::time::{Duration, Instant};

use crate::path::unique_socket_path;

/// Spawned broker instance bound to a unique tmp socket. `Drop` kills
/// the child and unlinks the socket file. Today we have two flavours
/// — upstream `ubusd` ([`UbusdHarness::start_upstream`]) and the
/// in-tree pure-Rust [`UbusdHarness::start_rust`] — but the matrix
/// macro treats them as the same fixture so test bodies are written
/// once and run against both.
pub struct UbusdHarness {
    child: Child,
    stderr: Option<ChildStderr>,
    socket_path: PathBuf,
    reaped: bool,
}

impl UbusdHarness {
    /// Start this exact executable, without the compatibility suite's discovery
    /// fallbacks. Benchmarks use this to avoid measuring a stale/debug broker.
    /// `socket_flag` is `-s` for OpenWrt or `--socket` for the Rust broker.
    pub fn start_binary(binary: &std::path::Path, socket_flag: &str) -> io::Result<Self> {
        Self::spawn(
            binary.as_os_str(),
            &[socket_flag],
            &[],
            &uid_spoof_shims(),
            &[],
            None,
        )?
        .ok_or_else(|| io::Error::other("explicit broker executable is not viable"))
    }

    /// Exact-binary benchmark variant with child-local ACL/stat/NSS fixtures.
    pub fn start_binary_with_acl(
        binary: &std::path::Path,
        socket_flag: &str,
        acl_dir: &str,
        extra_env: &[(&str, &str)],
    ) -> io::Result<Self> {
        let mut env = vec![("UBUS_TESTKIT_STAT_ROOT_PREFIX", acl_dir)];
        env.extend_from_slice(extra_env);
        Self::spawn(
            binary.as_os_str(),
            &[socket_flag],
            &["-A", acl_dir],
            &with_nss_shim(acl_shims(), &env),
            &env,
            None,
        )?
        .ok_or_else(|| io::Error::other("explicit ACL broker executable is not viable"))
    }

    /// Try to spawn upstream `ubusd -s <unique-path>`. `Ok(None)` when
    /// no binary is found; every other failure is `Err`. Probes the
    /// socket for up to ~5 s before returning.
    ///
    /// Lookup: `$UBUS_ZERO_UBUSD` → `.dep/bin/ubusd` (rel. to
    /// `CARGO_MANIFEST_DIR` and one-up) → `ubusd` on `$PATH`.
    ///
    /// On Linux, `LD_PRELOAD`s `libubus_testkit_uid_spoof.so` so the
    /// broker takes its root-uid ACL fast-path and stamps forwarded
    /// INVOKE/NOTIFY frames with deterministic root credentials (see
    /// `uid_spoof.c`). `start_rust` uses the same shim because
    /// `ubusd-rs` intentionally reads SO_PEERCRED through libc for
    /// interposable credential tests.
    pub fn start_upstream() -> io::Result<Option<Self>> {
        Self::start_upstream_with_env(&[])
    }

    /// Start upstream `ubusd` with extra child-only environment
    /// entries. This is used by ACL pin tests to override the
    /// peercred shim without mutating process-global env.
    pub fn start_upstream_with_env(env: &[(&str, &str)]) -> io::Result<Option<Self>> {
        let Some(binary) = locate_ubusd(&StdEnv) else {
            return Ok(None);
        };
        Self::spawn(
            &binary,
            &["-s"],
            &[],
            &with_nss_shim(uid_spoof_shims(), env),
            env,
            None,
        )
    }

    /// Start upstream `ubusd -s <socket> -A <acl_dir>` with both the
    /// peercred shim and the stat-family shim (`stat_spoof.c`) preloaded,
    /// so the test's ACL JSON in `acl_dir` is seen as root-owned and
    /// loaded. `extra_env` overrides the spoofed identity (e.g.
    /// `UBUS_TESTKIT_PEERCRED=1000:1000:1`) to drive the allow path with a
    /// non-root client. Unlocks the ACL *allow* pins (docs §P4.4). `Ok(None)`
    /// when the upstream binary isn't reachable.
    pub fn start_upstream_with_acl(
        acl_dir: &str,
        extra_env: &[(&str, &str)],
    ) -> io::Result<Option<Self>> {
        let Some(binary) = locate_ubusd(&StdEnv) else {
            return Ok(None);
        };
        let mut env: Vec<(&str, &str)> = Vec::with_capacity(extra_env.len() + 1);
        env.push(("UBUS_TESTKIT_STAT_ROOT_PREFIX", acl_dir));
        env.extend_from_slice(extra_env);
        Self::spawn(
            &binary,
            &["-s"],
            &["-A", acl_dir],
            &with_nss_shim(acl_shims(), &env),
            &env,
            None,
        )
    }

    /// Start upstream `ubusd` with a targeted per-connection TX stall
    /// (see `fault.c`). `conn` is the 0-based accept index to wedge and
    /// `after_bytes` is how many bytes the broker may write to that
    /// client — enough to complete HELLO + subscribe — before every
    /// subsequent write to it returns EAGAIN forever. Used by the
    /// deterministic backpressure test to force upstream's real
    /// drop-fan-out shed path without kernel-buffer or timing luck.
    ///
    /// Upstream-only: `ubusd-rs` bypasses libc write interposers, so its
    /// equivalent shed point is pinned by the `testing` write governor
    /// (`Config::tx_governor`), not this shim.
    pub fn start_upstream_with_tx_stall(
        conn: usize,
        after_bytes: usize,
    ) -> io::Result<Option<Self>> {
        let Some(binary) = locate_ubusd(&StdEnv) else {
            return Ok(None);
        };
        let fault = FaultProfile {
            stall_conn: Some(conn),
            stall_after: Some(after_bytes),
            ..FaultProfile::default()
        };
        Self::spawn(&binary, &["-s"], &[], &uid_spoof_shims(), &[], Some(fault))
    }

    /// Try to spawn the in-tree `ubusd-rs` broker. `Ok(None)` when no
    /// binary is reachable. Workspace tests build the broker first; callers
    /// outside this repository can provide `UBUS_ZERO_UBUSD_RS`.
    pub fn start_rust() -> io::Result<Option<Self>> {
        Self::start_rust_with_env(&[])
    }

    /// Start the in-tree broker with extra child-only environment entries.
    /// Like the upstream variant, this keeps credential spoofing per child so
    /// ACL matrix cases never mutate the test process's environment.
    pub fn start_rust_with_env(env: &[(&str, &str)]) -> io::Result<Option<Self>> {
        let Some(binary) = locate_ubusd_rs() else {
            return Ok(None);
        };
        Self::spawn(
            &binary,
            &["--socket"],
            &[],
            &with_nss_shim(uid_spoof_shims(), env),
            env,
            None,
        )
    }

    /// Start `ubusd-rs --socket <socket> -A <acl_dir>` with the same
    /// credential and stat-owner shims as upstream. The Rust loader uses
    /// `libc::stat`, so the test ACL is observed as root-owned on both arms.
    pub fn start_rust_with_acl(
        acl_dir: &str,
        extra_env: &[(&str, &str)],
    ) -> io::Result<Option<Self>> {
        let Some(binary) = locate_ubusd_rs() else {
            return Ok(None);
        };
        let mut env: Vec<(&str, &str)> = Vec::with_capacity(extra_env.len() + 1);
        env.push(("UBUS_TESTKIT_STAT_ROOT_PREFIX", acl_dir));
        env.extend_from_slice(extra_env);
        Self::spawn(
            &binary,
            &["--socket"],
            &["-A", acl_dir],
            &with_nss_shim(acl_shims(), &env),
            &env,
            None,
        )
    }

    fn spawn(
        binary: &OsStr,
        socket_flag: &[&str],
        extra_args: &[&str],
        ld_preload_shims: &[&str],
        extra_env: &[(&str, &str)],
        fault_override: Option<FaultProfile>,
    ) -> io::Result<Option<Self>> {
        let socket_path = unique_socket_path("ubusd");
        let _ = std::fs::remove_file(&socket_path);
        // An explicit per-child profile (e.g. a targeted TX stall) wins
        // over the process-global UBUS_ZERO_FAULT the fault-check
        // runner sets, so one test can wedge one connection without
        // perturbing the rest of a parallel suite.
        let fault = fault_override.or_else(fault_profile_from_env);

        let mut cmd = Command::new(binary);
        for f in socket_flag {
            cmd.arg(f);
        }
        cmd.arg(&socket_path);
        for a in extra_args {
            cmd.arg(a);
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());
        for (key, val) in extra_env {
            cmd.env(key, val);
        }
        // Append, not replace, so caller-set LD_PRELOAD (sanitizers,
        // tracers) survives. Multiple shims chain via RTLD_NEXT in the
        // order appended here.
        let mut preload = std::env::var_os("LD_PRELOAD").unwrap_or_default();
        for shim in ld_preload_shims {
            append_preload(&mut preload, shim);
        }
        #[cfg(target_os = "linux")]
        if let Some(fault) = &fault {
            append_preload(&mut preload, env!("UBUS_TESTKIT_FAULT_SO"));
            if let Some(max_write) = fault.max_write {
                cmd.env("UBUS_TESTKIT_MAX_WRITE", max_write.to_string());
            } else {
                cmd.env_remove("UBUS_TESTKIT_MAX_WRITE");
            }
            if let Some(eintr_every) = fault.eintr_every {
                cmd.env("UBUS_TESTKIT_EINTR_EVERY", eintr_every.to_string());
            } else {
                cmd.env_remove("UBUS_TESTKIT_EINTR_EVERY");
            }
            if let Some(rx_eintr_every) = fault.rx_eintr_every {
                cmd.env("UBUS_TESTKIT_RX_EINTR_EVERY", rx_eintr_every.to_string());
            } else {
                cmd.env_remove("UBUS_TESTKIT_RX_EINTR_EVERY");
            }
            if let Some(stall_conn) = fault.stall_conn {
                cmd.env("UBUS_TESTKIT_TX_STALL_CONN", stall_conn.to_string());
            } else {
                cmd.env_remove("UBUS_TESTKIT_TX_STALL_CONN");
            }
            if let Some(stall_after) = fault.stall_after {
                cmd.env("UBUS_TESTKIT_TX_STALL_AFTER_BYTES", stall_after.to_string());
            } else {
                cmd.env_remove("UBUS_TESTKIT_TX_STALL_AFTER_BYTES");
            }
        }
        if !preload.is_empty() {
            cmd.env("LD_PRELOAD", preload);
        }
        let mut child = cmd.spawn()?;
        let stderr = child.stderr.take();

        // 5 s, not 500 ms: the deadline only elapses when the broker
        // genuinely fails to bind, so a green run pays nothing, while a
        // loaded CI box under heavy parallelism no longer trips a false
        // "did not bind" on a broker that is merely slow to start.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
                return Ok(Some(Self {
                    child,
                    stderr,
                    socket_path,
                    reaped: false,
                }));
            }
            if let Ok(Some(status)) = child.try_wait() {
                let stderr_text = drain_stderr(stderr);
                let _ = std::fs::remove_file(&socket_path);
                // Exit 126 (Cannot exec) and "Exec format error" cover
                // the cross-platform-binary case: a host-built ubusd-rs
                // mounted into a Linux container, an aarch64 binary on
                // x86_64, etc. Silent-skip rather than failing the test
                // — the binary isn't viable on this runner regardless
                // of broker correctness.
                let exit = status.code();
                let exec_format_error = stderr_text.contains("Exec format error")
                    || stderr_text.contains("cannot execute binary file");
                if exit == Some(126) || exec_format_error {
                    return Ok(None);
                }
                return Err(io::Error::other(format!(
                    "broker exited early ({status}); stderr: {stderr_text}"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let _ = child.kill();
        let _ = child.wait();
        let stderr = drain_stderr(stderr);
        let _ = std::fs::remove_file(&socket_path);
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("broker did not bind socket within 5 s; stderr: {stderr}"),
        ))
    }

    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// PID of this broker child, for signal-delivery tests. Kill only this
    /// saved PID, never a process selected by name.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Send a signal to this harness's broker child.
    pub fn send_signal(&self, signal: rustix::process::Signal) -> io::Result<()> {
        let pid = rustix::process::Pid::from_raw(self.pid() as i32).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "broker child has invalid PID")
        })?;
        rustix::process::kill_process(pid, signal)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    /// Wait for deliberate broker exit, marking it reaped so `Drop` does not
    /// report that normal shutdown as a mid-test failure.
    pub fn wait_exit(&mut self, timeout: Duration) -> io::Result<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "broker did not exit before timeout",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Ask the broker to stop with SIGTERM and wait for it. A timeout falls
    /// back to SIGKILL; that non-success status intentionally fails callers'
    /// success assertions.
    pub fn shutdown_gracefully(
        &mut self,
        timeout: Duration,
    ) -> io::Result<std::process::ExitStatus> {
        self.send_signal(rustix::process::Signal::TERM)?;
        match self.wait_exit(timeout) {
            Ok(status) => Ok(status),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                self.child.kill()?;
                let status = self.child.wait()?;
                self.reaped = true;
                Ok(status)
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FaultProfile {
    pub(crate) max_write: Option<usize>,
    pub(crate) eintr_every: Option<usize>,
    pub(crate) rx_eintr_every: Option<usize>,
    pub(crate) fragment: Option<usize>,
    /// 0-based accept index of the client whose broker-side TX to wedge.
    pub(crate) stall_conn: Option<usize>,
    /// Bytes the broker may write to the stalled client before every
    /// further write to it returns EAGAIN forever.
    pub(crate) stall_after: Option<usize>,
}

pub(crate) fn fault_profile_from_env() -> Option<FaultProfile> {
    let raw = std::env::var("UBUS_ZERO_FAULT").ok()?;
    parse_fault_profile(&raw)
}

fn parse_fault_profile(raw: &str) -> Option<FaultProfile> {
    if raw.trim().is_empty() {
        return None;
    }
    let mut profile = FaultProfile::default();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .unwrap_or_else(|| panic!("invalid UBUS_ZERO_FAULT item {part:?}"));
        match key {
            "max_write" => profile.max_write = Some(parse_positive_usize(key, value)),
            "eintr_every" => profile.eintr_every = Some(parse_positive_usize(key, value)),
            "rx_eintr_every" => profile.rx_eintr_every = Some(parse_positive_usize(key, value)),
            "fragment" => profile.fragment = Some(parse_positive_usize(key, value)),
            // stall_conn is a 0-based accept index, so 0 is legal.
            "stall_conn" => profile.stall_conn = Some(parse_usize(key, value)),
            "stall_after" => profile.stall_after = Some(parse_positive_usize(key, value)),
            _ => panic!("unknown UBUS_ZERO_FAULT key {key:?}"),
        }
    }
    Some(profile)
}

fn parse_usize(key: &str, raw: &str) -> usize {
    raw.parse::<usize>()
        .unwrap_or_else(|_| panic!("invalid UBUS_ZERO_FAULT {key} value {raw:?}"))
}

fn parse_positive_usize(key: &str, raw: &str) -> usize {
    let value = raw
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("invalid UBUS_ZERO_FAULT {key} value {raw:?}"));
    assert!(value > 0, "UBUS_ZERO_FAULT {key} must be greater than zero");
    value
}

/// LD_PRELOAD shim set for a plain broker run: just the peercred spoofer
/// (Linux only; `struct ucred` is Linux-specific).
fn uid_spoof_shims() -> Vec<&'static str> {
    #[cfg(target_os = "linux")]
    {
        vec![env!("UBUS_TESTKIT_UID_SPOOF")]
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// LD_PRELOAD shim set for an ACL run: the peercred spoofer plus the
/// stat-family owner spoofer so a userland ACL file is seen as root-owned.
fn acl_shims() -> Vec<&'static str> {
    #[cfg(target_os = "linux")]
    {
        vec![
            env!("UBUS_TESTKIT_UID_SPOOF"),
            env!("UBUS_TESTKIT_STAT_SPOOF"),
        ]
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Append the NSS spoof shim iff the child env opts in — any
/// `UBUS_TESTKIT_NSS_*` key present. Existing scenarios pass no such
/// keys, so their LD_PRELOAD strings (and recorded golden transcripts)
/// are structurally unchanged.
fn with_nss_shim(mut shims: Vec<&'static str>, env: &[(&str, &str)]) -> Vec<&'static str> {
    if env
        .iter()
        .any(|(key, _)| key.starts_with("UBUS_TESTKIT_NSS_"))
    {
        #[cfg(target_os = "linux")]
        shims.push(env!("UBUS_TESTKIT_NSS_SPOOF"));
    }
    shims
}

pub(crate) fn append_preload(preload: &mut OsString, shim: &str) {
    if !preload.is_empty() {
        preload.push(":");
    }
    preload.push(shim);
}

impl Drop for UbusdHarness {
    fn drop(&mut self) {
        if self.reaped {
            let _ = std::fs::remove_file(&self.socket_path);
            return;
        }
        // try_wait before kill: any mid-test exit (success or not)
        // invalidates the test result, so surface stderr in either
        // case. A clean exit during a test is just as suspicious as
        // a crash — the broker isn't supposed to leave on its own.
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let stderr = drain_stderr(self.stderr.take());
                eprintln!("broker exited mid-test ({status}); stderr: {stderr}");
            }
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn drain_stderr(handle: Option<ChildStderr>) -> String {
    let Some(mut h) = handle else {
        return String::from("<unavailable>");
    };
    let mut buf = String::new();
    if let Err(e) = h.read_to_string(&mut buf) {
        // Append rather than replace — partial output is still useful
        // when the read aborts mid-stream.
        buf.push_str(&format!("\n<stderr read failed: {e}>"));
    }
    if buf.is_empty() {
        String::from("<empty>")
    } else {
        buf
    }
}

/// Env + filesystem facade so locate functions are testable without
/// mutating process-global state (parallel tests would race on
/// `set_var`).
pub(crate) trait LocateEnv {
    fn ubus_zero_ubusd(&self) -> Option<std::ffi::OsString>;
    fn ubus_zero_ubusd_rs(&self) -> Option<std::ffi::OsString>;
    fn cargo_bin_file_ubusd_rs(&self) -> Option<std::ffi::OsString>;
    fn cargo_bin_exe_ubusd_rs(&self) -> Option<std::ffi::OsString>;
    fn manifest_dir(&self) -> Option<std::ffi::OsString>;
    fn path(&self) -> Option<std::ffi::OsString>;
    fn is_file(&self, p: &std::path::Path) -> bool;
}

struct StdEnv;

impl LocateEnv for StdEnv {
    fn ubus_zero_ubusd(&self) -> Option<std::ffi::OsString> {
        std::env::var_os("UBUS_ZERO_UBUSD")
    }
    fn ubus_zero_ubusd_rs(&self) -> Option<std::ffi::OsString> {
        std::env::var_os("UBUS_ZERO_UBUSD_RS")
    }
    fn cargo_bin_file_ubusd_rs(&self) -> Option<std::ffi::OsString> {
        std::env::var_os("CARGO_BIN_FILE_UBUSD_RS")
    }
    fn cargo_bin_exe_ubusd_rs(&self) -> Option<std::ffi::OsString> {
        std::env::var_os("CARGO_BIN_EXE_ubusd")
    }
    fn manifest_dir(&self) -> Option<std::ffi::OsString> {
        // `env!` (not `var_os`): pin the value into the binary so
        // discovery works even outside `cargo test`.
        Some(std::ffi::OsString::from(env!("CARGO_MANIFEST_DIR")))
    }
    fn path(&self) -> Option<std::ffi::OsString> {
        std::env::var_os("PATH")
    }
    fn is_file(&self, p: &std::path::Path) -> bool {
        p.is_file()
    }
}

pub(crate) fn locate_ubusd<E: LocateEnv>(env: &E) -> Option<std::ffi::OsString> {
    if let Some(p) = env.ubus_zero_ubusd() {
        if !p.is_empty() {
            let candidate = std::path::Path::new(&p);
            if env.is_file(candidate) {
                return Some(p);
            }
        }
    }
    // CARGO_MANIFEST_DIR is `crates/testkit/`; the workspace root is two
    // `..` components up. Keep the older fallbacks for standalone use.
    if let Some(manifest) = env.manifest_dir() {
        for relative in [
            ".dep/bin/ubusd",
            "../.dep/bin/ubusd",
            "../../.dep/bin/ubusd",
        ] {
            let candidate = std::path::Path::new(&manifest).join(relative);
            if env.is_file(&candidate) {
                return Some(candidate.into_os_string());
            }
        }
    }
    let path = env.path()?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("ubusd");
        if env.is_file(&candidate) {
            return Some(candidate.into_os_string());
        }
    }
    None
}

fn locate_ubusd_rs() -> Option<std::ffi::OsString> {
    locate_ubusd_rs_with(&StdEnv)
}

pub(crate) fn locate_ubusd_rs_with<E: LocateEnv>(env: &E) -> Option<std::ffi::OsString> {
    if let Some(p) = env.ubus_zero_ubusd_rs() {
        if !p.is_empty() {
            let candidate = std::path::Path::new(&p);
            if env.is_file(candidate) {
                return Some(p);
            }
        }
    }
    if let Some(p) = env.cargo_bin_file_ubusd_rs() {
        if !p.is_empty() {
            let candidate = std::path::Path::new(&p);
            if env.is_file(candidate) {
                return Some(p);
            }
        }
    }
    if let Some(p) = env.cargo_bin_exe_ubusd_rs() {
        if !p.is_empty() {
            let candidate = std::path::Path::new(&p);
            if env.is_file(candidate) {
                return Some(p);
            }
        }
    }
    if let Some(manifest) = env.manifest_dir() {
        for relative in [
            "../target/debug/ubusd",
            "../target/release/ubusd",
            "../../target/debug/ubusd",
            "../../target/release/ubusd",
            "target/debug/ubusd",
            "target/release/ubusd",
        ] {
            let candidate = std::path::Path::new(&manifest).join(relative);
            if env.is_file(&candidate) {
                return Some(candidate.into_os_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn explicit_missing_binary_never_falls_back_to_another_broker() {
        let missing = unique_socket_path("missing_benchmark_binary");
        assert!(!missing.exists());
        assert!(UbusdHarness::start_binary(&missing, "--socket").is_err());
    }

    #[test]
    fn fault_profile_parses_rx_eintr_every() {
        assert_eq!(
            parse_fault_profile("rx_eintr_every=3"),
            Some(FaultProfile {
                rx_eintr_every: Some(3),
                ..FaultProfile::default()
            })
        );
    }

    #[test]
    #[should_panic(expected = "UBUS_ZERO_FAULT rx_eintr_every must be greater than zero")]
    fn fault_profile_rejects_zero_rx_eintr_every() {
        let _ = parse_fault_profile("rx_eintr_every=0");
    }

    struct FakeEnv {
        example: Option<OsString>,
        example_rs: Option<OsString>,
        cargo_file_rs: Option<OsString>,
        cargo_bin_rs: Option<OsString>,
        manifest: Option<OsString>,
        path: Option<OsString>,
        existing: HashSet<PathBuf>,
    }

    impl LocateEnv for FakeEnv {
        fn ubus_zero_ubusd(&self) -> Option<OsString> {
            self.example.clone()
        }
        fn ubus_zero_ubusd_rs(&self) -> Option<OsString> {
            self.example_rs.clone()
        }
        fn cargo_bin_file_ubusd_rs(&self) -> Option<OsString> {
            self.cargo_file_rs.clone()
        }
        fn cargo_bin_exe_ubusd_rs(&self) -> Option<OsString> {
            self.cargo_bin_rs.clone()
        }
        fn manifest_dir(&self) -> Option<OsString> {
            self.manifest.clone()
        }
        fn path(&self) -> Option<OsString> {
            self.path.clone()
        }
        fn is_file(&self, p: &Path) -> bool {
            self.existing.contains(p)
        }
    }

    fn env(
        example: Option<&str>,
        manifest: Option<&str>,
        path: Option<&str>,
        existing: &[&str],
    ) -> FakeEnv {
        FakeEnv {
            example: example.map(OsString::from),
            example_rs: None,
            cargo_file_rs: None,
            cargo_bin_rs: None,
            manifest: manifest.map(OsString::from),
            path: path.map(OsString::from),
            existing: existing.iter().map(PathBuf::from).collect(),
        }
    }

    fn env_rs(
        example_rs: Option<&str>,
        cargo_file_rs: Option<&str>,
        cargo_bin_rs: Option<&str>,
        manifest: Option<&str>,
        path: Option<&str>,
        existing: &[&str],
    ) -> FakeEnv {
        FakeEnv {
            example: None,
            example_rs: example_rs.map(OsString::from),
            cargo_file_rs: cargo_file_rs.map(OsString::from),
            cargo_bin_rs: cargo_bin_rs.map(OsString::from),
            manifest: manifest.map(OsString::from),
            path: path.map(OsString::from),
            existing: existing.iter().map(PathBuf::from).collect(),
        }
    }

    #[test]
    fn ubus_zero_ubusd_wins_over_dep_bin() {
        let e = env(
            Some("/explicit/ubusd"),
            Some("/repo/crates/testkit"),
            None,
            &["/explicit/ubusd", "/repo/crates/testkit/.dep/bin/ubusd"],
        );
        assert_eq!(locate_ubusd(&e), Some(OsString::from("/explicit/ubusd")));
    }

    #[test]
    fn ubus_zero_ubusd_pointing_at_missing_file_falls_through() {
        let e = env(
            Some("/missing/ubusd"),
            Some("/repo/crates/testkit"),
            None,
            &["/repo/crates/testkit/.dep/bin/ubusd"],
        );
        assert_eq!(
            locate_ubusd(&e),
            Some(OsString::from("/repo/crates/testkit/.dep/bin/ubusd")),
        );
    }

    #[test]
    fn empty_ubus_zero_ubusd_falls_through_to_path() {
        let e = env(
            Some(""),
            None,
            Some("/usr/local/bin:/usr/bin"),
            &["/usr/bin/ubusd"],
        );
        assert_eq!(locate_ubusd(&e), Some(OsString::from("/usr/bin/ubusd")));
    }

    #[test]
    fn dep_bin_two_up_is_resolved_from_nested_workspace_member() {
        let e = env(
            None,
            Some("/repo/crates/testkit"),
            None,
            &["/repo/crates/testkit/../../.dep/bin/ubusd"],
        );
        assert_eq!(
            locate_ubusd(&e),
            Some(OsString::from("/repo/crates/testkit/../../.dep/bin/ubusd")),
        );
    }

    #[test]
    fn returns_none_when_nothing_is_reachable() {
        let e = env(None, Some("/repo"), Some("/usr/bin"), &[]);
        assert_eq!(locate_ubusd(&e), None);
    }

    #[test]
    fn ubus_zero_ubusd_rs_wins_over_artifact_and_cargo_bin() {
        let e = env_rs(
            Some("/explicit/ubusd-rs"),
            Some("/cargo/artifacts/ubusd-rs"),
            Some("/cargo/target/debug/ubusd"),
            None,
            None,
            &[
                "/explicit/ubusd-rs",
                "/cargo/artifacts/ubusd-rs",
                "/cargo/target/debug/ubusd",
            ],
        );
        assert_eq!(
            locate_ubusd_rs_with(&e),
            Some(OsString::from("/explicit/ubusd-rs"))
        );
    }

    #[test]
    fn cargo_bin_file_ubusd_rs_wins_over_cargo_bin_exe_and_target_fallback() {
        let e = env_rs(
            None,
            Some("/cargo/artifacts/ubusd-rs"),
            Some("/cargo/target/debug/ubusd"),
            Some("/repo/crates/testkit"),
            None,
            &[
                "/cargo/artifacts/ubusd-rs",
                "/cargo/target/debug/ubusd",
                "/repo/crates/testkit/../../target/debug/ubusd",
            ],
        );
        assert_eq!(
            locate_ubusd_rs_with(&e),
            Some(OsString::from("/cargo/artifacts/ubusd-rs"))
        );
    }

    #[test]
    fn cargo_bin_exe_ubusd_rs_used_when_artifact_unset() {
        let e = env_rs(
            None,
            None,
            Some("/cargo/target/debug/ubusd"),
            None,
            None,
            &["/cargo/target/debug/ubusd"],
        );
        assert_eq!(
            locate_ubusd_rs_with(&e),
            Some(OsString::from("/cargo/target/debug/ubusd"))
        );
    }

    #[test]
    fn ubusd_rs_falls_through_to_workspace_target() {
        let e = env_rs(
            None,
            None,
            None,
            Some("/repo/crates/testkit"),
            None,
            &["/repo/crates/testkit/../../target/debug/ubusd"],
        );
        assert_eq!(
            locate_ubusd_rs_with(&e),
            Some(OsString::from(
                "/repo/crates/testkit/../../target/debug/ubusd"
            ))
        );
    }

    #[test]
    fn ubusd_rs_returns_none_when_nothing_reachable() {
        let e = env_rs(None, None, None, Some("/repo"), Some("/usr/bin"), &[]);
        assert_eq!(locate_ubusd_rs_with(&e), None);
    }

    #[test]
    fn with_nss_shim_leaves_non_nss_env_unchanged() {
        let shims = vec!["first", "second"];
        assert_eq!(
            with_nss_shim(shims.clone(), &[("UBUS_TESTKIT_PEERCRED", "0:0:1")]),
            shims
        );
    }

    #[test]
    fn with_nss_shim_appends_for_users() {
        let shims = with_nss_shim(
            vec!["first"],
            &[("UBUS_TESTKIT_NSS_USERS", "4242:spoofuser")],
        );
        assert_eq!(shims.len(), 2);
        #[cfg(target_os = "linux")]
        assert_eq!(shims[1], env!("UBUS_TESTKIT_NSS_SPOOF"));
    }

    #[test]
    fn with_nss_shim_appends_for_fail_uids() {
        let shims = with_nss_shim(vec!["first"], &[("UBUS_TESTKIT_NSS_FAIL_UIDS", "4242")]);
        assert_eq!(shims.len(), 2);
        #[cfg(target_os = "linux")]
        assert_eq!(shims[1], env!("UBUS_TESTKIT_NSS_SPOOF"));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod nss_tests {
    use std::process::{Command, Output};

    const NSS_KEYS: [&str; 4] = [
        "UBUS_TESTKIT_NSS_USERS",
        "UBUS_TESTKIT_NSS_GROUPS",
        "UBUS_TESTKIT_NSS_FAIL_UIDS",
        "UBUS_TESTKIT_NSS_FAIL_GIDS",
    ];

    fn getent(args: &[&str], env: &[(&str, &str)]) -> Option<Output> {
        let mut command = Command::new("getent");
        command
            .args(args)
            .env("LD_PRELOAD", env!("UBUS_TESTKIT_NSS_SPOOF"));
        for key in NSS_KEYS {
            command.env_remove(key);
        }
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().ok()
    }

    fn fields(output: &Output) -> Vec<&str> {
        let stdout = std::str::from_utf8(&output.stdout).expect("getent stdout is UTF-8");
        stdout.trim_end().split(':').collect()
    }

    #[test]
    fn getent_passwd_by_uid_uses_spoofed_user() {
        let Some(output) = getent(
            &["passwd", "4242"],
            &[("UBUS_TESTKIT_NSS_USERS", "4242:spoofuser")],
        ) else {
            return;
        };
        assert!(output.status.success());
        let fields = fields(&output);
        assert_eq!(fields[0], "spoofuser");
        assert_eq!(fields[2], "4242");
    }

    #[test]
    fn getent_passwd_by_name_uses_spoofed_user() {
        let Some(output) = getent(
            &["passwd", "spoofuser"],
            &[("UBUS_TESTKIT_NSS_USERS", "4242:spoofuser")],
        ) else {
            return;
        };
        assert!(output.status.success());
        assert_eq!(fields(&output)[2], "4242");
    }

    #[test]
    fn getent_passwd_fail_uid_wins_over_spoofed_user() {
        let Some(output) = getent(
            &["passwd", "4242"],
            &[
                ("UBUS_TESTKIT_NSS_USERS", "4242:spoofuser"),
                ("UBUS_TESTKIT_NSS_FAIL_UIDS", "4242"),
            ],
        ) else {
            return;
        };
        assert_eq!(output.status.code(), Some(2));
    }

    #[test]
    fn getent_group_by_gid_uses_spoofed_group() {
        let Some(output) = getent(
            &["group", "4242"],
            &[("UBUS_TESTKIT_NSS_GROUPS", "4242:spoofgroup")],
        ) else {
            return;
        };
        assert!(output.status.success());
        assert_eq!(fields(&output)[0], "spoofgroup");
    }

    #[test]
    fn getent_without_knobs_passes_through() {
        let Some(output) = getent(&["passwd", "0"], &[]) else {
            return;
        };
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
    }
}
