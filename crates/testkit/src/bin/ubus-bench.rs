//! One verified, untapped benchmark sample. Orchestrated by tools/ubus-benchmark.py.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::json;
use ubus::blobmsg::{lookup, BlobBuilder, BlobMsgTable};
use ubus::client::{ObjectInfo, UbusClient};
use ubus::envelope::{find, EnvBuilder, UbusAttr};
use ubus::server::{DispatchOutcome, UbusConnection, UbusObject};
use ubus::wire::{Frame, MsgType};
use ubus::{Transport, UbusError};
use ubus_testkit::{UbusdHarness, UnixUbusTransport};

type Client = UbusClient<UnixUbusTransport>;
type Result<T> = std::result::Result<T, String>;
const OBJECT: &str = "benchmark.echo";
const PIPELINE_DEPTH: usize = 32;

struct Config {
    broker: String,
    workload: String,
    iterations: usize,
    warmup: usize,
    clients: usize,
    payload_bytes: usize,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        if args.len() != 6 {
            return Err("usage: ubus-bench <upstream|rust> <connect|ping|ping-pipeline|lookup|echo> <iterations> <warmup> <clients> <payload-bytes>".into());
        }
        let number = |index: usize, min, max| -> Result<usize> {
            let value = args[index].parse::<usize>().map_err(|e| e.to_string())?;
            if !(min..=max).contains(&value) {
                return Err(format!("argument {} must be in {min}..={max}", index + 1));
            }
            Ok(value)
        };
        if !matches!(args[0].as_str(), "upstream" | "rust")
            || !matches!(
                args[1].as_str(),
                "connect"
                    | "ping"
                    | "ping-pipeline"
                    | "lookup"
                    | "echo"
                    | "lookup-many"
                    | "lookup-prefix"
                    | "acl-lookup"
                    | "registry-churn"
                    | "ping-idle"
                    | "event-fanout"
                    | "notify-fanout"
            )
        {
            return Err("unknown broker or workload".into());
        }
        Ok(Self {
            broker: args[0].clone(),
            workload: args[1].clone(),
            iterations: number(2, 1, 1_000_000)?,
            warmup: number(3, 0, 1_000_000)?,
            clients: number(4, 1, 64)?,
            payload_bytes: number(5, 0, 65_536)?,
        })
    }
}

fn connect(path: &str) -> Result<Client> {
    connect_with_buffer(path, 2048)
}

fn connect_with_buffer(path: &str, bytes: usize) -> Result<Client> {
    UbusClient::connect(
        UnixUbusTransport::connect_with_read_buffer(path, bytes).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn echo(args: &[u8]) -> ubus::Result<BlobMsgTable> {
    let payload = lookup(args, "payload")
        .and_then(|a| a.as_str())
        .ok_or(UbusError::Malformed("missing benchmark payload"))?;
    let client = lookup(args, "client")
        .and_then(|a| a.as_i32())
        .ok_or(UbusError::Malformed("missing benchmark client"))?;
    let sequence = lookup(args, "sequence")
        .and_then(|a| a.as_i32())
        .ok_or(UbusError::Malformed("missing benchmark sequence"))?;
    Ok(BlobMsgTable::build(|b| {
        b.put_str(Some("payload"), payload);
        b.put_i32(Some("client"), client);
        b.put_i32(Some("sequence"), sequence);
    }))
}

struct Provider {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
}

impl Provider {
    fn start(path: String) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let transport = UnixUbusTransport::connect_with_read_buffer(&path, 64 * 1024)
                .map_err(|e| e.to_string())?;
            let mut connection = UbusConnection::connect_and_register(
                transport,
                UbusObject::new(OBJECT).method("echo", echo),
            )
            .map_err(|e| e.to_string())?;
            ready_tx.send(()).map_err(|e| e.to_string())?;
            while !stopping.load(Ordering::Relaxed) {
                match connection.poll_one().map_err(|e| e.to_string())? {
                    DispatchOutcome::Idle => connection.transport_mut().wait_recv(),
                    DispatchOutcome::HandlerErr(error) => return Err(error.to_string()),
                    _ => {}
                }
            }
            Ok(())
        });
        let provider = Self {
            stop,
            thread: Some(thread),
        };
        ready_rx
            .recv_timeout(Duration::from_secs(15))
            .map_err(|e| format!("provider registration: {e}"))?;
        Ok(provider)
    }

    fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .take()
            .expect("provider thread")
            .join()
            .map_err(|_| "provider panicked".to_string())?
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Worker {
    client: Option<Client>,
    object: u32,
    identity: i32,
    payload: String,
    expected_objects: Vec<ObjectInfo>,
    listeners: Vec<(Client, u32, Option<u16>)>,
}

fn register_named(client: &mut Client, path: &str) -> Result<(u32, Vec<u8>)> {
    let mut signature = BlobBuilder::new();
    signature.open_table(Some("echo"));
    signature.close_table();
    let signature = signature.finish();
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, path);
    env.push_signature(&signature);
    let mut id = None;
    client
        .request(MsgType::AddObject, 0, env, |frame| {
            id = find(&frame.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32());
            Ok(())
        })
        .map_err(|error| error.to_string())?;
    Ok((
        id.filter(|id| *id != 0)
            .ok_or("registration omitted identity")?,
        signature,
    ))
}

struct AclFixture(std::path::PathBuf);
impl AclFixture {
    fn create() -> Result<Self> {
        let path = ubus_testkit::unique_socket_path("bench-acl");
        std::fs::create_dir(&path).map_err(|e| e.to_string())?;
        let fixture = Self(path);
        let access: serde_json::Map<String, serde_json::Value> = (0..100)
            .map(|index| {
                (
                    format!("benchmark.objects.{index:04}"),
                    json!({"methods": ["echo"]}),
                )
            })
            .collect();
        let policy = json!({"user": "bench", "publish": ["benchmark.*"], "access": access});
        std::fs::write(fixture.0.join("benchmark.json"), policy.to_string())
            .map_err(|e| e.to_string())?;
        Ok(fixture)
    }
}
impl Drop for AclFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Worker {
    fn pipeline(&mut self, count: usize) -> Result<Vec<u64>> {
        let transport = self
            .client
            .as_mut()
            .expect("persistent client")
            .transport_mut();
        let empty = EnvBuilder::new().finish();
        let mut success = EnvBuilder::new();
        success.push_u32(UbusAttr::Status, 0);
        let success = success.finish();
        let mut pending: VecDeque<(u16, Instant, bool)> = VecDeque::with_capacity(PIPELINE_DEPTH);
        let mut latencies = Vec::with_capacity(count);
        let mut sent = 0;
        while latencies.len() < count {
            while sent < count && pending.len() < PIPELINE_DEPTH {
                let sequence = (sent as u16).wrapping_add(1);
                let frame = Frame::to_broker(MsgType::Ping, sequence, empty.clone());
                let start = Instant::now();
                transport.send(&frame).map_err(|e| e.to_string())?;
                pending.push_back((sequence, start, false));
                sent += 1;
            }
            let frame = loop {
                match transport.recv().map_err(|e| e.to_string())? {
                    Some(frame) => break frame,
                    None => transport.wait_recv(),
                }
            };
            let (sequence, start, saw_data) = pending.front_mut().expect("outstanding ping");
            if frame.hdr.seq != *sequence || frame.hdr.peer != 0 {
                return Err("pipelined ping reply sequence/address mismatch".into());
            }
            match frame.hdr.ty {
                MsgType::Data if !*saw_data && frame.payload == empty => *saw_data = true,
                MsgType::Status if *saw_data && frame.payload == success => {
                    latencies.push(start.elapsed().as_nanos() as u64);
                    pending.pop_front();
                }
                _ => return Err("pipelined ping expected DATA followed by STATUS(0)".into()),
            }
        }
        Ok(latencies)
    }

    fn operation(&mut self, path: &str, workload: &str, sequence: i32) -> Result<()> {
        match workload {
            "connect" => {
                // Includes socket connect, HELLO validation and closing the connection.
                let client = connect(path)?;
                if client.peer_id().is_none() {
                    return Err("missing HELLO identity".into());
                }
            }
            "ping" | "ping-idle" => self
                .client
                .as_mut()
                .expect("persistent client")
                .ping()
                .map_err(|e| e.to_string())?,
            "lookup" => {
                if self
                    .client
                    .as_mut()
                    .expect("persistent client")
                    .lookup(OBJECT)
                    .map_err(|e| e.to_string())?
                    != self.object
                {
                    return Err("lookup returned the wrong object".into());
                }
            }
            "lookup-many" | "lookup-prefix" | "acl-lookup" => {
                let pattern = (workload == "lookup-prefix").then_some("benchmark.objects.09*");
                let actual = self
                    .client
                    .as_mut()
                    .expect("lookup client")
                    .lookup_objects(pattern)
                    .map_err(|e| e.to_string())?;
                if actual != self.expected_objects {
                    return Err(
                        "registry lookup returned incorrect ordered objects/signatures".into(),
                    );
                }
            }
            "registry-churn" => {
                let client = self.client.as_mut().expect("churn client");
                let name = format!("benchmark.churn.{}", self.identity);
                let (id, _) = register_named(client, &name)?;
                let mut env = EnvBuilder::new();
                env.push_u32(UbusAttr::ObjId, id);
                let mut removed = None;
                client
                    .request(MsgType::RemoveObject, 0, env, |frame| {
                        removed =
                            find(&frame.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32());
                        Ok(())
                    })
                    .map_err(|e| e.to_string())?;
                if removed != Some(id) {
                    return Err("churn removed the wrong object".into());
                }
            }
            "event-fanout" | "notify-fanout" => {
                let args = BlobMsgTable::build(|builder| {
                    builder.put_i32(Some("client"), self.identity);
                    builder.put_i32(Some("sequence"), sequence);
                });
                let client = self.client.as_mut().expect("fanout publisher");
                let seq = sequence as u16;
                if workload == "event-fanout" {
                    client
                        .send_event("benchmark.event", &args)
                        .map_err(|e| e.to_string())?;
                } else {
                    let mut env = EnvBuilder::new();
                    env.push_u32(UbusAttr::ObjId, self.object);
                    env.push_str(UbusAttr::Method, "benchmark.notify");
                    env.push_u8(UbusAttr::NoReply, 1);
                    env.push_data(args.contents());
                    client
                        .transport_mut()
                        .send(&Frame::to_broker(MsgType::Notify, seq, env.finish()))
                        .map_err(|e| e.to_string())?;
                }
                let address = if workload == "event-fanout" {
                    0
                } else {
                    client.peer_id().expect("publisher identity")
                };
                let method = if workload == "event-fanout" {
                    "benchmark.event"
                } else {
                    "benchmark.notify"
                };
                for (listener, id, previous_seq) in &mut self.listeners {
                    let frame = loop {
                        match listener.recv_frame().map_err(|e| e.to_string())? {
                            Some(frame) => break frame,
                            None => listener.transport_mut().wait_recv(),
                        }
                    };
                    let expected_seq = if workload == "event-fanout" {
                        previous_seq.map(|old| old.wrapping_add(50))
                    } else {
                        Some(seq)
                    };
                    if frame.hdr.ty != MsgType::Invoke
                        || frame.hdr.peer != address
                        || expected_seq.is_some_and(|expected| frame.hdr.seq != expected)
                        || find(&frame.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32())
                            != Some(*id)
                        || find(&frame.payload, UbusAttr::Method).and_then(|attr| attr.as_str())
                            != Some(method)
                        || find(&frame.payload, UbusAttr::Data).map(|attr| attr.payload)
                            != Some(args.contents())
                        || (workload == "notify-fanout"
                            && !find(&frame.payload, UbusAttr::NoReply)
                                .is_some_and(|attr| attr.as_bool_int8()))
                    {
                        return Err("fanout payload/recipient/sequence mismatch".into());
                    }
                    *previous_seq = Some(frame.hdr.seq);
                }
            }
            "echo" => {
                let args = BlobMsgTable::build(|b| {
                    b.put_str(Some("payload"), &self.payload);
                    b.put_i32(Some("client"), self.identity);
                    b.put_i32(Some("sequence"), sequence);
                });
                let reply = self
                    .client
                    .as_mut()
                    .expect("persistent client")
                    .invoke(self.object, "echo", &args)
                    .map_err(|e| e.to_string())?;
                if reply != args.contents() {
                    return Err("echo payload/client/sequence mismatch".into());
                }
            }
            _ => unreachable!("validated workload"),
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct BrokerCpuClock(libc::clockid_t);

#[cfg(target_os = "linux")]
impl BrokerCpuClock {
    fn new(pid: u32) -> Result<Self> {
        let mut clock = 0;
        let error = unsafe { libc::clock_getcpuclockid(pid as libc::pid_t, &mut clock) };
        if error != 0 {
            return Err(format!(
                "broker CPU clock: {}",
                std::io::Error::from_raw_os_error(error)
            ));
        }
        Ok(Self(clock))
    }
    fn now(&self) -> Result<u64> {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(self.0, &mut time) } != 0 {
            return Err(format!(
                "broker CPU measurement: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
    }
}

#[cfg(not(target_os = "linux"))]
struct BrokerCpuClock;
#[cfg(not(target_os = "linux"))]
impl BrokerCpuClock {
    fn new(_: u32) -> Result<Self> {
        Err("broker CPU measurements require Linux".into())
    }
    fn now(&self) -> Result<u64> {
        Err("broker CPU measurements require Linux".into())
    }
}

fn broker_memory(pid: u32) -> Result<(u64, u64)> {
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| e.to_string())?;
    let kib = |key| -> Result<u64> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| value * 1024)
            .ok_or_else(|| format!("missing broker memory counter {key}"))
    };
    Ok((kib("VmRSS:")?, kib("VmHWM:")?))
}

fn run(config: &Config) -> Result<serde_json::Value> {
    // The compatibility harness adds the same credential shim to both brokers.
    // Other instrumentation would invalidate this measurement.
    for (key, value) in std::env::vars_os() {
        if !value.is_empty()
            && (key == "UBUS_ZERO_FAULT"
                || key == "LD_PRELOAD"
                || key.to_string_lossy().starts_with("UBUS_TESTKIT_"))
        {
            return Err("unset fault injection, LD_PRELOAD and UBUS_TESTKIT_* overrides before benchmarking".into());
        }
    }
    let (variable, socket_flag) = if config.broker == "upstream" {
        ("UBUS_ZERO_UBUSD", "-s")
    } else {
        ("UBUS_ZERO_UBUSD_RS", "--socket")
    };
    let binary =
        std::env::var_os(variable).ok_or("use tools/ubus-benchmark.py to select exact binaries")?;
    let acl_fixture = if config.workload == "acl-lookup" {
        Some(AclFixture::create()?)
    } else {
        None
    };
    let broker = if let Some(fixture) = &acl_fixture {
        UbusdHarness::start_binary_with_acl(
            std::path::Path::new(&binary),
            socket_flag,
            fixture.0.to_str().ok_or("non-UTF8 ACL directory")?,
            &[
                ("UBUS_TESTKIT_PEERCRED", "1000:1000:1"),
                ("UBUS_TESTKIT_NSS_USERS", "1000:bench"),
                ("UBUS_TESTKIT_NSS_GROUPS", "1000:bench"),
                ("UBUS_TESTKIT_NSS_EXTRA_GIDS", ""),
            ],
        )
    } else {
        UbusdHarness::start_binary(std::path::Path::new(&binary), socket_flag)
    }
    .map_err(|e| e.to_string())?;
    let path = broker.socket_path().to_string_lossy().into_owned();
    let provider = if matches!(config.workload.as_str(), "lookup" | "echo") {
        Some(Provider::start(path.clone())?)
    } else {
        None
    };
    let mut fixture_clients = Vec::new();
    let mut expected_objects = Vec::new();
    if matches!(
        config.workload.as_str(),
        "lookup-many" | "lookup-prefix" | "acl-lookup"
    ) {
        let mut owner = connect_with_buffer(&path, 64 * 1024)?;
        let count = if config.workload == "acl-lookup" {
            100
        } else {
            1000
        };
        for index in 0..count {
            let name = format!("benchmark.objects.{index:04}");
            let (id, signature) = register_named(&mut owner, &name)?;
            if config.workload != "lookup-prefix" || name.starts_with("benchmark.objects.09") {
                expected_objects.push(ObjectInfo {
                    id,
                    path: name,
                    signature,
                });
            }
        }
        fixture_clients.push(owner);
    }
    if config.workload == "ping-idle" {
        for _ in 0..200 {
            fixture_clients.push(connect(&path)?);
        }
    }
    let mut workers = Vec::new();
    for identity in 0..config.clients {
        let mut client = if config.workload == "connect" {
            None
        } else {
            Some(connect_with_buffer(&path, 64 * 1024)?)
        };
        let object = if provider.is_some() {
            client
                .as_mut()
                .expect("persistent provider client")
                .lookup(OBJECT)
                .map_err(|e| e.to_string())?
        } else {
            0
        };
        if config.workload == "ping-pipeline" {
            // The client sends HELLO while the broker also sends one on
            // accept. A normal request drains the redundant HELLO's status
            // before the pipeline starts reading the transport directly.
            client
                .as_mut()
                .expect("persistent client")
                .ping()
                .map_err(|e| e.to_string())?;
        }
        let mut worker = Worker {
            client,
            object,
            identity: identity as i32,
            payload: "x".repeat(config.payload_bytes),
            expected_objects: expected_objects.clone(),
            listeners: Vec::new(),
        };
        if matches!(config.workload.as_str(), "event-fanout" | "notify-fanout") {
            if config.workload == "notify-fanout" {
                worker.object = worker
                    .client
                    .as_mut()
                    .expect("publisher")
                    .add_anonymous_object()
                    .map_err(|e| e.to_string())?;
            }
            for _ in 0..50 {
                let mut listener = connect_with_buffer(&path, 64 * 1024)?;
                let id = listener.add_anonymous_object().map_err(|e| e.to_string())?;
                if config.workload == "event-fanout" {
                    listener
                        .register_event(id, "benchmark.event")
                        .map_err(|e| e.to_string())?;
                } else {
                    listener
                        .subscribe(id, worker.object)
                        .map_err(|e| e.to_string())?;
                }
                while listener.recv_frame().map_err(|e| e.to_string())?.is_some() {}
                worker.listeners.push((listener, id, None));
            }
            while worker
                .client
                .as_mut()
                .expect("publisher")
                .recv_frame()
                .map_err(|e| e.to_string())?
                .is_some()
            {}
        }
        if config.workload == "ping-pipeline" {
            worker.pipeline(config.warmup)?;
        } else {
            for sequence in 0..config.warmup {
                worker.operation(&path, &config.workload, sequence as i32)?;
            }
        }
        workers.push(worker);
    }
    let gate = Barrier::new(config.clients + 1);
    let cpu_clock = BrokerCpuClock::new(broker.pid())?;

    let (elapsed_ns, cpu_ns, latencies) = thread::scope(|scope| -> Result<_> {
        let mut threads = Vec::new();
        for mut worker in workers {
            let (gate, path) = (&gate, &path);
            threads.push(scope.spawn(move || -> Result<Vec<u64>> {
                let mut latencies = Vec::with_capacity(config.iterations);
                gate.wait();
                if config.workload == "ping-pipeline" {
                    return worker.pipeline(config.iterations);
                }
                for sequence in config.warmup..config.warmup + config.iterations {
                    let start = Instant::now();
                    worker.operation(path, &config.workload, sequence as i32)?;
                    latencies.push(start.elapsed().as_nanos() as u64);
                }
                Ok(latencies)
            }));
        }
        let cpu_start = cpu_clock.now()?;
        let start = Instant::now();
        gate.wait();
        let mut latencies = Vec::with_capacity(config.clients * config.iterations);
        for thread in threads {
            latencies.extend(thread.join().map_err(|_| "client panicked")??);
        }
        let elapsed = start.elapsed().as_nanos() as u64;
        let cpu_ns = cpu_clock
            .now()?
            .checked_sub(cpu_start)
            .ok_or("broker CPU clock moved backwards")?;
        Ok((elapsed, cpu_ns, latencies))
    })?;
    let (rss_bytes, peak_rss_bytes) = broker_memory(broker.pid())?;
    if let Some(provider) = provider {
        provider.finish()?;
    }
    Ok(json!({
        "schema_version": 1, "broker": config.broker, "workload": config.workload,
        "clients": config.clients, "payload_bytes": config.payload_bytes,
        "iterations": config.iterations, "warmup": config.warmup,
        "operations": latencies.len(), "elapsed_ns": elapsed_ns, "latency_ns": latencies,
        "broker_cpu_ns": cpu_ns, "broker_rss_bytes": rss_bytes,
        "broker_lifetime_peak_rss_bytes": peak_rss_bytes,
        "pipeline_depth": if config.workload == "ping-pipeline" { PIPELINE_DEPTH } else { 1 },
    }))
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match Config::parse(&args).and_then(|config| run(&config)) {
        Ok(result) => {
            println!("{result}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ubus-bench: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
