//! Smoke test: spawn a `Broker` on a background thread, then drive a
//! real `UbusClient` against it through a unix socket.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
#[cfg(feature = "testing")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "testing")]
use rustix::fd::AsFd;
use ubus::client::UbusClient;
use ubus::error::UbusError;
#[cfg(feature = "testing")]
use ubus::transport::Transport;
#[cfg(feature = "testing")]
use ubus::wire::UBUS_STATUS_INVALID_ARGUMENT;
#[cfg(feature = "testing")]
use ubus::wire::UBUS_SYSTEM_OBJECT_MONITOR;
use ubus::wire::{
    Codec, Frame, Header, MsgType, HEADER_SIZE, MAX_MSG_LEN, PROTO_VERSION,
    UBUS_STATUS_INVALID_COMMAND,
};
#[cfg(feature = "testing")]
use ubus_testkit::FdPeer;
use ubus_testkit::{pipe, unique_socket_path};

use ubusd::peer::MAX_TX_BUF_BYTES;
use ubusd::registry::FIRST_PEER_ID;
#[cfg(feature = "testing")]
use ubusd::WriteGovernor;
use ubusd::{Broker, Config};

/// Wait this long for `Broker::bind` to publish the listening socket.
const BIND_TIMEOUT: Duration = Duration::from_secs(5);
/// Default ceiling for any single broker round-trip in these tests.
/// Generous vs. broker turnaround, tight enough to fail fast on a
/// regression that wedges a recv loop.
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn `Broker::run` on a worker thread, return the (socket path,
/// stop-flag, join handle). Call `shutdown(stop, h)` to set the
/// `AtomicBool` and join — dropping the `Arc` alone won't signal the
/// worker, since the loop reads the flag via `load(...)`.
fn spawn_broker() -> (PathBuf, Arc<AtomicBool>, thread::JoinHandle<()>) {
    spawn_broker_with(|_| {})
}

/// Variant that runs `setup` on the freshly-bound broker before the
/// poll loop starts. Used by tests that need to mutate broker state
/// (e.g. fast-forward the peer-id allocator).
fn spawn_broker_with<F>(setup: F) -> (PathBuf, Arc<AtomicBool>, thread::JoinHandle<()>)
where
    F: FnOnce(&mut Broker) + Send + 'static,
{
    let path = unique_socket_path("ubusd-smoke");
    #[allow(unused_mut)]
    let mut cfg = Config {
        socket_path: path.to_str().unwrap().into(),
        ..Default::default()
    };
    // In-process peers carry the test process's real (non-root) uid,
    // which the always-active ACL gate would default-deny. The socket
    // harness spoofs root via LD_PRELOAD; mirror that here so these
    // pre-ACL smokes keep exercising the routing paths, not the gate.
    // Tests that specifically want a non-root peer use
    // `spawn_broker_with_uid`.
    #[cfg(feature = "testing")]
    {
        cfg.peer_uid_override = Some(0);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let path_clone = path.clone();
    let h = thread::spawn(move || {
        let mut broker = Broker::bind(cfg).expect("broker bind");
        setup(&mut broker);
        while !stop_clone.load(Ordering::Relaxed) {
            broker.poll_once(50).expect("poll_once");
        }
        let _ = std::fs::remove_file(&path_clone);
    });
    let deadline = Instant::now() + BIND_TIMEOUT;
    while Instant::now() < deadline {
        if UnixStream::connect(&path).is_ok() {
            return (path, stop, h);
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("broker did not bind within {BIND_TIMEOUT:?}");
}

/// Spawn a broker whose [`Config`] pins the testing write governor, so
/// one peer's TX wedges at an exact byte budget. See
/// [`slow_subscriber_evicted_when_tx_buf_caps`].
///
/// Unlike [`spawn_broker`], readiness is signalled by the broker thread
/// over a channel rather than a connect-probe: the governor targets a
/// peer by *accept index*, and a probe connection would land at index 0
/// and shift every real client down one. With the channel, the first
/// client the caller connects is deterministically accept index 0.
#[cfg(feature = "testing")]
fn spawn_broker_governed(
    governor: WriteGovernor,
) -> (PathBuf, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let path = unique_socket_path("ubusd-smoke");
    let cfg = Config {
        socket_path: path.to_str().unwrap().into(),
        tx_governor: Some(governor),
        peer_uid_override: Some(0),
        ..Default::default()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let path_clone = path.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let h = thread::spawn(move || {
        let mut broker = Broker::bind(cfg).expect("broker bind");
        // Signal after bind but before the first accept, so no probe
        // connection occupies an accept index.
        ready_tx.send(()).expect("broker ready signal");
        while !stop_clone.load(Ordering::Relaxed) {
            broker.poll_once(50).expect("poll_once");
        }
        let _ = std::fs::remove_file(&path_clone);
    });
    ready_rx
        .recv_timeout(BIND_TIMEOUT)
        .expect("broker did not bind in time");
    (path, stop, h)
}

#[cfg(feature = "testing")]
fn spawn_broker_with_uid(uid: u32) -> (PathBuf, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let path = unique_socket_path("ubusd-monitor");
    let cfg = Config {
        socket_path: path.to_str().unwrap().into(),
        peer_uid_override: Some(uid),
        ..Default::default()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let path_clone = path.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let h = thread::spawn(move || {
        let mut broker = Broker::bind(cfg).expect("broker bind");
        ready_tx.send(()).expect("broker ready signal");
        while !stop_clone.load(Ordering::Relaxed) {
            broker.poll_once(50).expect("poll_once");
        }
        let _ = std::fs::remove_file(&path_clone);
    });
    ready_rx
        .recv_timeout(BIND_TIMEOUT)
        .expect("broker did not bind in time");
    (path, stop, h)
}

fn shutdown(stop: Arc<AtomicBool>, h: thread::JoinHandle<()>) {
    stop.store(true, Ordering::Relaxed);
    let _ = h.join();
}

#[test]
fn wake_pipe_shutdown_tag_makes_run_return() {
    let path = unique_socket_path("ubusd-wake");
    let cfg = Config {
        socket_path: path.to_str().expect("utf-8 socket path").into(),
        ..Default::default()
    };
    let (read_end, write_end) = pipe().expect("wake pipe");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let mut broker = Broker::bind(cfg).expect("broker bind");
        broker.set_wake_pipe(read_end);
        ready_tx.send(()).expect("broker ready");
        done_tx.send(broker.run()).expect("broker result receiver");
    });

    ready_rx
        .recv_timeout(BIND_TIMEOUT)
        .expect("broker did not bind in time");
    rustix::io::write(&write_end, b"T").expect("write shutdown tag");
    done_rx
        .recv_timeout(RECV_TIMEOUT)
        .expect("broker did not stop after wake tag")
        .expect("broker run");
    worker.join().expect("broker thread");
    assert!(
        !path.exists(),
        "Broker::Drop must unlink the socket after run returns"
    );
}

/// Minimal blocking transport for the smoke tests. Reuses the
/// in-tree wire codec; no rustix-only deps so the test stays
/// host-portable.
struct StdTransport {
    s: UnixStream,
    rx: Vec<u8>,
}

impl StdTransport {
    fn connect(path: &std::path::Path) -> Self {
        let s = UnixStream::connect(path).expect("connect");
        s.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        s.set_write_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        Self { s, rx: Vec::new() }
    }
}

impl ubus::transport::Transport for StdTransport {
    fn send(&mut self, frame: &Frame) -> Result<(), UbusError> {
        use std::io::Write;
        let bytes = Codec::write_frame(frame);
        self.s.write_all(&bytes).map_err(|_| UbusError::Closed)
    }

    fn recv(&mut self) -> Result<Option<Frame>, UbusError> {
        loop {
            match Codec::read_frame(&self.rx) {
                Ok((frame, n)) => {
                    self.rx.drain(..n);
                    return Ok(Some(frame));
                }
                Err(UbusError::Short { .. }) => {}
                Err(e) => return Err(e),
            }
            let mut tmp = [0u8; 1024];
            match self.s.read(&mut tmp) {
                Ok(0) => return Err(UbusError::Closed),
                Ok(n) => self.rx.extend_from_slice(&tmp[..n]),
                Err(_) => return Ok(None),
            }
        }
    }
}

/// Bounded wait for a frame on `t`. `StdTransport::recv` turns a 500
/// ms read-timeout into `Ok(None)`, so a naive `loop { if let Some(f)
/// = t.recv() ... }` would spin indefinitely against a regressed
/// broker that never sends anything — and hang the whole test suite.
/// Panic with `what` for diagnostics if the deadline elapses.
fn recv_within<T: ubus::transport::Transport>(t: &mut T, timeout: Duration, what: &str) -> Frame {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match t.recv() {
            Ok(Some(f)) => return f,
            Ok(None) => {}
            Err(e) => panic!("{what}: recv error: {e:?}"),
        }
    }
    panic!("{what}: timed out after {timeout:?}");
}

fn frame_status(frame: &Frame) -> Option<i32> {
    ubus::envelope::find(&frame.payload, ubus::envelope::UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
}

fn frame_obj_id(frame: &Frame) -> Option<u32> {
    ubus::envelope::find(&frame.payload, ubus::envelope::UbusAttr::ObjId).and_then(|a| a.as_u32())
}

fn ping_signature() -> Vec<u8> {
    let mut sig = ubus::blobmsg::BlobBuilder::new();
    sig.open_table(Some("ping"));
    sig.close_table();
    sig.finish()
}

#[cfg(feature = "testing")]
fn fd_send(peer: &FdPeer, frame: &Frame, fd: Option<rustix::fd::BorrowedFd<'_>>) {
    peer.send_frame_with_fd(&Codec::write_frame(frame), fd)
        .expect("fd frame send");
}

#[cfg(feature = "testing")]
fn fd_hello(peer: &FdPeer) -> u32 {
    let (hello, fd) = peer
        .recv_full_frame_with_fd(RECV_TIMEOUT)
        .expect("fd peer HELLO");
    assert_eq!(hello.hdr.ty, MsgType::Hello);
    assert!(fd.is_none());
    hello.hdr.peer
}

#[cfg(feature = "testing")]
fn fd_register_ping(peer: &FdPeer, seq: u16, path: &str) -> u32 {
    use ubus::envelope::{find, EnvBuilder, UbusAttr};

    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, path);
    env.push_signature(&ping_signature());
    fd_send(
        peer,
        &Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq,
                peer: 0,
            },
            payload: env.finish(),
        },
        None,
    );
    let (data, fd) = peer
        .recv_full_frame_with_fd(RECV_TIMEOUT)
        .expect("fd ADD_OBJECT DATA");
    assert_eq!(data.hdr.ty, MsgType::Data);
    assert!(fd.is_none());
    let obj = find(&data.payload, UbusAttr::ObjId)
        .and_then(|attr| attr.as_u32())
        .expect("fd ADD_OBJECT OBJID");
    let (status, fd) = peer
        .recv_full_frame_with_fd(RECV_TIMEOUT)
        .expect("fd ADD_OBJECT STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(status.hdr.seq, seq);
    assert_eq!(frame_status(&status), Some(0));
    assert!(fd.is_none());
    obj
}

#[cfg(feature = "testing")]
fn fd_invoke(seq: u16, obj: u32, data: &[u8]) -> Frame {
    use ubus::envelope::{EnvBuilder, UbusAttr};

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj);
    env.push_str(UbusAttr::Method, "ping");
    env.push_data(data);
    Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Invoke,
            seq,
            peer: obj,
        },
        payload: env.finish(),
    }
}

#[cfg(feature = "testing")]
/// An owner's STATUS reply. `caller_peer` is the id the broker stamped
/// into the forwarded INVOKE (`forwarded.hdr.peer`); the ObjId attr lets
/// `forward_owner_response` validate ownership and route the reply back.
fn fd_status(seq: u16, obj: u32, caller_peer: u32) -> Frame {
    use ubus::envelope::{EnvBuilder, UbusAttr};

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj);
    env.push_u32(UbusAttr::Status, 0);
    Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Status,
            seq,
            peer: caller_peer,
        },
        payload: env.finish(),
    }
}

#[cfg(feature = "testing")]
fn fd_pipe_reaches_eof(read_end: &rustix::fd::OwnedFd, timeout: Duration) -> bool {
    use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
    use rustix::io::Errno;

    let flags = fcntl_getfl(read_end).expect("pipe flags");
    fcntl_setfl(read_end, flags | OFlags::NONBLOCK).expect("pipe nonblocking");
    let deadline = Instant::now() + timeout;
    let mut byte = [0_u8; 1];
    while Instant::now() < deadline {
        match rustix::io::read(read_end, &mut byte) {
            Ok(0) => return true,
            Ok(_) => panic!("unexpected pipe marker"),
            Err(Errno::AGAIN) => thread::yield_now(),
            Err(e) => panic!("pipe read: {e}"),
        }
    }
    false
}

#[cfg(feature = "testing")]
#[test]
fn fd_relay_leaves_no_fd_behind_after_cycles() {
    let (path, stop, broker) = spawn_broker();
    let owner = FdPeer::connect(&path).expect("owner connect");
    let _owner_peer = fd_hello(&owner);
    let obj = fd_register_ping(&owner, 1, "smoke.fd.cycles");
    let caller = FdPeer::connect(&path).expect("caller connect");
    let _caller_peer = fd_hello(&caller);

    for seq in 10..42 {
        let (read_end, write_end) = pipe().expect("pipe");
        fd_send(&caller, &fd_invoke(seq, obj, &[]), Some(write_end.as_fd()));
        drop(write_end);
        let (forwarded, received) = owner
            .recv_full_frame_with_fd(RECV_TIMEOUT)
            .expect("forwarded INVOKE");
        assert_eq!(forwarded.hdr.ty, MsgType::Invoke);
        let received = received.expect("forwarded SCM_RIGHTS");
        rustix::io::write(&received, b"x").expect("write relayed fd");
        let mut marker = [0_u8; 1];
        assert_eq!(
            rustix::io::read(&read_end, &mut marker).expect("read marker"),
            1
        );
        assert_eq!(marker, [b'x']);
        drop(received);
        fd_send(&owner, &fd_status(seq, obj, forwarded.hdr.peer), None);
        let (reply, reply_fd) = caller
            .recv_full_frame_with_fd(RECV_TIMEOUT)
            .expect("caller STATUS");
        assert_eq!(reply.hdr.ty, MsgType::Status);
        assert!(reply_fd.is_none());
        // EOF proves every copy of this cycle's write descriptor was closed.
        // Process-wide FD counts also include concurrently running tests.
        assert!(
            fd_pipe_reaches_eof(&read_end, RECV_TIMEOUT),
            "SCM_RIGHTS relay retained a write descriptor after cycle {seq}"
        );
    }
    shutdown(stop, broker);
}

/// The write governor wedges the owner at an exact byte count. A PING
/// round-trip after each queued INVOKE keeps the caller's RX backlog bounded,
/// so only the owner's TX cap can trigger eviction.
#[cfg(feature = "testing")]
#[test]
fn fd_queued_behind_governed_tx_is_closed_on_eviction() {
    // Peer 0 is the owner. Its HELLO and ADD_OBJECT reply fit in this
    // allowance; the first large INVOKE spends the remainder and wedges its
    // tx. The fd-bearing INVOKE is then queued behind it until eviction.
    let (path, stop, broker) = spawn_broker_governed(WriteGovernor {
        peer_index: 0,
        budget_bytes: 4096,
    });
    let owner = FdPeer::connect(&path).expect("owner connect");
    let _owner_peer = fd_hello(&owner);
    let obj = fd_register_ping(&owner, 1, "smoke.fd.evict");
    let caller = FdPeer::connect(&path).expect("caller connect");
    let _caller_peer = fd_hello(&caller);
    let large = vec![b'x'; 32 * 1024];

    fd_send(&caller, &fd_invoke(10, obj, &large), None);
    let (read_end, write_end) = pipe().expect("pipe");
    fd_send(
        &caller,
        &fd_invoke(11, obj, &large),
        Some(write_end.as_fd()),
    );
    drop(write_end);
    // Pace the flood with same-connection protocol barriers. Without these,
    // both the caller RX and owner TX queues can hit their identical caps,
    // letting caller eviction prevent the descriptor-bearing request from
    // ever reaching the owner's queue.
    let flood = (2 * MAX_TX_BUF_BYTES / large.len()) as u16 + 8;
    for seq in 12..(12 + flood) {
        fd_send(&caller, &fd_invoke(seq, obj, &large), None);
        let ping_seq = seq + 1000;
        fd_send(
            &caller,
            &Frame::to_broker(
                MsgType::Ping,
                ping_seq,
                ubus::envelope::EnvBuilder::new().finish(),
            ),
            None,
        );
        loop {
            let (reply, fd) = caller
                .recv_full_frame_with_fd(RECV_TIMEOUT)
                .expect("flood barrier");
            assert!(fd.is_none());
            if reply.hdr.seq == ping_seq {
                assert_eq!(reply.hdr.ty, MsgType::Data);
                break;
            }
            // After owner eviction, later INVOKEs correctly report NOT_FOUND.
            assert_eq!(reply.hdr.seq, seq);
            assert_eq!(reply.hdr.ty, MsgType::Status);
            assert_eq!(
                frame_status(&reply),
                Some(ubus::wire::UBUS_STATUS_NOT_FOUND)
            );
        }
        let (status, fd) = caller
            .recv_full_frame_with_fd(RECV_TIMEOUT)
            .expect("flood barrier STATUS");
        assert_eq!(status.hdr.seq, ping_seq);
        assert_eq!(status.hdr.ty, MsgType::Status);
        assert_eq!(frame_status(&status), Some(0));
        assert!(fd.is_none());
    }

    assert!(
        fd_pipe_reaches_eof(&read_end, RECV_TIMEOUT),
        "evicting the stalled owner must close its queued fd"
    );
    let fresh = FdPeer::connect(&path).expect("fresh peer connect after eviction");
    assert_ne!(fd_hello(&fresh), 0, "broker remains live after eviction");
    shutdown(stop, broker);
}

fn attr_id_sequence(payload: &[u8]) -> Vec<u8> {
    let inner = ubus::envelope::unwrap(payload).expect("valid envelope");
    ubus::envelope::iter_attrs(inner).map(|a| a.id).collect()
}

#[cfg(feature = "testing")]
fn monitor_request(t: &mut StdTransport, seq: u16, method: &str) {
    use ubus::envelope::{EnvBuilder, UbusAttr};
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, UBUS_SYSTEM_OBJECT_MONITOR);
    env.push_str(UbusAttr::Method, method);
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Invoke,
            seq,
            peer: UBUS_SYSTEM_OBJECT_MONITOR,
        },
        payload: env.finish(),
    })
    .expect("monitor request send");
}

#[cfg(feature = "testing")]
fn mirror_attr(frame: &Frame, id: u8) -> &[u8] {
    ubus::envelope::iter_attrs(ubus::envelope::unwrap(&frame.payload).expect("mirror envelope"))
        .find(|attr| attr.id == id)
        .map(|attr| attr.payload)
        .expect("mirror attr")
}

#[cfg(feature = "testing")]
fn mirror_u32(frame: &Frame, id: u8) -> u32 {
    let payload = mirror_attr(frame, id);
    u32::from_be_bytes(payload.try_into().expect("u32 monitor attr"))
}

#[cfg(feature = "testing")]
fn assert_monitor(frame: &Frame, seq: u16, client: u32, ty: MsgType, send: bool) {
    assert_eq!(frame.hdr.ty, MsgType::Monitor);
    assert_eq!(frame.hdr.seq, seq);
    assert_eq!(frame.hdr.peer, 0);
    assert_eq!(mirror_u32(frame, 0), client);
    assert_eq!(mirror_u32(frame, 4), ty as u32);
    assert_eq!(mirror_attr(frame, 2), &[u8::from(send)]);
}

// ---- event-bus helpers ----------------------------------------------

/// Builtin `ubus.event` system object id (`UBUS_SYSTEM_OBJECT_EVENT`).
/// `ubus listen` / `ubus send` are INVOKEs addressed here.
const EVENT_OBJECT_ID: u32 = 1;

/// Connect and consume the broker's unsolicited HELLO, returning a
/// transport ready for application frames.
fn connect_and_hello(path: &std::path::Path) -> StdTransport {
    let mut t = StdTransport::connect(path);
    let hello = recv_within(&mut t, RECV_TIMEOUT, "unsolicited HELLO");
    assert_eq!(hello.hdr.ty, MsgType::Hello);
    t
}

/// Register a pathless (anonymous) object; returns its assigned id.
/// libubus listeners register one of these as their own identity before
/// registering on the event bus.
fn add_anonymous_object(t: &mut StdTransport, seq: u16) -> u32 {
    use ubus::envelope::EnvBuilder;
    use ubus::transport::Transport;
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq,
            peer: 0,
        },
        payload: EnvBuilder::new().finish(),
    })
    .unwrap();
    let data = recv_within(t, RECV_TIMEOUT, "anonymous ADD_OBJECT DATA");
    assert_eq!(data.hdr.ty, MsgType::Data);
    let obj = frame_obj_id(&data).expect("anonymous obj id");
    let status = recv_within(t, RECV_TIMEOUT, "anonymous ADD_OBJECT STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(frame_status(&status), Some(0));
    obj
}

/// Register a named, signature-bearing object; returns its assigned id.
fn add_named_object(t: &mut StdTransport, seq: u16, path: &str) -> u32 {
    use ubus::envelope::{EnvBuilder, UbusAttr};
    use ubus::transport::Transport;
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, path);
    env.push_signature(&ping_signature());
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq,
            peer: 0,
        },
        payload: env.finish(),
    })
    .unwrap();
    let data = recv_within(t, RECV_TIMEOUT, "named ADD_OBJECT DATA");
    assert_eq!(data.hdr.ty, MsgType::Data);
    let obj = frame_obj_id(&data).expect("named obj id");
    let status = recv_within(t, RECV_TIMEOUT, "named ADD_OBJECT STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(frame_status(&status), Some(0));
    obj
}

/// The default (empty) ACL registry must still deny named publication for a
/// non-root peer. Socket harness tests exercise this through the peercred shim;
/// keep this in-process pin so the gate cannot silently become opt-in.
#[cfg(feature = "testing")]
#[test]
fn empty_acl_default_denies_nonroot_named_add() {
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|out| out.trim().parse::<u32>().ok())
        .unwrap_or(0);
    if uid == 0 {
        eprintln!("skipping non-root ACL smoke while test process is root");
        return;
    }
    let (path, stop, handle) = spawn_broker_with_uid(uid);
    let mut t = connect_and_hello(&path);
    let mut env = ubus::envelope::EnvBuilder::new();
    env.push_str(ubus::envelope::UbusAttr::ObjPath, "smoke.acl.denied");
    env.push_signature(&ping_signature());
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq: 91,
            peer: 0,
        },
        payload: env.finish(),
    })
    .expect("send named ADD_OBJECT");
    let status = recv_within(&mut t, RECV_TIMEOUT, "default-deny ADD_OBJECT STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(frame_status(&status), Some(UBUS_STATUS_INVALID_ARGUMENT));
    shutdown(stop, handle);
}

/// `ubus listen <pattern>`: INVOKE obj 1 `register`, DATA blobmsg
/// `{object: <listener_obj>, pattern}`. Reads the STATUS(0) ack.
fn event_register(t: &mut StdTransport, seq: u16, listener_obj: u32, pattern: &str) {
    use ubus::envelope::{EnvBuilder, UbusAttr};
    use ubus::transport::Transport;
    let data = ubus::blobmsg::BlobMsgTable::build(|b| {
        b.put_i32(Some("object"), listener_obj as i32);
        b.put_str(Some("pattern"), pattern);
    });
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, EVENT_OBJECT_ID);
    env.push_str(UbusAttr::Method, "register");
    env.push_data(data.contents());
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Invoke,
            seq,
            peer: EVENT_OBJECT_ID,
        },
        payload: env.finish(),
    })
    .unwrap();
    let ack = recv_within(t, RECV_TIMEOUT, "event register STATUS");
    assert_eq!(ack.hdr.ty, MsgType::Status);
    assert_eq!(
        ack.hdr.peer, EVENT_OBJECT_ID,
        "register ack echoes the obj-1 request peer"
    );
    assert_eq!(frame_status(&ack), Some(0));
}

/// `ubus send <id> {value}`: INVOKE obj 1 `send`, DATA blobmsg
/// `{id: <event_name>, data: {value}}`. Reads the publisher's STATUS(0)
/// ack (fan-out lands on the *listeners'* sockets, not this one).
fn event_send(t: &mut StdTransport, seq: u16, event_name: &str, value: i32) {
    use ubus::envelope::{EnvBuilder, UbusAttr};
    use ubus::transport::Transport;
    let data = ubus::blobmsg::BlobMsgTable::build(|b| {
        b.put_str(Some("id"), event_name);
        b.open_table(Some("data"));
        b.put_i32(Some("value"), value);
        b.close_table();
    });
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, EVENT_OBJECT_ID);
    env.push_str(UbusAttr::Method, "send");
    env.push_data(data.contents());
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Invoke,
            seq,
            peer: EVENT_OBJECT_ID,
        },
        payload: env.finish(),
    })
    .unwrap();
    let ack = recv_within(t, RECV_TIMEOUT, "event send STATUS");
    assert_eq!(ack.hdr.ty, MsgType::Status);
    assert_eq!(frame_status(&ack), Some(0));
}

/// Assert the shape of a broker event fan-out INVOKE: `hdr.peer == 0`,
/// attrs `[ObjId(listener's own), Method(event name), Data]`.
fn assert_event_fanout(frame: &Frame, listener_obj: u32, event_name: &str, what: &str) {
    use ubus::envelope::{find, UbusAttr};
    assert_eq!(frame.hdr.ty, MsgType::Invoke, "{what} type");
    assert_eq!(frame.hdr.peer, 0, "{what} hdr.peer is 0");
    assert_eq!(
        attr_id_sequence(&frame.payload),
        vec![
            UbusAttr::ObjId as u8,
            UbusAttr::Method as u8,
            UbusAttr::Data as u8,
        ],
        "{what} attr order [ObjId, Method, Data]"
    );
    assert_eq!(
        frame_obj_id(frame),
        Some(listener_obj),
        "{what} ObjId is the listener's own object"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Method).and_then(|a| a.as_str()),
        Some(event_name),
        "{what} event name"
    );
}

/// The `Data` attr payload (blobmsg contents) of an event fan-out.
fn event_payload(frame: &Frame) -> &[u8] {
    ubus::envelope::find(&frame.payload, ubus::envelope::UbusAttr::Data)
        .map(|a| a.payload)
        .unwrap_or(&[])
}

fn expected_process_user_group() -> (Option<String>, Option<String>) {
    #[cfg(target_os = "linux")]
    {
        (
            user_name(unsafe { libc::getuid() }),
            group_name(unsafe { libc::getgid() }),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        (None, None)
    }
}

#[cfg(target_os = "linux")]
fn user_name(uid: libc::uid_t) -> Option<String> {
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; nss_buf_size(libc::_SC_GETPW_R_SIZE_MAX)];
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let pwd = unsafe { pwd.assume_init() };
    c_string(pwd.pw_name)
}

#[cfg(target_os = "linux")]
fn group_name(gid: libc::gid_t) -> Option<String> {
    let mut grp = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; nss_buf_size(libc::_SC_GETGR_R_SIZE_MAX)];
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            grp.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let grp = unsafe { grp.assume_init() };
    c_string(grp.gr_name)
}

#[cfg(target_os = "linux")]
fn nss_buf_size(name: libc::c_int) -> usize {
    let n = unsafe { libc::sysconf(name) };
    if n > 0 {
        n as usize
    } else {
        16 * 1024
    }
}

#[cfg(target_os = "linux")]
fn c_string(ptr: *const libc::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

#[cfg(feature = "testing")]
#[test]
fn monitor_add_receives_mirror_of_own_ack() {
    let (path, stop, h) = spawn_broker_with_uid(0);
    let mut monitor = StdTransport::connect(&path);
    let hello = recv_within(&mut monitor, RECV_TIMEOUT, "monitor HELLO");
    let monitor_id = hello.hdr.peer;
    monitor_request(&mut monitor, 7, "add");
    let mirror = recv_within(&mut monitor, RECV_TIMEOUT, "monitor add-ack mirror");
    assert_monitor(&mirror, 1, monitor_id, MsgType::Status, true);
    assert_eq!(attr_id_sequence(&mirror.payload), vec![0, 1, 3, 4, 2, 5]);
    assert_eq!(mirror_u32(&mirror, 1), UBUS_SYSTEM_OBJECT_MONITOR);
    assert_eq!(mirror_u32(&mirror, 3), 7);
    assert_eq!(
        mirror_attr(&mirror, 5),
        &[0x01, 0x00, 0x00, 0x08, 0, 0, 0, 0]
    );
    let ack = recv_within(&mut monitor, RECV_TIMEOUT, "monitor add STATUS");
    assert_eq!(ack.hdr.ty, MsgType::Status);
    assert_eq!(frame_status(&ack), Some(0));
    shutdown(stop, h);
}

#[cfg(feature = "testing")]
#[test]
fn monitor_mirrors_second_client_traffic_bidirectionally() {
    use ubus::transport::Transport;

    let (path, stop, h) = spawn_broker_with_uid(0);
    let mut monitor = connect_and_hello(&path);
    monitor_request(&mut monitor, 1, "add");
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "add mirror");
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "add ack");
    let mut client = StdTransport::connect(&path);
    let hello = recv_within(&mut client, RECV_TIMEOUT, "client HELLO");
    client
        .send(&Frame::to_broker(
            MsgType::Ping,
            9,
            ubus::envelope::EnvBuilder::new().finish(),
        ))
        .unwrap();
    let _ = recv_within(&mut client, RECV_TIMEOUT, "PING DATA");
    let _ = recv_within(&mut client, RECV_TIMEOUT, "PING STATUS");
    for (seq, ty, send) in [
        (2, MsgType::Hello, true),
        (3, MsgType::Ping, false),
        (4, MsgType::Data, true),
        (5, MsgType::Status, true),
    ] {
        let frame = recv_within(&mut monitor, RECV_TIMEOUT, "traffic mirror");
        assert_monitor(&frame, seq, hello.hdr.peer, ty, send);
    }
    shutdown(stop, h);
}

#[cfg(feature = "testing")]
#[test]
fn monitor_remove_stops_mirroring_and_re_add_resets_seq() {
    use ubus::transport::Transport;

    let (path, stop, h) = spawn_broker_with_uid(0);
    let mut monitor = StdTransport::connect(&path);
    let monitor_id = recv_within(&mut monitor, RECV_TIMEOUT, "monitor HELLO")
        .hdr
        .peer;
    monitor_request(&mut monitor, 1, "add");
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "add mirror");
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "add ack");
    let mut client = connect_and_hello(&path);
    let hello_mirror = recv_within(&mut monitor, RECV_TIMEOUT, "client HELLO mirror");
    assert_eq!(hello_mirror.hdr.ty, MsgType::Monitor);
    monitor_request(&mut monitor, 2, "remove");
    let remove_in = recv_within(&mut monitor, RECV_TIMEOUT, "remove inbound mirror");
    assert_monitor(&remove_in, 3, monitor_id, MsgType::Invoke, false);
    let remove_ack = recv_within(&mut monitor, RECV_TIMEOUT, "remove ack");
    assert_eq!(frame_status(&remove_ack), Some(0));
    client
        .send(&Frame::to_broker(
            MsgType::Ping,
            3,
            ubus::envelope::EnvBuilder::new().finish(),
        ))
        .unwrap();
    let _ = recv_within(&mut client, RECV_TIMEOUT, "PING DATA after remove");
    let _ = recv_within(&mut client, RECV_TIMEOUT, "PING STATUS after remove");
    assert!(
        monitor.recv().unwrap().is_none(),
        "remove must stop mirrors"
    );
    monitor_request(&mut monitor, 4, "add");
    let mirror = recv_within(&mut monitor, RECV_TIMEOUT, "re-add mirror");
    assert_eq!(mirror.hdr.seq, 1);
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "re-add ack");
    shutdown(stop, h);
}

#[cfg(feature = "testing")]
#[test]
fn monitor_add_denied_for_nonroot() {
    use ubus::transport::Transport;

    let (path, stop, h) = spawn_broker_with_uid(1000);
    let mut denied = connect_and_hello(&path);
    monitor_request(&mut denied, 1, "add");
    let denied_ack = recv_within(&mut denied, RECV_TIMEOUT, "denied monitor ack");
    assert_eq!(frame_status(&denied_ack), Some(6));
    let mut traffic = connect_and_hello(&path);
    traffic
        .send(&Frame::to_broker(
            MsgType::Ping,
            2,
            ubus::envelope::EnvBuilder::new().finish(),
        ))
        .unwrap();
    assert_eq!(
        recv_within(&mut traffic, RECV_TIMEOUT, "PING DATA").hdr.ty,
        MsgType::Data
    );
    assert_eq!(
        recv_within(&mut traffic, RECV_TIMEOUT, "PING STATUS")
            .hdr
            .ty,
        MsgType::Status
    );
    assert!(
        denied.recv().unwrap().is_none(),
        "denied peer must not mirror traffic"
    );
    shutdown(stop, h);
}

#[cfg(feature = "testing")]
#[test]
fn monitor_disconnect_cleanup_keeps_broker_live() {
    use ubus::transport::Transport;

    let (path, stop, h) = spawn_broker_with_uid(0);
    let mut monitor = connect_and_hello(&path);
    monitor_request(&mut monitor, 1, "add");
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "add mirror");
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "add ack");
    drop(monitor);
    let mut traffic = connect_and_hello(&path);
    traffic
        .send(&Frame::to_broker(
            MsgType::Ping,
            2,
            ubus::envelope::EnvBuilder::new().finish(),
        ))
        .unwrap();
    assert_eq!(
        recv_within(&mut traffic, RECV_TIMEOUT, "live DATA").hdr.ty,
        MsgType::Data
    );
    assert_eq!(
        recv_within(&mut traffic, RECV_TIMEOUT, "live STATUS")
            .hdr
            .ty,
        MsgType::Status
    );
    shutdown(stop, h);
}

#[cfg(feature = "testing")]
#[test]
fn slow_monitor_evicted_when_tx_buf_caps() {
    use ubus::transport::Transport;

    let (path, stop, h) = spawn_broker_governed(WriteGovernor {
        peer_index: 0,
        budget_bytes: 8 * 1024,
    });
    let mut monitor = connect_and_hello(&path);
    monitor_request(&mut monitor, 1, "add");
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "add mirror");
    let _ = recv_within(&mut monitor, RECV_TIMEOUT, "add ack");
    let mut traffic = connect_and_hello(&path);
    let mut flood_env = ubus::envelope::EnvBuilder::new();
    flood_env.push_bytes_id(7, &vec![b'x'; 64 * 1024]);
    let payload = flood_env.finish();
    for seq in 10..30 {
        traffic
            .send(&Frame::to_broker(MsgType::Ping, seq, payload.clone()))
            .unwrap();
        assert_eq!(
            recv_within(&mut traffic, RECV_TIMEOUT, "flood DATA").hdr.ty,
            MsgType::Data
        );
        assert_eq!(
            recv_within(&mut traffic, RECV_TIMEOUT, "flood STATUS")
                .hdr
                .ty,
            MsgType::Status
        );
    }
    monitor
        .s
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + RECV_TIMEOUT;
    let mut eof = false;
    while Instant::now() < deadline {
        match monitor.s.read(&mut buf) {
            Ok(0) => {
                eof = true;
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                eof = true;
                break;
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("monitor drain: {e:?}"),
        }
    }
    assert!(
        eof,
        "slow monitor must be evicted at tx cap {MAX_TX_BUF_BYTES}"
    );
    traffic
        .send(&Frame::to_broker(
            MsgType::Ping,
            99,
            ubus::envelope::EnvBuilder::new().finish(),
        ))
        .unwrap();
    let _ = recv_within(&mut traffic, RECV_TIMEOUT, "live DATA");
    let _ = recv_within(&mut traffic, RECV_TIMEOUT, "live STATUS");
    shutdown(stop, h);
}

#[test]
fn hello_assigns_peer_id_above_system_range() {
    let (path, stop, h) = spawn_broker();
    // The broker pushes HELLO unsolicited at accept (matches upstream
    // ubusd), so the first recv on a fresh connection is the assigned
    // peer-id frame — no client HELLO send required.
    let mut t = StdTransport::connect(&path);
    let hello = recv_within(&mut t, RECV_TIMEOUT, "unsolicited HELLO");
    assert_eq!(hello.hdr.ty, MsgType::Hello);
    assert!(
        hello.hdr.peer >= FIRST_PEER_ID.get(),
        "assigned peer id {} below FIRST_PEER_ID",
        hello.hdr.peer
    );
    shutdown(stop, h);
}

#[test]
fn connect_pushes_hello_unsolicited() {
    let (path, stop, h) = spawn_broker();
    // No client send first — the broker greets us.
    let mut t = StdTransport::connect(&path);
    let hello = recv_within(&mut t, RECV_TIMEOUT, "unsolicited HELLO");
    assert_eq!(hello.hdr.ty, MsgType::Hello);
    assert_eq!(hello.hdr.seq, 0, "unsolicited HELLO uses seq=0");
    assert!(hello.hdr.peer >= FIRST_PEER_ID.get());
    shutdown(stop, h);
}

#[test]
fn redundant_client_hello_replies_with_invalid_command_status() {
    use ubus::transport::Transport;

    let (path, stop, h) = spawn_broker();
    let mut t = StdTransport::connect(&path);
    // Consume the unsolicited HELLO first.
    let hello = recv_within(&mut t, RECV_TIMEOUT, "unsolicited HELLO");
    assert_eq!(hello.hdr.ty, MsgType::Hello);

    // Upstream `ubusd` replies to a redundant client HELLO with
    // `STATUS = UBUS_STATUS_INVALID_COMMAND` (1) on the HELLO's seq;
    // the in-tree broker mirrors that exactly. Send HELLO+PING
    // back-to-back and expect the redundant HELLO status, then PING's
    // DATA echo followed by STATUS(0). 4-byte empty envelope on each
    // so the broker's stream decoder doesn't desync on a back-to-back
    // frame.
    let env = ubus::envelope::EnvBuilder::new().finish();
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Hello,
            seq: 11,
            peer: hello.hdr.peer,
        },
        payload: env.clone(),
    })
    .unwrap();
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Ping,
            seq: 12,
            peer: hello.hdr.peer,
        },
        payload: env,
    })
    .unwrap();

    let hello_reply = recv_within(&mut t, RECV_TIMEOUT, "redundant-HELLO STATUS");
    assert_eq!(hello_reply.hdr.ty, MsgType::Status);
    assert_eq!(hello_reply.hdr.seq, 11);
    assert_eq!(hello_reply.hdr.peer, hello.hdr.peer);
    let s = ubus::envelope::find(&hello_reply.payload, ubus::envelope::UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .unwrap_or(0);
    // 1 = UBUS_STATUS_INVALID_COMMAND (libubus' enum, not POSIX errno).
    assert_eq!(
        s, UBUS_STATUS_INVALID_COMMAND,
        "redundant HELLO must yield UBUS_STATUS_INVALID_COMMAND"
    );

    let ping_data = recv_within(&mut t, RECV_TIMEOUT, "PING DATA");
    assert_eq!(ping_data.hdr.ty, MsgType::Data);
    assert_eq!(ping_data.hdr.seq, 12);
    assert_eq!(ping_data.hdr.peer, hello.hdr.peer);
    assert_eq!(
        ping_data.payload,
        ubus::envelope::EnvBuilder::new().finish()
    );

    let ping_status = recv_within(&mut t, RECV_TIMEOUT, "PING STATUS");
    assert_eq!(ping_status.hdr.ty, MsgType::Status);
    assert_eq!(ping_status.hdr.seq, 12);
    assert_eq!(ping_status.hdr.peer, hello.hdr.peer);
    let s = ubus::envelope::find(&ping_status.payload, ubus::envelope::UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .unwrap_or(-1);
    assert_eq!(s, 0, "PING must succeed");
    shutdown(stop, h);
}

#[test]
fn lookup_unknown_returns_not_found_or_status_err() {
    let (path, stop, h) = spawn_broker();
    let mut client = UbusClient::connect(StdTransport::connect(&path)).expect("hello");
    match client.lookup("does.not.exist") {
        Err(UbusError::Malformed(_)) | Err(UbusError::Status(_)) => {}
        other => panic!("expected Malformed or Status, got {other:?}"),
    }
    shutdown(stop, h);
}

#[test]
fn add_object_then_lookup_returns_assigned_id() {
    use ubus::envelope::{find, EnvBuilder, UbusAttr};

    let (path, stop, h) = spawn_broker();

    // Manually drive ADD_OBJECT: UbusConnection::register loops
    // forever waiting on a paired thread, which we don't have here.
    let mut t = StdTransport::connect(&path);
    use ubus::transport::Transport;
    // Consume the unsolicited HELLO that the broker pushes on accept.
    let hello = recv_within(&mut t, RECV_TIMEOUT, "unsolicited HELLO");
    assert_eq!(hello.hdr.ty, MsgType::Hello);
    assert!(hello.hdr.peer >= FIRST_PEER_ID.get());

    // ADD_OBJECT path = "smoke.target".
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "smoke.target");
    env.push_signature(&ping_signature());
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq: 2,
            peer: 0,
        },
        payload: env.finish(),
    })
    .unwrap();
    // Upstream shape: DATA(OBJID) carries the assigned id, then a plain
    // STATUS(0). The id rides the DATA frame — the STATUS has none.
    let data = recv_within(&mut t, RECV_TIMEOUT, "ADD_OBJECT DATA");
    assert_eq!(data.hdr.ty, MsgType::Data);
    assert_eq!(data.hdr.peer, 0, "ADD_OBJECT DATA must echo request peer");
    let obj_id = find(&data.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .expect("ObjId attr present in ADD_OBJECT DATA reply");
    assert!(obj_id >= 2);
    let status = recv_within(&mut t, RECV_TIMEOUT, "ADD_OBJECT STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(
        status.hdr.peer, 0,
        "ADD_OBJECT reply must echo request peer"
    );
    let s = find(&status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32);
    assert_eq!(s, Some(0), "ADD_OBJECT STATUS must be 0");

    // LOOKUP same path → should find the object we just registered.
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "smoke.target");
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Lookup,
            seq: 3,
            peer: 0,
        },
        payload: env.finish(),
    })
    .unwrap();
    // Expect: DATA frame(s) carrying ObjId, then STATUS=0.
    let mut found_id: Option<u32> = None;
    let mut got_status = false;
    let deadline = Instant::now() + Duration::from_millis(500);
    while !got_status && Instant::now() < deadline {
        match t.recv().unwrap() {
            Some(f) if f.hdr.seq == 3 => match f.hdr.ty {
                MsgType::Data => {
                    assert_eq!(f.hdr.peer, 0, "LOOKUP DATA must echo request peer");
                    if let Some(id) = find(&f.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()) {
                        found_id = Some(id);
                    }
                }
                MsgType::Status => {
                    got_status = true;
                    assert_eq!(f.hdr.peer, 0, "LOOKUP STATUS must echo request peer");
                    let s = find(&f.payload, UbusAttr::Status)
                        .and_then(|a| a.as_u32())
                        .map(|u| u as i32)
                        .unwrap_or(-1);
                    assert_eq!(s, 0, "expected STATUS=0 terminator");
                }
                _ => {}
            },
            _ => {}
        }
    }
    assert_eq!(found_id, Some(obj_id), "LOOKUP returned the registered id");

    shutdown(stop, h);
}

#[test]
fn pathless_add_object_is_anonymous_list_hidden_and_subscribable() {
    use ubus::envelope::{find, EnvBuilder, UbusAttr};
    use ubus::transport::Transport;

    let (path, stop, h) = spawn_broker();
    let mut t = StdTransport::connect(&path);
    let hello = recv_within(&mut t, RECV_TIMEOUT, "unsolicited HELLO");
    assert_eq!(hello.hdr.ty, MsgType::Hello);

    // Pathless ADD_OBJECT: libubus subscribers use this anonymous
    // object as their own identity for notifications.
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq: 20,
            peer: 0,
        },
        payload: EnvBuilder::new().finish(),
    })
    .unwrap();
    let data = recv_within(&mut t, RECV_TIMEOUT, "pathless ADD_OBJECT DATA");
    assert_eq!(data.hdr.ty, MsgType::Data);
    assert_eq!(data.hdr.seq, 20);
    let anon_obj = frame_obj_id(&data).expect("anonymous OBJID in DATA");
    assert_ne!(anon_obj, 0);
    let status = recv_within(&mut t, RECV_TIMEOUT, "pathless ADD_OBJECT STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(status.hdr.seq, 20);
    assert_eq!(frame_status(&status), Some(0));

    // Register one named publisher so list-all has a positive control
    // and SUBSCRIBE has a target.
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "smoke.publisher");
    env.push_signature(&ping_signature());
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq: 21,
            peer: 0,
        },
        payload: env.finish(),
    })
    .unwrap();
    let data = recv_within(&mut t, RECV_TIMEOUT, "named ADD_OBJECT DATA");
    assert_eq!(data.hdr.ty, MsgType::Data);
    let named_obj = frame_obj_id(&data).expect("named OBJID in DATA");
    let status = recv_within(&mut t, RECV_TIMEOUT, "named ADD_OBJECT STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(frame_status(&status), Some(0));

    // LOOKUP list-all must not publish anonymous ids.
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Lookup,
            seq: 22,
            peer: 0,
        },
        payload: EnvBuilder::new().finish(),
    })
    .unwrap();
    let deadline = Instant::now() + RECV_TIMEOUT;
    let mut saw_named = false;
    let mut got_status = false;
    while Instant::now() < deadline && !got_status {
        match t.recv().unwrap() {
            Some(f) if f.hdr.seq == 22 => match f.hdr.ty {
                MsgType::Data => {
                    let id = find(&f.payload, UbusAttr::ObjId)
                        .and_then(|a| a.as_u32())
                        .expect("LOOKUP DATA OBJID");
                    assert_ne!(id, anon_obj, "anonymous object leaked into list-all LOOKUP");
                    saw_named |= id == named_obj;
                }
                MsgType::Status => {
                    assert_eq!(frame_status(&f), Some(0));
                    got_status = true;
                }
                _ => {}
            },
            Some(_) | None => {}
        }
    }
    assert!(saw_named, "list-all LOOKUP must include the named object");
    assert!(got_status, "list-all LOOKUP must terminate with STATUS(0)");

    // Upstream SUBSCRIBE shape: OBJID is the subscriber's own object;
    // TARGET / hdr.peer identify the publisher being subscribed to.
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, anon_obj);
    env.push_u32(UbusAttr::Target, named_obj);
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Subscribe,
            seq: 23,
            peer: named_obj,
        },
        payload: env.finish(),
    })
    .unwrap();
    let active = recv_within(&mut t, RECV_TIMEOUT, "SUBSCRIBE Active");
    assert_eq!(active.hdr.ty, MsgType::Notify);
    assert_eq!(active.hdr.seq, 1);
    assert_eq!(active.hdr.peer, 0);
    assert_eq!(frame_obj_id(&active), Some(named_obj));
    assert_eq!(
        find(&active.payload, UbusAttr::Active).map(|a| a.payload),
        Some(&[1][..])
    );

    let status = recv_within(&mut t, RECV_TIMEOUT, "SUBSCRIBE STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(status.hdr.seq, 23);
    assert_eq!(frame_status(&status), Some(0));

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, named_obj);
    env.push_str(UbusAttr::Method, "fanout");
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Notify,
            seq: 24,
            peer: named_obj,
        },
        payload: env.finish(),
    })
    .unwrap();
    let ack = recv_within(&mut t, RECV_TIMEOUT, "NOTIFY ACK");
    assert_eq!(ack.hdr.ty, MsgType::Status);
    assert_eq!(ack.hdr.seq, 24);
    assert_eq!(ack.hdr.peer, named_obj);
    assert_eq!(
        attr_id_sequence(&ack.payload),
        vec![
            UbusAttr::ObjId as u8,
            UbusAttr::Subscribers as u8,
            UbusAttr::Status as u8,
        ],
        "NOTIFY ack attr order"
    );
    assert_eq!(frame_obj_id(&ack), Some(named_obj));
    assert_eq!(frame_status(&ack), Some(0));

    let fanout = recv_within(&mut t, RECV_TIMEOUT, "NOTIFY fan-out");
    assert_eq!(fanout.hdr.ty, MsgType::Invoke);
    assert_eq!(fanout.hdr.seq, 24);
    assert_eq!(fanout.hdr.peer, hello.hdr.peer);
    let (expected_user, expected_group) = expected_process_user_group();
    let mut expected_attrs = vec![UbusAttr::ObjId as u8, UbusAttr::Method as u8];
    if expected_user.is_some() {
        expected_attrs.push(UbusAttr::User as u8);
    }
    if expected_group.is_some() {
        expected_attrs.push(UbusAttr::Group as u8);
    }
    assert_eq!(
        attr_id_sequence(&fanout.payload),
        expected_attrs,
        "NOTIFY fan-out attr order"
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(anon_obj),
        "fan-out ObjId must be restamped to subscriber object"
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::Method).and_then(|a| a.as_str()),
        Some("fanout")
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::User).and_then(|a| a.as_str()),
        expected_user.as_deref()
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::Group).and_then(|a| a.as_str()),
        expected_group.as_deref()
    );

    shutdown(stop, h);
}

#[test]
fn untyped_named_object_is_lookup_invisible() {
    use ubus::envelope::{find, EnvBuilder, UbusAttr};
    use ubus::transport::Transport;

    let (path, stop, h) = spawn_broker();
    let mut t = StdTransport::connect(&path);
    let hello = recv_within(&mut t, RECV_TIMEOUT, "unsolicited HELLO");
    assert_eq!(hello.hdr.ty, MsgType::Hello);

    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "smoke.untyped");
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq: 30,
            peer: 0,
        },
        payload: env.finish(),
    })
    .unwrap();
    let data = recv_within(&mut t, RECV_TIMEOUT, "untyped ADD_OBJECT DATA");
    assert_eq!(data.hdr.ty, MsgType::Data);
    assert!(frame_obj_id(&data).is_some());
    let status = recv_within(&mut t, RECV_TIMEOUT, "untyped ADD_OBJECT STATUS");
    assert_eq!(status.hdr.ty, MsgType::Status);
    assert_eq!(frame_status(&status), Some(0));

    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "smoke.untyped");
    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Lookup,
            seq: 31,
            peer: 0,
        },
        payload: env.finish(),
    })
    .unwrap();
    let exact = recv_within(&mut t, RECV_TIMEOUT, "exact untyped LOOKUP STATUS");
    assert_eq!(exact.hdr.ty, MsgType::Status);
    assert_eq!(exact.hdr.seq, 31);
    assert_eq!(frame_status(&exact), Some(0));

    t.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Lookup,
            seq: 32,
            peer: 0,
        },
        payload: EnvBuilder::new().finish(),
    })
    .unwrap();
    let deadline = Instant::now() + RECV_TIMEOUT;
    while Instant::now() < deadline {
        match t.recv().unwrap() {
            Some(f) if f.hdr.seq == 32 && f.hdr.ty == MsgType::Data => {
                let path = find(&f.payload, UbusAttr::ObjPath).and_then(|a| a.as_str());
                assert_ne!(
                    path,
                    Some("smoke.untyped"),
                    "untyped object leaked into list-all"
                );
            }
            Some(f) if f.hdr.seq == 32 && f.hdr.ty == MsgType::Status => {
                assert_eq!(frame_status(&f), Some(0));
                shutdown(stop, h);
                return;
            }
            Some(_) | None => {}
        }
    }
    panic!("list-all LOOKUP did not terminate with STATUS(0)");
}

/// Hand-roll a frame whose declared envelope length exceeds
/// `MAX_MSG_LEN`. The codec's frame-size cap must close the
/// peer rather than let an attacker stream arbitrarily large frames
/// past the rx-buffer cap. EOF on the next read is the only
/// observable signal — the broker has no admin/log tap.
#[test]
fn oversized_frame_closes_peer() {
    let (path, stop, h) = spawn_broker();

    let mut s = UnixStream::connect(&path).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    // Drain the unsolicited HELLO so the broker's stream decoder is
    // sitting at a frame boundary when our oversized frame lands.
    let mut rx = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => panic!("EOF before HELLO"),
            Ok(n) => {
                rx.extend_from_slice(&tmp[..n]);
                if Codec::read_frame(&rx).is_ok() {
                    break;
                }
            }
            Err(e) => panic!("read HELLO: {e:?}"),
        }
    }
    let (hello, n) = Codec::read_frame(&rx).expect("HELLO");
    rx.drain(..n);
    assert_eq!(hello.hdr.ty, MsgType::Hello);

    // Hand-rolled frame: 8-byte header + 4-byte declared envelope
    // length (id_len) > MAX_MSG_LEN, then enough zero bytes for the
    // codec to see the declared body before rejecting it.
    let attr_len: u32 = (MAX_MSG_LEN as u32) + 1;
    let aligned = (attr_len as usize + 3) & !3;
    let hdr = Header {
        version: PROTO_VERSION,
        ty: MsgType::Ping,
        seq: 42,
        peer: 0,
    };
    let mut frame = Vec::with_capacity(HEADER_SIZE + aligned);
    frame.extend_from_slice(&hdr.encode());
    frame.extend_from_slice(&attr_len.to_be_bytes());
    frame.resize(HEADER_SIZE + aligned, 0);

    let _ = s.write_all(&frame);

    // Trail with a valid PING. A regression that tried to resync past
    // the oversized frame instead of closing would emit a STATUS reply
    // for this PING; the close path proves the channel is dead, not
    // just paused.
    let ping = Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Ping,
            seq: 99,
            peer: 0,
        },
        payload: Vec::new(),
    };
    let _ = s.write_all(&Codec::write_frame(&ping));

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got_eof = false;
    let mut rx_after = Vec::new();
    while Instant::now() < deadline {
        match s.read(&mut tmp) {
            Ok(0) => {
                got_eof = true;
                break;
            }
            Ok(n) => {
                rx_after.extend_from_slice(&tmp[..n]);
                while let Ok((f, n)) = Codec::read_frame(&rx_after) {
                    rx_after.drain(..n);
                    assert!(
                        !(f.hdr.ty == MsgType::Status && f.hdr.seq == 99),
                        "broker resynced past oversized frame and replied to follow-up PING"
                    );
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            // Closing with unread input may produce ECONNRESET on Linux.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                got_eof = true;
                break;
            }
            Err(e) => panic!("read after oversized: {e:?}"),
        }
    }
    assert!(got_eof, "broker must close peer after oversized frame");

    shutdown(stop, h);
}

/// A frame whose header fails codec validation (here: unknown message
/// type) hits the `Err(e)` branch of the broker's frame reader —
/// distinct from the size-cap path covered by
/// `oversized_frame_closes_peer`. The broker must close the peer
/// rather than spin or attempt to drain past the bad header.
#[test]
fn malformed_frame_closes_peer() {
    let (path, stop, h) = spawn_broker();

    let mut s = UnixStream::connect(&path).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    // Drain the unsolicited HELLO so the broker's stream decoder is
    // sitting at a frame boundary when our malformed frame lands.
    let mut rx = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => panic!("EOF before HELLO"),
            Ok(n) => {
                rx.extend_from_slice(&tmp[..n]);
                if Codec::read_frame(&rx).is_ok() {
                    break;
                }
            }
            Err(e) => panic!("read HELLO: {e:?}"),
        }
    }
    let (hello, n) = Codec::read_frame(&rx).expect("HELLO");
    rx.drain(..n);
    assert_eq!(hello.hdr.ty, MsgType::Hello);

    // 8-byte header with byte 1 = 99 (no such MsgType). Nonzero
    // version bytes are tolerated for upstream parity; unknown types
    // remain genuinely undecodable. We send only the header so the
    // broker's read loop reaches the frame decoder the moment our
    // bytes land.
    let mut bad = [0u8; HEADER_SIZE];
    bad[0] = PROTO_VERSION;
    bad[1] = 99;
    s.write_all(&bad).expect("send malformed frame");

    // Trail with a valid PING. A regression that tried to resync past
    // the bad header would emit a STATUS reply; the close path proves
    // the channel is dead.
    let ping = Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Ping,
            seq: 99,
            peer: 0,
        },
        payload: Vec::new(),
    };
    let _ = s.write_all(&Codec::write_frame(&ping));

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got_eof = false;
    let mut rx_after = Vec::new();
    while Instant::now() < deadline {
        match s.read(&mut tmp) {
            Ok(0) => {
                got_eof = true;
                break;
            }
            Ok(n) => {
                rx_after.extend_from_slice(&tmp[..n]);
                while let Ok((f, n)) = Codec::read_frame(&rx_after) {
                    rx_after.drain(..n);
                    assert!(
                        !(f.hdr.ty == MsgType::Status && f.hdr.seq == 99),
                        "broker resynced past malformed frame and replied to follow-up PING"
                    );
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            // On Linux, a write to a socket whose remote already shut
            // down can fault the read with ECONNRESET (RST received)
            // instead of clean EOF. Either is a valid "broker closed
            // me" signal for this test.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                got_eof = true;
                break;
            }
            Err(e) => panic!("read after malformed: {e:?}"),
        }
    }
    assert!(got_eof, "broker must close peer after malformed frame");

    shutdown(stop, h);
}

/// A subscriber that stops draining its socket must be evicted by the
/// per-peer `MAX_TX_BUF_BYTES` cap so a single hung peer can't balloon
/// the broker's heap.
///
/// Determinism comes from the `testing` write governor
/// ([`Config::tx_governor`]): it hands the subscriber exactly `BUDGET`
/// bytes — comfortably above its HELLO + subscribe handshake and far
/// below any kernel socket buffer — then reports `WouldBlock` on every
/// further send, with zero dependence on kernel buffer size, pacing, or
/// scheduling. From there each forwarded NOTIFY buffers whole into the
/// subscriber's `tx_buf` until the cap is crossed and the broker closes
/// it. The subscriber therefore receives *exactly* `BUDGET` bytes and
/// then EOF — the precise, timing-free shed point. The publisher floods
/// in lockstep (send one NOTIFY, await its ack) so the broker dispatches
/// each frame before the next arrives and no rx buffer overflows —
/// again, no sleeps.
#[cfg(feature = "testing")]
#[test]
fn slow_subscriber_evicted_when_tx_buf_caps() {
    use ubus::envelope::{find, EnvBuilder, UbusAttr};

    // Read frames off a raw stream against a persistent rx buffer,
    // returning the first that satisfies `pred`. Every byte pulled off
    // the socket is added to `*bytes` so callers can pin exact delivery
    // totals.
    fn read_frame_until(
        s: &mut UnixStream,
        rx: &mut Vec<u8>,
        bytes: &mut usize,
        pred: impl Fn(&Frame) -> bool,
        what: &str,
    ) -> Frame {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tmp = [0u8; 4096];
        loop {
            while let Ok((f, n)) = Codec::read_frame(rx) {
                rx.drain(..n);
                if pred(&f) {
                    return f;
                }
            }
            if Instant::now() >= deadline {
                panic!("{what}: timed out");
            }
            match s.read(&mut tmp) {
                Ok(0) => panic!("{what}: EOF"),
                Ok(n) => {
                    *bytes += n;
                    rx.extend_from_slice(&tmp[..n]);
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => panic!("{what}: read {e:?}"),
            }
        }
    }

    // Governor budget — see the doc comment.
    const BUDGET: usize = 8 * 1024;
    // Each forwarded NOTIFY carries a 24 KiB body (>24 KiB on the wire), so
    // 96 frames past the budget overshoot the 2 MiB tx cap and force an
    // eviction with margin.
    const FLOOD: u16 = 96;

    // Subscriber connects second (accept index 1); publisher is 0.
    let (path, stop, broker_h) = spawn_broker_governed(WriteGovernor {
        peer_index: 1,
        budget_bytes: BUDGET,
    });

    // --- Publisher (peer 0): register a named object to fan out from.
    let mut publisher = UnixStream::connect(&path).expect("publisher connect");
    publisher
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut pub_rx = Vec::new();
    let mut pub_bytes = 0usize;
    read_frame_until(
        &mut publisher,
        &mut pub_rx,
        &mut pub_bytes,
        |f| f.hdr.ty == MsgType::Hello,
        "publisher HELLO",
    );
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "example.flood");
    publisher
        .write_all(&Codec::write_frame(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq: 1,
                peer: 0,
            },
            payload: env.finish(),
        }))
        .expect("publisher AddObject");
    let pub_data = read_frame_until(
        &mut publisher,
        &mut pub_rx,
        &mut pub_bytes,
        |f| f.hdr.seq == 1 && f.hdr.ty == MsgType::Data,
        "publisher AddObject DATA",
    );
    let pub_obj = find(&pub_data.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .expect("publisher obj id");
    read_frame_until(
        &mut publisher,
        &mut pub_rx,
        &mut pub_bytes,
        |f| f.hdr.seq == 1 && f.hdr.ty == MsgType::Status,
        "publisher AddObject STATUS",
    );

    // --- Subscriber (peer 1): anon object + SUBSCRIBE, read the acks,
    // then stop reading entirely. From here the broker can hand it only
    // the BUDGET bytes before wedging.
    let mut sub = UnixStream::connect(&path).expect("subscriber connect");
    sub.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut sub_rx = Vec::new();
    let mut sub_bytes = 0usize;
    read_frame_until(
        &mut sub,
        &mut sub_rx,
        &mut sub_bytes,
        |f| f.hdr.ty == MsgType::Hello,
        "subscriber HELLO",
    );
    // Anonymous ADD_OBJECT — libubus registers one before SUBSCRIBE.
    sub.write_all(&Codec::write_frame(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq: 10,
            peer: 0,
        },
        payload: EnvBuilder::new().finish(),
    }))
    .expect("subscriber anon AddObject");
    let anon_data = read_frame_until(
        &mut sub,
        &mut sub_rx,
        &mut sub_bytes,
        |f| f.hdr.seq == 10 && f.hdr.ty == MsgType::Data,
        "subscriber anon DATA",
    );
    let own_obj = find(&anon_data.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .expect("subscriber anon obj id");
    read_frame_until(
        &mut sub,
        &mut sub_rx,
        &mut sub_bytes,
        |f| f.hdr.seq == 10 && f.hdr.ty == MsgType::Status,
        "subscriber anon STATUS",
    );
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, own_obj);
    env.push_u32(UbusAttr::Target, pub_obj);
    sub.write_all(&Codec::write_frame(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Subscribe,
            seq: 11,
            peer: pub_obj,
        },
        payload: env.finish(),
    }))
    .expect("subscriber SUBSCRIBE");
    let sub_ack = read_frame_until(
        &mut sub,
        &mut sub_rx,
        &mut sub_bytes,
        |f| f.hdr.seq == 11 && f.hdr.ty == MsgType::Status,
        "subscriber SUBSCRIBE ack",
    );
    assert_eq!(
        frame_status(&sub_ack),
        Some(0),
        "SUBSCRIBE must be accepted"
    );
    // Subscriber now stops reading. `sub_rx` still holds nothing beyond
    // the drained handshake; every later byte stays in the kernel until
    // the final drain.

    // --- Flood NOTIFY in lockstep: send one, await its ack, repeat.
    let body = vec![b'x'; 24 * 1024];
    let body_str = std::str::from_utf8(&body).unwrap();
    for i in 0..FLOOD {
        let seq = 1000u16.wrapping_add(i);
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, pub_obj);
        env.push_str(UbusAttr::Method, "fanout");
        env.push_str(UbusAttr::Data, body_str);
        publisher
            .write_all(&Codec::write_frame(&Frame {
                hdr: Header {
                    version: PROTO_VERSION,
                    ty: MsgType::Notify,
                    seq,
                    peer: pub_obj,
                },
                payload: env.finish(),
            }))
            .expect("publisher NOTIFY send");
        // The broker acks every NOTIFY (Status echoing its seq) after
        // dispatching the fan-out — awaiting it is our flow control.
        read_frame_until(
            &mut publisher,
            &mut pub_rx,
            &mut pub_bytes,
            |f| f.hdr.seq == seq && f.hdr.ty == MsgType::Status,
            "publisher NOTIFY ack",
        );
    }

    // --- Drain the subscriber: it must be evicted (EOF) after having
    // received EXACTLY the governor budget — no kernel-buffer slop.
    let mut drainbuf = [0u8; 16 * 1024];
    let mut bytes_read = 0usize;
    let mut got_eof = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match sub.read(&mut drainbuf) {
            Ok(0) => {
                got_eof = true;
                break;
            }
            Ok(n) => {
                bytes_read += n;
                sub_bytes += n;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                got_eof = true;
                break;
            }
            Err(e) => panic!("subscriber drain: {e:?}"),
        }
    }
    assert!(
        got_eof,
        "slow subscriber must be evicted (EOF); drained {bytes_read} B, tx cap {MAX_TX_BUF_BYTES} B"
    );
    // `sub_bytes` counts every byte the broker ever delivered to the
    // subscriber — the handshake it read during setup plus the flood
    // bytes drained here. The governor caps that total at exactly
    // BUDGET, so this is the timing-free eviction pin.
    assert_eq!(
        sub_bytes, BUDGET,
        "governor delivers exactly its {BUDGET}-byte budget then wedges; a different \
         total means kernel buffering — not the governor — set the shed point"
    );

    // --- Publisher stays live: its own PING still round-trips.
    publisher
        .write_all(&Codec::write_frame(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Ping,
                seq: 9999,
                peer: 0,
            },
            payload: EnvBuilder::new().finish(),
        }))
        .expect("publisher PING send");
    read_frame_until(
        &mut publisher,
        &mut pub_rx,
        &mut pub_bytes,
        |f| f.hdr.seq == 9999 && f.hdr.ty == MsgType::Status,
        "publisher PING STATUS after flood",
    );

    // --- A fresh peer still handshakes: the broker is not wedged.
    let mut fresh = UnixStream::connect(&path).expect("fresh connect");
    fresh
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut fresh_rx = Vec::new();
    let mut fresh_bytes = 0usize;
    read_frame_until(
        &mut fresh,
        &mut fresh_rx,
        &mut fresh_bytes,
        |f| f.hdr.ty == MsgType::Hello,
        "fresh peer HELLO",
    );

    shutdown(stop, broker_h);
}

/// Soak variant of the tx-cap eviction pin driven by real kernel
/// backpressure (shrunk SO_RCVBUF + pacing) rather than the write
/// governor. Kept `#[ignore]` because it depends on kernel buffer
/// sizing and scheduling and can flake under CPU contention; the
/// governor test above is the deterministic pin. Run on demand with
/// `--ignored` to exercise the real-kernel interplay.
#[ignore = "kernel-timing dependent soak; deterministic pin is slow_subscriber_evicted_when_tx_buf_caps"]
#[test]
fn slow_subscriber_evicted_kernel_backpressure_soak() {
    use ubus::envelope::{find, EnvBuilder, UbusAttr};

    let (path, stop, broker_h) = spawn_broker();

    // Publisher: AddObject "example.flood" on a raw socket (with no
    // write timeout — the flood relies on kernel sndbuf backpressure
    // making writes block, which is exactly what a short
    // write_timeout would mis-classify as failure), then blast NOTIFY
    // frames with a 4 KiB body.
    let path_pub = path.clone();
    let (pub_id_tx, pub_id_rx) = std::sync::mpsc::channel::<u32>();
    let (pub_done_tx, pub_done_rx) = std::sync::mpsc::channel::<()>();
    // Deterministic sequencing: the publisher must not start flooding
    // until the slow subscriber is attached, or a fast flood can finish
    // and reap the publisher's object before SUBSCRIBE lands.
    let (flood_go_tx, flood_go_rx) = std::sync::mpsc::channel::<()>();
    let publisher = thread::spawn(move || -> Result<(), String> {
        let mut s = UnixStream::connect(&path_pub).map_err(|e| format!("pub connect: {e:?}"))?;
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("pub rd timeout: {e:?}"))?;
        // No write timeout: see comment on the publisher thread.
        let mut rx = Vec::new();
        let mut tmp = [0u8; 1024];
        // Drain HELLO.
        let _hello = loop {
            match Codec::read_frame(&rx) {
                Ok((f, n)) => {
                    rx.drain(..n);
                    break f;
                }
                Err(_) => match s.read(&mut tmp) {
                    Ok(0) => return Err("pub EOF before HELLO".into()),
                    Ok(n) => rx.extend_from_slice(&tmp[..n]),
                    Err(e) => return Err(format!("pub read HELLO: {e:?}")),
                },
            }
        };
        let mut env = EnvBuilder::new();
        env.push_str(UbusAttr::ObjPath, "example.flood");
        let add_frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq: 1,
                peer: 0,
            },
            payload: env.finish(),
        };
        s.write_all(&Codec::write_frame(&add_frame))
            .map_err(|e| format!("pub send AddObject: {e:?}"))?;
        let status = loop {
            match Codec::read_frame(&rx) {
                Ok((f, n)) => {
                    rx.drain(..n);
                    break f;
                }
                Err(_) => match s.read(&mut tmp) {
                    Ok(0) => return Err("pub EOF before AddObject ack".into()),
                    Ok(n) => rx.extend_from_slice(&tmp[..n]),
                    Err(e) => return Err(format!("pub read AddObject ack: {e:?}")),
                },
            }
        };
        let pub_obj = find(&status.payload, UbusAttr::ObjId)
            .and_then(|a| a.as_u32())
            .ok_or_else(|| "pub obj id missing".to_string())?;
        pub_id_tx
            .send(pub_obj)
            .map_err(|_| "pub id tx".to_string())?;

        flood_go_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "flood-go signal timeout".to_string())?;

        // Build a single NOTIFY payload with a 4 KiB body string; the
        // hot loop just reuses the same envelope bytes.
        let body = vec![b'x'; 4096];
        let body_str = std::str::from_utf8(&body).unwrap();
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, pub_obj);
        env.push_str(UbusAttr::Method, "fanout");
        env.push_str(UbusAttr::Data, body_str);
        let payload = env.finish();

        // Hard upper bound so a regression that fails to evict
        // doesn't OOM the test runner. ~2000 frames × 4 KiB ≈ 8 MiB.
        // Sleep briefly every 32 frames so the broker's poll loop has
        // a chance to drain its rx_buf — without the pause, sustained
        // writes can outrun the broker's dispatch rate and the broker
        // closes the publisher under MAX_RX_BUF_BYTES instead.
        let mut seq: u16 = 0;
        for i in 0..2000 {
            if pub_done_rx.try_recv().is_ok() {
                return Ok(());
            }
            if i > 0 && i % 32 == 0 {
                thread::sleep(Duration::from_millis(1));
            }
            let frame = Frame {
                hdr: Header {
                    version: PROTO_VERSION,
                    ty: MsgType::Notify,
                    seq,
                    peer: pub_obj,
                },
                payload: payload.clone(),
            };
            seq = seq.wrapping_add(1);
            if s.write_all(&Codec::write_frame(&frame)).is_err() {
                return Ok(());
            }
        }
        Ok(())
    });
    let publisher_obj = pub_id_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("publisher obj id");

    // Slow peer: connect, drain HELLO, SUBSCRIBE, read the STATUS=0
    // ack, then stop draining. The broker's enqueue path short-
    // circuits to direct send on the first frame, so the kernel
    // sndbuf must fill before tx_buf accumulates. Shrink the kernel
    // rcv-buf so backpressure trips reliably across platforms (Linux
    // defaults are large enough that an unbounded rcv-buf would
    // absorb the whole publisher burst before tx_buf hit MAX_*).
    let mut s = UnixStream::connect(&path).expect("slow connect");
    {
        use std::os::fd::AsRawFd;
        let raw = s.as_raw_fd();
        let bfd = unsafe { rustix::fd::BorrowedFd::borrow_raw(raw) };
        let _ = rustix::net::sockopt::set_socket_recv_buffer_size(bfd, 4096);
    }
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut rx = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => panic!("slow peer EOF before HELLO"),
            Ok(n) => {
                rx.extend_from_slice(&tmp[..n]);
                if Codec::read_frame(&rx).is_ok() {
                    break;
                }
            }
            Err(e) => panic!("slow read HELLO: {e:?}"),
        }
    }
    let (_hello, n) = Codec::read_frame(&rx).expect("HELLO");
    rx.drain(..n);

    // Upstream-parity SUBSCRIBE requires ATTR_OBJID to be an object
    // the subscriber itself owns; register an anonymous one first,
    // exactly like libubus' ubus_register_subscriber does.
    let add = Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq: 10,
            peer: 0,
        },
        payload: EnvBuilder::new().finish(),
    };
    s.write_all(&Codec::write_frame(&add))
        .expect("anon add send");
    let mut own_obj = 0u32;
    let add_deadline = Instant::now() + Duration::from_secs(5);
    'anon_add: while Instant::now() < add_deadline {
        while let Ok((f, n)) = Codec::read_frame(&rx) {
            rx.drain(..n);
            if f.hdr.seq == 10 && f.hdr.ty == MsgType::Data {
                own_obj = find(&f.payload, ubus::envelope::UbusAttr::ObjId)
                    .and_then(|a| a.as_u32())
                    .expect("anon add DATA objid");
            }
            if f.hdr.seq == 10 && f.hdr.ty == MsgType::Status {
                break 'anon_add;
            }
        }
        match s.read(&mut tmp) {
            Ok(0) => panic!("slow peer EOF during anon add"),
            Ok(n) => rx.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("slow read anon add: {e:?}"),
        }
    }
    assert_ne!(own_obj, 0, "anonymous ADD_OBJECT objid");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, own_obj);
    env.push_u32(UbusAttr::Target, publisher_obj);
    let sub_frame = Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Subscribe,
            seq: 11,
            peer: publisher_obj,
        },
        payload: env.finish(),
    };
    s.write_all(&Codec::write_frame(&sub_frame))
        .expect("subscribe send");

    let ack_deadline = Instant::now() + Duration::from_secs(5);
    let mut got_ack = false;
    while Instant::now() < ack_deadline && !got_ack {
        while let Ok((f, n)) = Codec::read_frame(&rx) {
            rx.drain(..n);
            if f.hdr.ty == MsgType::Status && f.hdr.seq == 11 {
                let s = find(&f.payload, ubus::envelope::UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .unwrap_or(-1);
                assert_eq!(s, 0, "subscribe rejected: status={s}");
                got_ack = true;
                flood_go_tx.send(()).expect("flood-go send");
                break;
            }
        }
        if got_ack {
            break;
        }
        match s.read(&mut tmp) {
            Ok(0) => panic!("slow peer EOF before SUBSCRIBE ack"),
            Ok(n) => rx.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("slow read SUBSCRIBE ack: {e:?}"),
        }
    }
    assert!(got_ack, "did not receive SUBSCRIBE ack");

    // Stop draining for ~150 ms so the kernel rcv buffer fills and
    // backpressure migrates back to the broker's tx_buf.
    thread::sleep(Duration::from_millis(150));

    // Now drain everything. Either the broker's enqueue path will
    // have hit MAX_TX_BUF_BYTES and evicted us, or the publisher's
    // 2000-frame upper bound will have completed without eviction
    // (regression). Sized read buffer so we drain quickly.
    let mut drain = [0u8; 16 * 1024];
    let evict_deadline = Instant::now() + Duration::from_secs(15);
    let mut got_eof = false;
    let mut bytes_read: usize = 0;
    while Instant::now() < evict_deadline {
        match s.read(&mut drain) {
            Ok(0) => {
                got_eof = true;
                break;
            }
            Ok(n) => bytes_read += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("slow drain: {e:?}"),
        }
    }
    let _ = pub_done_tx.send(());
    let _ = publisher.join();

    assert!(
        got_eof,
        "slow subscriber must be evicted; broker tx_buf cap is {MAX_TX_BUF_BYTES} B; we read {bytes_read} B without EOF"
    );
    // Eviction by `MAX_TX_BUF_BYTES` happens after the broker has
    // queued at most kernel-sndbuf + tx_buf-cap worth of frames. The
    // publisher pushes up to 8 MiB; if EOF arrives at >= ~half of
    // that, it isn't tx_buf eviction — it's the publisher running to
    // completion, the broker tearing down via `MAX_RX_BUF_BYTES`, or
    // any other path that closes both ends.
    let evict_ceiling = MAX_TX_BUF_BYTES * 4 + 1024 * 1024;
    assert!(
        bytes_read < evict_ceiling,
        "EOF arrived at {bytes_read} B (>= {evict_ceiling} B); too late to be MAX_TX_BUF_BYTES eviction"
    );

    shutdown(stop, broker_h);
}

/// Pin the graceful refusal path: once the u32 peer-id space is
/// exhausted, the broker drops the freshly-accepted fd (the client
/// sees an immediate EOF) instead of panicking and tearing down all
/// other peers. Achieved by fast-forwarding `PeerTable.next_id` to
/// `u32::MAX` before any accept happens.
#[test]
fn exhausted_peer_id_space_refuses_new_connections_gracefully() {
    use std::num::NonZeroU32;

    let (path, stop, h) = spawn_broker_with(|broker| {
        let max = NonZeroU32::new(u32::MAX).unwrap();
        broker.__test_peers_mut().__test_set_next_id(max);
    });

    // First connection: broker bumps next_id from u32::MAX → overflow,
    // returns PeerIdExhausted, drops the fd.
    let mut s = UnixStream::connect(&path).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tmp = [0u8; 16];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got_eof = false;
    while Instant::now() < deadline {
        match s.read(&mut tmp) {
            Ok(0) => {
                got_eof = true;
                break;
            }
            // Spec violation only — but a regression that still sent
            // HELLO before realising id space was exhausted should
            // surface the divergence loudly.
            Ok(n) => panic!("got {n} unexpected bytes after exhaustion"),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("read after exhausted accept: {e:?}"),
        }
    }
    assert!(
        got_eof,
        "broker must drop the fd when peer id space is exhausted"
    );

    // Second connect: still refused, broker is still alive (poll_once
    // didn't return Err — the worker thread keeps looping).
    let mut s2 = UnixStream::connect(&path).expect("second connect must still bind");
    s2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut got_second_eof = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match s2.read(&mut tmp) {
            Ok(0) => {
                got_second_eof = true;
                break;
            }
            Ok(_) => break,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("second read: {e:?}"),
        }
    }
    assert!(
        got_second_eof,
        "broker should still be alive and still refusing fresh peers"
    );

    shutdown(stop, h);
}

/// Backpressured peer drains all buffered bytes once it resumes
/// reading. Distinct from `slow_subscriber_evicted_when_tx_buf_caps`
/// (which forces a permanent close): here the volume is well under
/// `MAX_TX_BUF_BYTES`, so the broker must accumulate in `tx_buf` and
/// flush via `drain_tx` once the kernel rcv-buf has space again. A
/// regression that fails to re-arm POLLOUT (or fails to actually
/// flush from `tx_buf`) leaves bytes stranded.
#[test]
fn drain_tx_flushes_buffered_bytes_after_backpressure() {
    use ubus::envelope::{EnvBuilder, UbusAttr};

    let (path, stop, h) = spawn_broker();

    fn drain_hello(s: &mut UnixStream) -> Frame {
        let mut rx = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            match s.read(&mut tmp) {
                Ok(0) => panic!("EOF before HELLO"),
                Ok(n) => {
                    rx.extend_from_slice(&tmp[..n]);
                    if let Ok((f, n)) = Codec::read_frame(&rx) {
                        let _ = rx.drain(..n);
                        return f;
                    }
                }
                Err(e) => panic!("read HELLO: {e:?}"),
            }
        }
    }

    let mut a = UnixStream::connect(&path).expect("A connect");
    a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    a.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let _hello_a = drain_hello(&mut a);

    // Owner-response forwarding only relays DATA frames whose ObjId
    // resolves to an object the sender owns (upstream
    // `ubusd_handle_response` semantics) — register A as an owner so
    // the backpressure frames below are forwardable at all.
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "smoke.drain");
    let add = Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::AddObject,
            seq: 100,
            peer: 0,
        },
        payload: env.finish(),
    };
    a.write_all(&Codec::write_frame(&add))
        .expect("A add_object");
    // DATA(OBJID) + STATUS(0) can land in one read; keep a shared
    // buffer across both frames (drain_hello's per-call buffer would
    // discard the trailing STATUS bytes).
    let mut reply_frames = Vec::new();
    let mut rx = Vec::new();
    let mut tmp = [0u8; 1024];
    while reply_frames.len() < 2 {
        match a.read(&mut tmp) {
            Ok(0) => panic!("EOF before ADD_OBJECT replies"),
            Ok(n) => {
                rx.extend_from_slice(&tmp[..n]);
                while let Ok((f, consumed)) = Codec::read_frame(&rx) {
                    rx.drain(..consumed);
                    reply_frames.push(f);
                }
            }
            Err(e) => panic!("read ADD_OBJECT replies: {e:?}"),
        }
    }
    assert_eq!(reply_frames[0].hdr.ty, MsgType::Data);
    assert_eq!(reply_frames[1].hdr.ty, MsgType::Status);
    let a_obj_id = ubus::envelope::find(&reply_frames[0].payload, UbusAttr::ObjId)
        .and_then(|attr| attr.as_u32())
        .expect("ObjId in ADD_OBJECT DATA reply");

    let mut b = UnixStream::connect(&path).expect("B connect");
    b.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    {
        use std::os::fd::AsRawFd;
        let raw = b.as_raw_fd();
        let bfd = unsafe { rustix::fd::BorrowedFd::borrow_raw(raw) };
        // Shrink B's kernel rcv-buf so backpressure trips well
        // before tx_buf hits the cap. Linux defaults are large
        // enough (~208 KiB) that an unbounded rcv-buf absorbs
        // 32 frames × 4 KiB without ever forcing the broker to
        // buffer.
        let _ = rustix::net::sockopt::set_socket_recv_buffer_size(bfd, 4096);
    }
    let hello_b = drain_hello(&mut b);
    let b_peer = hello_b.hdr.peer;

    // A → broker → B: enough frames to overrun the kernel rcv buffer,
    // forcing the broker to keep some bytes in tx_buf. Stays well
    // under MAX_TX_BUF_BYTES so the eviction path doesn't
    // fire — the regression we're catching is "tx_buf accumulates
    // but never flushes".
    let body = vec![b'x'; 4000];
    let body_str = std::str::from_utf8(&body).unwrap();
    let mut total_sent = 0usize;
    for seq in 0..32u16 {
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, a_obj_id);
        env.push_str(UbusAttr::Data, body_str);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Data,
                seq,
                peer: b_peer,
            },
            payload: env.finish(),
        };
        let bytes = Codec::write_frame(&frame);
        total_sent += bytes.len();
        a.write_all(&bytes).expect("A send");
    }

    // Pause so backpressure builds up: B's rcv-buf fills, broker
    // accumulates the rest in tx_buf.
    thread::sleep(Duration::from_millis(150));

    // Now drain B and confirm all 32 frames arrive. A POLLOUT-re-arm
    // regression (or a `drain_tx` that fails to flush) would leave
    // the trailing frames permanently buffered.
    let want_frames = 32;
    let mut rx = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut tmp = [0u8; 8192];
    let mut frames_seen = 0;
    while frames_seen < want_frames && Instant::now() < deadline {
        match b.read(&mut tmp) {
            Ok(0) => panic!("B closed unexpectedly at {} bytes", rx.len()),
            Ok(n) => {
                rx.extend_from_slice(&tmp[..n]);
                while let Ok((_f, consumed)) = Codec::read_frame(&rx) {
                    rx.drain(..consumed);
                    frames_seen += 1;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("B drain: {e:?}"),
        }
    }
    assert_eq!(
        frames_seen, want_frames,
        "broker must drain all {want_frames} buffered frames; sent {total_sent} B"
    );

    shutdown(stop, h);
}

/// A `ubus listen` registration receives `ubus send` fan-out on its own
/// socket: an INVOKE `hdr.peer=0` stamped with the listener's own object
/// id, the event name in Method, and the inner `data` table in Data.
#[test]
fn event_register_then_send_fans_out_to_listener() {
    let (path, stop, h) = spawn_broker();

    let mut listener = connect_and_hello(&path);
    let listener_obj = add_anonymous_object(&mut listener, 1);
    event_register(&mut listener, 2, listener_obj, "*");

    // Publisher on a separate connection so self-suppression doesn't fire.
    let mut publisher = connect_and_hello(&path);
    event_send(&mut publisher, 10, "example.probe.event", 7);

    let fanout = recv_within(&mut listener, RECV_TIMEOUT, "event fan-out");
    assert_event_fanout(&fanout, listener_obj, "example.probe.event", "send fan-out");
    assert_eq!(
        fanout.hdr.seq, 1,
        "first fan-out delivery carries global seq 1"
    );
    // Delivered Data is the inner `data` table only, not the {id,data}
    // wrapper the publisher sent.
    assert_eq!(
        ubus::blobmsg::lookup(event_payload(&fanout), "value").and_then(|r| r.as_i32()),
        Some(7),
        "fan-out Data carries the inner data table"
    );

    shutdown(stop, h);
}

/// A connection that registers a named object then drops WITHOUT a
/// REMOVE_OBJECT still makes the broker broadcast `ubus.object.remove`
/// during disconnect reap — same teardown-during-reap class as the
/// Active=0 lesson. The paired `ubus.object.add` fires on registration.
#[test]
fn disconnect_reap_broadcasts_object_remove() {
    let (path, stop, h) = spawn_broker();

    let mut listener = connect_and_hello(&path);
    let listener_obj = add_anonymous_object(&mut listener, 1);
    event_register(&mut listener, 2, listener_obj, "ubus.object.*");

    let gone_obj;
    {
        // Second connection registers a named object then drops.
        let mut gone = connect_and_hello(&path);
        gone_obj = add_named_object(&mut gone, 10, "example.gone");

        let add = recv_within(&mut listener, RECV_TIMEOUT, "ubus.object.add");
        assert_event_fanout(&add, listener_obj, "ubus.object.add", "object.add");
        assert_eq!(add.hdr.seq, 1, "object.add carries global seq 1");
        let add_data = event_payload(&add);
        assert_eq!(
            ubus::blobmsg::lookup(add_data, "path").and_then(|r| r.as_str()),
            Some("example.gone")
        );
        assert_eq!(
            ubus::blobmsg::lookup(add_data, "id")
                .and_then(|r| r.as_i32())
                .map(|v| v as u32),
            Some(gone_obj),
            "object.add id is the registered object id"
        );
        // drop `gone` → disconnect reap mints ubus.object.remove
    }

    let remove = recv_within(&mut listener, RECV_TIMEOUT, "ubus.object.remove");
    assert_event_fanout(&remove, listener_obj, "ubus.object.remove", "object.remove");
    assert_eq!(
        remove.hdr.seq, 2,
        "object.remove continues the global seq counter"
    );
    let rm_data = event_payload(&remove);
    assert_eq!(
        ubus::blobmsg::lookup(rm_data, "path").and_then(|r| r.as_str()),
        Some("example.gone")
    );
    assert_eq!(
        ubus::blobmsg::lookup(rm_data, "id")
            .and_then(|r| r.as_i32())
            .map(|v| v as u32),
        Some(gone_obj),
        "object.remove id is the reaped object id"
    );

    shutdown(stop, h);
}

/// Fan-out sequence numbers come from ONE broker-global counter (not
/// per-client): two listeners delivered in pattern-key order get seqs 1
/// then 2, and a later single-listener event continues at 3.
#[test]
fn event_fanout_uses_one_global_seq_counter() {
    let (path, stop, h) = spawn_broker();

    // Catch-all listener (pattern key "") and a "example." prefix
    // listener on separate connections. Upstream walks its pattern AVL
    // in key order, so "" is delivered before "example.".
    let mut all = connect_and_hello(&path);
    let all_obj = add_anonymous_object(&mut all, 1);
    event_register(&mut all, 2, all_obj, "*");

    let mut prefix = connect_and_hello(&path);
    let prefix_obj = add_anonymous_object(&mut prefix, 1);
    event_register(&mut prefix, 2, prefix_obj, "example.*");

    let mut publisher = connect_and_hello(&path);

    // Matching event: both listeners; catch-all first (seq 1), prefix
    // second (seq 2).
    event_send(&mut publisher, 10, "example.probe.event", 7);
    let all_first = recv_within(&mut all, RECV_TIMEOUT, "catch-all fan-out 1");
    assert_event_fanout(&all_first, all_obj, "example.probe.event", "catch-all 1");
    assert_eq!(all_first.hdr.seq, 1, "catch-all delivered first (seq 1)");
    let prefix_first = recv_within(&mut prefix, RECV_TIMEOUT, "prefix fan-out 1");
    assert_event_fanout(&prefix_first, prefix_obj, "example.probe.event", "prefix 1");
    assert_eq!(prefix_first.hdr.seq, 2, "prefix delivered second (seq 2)");

    // Non-matching-for-prefix event: only catch-all receives it, and the
    // global counter continues at 3 (proving it is not per-event).
    event_send(&mut publisher, 11, "other.event", 9);
    let all_second = recv_within(&mut all, RECV_TIMEOUT, "catch-all fan-out 2");
    assert_event_fanout(&all_second, all_obj, "other.event", "catch-all 2");
    assert_eq!(
        all_second.hdr.seq, 3,
        "global seq continues across events (not per-event)"
    );

    shutdown(stop, h);
}
