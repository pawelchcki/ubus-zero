//! Listener + per-peer I/O glue.
//!
//! Single-threaded poll loop over the listen fd plus every accepted
//! peer's fd. NONBLOCK throughout — the broker never blocks except
//! inside the `poll(2)` syscall in [`Broker::poll_once`].
//!
//! The pure protocol decisions live in [`crate::routing`]; this module
//! is the thin shell that:
//! 1. accepts new peers on the listen fd,
//! 2. drains framed bytes out of each peer's socket into [`Frame`]s,
//! 3. hands each frame to `routing::dispatch`,
//! 4. applies the returned [`Action`]s back to the per-peer tx
//!    buffers + reaper queue,
//! 5. drains tx buffers, re-arming POLLOUT for any peer that
//!    short-wrote.

use std::collections::HashSet;
use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;

#[cfg(any(test, not(target_os = "linux")))]
use rustix::event::{poll, PollFd};
use rustix::event::{PollFlags, Timespec};
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::io::Errno;
use rustix::io::{IoSlice, IoSliceMut};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketAddrUnix,
};

use ubus::blobmsg::BlobMsgTable;
use ubus::error::UbusError;
use ubus::wire::{Codec, Frame, FrameRef};

use crate::acl::{apply_reload, AclRegistry};
use crate::peer::{Peer, MAX_RX_BUF_BYTES, MAX_TX_BUF_BYTES, RX_FD_WINDOW};
#[cfg(feature = "testing")]
use crate::registry::FIRST_PEER_ID;
use crate::registry::{
    EventRegistry, MonitorRegistry, ObjectId, ObjectRegistry, PeerId, PeerTable, SubscriberRegistry,
};
use crate::reply;
use crate::routing::{self, Action};

#[derive(Clone, Debug)]
pub struct Config {
    /// Path the listener binds at. Recreated on bind — a stale
    /// socket from a previous run is unlinked first.
    pub socket_path: String,
    /// chmod for the bound socket. `0o666` matches real ubusd so
    /// unprivileged peers (luci, hotplug scripts) can connect.
    pub socket_mode: u32,
    /// listen(2) backlog. 64 matches OpenWrt's default.
    pub backlog: u32,
    /// Optional ACL directory. No directory keeps the ACL gate active with
    /// an empty (therefore non-root default-deny) registry.
    pub acl_dir: Option<String>,
    /// Testing-only write governor. When set, the broker delivers at
    /// most `budget_bytes` to the targeted peer and then reports
    /// `WouldBlock` on every further send, so its tx backlog grows by
    /// exact frame sizes to a deterministic `MAX_TX_BUF_BYTES`
    /// eviction — no kernel-buffer or scheduling dependence. See
    /// [`WriteGovernor`].
    #[cfg(feature = "testing")]
    pub tx_governor: Option<WriteGovernor>,
    /// Testing-only accepted-peer uid override. In-process tests cannot use
    /// the credential interposer, so this pins monitor authorization.
    #[cfg(feature = "testing")]
    pub peer_uid_override: Option<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_path: "/var/run/ubus.sock".into(),
            socket_mode: 0o666,
            backlog: 64,
            acl_dir: None,
            #[cfg(feature = "testing")]
            tx_governor: None,
            #[cfg(feature = "testing")]
            peer_uid_override: None,
        }
    }
}

/// Testing-only per-peer TX throttle. Pins the exact byte at which a
/// stuck subscriber stops draining so the deterministic backpressure
/// test asserts an exact eviction point. See [`Config::tx_governor`].
#[cfg(feature = "testing")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteGovernor {
    /// 0-based accept index of the peer to throttle. Peer ids are
    /// handed out from [`crate::registry::FIRST_PEER_ID`] in accept
    /// order, so index `k` is the `k`-th accepted connection.
    pub peer_index: u32,
    /// Bytes the broker may hand to that peer before every subsequent
    /// send to it reports `WouldBlock`.
    pub budget_bytes: usize,
}

#[derive(Debug)]
pub enum BrokerError {
    Io(String),
    /// `PeerTable::insert` ran out of u32 ids (~4B accepts in a single
    /// broker session). Surfaced separately from `ObjectIdExhausted`
    /// so log triage can tell which axis tripped without parsing a
    /// `Kind` enum.
    PeerIdExhausted,
    /// `ObjectRegistry::insert` ran out of u32 obj-ids.
    ObjectIdExhausted,
}

impl core::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BrokerError::Io(s) => write!(f, "io: {s}"),
            BrokerError::PeerIdExhausted => write!(f, "peer id space exhausted"),
            BrokerError::ObjectIdExhausted => write!(f, "object id space exhausted"),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<rustix::io::Errno> for BrokerError {
    fn from(e: rustix::io::Errno) -> Self {
        // io::Error::from_raw_os_error renders the human-readable
        // strerror string ("Address already in use") rather than the
        // raw errno number, which is much more useful for log triage.
        BrokerError::Io(io::Error::from_raw_os_error(e.raw_os_error()).to_string())
    }
}

impl From<io::Error> for BrokerError {
    fn from(e: io::Error) -> Self {
        BrokerError::Io(format!("{e}"))
    }
}

impl BrokerError {
    /// Tag a syscall failure with the operation name. Without this the
    /// caller sees only "Address already in use" — useful, but not
    /// enough to know whether `socket`, `bind`, or `listen` produced
    /// it. Mirrors the `io_err("op", e)` pattern in `unix_sock.rs`.
    fn op(op: &'static str, e: rustix::io::Errno) -> Self {
        BrokerError::Io(format!(
            "{op}: {}",
            io::Error::from_raw_os_error(e.raw_os_error())
        ))
    }
}

pub struct Broker {
    config: Config,
    listen_fd: OwnedFd,
    peers: PeerTable,
    objects: ObjectRegistry,
    subs: SubscriberRegistry,
    events: EventRegistry,
    monitors: MonitorRegistry,
    acl: AclRegistry,
    acl_sequence: u32,
    wake_pipe: Option<OwnedFd>,
    shutdown: bool,
    /// peer-ids queued for close at the end of the current
    /// `poll_once`. Drained at iteration end so dispatch isn't
    /// iterating over a peer set that's mutating under it.
    pending_close: HashSet<PeerId>,
    /// Reusable scratch for `poll_once`. Cleared and refilled each
    /// tick so the steady-state allocation count is zero.
    #[cfg(any(test, not(target_os = "linux")))]
    live_ids_buf: Vec<PeerId>,
    #[cfg(target_os = "linux")]
    poller: crate::poller::Poller,
    tx_ready: HashSet<PeerId>,
    peer_revents_buf: Vec<(PeerId, PollFlags)>,
    /// Reused across peers. Grow only for a declared frame body, capped at
    /// 64 KiB, so large messages do not require one syscall per 4 KiB.
    rx_scratch: Vec<u8>,
    tx_scratch: Vec<u8>,
}

impl Broker {
    /// Bind the listener at `config.socket_path`. NONBLOCK so the
    /// poll loop's accept(2) returns AGAIN cleanly when no client is
    /// pending.
    pub fn bind(config: Config) -> Result<Self, BrokerError> {
        let acl_load = config
            .acl_dir
            .as_deref()
            .map(AclRegistry::load_dir)
            .unwrap_or_default();
        // No stale socket is the happy path. Anything else
        // (EACCES wrong-owner, EISDIR if a directory exists at the
        // path) will surface downstream as a confusing EADDRINUSE on
        // bind(), so log it now while we have the errno.
        if let Err(e) = rustix::fs::unlink(config.socket_path.as_str()) {
            if e != Errno::NOENT {
                log::warn!(
                    "ubusd: pre-bind unlink {} failed: {}; bind() may now fail",
                    config.socket_path,
                    io::Error::from_raw_os_error(e.raw_os_error()),
                );
            }
        }
        let fd = crate::net::unix_stream_socket().map_err(|e| BrokerError::op("socket", e))?;
        let addr = SocketAddrUnix::new(config.socket_path.as_str())
            .map_err(|e| BrokerError::op("addr", e))?;
        rustix::net::bind(&fd, &addr).map_err(|e| BrokerError::op("bind", e))?;
        rustix::net::listen(&fd, config.backlog as i32)
            .map_err(|e| BrokerError::op("listen", e))?;
        if let Err(e) = rustix::fs::chmod(config.socket_path.as_str(), to_mode(config.socket_mode))
        {
            log::warn!(
                "ubusd: chmod {:o} on {} failed: {e:?}; unprivileged peers may be unable to connect",
                config.socket_mode,
                config.socket_path,
            );
        }
        #[cfg(target_os = "linux")]
        let poller =
            crate::poller::Poller::new(&fd).map_err(|e| BrokerError::op("epoll_create", e))?;
        let mut broker = Self {
            config,
            listen_fd: fd,
            peers: PeerTable::new(),
            objects: ObjectRegistry::new(),
            subs: SubscriberRegistry::new(),
            events: EventRegistry::new(),
            monitors: MonitorRegistry::new(),
            acl: acl_load.registry,
            acl_sequence: u32::from(acl_load.had_candidates),
            wake_pipe: None,
            shutdown: false,
            pending_close: HashSet::new(),
            #[cfg(any(test, not(target_os = "linux")))]
            live_ids_buf: Vec::new(),
            #[cfg(target_os = "linux")]
            poller,
            tx_ready: HashSet::new(),
            peer_revents_buf: Vec::new(),
            rx_scratch: vec![0; 4096],
            tx_scratch: Vec::with_capacity(4096),
        };
        if acl_load.had_candidates {
            broker.broadcast_acl_sequence();
        }
        Ok(broker)
    }

    /// Set the read end of a self-pipe used to wake this broker. The standalone
    /// binary's signal handlers write single-byte tags to its write end;
    /// embedders that never call this retain the ordinary blocking poll loop.
    ///
    /// The read end is forced NONBLOCK here: `drain_wake_pipe` reads until
    /// AGAIN, and a blocking fd from a caller would wedge the whole poll
    /// loop on the read after the last tag byte.
    pub fn set_wake_pipe(&mut self, fd: OwnedFd) {
        if let Err(e) = rustix::fs::fcntl_setfl(&fd, rustix::fs::OFlags::NONBLOCK) {
            log::warn!("ubusd: wake pipe O_NONBLOCK failed: {e:?}; leaving pipe unset");
            return;
        }
        #[cfg(target_os = "linux")]
        {
            if let Err(error) = self.poller.add_wake(&fd) {
                log::warn!("ubusd: register wake pipe failed: {error:?}");
                return;
            }
            if let Some(old) = &self.wake_pipe {
                let _ = self.poller.remove(old);
            }
        }
        self.wake_pipe = Some(fd);
    }

    /// Run the broker until a wake-pipe shutdown tag requests a clean exit.
    pub fn run(&mut self) -> Result<(), BrokerError> {
        loop {
            self.poll_once(-1)?;
            if self.shutdown {
                return Ok(());
            }
        }
    }

    /// Test-only handle to the peer table — used by integration tests
    /// that need to fast-forward the id allocator (see
    /// `PeerTable::__test_set_next_id`).
    #[doc(hidden)]
    pub fn __test_peers_mut(&mut self) -> &mut PeerTable {
        &mut self.peers
    }

    /// One pass of the poll loop. Embed-mode call sites pass
    /// `timeout_ms = 0` so this returns immediately when there's no
    /// work, leaving the host event loop free to tick its other
    /// duties between broker polls.
    pub fn poll_once(&mut self, timeout_ms: i32) -> Result<(), BrokerError> {
        self.peer_revents_buf.clear();
        let timeout_ms = if !self.tx_ready.is_empty() || !self.pending_close.is_empty() {
            0
        } else {
            timeout_ms
        };
        let (listen_revents, wake_revents) = match self.wait_ready(timeout_ms) {
            Ok(ready) => ready,
            Err(Errno::INTR) => return Ok(()),
            Err(error) => return Err(BrokerError::op("readiness wait", error)),
        };

        if wake_revents.is_some_and(|flags| flags.contains(PollFlags::IN)) {
            self.drain_wake_pipe();
        }
        if listen_revents.intersects(PollFlags::IN | PollFlags::ERR | PollFlags::HUP) {
            self.accept_pending()?;
        }
        for i in 0..self.peer_revents_buf.len() {
            let (id, revents) = self.peer_revents_buf[i];
            if revents.contains(PollFlags::ERR) {
                // POLLERR means the kernel has a pending socket-level
                // fault (firewall reset, ICMP error). Distinct from
                // POLLHUP — a clean peer close vs. an L4 abort look
                // identical in logs otherwise.
                log::debug!("ubusd: peer {id} POLLERR, closing");
                self.pending_close.insert(id);
                continue;
            }
            // POLLHUP and POLLIN can fire together: a peer that does
            // `send(LAST_FRAME); close()` produces both at once. Drain
            // first so the final frame still dispatches; the close
            // gets scheduled either way (read_into_buf returns false
            // on EOF, drain_rx_and_dispatch routes that into
            // pending_close).
            if revents.contains(PollFlags::IN) {
                self.drain_rx_and_dispatch(id, revents.contains(PollFlags::HUP));
            }
            if revents.contains(PollFlags::HUP) {
                self.pending_close.insert(id);
            }
        }
        self.tx_ready
            .extend(self.peer_revents_buf.iter().map(|(id, _)| *id));
        let mut ready = std::mem::take(&mut self.tx_ready);
        for id in ready.drain() {
            self.drain_tx(id);
            self.sync_write_interest(id);
        }
        self.tx_ready = ready;
        let to_close: Vec<PeerId> = self.pending_close.drain().collect();
        for id in to_close {
            self.close_peer(id);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn wait_ready(&mut self, timeout_ms: i32) -> Result<(PollFlags, Option<PollFlags>), Errno> {
        self.poller.wait(
            poll_timeout(timeout_ms).as_ref(),
            &mut self.peer_revents_buf,
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn wait_ready(&mut self, timeout_ms: i32) -> Result<(PollFlags, Option<PollFlags>), Errno> {
        self.wait_poll(timeout_ms)
    }

    #[cfg(any(test, not(target_os = "linux")))]
    fn wait_poll(&mut self, timeout_ms: i32) -> Result<(PollFlags, Option<PollFlags>), Errno> {
        self.peers.live_ids_into(&mut self.live_ids_buf);
        let listen_revents;
        let wake_revents;
        {
            let mut fds: Vec<PollFd<'_>> = Vec::with_capacity(
                1 + usize::from(self.wake_pipe.is_some()) + self.live_ids_buf.len(),
            );
            fds.push(PollFd::new(&self.listen_fd, PollFlags::IN));
            if let Some(wake_pipe) = self.wake_pipe.as_ref() {
                fds.push(PollFd::new(wake_pipe, PollFlags::IN));
            }
            // Walk peer_ids manually so a vanished or fd-less peer
            // (only possible if invariants regress; non-fatal here)
            // is dropped from the poll set instead of panicking.
            self.live_ids_buf.retain(|id| {
                let Some(peer) = self.peers.get(*id) else {
                    log::error!("ubusd: peer {id} listed but not in table; skipping poll");
                    return false;
                };
                let Some(fd) = peer.fd.as_ref() else {
                    log::error!("ubusd: peer {id} has no fd; skipping poll");
                    return false;
                };
                let mut flags = PollFlags::IN;
                if peer.has_pending_tx() {
                    flags |= PollFlags::OUT;
                }
                fds.push(PollFd::new(fd, flags));
                true
            });
            let timeout_ts = poll_timeout(timeout_ms);
            match poll(&mut fds, timeout_ts.as_ref()) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            listen_revents = fds[0].revents();
            let peer_start = 1 + usize::from(self.wake_pipe.is_some());
            wake_revents = self.wake_pipe.as_ref().map(|_| fds[1].revents());
            self.peer_revents_buf.extend(
                self.live_ids_buf
                    .iter()
                    .enumerate()
                    .map(|(i, id)| (*id, fds[peer_start + i].revents())),
            );
        }

        Ok((listen_revents, wake_revents))
    }

    fn sync_write_interest(&mut self, id: PeerId) {
        #[cfg(target_os = "linux")]
        if let Some(peer) = self.peers.get_mut(id) {
            let pending = peer.has_pending_tx();
            if pending != peer.write_interest {
                if let Some(fd) = &peer.fd {
                    if let Err(error) = self.poller.writable(fd, id, pending) {
                        log::warn!("ubusd: update peer {id} readiness failed: {error:?}");
                        self.pending_close.insert(id);
                        return;
                    }
                }
                peer.write_interest = pending;
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = id;
    }

    fn drain_wake_pipe(&mut self) {
        let mut buf = [0_u8; 64];
        loop {
            let read = match self.wake_pipe.as_ref() {
                Some(fd) => rustix::io::read(fd, &mut buf),
                None => return,
            };
            match read {
                Ok(0) => return,
                Ok(n) => {
                    for tag in &buf[..n] {
                        match tag {
                            b'T' | b'I' => self.shutdown = true,
                            b'H' => self.reload_acls(),
                            unknown => {
                                log::debug!("ubusd: ignoring unknown wake-pipe tag {unknown:#x}")
                            }
                        }
                    }
                }
                Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => continue,
                Err(e) => {
                    log::warn!("ubusd: wake-pipe read failed: {e:?}");
                    return;
                }
            }
        }
    }

    fn reload_acls(&mut self) {
        let acl_load = self
            .config
            .acl_dir
            .as_deref()
            .map(AclRegistry::load_dir)
            .unwrap_or_default();
        let (acl, bump_sequence) = apply_reload(core::mem::take(&mut self.acl), acl_load);
        self.acl = acl;
        if bump_sequence {
            self.acl_sequence = self.acl_sequence.wrapping_add(1);
            self.broadcast_acl_sequence();
        }
    }

    fn broadcast_acl_sequence(&mut self) {
        let data = BlobMsgTable::build(|builder| {
            builder.put_i32(Some("sequence"), self.acl_sequence as i32);
        });
        for action in
            routing::event_fanout(&mut self.events, "ubus.acl.sequence", data.contents(), None)
        {
            self.apply_action(action);
        }
    }

    fn accept_pending(&mut self) -> Result<(), BrokerError> {
        loop {
            match crate::net::accept_nonblock_cloexec(&self.listen_fd) {
                Ok(fd) => {
                    let credentials = accepted_peer_cred(&fd);
                    #[cfg(feature = "testing")]
                    let peer_uid_override = self.config.peer_uid_override;
                    #[cfg(not(feature = "testing"))]
                    let peer_uid_override: Option<u32> = None;
                    if !accept_peer_credentials(&credentials, peer_uid_override.is_some()) {
                        // On Linux, a real socket accept can no longer create a
                        // None-named peer at this upstream revision. Preserve
                        // that encoding for the testing override path and
                        // non-Linux builds.
                        log::debug!("ubusd: refusing client with unresolvable credentials");
                        continue;
                    }
                    #[cfg(target_os = "linux")]
                    let (uid, gid, user, group, extra_gids) = match credentials {
                        PeerCredentials::Resolved {
                            uid,
                            gid,
                            user,
                            group,
                            extra_gids,
                        } => (Some(uid), Some(gid), Some(user), Some(group), extra_gids),
                        PeerCredentials::ResolutionFailed => (None, None, None, None, Vec::new()),
                    };
                    #[cfg(not(target_os = "linux"))]
                    let (uid, gid, user, group, extra_gids) = {
                        let _ = credentials;
                        (None, None, None, None, Vec::new())
                    };
                    #[cfg(feature = "testing")]
                    let uid = peer_uid_override.or(uid);
                    let peer = Peer::with_credentials(
                        fd,
                        crate::acl::Cred {
                            uid,
                            gid,
                            user,
                            group,
                            extra_gids,
                        },
                    );
                    match self.peers.insert(peer) {
                        Ok((id, _)) => {
                            #[cfg(target_os = "linux")]
                            if let Some(fd) = self.peers.get(id).and_then(|peer| peer.fd.as_ref()) {
                                if let Err(error) = self.poller.add_peer(fd, id) {
                                    log::warn!(
                                        "ubusd: register peer {id} readiness failed: {error:?}"
                                    );
                                    self.pending_close.insert(id);
                                    continue;
                                }
                            }
                            log::debug!("ubusd: accepted peer {id}");
                            // Match upstream `ubusd`: push HELLO unsolicited
                            // at accept time (seq=0, peer=assigned id), so
                            // libubus clients see their id without sending a
                            // client HELLO first.
                            let hello = reply::hello_reply(0, id);
                            self.enqueue_to_peer(id, &hello);
                        }
                        Err(BrokerError::PeerIdExhausted) => {
                            // Drop the freshly-accepted fd silently. Once the
                            // u32 peer-id space is exhausted there is no id
                            // we can give this client — better to refuse the
                            // connection (kernel sees an immediate EOF on the
                            // peer's socket) than to crash and tear down every
                            // other peer too.
                            log::error!("ubusd: peer id space exhausted; dropping accepted fd");
                        }
                        Err(other) => {
                            // `PeerTable::insert` only returns `PeerIdExhausted`
                            // today, but a future regression that adds an `Io`
                            // or `ObjectIdExhausted` arm shouldn't take the whole
                            // broker down via `unreachable!()`. Drop the fd and
                            // log; a single misbehaving peer never ends the run.
                            log::error!(
                            "ubusd: peer insert returned unexpected error {other:?}; dropping fd"
                        );
                        }
                    }
                }
                Err(e) if e == Errno::AGAIN || e == Errno::WOULDBLOCK => return Ok(()),
                Err(Errno::INTR) => continue,
                // Per-connection errors: the listener is fine, this
                // candidate isn't. Keep accepting.
                Err(e @ (Errno::CONNABORTED | Errno::PROTO | Errno::PERM)) => {
                    log::debug!("ubusd: accept dropped one connection: {e:?}");
                    continue;
                }
                // Resource pressure: we can't accept right now. Yield —
                // the next `poll_once` will re-fire POLLIN if the
                // condition cleared.
                Err(e @ (Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOMEM)) => {
                    log::warn!("ubusd: accept under resource pressure: {e:?}");
                    return Ok(());
                }
                // Listener-fatal: bad fd/socket/argument mean the
                // poll set sees an unusable fd and would re-fire
                // forever. Propagate so `run()` exits with a clear
                // error rather than burning CPU.
                Err(e) => return Err(BrokerError::op("accept", e)),
            }
        }
    }

    fn drain_rx_and_dispatch(&mut self, peer_id: PeerId, drain_eof: bool) {
        let Some(peer) = self.peers.get_mut(peer_id) else {
            return;
        };
        let mut close = !read_into_buf_available(peer, peer_id, &mut self.rx_scratch, !drain_eof);
        // Own this buffer locally so borrowed payloads survive registry mutation.
        // The connection remains live until the poll loop's deferred reaper.
        let mut bytes = std::mem::take(&mut peer.rx_buf);
        let start = peer.rx_abs;
        let mut consumed = 0;
        while bytes.len() - consumed >= RX_FD_WINDOW {
            match Codec::read_frame_borrowed_lenient_version(&bytes[consumed..]) {
                Ok((frame, size)) => {
                    let mut fd = self
                        .peers
                        .get_mut(peer_id)
                        .and_then(|peer| peer.take_rx_fd(start.saturating_add(consumed)));
                    consumed += size;
                    self.mirror_inbound(peer_id, &frame);
                    let actions = routing::dispatch_ref(
                        &frame,
                        peer_id,
                        &self.acl,
                        self.acl_sequence,
                        &mut self.peers,
                        &mut self.objects,
                        &mut self.subs,
                        &mut self.events,
                        &mut self.monitors,
                        &mut fd,
                    );
                    drop(fd);
                    self.apply_actions(actions);
                }
                Err(UbusError::Short { .. }) => break,
                Err(error) => {
                    log::warn!("ubusd: peer {peer_id} malformed frame ({error:?}); closing");
                    close = true;
                    break;
                }
            }
        }
        bytes.drain(..consumed);
        if bytes.is_empty() && bytes.capacity() > 64 * 1024 {
            bytes.shrink_to(4096);
        }
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.rx_abs = start.saturating_add(consumed);
            peer.rx_buf = bytes;
        }
        if close {
            self.pending_close.insert(peer_id);
        }
    }

    /// Coalesce consecutive descriptor-free replies without changing per-peer
    /// order. Monitor records retain their existing one-frame send boundary.
    fn apply_actions(&mut self, actions: Vec<Action>) {
        if !self.monitors.is_empty() {
            for action in actions {
                self.apply_action(action);
            }
            return;
        }
        let mut actions = actions.into_iter().peekable();
        while let Some(action) = actions.next() {
            match action {
                Action::SendTo {
                    peer_id,
                    frame,
                    fd: None,
                } => {
                    let mut bytes = std::mem::take(&mut self.tx_scratch);
                    Codec::write_frame_into(&frame, &mut bytes);
                    while let Some(Action::SendTo {
                        peer_id: next,
                        frame,
                        fd: None,
                    }) = actions.peek()
                    {
                        if *next != peer_id || bytes.len() + 8 + frame.payload.len() > 64 * 1024 {
                            break;
                        }
                        if let Some(Action::SendTo { frame, .. }) = actions.next() {
                            bytes.extend_from_slice(&frame.hdr.encode());
                            bytes.extend_from_slice(&frame.payload);
                        }
                    }
                    self.send_encoded(peer_id, &bytes);
                    self.tx_scratch = bytes;
                }
                other => self.apply_action(other),
            }
        }
    }

    fn apply_action(&mut self, action: Action) {
        match action {
            Action::SendTo { peer_id, frame, fd } => {
                let mut bytes = std::mem::take(&mut self.tx_scratch);
                Codec::write_frame_into(&frame, &mut bytes);
                match fd {
                    Some(fd) => self.send_encoded_with_fd(peer_id, &bytes, fd),
                    None => self.send_encoded(peer_id, &bytes),
                }
                self.tx_scratch = bytes;
            }
            Action::SendBytes { peer_id, bytes } => {
                self.send_encoded(peer_id, &bytes);
            }
            Action::ClosePeer { peer_id } => {
                self.pending_close.insert(peer_id);
            }
        }
    }

    /// Best-effort synchronous write of already-encoded `bytes`; on
    /// EAGAIN, stash the leftover in `tx_buf` and let the next
    /// `poll_once` drain it. The common case (uncontended kernel
    /// buffer) costs zero extra syscalls vs. always-buffer.
    fn enqueue_to_peer(&mut self, peer_id: PeerId, frame: &Frame) {
        let mut bytes = std::mem::take(&mut self.tx_scratch);
        Codec::write_frame_into(frame, &mut bytes);
        self.send_encoded(peer_id, &bytes);
        self.tx_scratch = bytes;
    }

    /// Mirror-aware outgoing choke point for all ordinary broker sends.
    fn send_encoded(&mut self, peer_id: PeerId, bytes: &[u8]) {
        self.mirror_outbound(peer_id, bytes);
        self.enqueue_bytes_raw(peer_id, bytes);
    }

    /// SCM_RIGHTS is bound to the frame's first byte, so fd-bearing frames
    /// always enter the TX queue and are emitted by `drain_tx`.
    fn send_encoded_with_fd(&mut self, peer_id: PeerId, bytes: &[u8], fd: OwnedFd) {
        self.mirror_outbound(peer_id, bytes);
        self.enqueue_bytes_with_fd(peer_id, bytes, fd);
    }

    /// Mirror-free raw write used to deliver monitor records themselves.
    fn enqueue_bytes_raw(&mut self, peer_id: PeerId, bytes: &[u8]) {
        // Testing seam: read the governor's remaining allowance before
        // borrowing the peer mutably below. `None` = ungoverned peer.
        #[cfg(feature = "testing")]
        let gov_cap = self.governor_cap(peer_id);
        let peer = match self.peers.get_mut(peer_id) {
            Some(p) => p,
            None => {
                log::debug!("ubusd: dropping frame for vanished peer {peer_id}");
                return;
            }
        };
        // Preserve send order: never interleave a fresh write past
        // bytes the kernel hasn't accepted yet.
        if peer.has_pending_tx() {
            self.buffer_or_close(peer_id, bytes);
            return;
        }
        let fd = match peer.fd.as_ref() {
            Some(f) => f,
            None => {
                log::error!(
                    "ubusd: peer {peer_id} has no fd in enqueue_to_peer; closing (invariant violation)"
                );
                self.pending_close.insert(peer_id);
                return;
            }
        };
        // Cap the directly-sent prefix at the governor budget; the
        // remainder falls through to buffer_or_close exactly as a real
        // kernel EAGAIN would route it.
        #[cfg(feature = "testing")]
        let allow = match gov_cap {
            Some(remaining) => remaining.min(bytes.len()),
            None => bytes.len(),
        };
        #[cfg(not(feature = "testing"))]
        let allow = bytes.len();
        let mut sent = 0usize;
        while sent < allow {
            match send_some(fd, &bytes[sent..allow], peer_id, "send") {
                SendOutcome::Sent(n) => sent += n,
                SendOutcome::WouldBlock => break,
                SendOutcome::Closed => {
                    self.pending_close.insert(peer_id);
                    return;
                }
            }
        }
        #[cfg(feature = "testing")]
        {
            peer.tx_sent_total += sent;
        }
        if sent < bytes.len() {
            self.buffer_or_close(peer_id, &bytes[sent..]);
        }
    }

    fn enqueue_bytes_with_fd(&mut self, peer_id: PeerId, bytes: &[u8], fd: OwnedFd) {
        let Some(peer) = self.peers.get_mut(peer_id) else {
            log::debug!("ubusd: dropping fd-bearing frame for vanished peer {peer_id}");
            return;
        };
        if peer.tx_buf.len().saturating_add(bytes.len()) > MAX_TX_BUF_BYTES {
            log::warn!("ubusd: peer {peer_id} tx_buf would exceed {MAX_TX_BUF_BYTES} B, closing");
            self.pending_close.insert(peer_id);
            return;
        }
        peer.tx_fds.push_back((peer.tx_enq_abs, fd));
        peer.enqueue(bytes);
        self.tx_ready.insert(peer_id);
        self.sync_write_interest(peer_id);
    }

    fn mirror_outbound(&mut self, dest: PeerId, bytes: &[u8]) {
        if self.monitors.is_empty() || bytes.get(1) == Some(&(ubus::wire::MsgType::Monitor as u8)) {
            return;
        }
        let peer = bytes
            .get(4..8)
            .map(|v| u32::from_be_bytes(v.try_into().expect("4-byte header peer")))
            .unwrap_or(0);
        let seq = bytes
            .get(2..4)
            .map(|v| u16::from_be_bytes(v.try_into().expect("2-byte header seq")))
            .unwrap_or(0);
        let ty = bytes.get(1).copied().unwrap_or(0);
        let frame = reply::monitor_mirror(
            0,
            dest.get(),
            peer,
            seq,
            ty,
            true,
            bytes.get(12..).unwrap_or(&[]),
        );
        self.enqueue_mirrors(frame);
    }

    fn mirror_inbound(&mut self, src: PeerId, frame: &FrameRef<'_>) {
        if self.monitors.is_empty() {
            return;
        }
        self.enqueue_mirrors(reply::monitor_mirror(
            0,
            src.get(),
            frame.hdr.peer,
            frame.hdr.seq,
            frame.hdr.ty as u8,
            false,
            frame.payload.get(4..).unwrap_or(&[]),
        ));
    }

    /// Encode the common record once, then patch each monitor's private seq.
    fn enqueue_mirrors(&mut self, frame: Frame) {
        let mut bytes = Codec::write_frame(&frame);
        for (monitor, seq) in self.monitors.mint_seqs() {
            bytes[2..4].copy_from_slice(&seq.to_be_bytes());
            self.enqueue_bytes_raw(monitor, &bytes);
        }
    }

    fn buffer_or_close(&mut self, peer_id: PeerId, bytes: &[u8]) {
        let Some(peer) = self.peers.get_mut(peer_id) else {
            return;
        };
        if peer.tx_buf.len().saturating_add(bytes.len()) > MAX_TX_BUF_BYTES {
            log::warn!("ubusd: peer {peer_id} tx_buf would exceed {MAX_TX_BUF_BYTES} B, closing");
            self.pending_close.insert(peer_id);
            return;
        }
        peer.enqueue(bytes);
        self.tx_ready.insert(peer_id);
        self.sync_write_interest(peer_id);
    }

    fn drain_tx(&mut self, peer_id: PeerId) {
        // Governor allowance snapshot (testing). `None` = ungoverned;
        // `Some(rem)` shrinks as this drain hands bytes to the kernel,
        // and `Some(0)` wedges the peer so its tx_buf never drains.
        #[cfg(feature = "testing")]
        let mut gov_remaining = self.governor_cap(peer_id);

        let peer = match self.peers.get_mut(peer_id) {
            Some(p) => p,
            None => return,
        };
        if peer.tx_buf.is_empty() {
            return;
        }
        let fd = match peer.fd.as_ref() {
            Some(f) => f,
            None => {
                log::error!(
                    "ubusd: peer {peer_id} has no fd in drain_tx; closing (invariant violation)"
                );
                self.pending_close.insert(peer_id);
                return;
            }
        };
        loop {
            #[cfg(feature = "testing")]
            if gov_remaining == Some(0) {
                return;
            }
            let (front, back) = peer.tx_buf.as_slices();
            if front.is_empty() && back.is_empty() {
                if peer.tx_buf.capacity() > 64 * 1024 {
                    peer.tx_buf.shrink_to(4096);
                }
                return;
            }
            let buf = if !front.is_empty() { front } else { back };
            #[cfg(feature = "testing")]
            let buf = match gov_remaining {
                Some(rem) => &buf[..buf.len().min(rem)],
                None => buf,
            };
            let next_fd_abs = peer.tx_fds.front().map(|(abs, _)| *abs);
            // `tx_send_window` identifies the marker at this send start.
            // When that is an fd marker, pre-clamp at the following marker
            // so this one send cannot carry two frame starts.
            let chunk_len = if next_fd_abs == Some(peer.tx_sent_abs) {
                peer.tx_fds.get(1).map_or(buf.len(), |(next_abs, _)| {
                    buf.len().min(next_abs.saturating_sub(peer.tx_sent_abs))
                })
            } else {
                buf.len()
            };
            let (send_len, attach_fd) = tx_send_window(peer.tx_sent_abs, chunk_len, next_fd_abs);
            let buf = &buf[..send_len];
            let outcome = if attach_fd {
                let (_, frame_fd) = peer
                    .tx_fds
                    .front()
                    .expect("fd marker required when tx_send_window attaches");
                send_some_with_fd(fd, buf, frame_fd, peer_id, "drain_tx")
            } else if next_fd_abs.is_some() {
                send_some_with_empty_ancillary(fd, buf, peer_id, "drain_tx")
            } else {
                send_some(fd, buf, peer_id, "drain_tx")
            };
            match outcome {
                SendOutcome::Sent(n) => {
                    #[cfg(feature = "testing")]
                    {
                        peer.tx_sent_total += n;
                        if let Some(rem) = gov_remaining.as_mut() {
                            *rem = rem.saturating_sub(n);
                        }
                    }
                    peer.tx_buf.drain(..n);
                    peer.tx_sent_abs = peer.tx_sent_abs.saturating_add(n);
                    if peer
                        .tx_fds
                        .front()
                        .is_some_and(|(abs, _)| peer.tx_sent_abs > *abs)
                    {
                        let _ = peer.tx_fds.pop_front();
                    }
                }
                SendOutcome::WouldBlock => return,
                SendOutcome::Closed => {
                    self.pending_close.insert(peer_id);
                    return;
                }
            }
        }
    }

    /// Testing seam: bytes the write governor still permits to
    /// `peer_id` before it wedges. `None` when the peer is ungoverned
    /// (no governor configured, or a different peer index); `Some(0)`
    /// once the budget is spent. See [`WriteGovernor`].
    #[cfg(feature = "testing")]
    fn governor_cap(&self, peer_id: PeerId) -> Option<usize> {
        let gov = self.config.tx_governor?;
        let index = peer_id.get().checked_sub(FIRST_PEER_ID.get())?;
        if index != gov.peer_index {
            return None;
        }
        let peer = self.peers.get(peer_id)?;
        Some(gov.budget_bytes.saturating_sub(peer.tx_sent_total))
    }

    fn close_peer(&mut self, peer_id: PeerId) {
        self.monitors.remove_peer(peer_id);
        // Peer is removed immediately after, so `take_*` is safe and
        // avoids cloning the per-peer indices.
        let (owned, subscribed_to) = match self.peers.get_mut(peer_id) {
            Some(p) => (p.take_owned(), p.take_subs()),
            None => return,
        };
        let self_active_zero = match self.peers.get_mut(peer_id) {
            Some(peer) => active_zero_for_owned_subscribed_objects(peer, &owned, &self.subs),
            None => Vec::new(),
        };
        // Snapshot named objects before they're dropped: their reap must
        // broadcast `ubus.object.remove` even though no REMOVE_OBJECT
        // frame arrived (owner just vanished).
        let reaped_named: Vec<(ObjectId, String)> = owned
            .iter()
            .filter_map(|id| self.objects.named_path(*id).map(|p| (*id, p.to_string())))
            .collect();
        let dead_objs = self.objects.drop_owned_by(&owned);
        // The disconnecting peer's own `ubus listen` registrations vanish
        // with it — drop them before fan-out so a dead listener can't be
        // a delivery target.
        self.events.remove_peer(peer_id);
        let dead_subscribers = self.subs.remove_objects(&dead_objs);
        let inactive_objects = self.subs.purge_peer(peer_id, &dead_objs, &subscribed_to);
        let active_zero = routing::active_zero_for_purged_subscriptions(
            &mut self.peers,
            &self.objects,
            &inactive_objects,
        );
        let unsubscribe = routing::unsubscribe_for_dead_objects(&mut self.peers, &dead_subscribers);
        for frame in self_active_zero {
            self.enqueue_to_peer(peer_id, &frame);
        }
        self.drain_tx(peer_id);
        for action in active_zero {
            self.apply_action(action);
        }
        for action in unsubscribe {
            self.apply_action(action);
        }
        // Broadcast `ubus.object.remove` for every named object actually
        // reaped (some may have been REMOVE_OBJECT'd already). The owner
        // is gone, so its own listeners were already purged above.
        let dead_set: HashSet<ObjectId> = dead_objs.iter().copied().collect();
        for (obj_id, path) in &reaped_named {
            if dead_set.contains(obj_id) {
                let actions =
                    routing::object_remove_fanout(&mut self.events, *obj_id, path, peer_id);
                for action in actions {
                    self.apply_action(action);
                }
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(fd) = self.peers.get(peer_id).and_then(|peer| peer.fd.as_ref()) {
            let _ = self.poller.remove(fd);
        }
        self.tx_ready.remove(&peer_id);
        let _ = self.peers.remove(peer_id);
        log::debug!(
            "ubusd: peer {peer_id} closed; reaped {} objects",
            dead_objs.len()
        );
    }
}

fn active_zero_for_owned_subscribed_objects(
    peer: &mut Peer,
    owned: &[ObjectId],
    subs: &SubscriberRegistry,
) -> Vec<Frame> {
    owned
        .iter()
        .copied()
        .filter(|obj_id| !subs.subscribers_of(*obj_id).is_empty())
        .map(|obj_id| {
            let seq = peer.next_notify_seq();
            reply::active_notify(seq, obj_id, false)
        })
        .collect()
}

impl Drop for Broker {
    fn drop(&mut self) {
        if let Err(e) = rustix::fs::unlink(self.config.socket_path.as_str()) {
            if e != Errno::NOENT {
                // The next bind() at this path will hit the same
                // condition and surface as a confusing EADDRINUSE; log
                // at the same level as the pre-bind unlink so the
                // operator gets a paired diagnostic.
                log::warn!(
                    "ubusd: drop unlink {} failed: {}",
                    self.config.socket_path,
                    io::Error::from_raw_os_error(e.raw_os_error()),
                );
            }
        }
    }
}

enum SendOutcome {
    Sent(usize),
    WouldBlock,
    Closed,
}

/// Logs unexpected errnos here so callers don't reproduce identical
/// warn-and-close ladders.
fn send_some<F: rustix::fd::AsFd>(
    fd: F,
    buf: &[u8],
    peer_id: PeerId,
    site: &'static str,
) -> SendOutcome {
    loop {
        match rustix::net::send(&fd, buf, send_flags()) {
            Ok(0) => return SendOutcome::Closed,
            Ok(n) => return SendOutcome::Sent(n),
            Err(Errno::AGAIN) => return SendOutcome::WouldBlock,
            Err(Errno::INTR) => continue,
            Err(Errno::PIPE) => {
                // Peer closed mid-send. SIGPIPE is suppressed via
                // MSG_NOSIGNAL on Linux and SO_NOSIGPIPE on macOS;
                // surface the EPIPE as a clean close.
                return SendOutcome::Closed;
            }
            Err(e) => {
                log::warn!("ubusd: {site} to peer {peer_id} failed: {e:?}");
                return SendOutcome::Closed;
            }
        }
    }
}

fn send_some_with_fd<F: rustix::fd::AsFd>(
    fd: F,
    buf: &[u8],
    rights_fd: &OwnedFd,
    peer_id: PeerId,
    site: &'static str,
) -> SendOutcome {
    send_some_with_ancillary(fd, buf, Some(rights_fd), peer_id, site)
}

fn send_some_with_empty_ancillary<F: rustix::fd::AsFd>(
    fd: F,
    buf: &[u8],
    peer_id: PeerId,
    site: &'static str,
) -> SendOutcome {
    send_some_with_ancillary(fd, buf, None, peer_id, site)
}

fn send_some_with_ancillary<F: rustix::fd::AsFd>(
    fd: F,
    buf: &[u8],
    rights_fd: Option<&OwnedFd>,
    peer_id: PeerId,
    site: &'static str,
) -> SendOutcome {
    loop {
        let mut control_storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_storage);
        let rights = rights_fd.map(|fd| [fd.as_fd()]);
        if let Some(rights) = rights.as_ref() {
            if !control.push(SendAncillaryMessage::ScmRights(rights)) {
                log::error!("ubusd: {site} SCM_RIGHTS buffer unexpectedly too small");
                return SendOutcome::Closed;
            }
        }
        let iov = [IoSlice::new(buf)];
        match rustix::net::sendmsg(&fd, &iov, &mut control, send_flags()) {
            Ok(0) => return SendOutcome::Closed,
            Ok(n) => return SendOutcome::Sent(n),
            Err(Errno::AGAIN) => return SendOutcome::WouldBlock,
            Err(Errno::INTR) => continue,
            Err(Errno::PIPE) => return SendOutcome::Closed,
            Err(e) => {
                log::warn!("ubusd: {site} to peer {peer_id} failed: {e:?}");
                return SendOutcome::Closed;
            }
        }
    }
}

/// Clamp a socket send so SCM_RIGHTS is attached exactly at its frame start.
fn tx_send_window(sent_abs: usize, chunk_len: usize, next_fd_abs: Option<usize>) -> (usize, bool) {
    match next_fd_abs {
        Some(fd_abs) if fd_abs == sent_abs => (chunk_len, true),
        Some(fd_abs) => (chunk_len.min(fd_abs.saturating_sub(sent_abs)), false),
        None => (chunk_len, false),
    }
}

/// Peek without consuming, returning the length only if every peeked byte is
/// descriptor-free. SCM_RIGHTS received under MSG_PEEK are fresh duplicates:
/// explicitly close all of them, including the visible part of a truncated cmsg.
fn peek_descriptor_free_bytes(fd: &OwnedFd, bytes: &mut [u8]) -> Result<Option<usize>, Errno> {
    let mut iov = [IoSliceMut::new(bytes)];
    let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut storage);
    let received = rustix::net::recvmsg(
        fd,
        &mut iov,
        &mut control,
        RecvFlags::PEEK | RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut ancillary = received.flags.contains(ReturnFlags::CTRUNC);
    for message in control.drain() {
        ancillary = true;
        if let RecvAncillaryMessage::ScmRights(fds) = message {
            for fd in fds {
                drop(fd);
            }
        }
    }
    Ok((!ancillary).then_some(received.bytes))
}

/// Locate the partial frame without consuming it. Only descriptor-bearing
/// reads and buffer growth need framing here; ordinary small batches go
/// straight to the codec after the socket has been drained.
fn rx_frame_window(peer: &Peer, frame_start: &mut usize) -> Option<(usize, bool)> {
    loop {
        let available = peer.rx_buf.len() - *frame_start;
        if available < RX_FD_WINDOW {
            return Some((RX_FD_WINDOW - available, true));
        }
        let prefix = &peer.rx_buf[*frame_start + 8..*frame_start + 12];
        let raw_len = (u32::from_be_bytes(prefix.try_into().unwrap()) & 0x00ff_ffff) as usize;
        if !(4..=ubus::wire::MAX_MSG_LEN).contains(&raw_len) {
            return None;
        }
        let frame_len = ubus::wire::HEADER_SIZE + ubus::blob::align4(raw_len);
        if available >= frame_len {
            *frame_start += frame_len;
            continue;
        }
        return Some((frame_len - available, false));
    }
}

/// Read everything currently queued on `peer.fd` into `peer.rx_buf`.
/// Returns `false` if the peer hung up — caller schedules a close.
#[cfg(test)]
fn read_into_buf(peer: &mut Peer, peer_id: PeerId, scratch: &mut Vec<u8>) -> bool {
    read_into_buf_available(peer, peer_id, scratch, false)
}

fn read_into_buf_available(
    peer: &mut Peer,
    peer_id: PeerId,
    scratch: &mut Vec<u8>,
    stop_after_short: bool,
) -> bool {
    let fd = match peer.fd.as_ref() {
        Some(f) => f,
        None => {
            log::error!(
                "ubusd: peer {peer_id} has no fd in read_into_buf; closing (invariant violation)"
            );
            return false;
        }
    };
    let mut frame_start = 0;
    loop {
        // Avoid a second framing walk for small traffic. Once a bufferful
        // has accumulated, size the shared scratch for the declared frame.
        if peer.rx_buf.len() >= scratch.len() && scratch.len() < 64 * 1024 {
            let Some((remaining, _)) = rx_frame_window(peer, &mut frame_start) else {
                return true; // The codec diagnoses the invalid frame.
            };
            let frame_len = peer.rx_buf.len() - frame_start + remaining;
            let wanted = frame_len.min(64 * 1024).next_power_of_two();
            if scratch.len() < wanted {
                scratch.resize(wanted, 0);
            }
        }
        // This socket has a single reader. Bytes proven descriptor-free by
        // MSG_PEEK cannot change before consumption; appended fd-bearing
        // bytes remain queued beyond that exact prefix. Ordinary traffic can
        // therefore retain the original multi-frame batching behavior.
        let batch = match peek_descriptor_free_bytes(fd, scratch) {
            Ok(Some(0)) => return false,
            Ok(batch) => batch,
            Err(Errno::AGAIN) => return true,
            Err(Errno::INTR) => continue,
            Err(e) => {
                log::warn!("ubusd: peer {peer_id} recv peek failed: {e:?}");
                return false;
            }
        };
        let (read_len, frame_abs, capture_fd) = if let Some(batch) = batch {
            (batch, 0, false)
        } else {
            // SCM_RIGHTS is a barrier at the END of a stream read: recvmsg
            // may return preceding plain bytes together with the fd. Once a
            // peek finds ancillary data, locate the partial frame and bound
            // every read to its header/body, matching upstream's fd window.
            let Some((remaining, header)) = rx_frame_window(peer, &mut frame_start) else {
                return true;
            };
            let frame_abs = peer.rx_abs.saturating_add(frame_start);
            let capture_fd = header && !peer.rx_fds.iter().any(|(at, _)| *at == frame_abs);
            (remaining.min(scratch.len()), frame_abs, capture_fd)
        };
        let mut iov = [IoSliceMut::new(&mut scratch[..read_len])];
        let mut control_storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        // Upstream reads the body without an ancillary buffer, and disables
        // further fd reception once this frame already owns one. The kernel
        // closes discarded descriptors in both cases.
        let control_len = if capture_fd { control_storage.len() } else { 0 };
        let mut control = RecvAncillaryBuffer::new(&mut control_storage[..control_len]);
        match rustix::net::recvmsg(fd, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC) {
            Ok(received) if received.bytes == 0 => return false,
            Ok(received) => {
                let mut received_fd = None;
                for message in control.drain() {
                    if let RecvAncillaryMessage::ScmRights(fds) = message {
                        for received_fd_candidate in fds {
                            if received_fd.is_none() {
                                received_fd = Some(received_fd_candidate);
                            }
                        }
                    }
                }
                if let Some(received_fd) = received_fd {
                    Peer::push_rx_fd(&mut peer.rx_fds, frame_abs, received_fd);
                }
                // Pre-check before extend: a hostile peer firehosing
                // bytes faster than the dispatch can drain shouldn't
                // be able to balloon the rx Vec past the cap before
                // the post-decode check trips.
                if peer.rx_buf.len().saturating_add(received.bytes) > MAX_RX_BUF_BYTES {
                    log::warn!(
                        "ubusd: peer {peer_id} rx_buf would exceed {MAX_RX_BUF_BYTES} B, closing"
                    );
                    return false;
                }
                peer.rx_buf.extend_from_slice(&scratch[..received.bytes]);
                // Level-triggered poll will report subsequently appended data.
                // On HUP the caller disables this shortcut and drains to EOF;
                // descriptor-bearing reads always retain the framing loop.
                if stop_after_short && batch.is_some_and(|size| size < scratch.len()) {
                    return true;
                }
            }
            Err(Errno::AGAIN) => return true,
            Err(Errno::INTR) => continue,
            Err(e) => {
                log::warn!("ubusd: peer {peer_id} recv failed: {e:?}");
                return false;
            }
        }
    }
}

enum PeerCredentials {
    #[cfg(target_os = "linux")]
    Resolved {
        uid: u32,
        gid: u32,
        user: String,
        group: String,
        extra_gids: Vec<u32>,
    },
    #[cfg(target_os = "linux")]
    ResolutionFailed,
    #[cfg(not(target_os = "linux"))]
    NotApplicable,
}

/// Decide whether an accepted client may proceed to receive HELLO.
///
/// The override only exists in testing builds, but an explicit boolean keeps
/// this policy independently unit-testable without feature-gating the tests.
fn accept_peer_credentials(credentials: &PeerCredentials, has_peer_uid_override: bool) -> bool {
    #[cfg(target_os = "linux")]
    {
        match credentials {
            PeerCredentials::Resolved { .. } => true,
            PeerCredentials::ResolutionFailed => has_peer_uid_override,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (credentials, has_peer_uid_override);
        true
    }
}

/// Read peer credentials through libc, not rustix, by design.
///
/// The compatibility harness interposes `getsockopt(SO_PEERCRED)` via
/// `LD_PRELOAD` to make upstream `ubusd` and `ubusd` see the same
/// client identity. Calling libc keeps that interposability property;
/// a raw-syscall credential read would bypass the shim and make the
/// two brokers observe different users under test.
fn accepted_peer_cred(fd: &OwnedFd) -> PeerCredentials {
    #[cfg(target_os = "linux")]
    {
        let Some((uid, gid, pid)) = socket_peer_ids(fd) else {
            return PeerCredentials::ResolutionFailed;
        };
        let Some(user) = user_name(uid) else {
            return PeerCredentials::ResolutionFailed;
        };
        let Some(group) = group_name(gid) else {
            return PeerCredentials::ResolutionFailed;
        };
        PeerCredentials::Resolved {
            uid,
            gid,
            user,
            group,
            extra_gids: supplementary_gids(pid),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        PeerCredentials::NotApplicable
    }
}

#[cfg(target_os = "linux")]
fn socket_peer_ids(fd: &OwnedFd) -> Option<(libc::uid_t, libc::gid_t, libc::pid_t)> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 || len < std::mem::size_of::<libc::ucred>() as libc::socklen_t {
        return None;
    }
    let cred = unsafe { cred.assume_init() };
    Some((cred.uid, cred.gid, cred.pid))
}

/// Upstream reads the peer's supplementary groups from its proc status at
/// accept time, retaining at most 64 groups. Keep libc file I/O so isolated
/// compatibility children can substitute this one process-local fixture.
#[cfg(target_os = "linux")]
fn supplementary_gids(pid: libc::pid_t) -> Vec<u32> {
    let path = std::ffi::CString::new(format!("/proc/{pid}/status")).expect("numeric proc path");
    let file = unsafe { libc::fopen(path.as_ptr(), c"r".as_ptr()) };
    if file.is_null() {
        return Vec::new();
    }
    // A fixed fgets buffer can split a decimal token and grant a different
    // numeric GID. Read the complete record before applying the group cap.
    let mut line = std::ptr::null_mut();
    let mut capacity = 0;
    let mut groups = Vec::new();
    loop {
        // SAFETY: getline owns/reallocates this initially null allocation and
        // NUL-terminates every successful record. The stream remains open.
        let read = unsafe { libc::getline(&mut line, &mut capacity, file) };
        if read < 0 {
            break;
        }
        let bytes = unsafe { std::slice::from_raw_parts(line.cast::<u8>(), read as usize) };
        let Some(rest) = bytes.strip_prefix(b"Groups:") else {
            continue;
        };
        // strtoul mirrors upstream's whitespace, overflow and stopping rules.
        let mut p = unsafe { line.add(bytes.len() - rest.len()) };
        while unsafe { *p } != 0 && groups.len() < 64 {
            let mut end = std::ptr::null_mut();
            let gid = unsafe { libc::strtoul(p, &mut end, 10) };
            if std::ptr::eq(p, end) {
                break;
            }
            groups.push(gid as u32);
            p = end;
        }
        break;
    }
    unsafe {
        libc::free(line.cast());
        libc::fclose(file);
    }
    groups
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
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// On Linux, `MSG_NOSIGNAL` suppresses the per-write SIGPIPE delivery
/// that would otherwise tear the daemon down when a peer disconnects
/// mid-send. macOS lacks the flag — the standalone `main.rs` installs
/// `SIG_IGN` for SIGPIPE at startup, and the EPIPE arm in `send_some`
/// surfaces the disconnect as a clean close. Embedding hosts must
/// install their own SIGPIPE policy.
#[cfg(not(target_os = "macos"))]
fn send_flags() -> SendFlags {
    SendFlags::NOSIGNAL
}

#[cfg(target_os = "macos")]
fn send_flags() -> SendFlags {
    SendFlags::empty()
}

/// `rustix::fs::Mode` wraps a platform-typed `RawMode`: `c_uint` on
/// Linux, `u16` on macOS. Truncating `u32` keeps the public `Config`
/// field portable while letting the cast surface the platform diff
/// at exactly one site.
#[cfg(not(target_os = "macos"))]
fn to_mode(m: u32) -> rustix::fs::Mode {
    rustix::fs::Mode::from_bits_truncate(m)
}

#[cfg(target_os = "macos")]
fn to_mode(m: u32) -> rustix::fs::Mode {
    rustix::fs::Mode::from_bits_truncate(m as u16)
}

/// `i32` ms → rustix's `Option<&Timespec>`. `-1` means "block forever",
/// matching `poll(2)`'s historical convention.
fn poll_timeout(ms: i32) -> Option<Timespec> {
    if ms < 0 {
        return None;
    }
    Some(Timespec {
        tv_sec: (ms / 1000) as _,
        tv_nsec: ((ms % 1000) as i64 * 1_000_000) as _,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubus::envelope::{find, UbusAttr};
    use ubus::wire::MsgType;

    fn oid(n: u32) -> ObjectId {
        ObjectId::new(n).unwrap()
    }

    fn pid(n: u32) -> PeerId {
        PeerId::new(n).unwrap()
    }

    #[test]
    fn portable_and_native_readiness_report_listener_and_wake() {
        let path = ubus_testkit::unique_socket_path("ready");
        let mut broker = Broker::bind(Config {
            socket_path: path.to_str().unwrap().into(),
            ..Config::default()
        })
        .unwrap();
        let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let (read, write) = rustix::pipe::pipe().unwrap();
        broker.set_wake_pipe(read);
        rustix::io::write(&write, b"H").unwrap();
        let portable = broker.wait_poll(0).unwrap();
        assert!(portable.0.contains(PollFlags::IN));
        assert!(portable.1.unwrap().contains(PollFlags::IN));
        broker.peer_revents_buf.clear();
        let native = broker.wait_ready(0).unwrap();
        assert!(native.0.contains(PollFlags::IN));
        assert!(native.1.unwrap().contains(PollFlags::IN));
    }

    #[test]
    fn owned_subscribed_objects_emit_active_zero_to_dying_peer() {
        let mut peer = Peer::stub();
        let owned_with_subscriber = oid(2);
        let owned_without_subscriber = oid(3);
        let subscriber = pid(1026);
        let subscriber_obj = oid(4);
        let mut subs = SubscriberRegistry::new();
        assert!(subs.add(owned_with_subscriber, subscriber, subscriber_obj));

        assert_eq!(peer.next_notify_seq(), 1, "Active=1 consumed seq 1");
        let frames = active_zero_for_owned_subscribed_objects(
            &mut peer,
            &[owned_with_subscriber, owned_without_subscriber],
            &subs,
        );

        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert_eq!(frame.hdr.ty, MsgType::Notify);
        assert_eq!(frame.hdr.seq, 2);
        assert_eq!(frame.hdr.peer, 0);
        assert_eq!(
            find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
            Some(owned_with_subscriber.get())
        );
        assert_eq!(
            find(&frame.payload, UbusAttr::Active).map(|a| a.payload),
            Some(&[0][..])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_resolved_credentials_are_accepted() {
        let credentials = PeerCredentials::Resolved {
            uid: 1,
            gid: 1,
            user: "user".into(),
            group: "group".into(),
            extra_gids: Vec::new(),
        };

        assert!(accept_peer_credentials(&credentials, false));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unresolvable_credentials_without_override_are_refused() {
        assert!(!accept_peer_credentials(
            &PeerCredentials::ResolutionFailed,
            false
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unresolvable_credentials_with_testing_override_are_accepted() {
        assert!(accept_peer_credentials(
            &PeerCredentials::ResolutionFailed,
            true
        ));
    }
}

#[cfg(test)]
mod tx_send_window_tests {
    use super::tx_send_window;

    #[test]
    fn fd_at_head_attaches_and_stays_before_next_marker() {
        // The caller limits the chunk at the following marker first.
        assert_eq!(tx_send_window(100, 20, Some(100)), (20, true));
    }

    #[test]
    fn fd_mid_buffer_clamps_plain_send_then_attaches() {
        assert_eq!(tx_send_window(100, 40, Some(120)), (20, false));
        assert_eq!(tx_send_window(120, 20, Some(120)), (20, true));
    }

    #[test]
    fn back_to_back_fds_each_attach_to_their_own_send() {
        assert_eq!(tx_send_window(100, 0, Some(100)), (0, true));
        assert_eq!(tx_send_window(100, 12, Some(100)), (12, true));
        assert_eq!(tx_send_window(112, 8, Some(112)), (8, true));
    }

    #[test]
    fn no_marker_does_not_clamp() {
        assert_eq!(tx_send_window(100, 40, None), (40, false));
    }
}

#[cfg(test)]
mod rx_frame_tests {
    use super::*;
    use rustix::fs::{fcntl_setfl, OFlags};
    use rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType};
    use ubus::envelope::{EnvBuilder, UbusAttr};
    use ubus::wire::MsgType;
    use ubus_testkit::pipe;

    fn sockets() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .expect("socketpair")
    }

    fn send_rights(socket: &OwnedFd, bytes: &[u8], descriptor: &OwnedFd, count: usize) {
        let rights = vec![descriptor.as_fd(); count];
        let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
        let mut control = SendAncillaryBuffer::new(&mut storage);
        assert!(control.push(SendAncillaryMessage::ScmRights(&rights)));
        assert_eq!(
            rustix::net::sendmsg(
                socket,
                &[IoSlice::new(bytes)],
                &mut control,
                SendFlags::empty()
            )
            .expect("sendmsg"),
            bytes.len()
        );
    }

    fn assert_pipe_closed(read_end: &OwnedFd) {
        let mut ready = [PollFd::new(read_end, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert_eq!(poll(&mut ready, Some(&timeout)).expect("pipe readiness"), 1);
        fcntl_setfl(read_end, OFlags::NONBLOCK).expect("nonblocking pipe");
        assert_eq!(
            rustix::io::read(read_end, &mut [0; 1]).expect("pipe EOF"),
            0
        );
    }

    #[test]
    fn header_keeps_one_descriptor_and_closes_truncated_rights() {
        for count in [1, 3, 253] {
            let (sender, receiver) = sockets();
            let (read_end, write_end) = pipe().expect("pipe");
            let frame = Frame::to_broker(MsgType::Ping, 1, EnvBuilder::new().finish());
            let bytes = Codec::write_frame(&frame);
            send_rights(&sender, &bytes, &write_end, count);
            drop(write_end);
            let mut peer = Peer::new(receiver, Some(0), None, None);
            assert!(read_into_buf(
                &mut peer,
                PeerId::new(1).unwrap(),
                &mut vec![0; 4096]
            ));
            assert_eq!(peer.rx_buf, bytes);
            assert_eq!(peer.rx_fds.len(), 1);
            assert!(peer.take_rx_fd(0).is_some());
            assert_pipe_closed(&read_end);
        }
    }

    #[test]
    fn fragmented_large_body_drops_its_fd_and_preserves_next_headers_fd() {
        for body_has_fd in [false, true] {
            let (sender, receiver) = sockets();
            let mut env = EnvBuilder::new();
            env.push_bytes_id(UbusAttr::Data as u8, &vec![0x5a; 32 * 1024]);
            let first = Codec::write_frame(&Frame::to_broker(MsgType::Data, 1, env.finish()));
            let second = Codec::write_frame(&Frame::to_broker(
                MsgType::Ping,
                2,
                EnvBuilder::new().finish(),
            ));
            let mut peer = Peer::new(receiver, Some(0), None, None);
            let mut scratch = vec![0; 4096];
            let id = PeerId::new(1).unwrap();

            assert_eq!(rustix::io::write(&sender, &first[..5]).unwrap(), 5);
            assert!(read_into_buf(&mut peer, id, &mut scratch));
            assert_eq!(peer.rx_buf, first[..5]);
            assert_eq!(
                rustix::io::write(&sender, &first[5..RX_FD_WINDOW]).unwrap(),
                RX_FD_WINDOW - 5
            );
            assert!(read_into_buf(&mut peer, id, &mut scratch));

            let (body_read, body_write) = pipe().expect("body pipe");
            let (header_read, header_write) = pipe().expect("header pipe");
            if body_has_fd {
                send_rights(&sender, &first[RX_FD_WINDOW..], &body_write, 1);
            } else {
                assert_eq!(
                    rustix::io::write(&sender, &first[RX_FD_WINDOW..]).unwrap(),
                    first.len() - RX_FD_WINDOW
                );
            }
            send_rights(&sender, &second, &header_write, 1);
            drop(body_write);
            drop(header_write);
            assert!(read_into_buf(&mut peer, id, &mut scratch));
            assert_eq!(peer.rx_buf, [first.as_slice(), second.as_slice()].concat());
            assert!(peer.take_rx_fd(0).is_none());
            assert_pipe_closed(&body_read);
            fcntl_setfl(&header_read, OFlags::NONBLOCK).unwrap();
            assert_eq!(
                rustix::io::read(&header_read, &mut [0; 1]),
                Err(Errno::AGAIN)
            );
            assert!(peer.take_rx_fd(first.len()).is_some());
            assert_pipe_closed(&header_read);
        }
    }
}

#[cfg(test)]
mod rx_peek_tests {
    use super::*;
    use rustix::fs::{fcntl_setfl, OFlags};
    use rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType};
    use ubus_testkit::pipe;

    fn sockets() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair")
    }

    fn send_rights(socket: &OwnedFd, bytes: &[u8], descriptor: &OwnedFd, count: usize) {
        let rights = vec![descriptor.as_fd(); count];
        let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
        let mut control = SendAncillaryBuffer::new(&mut storage);
        assert!(control.push(SendAncillaryMessage::ScmRights(&rights)));
        assert_eq!(
            rustix::net::sendmsg(
                socket,
                &[IoSlice::new(bytes)],
                &mut control,
                SendFlags::empty()
            )
            .expect("sendmsg"),
            bytes.len()
        );
    }

    #[test]
    fn repeated_peeks_close_all_duplicates_including_truncated_rights() {
        for count in [1, 3, 253] {
            let (sender, receiver) = sockets();
            let (read_end, write_end) = pipe().expect("pipe");
            send_rights(&sender, b"rights", &write_end, count);
            drop(write_end);
            let mut bytes = [0; 64];
            for _ in 0..8 {
                assert_eq!(
                    peek_descriptor_free_bytes(&receiver, &mut bytes).expect("peek"),
                    None
                );
            }
            drop(receiver);
            drop(sender);
            fcntl_setfl(&read_end, OFlags::NONBLOCK).expect("nonblocking pipe");
            assert_eq!(
                rustix::io::read(&read_end, &mut bytes).expect("all peek duplicates must close"),
                0
            );
        }
    }

    #[test]
    fn descriptor_appended_after_peek_remains_after_the_consumed_prefix() {
        let (sender, receiver) = sockets();
        rustix::io::write(&sender, b"prefix").expect("plain prefix");
        let mut bytes = [0; 64];
        let plain = peek_descriptor_free_bytes(&receiver, &mut bytes)
            .expect("plain peek")
            .expect("no rights yet");
        assert_eq!(plain, 6);
        let (read_end, write_end) = pipe().expect("pipe");
        send_rights(&sender, b"suffix", &write_end, 1);
        drop(write_end);
        assert_eq!(
            rustix::io::read(&receiver, &mut bytes[..plain]).expect("consume peeked prefix"),
            plain
        );
        assert_eq!(&bytes[..plain], b"prefix");
        assert_eq!(
            peek_descriptor_free_bytes(&receiver, &mut bytes).expect("appended rights peek"),
            None
        );
        // The peek must preserve the original queued descriptor, and close
        // only the temporary duplicate returned by MSG_PEEK.
        fcntl_setfl(&read_end, OFlags::NONBLOCK).expect("nonblocking pipe");
        assert_eq!(rustix::io::read(&read_end, &mut bytes), Err(Errno::AGAIN));
        drop(receiver);
        assert_eq!(
            rustix::io::read(&read_end, &mut bytes).expect("queued rights close"),
            0
        );
    }
}
