//! Per-connection state owned by [`crate::registry::PeerTable`].
//!
//! A peer pins one accepted unix-socket fd (or `None` for in-memory
//! test stubs) plus inbound and outbound byte buffers. The framing
//! state lives entirely in `rx_buf`; outbound writes prefer the
//! best-effort synchronous path and only buffer in `tx_buf` on
//! `EAGAIN`. POLLOUT is then re-armed by [`crate::broker`] until the
//! buffer drains.

use std::collections::VecDeque;
use std::sync::Arc;

use rustix::fd::OwnedFd;
use ubus::wire::MAX_MSG_LEN;

use crate::acl::Cred;
use crate::registry::ObjectId;

/// Bytes at the head of a frame during which an inbound SCM_RIGHTS fd
/// still binds to that frame. Upstream `ubusd` reads `cl->hdrbuf` —
/// `struct ubus_msg_hdr` (8 B) plus the leading `struct blob_attr`
/// (4 B) — with `recvmsg` and a control buffer, then reads the body
/// with a bare `read()`. An fd that lands after that window is dropped
/// by the kernel (no control buffer to receive it), so it is dropped
/// here too.
pub(crate) const RX_FD_WINDOW: usize = ubus::wire::HEADER_SIZE + 4;

/// Per-peer rx buffer cap: one full legal frame plus a partial successor.
pub const MAX_RX_BUF_BYTES: usize = 2 * MAX_MSG_LEN;

/// Per-peer tx buffer cap. This admits one legal 1 MiB reply; a
/// subscriber that keeps not draining is dropped once it would exceed
/// the budget rather than balloon the broker heap during a NOTIFY fan-out.
pub const MAX_TX_BUF_BYTES: usize = 2 * MAX_MSG_LEN;

pub struct Peer {
    /// Accepted socket fd. `None` for the in-memory test stubs the
    /// pure routing tests use.
    pub(crate) fd: Option<OwnedFd>,

    /// Immutable accepted credentials, shared by dispatch without per-frame
    /// string/group allocation. Only test setup mutates through Arc::make_mut.
    pub(crate) credentials: Arc<Cred>,
    #[cfg(target_os = "linux")]
    pub(crate) write_interest: bool,

    pub(crate) rx_buf: Vec<u8>,
    pub(crate) tx_buf: VecDeque<u8>,
    /// Inbound SCM_RIGHTS fds keyed by the absolute rx-stream offset of
    /// the first byte that arrived alongside them. A scalar slot would
    /// lose fds whenever a peer pipelines several fd-bearing frames into
    /// one poll cycle: upstream binds each fd to the frame whose header
    /// `recvmsg` carried it, and so does this queue.
    pub(crate) rx_fds: VecDeque<(usize, OwnedFd)>,
    /// Absolute rx-stream offset of `rx_buf[0]`, i.e. bytes already
    /// drained into decoded frames. Keeps `rx_fds` valid across drains.
    pub(crate) rx_abs: usize,
    /// SCM_RIGHTS fds keyed by the absolute offset of their frame's first byte.
    pub(crate) tx_fds: VecDeque<(usize, OwnedFd)>,
    /// Running byte counters used to keep `tx_fds` valid across buffer drains.
    pub(crate) tx_enq_abs: usize,
    pub(crate) tx_sent_abs: usize,

    /// obj-ids this peer registered. Reaped wholesale on disconnect.
    pub(crate) owned: Vec<ObjectId>,
    /// obj-ids this peer is subscribed to. Reaped on disconnect so
    /// the SubscriberRegistry doesn't keep handing frames at a dead
    /// fd.
    pub(crate) subs: Vec<ObjectId>,
    /// Broker-originated NOTIFY sequence counter for subscription
    /// Active state changes delivered to this peer.
    next_notify_seq: u16,

    /// Cumulative bytes the broker has actually handed to the kernel
    /// for this peer. Only consulted by the `testing` write governor
    /// (`crate::broker`), which wedges a peer's TX once this crosses a
    /// configured budget — deterministic backpressure with no kernel-
    /// buffer or scheduling dependence. Never read in production.
    #[cfg(feature = "testing")]
    pub(crate) tx_sent_total: usize,
}

impl Peer {
    pub fn new(fd: OwnedFd, uid: Option<u32>, user: Option<String>, group: Option<String>) -> Self {
        Self::with_credentials(
            fd,
            Cred {
                uid,
                user,
                group,
                ..Cred::default()
            },
        )
    }

    pub(crate) fn with_credentials(fd: OwnedFd, credentials: Cred) -> Self {
        Self {
            fd: Some(fd),
            credentials: Arc::new(credentials),
            #[cfg(target_os = "linux")]
            write_interest: false,
            rx_buf: Vec::with_capacity(2048),
            tx_buf: VecDeque::with_capacity(2048),
            rx_fds: VecDeque::new(),
            rx_abs: 0,
            tx_fds: VecDeque::new(),
            tx_enq_abs: 0,
            tx_sent_abs: 0,
            owned: Vec::new(),
            subs: Vec::new(),
            next_notify_seq: 1,
            #[cfg(feature = "testing")]
            tx_sent_total: 0,
        }
    }

    /// Stub peer with no fd, for routing-only tests.
    #[cfg(test)]
    pub fn stub() -> Self {
        Self {
            fd: None,
            credentials: Arc::new(Cred::default()),
            #[cfg(target_os = "linux")]
            write_interest: false,
            rx_buf: Vec::new(),
            tx_buf: VecDeque::new(),
            rx_fds: VecDeque::new(),
            rx_abs: 0,
            tx_fds: VecDeque::new(),
            tx_enq_abs: 0,
            tx_sent_abs: 0,
            owned: Vec::new(),
            subs: Vec::new(),
            next_notify_seq: 1,
            #[cfg(feature = "testing")]
            tx_sent_total: 0,
        }
    }

    #[cfg(test)]
    pub fn stub_with_uid(uid: u32) -> Self {
        let mut peer = Self::stub();
        Arc::make_mut(&mut peer.credentials).uid = Some(uid);
        peer
    }

    pub(crate) fn cred(&self) -> Arc<Cred> {
        Arc::clone(&self.credentials)
    }

    pub fn enqueue(&mut self, bytes: &[u8]) {
        self.tx_buf.extend(bytes);
        self.tx_enq_abs = self.tx_enq_abs.saturating_add(bytes.len());
    }

    /// Record an fd that arrived alongside the byte at absolute rx
    /// offset `abs`. Upstream accepts at most one fd per in-flight
    /// frame — once `cl->pending_msg_fd` is set it passes a NULL control
    /// buffer, so the kernel discards any further fd for that frame —
    /// hence a second fd at the same offset is dropped (closed) here.
    ///
    /// Takes the queue rather than `&mut self` so the read loop can call
    /// it while still holding an immutable borrow of `peer.fd`.
    pub(crate) fn push_rx_fd(rx_fds: &mut VecDeque<(usize, OwnedFd)>, abs: usize, fd: OwnedFd) {
        if rx_fds.iter().any(|(at, _)| *at == abs) {
            return;
        }
        rx_fds.push_back((abs, fd));
    }

    /// Take the fd belonging to a frame starting at absolute rx offset
    /// `start`. Only an fd landing inside that frame's header window
    /// counts ([`RX_FD_WINDOW`]); fds stranded before `start`, or
    /// arriving mid-body, are dropped exactly as upstream drops them.
    pub(crate) fn take_rx_fd(&mut self, start: usize) -> Option<OwnedFd> {
        while let Some((at, _)) = self.rx_fds.front() {
            if *at < start {
                self.rx_fds.pop_front();
                continue;
            }
            if *at < start.saturating_add(RX_FD_WINDOW) {
                return self.rx_fds.pop_front().map(|(_, fd)| fd);
            }
            return None;
        }
        None
    }

    pub fn has_pending_tx(&self) -> bool {
        !self.tx_buf.is_empty()
    }

    /// Record `obj_id` in the peer's owned-objects mirror. No-op on
    /// duplicates so callers don't have to hand-coordinate with the
    /// `ObjectRegistry`. Paired with `remove_owned` / `take_owned`.
    pub fn add_owned(&mut self, obj_id: ObjectId) {
        sorted_insert(&mut self.owned, obj_id);
    }

    pub fn remove_owned(&mut self, obj_id: ObjectId) {
        sorted_remove(&mut self.owned, obj_id);
    }

    pub fn owns(&self, obj_id: ObjectId) -> bool {
        self.owned.binary_search(&obj_id).is_ok()
    }

    pub fn owned_count(&self) -> usize {
        self.owned.len()
    }

    /// Move the owned list out, leaving an empty Vec behind. Used at
    /// disconnect time so the broker hands the list to the registry
    /// without cloning.
    pub fn take_owned(&mut self) -> Vec<ObjectId> {
        core::mem::take(&mut self.owned)
    }

    pub fn add_sub(&mut self, obj_id: ObjectId) {
        sorted_insert(&mut self.subs, obj_id);
    }

    pub fn remove_sub(&mut self, obj_id: ObjectId) {
        sorted_remove(&mut self.subs, obj_id);
    }

    pub fn is_subscribed_to(&self, obj_id: ObjectId) -> bool {
        self.subs.binary_search(&obj_id).is_ok()
    }

    pub fn sub_count(&self) -> usize {
        self.subs.len()
    }

    pub fn take_subs(&mut self) -> Vec<ObjectId> {
        core::mem::take(&mut self.subs)
    }

    /// Copy of the subscribed-target mirror, for callers that still need
    /// the peer alive afterwards (REMOVE_OBJECT tearing down only the
    /// subscriptions held via the removed object).
    pub fn subs_snapshot(&self) -> Vec<ObjectId> {
        self.subs.clone()
    }

    pub fn next_notify_seq(&mut self) -> u16 {
        let seq = self.next_notify_seq;
        self.next_notify_seq = self.next_notify_seq.wrapping_add(1);
        seq
    }
}

/// Sorted-Vec set helpers. The vectors hold one entry per registered
/// object, so a binary-search lookup paired with sorted insertion
/// turns the contains-then-push idiom from O(N) into O(log N) lookup
/// plus a single shift on insert. Iteration order stays
/// deterministic, which the disconnect reaper relies on for stable
/// debug output.
fn sorted_insert<T: Ord>(v: &mut Vec<T>, item: T) {
    if let Err(pos) = v.binary_search(&item) {
        v.insert(pos, item);
    }
}

fn sorted_remove<T: Ord>(v: &mut Vec<T>, item: T) {
    if let Ok(pos) = v.binary_search(&item) {
        v.remove(pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second fd for the same in-flight frame is refused and closed —
    /// upstream stops offering a control buffer once it holds one.
    #[test]
    fn duplicate_rx_fd_at_same_offset_is_closed() {
        let (read_end, write_end) = rustix::pipe::pipe().unwrap();
        let (_, first) = rustix::pipe::pipe().unwrap();
        let mut peer = Peer::stub();
        Peer::push_rx_fd(&mut peer.rx_fds, 0, first);
        Peer::push_rx_fd(&mut peer.rx_fds, 0, write_end);

        let mut byte = [0_u8; 1];
        assert_eq!(rustix::io::read(read_end, &mut byte).unwrap(), 0);
        assert!(peer.take_rx_fd(0).is_some());
    }

    /// Two pipelined fd-bearing frames each keep their own fd; before
    /// the offset queue the second `recvmsg` overwrote (and closed) the
    /// first, so frame 1 got frame 2's fd and frame 2 got none.
    #[test]
    fn pipelined_rx_fds_bind_to_their_own_frames() {
        let (read_a, write_a) = rustix::pipe::pipe().unwrap();
        let (read_b, write_b) = rustix::pipe::pipe().unwrap();
        let mut peer = Peer::stub();
        Peer::push_rx_fd(&mut peer.rx_fds, 0, write_a);
        Peer::push_rx_fd(&mut peer.rx_fds, 64, write_b);

        let first = peer.take_rx_fd(0).expect("fd for frame at offset 0");
        let second = peer.take_rx_fd(64).expect("fd for frame at offset 64");

        rustix::io::write(&first, b"a").unwrap();
        rustix::io::write(&second, b"b").unwrap();
        let mut byte = [0_u8; 1];
        rustix::io::read(&read_a, &mut byte).unwrap();
        assert_eq!(&byte, b"a");
        rustix::io::read(&read_b, &mut byte).unwrap();
        assert_eq!(&byte, b"b");
    }

    /// An fd landing past the header window belongs to no frame:
    /// upstream reads the body with a bare `read()`, so the kernel
    /// discards it. Here it is dropped when the stream moves past it.
    #[test]
    fn mid_body_rx_fd_is_not_handed_to_any_frame() {
        let (read_end, write_end) = rustix::pipe::pipe().unwrap();
        let mut peer = Peer::stub();
        Peer::push_rx_fd(&mut peer.rx_fds, RX_FD_WINDOW + 1, write_end);

        assert!(peer.take_rx_fd(0).is_none(), "not in frame 0's header");
        assert!(peer.take_rx_fd(128).is_none(), "stranded, dropped");
        let mut byte = [0_u8; 1];
        assert_eq!(rustix::io::read(read_end, &mut byte).unwrap(), 0);
    }
}
