//! Level-triggered Linux readiness keyed by monotonic peer IDs, never fd numbers.
use crate::registry::PeerId;
use rustix::event::{epoll, PollFlags, Timespec};
use rustix::fd::OwnedFd;
use rustix::io;
use std::mem::MaybeUninit;

pub(crate) struct Poller(OwnedFd);

impl Poller {
    pub fn new(listener: &OwnedFd) -> io::Result<Self> {
        let fd = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        epoll::add(
            &fd,
            listener,
            epoll::EventData::new_u64(0),
            epoll::EventFlags::IN,
        )?;
        Ok(Self(fd))
    }

    pub fn add_peer(&self, fd: &OwnedFd, peer: PeerId) -> io::Result<()> {
        epoll::add(
            &self.0,
            fd,
            epoll::EventData::new_u64(peer.get().into()),
            epoll::EventFlags::IN,
        )
    }

    pub fn add_wake(&self, fd: &OwnedFd) -> io::Result<()> {
        epoll::add(
            &self.0,
            fd,
            epoll::EventData::new_u64(1),
            epoll::EventFlags::IN,
        )
    }

    pub fn remove(&self, fd: &OwnedFd) -> io::Result<()> {
        epoll::delete(&self.0, fd)
    }

    pub fn writable(&self, fd: &OwnedFd, peer: PeerId, enabled: bool) -> io::Result<()> {
        let mut flags = epoll::EventFlags::IN;
        if enabled {
            flags |= epoll::EventFlags::OUT;
        }
        epoll::modify(
            &self.0,
            fd,
            epoll::EventData::new_u64(peer.get().into()),
            flags,
        )
    }

    pub fn wait(
        &self,
        timeout: Option<&Timespec>,
        peers: &mut Vec<(PeerId, PollFlags)>,
    ) -> io::Result<(PollFlags, Option<PollFlags>)> {
        let mut storage = [MaybeUninit::<epoll::Event>::uninit(); 64];
        let (events, _) = epoll::wait(&self.0, &mut storage, timeout)?;
        let mut listen = PollFlags::empty();
        let mut wake = None;
        for event in events {
            let flags = event.flags;
            let data = event.data;
            let mut ready = PollFlags::empty();
            if flags.contains(epoll::EventFlags::IN) {
                ready |= PollFlags::IN;
            }
            if flags.contains(epoll::EventFlags::OUT) {
                ready |= PollFlags::OUT;
            }
            if flags.contains(epoll::EventFlags::ERR) {
                ready |= PollFlags::ERR;
            }
            if flags.contains(epoll::EventFlags::HUP) {
                ready |= PollFlags::HUP;
            }
            match data.u64() {
                0 => listen |= ready,
                1 => wake = Some(ready),
                token => {
                    if let Ok(value) = u32::try_from(token) {
                        if let Some(peer) = PeerId::new(value) {
                            peers.push((peer, ready));
                        }
                    }
                }
            }
        }
        Ok((listen, wake))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn writable_interest_and_reused_descriptor_tokens_do_not_leak_events() {
        use rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType};
        let (listener, _listener_other) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let poller = Poller::new(&listener).unwrap();
        let (peer, other) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let first = PeerId::new(1025).unwrap();
        let second = PeerId::new(1026).unwrap();
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut ready = Vec::new();
        poller.add_peer(&peer, first).unwrap();
        poller.wait(Some(&timeout), &mut ready).unwrap();
        assert!(
            ready.is_empty(),
            "idle peers must not keep the loop writable"
        );
        poller.writable(&peer, first, true).unwrap();
        poller.wait(Some(&timeout), &mut ready).unwrap();
        assert!(ready
            .iter()
            .any(|(id, flags)| *id == first && flags.contains(PollFlags::OUT)));
        ready.clear();
        poller.writable(&peer, first, false).unwrap();
        poller.wait(Some(&timeout), &mut ready).unwrap();
        assert!(ready.is_empty());
        rustix::io::write(&other, b"payload").unwrap();
        poller.remove(&peer).unwrap();
        poller.wait(Some(&timeout), &mut ready).unwrap();
        assert!(
            ready.is_empty(),
            "removed ready descriptors must be unregistered"
        );
        poller.add_peer(&peer, second).unwrap();
        poller.wait(Some(&timeout), &mut ready).unwrap();
        assert!(ready
            .iter()
            .any(|(id, flags)| *id == second && flags.contains(PollFlags::IN)));
        assert!(ready.iter().all(|(id, _)| *id != first));
    }
}
