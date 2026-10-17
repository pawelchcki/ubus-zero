//! Host-side Unix socket transport used by the compatibility suites.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fd::BorrowedFd;

use ubus::error::UbusError;
use ubus::transport::Transport;
use ubus::wire::{Codec, Frame, HEADER_SIZE, MAX_MSG_LEN};

/// A non-blocking Unix-stream transport for integration tests and examples.
pub struct UnixUbusTransport {
    stream: UnixStream,
    rx_buf: Vec<u8>,
    read_buffer: Vec<u8>,
}

impl UnixUbusTransport {
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, UbusError> {
        Self::connect_with_read_buffer(path, 2048)
    }

    /// Benchmark endpoints can reserve larger reads once, outside measurement.
    pub fn connect_with_read_buffer(
        path: impl AsRef<Path>,
        bytes: usize,
    ) -> Result<Self, UbusError> {
        if !(1..=64 * 1024).contains(&bytes) {
            return Err(UbusError::Malformed("invalid read buffer size"));
        }
        let stream = UnixStream::connect(path).map_err(io_error)?;
        stream.set_nonblocking(true).map_err(io_error)?;
        Ok(Self {
            stream,
            rx_buf: Vec::with_capacity(1024),
            read_buffer: vec![0; bytes],
        })
    }

    fn fill_rx(&mut self) -> Result<bool, UbusError> {
        const RX_BUF_CAP: usize = MAX_MSG_LEN * 2;
        loop {
            match self.stream.read(&mut self.read_buffer) {
                Ok(0) => return Ok(true),
                Ok(n) => {
                    if self.rx_buf.len().saturating_add(n) > RX_BUF_CAP {
                        return Err(UbusError::Malformed("rx buffer exceeded cap"));
                    }
                    self.rx_buf.extend_from_slice(&self.read_buffer[..n]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error(error)),
            }
        }
    }
}

impl Transport for UnixUbusTransport {
    fn send(&mut self, frame: &Frame) -> Result<(), UbusError> {
        let bytes = Codec::write_frame(frame);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sent = 0;
        while sent < bytes.len() {
            match self.stream.write(&bytes[sent..]) {
                Ok(0) => return Err(UbusError::Closed),
                Ok(n) => sent += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(UbusError::Io("send timed out".into()));
                    }
                    let fd = unsafe { BorrowedFd::borrow_raw(self.stream.as_raw_fd()) };
                    let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let timeout = Timespec {
                        tv_sec: remaining.as_secs() as _,
                        tv_nsec: remaining.subsec_nanos() as _,
                    };
                    match poll(&mut fds, Some(&timeout)) {
                        Ok(_) => {}
                        Err(rustix::io::Errno::INTR) => {}
                        Err(error) => {
                            return Err(io_error(io::Error::from_raw_os_error(
                                error.raw_os_error(),
                            )))
                        }
                    }
                }
                Err(error) => return Err(io_error(error)),
            }
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Frame>, UbusError> {
        let closed = match self.fill_rx() {
            Ok(closed) => closed,
            Err(error) => {
                self.rx_buf.clear();
                return Err(error);
            }
        };

        // The codec accepts standalone eight-byte headers for in-memory
        // callers. Socket frames always include the four-byte outer blob
        // header, so an eight-byte read must remain buffered until it arrives.
        if self.rx_buf.len() < HEADER_SIZE + 4 {
            return if closed {
                Err(UbusError::Closed)
            } else {
                Ok(None)
            };
        }

        match Codec::read_frame(&self.rx_buf) {
            Ok((frame, consumed)) => {
                self.rx_buf.drain(..consumed);
                Ok(Some(frame))
            }
            Err(UbusError::Short { .. }) if closed => Err(UbusError::Closed),
            Err(UbusError::Short { .. }) => Ok(None),
            Err(error) => {
                self.rx_buf.clear();
                Err(error)
            }
        }
    }

    fn wait_recv(&mut self) {
        // Match the public Unix transport's readiness wait. The client's
        // fixed idle-iteration budget assumes up to 50 ms of waiting per
        // iteration; 1 ms sleeps gave fragmented compatibility probes only
        // about 200 ms to finish under contention.
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        // SAFETY: the stream owns this descriptor for the entire poll call.
        let fd = unsafe { BorrowedFd::borrow_raw(self.stream.as_raw_fd()) };
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        let _ = poll(&mut fds, Some(&timeout));
    }
}

fn io_error(error: io::Error) -> UbusError {
    UbusError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubus::envelope::{EnvBuilder, UbusAttr};
    use ubus::wire::MsgType;

    fn pair() -> (UnixStream, UnixUbusTransport) {
        let (sender, stream) = UnixStream::pair().expect("socketpair");
        stream.set_nonblocking(true).expect("nonblocking receiver");
        (
            sender,
            UnixUbusTransport {
                stream,
                rx_buf: Vec::new(),
                read_buffer: vec![0; 2048],
            },
        )
    }

    fn frame() -> Frame {
        let mut envelope = EnvBuilder::new();
        envelope.push_u32(UbusAttr::Status, 0);
        Frame::to_broker(MsgType::Status, 17, envelope.finish())
    }

    #[test]
    fn every_header_split_waits_for_the_complete_wire_frame() {
        let expected = frame();
        let bytes = Codec::write_frame(&expected);
        for split in 1..=HEADER_SIZE + 4 {
            let (mut sender, mut receiver) = pair();
            sender.write_all(&bytes[..split]).expect("header prefix");
            assert_eq!(
                receiver.recv().expect("partial frame"),
                None,
                "split {split}"
            );
            sender.write_all(&bytes[split..]).expect("remaining frame");
            assert_eq!(
                receiver.recv().expect("complete frame"),
                Some(expected.clone()),
                "split {split}"
            );
        }
    }

    #[test]
    fn eof_at_every_header_split_reports_closed() {
        let bytes = Codec::write_frame(&frame());
        for split in 1..=HEADER_SIZE + 4 {
            let (mut sender, mut receiver) = pair();
            sender.write_all(&bytes[..split]).expect("header prefix");
            drop(sender);
            assert!(
                matches!(receiver.recv(), Err(UbusError::Closed)),
                "split {split}"
            );
        }
    }
}
