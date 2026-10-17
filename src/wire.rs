//! UBUS message framing: 8-byte header optionally followed by one
//! top-level blob attribute. HELLO carries a 4-byte empty outer
//! attribute (`id=0`, `len=4`) in both directions: libubus emits
//! the wrapper on the client side, and upstream `ubusd` emits the
//! same shape back to the client (broker -> client HELLO is also
//! 8 + 4 = 12 bytes on the wire — see `ubusd::reply::hello_reply`
//! and the cross-impl matrix that pins the parity). The parser
//! short-circuits HELLO before reading the body, so the 4 trailing
//! bytes are simply ignored either way. Typed messages (DATA /
//! STATUS / INVOKE / …) carry exactly one outer `blob_attr` whose
//! 24-bit length field is the on-wire framing boundary — there is
//! no separate outer length prefix; the next frame begins after
//! the 4-byte-aligned outer attr.

use alloc::vec::Vec;
use core::num::NonZeroU32;

use crate::blob::align4;
use crate::error::UbusError;

/// Wire-side object identity. Always non-zero (the protocol reserves
/// 0 for "no object" / broker-internal). Distinct type from
/// [`PeerId`] so the wire layer can't silently swap the two when
/// building reply frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct ObjId(NonZeroU32);

impl ObjId {
    pub const fn new(n: u32) -> Option<Self> {
        match NonZeroU32::new(n) {
            Some(nz) => Some(Self(nz)),
            None => None,
        }
    }
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl core::fmt::Display for ObjId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// Wire-side peer identity. Always non-zero — peer 0 is the broker
/// itself, never a valid destination for a peer-targeted frame.
/// Distinct from [`ObjId`] at the type level.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct PeerId(NonZeroU32);

impl PeerId {
    pub const fn new(n: u32) -> Option<Self> {
        match NonZeroU32::new(n) {
            Some(nz) => Some(Self(nz)),
            None => None,
        }
    }
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl core::fmt::Display for PeerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub version: u8,
    pub ty: MsgType,
    pub seq: u16,
    pub peer: u32,
}

pub const HEADER_SIZE: usize = 8;
pub const PROTO_VERSION: u8 = 0;
/// Wire-visible status values from upstream `ubusmsg.h`
/// `enum ubus_msg_status`; clients decode these exact numbers, so do
/// not re-coin them locally.
pub const UBUS_STATUS_OK: i32 = 0;
pub const UBUS_STATUS_INVALID_COMMAND: i32 = 1;
pub const UBUS_STATUS_INVALID_ARGUMENT: i32 = 2;
pub const UBUS_STATUS_METHOD_NOT_FOUND: i32 = 3;
pub const UBUS_STATUS_NOT_FOUND: i32 = 4;
pub const UBUS_STATUS_NO_DATA: i32 = 5;
pub const UBUS_STATUS_PERMISSION_DENIED: i32 = 6;
pub const UBUS_STATUS_TIMEOUT: i32 = 7;
/// `UBUS_SYSTEM_OBJECT_ACL` from upstream `ubusmsg.h`.
pub const UBUS_SYSTEM_OBJECT_ACL: u32 = 2;
/// `UBUS_SYSTEM_OBJECT_MONITOR` from upstream `ubusmsg.h`.
pub const UBUS_SYSTEM_OBJECT_MONITOR: u32 = 3;
/// Matches `UBUS_MAX_MSGLEN` in libubus. The protocol's 24-bit length
/// field allows up to 16 MiB; ubusd itself caps frames much lower. A
/// hostile peer could otherwise force the read loop to block until 16
/// MiB has buffered, amplifying memory and stalling the AT loop.
pub const MAX_MSG_LEN: usize = 1024 * 1024;

/// Cap on non-HELLO frames the handshake will tolerate. Real upstream
/// `ubusd` sends HELLO first; a broker that streams unrelated traffic
/// past this without a HELLO is buggy and should surface, not hang.
pub const HELLO_NON_HELLO_BUDGET: u32 = 16;

/// Cap on `recv() == None → wait_recv()` cycles per request phase. The
/// real `wait_recv` parks ~50 ms (`WAIT_RECV_PARK` in `unix_sock.rs`),
/// so 200 ≈ 10 s wallclock — long enough that a slow broker doesn't
/// get spuriously timed out, short enough that a silent broker
/// surfaces as `Timeout` rather than parking the AT loop forever.
pub const IDLE_WAIT_BUDGET: u32 = 200;

#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MsgType {
    Hello = 0,
    Status = 1,
    Data = 2,
    Ping = 3,
    Lookup = 4,
    Invoke = 5,
    AddObject = 6,
    RemoveObject = 7,
    Subscribe = 8,
    Unsubscribe = 9,
    Notify = 10,
    Monitor = 11,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Result<Self, UbusError> {
        Ok(match v {
            0 => Self::Hello,
            1 => Self::Status,
            2 => Self::Data,
            3 => Self::Ping,
            4 => Self::Lookup,
            5 => Self::Invoke,
            6 => Self::AddObject,
            7 => Self::RemoveObject,
            8 => Self::Subscribe,
            9 => Self::Unsubscribe,
            10 => Self::Notify,
            11 => Self::Monitor,
            v => return Err(UbusError::UnknownType(v)),
        })
    }
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0] = self.version;
        out[1] = self.ty as u8;
        out[2..4].copy_from_slice(&self.seq.to_be_bytes());
        out[4..8].copy_from_slice(&self.peer.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, UbusError> {
        if buf.len() < HEADER_SIZE {
            return Err(UbusError::Short {
                need: HEADER_SIZE,
                have: buf.len(),
            });
        }
        if buf[0] != PROTO_VERSION {
            return Err(UbusError::Malformed("unsupported protocol version"));
        }
        Ok(Self {
            version: buf[0],
            ty: MsgType::from_u8(buf[1])?,
            seq: u16::from_be_bytes([buf[2], buf[3]]),
            peer: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }

    fn decode_lenient_version(buf: &[u8]) -> Result<Self, UbusError> {
        if buf.len() < HEADER_SIZE {
            return Err(UbusError::Short {
                need: HEADER_SIZE,
                have: buf.len(),
            });
        }
        Ok(Self {
            version: buf[0],
            ty: MsgType::from_u8(buf[1])?,
            seq: u16::from_be_bytes([buf[2], buf[3]]),
            peer: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub hdr: Header,
    pub payload: Vec<u8>,
}

/// Borrowed frame view for dispatch without copying the inbound payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameRef<'a> {
    pub hdr: Header,
    pub payload: &'a [u8],
}

impl FrameRef<'_> {
    pub fn to_owned(self) -> Frame {
        Frame {
            hdr: self.hdr,
            payload: self.payload.to_vec(),
        }
    }
}

impl<'a> From<&'a Frame> for FrameRef<'a> {
    fn from(frame: &'a Frame) -> Self {
        Self {
            hdr: frame.hdr,
            payload: &frame.payload,
        }
    }
}

impl Frame {
    /// `peer=0` is the wire convention for "destination = ubusd". Sending
    /// peer=local_id makes ubusd treat the message as targeted at us and
    /// silently drop it; HELLO / LOOKUP / ADD_OBJECT must use this.
    pub fn to_broker(ty: MsgType, seq: u16, payload: Vec<u8>) -> Self {
        Self {
            hdr: Header {
                version: PROTO_VERSION,
                ty,
                seq,
                peer: 0,
            },
            payload,
        }
    }

    /// Outbound frame addressed to a specific peer (object id for client
    /// INVOKE; client's local_id for server DATA / STATUS replies).
    pub fn to_peer(ty: MsgType, seq: u16, peer: u32, payload: Vec<u8>) -> Self {
        Self {
            hdr: Header {
                version: PROTO_VERSION,
                ty,
                seq,
                peer,
            },
            payload,
        }
    }
}

pub struct Codec;

impl Codec {
    pub fn write_frame(frame: &Frame) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + frame.payload.len());
        Self::write_frame_into(frame, &mut out);
        out
    }

    /// Encode into reusable storage, retaining its capacity between sends.
    pub fn write_frame_into(frame: &Frame, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(&frame.hdr.encode());
        out.extend_from_slice(&frame.payload);
    }

    /// Header-only frames (e.g. broker -> client HELLO) decode only
    /// when they are alone at the end of `buf`: with any follow-up
    /// frame batched in, the next 4 bytes look like an outer attr
    /// `id_len` and the codec mis-decodes the boundary. Real upstream
    /// `ubusd` always emits HELLO before the client sends anything,
    /// so the read buffer never contains both at once; tests that
    /// pre-queue multiple frames must use the libubus-shape HELLO
    /// (header + 4-byte empty envelope) to give the codec a length.
    pub fn read_frame(buf: &[u8]) -> Result<(Frame, usize), UbusError> {
        Self::read_frame_with(buf, Header::decode).map(|(frame, size)| (frame.to_owned(), size))
    }

    /// Broker-side frame decode compatible with upstream `ubusd`:
    /// tolerate any header version byte while preserving it in the
    /// returned [`Frame`]. Client-side transports intentionally keep
    /// using [`read_frame`](Self::read_frame), which remains strict.
    pub fn read_frame_lenient_version(buf: &[u8]) -> Result<(Frame, usize), UbusError> {
        Self::read_frame_borrowed_lenient_version(buf).map(|(frame, size)| (frame.to_owned(), size))
    }

    /// Broker-side decoding that borrows the payload until dispatch completes.
    pub fn read_frame_borrowed_lenient_version(
        buf: &[u8],
    ) -> Result<(FrameRef<'_>, usize), UbusError> {
        Self::read_frame_with(buf, Header::decode_lenient_version)
    }

    fn read_frame_with(
        buf: &[u8],
        decode_header: fn(&[u8]) -> Result<Header, UbusError>,
    ) -> Result<(FrameRef<'_>, usize), UbusError> {
        if buf.len() < HEADER_SIZE {
            return Err(UbusError::Short {
                need: HEADER_SIZE,
                have: buf.len(),
            });
        }
        let hdr = decode_header(&buf[..HEADER_SIZE])?;

        let body_start = HEADER_SIZE;
        let attr_len = if buf.len() == body_start {
            0
        } else if buf.len() < body_start + 4 {
            return Err(UbusError::Short {
                need: body_start + 4,
                have: buf.len(),
            });
        } else {
            let id_len = u32::from_be_bytes([
                buf[body_start],
                buf[body_start + 1],
                buf[body_start + 2],
                buf[body_start + 3],
            ]);
            (id_len & 0x00_FF_FF_FF) as usize
        };
        // Once any body bytes are present, the outer blob_attr header
        // (4 bytes id_len) is the minimum legal size. attr_len == 0
        // here would mean the peer wrote a 4-byte zero header: we'd
        // consume only HEADER_SIZE and leave 4 stale bytes at the
        // front of the next read, mis-decoding them as the next
        // msghdr. Reject up front rather than desync the stream.
        if buf.len() > body_start && attr_len < 4 {
            return Err(UbusError::Malformed("outer attr_len < 4"));
        }
        if attr_len > MAX_MSG_LEN {
            return Err(UbusError::Malformed("attr_len exceeds max frame size"));
        }
        // `id_len` is the *unpadded* declared length but the next msghdr
        // starts on a 4-byte boundary, so the receiver advances past
        // the trailing alignment pad. Real ubusd emits non-4-aligned
        // attr_len for some control frames; without skipping the pad,
        // 1–3 stale bytes leak into the next read and poison its
        // msghdr. The returned `payload` slice stays unpadded —
        // `envelope::unwrap` reads total_len from its first 4 bytes
        // and would mis-bound otherwise.
        let payload_end = body_start + attr_len;
        let consumed = body_start + align4(attr_len);
        // Require the full aligned length: on a stream-oriented
        // transport, returning a frame whose pad bytes haven't arrived
        // yet would leave 1–3 stray bytes at the front of the next
        // read and corrupt the next msghdr. Callers that observe EOF
        // mid-pad must drop the residual bytes themselves.
        if buf.len() < consumed {
            return Err(UbusError::Short {
                need: consumed,
                have: buf.len(),
            });
        }
        let payload = &buf[body_start..payload_end];
        Ok((FrameRef { hdr, payload }, consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvBuilder;

    #[test]
    fn borrowed_decode_preserves_boundary_without_copying_payload() {
        let mut env = EnvBuilder::new();
        env.push_u32(crate::envelope::UbusAttr::ObjId, 17);
        let frame = Frame::to_broker(MsgType::Lookup, 9, env.finish());
        let bytes = Codec::write_frame(&frame);
        let mut pipeline = bytes.clone();
        pipeline.extend_from_slice(&bytes);
        let (borrowed, consumed) = Codec::read_frame_borrowed_lenient_version(&pipeline).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(borrowed.to_owned(), frame);
        assert_eq!(borrowed.payload.as_ptr(), pipeline[HEADER_SIZE..].as_ptr());
        for cut in HEADER_SIZE + 1..bytes.len() {
            assert!(matches!(
                Codec::read_frame_borrowed_lenient_version(&bytes[..cut]),
                Err(UbusError::Short { .. })
            ));
        }
        let mut reused = alloc::vec![0xff; 128];
        let capacity = reused.capacity();
        Codec::write_frame_into(&frame, &mut reused);
        assert_eq!(reused, bytes);
        assert_eq!(reused.capacity(), capacity);
    }

    #[test]
    fn header_roundtrip() {
        let h = Header {
            version: PROTO_VERSION,
            ty: MsgType::Invoke,
            seq: 0xAABB,
            peer: 0xDEADBEEF,
        };
        let bytes = h.encode();
        let h2 = Header::decode(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn header_short_errors() {
        assert!(matches!(
            Header::decode(&[0u8; 4]),
            Err(UbusError::Short { .. })
        ));
    }

    #[test]
    fn header_unknown_type() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[1] = 99;
        assert!(matches!(
            Header::decode(&bytes),
            Err(UbusError::UnknownType(99))
        ));
    }

    #[test]
    fn header_unsupported_version() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = 99;
        assert!(matches!(
            Header::decode(&bytes),
            Err(UbusError::Malformed("unsupported protocol version"))
        ));
    }

    #[test]
    fn lenient_frame_decode_preserves_nonzero_version() {
        let f = Frame {
            hdr: Header {
                version: 7,
                ty: MsgType::Ping,
                seq: 9,
                peer: 11,
            },
            payload: EnvBuilder::new().finish(),
        };
        let buf = Codec::write_frame(&f);
        assert!(matches!(
            Codec::read_frame(&buf),
            Err(UbusError::Malformed("unsupported protocol version"))
        ));
        let (decoded, consumed) = Codec::read_frame_lenient_version(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, f);
    }

    fn fake_attr(body_len: usize) -> alloc::vec::Vec<u8> {
        let total = 4 + body_len;
        let id_len: u32 = ((2u32) << 24) | (total as u32 & 0x00_FF_FF_FF);
        let mut out = alloc::vec::Vec::with_capacity(total);
        out.extend_from_slice(&id_len.to_be_bytes());
        out.extend(core::iter::repeat_n(0xAAu8, body_len));
        out
    }

    #[test]
    fn frame_codec_roundtrip_with_attr_body() {
        let f = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Data,
                seq: 7,
                peer: 1,
            },
            payload: fake_attr(8),
        };
        let buf = Codec::write_frame(&f);
        assert_eq!(buf.len(), HEADER_SIZE + 12);
        let (f2, n) = Codec::read_frame(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(f, f2);
    }

    #[test]
    fn frame_codec_handles_empty_payload() {
        let f = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Hello,
                seq: 0,
                peer: 0,
            },
            payload: alloc::vec::Vec::new(),
        };
        let buf = Codec::write_frame(&f);
        assert_eq!(buf.len(), HEADER_SIZE);
        let (f2, n) = Codec::read_frame(&buf).unwrap();
        assert_eq!(n, HEADER_SIZE);
        assert_eq!(f, f2);
    }

    #[test]
    fn read_frame_partial_returns_short() {
        let f = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Status,
                seq: 0,
                peer: 0,
            },
            payload: fake_attr(28),
        };
        let buf = Codec::write_frame(&f);
        for cut in [4usize, HEADER_SIZE + 2, HEADER_SIZE + 10] {
            assert!(matches!(
                Codec::read_frame(&buf[..cut]),
                Err(UbusError::Short { .. })
            ));
        }
    }

    /// Outer attr with non-4-aligned total_len (9 + 3 pad). The
    /// receiver must consume the pad or the next frame's msghdr is
    /// read at the wrong offset.
    #[test]
    fn read_frame_consumes_outer_alignment_pad() {
        let mut buf = alloc::vec::Vec::new();
        let hdr = Header {
            version: PROTO_VERSION,
            ty: MsgType::Data,
            seq: 1,
            peer: 0,
        };
        buf.extend_from_slice(&hdr.encode());
        let id_len: u32 = 9;
        buf.extend_from_slice(&id_len.to_be_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        buf.extend_from_slice(&[0u8; 3]);
        let next_hdr = Header {
            version: PROTO_VERSION,
            ty: MsgType::Status,
            seq: 2,
            peer: 0,
        };
        buf.extend_from_slice(&next_hdr.encode());

        let (frame, consumed) = Codec::read_frame(&buf).unwrap();
        assert_eq!(frame.hdr, hdr);
        assert_eq!(frame.payload.len(), 9);
        assert_eq!(consumed, HEADER_SIZE + 12);
        let (frame2, _) = Codec::read_frame(&buf[consumed..]).unwrap();
        assert_eq!(frame2.hdr, next_hdr);
    }

    /// A peer-supplied 16 MiB attr_len would otherwise force the read
    /// loop to block until 16 MiB has buffered. Cap at MAX_MSG_LEN so
    /// `read_frame` rejects oversized declared lengths up front.
    #[test]
    fn read_frame_rejects_attr_len_above_max_frame_size() {
        let mut buf = alloc::vec::Vec::new();
        let hdr = Header {
            version: PROTO_VERSION,
            ty: MsgType::Data,
            seq: 1,
            peer: 0,
        };
        buf.extend_from_slice(&hdr.encode());
        // Declare attr_len = MAX_MSG_LEN + 1.
        let oversized = (MAX_MSG_LEN as u32) + 1;
        buf.extend_from_slice(&oversized.to_be_bytes());
        assert!(matches!(
            Codec::read_frame(&buf),
            Err(UbusError::Malformed("attr_len exceeds max frame size"))
        ));
    }

    /// Buffer ends at unpadded payload end (mid-pad). On a stream
    /// transport we must wait for the pad bytes rather than return a
    /// frame and leave 1–3 stale bytes at the head of the next read.
    #[test]
    fn read_frame_short_until_alignment_pad_arrives() {
        let mut buf = alloc::vec::Vec::new();
        let hdr = Header {
            version: PROTO_VERSION,
            ty: MsgType::Data,
            seq: 3,
            peer: 0,
        };
        buf.extend_from_slice(&hdr.encode());
        let id_len: u32 = 9;
        buf.extend_from_slice(&id_len.to_be_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        assert!(matches!(
            Codec::read_frame(&buf),
            Err(UbusError::Short { .. })
        ));
        buf.extend_from_slice(&[0u8; 3]);
        let (frame, consumed) = Codec::read_frame(&buf).unwrap();
        assert_eq!(frame.hdr, hdr);
        assert_eq!(consumed, buf.len());
    }
}
