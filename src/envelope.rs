//! UBUS envelope: the outer attribute layer keyed by numeric
//! `UBUS_ATTR_*` ids. Wire shape:
//!
//! ```text
//!   [8B  ubus_msghdr]
//!   [4B  outer blob_attr id_len]   // id=0 (UNSPEC), len=total
//!   [    inner blob_attr stream]   // each: 4B id_len + payload + pad
//! ```
//!
//! Inner attrs are bare [`crate::blob`] (no name field). The named
//! blobmsg layer is only reached via [`UbusAttr::Data`].

use alloc::vec::Vec;

use crate::blob::{self, LEN_MASK};
use crate::error::UbusError;

/// Wire ids per OpenWrt libubox `UBUS_ATTR_*`.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UbusAttr {
    Status = 1,
    ObjPath = 2,
    ObjId = 3,
    Method = 4,
    ObjType = 5,
    Signature = 6,
    Data = 7,
    Target = 8,
    Active = 9,
    NoReply = 10,
    Subscribers = 11,
    User = 12,
    Group = 13,
}

/// Attribute ids carried inside a `MsgType::Monitor` envelope. These are a
/// separate id space from [`UbusAttr`]. The required wire order is Client,
/// Peer, Seq, Type, Send, Data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MonitorAttr {
    Client = 0,
    Peer = 1,
    Send = 2,
    Seq = 3,
    Type = 4,
    Data = 5,
}

impl UbusAttr {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Status,
            2 => Self::ObjPath,
            3 => Self::ObjId,
            4 => Self::Method,
            5 => Self::ObjType,
            6 => Self::Signature,
            7 => Self::Data,
            8 => Self::Target,
            9 => Self::Active,
            10 => Self::NoReply,
            11 => Self::Subscribers,
            12 => Self::User,
            13 => Self::Group,
            _ => return None,
        })
    }
}

pub struct EnvBuilder {
    /// Full outer-attr buffer (id=0 BLOB_ATTR_UNSPEC). The leading
    /// 4-byte `id_len` header is back-patched on `finish`.
    buf: Vec<u8>,
}

impl Default for EnvBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvBuilder {
    pub fn new() -> Self {
        Self::with_capacity(32)
    }

    /// Reserve the complete envelope to avoid growth while forwarding payloads.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut buf = Vec::with_capacity(capacity.max(4));
        buf.extend_from_slice(&[0u8; 4]);
        Self { buf }
    }

    pub fn push_str(&mut self, id: UbusAttr, val: &str) {
        let length = 4 + val.len() + 1;
        assert!(
            length <= LEN_MASK as usize,
            "attribute exceeds 24-bit length field"
        );
        self.buf
            .extend_from_slice(&(((id as u32) << 24) | length as u32).to_be_bytes());
        self.buf.extend_from_slice(val.as_bytes());
        self.buf.push(0);
        self.buf
            .resize(self.buf.len() + blob::align4(length) - length, 0);
    }

    pub fn push_u32(&mut self, id: UbusAttr, val: u32) {
        self.push(id, &val.to_be_bytes());
    }

    pub fn push_u32_id(&mut self, id: u8, val: u32) {
        self.push_raw(id, &val.to_be_bytes());
    }

    pub fn push_u8(&mut self, id: UbusAttr, val: u8) {
        self.push(id, &[val]);
    }

    pub fn push_u8_id(&mut self, id: u8, val: u8) {
        self.push_raw(id, &[val]);
    }

    pub fn push_i32(&mut self, id: UbusAttr, val: i32) {
        self.push(id, &val.to_be_bytes());
    }

    pub fn push_data(&mut self, blobmsg_outer: &[u8]) {
        self.push(UbusAttr::Data, blobmsg_outer);
    }

    pub fn push_bytes_id(&mut self, id: u8, payload: &[u8]) {
        self.push_raw(id, payload);
    }

    /// Raw signature blob produced by `BlobBuilder` (see
    /// `UbusConnection::register`). Other attrs use `push_str` /
    /// `push_u32` / `push_i32` / `push_data`.
    pub fn push_signature(&mut self, sig_blob: &[u8]) {
        self.push(UbusAttr::Signature, sig_blob);
    }

    pub fn push_container(&mut self, id: UbusAttr, build: impl FnOnce(&mut AttrBuilder)) {
        let mut inner = AttrBuilder::new();
        build(&mut inner);
        self.push(id, inner.as_slice());
    }

    fn push(&mut self, id: UbusAttr, payload: &[u8]) {
        self.push_raw(id as u8, payload);
    }

    fn push_raw(&mut self, id: u8, payload: &[u8]) {
        blob::encode_into(&mut self.buf, id, false, payload);
    }

    /// Panics on >16 MiB envelopes — silently truncating the declared
    /// length while the wire still carries the full byte stream would
    /// leave 1+ extra bytes at the head of the next frame on the
    /// receiver's socket and corrupt the connection. Real envelopes are
    /// kilobyte-scale; this exists to fail loudly on a programming error.
    pub fn finish(mut self) -> Vec<u8> {
        let total = self.buf.len();
        assert!(
            total <= LEN_MASK as usize,
            "envelope size exceeds 24-bit length field"
        );
        let id_len = total as u32;
        self.buf[..4].copy_from_slice(&id_len.to_be_bytes());
        self.buf
    }
}

pub struct AttrBuilder {
    buf: Vec<u8>,
}

impl Default for AttrBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AttrBuilder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push_u32_raw(&mut self, id: u8, val: u32) {
        self.push_raw(id, &val.to_be_bytes());
    }

    pub fn push_raw(&mut self, id: u8, payload: &[u8]) {
        blob::encode_into(&mut self.buf, id, false, payload);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EnvAttr<'a> {
    pub id: u8,
    pub payload: &'a [u8],
}

impl<'a> EnvAttr<'a> {
    /// Requires the payload to be NUL-terminated UTF-8. libubox always
    /// emits the NUL; treating an unterminated payload as "the whole
    /// buffer" would silently accept wire violations on Method /
    /// ObjPath strings.
    pub fn as_str(&self) -> Option<&'a str> {
        let p = self.payload;
        let end = p.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&p[..end]).ok()
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.payload.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]))
    }

    /// Decode this attr with libubox `blob_get_int8` semantics: the
    /// first payload byte is non-zero. An empty payload is false. In
    /// particular, a u32 encoding of one (`[0, 0, 0, 1]`) is false.
    pub fn as_bool_int8(&self) -> bool {
        self.payload.first().is_some_and(|byte| *byte != 0)
    }

    pub fn as_blobmsg(&self) -> &'a [u8] {
        self.payload
    }
}

/// Walks an envelope's inner-attr stream (after the 4-byte id_len
/// header). The `Iterator` impl is lossy (parse errors silently
/// terminate); strict consumers should call [`EnvIter::try_next`].
pub fn iter_attrs(buf: &[u8]) -> EnvIter<'_> {
    EnvIter { buf }
}

pub struct EnvIter<'a> {
    buf: &'a [u8],
}

impl<'a> EnvIter<'a> {
    /// Result-yielding parse step. On `Err`, the iterator is drained —
    /// TLV chains can't be safely resumed past corruption. Use this
    /// when "no more attrs" must be distinguishable from "attr stream
    /// went corrupt", e.g. server-side INVOKE dispatch.
    pub fn try_next(&mut self) -> Result<Option<EnvAttr<'a>>, UbusError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        match blob::BlobAttr::parse(self.buf) {
            Ok((attr, consumed)) => {
                self.buf = &self.buf[consumed..];
                Ok(Some(EnvAttr {
                    id: attr.id,
                    payload: attr.payload,
                }))
            }
            Err(e) => {
                self.buf = &[];
                Err(e)
            }
        }
    }
}

impl<'a> Iterator for EnvIter<'a> {
    type Item = EnvAttr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.try_next().ok().flatten()
    }
}

pub fn unwrap(frame_payload: &[u8]) -> Result<&[u8], UbusError> {
    if frame_payload.len() < 4 {
        return Err(UbusError::Short {
            need: 4,
            have: frame_payload.len(),
        });
    }
    let id_len = u32::from_be_bytes([
        frame_payload[0],
        frame_payload[1],
        frame_payload[2],
        frame_payload[3],
    ]);
    let total = (id_len & 0x00_FF_FF_FF) as usize;
    if total < 4 || total > frame_payload.len() {
        return Err(UbusError::Malformed("envelope outer length"));
    }
    Ok(&frame_payload[4..total])
}

/// Last attribute accepted by the pinned ubusd/libubox policy. Invalid
/// duplicates are skipped, so they do not hide an earlier valid value.
pub fn find(frame_payload: &[u8], id: UbusAttr) -> Option<EnvAttr<'_>> {
    let inner = unwrap(frame_payload).ok()?;
    iter_attrs(inner).filter(|a| policy_accepts(a, id)).last()
}

fn policy_accepts(attr: &EnvAttr<'_>, id: UbusAttr) -> bool {
    if attr.id != id as u8 {
        return false;
    }
    match id {
        UbusAttr::Status | UbusAttr::ObjId | UbusAttr::ObjType => attr.payload.len() == 4,
        UbusAttr::ObjPath | UbusAttr::Method | UbusAttr::User | UbusAttr::Group => {
            attr.payload.last() == Some(&0)
        }
        // ubusd's ubus_policy leaves Target, Active and NoReply UNSPEC.
        // Their widths are not filtered: e.g. a later u32 NoReply=1 is
        // accepted and its first byte (zero) overrides an earlier INT8=1.
        _ => true,
    }
}

/// Like `find` but distinguishes "envelope malformed" from "attr
/// absent". Use this when the *absence* of the attr is a protocol error
/// (e.g. STATUS frames where the Status attr is mandatory) — a callsite
/// using `find` cannot tell `Ok(missing)` from `Ok(garbage envelope)`.
/// Surfaces both outer-envelope and inner-stream parse errors.
pub fn try_find(frame_payload: &[u8], id: UbusAttr) -> Result<Option<EnvAttr<'_>>, UbusError> {
    let inner = unwrap(frame_payload)?;
    let mut it = iter_attrs(inner);
    let mut found = None;
    while let Some(a) = it.try_next()? {
        if policy_accepts(&a, id) {
            found = Some(a);
        }
    }
    Ok(found)
}

/// Decode an `i32` STATUS attr or surface a Malformed envelope. Returns
/// `Err(Malformed)` when the envelope is corrupt OR the Status attr is
/// missing/short (peer must always include it on STATUS frames). The
/// `as_u32 → as i32` round-trip is sound: `EnvBuilder::push_i32` writes
/// `i32::to_be_bytes` which is bit-identical to `(val as u32).to_be_bytes`.
pub fn read_status(frame_payload: &[u8]) -> Result<i32, UbusError> {
    try_find(frame_payload, UbusAttr::Status)?
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .ok_or(UbusError::Malformed("missing or short Status attr"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_policy_skips_invalid_values_and_selects_last_valid() {
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, 7);
        env.push_bytes_id(UbusAttr::ObjId as u8, &[0, 0, 0, 9, 0]);
        env.push_u32(UbusAttr::ObjId, 11);
        env.push_bytes_id(UbusAttr::ObjId as u8, &[0]);
        env.push_str(UbusAttr::Method, "first");
        env.push_str(UbusAttr::Method, "last");
        env.push_bytes_id(UbusAttr::Method as u8, b"invalid");
        let bytes = env.finish();
        assert_eq!(
            find(&bytes, UbusAttr::ObjId).and_then(|a| a.as_u32()),
            Some(11)
        );
        assert_eq!(
            find(&bytes, UbusAttr::Method).and_then(|a| a.as_str()),
            Some("last")
        );
        assert_eq!(
            try_find(&bytes, UbusAttr::ObjId).unwrap().unwrap().as_u32(),
            Some(11)
        );
    }

    #[test]
    fn build_and_iter_round_trip() {
        let mut b = EnvBuilder::new();
        b.push_str(UbusAttr::ObjPath, "example");
        b.push_u32(UbusAttr::ObjId, 0xDEADBEEF);
        let body = b.finish();

        let inner = unwrap(&body).unwrap();
        let attrs: alloc::vec::Vec<EnvAttr> = iter_attrs(inner).collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].id, UbusAttr::ObjPath as u8);
        assert_eq!(attrs[0].as_str(), Some("example"));
        assert_eq!(attrs[1].id, UbusAttr::ObjId as u8);
        assert_eq!(attrs[1].as_u32(), Some(0xDEADBEEF));
    }

    #[test]
    fn find_locates_attr() {
        let mut b = EnvBuilder::new();
        b.push_str(UbusAttr::Method, "ping");
        b.push_str(UbusAttr::ObjPath, "obj");
        let body = b.finish();
        assert_eq!(
            find(&body, UbusAttr::Method).and_then(|a| a.as_str()),
            Some("ping")
        );
        assert_eq!(
            find(&body, UbusAttr::ObjPath).and_then(|a| a.as_str()),
            Some("obj")
        );
        assert!(find(&body, UbusAttr::Status).is_none());
    }

    #[test]
    fn push_u8_encodes_one_byte_attr_with_padding() {
        let mut b = EnvBuilder::new();
        b.push_u8(UbusAttr::Active, 1);
        let body = b.finish();

        assert_eq!(
            &body[4..],
            &[0x09, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            find(&body, UbusAttr::Active).map(|a| a.payload),
            Some(&[1][..])
        );
    }

    #[test]
    fn bool_int8_uses_the_first_payload_byte() {
        assert!(EnvAttr {
            id: UbusAttr::NoReply as u8,
            payload: &[1],
        }
        .as_bool_int8());
        assert!(!EnvAttr {
            id: UbusAttr::NoReply as u8,
            payload: &[0],
        }
        .as_bool_int8());
        assert!(!EnvAttr {
            id: UbusAttr::NoReply as u8,
            payload: &[0, 0, 0, 1],
        }
        .as_bool_int8());
        assert!(EnvAttr {
            id: UbusAttr::NoReply as u8,
            payload: &[1, 0, 0, 0],
        }
        .as_bool_int8());
        assert!(!EnvAttr {
            id: UbusAttr::NoReply as u8,
            payload: &[],
        }
        .as_bool_int8());
    }

    #[test]
    fn push_container_wraps_nested_raw_attrs() {
        let mut b = EnvBuilder::new();
        b.push_container(UbusAttr::Subscribers, |subs| {
            subs.push_u32_raw(0, 0x1122_3344);
            subs.push_u32_raw(0, 0x5566_7788);
        });
        let body = b.finish();
        let subs = find(&body, UbusAttr::Subscribers).expect("Subscribers attr");
        let nested: alloc::vec::Vec<_> = blob::BlobAttr::iter(subs.payload)
            .map(|a| {
                let a = a.expect("nested attr");
                (a.id, a.payload.to_vec())
            })
            .collect();

        assert_eq!(
            nested,
            alloc::vec![
                (0, 0x1122_3344u32.to_be_bytes().to_vec()),
                (0, 0x5566_7788u32.to_be_bytes().to_vec()),
            ]
        );
    }

    #[test]
    fn monitor_attrs_preserve_required_wire_order() {
        let mut b = EnvBuilder::new();
        b.push_u32_id(MonitorAttr::Client as u8, 1);
        b.push_u32_id(MonitorAttr::Peer as u8, 2);
        b.push_u32_id(MonitorAttr::Seq as u8, 3);
        b.push_u32_id(MonitorAttr::Type as u8, 4);
        b.push_u8_id(MonitorAttr::Send as u8, 1);
        b.push_bytes_id(MonitorAttr::Data as u8, &[5]);
        let ids: alloc::vec::Vec<_> = iter_attrs(unwrap(&b.finish()).unwrap())
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, [0, 1, 3, 4, 2, 5]);
    }

    #[test]
    fn try_next_surfaces_parse_errors() {
        // Outer envelope wraps an inner attr stream. Build a valid
        // envelope and corrupt the second inner attr's id_len so its
        // declared total exceeds the buffer.
        let mut b = EnvBuilder::new();
        b.push_str(UbusAttr::Method, "ping");
        b.push_u32(UbusAttr::ObjId, 0xDEAD);
        let mut body = b.finish();
        // First inner attr starts at offset 4 (after outer id_len).
        // Walk to the second attr and overwrite its declared length.
        let inner = unwrap(&body).unwrap();
        let first_consumed = blob::BlobAttr::parse(inner).unwrap().1;
        let second_attr_offset = 4 + first_consumed;
        // Set declared total to a giant value so parse rejects.
        body[second_attr_offset + 1] = 0xFF;
        body[second_attr_offset + 2] = 0xFF;
        body[second_attr_offset + 3] = 0xFF;
        let inner = unwrap(&body).unwrap();
        let mut it = iter_attrs(inner);
        // First attr parses fine.
        assert_eq!(
            it.try_next().unwrap().map(|a| a.id),
            Some(UbusAttr::Method as u8)
        );
        // Second attr surfaces parse error instead of silently terminating.
        assert!(matches!(it.try_next(), Err(UbusError::Short { .. })));
    }

    #[test]
    fn try_find_surfaces_envelope_corruption_distinct_from_missing() {
        // Empty envelope: try_find returns Ok(None) (no attr).
        let body = EnvBuilder::new().finish();
        assert!(try_find(&body, UbusAttr::Status).unwrap().is_none());
        // Truncated outer wrapper: returns Err.
        assert!(matches!(
            try_find(&[1, 2, 3], UbusAttr::Status),
            Err(UbusError::Short { .. })
        ));
    }
}
