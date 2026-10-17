//! Pure protocol dispatch: `dispatch(frame, src_peer, &mut state) → Vec<Action>`.
//!
//! No socket I/O lives here. The broker's outer loop reads a frame,
//! calls [`dispatch`], and applies each [`Action`] (write to a peer's
//! tx buffer, schedule a peer for close). This split is what lets the
//! protocol matrix be unit-tested in isolation under
//! `cargo test -p ubusd`.
//!
//! The split also keeps the bug surface small: the routing logic is
//! the most intricate part, and a function that takes plain data
//! and returns plain actions is straightforward to reason about.
//!
//! `frame.hdr.peer` is a bare `u32` on the wire whose meaning shifts
//! with [`MsgType`] — caller peer-id, target obj-id, dest peer-id,
//! or unused. Each handler reinterprets it through
//! [`PeerId::new`] / [`ObjectId::new`] at the wire boundary; from
//! there on the type system enforces axis discipline.

use std::sync::Arc;

use rustix::fd::OwnedFd;

use ubus::blobmsg::{lookup as blobmsg_lookup, BlobBuilder, BlobMsgTable};
use ubus::envelope::{find, UbusAttr};
use ubus::wire::{
    Codec, Frame, FrameRef, MsgType, UBUS_STATUS_INVALID_ARGUMENT, UBUS_STATUS_INVALID_COMMAND,
    UBUS_STATUS_METHOD_NOT_FOUND, UBUS_STATUS_NOT_FOUND, UBUS_STATUS_PERMISSION_DENIED,
    UBUS_SYSTEM_OBJECT_ACL, UBUS_SYSTEM_OBJECT_MONITOR,
};

use crate::acl::{append_priv_blob, AclOp, AclRegistry, Cred};
use crate::registry::{
    EventRegistry, MonitorRegistry, ObjectId, ObjectRegistry, PeerId, PeerTable,
    SubscriberRegistry, Subscription,
};
use crate::reply;

/// Builtin `ubus.event` system object id (`UBUS_SYSTEM_OBJECT_EVENT`).
/// INVOKE carrying this id in `UbusAttr::ObjId` is a `register` / `send`
/// against the event bus, handled entirely inside the broker — it never
/// enters the object registry (rs reserves the system range; `FIRST_OBJ_ID = 4`).
const EVENT_OBJECT_ID: u32 = 1;

/// One side-effect emitted by `dispatch`. The broker's outer loop
/// turns these into socket writes and book-keeping.
#[derive(Debug)]
pub enum Action {
    /// Write `frame` to the peer with id `peer_id`. If the peer is
    /// gone (race with a concurrent disconnect), the broker drops
    /// the frame silently — no resurrection.
    SendTo {
        peer_id: PeerId,
        frame: Frame,
        fd: Option<OwnedFd>,
    },
    /// Pre-encoded fan-out: the same on-wire bytes go to many peers
    /// without each peer paying an independent frame clone + encode.
    /// NOTIFY across N subscribers ends up as N of these sharing one
    /// `Arc<[u8]>`, so the heap cost of the body is paid once.
    SendBytes { peer_id: PeerId, bytes: Arc<[u8]> },
    /// Schedule a peer for close after the current poll iteration
    /// finishes draining. Deferred via `Broker::pending_close` so the
    /// in-flight dispatch loop iterates over a stable peer set.
    ClosePeer { peer_id: PeerId },
}

impl Action {
    fn send(peer_id: PeerId, frame: Frame) -> Self {
        Self::SendTo {
            peer_id,
            frame,
            fd: None,
        }
    }
}

/// Apply protocol decisions for a single inbound frame.
///
/// `src_peer` is the peer-id of the connection the frame came from.
/// HELLO is special: the caller is brand new and doesn't have an id
/// yet, so the broker assigns one **before** entering this function
/// and passes the freshly-allocated id as `src_peer`.
#[allow(clippy::too_many_arguments)]
pub fn dispatch(
    frame: &Frame,
    src_peer: PeerId,
    acl: &AclRegistry,
    acl_sequence: u32,
    peers: &mut PeerTable,
    objects: &mut ObjectRegistry,
    subs: &mut SubscriberRegistry,
    events: &mut EventRegistry,
    monitors: &mut MonitorRegistry,
    frame_fd: &mut Option<OwnedFd>,
) -> Vec<Action> {
    dispatch_ref(
        &FrameRef::from(frame),
        src_peer,
        acl,
        acl_sequence,
        peers,
        objects,
        subs,
        events,
        monitors,
        frame_fd,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_ref(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    acl: &AclRegistry,
    acl_sequence: u32,
    peers: &mut PeerTable,
    objects: &mut ObjectRegistry,
    subs: &mut SubscriberRegistry,
    events: &mut EventRegistry,
    monitors: &mut MonitorRegistry,
    frame_fd: &mut Option<OwnedFd>,
) -> Vec<Action> {
    let cred = peers
        .get(src_peer)
        .map(crate::peer::Peer::cred)
        .unwrap_or_default();
    match frame.hdr.ty {
        MsgType::Hello => dispatch_hello(frame, src_peer),
        MsgType::AddObject => {
            dispatch_add_object(frame, src_peer, &cred, acl, peers, objects, subs, events)
        }
        MsgType::RemoveObject => {
            dispatch_remove_object(frame, src_peer, peers, objects, subs, events)
        }
        MsgType::Lookup => dispatch_lookup(frame, src_peer, &cred, acl, objects),
        MsgType::Invoke => dispatch_invoke(
            frame,
            src_peer,
            &cred,
            acl,
            acl_sequence,
            peers,
            objects,
            events,
            monitors,
            frame_fd,
        ),
        MsgType::Subscribe => dispatch_subscribe(frame, src_peer, &cred, acl, peers, objects, subs),
        MsgType::Unsubscribe => dispatch_unsubscribe(frame, src_peer, peers, objects, subs),
        MsgType::Notify => dispatch_notify(frame, src_peer, peers, objects, subs),
        MsgType::Ping => dispatch_ping(frame, src_peer),
        // DATA / STATUS coming in from a registered owner are
        // replies to a previously-forwarded INVOKE: the owner has
        // already addressed `hdr.peer = caller_peer_id`, so we just
        // forward by destination address.
        MsgType::Data | MsgType::Status => {
            forward_owner_response(frame, src_peer, objects, frame_fd)
        }
        MsgType::Monitor => status_action(frame, src_peer, UBUS_STATUS_INVALID_COMMAND),
    }
}

fn dispatch_hello(frame: &FrameRef<'_>, src_peer: PeerId) -> Vec<Action> {
    // The unsolicited HELLO is pushed by `accept_pending`; any HELLO
    // arriving via `dispatch` is a redundant client greeting on an
    // already-handshaked connection. Upstream `ubusd` replies with
    // `STATUS = UBUS_STATUS_INVALID_COMMAND` (status code 1) on the
    // request's seq — verified by an upstream-vs-rs frame dump — so
    // mirror that exactly. A libubus client decoding our reply must
    // see the same bytes either broker emits.
    status_action(frame, src_peer, UBUS_STATUS_INVALID_COMMAND)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_add_object(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    cred: &Cred,
    acl: &AclRegistry,
    peers: &mut PeerTable,
    objects: &mut ObjectRegistry,
    subs: &mut SubscriberRegistry,
    events: &mut EventRegistry,
) -> Vec<Action> {
    let signature = find(frame.payload, UbusAttr::Signature)
        .and_then(|attr| object_signature(attr.as_blobmsg()));
    // Named objects broadcast `ubus.object.add` once registered; capture
    // the path so we can mint that event after the owner's reply.
    let mut named_path: Option<String> = None;
    let (obj_id, replaced) = match find(frame.payload, UbusAttr::ObjPath).and_then(|a| a.as_str()) {
        Some(path) => {
            if !acl.check(cred, path, AclOp::Publish, None) {
                return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
            }
            match objects.insert(path.to_string(), src_peer, signature) {
                Ok(v) => {
                    named_path = Some(path.to_string());
                    v
                }
                Err(_) => {
                    // libubus' UBUS_STATUS_* enum has no resource-exhaustion
                    // variant. Use INVALID_ARGUMENT to match the broker's
                    // other local AddObject rejection shape; upstream `ubusd`
                    // uses an unchecked allocator, so there is no parity
                    // target to match.
                    log::error!(
                        "ubusd: peer {src_peer} AddObject refused — obj id space exhausted"
                    );
                    return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
                }
            }
        }
        None => match objects.insert_anonymous(src_peer) {
            Ok(id) => (id, None),
            Err(_) => {
                // Same exhaustion shape as named ADD_OBJECT: no ubus
                // resource-exhaustion status exists, so reject locally
                // while keeping the broker alive for other peers.
                log::error!(
                    "ubusd: peer {src_peer} anonymous AddObject refused — obj id space exhausted"
                );
                return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
            }
        },
    };
    // Last-writer-wins re-registration: scrub the displaced obj-id
    // from its old owner's `owned` list and from any subscriber lists
    // keyed at it, so disconnect reaping doesn't chase a stale id and
    // NOTIFY fan-out can't leak to a list that outlived the object.
    if let Some((prev_id, prev_owner)) = replaced {
        if let Some(prev_peer) = peers.get_mut(prev_owner) {
            prev_peer.remove_owned(prev_id);
        }
        subs.purge_peer(prev_owner, &[prev_id], &[]);
    }
    // Mirror onto the peer's own owned-list so the disconnect reaper
    // doesn't have to scan every registered object to find this peer's.
    if let Some(peer) = peers.get_mut(src_peer) {
        peer.add_owned(obj_id);
    }
    // Upstream `ubusd` answers a successful ADD_OBJECT with two frames:
    // a DATA frame carrying the assigned OBJID, then a plain STATUS(0)
    // (status attr only). libubus' `ubus_add_object` harvests the id
    // exclusively from the DATA frame — a lone STATUS with an inline
    // OBJID leaves a real client with `UBUS_STATUS_NO_DATA`.
    let mut out = add_or_remove_reply(
        src_peer,
        frame,
        obj_id,
        objects.type_of(obj_id).map(|t| t.id()),
    );
    // A named registration broadcasts `ubus.object.add` to matching
    // listeners (anonymous objects are silent — pathless, LOOKUP-hidden).
    if let Some(path) = named_path {
        out.extend(object_lifecycle_fanout(
            events,
            "ubus.object.add",
            obj_id,
            &path,
            src_peer,
        ));
    }
    out
}

fn dispatch_remove_object(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    peers: &mut PeerTable,
    objects: &mut ObjectRegistry,
    subs: &mut SubscriberRegistry,
    events: &mut EventRegistry,
) -> Vec<Action> {
    let obj_id = match find(frame.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .and_then(ObjectId::new)
    {
        Some(id) => id,
        None => return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT),
    };
    // Upstream `ubusd` distinguishes the two failure modes: an unknown
    // obj id is `UBUS_STATUS_NOT_FOUND`, an object owned by a *different*
    // client is `UBUS_STATUS_PERMISSION_DENIED`. Only the owner may
    // remove its own object.
    match objects.owner_of(obj_id) {
        None => return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND),
        Some(owner) if owner != src_peer => {
            return status_action(frame, src_peer, UBUS_STATUS_PERMISSION_DENIED)
        }
        Some(_) => {}
    }
    let obj_type = objects.type_of(obj_id).map(|t| t.id());
    // Capture the path before the entry is dropped so the matching
    // `ubus.object.remove` broadcast can carry it.
    let named_path = objects.named_path(obj_id).map(str::to_string);
    objects.remove(obj_id);
    // Upstream `ubusd_free_object()` walks `obj->target_list` first:
    // every subscription where *this* object is the subscriber is torn
    // down, and each publisher left with no subscribers gets an
    // `Active=0` notify. The registry is keyed by target, so the peer's
    // own `subs` mirror is what narrows the search.
    let subscribed_to = peers
        .get(src_peer)
        .map(|p| p.subs_snapshot())
        .unwrap_or_default();
    let (detached, emptied) = subs.remove_subscriber_object(src_peer, obj_id, &subscribed_to);
    let dead_subscribers = subs.remove_object(obj_id);
    let unsubscribe_actions = unsubscribe_for_dead_objects(peers, &[(obj_id, dead_subscribers)]);
    // Targeted purge: the only obj_id whose subscriber-list could
    // be affected is this one, and every subscription *via this object*
    // was already dropped above, so an empty `subscribed_to` suffices.
    subs.purge_peer(src_peer, &[obj_id], &[]);
    if let Some(peer) = peers.get_mut(src_peer) {
        peer.remove_owned(obj_id);
        // The mirror is a set of targets, not of subscriptions: only
        // forget a target once no sibling subscriber object still holds
        // it.
        for target in &detached {
            if subs
                .subscribers_of(*target)
                .iter()
                .all(|s| s.peer_id != src_peer)
            {
                peer.remove_sub(*target);
            }
        }
    }
    let active_zero = active_zero_for_purged_subscriptions(peers, objects, &emptied);
    // Upstream frees the object's `event_source` list in
    // `ubusd_event_cleanup_object()` — before the `ubus.object.remove`
    // broadcast, so the removed listener never sees its own removal.
    events.remove_object(obj_id);
    // Same two-frame shape as ADD_OBJECT: DATA(OBJID) then STATUS(0).
    let mut out = add_or_remove_reply(src_peer, frame, obj_id, obj_type);
    out.extend(active_zero);
    out.extend(unsubscribe_actions);
    // A named removal broadcasts `ubus.object.remove` to listeners.
    if let Some(path) = named_path {
        out.extend(object_lifecycle_fanout(
            events,
            "ubus.object.remove",
            obj_id,
            &path,
            src_peer,
        ));
    }
    out
}

/// Broker reply to a successful ADD_OBJECT / REMOVE_OBJECT: a
/// `DATA(OBJID)` frame followed by a plain `STATUS(0)` (status attr
/// only), matching upstream `ubusd`. Both frames echo the request's
/// seq/peer via [`reply`].
fn add_or_remove_reply(
    dest: PeerId,
    frame: &FrameRef<'_>,
    obj_id: ObjectId,
    obj_type: Option<ObjectId>,
) -> Vec<Action> {
    vec![
        Action::send(
            dest,
            reply::obj_id_data(frame.hdr.seq, frame.hdr.peer, obj_id, obj_type),
        ),
        Action::send(dest, reply::status_reply(frame.hdr.seq, frame.hdr.peer, 0)),
    ]
}

/// Mirror ubus_create_obj_type's method walk. A malformed declared method
/// discards the entire type, while an incomplete trailing attr stops the
/// blob_for_each_attr walk and retains the complete methods before it.
fn object_signature(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut remaining = bytes;
    let mut signature = Vec::new();
    while remaining.len() >= 4 {
        let raw_len =
            (u32::from_be_bytes(remaining[..4].try_into().unwrap()) & 0x00ff_ffff) as usize;
        let padded = ubus::blob::align4(raw_len);
        if padded < 4 || padded > remaining.len() {
            break;
        }
        let (attr, _) = ubus::blob::BlobAttr::parse(remaining).ok()?;
        if !attr.extended || attr.id > 8 || attr.payload.len() < 2 {
            return None;
        }
        let name_len = u16::from_be_bytes(attr.payload[..2].try_into().unwrap()) as usize;
        let data_start = ubus::blob::align4(2 + name_len + 1);
        if name_len == 0 || data_start > attr.payload.len() || attr.payload[2 + name_len] != 0 {
            return None;
        }
        let data = &attr.payload[data_start..];
        // Pinned libubox blob_check_type requires exact integer widths.
        // Its double case instead accepts any payload of at least 8 bytes.
        let valid = match attr.id {
            3 => !data.is_empty() && data.last() == Some(&0),
            4 => data.len() == 8,
            5 => data.len() == 4,
            6 => data.len() == 2,
            7 => data.len() == 1,
            8 => data.len() >= 8,
            _ => true,
        };
        if !valid {
            return None;
        }
        signature.extend_from_slice(&remaining[..padded]);
        remaining = &remaining[padded..];
    }
    Some(signature)
}

fn dispatch_lookup(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    cred: &Cred,
    acl: &AclRegistry,
    objects: &ObjectRegistry,
) -> Vec<Action> {
    // If the caller didn't include a path attr we treat it as "list
    // everything" — matches libubus for `ubus list`. libubox drops an
    // ObjPath whose payload is not a NUL-terminated string, so it is
    // likewise list-all here. A valid present empty path is invalid. A
    // non-empty path
    // is a wildcard *only* when its last byte is `*`: upstream `ubusd`
    // strips that trailing star and prefix-matches the literal
    // remainder against its path AVL. It is NOT fnmatch — `?`, `[...]`,
    // and any embedded `*` are matched literally (probed live:
    // `example.[ag]*` returns NOT_FOUND even with `example.alpha`
    // registered). Everything else is an exact-path lookup.
    let path_attr = lookup_obj_path(frame.payload);
    if path_attr == Some("") {
        return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
    }
    let mut out: Vec<Action> = Vec::new();
    let matches: Vec<(ObjectId, &str)> = match path_attr {
        Some(p) if !p.is_empty() => match p.strip_suffix('*') {
            Some(prefix) => {
                // NOT_FOUND fires only when nothing carries the prefix.
                // Untyped matches count toward "found" but emit no DATA
                // (LOOKUP-invisible), exactly like `ubusd_send_obj`.
                if !objects.any_path_with_prefix(prefix) {
                    return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND);
                }
                objects
                    .iter_typed_prefix(prefix)
                    .map(|(id, path, _)| (id, path))
                    .collect()
            }
            None => match objects.lookup_exact(p) {
                Some(id) if objects.type_of(id).is_some() => vec![(id, p)],
                Some(_) => Vec::new(),
                None => return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND),
            },
        },
        _ => sorted_typed_paths(objects),
    };
    for (id, path) in matches {
        let obj_type = objects
            .type_of(id)
            .expect("typed LOOKUP match must still have ObjectType");
        let signature = obj_type.signature();
        let filtered;
        let signature = if cred.uid == Some(0) {
            signature
        } else {
            let grants = acl.matching_access_grants(cred, path);
            let mut remaining = signature;
            let mut allowed = Vec::new();
            let mut declared = 0;
            while let Ok((_, consumed)) = ubus::blob::BlobAttr::parse(remaining) {
                declared += 1;
                let raw = &remaining[..consumed];
                if let Some(method) = ubus::blobmsg::BlobIter::new(raw)
                    .next()
                    .and_then(|attr| attr.name)
                {
                    if grants.iter().any(|grant| grant.allows_method(method)) {
                        allowed.extend_from_slice(raw);
                    }
                }
                remaining = &remaining[consumed..];
            }
            if declared > 0 && allowed.is_empty() {
                continue;
            }
            filtered = allowed;
            filtered.as_slice()
        };
        out.push(Action::send(
            src_peer,
            reply::lookup_data_with_signature(
                frame.hdr.seq,
                frame.hdr.peer,
                id,
                path,
                obj_type,
                signature,
            ),
        ));
    }
    out.push(Action::send(
        src_peer,
        reply::status_reply(frame.hdr.seq, frame.hdr.peer, 0),
    ));
    out
}

/// Mirror `blob_parse()` string validation for LOOKUP's ObjPath: a
/// string attr is visible only when it has a non-empty NUL-terminated
/// payload. Invalid payloads are dropped before ubusd's lookup handler.
fn lookup_obj_path(payload: &[u8]) -> Option<&str> {
    find(payload, UbusAttr::ObjPath)
        .filter(|attr| !attr.payload.is_empty() && attr.payload.last() == Some(&0))
        .and_then(|attr| attr.as_str())
}

fn sorted_typed_paths(objects: &ObjectRegistry) -> Vec<(ObjectId, &str)> {
    objects
        .iter_typed_paths()
        .map(|(id, path, _)| (id, path))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn dispatch_invoke(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    cred: &Cred,
    acl: &AclRegistry,
    acl_sequence: u32,
    peers: &PeerTable,
    objects: &ObjectRegistry,
    events: &mut EventRegistry,
    monitors: &mut MonitorRegistry,
    frame_fd: &mut Option<OwnedFd>,
) -> Vec<Action> {
    let method = find(frame.payload, UbusAttr::Method).and_then(|a| a.as_str());
    let obj_id = find(frame.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .and_then(ObjectId::new);
    let (Some(method), Some(obj_id)) = (method, obj_id) else {
        return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
    };
    // INVOKE carrying the builtin event object's ObjId attr is `register` /
    // `send` against the event bus — handled inside the broker, never
    // forwarded to an owner.
    if obj_id.get() == EVENT_OBJECT_ID {
        return dispatch_event_builtin(frame, src_peer, cred, acl, objects, events);
    }
    if obj_id.get() == UBUS_SYSTEM_OBJECT_ACL {
        return dispatch_acl_builtin(frame, src_peer, method, objects, acl, acl_sequence);
    }
    if obj_id.get() == UBUS_SYSTEM_OBJECT_MONITOR {
        return dispatch_monitor_builtin(frame, src_peer, peers, monitors);
    }
    // The ObjId attr identifies the target; hdr.peer is echoed only.
    // We look up the owner peer-id and rewrite `hdr.peer = src_peer` so the
    // owner addresses the reply at the caller (matching what
    // `UbusConnection::dispatch_invoke` does — it copies
    // `frame.hdr.peer` straight into its DATA/STATUS replies).
    match objects.owner_of(obj_id) {
        Some(owner) => {
            if let Some(path) = objects.named_path(obj_id) {
                if !acl.check(cred, path, AclOp::Access, Some(method)) {
                    return status_action(frame, src_peer, UBUS_STATUS_PERMISSION_DENIED);
                }
            }
            let (user, group) = peer_names(peers, src_peer);
            vec![Action::SendTo {
                peer_id: owner,
                frame: reply::stamped_forwarded_invoke_ref(frame, src_peer, obj_id, user, group),
                fd: frame_fd.take(),
            }]
        }
        None => status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND),
    }
}

/// INVOKE against `ubus`' ACL system object. The missing/unknown object-id
/// ladder in upstream's `ubusd_reply_query` is unreachable here: INVOKE has
/// already required and resolved METHOD + OBJID before entering this branch.
fn dispatch_acl_builtin(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    method: &str,
    objects: &ObjectRegistry,
    acl: &AclRegistry,
    acl_sequence: u32,
) -> Vec<Action> {
    if method != "query" {
        return status_action(frame, src_peer, UBUS_STATUS_INVALID_COMMAND);
    }
    let mut data = BlobBuilder::new();
    data.put_i32(Some("seq"), acl_sequence as i32);
    data.open_array(Some("acl"));
    for (_, path) in objects.named_objects_of(src_peer) {
        for grant in acl.priv_grants_matching(path) {
            data.open_table(None);
            data.put_str(Some("obj"), path);
            if let Some(user) = grant.user {
                data.put_str(Some("user"), user);
            }
            if let Some(group) = grant.group {
                data.put_str(Some("group"), group);
            }
            data.open_table(Some("acl"));
            if append_priv_blob(&mut data, grant.blob).is_err() {
                // Parsed ACL blobs originate from our own encoder. Keep a
                // malformed literal from turning a broker query into panic.
                data.close_table();
                data.close_table();
                continue;
            }
            data.close_table();
            data.close_table();
        }
    }
    data.close_array();
    let mut env = ubus::envelope::EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, UBUS_SYSTEM_OBJECT_ACL);
    env.push_data(&data.finish());
    vec![
        Action::send(
            src_peer,
            Frame::to_peer(MsgType::Data, frame.hdr.seq, frame.hdr.peer, env.finish()),
        ),
        Action::send(
            src_peer,
            reply::status_reply(frame.hdr.seq, frame.hdr.peer, 0),
        ),
    ]
}

/// INVOKE against upstream's monitor system object (`ObjId == 3`). The uid
/// gate intentionally precedes method lookup, including unknown methods.
fn dispatch_monitor_builtin(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    peers: &PeerTable,
    monitors: &mut MonitorRegistry,
) -> Vec<Action> {
    if peers.get(src_peer).and_then(|peer| peer.credentials.uid) != Some(0) {
        return status_action(frame, src_peer, UBUS_STATUS_PERMISSION_DENIED);
    }
    match find(frame.payload, UbusAttr::Method).and_then(|a| a.as_str()) {
        Some("add") => {
            monitors.add(src_peer);
            status_action(frame, src_peer, 0)
        }
        Some("remove") => {
            monitors.remove(src_peer);
            status_action(frame, src_peer, 0)
        }
        _ => status_action(frame, src_peer, UBUS_STATUS_METHOD_NOT_FOUND),
    }
}

/// INVOKE against the builtin event object (`ObjId == 1`): dispatch
/// on the METHOD attr. Both `register` and `send` reply with a plain
/// `STATUS(0)` echoing the request's seq/peer, exactly like upstream.
fn dispatch_event_builtin(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    cred: &Cred,
    acl: &AclRegistry,
    objects: &ObjectRegistry,
    events: &mut EventRegistry,
) -> Vec<Action> {
    let data = find(frame.payload, UbusAttr::Data)
        .map(|a| a.payload)
        .unwrap_or(&[]);
    match find(frame.payload, UbusAttr::Method).and_then(|a| a.as_str()) {
        Some("register") => {
            dispatch_event_register(frame, src_peer, cred, acl, objects, events, data)
        }
        Some("send") => dispatch_event_send(frame, src_peer, cred, acl, events, data),
        // Unknown builtin method: upstream has only register/send.
        _ => status_action(frame, src_peer, UBUS_STATUS_INVALID_COMMAND),
    }
}

/// `ubus listen` registration: DATA blobmsg `{object: u32, pattern:
/// string}`. The object must be one the caller owns (libubus registers
/// an anonymous object first). Only a *trailing* `*` is a wildcard.
fn dispatch_event_register(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    cred: &Cred,
    acl: &AclRegistry,
    objects: &ObjectRegistry,
    events: &mut EventRegistry,
    data: &[u8],
) -> Vec<Action> {
    let object = blobmsg_lookup(data, "object")
        .and_then(|r| r.as_i32())
        .map(|v| v as u32)
        .and_then(ObjectId::new);
    let pattern = blobmsg_lookup(data, "pattern").and_then(|r| r.as_str());
    let (Some(object), Some(pattern)) = (object, pattern) else {
        return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
    };
    match objects.owner_of(object) {
        None => return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND),
        Some(owner) if owner != src_peer => {
            return status_action(frame, src_peer, UBUS_STATUS_PERMISSION_DENIED)
        }
        Some(_) => {}
    }
    let acl_path = pattern.strip_suffix('*').unwrap_or(pattern);
    if !acl.check(cred, acl_path, AclOp::Listen, None) {
        return status_action(frame, src_peer, UBUS_STATUS_PERMISSION_DENIED);
    }
    let (prefix, partial) = match pattern.strip_suffix('*') {
        Some(p) => (p.to_string(), true),
        None => (pattern.to_string(), false),
    };
    events.register(prefix, partial, src_peer, object);
    status_action(frame, src_peer, 0)
}

/// `ubus send`: DATA blobmsg `{id: string, data: table}`. Fan the inner
/// `data` table out to every matching listener (the sender's own
/// listeners are suppressed), then ack the sender with `STATUS(0)`.
fn dispatch_event_send(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    cred: &Cred,
    acl: &AclRegistry,
    events: &mut EventRegistry,
    data: &[u8],
) -> Vec<Action> {
    let Some(event_id) = blobmsg_lookup(data, "id").and_then(|r| r.as_str()) else {
        return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
    };
    if !acl.check(cred, event_id, AclOp::Send, None) {
        return status_action(frame, src_peer, UBUS_STATUS_PERMISSION_DENIED);
    }
    let event_data = blobmsg_lookup(data, "data")
        .map(|r| r.payload)
        .unwrap_or(&[]);
    let mut out = event_fanout(events, event_id, event_data, Some(src_peer));
    out.extend(status_action(frame, src_peer, 0));
    out
}

/// Deliver `event_id` (+`data`) to every matching listener in upstream's
/// pattern-sorted order, each stamped with the next global fan-out seq.
/// `exclude` suppresses the originating peer (loop-back guard).
pub(crate) fn event_fanout(
    events: &mut EventRegistry,
    event_id: &str,
    data: &[u8],
    exclude: Option<PeerId>,
) -> Vec<Action> {
    let targets = events.matching_sorted(event_id, exclude);
    targets
        .into_iter()
        .map(|(peer_id, obj_id)| {
            let seq = events.next_seq();
            Action::send(peer_id, reply::event_invoke(seq, obj_id, event_id, data))
        })
        .collect()
}

/// Broker-minted `ubus.object.add`/`remove`: an event whose payload is
/// `{id: <obj_id>, path: <path>}`. `owner` is the changed object's owner
/// (suppressed from delivery, mirroring upstream's `cl = obj->client`).
fn object_lifecycle_fanout(
    events: &mut EventRegistry,
    event_name: &str,
    obj_id: ObjectId,
    path: &str,
    owner: PeerId,
) -> Vec<Action> {
    let data = BlobMsgTable::build(|b| {
        b.put_i32(Some("id"), obj_id.get() as i32);
        b.put_str(Some("path"), path);
    });
    event_fanout(events, event_name, data.contents(), Some(owner))
}

/// Crate-visible `ubus.object.remove` fan-out for the broker's
/// disconnect reaper (an owner drop reaps its named objects without a
/// REMOVE_OBJECT frame, yet upstream still broadcasts the removal).
pub(crate) fn object_remove_fanout(
    events: &mut EventRegistry,
    obj_id: ObjectId,
    path: &str,
    owner: PeerId,
) -> Vec<Action> {
    object_lifecycle_fanout(events, "ubus.object.remove", obj_id, path, owner)
}

fn dispatch_subscribe(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    cred: &Cred,
    acl: &AclRegistry,
    peers: &mut PeerTable,
    objects: &ObjectRegistry,
    subs: &mut SubscriberRegistry,
) -> Vec<Action> {
    let obj_id = match find(frame.payload, UbusAttr::Target)
        .and_then(|a| a.as_u32())
        .and_then(ObjectId::new)
    {
        Some(id) => id,
        None => return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT),
    };
    let Some(subscriber_obj) = find(frame.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .and_then(ObjectId::new)
        .filter(|id| objects.owner_of(*id) == Some(src_peer))
    else {
        return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
    };
    let Some(owner) = objects.owner_of(obj_id) else {
        return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND);
    };
    if let Some(path) = objects.named_path(obj_id) {
        // Probed: upstream hides an un-subscribable target as NOT_FOUND
        // rather than PERMISSION_DENIED (existence-masking on the
        // subscribe ACL), unlike the access/listen/send denials.
        if !acl.check(cred, path, AclOp::Subscribe, None) {
            return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND);
        }
    }

    let newly_added = subs.add(obj_id, src_peer, subscriber_obj);
    // Mirror onto the peer's subs list so the disconnect reaper
    // can target only the obj-ids this peer cared about.
    if let Some(peer) = peers.get_mut(src_peer) {
        peer.add_sub(obj_id);
    }

    let mut out = Vec::new();
    if newly_added {
        if let Some(action) = active_notify_action(peers, owner, obj_id, true) {
            out.push(action);
        }
    }
    out.extend(status_action(frame, src_peer, 0));
    out
}

fn dispatch_unsubscribe(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    peers: &mut PeerTable,
    objects: &ObjectRegistry,
    subs: &mut SubscriberRegistry,
) -> Vec<Action> {
    let obj_id = match find(frame.payload, UbusAttr::Target)
        .and_then(|a| a.as_u32())
        .and_then(ObjectId::new)
    {
        Some(id) => id,
        None => return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT),
    };
    let Some(subscriber_obj) = find(frame.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .and_then(ObjectId::new)
        .filter(|id| objects.owner_of(*id) == Some(src_peer))
    else {
        return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
    };
    if objects.owner_of(obj_id).is_none() {
        return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND);
    }
    let (removed, became_inactive) = subs.remove(obj_id, src_peer, subscriber_obj);
    if !removed {
        return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND);
    }
    if let Some(peer) = peers.get_mut(src_peer) {
        peer.remove_sub(obj_id);
    }
    let mut out = Vec::new();
    if became_inactive {
        if let Some(owner) = objects.owner_of(obj_id) {
            if let Some(action) = active_notify_action(peers, owner, obj_id, false) {
                out.push(action);
            }
        }
    }
    out.extend(status_action(frame, src_peer, 0));
    out
}

fn dispatch_notify(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    peers: &PeerTable,
    objects: &ObjectRegistry,
    subs: &SubscriberRegistry,
) -> Vec<Action> {
    let obj_id = match find(frame.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .and_then(ObjectId::new)
    {
        Some(id) => id,
        None => return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT),
    };
    if find(frame.payload, UbusAttr::Method)
        .and_then(|a| a.as_str())
        .is_none()
    {
        return status_action(frame, src_peer, UBUS_STATUS_INVALID_ARGUMENT);
    }
    match objects.owner_of(obj_id) {
        None => return status_action(frame, src_peer, UBUS_STATUS_NOT_FOUND),
        Some(owner) if owner != src_peer => {
            return status_action(frame, src_peer, UBUS_STATUS_PERMISSION_DENIED)
        }
        Some(_) => {}
    }
    let subscribers = subs.subscribers_of(obj_id);
    let subscriber_obj_ids: Vec<ObjectId> = subscribers.iter().map(|sub| sub.obj_id).collect();
    let method = find(frame.payload, UbusAttr::Method).and_then(|a| a.as_str());
    let data = find(frame.payload, UbusAttr::Data).map(|a| a.payload);
    let no_reply = find(frame.payload, UbusAttr::NoReply).is_some_and(|attr| attr.as_bool_int8());
    let (user, group) = peer_names(peers, src_peer);
    let mut out = Vec::with_capacity(subscribers.len() + 1);
    if !no_reply {
        out.push(Action::send(
            src_peer,
            reply::notify_ack(frame.hdr.seq, frame.hdr.peer, obj_id, &subscriber_obj_ids),
        ));
    }
    if let Some(first) = subscribers.first() {
        let template = reply::stamped_invoke(
            frame.hdr.seq,
            src_peer,
            first.obj_id,
            method,
            user,
            group,
            data,
            no_reply,
        );
        let attr = find(&template.payload, UbusAttr::ObjId).expect("stamped invoke objid");
        let offset = ubus::wire::HEADER_SIZE + attr.payload.as_ptr() as usize
            - template.payload.as_ptr() as usize;
        let bytes = Codec::write_frame(&template);
        for subscriber in subscribers {
            let mut encoded: Arc<[u8]> = Arc::from(bytes.as_slice());
            Arc::get_mut(&mut encoded).expect("fresh fanout buffer")[offset..offset + 4]
                .copy_from_slice(&subscriber.obj_id.get().to_be_bytes());
            out.push(Action::SendBytes {
                peer_id: subscriber.peer_id,
                bytes: encoded,
            });
        }
    }
    out
}

fn dispatch_ping(frame: &FrameRef<'_>, src_peer: PeerId) -> Vec<Action> {
    vec![
        Action::send(src_peer, reply::data_echo_ref(frame)),
        Action::send(
            src_peer,
            reply::status_reply(frame.hdr.seq, frame.hdr.peer, 0),
        ),
    ]
}

fn forward_owner_response(
    frame: &FrameRef<'_>,
    src_peer: PeerId,
    objects: &ObjectRegistry,
    frame_fd: &mut Option<OwnedFd>,
) -> Vec<Action> {
    // Owner-emitted DATA / STATUS are addressed at the caller in
    // `hdr.peer`, but libubus expects the delivered reply to be
    // addressed from the target object id. Upstream `ubusd` therefore
    // validates the ObjId attr, routes to the original `hdr.peer`, and
    // rewrites the delivered `hdr.peer` to ObjId.
    let dest = match PeerId::new(frame.hdr.peer) {
        Some(id) => id,
        None => {
            log::debug!(
                "ubusd: peer {src_peer} {:?} with hdr.peer=0 dropped (no dest)",
                frame.hdr.ty,
            );
            return Vec::new();
        }
    };
    let obj_id = match find(frame.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .and_then(ObjectId::new)
    {
        Some(id) => id,
        None => return Vec::new(),
    };
    if objects.owner_of(obj_id) != Some(src_peer) {
        return Vec::new();
    }
    let has_required_payload = match frame.hdr.ty {
        MsgType::Data => find(frame.payload, UbusAttr::Data).is_some(),
        MsgType::Status => find(frame.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .is_some(),
        _ => false,
    };
    if !has_required_payload {
        return Vec::new();
    }
    let mut out = (*frame).to_owned();
    out.hdr.peer = obj_id.get();
    vec![Action::SendTo {
        peer_id: dest,
        frame: out,
        // Probe: upstream relays reply fds on STATUS only; DATA fds are closed.
        fd: (frame.hdr.ty == MsgType::Status)
            .then(|| frame_fd.take())
            .flatten(),
    }]
}

/// Single-action reply with a bare status code (no obj-id payload).
fn status_action(frame: &FrameRef<'_>, dest: PeerId, status: i32) -> Vec<Action> {
    vec![Action::send(
        dest,
        reply::status_reply(frame.hdr.seq, frame.hdr.peer, status),
    )]
}

fn peer_names(peers: &PeerTable, peer_id: PeerId) -> (Option<&str>, Option<&str>) {
    peers
        .get(peer_id)
        .map(|peer| {
            (
                peer.credentials.user.as_deref(),
                peer.credentials.group.as_deref(),
            )
        })
        .unwrap_or((None, None))
}

fn active_notify_action(
    peers: &mut PeerTable,
    owner: PeerId,
    obj_id: ObjectId,
    active: bool,
) -> Option<Action> {
    let seq = peers.get_mut(owner)?.next_notify_seq();
    Some(Action::send(
        owner,
        reply::active_notify(seq, obj_id, active),
    ))
}

pub(crate) fn active_zero_for_purged_subscriptions(
    peers: &mut PeerTable,
    objects: &ObjectRegistry,
    inactive_objects: &[ObjectId],
) -> Vec<Action> {
    inactive_objects
        .iter()
        .filter_map(|obj_id| {
            let owner = objects.owner_of(*obj_id)?;
            active_notify_action(peers, owner, *obj_id, false)
        })
        .collect()
}

pub(crate) fn unsubscribe_for_dead_objects(
    peers: &mut PeerTable,
    dead_objects: &[(ObjectId, Vec<Subscription>)],
) -> Vec<Action> {
    let mut out = Vec::new();
    for (dead_obj, subscribers) in dead_objects {
        for subscriber in subscribers {
            let Some(peer) = peers.get_mut(subscriber.peer_id) else {
                continue;
            };
            peer.remove_sub(*dead_obj);
            let seq = peer.next_notify_seq();
            out.push(Action::send(
                subscriber.peer_id,
                reply::unsubscribe_notify(seq, subscriber.obj_id, *dead_obj),
            ));
        }
    }
    out
}

#[cfg(test)]
fn dispatch_without_acl(
    frame: &Frame,
    src_peer: PeerId,
    peers: &mut PeerTable,
    objects: &mut ObjectRegistry,
    subs: &mut SubscriberRegistry,
    events: &mut EventRegistry,
    monitors: &mut MonitorRegistry,
) -> Vec<Action> {
    let mut frame_fd = None;
    dispatch(
        frame,
        src_peer,
        &AclRegistry::default(),
        0,
        peers,
        objects,
        subs,
        events,
        monitors,
        &mut frame_fd,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AccessGrant, AclEntry, Pattern};
    use crate::peer::Peer;
    use ubus::envelope::{iter_attrs, unwrap as unwrap_envelope, EnvBuilder};
    use ubus::wire::{Header, PROTO_VERSION};

    /// Terse dispatch for the pure-protocol tests below, which predate
    /// the event bus and never register listeners. Shadows `super::
    /// dispatch` inside this module: it routes through a throwaway
    /// `EventRegistry` (empty ⇒ event minting yields zero extra actions),
    /// keeping the existing call sites 5-arg. Event-specific tests call
    /// `super::dispatch` with a shared registry.
    fn dispatch(
        frame: &Frame,
        src_peer: PeerId,
        peers: &mut PeerTable,
        objects: &mut ObjectRegistry,
        subs: &mut SubscriberRegistry,
    ) -> Vec<Action> {
        super::dispatch_without_acl(
            frame,
            src_peer,
            peers,
            objects,
            subs,
            &mut EventRegistry::new(),
            &mut MonitorRegistry::new(),
        )
    }

    fn oid(n: u32) -> ObjectId {
        ObjectId::new(n).unwrap()
    }

    fn empty_frame(ty: MsgType, seq: u16, peer: u32) -> Frame {
        Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty,
                seq,
                peer,
            },
            payload: Vec::new(),
        }
    }

    fn add_object_frame(seq: u16, path: &str) -> Frame {
        let mut env = EnvBuilder::new();
        env.push_str(UbusAttr::ObjPath, path);
        Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq,
                peer: 0,
            },
            payload: env.finish(),
        }
    }

    fn invoke_frame(seq: u16, target_obj_id: u32, method: &str) -> Frame {
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, target_obj_id);
        env.push_str(UbusAttr::Method, method);
        Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq,
                peer: target_obj_id,
            },
            payload: env.finish(),
        }
    }

    fn install_peer(peers: &mut PeerTable) -> PeerId {
        let (id, _) = peers.insert(Peer::stub_with_uid(0)).expect("peer insert");
        id
    }

    fn install_peer_with_uid(peers: &mut PeerTable, uid: u32) -> PeerId {
        let (id, _) = peers.insert(Peer::stub_with_uid(uid)).expect("peer insert");
        id
    }

    fn install_peer_without_uid(peers: &mut PeerTable) -> PeerId {
        let (id, _) = peers.insert(Peer::stub()).expect("peer insert");
        id
    }

    fn set_names(peers: &mut PeerTable, id: PeerId, user: &str, group: &str) {
        let peer = peers.get_mut(id).expect("peer exists");
        let cred = Arc::make_mut(&mut peer.credentials);
        cred.user = Some(user.to_string());
        cred.group = Some(group.to_string());
    }

    fn install_user_peer(peers: &mut PeerTable, user: &str) -> PeerId {
        let id = install_peer_with_uid(peers, 1000);
        set_names(peers, id, user, "g");
        id
    }

    fn acl_for(user: &str, op: AclOp, path: &str, method: Option<&str>) -> AclRegistry {
        let mut entry = AclEntry {
            user: Some(user.to_string()),
            group: None,
            uid: None,
            gid: None,
            publish: Vec::new(),
            subscribe: Vec::new(),
            listen: Vec::new(),
            send: Vec::new(),
            access: Vec::new(),
        };
        match op {
            AclOp::Publish => entry.publish.push(Pattern::parse(path)),
            AclOp::Subscribe => entry.subscribe.push(Pattern::parse(path)),
            AclOp::Listen => entry.listen.push(Pattern::parse(path)),
            AclOp::Send => entry.send.push(Pattern::parse(path)),
            AclOp::Access => entry.access.push(AccessGrant {
                object: Pattern::parse(path),
                methods: method.map(|method| vec![method.to_string()]),
                priv_blob: None,
            }),
        }
        AclRegistry {
            entries: vec![entry],
        }
    }

    fn dispatch_acl(
        frame: &Frame,
        src_peer: PeerId,
        acl: &AclRegistry,
        peers: &mut PeerTable,
        objects: &mut ObjectRegistry,
        subs: &mut SubscriberRegistry,
    ) -> Vec<Action> {
        let mut frame_fd = None;
        super::dispatch(
            frame,
            src_peer,
            acl,
            0,
            peers,
            objects,
            subs,
            &mut EventRegistry::new(),
            &mut MonitorRegistry::new(),
            &mut frame_fd,
        )
    }

    fn attr_ids(payload: &[u8]) -> Vec<u8> {
        let inner = unwrap_envelope(payload).expect("valid envelope");
        iter_attrs(inner).map(|a| a.id).collect()
    }

    #[test]
    fn redundant_hello_replies_with_invalid_command_status() {
        // `accept_pending` pushes the unsolicited HELLO; any HELLO
        // arriving via dispatch is the client re-greeting on an
        // already-handshaked connection. Upstream `ubusd` replies
        // with `Status = UBUS_STATUS_INVALID_COMMAND` (1) on the
        // request seq — assert that exact shape.
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        let actions = dispatch(
            &empty_frame(MsgType::Hello, 11, 0),
            id,
            &mut peers,
            &mut objs,
            &mut subs,
        );
        let Action::SendTo { peer_id, frame, .. } = actions.into_iter().next().expect("one action")
        else {
            panic!("expected SendTo");
        };
        assert_eq!(peer_id, id, "reply addressed to redundant-HELLO sender");
        assert_eq!(frame.hdr.ty, MsgType::Status);
        assert_eq!(frame.hdr.seq, 11, "reply must echo the request seq");
        assert_eq!(frame.hdr.peer, 0, "reply must echo the request peer");
        let s = ubus::envelope::find(&frame.payload, ubus::envelope::UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32);
        assert_eq!(s, Some(UBUS_STATUS_INVALID_COMMAND));
    }

    #[test]
    fn monitor_builtin_gates_uid_before_method_and_tracks_registration() {
        for (uid, method) in [
            (Some(1000), "add"),
            (Some(1000), "remove"),
            (Some(1000), "unknown"),
            (None, "add"),
            (None, "remove"),
            (None, "unknown"),
        ] {
            let mut peers = PeerTable::new();
            let src = match uid {
                Some(uid) => install_peer_with_uid(&mut peers, uid),
                None => install_peer_without_uid(&mut peers),
            };
            let mut objects = ObjectRegistry::new();
            let mut subs = SubscriberRegistry::new();
            let mut events = EventRegistry::new();
            let mut monitors = MonitorRegistry::new();
            let actions = super::dispatch_without_acl(
                &invoke_frame(1, UBUS_SYSTEM_OBJECT_MONITOR, method),
                src,
                &mut peers,
                &mut objects,
                &mut subs,
                &mut events,
                &mut monitors,
            );
            assert_eq!(find_status(&actions), Some(UBUS_STATUS_PERMISSION_DENIED));
            assert!(monitors.is_empty());
        }

        let mut peers = PeerTable::new();
        let src = install_peer_with_uid(&mut peers, 0);
        let mut objects = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let mut monitors = MonitorRegistry::new();
        let add = super::dispatch_without_acl(
            &invoke_frame(2, UBUS_SYSTEM_OBJECT_MONITOR, "add"),
            src,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
        );
        assert_eq!(find_status(&add), Some(0));
        assert_eq!(monitors.mint_seqs(), vec![(src, 1)]);
        let remove = super::dispatch_without_acl(
            &invoke_frame(3, UBUS_SYSTEM_OBJECT_MONITOR, "remove"),
            src,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
        );
        assert_eq!(find_status(&remove), Some(0));
        assert!(monitors.is_empty());
        let unknown = super::dispatch_without_acl(
            &invoke_frame(4, UBUS_SYSTEM_OBJECT_MONITOR, "unknown"),
            src,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
        );
        assert_eq!(find_status(&unknown), Some(UBUS_STATUS_METHOD_NOT_FOUND));
    }

    #[test]
    fn inbound_monitor_frame_is_invalid_command() {
        let mut peers = PeerTable::new();
        let src = install_peer(&mut peers);
        let mut objects = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let mut monitors = MonitorRegistry::new();
        let actions = super::dispatch_without_acl(
            &empty_frame(MsgType::Monitor, 9, 0),
            src,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
        );
        assert_eq!(find_status(&actions), Some(UBUS_STATUS_INVALID_COMMAND));
    }

    #[test]
    fn add_object_replies_data_objid_then_status_ok() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        let actions = dispatch(
            &add_object_frame(2, "example"),
            id,
            &mut peers,
            &mut objs,
            &mut subs,
        );
        // Upstream shape: DATA(OBJID) strictly before a plain STATUS(0).
        assert_eq!(actions.len(), 2, "ADD_OBJECT must emit DATA then STATUS");
        let obj_id = match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, id);
                assert_eq!(frame.hdr.ty, MsgType::Data, "first frame must be DATA");
                assert_eq!(frame.hdr.peer, 0, "reply must echo the request peer");
                let obj_id = find(&frame.payload, UbusAttr::ObjId)
                    .and_then(|a| a.as_u32())
                    .and_then(ObjectId::new)
                    .expect("ObjId in DATA reply");
                assert_eq!(objs.owner_of(obj_id), Some(id));
                obj_id
            }
            other => panic!("unexpected action: {other:?}"),
        };
        match &actions[1] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, id);
                assert_eq!(frame.hdr.ty, MsgType::Status, "second frame must be STATUS");
                assert_eq!(frame.hdr.peer, 0, "reply must echo the request peer");
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(0));
                assert!(
                    find(&frame.payload, UbusAttr::ObjId).is_none(),
                    "STATUS must carry only the status attr — id rides the DATA frame"
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
        // Sanity: the DATA-borne id is the one the registry recorded.
        assert_eq!(objs.owner_of(obj_id), Some(id));
    }

    #[test]
    fn invoke_routes_to_owner_with_caller_in_hdr_peer() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let caller = install_peer(&mut peers);
        set_names(&mut peers, caller, "alice", "staff");
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");

        let actions = dispatch(
            &invoke_frame(7, obj_id.get(), "ping"),
            caller,
            &mut peers,
            &mut objs,
            &mut subs,
        );
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, owner, "frame should be forwarded to owner");
                assert_eq!(
                    frame.hdr.peer,
                    caller.get(),
                    "hdr.peer must be rewritten to caller for return-routing"
                );
                assert_eq!(frame.hdr.ty, MsgType::Invoke);
                assert_eq!(
                    attr_ids(&frame.payload),
                    vec![
                        UbusAttr::ObjId as u8,
                        UbusAttr::Method as u8,
                        UbusAttr::User as u8,
                        UbusAttr::Group as u8,
                    ],
                    "forwarded INVOKE attr order"
                );
                assert_eq!(
                    find(&frame.payload, UbusAttr::User).and_then(|a| a.as_str()),
                    Some("alice")
                );
                assert_eq!(
                    find(&frame.payload, UbusAttr::Group).and_then(|a| a.as_str()),
                    Some("staff")
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn invoke_no_reply_is_not_forwarded_to_owner() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let caller = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("object insert");
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        env.push_str(UbusAttr::Method, "ping");
        env.push_u8(UbusAttr::NoReply, 1);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq: 7,
                peer: obj_id.get(),
            },
            payload: env.finish(),
        };

        let actions = dispatch(&frame, caller, &mut peers, &mut objs, &mut subs);
        let Action::SendTo { peer_id, frame, .. } = &actions[0] else {
            panic!("expected forwarded INVOKE");
        };
        assert_eq!(*peer_id, owner);
        assert_eq!(
            attr_ids(&frame.payload),
            vec![UbusAttr::ObjId as u8, UbusAttr::Method as u8]
        );
        assert!(find(&frame.payload, UbusAttr::NoReply).is_none());
    }

    #[test]
    fn lookup_unknown_returns_not_found() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        let mut env = EnvBuilder::new();
        env.push_str(UbusAttr::ObjPath, "no.such.thing");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 1,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, id, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SendTo { frame, .. } => {
                assert_eq!(frame.hdr.peer, 0, "reply must echo the request peer");
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(UBUS_STATUS_NOT_FOUND));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn lookup_all_empty_registry_returns_status_ok() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        let frame = empty_frame(MsgType::Lookup, 2, 0);
        let actions = dispatch(&frame, id, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 1, "empty list-all emits only STATUS");
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, id);
                assert_eq!(frame.hdr.ty, MsgType::Status);
                assert_eq!(frame.hdr.peer, 0, "reply must echo the request peer");
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(0));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn lookup_non_nul_terminated_objpath_is_dropped_and_lists_all() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example.typed".into(), id, Some(vec![]))
            .expect("typed object");
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjPath, 2);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 3,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, id, &mut peers, &mut objs, &mut subs);
        assert_eq!(
            actions.len(),
            2,
            "invalid ObjPath must list typed objects then STATUS"
        );
        let Action::SendTo { frame, .. } = &actions[0] else {
            panic!("list-all must start with DATA");
        };
        assert_eq!(frame.hdr.ty, MsgType::Data);
        assert_eq!(
            find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
            Some(obj_id.get())
        );
        assert_eq!(find_status(&actions), Some(0));
    }

    #[test]
    fn lookup_treats_glob_metachars_as_literal() {
        // Upstream `ubusd` honours only a *trailing* `*`; `?` and
        // `[...]` are not fnmatch metacharacters, they are literal path
        // bytes. So `example.[ag]*` strips the trailing `*`, prefix-
        // matches the literal `example.[ag]`, finds nothing, and returns
        // NOT_FOUND even though alpha/gamma are registered. Regression:
        // an earlier fnmatch implementation returned {alpha, gamma}.
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        let sig = vec![0, 0, 0, 4];
        objs.insert("example.alpha".into(), id, Some(sig.clone()))
            .expect("alpha insert");
        objs.insert("example.gamma".into(), id, Some(sig))
            .expect("gamma insert");

        let mut env = EnvBuilder::new();
        env.push_str(UbusAttr::ObjPath, "example.[ag]*");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 14,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, id, &mut peers, &mut objs, &mut subs);
        assert_eq!(
            actions.len(),
            1,
            "literal-prefix miss must emit only STATUS"
        );
        let Action::SendTo { frame, .. } = &actions[0] else {
            panic!("expected SendTo");
        };
        assert_eq!(frame.hdr.ty, MsgType::Status);
        assert_eq!(
            find(&frame.payload, UbusAttr::Status)
                .and_then(|a| a.as_u32())
                .map(|u| u as i32),
            Some(UBUS_STATUS_NOT_FOUND)
        );
    }

    #[test]
    fn lookup_pattern_matches_typed_objects_in_path_order() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        let sig = vec![0, 0, 0, 4];
        let (gamma, _) = objs
            .insert("example.gamma".into(), id, Some(sig.clone()))
            .expect("gamma insert");
        let (alpha, _) = objs
            .insert("example.alpha".into(), id, Some(sig.clone()))
            .expect("alpha insert");
        let (alpine, _) = objs
            .insert("example.alpine".into(), id, Some(sig.clone()))
            .expect("alpine insert");
        let untyped = objs
            .insert("example.atom".into(), id, None)
            .expect("untyped insert")
            .0;
        assert_ne!(gamma, alpha);
        assert_ne!(untyped, alpine);

        let mut env = EnvBuilder::new();
        env.push_str(UbusAttr::ObjPath, "example.a*");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 12,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, id, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 3, "two DATA frames plus STATUS");

        let mut paths = Vec::new();
        for action in &actions[..2] {
            let Action::SendTo { frame, .. } = action else {
                panic!("expected SendTo");
            };
            assert_eq!(frame.hdr.ty, MsgType::Data);
            paths.push(
                find(&frame.payload, UbusAttr::ObjPath)
                    .and_then(|a| a.as_str())
                    .expect("ObjPath")
                    .to_string(),
            );
        }
        assert_eq!(paths, vec!["example.alpha", "example.alpine"]);
        let Action::SendTo { frame, .. } = actions.last().expect("status") else {
            panic!("expected SendTo");
        };
        assert_eq!(frame.hdr.ty, MsgType::Status);
        assert_eq!(
            find(&frame.payload, UbusAttr::Status)
                .and_then(|a| a.as_u32())
                .map(|u| u as i32),
            Some(0)
        );
    }

    #[test]
    fn lookup_pattern_no_match_returns_not_found() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        objs.insert("example.alpha".into(), id, Some(vec![0, 0, 0, 4]))
            .expect("alpha insert");

        let mut env = EnvBuilder::new();
        env.push_str(UbusAttr::ObjPath, "example.z*");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 13,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, id, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 1);
        let Action::SendTo { frame, .. } = &actions[0] else {
            panic!("expected SendTo");
        };
        assert_eq!(frame.hdr.ty, MsgType::Status);
        assert_eq!(
            find(&frame.payload, UbusAttr::Status)
                .and_then(|a| a.as_u32())
                .map(|u| u as i32),
            Some(UBUS_STATUS_NOT_FOUND)
        );
    }

    #[test]
    fn notify_fans_out_to_every_subscriber_only() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let sub_a = install_peer(&mut peers);
        let sub_b = install_peer(&mut peers);
        let bystander = install_peer(&mut peers);
        set_names(&mut peers, owner, "root", "root");
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        let sub_a_obj = objs.insert_anonymous(sub_a).expect("sub a obj");
        let sub_b_obj = objs.insert_anonymous(sub_b).expect("sub b obj");
        subs.add(obj_id, sub_a, sub_a_obj);
        subs.add(obj_id, sub_b, sub_b_obj);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        env.push_str(UbusAttr::Method, "fanout");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 9,
                peer: obj_id.get(),
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 3, "NOTIFY must ack publisher and fan out");
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, owner);
                assert_eq!(frame.hdr.ty, MsgType::Status);
                assert_eq!(frame.hdr.seq, 9);
                assert_eq!(frame.hdr.peer, obj_id.get());
                assert_eq!(
                    attr_ids(&frame.payload),
                    vec![
                        UbusAttr::ObjId as u8,
                        UbusAttr::Subscribers as u8,
                        UbusAttr::Status as u8,
                    ],
                    "NOTIFY ack attr order"
                );
            }
            other => panic!("unexpected ack action: {other:?}"),
        }
        let dests: Vec<PeerId> = actions
            .iter()
            .filter_map(|a| match a {
                Action::SendBytes { peer_id, .. } => Some(*peer_id),
                _ => None,
            })
            .collect();
        assert_eq!(dests.len(), 2);
        assert!(dests.contains(&sub_a));
        assert!(dests.contains(&sub_b));
        assert!(!dests.contains(&bystander));
        assert!(!dests.contains(&owner));
        for action in actions.into_iter().skip(1) {
            let (dest, bytes) = match action {
                Action::SendBytes { peer_id, bytes } => (peer_id, bytes),
                other => panic!("unexpected action: {other:?}"),
            };
            let (forwarded, consumed) = Codec::read_frame(&bytes).expect("encoded fan-out");
            assert_eq!(consumed, bytes.len());
            assert_eq!(forwarded.hdr.ty, MsgType::Invoke);
            assert_eq!(forwarded.hdr.seq, 9);
            assert_eq!(forwarded.hdr.peer, owner.get());
            let expected_obj = if dest == sub_a { sub_a_obj } else { sub_b_obj };
            assert_eq!(
                find(&forwarded.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
                Some(expected_obj.get())
            );
            assert_eq!(
                attr_ids(&forwarded.payload),
                vec![
                    UbusAttr::ObjId as u8,
                    UbusAttr::Method as u8,
                    UbusAttr::User as u8,
                    UbusAttr::Group as u8,
                ],
                "fan-out attr order"
            );
            assert_eq!(
                find(&forwarded.payload, UbusAttr::Method).and_then(|a| a.as_str()),
                Some("fanout")
            );
            assert_eq!(
                find(&forwarded.payload, UbusAttr::User).and_then(|a| a.as_str()),
                Some("root")
            );
            assert_eq!(
                find(&forwarded.payload, UbusAttr::Group).and_then(|a| a.as_str()),
                Some("root")
            );
        }
    }

    #[test]
    fn notify_int8_no_reply_suppresses_ack_and_stamps_fanout() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let subscriber = install_peer(&mut peers);
        set_names(&mut peers, owner, "root", "root");
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("object insert");
        let subscriber_obj = objs
            .insert_anonymous(subscriber)
            .expect("subscriber object");
        subs.add(obj_id, subscriber, subscriber_obj);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        env.push_str(UbusAttr::Method, "fanout");
        env.push_u8(UbusAttr::NoReply, 1);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 9,
                peer: obj_id.get(),
            },
            payload: env.finish(),
        };

        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 1, "NoReply must suppress the NOTIFY ack");
        let Action::SendBytes { peer_id, bytes } = &actions[0] else {
            panic!("expected encoded fan-out");
        };
        assert_eq!(*peer_id, subscriber);
        let (fanout, consumed) = Codec::read_frame(bytes).expect("encoded fan-out");
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            attr_ids(&fanout.payload),
            vec![
                UbusAttr::NoReply as u8,
                UbusAttr::ObjId as u8,
                UbusAttr::Method as u8,
                UbusAttr::User as u8,
                UbusAttr::Group as u8,
            ]
        );
        assert_eq!(
            find(&fanout.payload, UbusAttr::NoReply).map(|a| a.payload),
            Some(&[1][..])
        );
    }

    #[test]
    fn notify_u32_no_reply_still_acks_without_stamping_fanout() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let subscriber = install_peer(&mut peers);
        set_names(&mut peers, owner, "root", "root");
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("object insert");
        let subscriber_obj = objs
            .insert_anonymous(subscriber)
            .expect("subscriber object");
        subs.add(obj_id, subscriber, subscriber_obj);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        env.push_str(UbusAttr::Method, "fanout");
        env.push_u32(UbusAttr::NoReply, 1);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 9,
                peer: obj_id.get(),
            },
            payload: env.finish(),
        };

        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 2, "u32 NoReply=1 is false as an int8");
        assert!(
            matches!(actions[0], Action::SendTo { ref frame, .. } if frame.hdr.ty == MsgType::Status)
        );
        let Action::SendBytes { bytes, .. } = &actions[1] else {
            panic!("expected encoded fan-out");
        };
        let (fanout, consumed) = Codec::read_frame(bytes).expect("encoded fan-out");
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            attr_ids(&fanout.payload),
            vec![
                UbusAttr::ObjId as u8,
                UbusAttr::Method as u8,
                UbusAttr::User as u8,
                UbusAttr::Group as u8,
            ]
        );
        assert!(find(&fanout.payload, UbusAttr::NoReply).is_none());
    }

    #[test]
    fn notify_ack_echoes_request_header_peer_verbatim() {
        // Upstream builds the publisher ack before rewriting hdr.peer for
        // the fan-out, so the ack carries whatever the publisher sent —
        // NOT the publisher's object id. A libubus subscriber scenario
        // sending NOTIFY with hdr.peer=0 caught rs pinning the object id.
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        set_names(&mut peers, owner, "root", "root");
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("object insert");

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        env.push_str(UbusAttr::Method, "fanout");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 9,
                peer: 0xabcd_1234,
            },
            payload: env.finish(),
        };

        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        let Action::SendTo { frame: ack, .. } = &actions[0] else {
            panic!("expected publisher ack");
        };
        assert_eq!(ack.hdr.ty, MsgType::Status);
        assert_eq!(ack.hdr.peer, 0xabcd_1234, "ack must echo request hdr.peer");
        assert_eq!(
            find(&ack.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
            Some(obj_id.get()),
            "payload OBJID still names the publisher object"
        );
    }

    #[test]
    fn notify_from_non_owner_reports_permission_denied() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let attacker = install_peer(&mut peers);
        let listener = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        let listener_obj = objs.insert_anonymous(listener).expect("listener obj");
        subs.add(obj_id, listener, listener_obj);

        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 9,
                peer: obj_id.get(),
            },
            payload: {
                let mut env = EnvBuilder::new();
                env.push_u32(UbusAttr::ObjId, obj_id.get());
                env.push_str(UbusAttr::Method, "event");
                env.finish()
            },
        };
        let actions = dispatch(&frame, attacker, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 1, "non-owner NOTIFY must be rejected");
        assert_eq!(find_status(&actions), Some(UBUS_STATUS_PERMISSION_DENIED));
    }

    #[test]
    fn invoke_unknown_obj_id_returns_not_found() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let caller = install_peer(&mut peers);
        let actions = dispatch(
            &invoke_frame(3, 9999, "ping"),
            caller,
            &mut peers,
            &mut objs,
            &mut subs,
        );
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, caller);
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(UBUS_STATUS_NOT_FOUND));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn subscribe_known_object_records_subscription_and_replies_zero() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let sub = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");

        let sub_obj = objs.insert_anonymous(sub).expect("sub obj");
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, sub_obj.get());
        env.push_u32(UbusAttr::Target, obj_id.get());
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq: 4,
                peer: obj_id.get(),
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, sub, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 2);
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, owner);
                assert_eq!(frame.hdr.ty, MsgType::Notify);
                assert_eq!(frame.hdr.seq, 1);
                assert_eq!(frame.hdr.peer, 0);
                assert_eq!(
                    find(&frame.payload, UbusAttr::Active).map(|a| a.payload),
                    Some(&[1][..])
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
        match &actions[1] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, sub);
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(0));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(
            subs.subscribers_of(obj_id),
            &[crate::registry::Subscription {
                peer_id: sub,
                obj_id: sub_obj,
            }]
        );
        assert!(peers.get(sub).unwrap().is_subscribed_to(obj_id));
    }

    #[test]
    fn subscribe_unknown_object_returns_not_found_no_state_change() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let sub = install_peer(&mut peers);

        let sub_obj = objs.insert_anonymous(sub).expect("sub obj");
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, sub_obj.get());
        env.push_u32(UbusAttr::Target, 9999);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq: 4,
                peer: 9999,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, sub, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SendTo { frame, .. } => {
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(UBUS_STATUS_NOT_FOUND));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert!(subs.subscribers_of(oid(9999)).is_empty());
        assert_eq!(peers.get(sub).unwrap().sub_count(), 0);
    }

    #[test]
    fn unsubscribe_clears_registry_and_peer_index() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let sub = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        let sub_obj = objs.insert_anonymous(sub).expect("sub obj");
        subs.add(obj_id, sub, sub_obj);
        peers.get_mut(sub).unwrap().add_sub(obj_id);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, sub_obj.get());
        env.push_u32(UbusAttr::Target, obj_id.get());
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Unsubscribe,
                seq: 5,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, sub, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 2);
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, owner);
                assert_eq!(frame.hdr.ty, MsgType::Notify);
                assert_eq!(frame.hdr.seq, 1);
                assert_eq!(
                    find(&frame.payload, UbusAttr::Active).map(|a| a.payload),
                    Some(&[0][..])
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
        match &actions[1] {
            Action::SendTo { frame, .. } => {
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(0));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert!(subs.subscribers_of(obj_id).is_empty());
        assert_eq!(peers.get(sub).unwrap().sub_count(), 0);
    }

    #[test]
    fn disconnect_purge_emits_active_zero_on_last_subscriber() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let sub_a = install_peer(&mut peers);
        let sub_b = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        let sub_a_obj = objs.insert_anonymous(sub_a).expect("sub a obj");
        let sub_b_obj = objs.insert_anonymous(sub_b).expect("sub b obj");

        assert!(subs.add(obj_id, sub_a, sub_a_obj));
        peers.get_mut(sub_a).unwrap().add_sub(obj_id);
        let active_one =
            active_notify_action(&mut peers, owner, obj_id, true).expect("owner active one");
        match active_one {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(peer_id, owner);
                assert_eq!(frame.hdr.ty, MsgType::Notify);
                assert_eq!(frame.hdr.seq, 1);
                assert_eq!(
                    find(&frame.payload, UbusAttr::Active).map(|a| a.payload),
                    Some(&[1][..])
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }

        assert!(!subs.add(obj_id, sub_b, sub_b_obj));
        peers.get_mut(sub_b).unwrap().add_sub(obj_id);

        let sub_a_subs = peers.get_mut(sub_a).unwrap().take_subs();
        let inactive = subs.purge_peer(sub_a, &[], &sub_a_subs);
        assert!(
            inactive.is_empty(),
            "first of two subscribers must not deactivate"
        );
        assert!(
            active_zero_for_purged_subscriptions(&mut peers, &objs, &inactive).is_empty(),
            "no Active=0 while one subscriber remains"
        );

        let sub_b_subs = peers.get_mut(sub_b).unwrap().take_subs();
        let inactive = subs.purge_peer(sub_b, &[], &sub_b_subs);
        assert_eq!(inactive, vec![obj_id]);
        let actions = active_zero_for_purged_subscriptions(&mut peers, &objs, &inactive);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, owner);
                assert_eq!(frame.hdr.ty, MsgType::Notify);
                assert_eq!(frame.hdr.seq, 2);
                assert_eq!(frame.hdr.peer, 0);
                assert_eq!(
                    find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
                    Some(obj_id.get())
                );
                assert_eq!(
                    find(&frame.payload, UbusAttr::Active).map(|a| a.payload),
                    Some(&[0][..])
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn dead_object_emits_unsubscribe_to_each_subscriber() {
        let mut peers = PeerTable::new();
        let owner = install_peer(&mut peers);
        let sub_a = install_peer(&mut peers);
        let sub_b = install_peer(&mut peers);
        let dead_obj = oid(2);
        let sub_a_obj = oid(5);
        let sub_b_obj = oid(6);
        peers.get_mut(owner).unwrap().add_owned(dead_obj);
        peers.get_mut(sub_a).unwrap().add_sub(dead_obj);
        peers.get_mut(sub_b).unwrap().add_sub(dead_obj);

        let actions = unsubscribe_for_dead_objects(
            &mut peers,
            &[(
                dead_obj,
                vec![
                    Subscription {
                        peer_id: sub_a,
                        obj_id: sub_a_obj,
                    },
                    Subscription {
                        peer_id: sub_b,
                        obj_id: sub_b_obj,
                    },
                ],
            )],
        );

        assert_eq!(actions.len(), 2);
        for (action, peer_id, subscriber_obj) in [
            (&actions[0], sub_a, sub_a_obj),
            (&actions[1], sub_b, sub_b_obj),
        ] {
            match action {
                Action::SendTo {
                    peer_id: actual,
                    frame,
                    ..
                } => {
                    assert_eq!(*actual, peer_id);
                    assert_eq!(frame.hdr.ty, MsgType::Unsubscribe);
                    assert_eq!(frame.hdr.seq, 1);
                    assert_eq!(frame.hdr.peer, 0);
                    assert_eq!(
                        attr_ids(&frame.payload),
                        vec![UbusAttr::ObjId as u8, UbusAttr::Target as u8]
                    );
                    assert_eq!(
                        find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
                        Some(subscriber_obj.get())
                    );
                    assert_eq!(
                        find(&frame.payload, UbusAttr::Target).and_then(|a| a.as_u32()),
                        Some(dead_obj.get())
                    );
                }
                other => panic!("unexpected action: {other:?}"),
            }
        }
        assert!(!peers.get(sub_a).unwrap().is_subscribed_to(dead_obj));
        assert!(!peers.get(sub_b).unwrap().is_subscribed_to(dead_obj));
        assert_eq!(peers.get_mut(sub_a).unwrap().next_notify_seq(), 2);
        assert_eq!(peers.get_mut(sub_b).unwrap().next_notify_seq(), 2);
    }

    #[test]
    fn remove_object_owner_drops_registration_and_subscribers() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let watcher = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        peers.get_mut(owner).unwrap().add_owned(obj_id);
        let watcher_obj = objs.insert_anonymous(watcher).expect("watcher obj");
        subs.add(obj_id, watcher, watcher_obj);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 6,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        // Same owner reply shape as ADD_OBJECT: DATA(OBJID) then
        // STATUS(0), plus broker Unsubscribe to each subscriber of
        // the destroyed object.
        assert_eq!(
            actions.len(),
            3,
            "REMOVE_OBJECT must emit DATA, STATUS, and subscriber Unsubscribe"
        );
        match &actions[0] {
            Action::SendTo { frame, .. } => {
                assert_eq!(frame.hdr.ty, MsgType::Data, "first frame must be DATA");
                let id = find(&frame.payload, UbusAttr::ObjId)
                    .and_then(|a| a.as_u32())
                    .and_then(ObjectId::new)
                    .expect("ObjId in DATA reply");
                assert_eq!(id, obj_id, "DATA must carry the removed obj id");
            }
            other => panic!("unexpected action: {other:?}"),
        }
        match &actions[1] {
            Action::SendTo { frame, .. } => {
                assert_eq!(frame.hdr.ty, MsgType::Status, "second frame must be STATUS");
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(0));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        match &actions[2] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, watcher);
                assert_eq!(frame.hdr.ty, MsgType::Unsubscribe);
                assert_eq!(frame.hdr.seq, 1);
                assert_eq!(frame.hdr.peer, 0);
                assert_eq!(
                    find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
                    Some(watcher_obj.get())
                );
                assert_eq!(
                    find(&frame.payload, UbusAttr::Target).and_then(|a| a.as_u32()),
                    Some(obj_id.get())
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(objs.owner_of(obj_id), None);
        assert!(subs.subscribers_of(obj_id).is_empty());
        assert!(!peers.get(owner).unwrap().owns(obj_id));
        assert!(!peers.get(watcher).unwrap().is_subscribed_to(obj_id));
    }

    #[test]
    fn remove_object_non_owner_reports_permission_denied() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let other = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        peers.get_mut(owner).unwrap().add_owned(obj_id);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 6,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, other, &mut peers, &mut objs, &mut subs);
        // Upstream: a non-owner remove is PERMISSION_DENIED, not a silent
        // no-op; the registration stays intact (single STATUS, no DATA).
        assert_eq!(actions.len(), 1, "permission-denied emits only STATUS");
        match &actions[0] {
            Action::SendTo { frame, .. } => {
                assert_eq!(frame.hdr.ty, MsgType::Status);
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(UBUS_STATUS_PERMISSION_DENIED));
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(objs.owner_of(obj_id), Some(owner));
        assert!(peers.get(owner).unwrap().owns(obj_id));
    }

    #[test]
    fn remove_object_unknown_id_reports_not_found() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, 0x7fff_ffff);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 6,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, id, &mut peers, &mut objs, &mut subs);
        // Unknown obj id: single STATUS = NOT_FOUND, no DATA frame.
        assert_eq!(actions.len(), 1, "unknown-id remove emits only STATUS");
        match &actions[0] {
            Action::SendTo { frame, .. } => {
                assert_eq!(frame.hdr.ty, MsgType::Status);
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(UBUS_STATUS_NOT_FOUND));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn remove_object_without_attr_returns_invalid_argument() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        let actions = dispatch(
            &empty_frame(MsgType::RemoveObject, 6, 0),
            id,
            &mut peers,
            &mut objs,
            &mut subs,
        );
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SendTo { frame, .. } => {
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(UBUS_STATUS_INVALID_ARGUMENT));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn data_reply_rewrites_hdr_peer_to_obj_id_and_forwards_to_caller() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let caller = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        env.push_data(&[]);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Data,
                seq: 7,
                peer: caller.get(),
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, caller);
                assert_eq!(frame.hdr.ty, MsgType::Data);
                assert_eq!(
                    frame.hdr.peer,
                    obj_id.get(),
                    "delivered DATA must be addressed from object"
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn data_reply_without_obj_id_is_silently_dropped() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let caller = install_peer(&mut peers);
        let mut env = EnvBuilder::new();
        env.push_data(&[]);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Data,
                seq: 7,
                peer: caller.get(),
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        assert!(actions.is_empty());
    }

    #[test]
    fn data_reply_from_non_owner_is_silently_dropped() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let other = install_peer(&mut peers);
        let caller = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        env.push_data(&[]);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Data,
                seq: 7,
                peer: caller.get(),
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, other, &mut peers, &mut objs, &mut subs);
        assert!(actions.is_empty());
    }

    #[test]
    fn data_with_zero_dest_is_silently_dropped() {
        // hdr.peer = 0 means "broker", which is never a valid
        // routing destination for an owner-emitted DATA. Pre-typed
        // ids the frame fell through to enqueue_to_peer and got
        // dropped at the table lookup; with typed ids we drop at
        // dispatch instead — same end state, more visible.
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let frame = empty_frame(MsgType::Data, 7, 0);
        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        assert!(actions.is_empty());
    }

    #[test]
    fn ping_replies_data_echo_then_status_zero() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        // Real clients never send header-only frames (they desync
        // upstream's recv loop): a wire PING carries the 4-byte empty
        // envelope, and upstream's DATA reply echoes exactly that.
        let ping = Frame {
            hdr: Header {
                version: 7,
                ty: MsgType::Ping,
                seq: 1,
                peer: 77,
            },
            payload: EnvBuilder::new().finish(),
        };
        let actions = dispatch(&ping, id, &mut peers, &mut objs, &mut subs);
        assert_eq!(actions.len(), 2);
        match &actions[0] {
            Action::SendTo { frame, .. } => {
                assert_eq!(frame.hdr.ty, MsgType::Data);
                assert_eq!(frame.hdr.version, 7, "PING DATA must echo request version");
                assert_eq!(frame.hdr.peer, 77, "reply must echo the request peer");
                assert_eq!(frame.payload, EnvBuilder::new().finish());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        match &actions[1] {
            Action::SendTo { frame, .. } => {
                assert_eq!(frame.hdr.ty, MsgType::Status);
                assert_eq!(
                    frame.hdr.version, PROTO_VERSION,
                    "PING STATUS uses normal protocol version"
                );
                assert_eq!(frame.hdr.peer, 77, "reply must echo the request peer");
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(0));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn add_object_with_exhausted_obj_id_space_replies_invalid_argument_no_panic() {
        use core::num::NonZeroU32;

        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let id = install_peer(&mut peers);
        // Force the obj-id allocator to its overflow boundary so the
        // very next AddObject hits ObjectIdExhausted.
        objs.next_id = NonZeroU32::new(u32::MAX).unwrap();

        let actions = dispatch(
            &add_object_frame(2, "example"),
            id,
            &mut peers,
            &mut objs,
            &mut subs,
        );
        assert_eq!(actions.len(), 1, "exhaustion must reply, not crash");
        match &actions[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, id);
                assert_eq!(frame.hdr.ty, MsgType::Status);
                let s = find(&frame.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32);
                assert_eq!(s, Some(UBUS_STATUS_INVALID_ARGUMENT));
                // No ObjId in the reply — the registration didn't
                // happen, so leaking a phantom id would be a bug.
                assert!(find(&frame.payload, UbusAttr::ObjId).is_none());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        // Registry must be unchanged — a half-applied insert that
        // dropped a prior registration on the way out would silently
        // delete an existing object.
        assert!(objs.lookup_exact("example").is_none());
        let owned_after = peers.get(id).map(Peer::owned_count).unwrap_or(0);
        assert_eq!(owned_after, 0, "peer.owned must not gain a phantom id");
    }

    // ---- event bus -------------------------------------------------

    fn event_register_frame(seq: u16, object: u32, pattern: &str) -> Frame {
        let data = BlobMsgTable::build(|b| {
            b.put_i32(Some("object"), object as i32);
            b.put_str(Some("pattern"), pattern);
        });
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, EVENT_OBJECT_ID);
        env.push_str(UbusAttr::Method, "register");
        env.push_data(data.contents());
        Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq,
                peer: EVENT_OBJECT_ID,
            },
            payload: env.finish(),
        }
    }

    fn event_send_frame(seq: u16, id: &str, value: i32) -> Frame {
        let data = BlobMsgTable::build(|b| {
            b.put_str(Some("id"), id);
            b.open_table(Some("data"));
            b.put_i32(Some("value"), value);
            b.close_table();
        });
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, EVENT_OBJECT_ID);
        env.push_str(UbusAttr::Method, "send");
        env.push_data(data.contents());
        Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq,
                peer: EVENT_OBJECT_ID,
            },
            payload: env.finish(),
        }
    }

    /// Install a peer with an anonymous listener object and register it
    /// on the event bus with `pattern`. Returns (peer, listener obj).
    fn install_listener(
        peers: &mut PeerTable,
        objects: &mut ObjectRegistry,
        events: &mut EventRegistry,
        subs: &mut SubscriberRegistry,
        seq: u16,
        pattern: &str,
    ) -> (PeerId, ObjectId) {
        let peer = install_peer(peers);
        let obj = objects.insert_anonymous(peer).expect("listener obj");
        let reply = super::dispatch_without_acl(
            &event_register_frame(seq, obj.get(), pattern),
            peer,
            peers,
            objects,
            subs,
            events,
            &mut MonitorRegistry::new(),
        );
        assert_eq!(reply.len(), 1, "register replies with a single STATUS");
        match &reply[0] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, peer);
                assert_eq!(frame.hdr.ty, MsgType::Status);
                assert_eq!(
                    frame.hdr.peer, EVENT_OBJECT_ID,
                    "register echoes obj-1 peer"
                );
                assert_eq!(
                    find(&frame.payload, UbusAttr::Status)
                        .and_then(|a| a.as_u32())
                        .map(|u| u as i32),
                    Some(0)
                );
            }
            other => panic!("unexpected register reply: {other:?}"),
        }
        (peer, obj)
    }

    fn fanout_target(action: &Action) -> (PeerId, u16, String, ObjectId) {
        let Action::SendTo { peer_id, frame, .. } = action else {
            panic!("expected SendTo fan-out, got {action:?}");
        };
        assert_eq!(frame.hdr.ty, MsgType::Invoke, "fan-out is INVOKE");
        assert_eq!(frame.hdr.peer, 0, "fan-out hdr.peer is 0");
        assert_eq!(
            attr_ids(&frame.payload),
            vec![
                UbusAttr::ObjId as u8,
                UbusAttr::Method as u8,
                UbusAttr::Data as u8,
            ],
            "fan-out attr order [ObjId, Method, Data] (no User/Group)"
        );
        let method = find(&frame.payload, UbusAttr::Method)
            .and_then(|a| a.as_str())
            .expect("method")
            .to_owned();
        let obj_id = find(&frame.payload, UbusAttr::ObjId)
            .and_then(|a| a.as_u32())
            .and_then(ObjectId::new)
            .expect("objid");
        (*peer_id, frame.hdr.seq, method, obj_id)
    }

    #[test]
    fn event_register_then_send_fans_out_and_acks() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let (listener, listener_obj) =
            install_listener(&mut peers, &mut objs, &mut events, &mut subs, 2, "*");
        let publisher = install_peer(&mut peers);

        let out = super::dispatch_without_acl(
            &event_send_frame(9, "example.probe.event", 7),
            publisher,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        // One fan-out INVOKE to the listener, then STATUS(0) to publisher.
        assert_eq!(out.len(), 2);
        let (dest, seq, method, obj_id) = fanout_target(&out[0]);
        assert_eq!(dest, listener);
        assert_eq!(seq, 1, "first fan-out delivery carries global seq 1");
        assert_eq!(method, "example.probe.event");
        assert_eq!(obj_id, listener_obj, "ObjId is the listener's own object");
        match &out[1] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, publisher);
                assert_eq!(frame.hdr.ty, MsgType::Status);
                assert_eq!(frame.hdr.peer, EVENT_OBJECT_ID);
                assert_eq!(
                    find(&frame.payload, UbusAttr::Status)
                        .and_then(|a| a.as_u32())
                        .map(|u| u as i32),
                    Some(0)
                );
            }
            other => panic!("unexpected ack: {other:?}"),
        }
    }

    #[test]
    fn event_send_prefix_pattern_filters_and_globals_seq_is_pattern_ordered() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        // Two listeners: catch-all ("" prefix) and "example." prefix.
        let (all, _) = install_listener(&mut peers, &mut objs, &mut events, &mut subs, 2, "*");
        let (pfx, _) = install_listener(
            &mut peers,
            &mut objs,
            &mut events,
            &mut subs,
            3,
            "example.*",
        );
        let publisher = install_peer(&mut peers);

        // Matching event: both listeners get it, catch-all first (prefix
        // "" < "example."), so catch-all seq 1, prefix seq 2.
        let out = super::dispatch_without_acl(
            &event_send_frame(9, "example.probe.event", 7),
            publisher,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        let fanouts: Vec<_> = out.iter().take(2).map(fanout_target).collect();
        assert_eq!(fanouts[0].0, all);
        assert_eq!(fanouts[0].1, 1, "catch-all delivered first (seq 1)");
        assert_eq!(fanouts[1].0, pfx);
        assert_eq!(fanouts[1].1, 2, "prefix listener delivered second (seq 2)");

        // Non-matching event: only catch-all, and the global counter
        // continues from 3 (proving it is broker-global, not per-event).
        let out = super::dispatch_without_acl(
            &event_send_frame(10, "other.event", 9),
            publisher,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        let (dest, seq, _, _) = fanout_target(&out[0]);
        assert_eq!(dest, all);
        assert_eq!(seq, 3, "global seq continues across events");
        // Only the one fan-out plus the publisher ack.
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn event_pattern_brackets_are_literal_not_fnmatch() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        install_listener(
            &mut peers,
            &mut objs,
            &mut events,
            &mut subs,
            2,
            "example.[p]*",
        );
        let publisher = install_peer(&mut peers);
        // `example.[p]*` → prefix "example.[p]" — does NOT match
        // "example.probe.event" (regression against fnmatch).
        let out = super::dispatch_without_acl(
            &event_send_frame(9, "example.probe.event", 7),
            publisher,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        assert_eq!(out.len(), 1, "no fan-out; only the publisher ack");
        assert!(matches!(&out[0], Action::SendTo { frame, .. } if frame.hdr.ty == MsgType::Status));
    }

    #[test]
    fn event_send_suppresses_the_publishers_own_listener() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        // The publisher is ALSO a catch-all listener.
        let (publisher, _) =
            install_listener(&mut peers, &mut objs, &mut events, &mut subs, 2, "*");
        let out = super::dispatch_without_acl(
            &event_send_frame(9, "self.event", 1),
            publisher,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        assert_eq!(out.len(), 1, "publisher must not receive its own event");
        assert!(matches!(&out[0], Action::SendTo { frame, .. } if frame.hdr.ty == MsgType::Status));
    }

    #[test]
    fn named_add_object_broadcasts_object_add_to_listeners() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let (listener, listener_obj) = install_listener(
            &mut peers,
            &mut objs,
            &mut events,
            &mut subs,
            2,
            "ubus.object.*",
        );
        let owner = install_peer(&mut peers);

        let mut env = EnvBuilder::new();
        env.push_str(UbusAttr::ObjPath, "example.svc");
        let sig = ubus::blobmsg::BlobMsgTable::build(|b| {
            b.open_table(Some("ping"));
            b.close_table();
        });
        env.push_signature(sig.as_slice());
        let add = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq: 5,
                peer: 0,
            },
            payload: env.finish(),
        };
        let out = super::dispatch_without_acl(
            &add,
            owner,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        // DATA + STATUS to owner, then a ubus.object.add fan-out.
        let fanout = out
            .iter()
            .find_map(|a| match a {
                Action::SendTo { peer_id, frame, .. } if frame.hdr.ty == MsgType::Invoke => {
                    Some((*peer_id, frame))
                }
                _ => None,
            })
            .expect("ubus.object.add fan-out present");
        assert_eq!(fanout.0, listener);
        assert_eq!(
            find(&fanout.1.payload, UbusAttr::Method).and_then(|a| a.as_str()),
            Some("ubus.object.add")
        );
        assert_eq!(
            find(&fanout.1.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
            Some(listener_obj.get()),
            "fan-out ObjId is the listener's own object"
        );
        // Payload {id, path}: id = the newly-registered object id, path.
        let data = find(&fanout.1.payload, UbusAttr::Data)
            .map(|a| a.payload)
            .expect("event data");
        assert_eq!(
            blobmsg_lookup(data, "path").and_then(|r| r.as_str()),
            Some("example.svc")
        );
        let added_id = objs.lookup_exact("example.svc").expect("registered").get();
        assert_eq!(
            blobmsg_lookup(data, "id")
                .and_then(|r| r.as_i32())
                .map(|v| v as u32),
            Some(added_id)
        );
    }

    #[test]
    fn anonymous_add_object_is_silent_on_the_event_bus() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        install_listener(&mut peers, &mut objs, &mut events, &mut subs, 2, "*");
        let owner = install_peer(&mut peers);
        // Anonymous (pathless) registration mints no ubus.object.add.
        let out = super::dispatch_without_acl(
            &empty_frame(MsgType::AddObject, 5, 0),
            owner,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        assert!(
            out.iter().all(
                |a| !matches!(a, Action::SendTo { frame, .. } if frame.hdr.ty == MsgType::Invoke)
            ),
            "pathless ADD_OBJECT must not broadcast ubus.object.add"
        );
    }

    #[test]
    fn event_register_requires_a_caller_owned_object() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let caller = install_peer(&mut peers);
        let other = install_peer(&mut peers);
        let foreign = objs.insert_anonymous(other).expect("foreign obj");

        // Foreign object → PERMISSION_DENIED.
        let out = super::dispatch_without_acl(
            &event_register_frame(2, foreign.get(), "*"),
            caller,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        assert_eq!(
            find_status(&out),
            Some(UBUS_STATUS_PERMISSION_DENIED),
            "registering a foreign object is denied"
        );
        // Unknown object → NOT_FOUND.
        let out = super::dispatch_without_acl(
            &event_register_frame(3, 9999, "*"),
            caller,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut MonitorRegistry::new(),
        );
        assert_eq!(find_status(&out), Some(UBUS_STATUS_NOT_FOUND));
    }

    fn find_status(actions: &[Action]) -> Option<i32> {
        actions.iter().find_map(|a| match a {
            Action::SendTo { frame, .. } if frame.hdr.ty == MsgType::Status => {
                find(&frame.payload, UbusAttr::Status)
                    .and_then(|x| x.as_u32())
                    .map(|u| u as i32)
            }
            _ => None,
        })
    }

    #[test]
    fn invoke_validates_attrs_and_routes_by_objid_attr() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let caller = install_peer(&mut peers);
        let owner = install_peer(&mut peers);
        let (obj, _) = objs.insert("x".into(), owner, None).expect("object");
        let mut missing_method = EnvBuilder::new();
        missing_method.push_u32(UbusAttr::ObjId, obj.get());
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq: 1,
                peer: obj.get(),
            },
            payload: missing_method.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, caller, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_INVALID_ARGUMENT)
        );
        let mut missing_obj = EnvBuilder::new();
        missing_obj.push_str(UbusAttr::Method, "ping");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq: 2,
                peer: obj.get(),
            },
            payload: missing_obj.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, caller, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_INVALID_ARGUMENT)
        );
        let frame = invoke_frame(3, 9999, "ping");
        assert_eq!(
            find_status(&dispatch(&frame, caller, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_NOT_FOUND)
        );
        let mut frame = invoke_frame(4, obj.get(), "ping");
        frame.hdr.peer = 0;
        let actions = dispatch(&frame, caller, &mut peers, &mut objs, &mut subs);
        assert!(
            matches!(actions.as_slice(), [Action::SendTo { peer_id, .. }] if *peer_id == owner)
        );
    }

    #[test]
    fn event_unknown_method_is_invalid_command() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let caller = install_peer(&mut peers);
        assert_eq!(
            find_status(&dispatch(
                &invoke_frame(1, EVENT_OBJECT_ID, "bogus"),
                caller,
                &mut peers,
                &mut objs,
                &mut subs
            )),
            Some(UBUS_STATUS_INVALID_COMMAND)
        );
    }

    #[test]
    fn subscribe_and_unsubscribe_validate_their_ladders() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let caller = install_peer(&mut peers);
        let (target, _) = objs.insert("target".into(), owner, None).expect("target");
        let mine = objs.insert_anonymous(caller).expect("mine");
        let mut foreign = EnvBuilder::new();
        foreign.push_u32(UbusAttr::ObjId, target.get());
        foreign.push_u32(UbusAttr::Target, 9999);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq: 1,
                peer: 0,
            },
            payload: foreign.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, caller, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_INVALID_ARGUMENT)
        );
        let mut unknown = EnvBuilder::new();
        unknown.push_u32(UbusAttr::ObjId, mine.get());
        unknown.push_u32(UbusAttr::Target, 9999);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Unsubscribe,
                seq: 2,
                peer: 0,
            },
            payload: unknown.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, caller, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_NOT_FOUND)
        );
        let mut absent = EnvBuilder::new();
        absent.push_u32(UbusAttr::ObjId, mine.get());
        absent.push_u32(UbusAttr::Target, target.get());
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Unsubscribe,
                seq: 3,
                peer: 0,
            },
            payload: absent.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, caller, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_NOT_FOUND)
        );
    }

    #[test]
    fn notify_ladder_and_empty_path_add_object_match_upstream() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let other = install_peer(&mut peers);
        let (obj, _) = objs.insert("x".into(), owner, None).expect("object");
        let frame = empty_frame(MsgType::Notify, 1, 0);
        assert_eq!(
            find_status(&dispatch(&frame, owner, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_INVALID_ARGUMENT)
        );
        let mut no_method = EnvBuilder::new();
        no_method.push_u32(UbusAttr::ObjId, obj.get());
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 11,
                peer: 0,
            },
            payload: no_method.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, owner, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_INVALID_ARGUMENT)
        );
        let mut unknown = EnvBuilder::new();
        unknown.push_u32(UbusAttr::ObjId, 9999);
        unknown.push_str(UbusAttr::Method, "x");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 2,
                peer: 0,
            },
            payload: unknown.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, owner, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_NOT_FOUND)
        );
        let mut foreign = EnvBuilder::new();
        foreign.push_u32(UbusAttr::ObjId, obj.get());
        foreign.push_str(UbusAttr::Method, "x");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 3,
                peer: 0,
            },
            payload: foreign.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, other, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_PERMISSION_DENIED)
        );
        assert_eq!(
            dispatch(
                &add_object_frame(4, ""),
                owner,
                &mut peers,
                &mut objs,
                &mut subs
            )
            .len(),
            2
        );
        let mut typed_empty = EnvBuilder::new();
        typed_empty.push_str(UbusAttr::ObjPath, "");
        typed_empty.push_signature(&[]);
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq: 5,
                peer: 0,
            },
            payload: typed_empty.finish(),
        };
        let typed_actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        assert_eq!(typed_actions.len(), 2);
        let Action::SendTo { frame, .. } = &typed_actions[0] else {
            panic!("typed empty-path ADD_OBJECT must start with DATA");
        };
        assert_eq!(frame.hdr.ty, MsgType::Data);
        assert!(find(&frame.payload, UbusAttr::ObjType).is_some());
        let mut empty_lookup = EnvBuilder::new();
        empty_lookup.push_str(UbusAttr::ObjPath, "");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 6,
                peer: 0,
            },
            payload: empty_lookup.finish(),
        };
        assert_eq!(
            find_status(&dispatch(&frame, owner, &mut peers, &mut objs, &mut subs)),
            Some(UBUS_STATUS_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn acl_publish_grant_denial_and_root_bypass() {
        let acl = acl_for("u", AclOp::Publish, "example.*", None);
        let mut peers = PeerTable::new();
        let user = install_user_peer(&mut peers, "u");
        let other = install_user_peer(&mut peers, "other");
        let root = install_peer(&mut peers);
        let mut objects = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();

        assert_eq!(
            find_status(&dispatch_acl(
                &add_object_frame(1, "example.user"),
                user,
                &acl,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(0)
        );
        assert_eq!(
            find_status(&dispatch_acl(
                &add_object_frame(2, "example.other"),
                other,
                &acl,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(UBUS_STATUS_INVALID_ARGUMENT)
        );
        assert_eq!(
            find_status(&dispatch_acl(
                &add_object_frame(3, "outside.root"),
                root,
                &acl,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(0)
        );
    }

    #[test]
    fn acl_access_grant_and_acl_builtin_status() {
        let acl = acl_for("u", AclOp::Access, "example.target", Some("allowed"));
        let mut peers = PeerTable::new();
        let owner = install_peer(&mut peers);
        let user = install_user_peer(&mut peers, "u");
        let mut objects = ObjectRegistry::new();
        let target = objects
            .insert("example.target".to_string(), owner, None)
            .expect("object insert")
            .0;
        let mut subs = SubscriberRegistry::new();

        assert_eq!(
            find_status(&dispatch_acl(
                &invoke_frame(1, target.get(), "blocked"),
                user,
                &acl,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(UBUS_STATUS_PERMISSION_DENIED)
        );
        let allowed = dispatch_acl(
            &invoke_frame(2, target.get(), "allowed"),
            user,
            &acl,
            &mut peers,
            &mut objects,
            &mut subs,
        );
        assert!(
            matches!(allowed.as_slice(), [Action::SendTo { peer_id, .. }] if *peer_id == owner)
        );
        assert_eq!(
            find_status(&dispatch_acl(
                &invoke_frame(3, UBUS_SYSTEM_OBJECT_ACL, "get"),
                user,
                &acl,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(UBUS_STATUS_INVALID_COMMAND)
        );
    }

    #[test]
    fn acl_query_returns_empty_array_and_echoes_sequence() {
        let mut peers = PeerTable::new();
        let caller = install_peer(&mut peers);
        let mut objects = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let mut monitors = MonitorRegistry::new();
        let mut fd = None;
        let request = invoke_frame(71, UBUS_SYSTEM_OBJECT_ACL, "query");

        let actions = super::dispatch(
            &request,
            caller,
            &AclRegistry::default(),
            9,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
            &mut fd,
        );
        assert_eq!(actions.len(), 2);
        let Action::SendTo { frame, .. } = &actions[0] else {
            panic!("DATA action")
        };
        assert_eq!(frame.hdr.ty, MsgType::Data);
        assert_eq!(frame.hdr.seq, 71);
        assert_eq!(frame.hdr.peer, UBUS_SYSTEM_OBJECT_ACL);
        let expected_blob = BlobMsgTable::build(|builder| {
            builder.put_i32(Some("seq"), 9);
            builder.open_array(Some("acl"));
            builder.close_array();
        });
        let mut expected = EnvBuilder::new();
        expected.push_u32(UbusAttr::ObjId, UBUS_SYSTEM_OBJECT_ACL);
        expected.push_data(expected_blob.contents());
        assert_eq!(frame.payload, expected.finish());
        assert_eq!(find_status(&actions[1..]), Some(0));
    }

    #[test]
    fn acl_query_renders_matching_privilege_entries_in_wire_order() {
        let entries = crate::acl::parse_file(
            br#"{"user":"alice","access":{"svc.*":{"acl":{"custom":"tag","n":7}}}}"#,
        )
        .expect("ACL parses");
        let acl = AclRegistry { entries };
        let mut peers = PeerTable::new();
        let caller = install_peer(&mut peers);
        let mut objects = ObjectRegistry::new();
        objects
            .insert("svc.a".to_string(), caller, None)
            .expect("object");
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let mut monitors = MonitorRegistry::new();
        let mut fd = None;
        let request = invoke_frame(4, UBUS_SYSTEM_OBJECT_ACL, "query");

        let actions = super::dispatch(
            &request,
            caller,
            &acl,
            1,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
            &mut fd,
        );
        let Action::SendTo { frame, .. } = &actions[0] else {
            panic!("DATA action")
        };
        let expected_blob = BlobMsgTable::build(|builder| {
            builder.put_i32(Some("seq"), 1);
            builder.open_array(Some("acl"));
            builder.open_table(None);
            builder.put_str(Some("obj"), "svc.a");
            builder.put_str(Some("user"), "alice");
            builder.open_table(Some("acl"));
            builder.put_str(Some("custom"), "tag");
            builder.put_i32(Some("n"), 7);
            builder.close_table();
            builder.close_table();
            builder.close_array();
        });
        let mut expected = EnvBuilder::new();
        expected.push_u32(UbusAttr::ObjId, UBUS_SYSTEM_OBJECT_ACL);
        expected.push_data(expected_blob.contents());
        assert_eq!(frame.payload, expected.finish());
        assert_eq!(find_status(&actions[1..]), Some(0));
    }

    #[test]
    fn acl_subscribe_listen_and_send_gate_independently() {
        let mut peers = PeerTable::new();
        let owner = install_peer(&mut peers);
        let user = install_user_peer(&mut peers, "u");
        let mut objects = ObjectRegistry::new();
        let target = objects
            .insert("example.target".to_string(), owner, None)
            .expect("target insert")
            .0;
        let listener = objects.insert_anonymous(user).expect("listener insert");
        let mut subs = SubscriberRegistry::new();
        let mut subscribe = EnvBuilder::new();
        subscribe.push_u32(UbusAttr::Target, target.get());
        subscribe.push_u32(UbusAttr::ObjId, listener.get());
        let subscribe = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq: 1,
                peer: 0,
            },
            payload: subscribe.finish(),
        };

        let denied = AclRegistry::default();
        assert_eq!(
            find_status(&dispatch_acl(
                &subscribe,
                user,
                &denied,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            // Probed: subscribe-ACL deny is masked as NOT_FOUND, not
            // PERMISSION_DENIED (unlike access/listen/send).
            Some(UBUS_STATUS_NOT_FOUND)
        );
        let subscribe_acl = acl_for("u", AclOp::Subscribe, "example.*", None);
        assert_eq!(
            find_status(&dispatch_acl(
                &subscribe,
                user,
                &subscribe_acl,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(0)
        );

        let listen_acl = acl_for("u", AclOp::Listen, "example.*", None);
        assert_eq!(
            find_status(&dispatch_acl(
                &event_register_frame(2, listener.get(), "example.*"),
                user,
                &denied,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(UBUS_STATUS_PERMISSION_DENIED)
        );
        assert_eq!(
            find_status(&dispatch_acl(
                &event_register_frame(3, listener.get(), "example.*"),
                user,
                &listen_acl,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(0)
        );

        let send_acl = acl_for("u", AclOp::Send, "example.*", None);
        assert_eq!(
            find_status(&dispatch_acl(
                &event_send_frame(4, "example.event", 1),
                user,
                &denied,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(UBUS_STATUS_PERMISSION_DENIED)
        );
        assert_eq!(
            find_status(&dispatch_acl(
                &event_send_frame(5, "example.event", 1),
                user,
                &send_acl,
                &mut peers,
                &mut objects,
                &mut subs,
            )),
            Some(0)
        );
    }

    #[test]
    fn forwarded_invoke_takes_frame_fd_but_rejected_invokes_leave_it() {
        let mut peers = PeerTable::new();
        let owner = install_peer(&mut peers);
        let caller = install_peer(&mut peers);
        let denied = install_user_peer(&mut peers, "denied");
        let mut objects = ObjectRegistry::new();
        let target = objects.insert_anonymous(owner).expect("object insert");
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let mut monitors = MonitorRegistry::new();

        let (_, write_end) = rustix::pipe::pipe().unwrap();
        let mut frame_fd = Some(write_end);
        let actions = super::dispatch(
            &invoke_frame(1, target.get(), "call"),
            caller,
            &AclRegistry::default(),
            0,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
            &mut frame_fd,
        );
        assert!(frame_fd.is_none());
        assert!(
            matches!(actions.as_slice(), [Action::SendTo { peer_id, fd: Some(_), .. }] if *peer_id == owner)
        );

        let (_, write_end) = rustix::pipe::pipe().unwrap();
        let mut frame_fd = Some(write_end);
        let _ = super::dispatch(
            &invoke_frame(2, 999_999, "call"),
            caller,
            &AclRegistry::default(),
            0,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
            &mut frame_fd,
        );
        assert!(frame_fd.is_some(), "unroutable INVOKE must not take the fd");

        let named = objects
            .insert("denied.target".to_string(), owner, None)
            .expect("named object insert")
            .0;
        let (_, write_end) = rustix::pipe::pipe().unwrap();
        let mut frame_fd = Some(write_end);
        let _ = super::dispatch(
            &invoke_frame(3, named.get(), "call"),
            denied,
            &AclRegistry::default(),
            0,
            &mut peers,
            &mut objects,
            &mut subs,
            &mut events,
            &mut monitors,
            &mut frame_fd,
        );
        assert!(frame_fd.is_some(), "ACL-denied INVOKE must not take the fd");
    }

    #[test]
    fn owner_response_takes_fd_for_status_not_data() {
        let mut peers = PeerTable::new();
        let owner = install_peer(&mut peers);
        let caller = install_peer(&mut peers);
        let mut objects = ObjectRegistry::new();
        let target = objects.insert_anonymous(owner).expect("object insert");

        let response = |ty| {
            let mut env = EnvBuilder::new();
            env.push_u32(UbusAttr::ObjId, target.get());
            match ty {
                MsgType::Status => env.push_u32(UbusAttr::Status, 0),
                MsgType::Data => env.push_data(&[]),
                _ => unreachable!(),
            }
            Frame {
                hdr: Header {
                    version: PROTO_VERSION,
                    ty,
                    seq: 1,
                    peer: caller.get(),
                },
                payload: env.finish(),
            }
        };

        let (_, write_end) = rustix::pipe::pipe().unwrap();
        let mut status_fd = Some(write_end);
        let status = forward_owner_response(
            &FrameRef::from(&response(MsgType::Status)),
            owner,
            &objects,
            &mut status_fd,
        );
        assert!(status_fd.is_none());
        assert!(matches!(
            status.as_slice(),
            [Action::SendTo { fd: Some(_), .. }]
        ));

        let (_, write_end) = rustix::pipe::pipe().unwrap();
        let mut data_fd = Some(write_end);
        let data = forward_owner_response(
            &FrameRef::from(&response(MsgType::Data)),
            owner,
            &objects,
            &mut data_fd,
        );
        assert!(data_fd.is_some());
        assert!(matches!(data.as_slice(), [Action::SendTo { fd: None, .. }]));
    }

    // ---- REMOVE_OBJECT tears down everything the object owned ------

    /// Upstream's `ubusd_free_object()` calls
    /// `ubusd_event_cleanup_object()`, so an explicit REMOVE_OBJECT ends
    /// the object's `ubus listen` registrations. Before this, only a
    /// disconnect pruned them and a client that unregistered its
    /// listener kept receiving events on the dead obj id.
    #[test]
    fn remove_object_ends_its_event_listener_registration() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let mut events = EventRegistry::new();
        let mut monitors = MonitorRegistry::new();
        let (listener, listener_obj) = install_listener(
            &mut peers,
            &mut objs,
            &mut events,
            &mut subs,
            1,
            "example.*",
        );
        peers.get_mut(listener).unwrap().add_owned(listener_obj);
        let sender = install_peer(&mut peers);

        let before = super::dispatch_without_acl(
            &event_send_frame(2, "example.up", 1),
            sender,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut monitors,
        );
        assert_eq!(before.len(), 2, "listener fan-out plus the sender STATUS");

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, listener_obj.get());
        let remove = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 3,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = super::dispatch_without_acl(
            &remove,
            listener,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut monitors,
        );
        assert_eq!(
            actions.len(),
            2,
            "removing an anonymous object is just DATA + STATUS"
        );

        let after = super::dispatch_without_acl(
            &event_send_frame(4, "example.up", 1),
            sender,
            &mut peers,
            &mut objs,
            &mut subs,
            &mut events,
            &mut monitors,
        );
        assert_eq!(
            after.len(),
            1,
            "only the sender STATUS — the removed listener object is gone"
        );
    }

    /// Upstream walks `obj->target_list` in `ubusd_free_object()`, so
    /// removing an object also cancels the subscriptions it holds *as a
    /// subscriber* — and the publisher left with none gets `Active=0`.
    /// The registry is keyed by target, so this used to be missed
    /// entirely: fan-out kept reaching the peer stamped with a dead id.
    #[test]
    fn remove_object_drops_the_subscriptions_it_holds() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let publisher = install_peer(&mut peers);
        let subscriber = install_peer(&mut peers);
        let (target, _) = objs
            .insert("example".into(), publisher, None)
            .expect("target insert");
        peers.get_mut(publisher).unwrap().add_owned(target);
        let sub_obj = objs.insert_anonymous(subscriber).expect("subscriber obj");
        peers.get_mut(subscriber).unwrap().add_owned(sub_obj);
        assert!(subs.add(target, subscriber, sub_obj));
        peers.get_mut(subscriber).unwrap().add_sub(target);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, sub_obj.get());
        let remove = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 7,
                peer: 0,
            },
            payload: env.finish(),
        };
        let actions = dispatch(&remove, subscriber, &mut peers, &mut objs, &mut subs);
        assert_eq!(
            actions.len(),
            3,
            "DATA + STATUS to the remover, Active=0 to the publisher"
        );
        match &actions[2] {
            Action::SendTo { peer_id, frame, .. } => {
                assert_eq!(*peer_id, publisher);
                assert_eq!(frame.hdr.ty, MsgType::Notify);
                assert_eq!(
                    find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
                    Some(target.get())
                );
                assert_eq!(
                    find(&frame.payload, UbusAttr::Active).map(|a| a.payload),
                    Some(&[0][..])
                );
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert!(
            subs.subscribers_of(target).is_empty(),
            "the removed object's subscription must be gone"
        );
        assert_eq!(peers.get(subscriber).unwrap().sub_count(), 0);
    }

    /// libubus allows several `ubus_subscriber` objects on one context,
    /// and upstream keys `target->subscribers` by subscriber object. A
    /// per-peer key collapsed them into one, so the NOTIFY ack listed a
    /// single id and only one object saw the fan-out.
    #[test]
    fn two_subscriber_objects_on_one_connection_both_receive_fanout() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let sub_peer = install_peer(&mut peers);
        set_names(&mut peers, owner, "root", "root");
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        let first = objs.insert_anonymous(sub_peer).expect("first sub obj");
        let second = objs.insert_anonymous(sub_peer).expect("second sub obj");
        assert!(
            subs.add(obj_id, sub_peer, first),
            "first subscriber activates the target"
        );
        assert!(
            !subs.add(obj_id, sub_peer, second),
            "second subscriber joins an already-active target"
        );
        assert!(
            !subs.add(obj_id, sub_peer, second),
            "an exact repeat stays idempotent"
        );
        assert_eq!(subs.subscribers_of(obj_id).len(), 2);

        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, obj_id.get());
        env.push_str(UbusAttr::Method, "fanout");
        let frame = Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Notify,
                seq: 11,
                peer: obj_id.get(),
            },
            payload: env.finish(),
        };
        let actions = dispatch(&frame, owner, &mut peers, &mut objs, &mut subs);
        assert_eq!(
            actions.len(),
            3,
            "ack plus one fan-out per subscriber object"
        );

        let acked: Vec<u32> = match &actions[0] {
            Action::SendTo { frame, .. } => {
                let container = find(&frame.payload, UbusAttr::Subscribers).expect("subscribers");
                iter_attrs(container.payload)
                    .filter_map(|a| a.as_u32())
                    .collect()
            }
            other => panic!("unexpected ack action: {other:?}"),
        };
        assert_eq!(acked, vec![first.get(), second.get()]);

        let delivered: Vec<(PeerId, u32)> = actions
            .iter()
            .skip(1)
            .map(|action| {
                let Action::SendBytes { peer_id, bytes } = action else {
                    panic!("expected encoded fan-out, got {action:?}");
                };
                let (forwarded, _) = Codec::read_frame(bytes).expect("encoded fan-out");
                let obj = find(&forwarded.payload, UbusAttr::ObjId)
                    .and_then(|a| a.as_u32())
                    .expect("fan-out objid");
                (*peer_id, obj)
            })
            .collect();
        assert_eq!(
            delivered,
            vec![(sub_peer, first.get()), (sub_peer, second.get())],
            "both subscriber objects on the connection receive their own INVOKE"
        );
    }

    /// Disconnect must sweep every subscription a connection held on a
    /// target, not just the first one a keyed lookup lands on.
    #[test]
    fn disconnect_purges_all_subscriber_objects_of_one_connection() {
        let mut peers = PeerTable::new();
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = install_peer(&mut peers);
        let sub_peer = install_peer(&mut peers);
        let (obj_id, _) = objs
            .insert("example".into(), owner, None)
            .expect("obj insert");
        let first = objs.insert_anonymous(sub_peer).expect("first sub obj");
        let second = objs.insert_anonymous(sub_peer).expect("second sub obj");
        subs.add(obj_id, sub_peer, first);
        subs.add(obj_id, sub_peer, second);
        peers.get_mut(sub_peer).unwrap().add_sub(obj_id);

        let held = peers.get_mut(sub_peer).unwrap().take_subs();
        assert_eq!(subs.purge_peer(sub_peer, &[], &held), vec![obj_id]);
        assert!(subs.subscribers_of(obj_id).is_empty());
    }
}
