use ubus::envelope::{find, EnvBuilder, MonitorAttr, UbusAttr};
use ubus::wire::{Frame, FrameRef, Header, MsgType};

use crate::registry::{ObjectId, ObjectType, PeerId};

/// HELLO reply. Carries the broker-assigned peer-id in `hdr.peer`.
/// Body is an empty envelope (`[0, 0, 0, 4]`) so the on-wire layout
/// matches upstream `ubusd` byte-for-byte: 8-byte header + 4-byte
/// envelope length prefix with no attrs. Real `libubus` reads only
/// `hdr.peer` from the reply, but the envelope keeps the trailer
/// well-formed for clients that do parse the body.
pub fn hello_reply(seq: u16, assigned_peer: PeerId) -> Frame {
    Frame::to_peer(
        MsgType::Hello,
        seq,
        assigned_peer.get(),
        EnvBuilder::new().finish(),
    )
}

/// STATUS frame carrying just the status code. Upstream `ubusd`'s
/// STATUS never carries an ObjId attr — the assigned/removed id rides
/// the paired [`obj_id_data`] DATA frame instead.
pub fn status_reply(seq: u16, reply_peer: u32, status: i32) -> Frame {
    let mut env = EnvBuilder::new();
    env.push_i32(UbusAttr::Status, status);
    Frame::to_peer(MsgType::Status, seq, reply_peer, env.finish())
}

/// One broker-generated monitor record. Monitor attrs deliberately use their
/// own raw id space and the upstream-required put order.
pub fn monitor_mirror(
    mirror_seq: u16,
    client: u32,
    peer: u32,
    seq: u16,
    ty: u8,
    send: bool,
    data: &[u8],
) -> Frame {
    let mut env = EnvBuilder::new();
    env.push_u32_id(MonitorAttr::Client as u8, client);
    env.push_u32_id(MonitorAttr::Peer as u8, peer);
    env.push_u32_id(MonitorAttr::Seq as u8, seq.into());
    env.push_u32_id(MonitorAttr::Type as u8, ty.into());
    env.push_u8_id(MonitorAttr::Send as u8, u8::from(send));
    env.push_bytes_id(MonitorAttr::Data as u8, data);
    Frame::to_peer(MsgType::Monitor, mirror_seq, 0, env.finish())
}

/// One DATA frame for a typed LOOKUP reply. Upstream attr order is
/// ObjPath, ObjId, ObjType, Signature.
pub fn lookup_data(
    seq: u16,
    reply_peer: u32,
    obj_id: ObjectId,
    path: &str,
    obj_type: &ObjectType,
) -> Frame {
    lookup_data_with_signature(
        seq,
        reply_peer,
        obj_id,
        path,
        obj_type,
        obj_type.signature(),
    )
}

/// LOOKUP's object identity is stable, while each caller sees only the
/// declared methods its ACL permits. Preserve their original wire bytes.
pub fn lookup_data_with_signature(
    seq: u16,
    reply_peer: u32,
    obj_id: ObjectId,
    path: &str,
    obj_type: &ObjectType,
    signature: &[u8],
) -> Frame {
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, path);
    env.push_u32(UbusAttr::ObjId, obj_id.get());
    env.push_u32(UbusAttr::ObjType, obj_type.id().get());
    env.push_signature(signature);
    Frame::to_peer(MsgType::Data, seq, reply_peer, env.finish())
}

/// Broker-originated DATA reply for a successful ADD_OBJECT /
/// REMOVE_OBJECT: carries just `ObjId`, stamped with the request's
/// seq/peer exactly like [`lookup_data`]. Upstream `ubusd` answers
/// both with `DATA(OBJID)` before the terminating `STATUS(0)`, and
/// libubus' `ubus_add_object` harvests the assigned id *only* from
/// this DATA frame (no DATA → `UBUS_STATUS_NO_DATA`).
///
pub fn obj_id_data(
    seq: u16,
    reply_peer: u32,
    obj_id: ObjectId,
    obj_type: Option<ObjectId>,
) -> Frame {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj_id.get());
    if let Some(obj_type) = obj_type {
        env.push_u32(UbusAttr::ObjType, obj_type.get());
    }
    Frame::to_peer(MsgType::Data, seq, reply_peer, env.finish())
}

/// PING reply DATA echo. Upstream converts the request frame into a
/// DATA frame before sending the terminating STATUS(0), preserving
/// the request version byte and payload while changing only the type.
pub fn data_echo(request: &Frame) -> Frame {
    data_echo_ref(&FrameRef::from(request))
}

pub(crate) fn data_echo_ref(request: &FrameRef<'_>) -> Frame {
    Frame {
        hdr: Header {
            version: request.hdr.version,
            ty: MsgType::Data,
            seq: request.hdr.seq,
            peer: request.hdr.peer,
        },
        payload: request.payload.to_vec(),
    }
}

/// Publisher-side NOTIFY acknowledgement. The Subscribers attr is a
/// container of anonymous u32 attrs, each carrying a subscriber object
/// id, and is present even when empty.
///
/// `reply_peer` echoes the NOTIFY request's `hdr.peer` verbatim —
/// upstream builds this ack via `ubus_proto_send_msg_from_blob` before
/// rewriting `ub->hdr.peer` for the fan-out, so whatever the publisher
/// put in the header comes straight back. (Pinning the publisher's
/// object id here instead was invisible for years because every
/// scenario happened to send NOTIFY with `hdr.peer == publisher_obj`;
/// a real libubus subscriber run with `hdr.peer == 0` exposed it.)
pub fn notify_ack(
    seq: u16,
    reply_peer: u32,
    publisher_obj: ObjectId,
    subscribers: &[ObjectId],
) -> Frame {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, publisher_obj.get());
    env.push_container(UbusAttr::Subscribers, |inner| {
        for subscriber in subscribers {
            inner.push_u32_raw(0, subscriber.get());
        }
    });
    env.push_i32(UbusAttr::Status, 0);
    Frame::to_peer(MsgType::Status, seq, reply_peer, env.finish())
}

/// Broker-originated subscription Active state notification sent to
/// the owner of the publisher object.
pub fn active_notify(seq: u16, owner_obj: ObjectId, active: bool) -> Frame {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, owner_obj.get());
    env.push_u8(UbusAttr::Active, u8::from(active));
    Frame::to_peer(MsgType::Notify, seq, 0, env.finish())
}

/// Broker-originated notification to a subscriber that a publisher
/// object it subscribed to has gone away.
pub fn unsubscribe_notify(seq: u16, subscriber_obj: ObjectId, dead_obj: ObjectId) -> Frame {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, subscriber_obj.get());
    env.push_u32(UbusAttr::Target, dead_obj.get());
    Frame::to_peer(MsgType::Unsubscribe, seq, 0, env.finish())
}

/// Broker-originated event fan-out INVOKE delivered to one `ubus listen`
/// listener. `hdr.peer = 0`; attrs `[ObjId(listener's own obj), Method
/// (event name), Data(payload)]`. Unlike forwarded INVOKE / NOTIFY
/// fan-out, event delivery carries NO User/Group — it is uncredentialed.
/// For `ubus send` the payload is the inner `data` table; for the
/// broker-minted `ubus.object.add`/`remove` it is `{id, path}`.
pub fn event_invoke(seq: u16, listener_obj: ObjectId, event_name: &str, data: &[u8]) -> Frame {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, listener_obj.get());
    env.push_str(UbusAttr::Method, event_name);
    env.push_data(data);
    Frame::to_peer(MsgType::Invoke, seq, 0, env.finish())
}

/// Forward `frame` to a different peer with a rewritten `hdr.peer`.
/// Used when the broker rewrites INVOKE.hdr.peer = caller before
/// handing the frame to the owner so the owner can reply directly
/// to the caller's id.
pub fn rewrite_dest(frame: &Frame, new_peer: PeerId) -> Frame {
    let mut out = frame.clone();
    out.hdr.peer = new_peer.get();
    out
}

/// Broker-forwarded INVOKE shape used for both caller INVOKE routing
/// and NOTIFY fan-out. Upstream stamps credentials between Method and
/// Data, and Data must remain the final attr when present.
#[allow(clippy::too_many_arguments)]
pub fn stamped_invoke(
    seq: u16,
    hdr_peer: PeerId,
    obj_id: ObjectId,
    method: Option<&str>,
    user: Option<&str>,
    group: Option<&str>,
    data: Option<&[u8]>,
    no_reply: bool,
) -> Frame {
    let capacity = 4
        + 8
        + usize::from(no_reply) * 8
        + [method, user, group]
            .into_iter()
            .flatten()
            .map(|value| ubus::blob::align4(5 + value.len()))
            .sum::<usize>()
        + data.map_or(0, |value| ubus::blob::align4(4 + value.len()));
    let mut env = EnvBuilder::with_capacity(capacity);
    if no_reply {
        env.push_u8(UbusAttr::NoReply, 1);
    }
    env.push_u32(UbusAttr::ObjId, obj_id.get());
    if let Some(method) = method {
        env.push_str(UbusAttr::Method, method);
    }
    if let Some(user) = user {
        env.push_str(UbusAttr::User, user);
    }
    if let Some(group) = group {
        env.push_str(UbusAttr::Group, group);
    }
    if let Some(data) = data {
        env.push_data(data);
    }
    Frame::to_peer(MsgType::Invoke, seq, hdr_peer.get(), env.finish())
}

pub fn stamped_forwarded_invoke(
    frame: &Frame,
    caller: PeerId,
    obj_id: ObjectId,
    user: Option<&str>,
    group: Option<&str>,
) -> Frame {
    stamped_forwarded_invoke_ref(&FrameRef::from(frame), caller, obj_id, user, group)
}

pub(crate) fn stamped_forwarded_invoke_ref(
    frame: &FrameRef<'_>,
    caller: PeerId,
    obj_id: ObjectId,
    user: Option<&str>,
    group: Option<&str>,
) -> Frame {
    // Probed upstream: caller INVOKE never forwards UBUS_ATTR_NO_REPLY
    // to the owner.
    stamped_invoke(
        frame.hdr.seq,
        caller,
        obj_id,
        find(frame.payload, UbusAttr::Method).and_then(|a| a.as_str()),
        user,
        group,
        find(frame.payload, UbusAttr::Data).map(|a| a.payload),
        false,
    )
}
