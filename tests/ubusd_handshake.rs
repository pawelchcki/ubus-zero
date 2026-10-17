//! Wire-level cross-check: drive the in-tree client/server against
//! both the upstream `ubusd` binary and `ubusd::Broker` from one
//! `rstest` body, so any divergence shows up as a paired pass/fail.
//! Upstream reports a visible skip when its binary isn't reachable.

#![cfg(feature = "testing")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use rstest::rstest;
use ubus::blobmsg::{lookup as blobmsg_lookup, BlobMsgTable};
use ubus::client::UbusClient;
use ubus::envelope::{find, iter_attrs, unwrap as unwrap_envelope, EnvBuilder, UbusAttr};
use ubus::error::UbusError;
use ubus::server::{UbusConnection, UbusObject};
use ubus::transport::Transport;
use ubus::wire::{
    Codec, Frame, Header, MsgType, HEADER_SIZE, MAX_MSG_LEN, PROTO_VERSION,
    UBUS_STATUS_INVALID_ARGUMENT, UBUS_STATUS_INVALID_COMMAND, UBUS_STATUS_NOT_FOUND,
    UBUS_STATUS_OK, UBUS_STATUS_PERMISSION_DENIED,
};
use ubus_testkit::UnixUbusTransport;
use ubus_testkit::{run_matrix_case, skip, BrokerArm, MatrixArm, UbusdHarness};

#[allow(dead_code)]
mod common;
use common::{
    expect_typed_data_then_status_ok, join_owner, raw_add_object_with_signature, recv_until,
    signature_with_ping_method, OwnerThread,
};

fn hello_handshake_body(path: &str) {
    let transport = UnixUbusTransport::connect(path).expect("connect");
    // HELLO completes only when the broker assigns a non-zero peer id;
    // a follow-up LOOKUP exercises that the post-HELLO connection is
    // actually in the "registered" state (not silently half-handshook).
    let mut client = UbusClient::connect(transport).expect("hello");
    match client.lookup("ubus.no.such.thing") {
        Err(UbusError::Status(s)) => assert_eq!(
            s, UBUS_STATUS_NOT_FOUND,
            "lookup-unknown must report UBUS_STATUS_NOT_FOUND"
        ),
        other => panic!("expected UBUS_STATUS_NOT_FOUND, got {other:?}"),
    }
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn hello_handshake(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!("ubusd_handshake ", stringify!(hello_handshake)),
        arm,
        &hello_handshake_body,
    );
}

fn lookup_unknown_body(path: &str) {
    let transport = UnixUbusTransport::connect(path).expect("connect");
    let mut client = UbusClient::connect(transport).expect("hello");
    match client.lookup("example.no.such.object") {
        Err(UbusError::Status(s)) => assert_eq!(
            s, UBUS_STATUS_NOT_FOUND,
            "lookup-unknown must report UBUS_STATUS_NOT_FOUND"
        ),
        other => panic!("expected UBUS_STATUS_NOT_FOUND, got {other:?}"),
    }
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn lookup_unknown_object(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!("ubusd_handshake ", stringify!(lookup_unknown_object)),
        arm,
        &lookup_unknown_body,
    );
}

fn register_and_invoke_body(path: &str) {
    let path = path.to_owned();

    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example.test").method("ping", |_args| {
            Ok(BlobMsgTable::build(|bb| {
                bb.put_str(Some("pong"), "yes");
            }))
        })
    });
    owner.wait_ready();

    let transport = UnixUbusTransport::connect(&path).expect("caller connect");
    let mut client = UbusClient::connect(transport).expect("caller hello");
    let obj_id = client.lookup("example.test").expect("lookup");
    assert_ne!(obj_id, 0, "broker should assign a non-zero obj_id");

    let reply = client
        .invoke(obj_id, "ping", &BlobMsgTable::empty())
        .expect("invoke");
    let pong = blobmsg_lookup(&reply, "pong")
        .expect("pong attribute present")
        .as_str();
    assert_eq!(pong, Some("yes"));

    owner.shutdown();
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn register_object_and_invoke_round_trip(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(register_object_and_invoke_round_trip)
        ),
        arm,
        &register_and_invoke_body,
    );
}

fn invoke_with_large_payload_round_trips_body(path: &str) {
    let path = path.to_owned();

    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example.test").method("echo", |args| {
            let echoed = blobmsg_lookup(args, "payload")
                .and_then(|a| a.as_str())
                .expect("payload argument")
                .to_owned();
            Ok(BlobMsgTable::build(|bb| {
                bb.put_str(Some("payload"), &echoed);
            }))
        })
    });
    owner.wait_ready();

    let transport = UnixUbusTransport::connect(&path).expect("caller connect");
    let mut client = UbusClient::connect(transport).expect("caller hello");
    let obj_id = client.lookup("example.test").expect("lookup");
    let payload = "x".repeat(80 * 1024);
    let args = BlobMsgTable::build(|bb| {
        bb.put_str(Some("payload"), &payload);
    });

    let reply = client.invoke(obj_id, "echo", &args).expect("large invoke");
    assert_eq!(
        blobmsg_lookup(&reply, "payload").and_then(|a| a.as_str()),
        Some(payload.as_str()),
        "80 KiB INVOKE payload must round-trip through the owner"
    );

    owner.shutdown();
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn invoke_with_large_payload_round_trips(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(invoke_with_large_payload_round_trips)
        ),
        arm,
        &invoke_with_large_payload_round_trips_body,
    );
}

fn invoke_reply_addressed_from_target_object_body(path: &str) {
    let path = path.to_owned();

    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example.test").method("ping", |_args| {
            Ok(BlobMsgTable::build(|bb| {
                bb.put_str(Some("pong"), "yes");
            }))
        })
    });
    owner.wait_ready();

    let probe_transport = UnixUbusTransport::connect(&path).expect("probe connect");
    let mut probe = UbusClient::connect(probe_transport).expect("probe hello");
    let obj_id = probe.lookup("example.test").expect("lookup");

    let mut raw = UnixUbusTransport::connect(&path).expect("raw caller connect");
    recv_until(&mut raw, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("raw caller HELLO");

    let args = BlobMsgTable::empty();
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj_id);
    env.push_str(UbusAttr::Method, "ping");
    env.push_data(args.contents());
    raw.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Invoke,
            seq: 31,
            peer: obj_id,
        },
        payload: env.finish(),
    })
    .expect("send raw INVOKE");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_data = false;
    let mut saw_status = false;
    while Instant::now() < deadline && !(saw_data && saw_status) {
        match raw.recv() {
            Ok(Some(f)) if f.hdr.seq == 31 && f.hdr.ty == MsgType::Data => {
                assert_eq!(f.hdr.peer, obj_id, "DATA reply must come from obj_id");
                saw_data = true;
            }
            Ok(Some(f)) if f.hdr.seq == 31 && f.hdr.ty == MsgType::Status => {
                assert_eq!(f.hdr.peer, obj_id, "STATUS reply must come from obj_id");
                let s = find(&f.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .expect("STATUS attr");
                assert_eq!(s, UBUS_STATUS_OK, "INVOKE status must be OK");
                saw_status = true;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("raw recv: {e:?}"),
        }
    }
    assert!(saw_data, "raw INVOKE DATA reply missing");
    assert!(saw_status, "raw INVOKE STATUS reply missing");

    owner.shutdown();
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn invoke_reply_addressed_from_target_object(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(invoke_reply_addressed_from_target_object)
        ),
        arm,
        &invoke_reply_addressed_from_target_object_body,
    );
}

/// Cross-impl arm: a libubox-built sender (via `libubox-sys` →
/// `ubus_invoke`) drives our `UbusObject` server through both broker
/// implementations. The existing `register_object_and_invoke_round_trip`
/// matrix uses our codec on both ends, so the libubox-shaped
/// `UBUS_ATTR_DATA` bytes never touch the wire there — this case
/// exercises that gap across the broker dimension.
///
/// Pinned regression: when `UBUS_ATTR_DATA` carries the inner contents
/// of a blobmsg (libubox `blob_data(msg)` / `blob_len(msg)`) rather
/// than a wrapped TABLE attr, the dispatcher must accept it. A
/// previous version of `dispatch_invoke` insisted on a TABLE wrapper
/// and rejected `ubus call` / LuCI rpcd traffic with `INVOKE Data
/// outer attr is not TABLE` / `INVOKE Data attr missing wrapper`.
#[cfg(target_os = "linux")]
fn libubox_caller_invokes_our_server_body(path: &str) {
    use ubus_testkit::LibuboxClient;

    let path = path.to_owned();

    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example.test").method("ping", |_args| {
            Ok(BlobMsgTable::build(|bb| {
                bb.put_str(Some("pong"), "yes");
            }))
        })
    });
    owner.wait_ready();

    let Some(mut caller) =
        LibuboxClient::connect(std::path::Path::new(&path)).expect("libubox client connect")
    else {
        // libubox-sys built without `.dep/bin/` artifacts — visible
        // skip so a fresh clone (before `tools/ubusd-builder/build.sh`)
        // still reports `ok` on this case rather than failing for an
        // infra-missing reason.
        skip::or_skip(
            "ubusd_handshake libubox_caller_invokes_our_server",
            "libubox FFI artifacts not reachable",
        );
        owner.shutdown();
        return;
    };

    let reply = caller
        .invoke("example.test", "ping")
        .expect("libubox invoke");

    // Reply bytes are libubox's `blob_data(msg)` — the inner contents
    // of the top-level reply blob_attr. Look for the `pong` blobmsg
    // string attr inside.
    let pong = blobmsg_lookup(&reply, "pong")
        .expect("pong attribute present in libubox reply")
        .as_str();
    assert_eq!(pong, Some("yes"));

    owner.shutdown();
}

#[cfg(target_os = "linux")]
#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn libubox_caller_invokes_our_server(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(libubox_caller_invokes_our_server)
        ),
        arm,
        &libubox_caller_invokes_our_server_body,
    );
}

#[cfg(target_os = "linux")]
fn libubox_caller_args_round_trip_body(path: &str) {
    use ubus_testkit::LibuboxClient;

    let path = path.to_owned();

    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example.test").method("echo", |args| {
            let echoed = blobmsg_lookup(args, "key")
                .and_then(|a| a.as_str())
                .unwrap_or("__missing__")
                .to_owned();
            Ok(BlobMsgTable::build(|bb| {
                bb.put_str(Some("key"), &echoed);
            }))
        })
    });
    owner.wait_ready();

    let Some(mut caller) =
        LibuboxClient::connect(std::path::Path::new(&path)).expect("libubox client connect")
    else {
        // libubox-sys built without `.dep/bin/` artifacts — visible
        // skip so a fresh clone (before `tools/ubusd-builder/build.sh`)
        // still reports `ok` on this case rather than failing for an
        // infra-missing reason.
        skip::or_skip(
            "ubusd_handshake libubox_caller_args_round_trip",
            "libubox FFI artifacts not reachable",
        );
        owner.shutdown();
        return;
    };

    let reply = caller
        .invoke_with_args("example.test", "echo", &[("key", "val")])
        .expect("libubox invoke with args");
    let echoed = blobmsg_lookup(&reply, "key")
        .expect("echoed key present in libubox reply")
        .as_str();
    assert_eq!(echoed, Some("val"));

    owner.shutdown();
}

#[cfg(target_os = "linux")]
#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn libubox_caller_args_round_trip(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(libubox_caller_args_round_trip)
        ),
        arm,
        &libubox_caller_args_round_trip_body,
    );
}

#[cfg(target_os = "linux")]
fn libubox_host_or_skip(path: &str, scenario: &str) -> Option<ubus_testkit::LibuboxHost> {
    match ubus_testkit::LibuboxHost::connect(std::path::Path::new(path))
        .expect("libubox host connect")
    {
        Some(host) => Some(host),
        None => {
            skip::or_skip(scenario, "libubox FFI artifacts not reachable");
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn assert_libubox_broker_notify_ack(
    frame: &Frame,
    seq: u16,
    publisher_obj: u32,
    subscribers: &[u32],
    what: &str,
) {
    assert_eq!(frame.hdr.ty, MsgType::Status, "{what} type");
    assert_eq!(frame.hdr.seq, seq, "{what} seq");
    assert_eq!(frame.hdr.peer, 0, "{what} hdr.peer");
    expect_attr_sequence(
        &frame.payload,
        &[UbusAttr::ObjId, UbusAttr::Subscribers, UbusAttr::Status],
        what,
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32()),
        Some(publisher_obj),
        "{what} ObjId"
    );
    assert_eq!(
        subscriber_ids(&frame.payload),
        subscribers,
        "{what} Subscribers"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Status)
            .and_then(|attr| attr.as_u32())
            .map(|status| status as i32),
        Some(UBUS_STATUS_OK),
        "{what} Status"
    );
}

#[cfg(target_os = "linux")]
fn libubox_server_answers_intree_invoke_body(path: &str) {
    let Some(host) =
        libubox_host_or_skip(path, "ubusd_handshake libubox_server_answers_intree_invoke")
    else {
        return;
    };
    let _object = host
        .add_object("lx.srv", &["ping", "echo"], |method, args| match method {
            "ping" => (
                UBUS_STATUS_OK,
                Some(
                    BlobMsgTable::build(|builder| {
                        builder.put_str(Some("pong"), "libubox");
                    })
                    .contents()
                    .to_vec(),
                ),
            ),
            "echo" => (UBUS_STATUS_OK, Some(args.to_vec())),
            other => panic!("unexpected libubox method {other}"),
        })
        .expect("add libubox server object");

    {
        let transport = UnixUbusTransport::connect(path).expect("in-tree client connect");
        let mut client = UbusClient::connect(transport).expect("in-tree client hello");
        let object = client.lookup("lx.srv").expect("lookup libubox server");
        let ping = client
            .invoke(object, "ping", &BlobMsgTable::empty())
            .expect("invoke ping");
        assert_eq!(
            blobmsg_lookup(&ping, "pong").and_then(|attr| attr.as_str()),
            Some("libubox")
        );

        let args = BlobMsgTable::build(|builder| builder.put_str(Some("k"), "v"));
        let echo = client.invoke(object, "echo", &args).expect("invoke echo");
        assert_eq!(
            blobmsg_lookup(&echo, "k").and_then(|attr| attr.as_str()),
            Some("v"),
            "libubox echo must return the original blobmsg contents"
        );
    }
    host.shutdown().expect("libubox host shutdown");
}

#[cfg(target_os = "linux")]
fn libubox_server_maps_handler_status_and_unknown_method_body(path: &str) {
    let Some(host) = libubox_host_or_skip(
        path,
        "ubusd_handshake libubox_server_maps_handler_status_and_unknown_method",
    ) else {
        return;
    };
    let _object = host
        .add_object("lx.status", &["grumpy"], |_method, _args| {
            (UBUS_STATUS_PERMISSION_DENIED, None)
        })
        .expect("add libubox status object");

    {
        let transport = UnixUbusTransport::connect(path).expect("in-tree client connect");
        let mut client = UbusClient::connect(transport).expect("in-tree client hello");
        let object = client.lookup("lx.status").expect("lookup libubox server");
        assert!(matches!(
            client.invoke(object, "grumpy", &BlobMsgTable::empty()),
            Err(UbusError::Status(UBUS_STATUS_PERMISSION_DENIED))
        ));
        assert!(matches!(
            client.invoke(object, "nosuch", &BlobMsgTable::empty()),
            Err(UbusError::Status(3))
        ));
    }
    host.shutdown().expect("libubox host shutdown");
}

#[cfg(target_os = "linux")]
fn libubox_server_deferred_reply_completes_after_gap_body(path: &str) {
    use ubus_testkit::DeferChoice;

    let Some(host) = libubox_host_or_skip(
        path,
        "ubusd_handshake libubox_server_deferred_reply_completes_after_gap",
    ) else {
        return;
    };
    let (_object, deferred_rx) = host
        .add_object_deferring("lx.defer", &["slow"], |_method, _args| DeferChoice::Defer)
        .expect("add deferred libubox object");

    let caller_path = path.to_owned();
    let caller = std::thread::spawn(move || {
        let transport = UnixUbusTransport::connect(&caller_path).expect("deferred caller connect");
        let mut client = UbusClient::connect(transport).expect("deferred caller hello");
        let object = client.lookup("lx.defer").expect("lookup deferred object");
        client.invoke(object, "slow", &BlobMsgTable::empty())
    });
    let token = deferred_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("deferred request token");
    std::thread::sleep(Duration::from_millis(100));
    host.complete_deferred(
        token,
        UBUS_STATUS_OK,
        Some(
            BlobMsgTable::build(|builder| {
                builder.put_str(Some("late"), "yes");
            })
            .contents()
            .to_vec(),
        ),
    )
    .expect("complete deferred reply");
    let reply = caller
        .join()
        .expect("deferred caller thread panicked")
        .expect("deferred invoke reply");
    assert_eq!(
        blobmsg_lookup(&reply, "late").and_then(|attr| attr.as_str()),
        Some("yes")
    );
    host.shutdown().expect("libubox host shutdown");
}

#[cfg(target_os = "linux")]
fn libubox_subscriber_receives_intree_notify_body(path: &str) {
    let Some(host) = libubox_host_or_skip(
        path,
        "ubusd_handshake libubox_subscriber_receives_intree_notify",
    ) else {
        return;
    };
    let mut publisher = raw_connection(path);
    let publisher_obj =
        raw_add_object_with_signature(&mut publisher, 800, "lx.pub", &signature_with_ping_method())
            .0;
    let (notify_tx, notify_rx) = std::sync::mpsc::channel();
    let subscriber = host
        .register_subscriber(
            move |method, args| {
                notify_tx
                    .send((method.to_owned(), args.to_vec()))
                    .expect("notify callback channel");
                UBUS_STATUS_OK
            },
            |_removed| {},
        )
        .expect("register libubox subscriber");
    host.subscribe(&subscriber, publisher_obj)
        .expect("libubox subscribe");
    let active = recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Notify
            && find(&frame.payload, UbusAttr::Active).map(|attr| attr.payload) == Some(&[1][..])
    })
    .expect("publisher Active=1");
    assert_active_notify(
        &active,
        active.hdr.seq,
        publisher_obj,
        1,
        "libubox subscribe Active=1",
    );

    let data = BlobMsgTable::build(|builder| builder.put_str(Some("k"), "v"));
    let mut notify = EnvBuilder::new();
    notify.push_u32(UbusAttr::ObjId, publisher_obj);
    notify.push_str(UbusAttr::Method, "changed");
    notify.push_data(data.contents());
    publisher
        .send(&Frame::to_peer(
            MsgType::Notify,
            801,
            // hdr.peer 0: the broker ack echoes the request peer, and the
            // scenario tells the two acks apart by peer==0 (broker) vs
            // peer==subscriber-obj (forwarded subscriber ack).
            0,
            notify.finish(),
        ))
        .expect("send intree NOTIFY");

    let broker_ack = recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Status && frame.hdr.seq == 801 && frame.hdr.peer == 0
    })
    .expect("NOTIFY broker ack");
    let subscriber_ack = recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Status && frame.hdr.seq == 801 && frame.hdr.peer != 0
    })
    .expect("NOTIFY subscriber ack");
    let subscriber_obj = subscriber_ack.hdr.peer;
    assert_libubox_broker_notify_ack(
        &broker_ack,
        801,
        publisher_obj,
        &[subscriber_obj],
        "libubox subscriber broker ack",
    );
    expect_attr_sequence(
        &subscriber_ack.payload,
        &[UbusAttr::Status, UbusAttr::ObjId],
        "libubox subscriber forwarded ack",
    );
    assert_eq!(
        find(&subscriber_ack.payload, UbusAttr::Status)
            .and_then(|attr| attr.as_u32())
            .map(|status| status as i32),
        Some(UBUS_STATUS_OK)
    );
    assert_eq!(
        find(&subscriber_ack.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32()),
        Some(subscriber_obj)
    );
    let (method, args) = notify_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("libubox notify callback");
    assert_eq!(method, "changed");
    assert_eq!(
        blobmsg_lookup(&args, "k").and_then(|attr| attr.as_str()),
        Some("v")
    );

    host.unsubscribe(&subscriber, publisher_obj)
        .expect("libubox unsubscribe");
    let inactive = recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Notify
            && find(&frame.payload, UbusAttr::Active).map(|attr| attr.payload) == Some(&[0][..])
    })
    .expect("publisher Active=0");
    assert_active_notify(
        &inactive,
        inactive.hdr.seq,
        publisher_obj,
        0,
        "libubox unsubscribe Active=0",
    );
    drop(publisher);
    host.shutdown().expect("libubox host shutdown");
}

#[cfg(target_os = "linux")]
fn libubox_subscriber_unsubscribe_halts_fanout_body(path: &str) {
    let Some(host) = libubox_host_or_skip(
        path,
        "ubusd_handshake libubox_subscriber_unsubscribe_halts_fanout",
    ) else {
        return;
    };
    let mut publisher = raw_connection(path);
    let publisher_obj = raw_add_object_with_signature(
        &mut publisher,
        810,
        "lx.pub.stop",
        &signature_with_ping_method(),
    )
    .0;
    let (notify_tx, notify_rx) = std::sync::mpsc::channel();
    let subscriber = host
        .register_subscriber(
            move |method, args| {
                notify_tx
                    .send((method.to_owned(), args.to_vec()))
                    .expect("notify callback channel");
                UBUS_STATUS_OK
            },
            |_removed| {},
        )
        .expect("register libubox subscriber");
    host.subscribe(&subscriber, publisher_obj)
        .expect("libubox subscribe");
    recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Notify
            && find(&frame.payload, UbusAttr::Active).map(|attr| attr.payload) == Some(&[1][..])
    })
    .expect("publisher Active=1");

    // Real libubus rejects any inbound invoke without a DATA attr
    // (ubus_process_invoke: INVALID_ARGUMENT before the handler runs), so
    // fan-outs to a libubus subscriber must carry at least an empty table —
    // exactly what ubus_notify itself always attaches.
    let empty = BlobMsgTable::empty();
    let mut first = EnvBuilder::new();
    first.push_u32(UbusAttr::ObjId, publisher_obj);
    first.push_str(UbusAttr::Method, "first");
    first.push_data(empty.contents());
    publisher
        .send(&Frame::to_peer(
            MsgType::Notify,
            811,
            // hdr.peer 0: the broker ack echoes the request peer, and the
            // scenario tells the two acks apart by peer==0 (broker) vs
            // peer==subscriber-obj (forwarded subscriber ack).
            0,
            first.finish(),
        ))
        .expect("send first NOTIFY");
    let _broker_ack = recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Status && frame.hdr.seq == 811 && frame.hdr.peer == 0
    })
    .expect("first NOTIFY broker ack");
    recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Status && frame.hdr.seq == 811 && frame.hdr.peer != 0
    })
    .expect("first NOTIFY subscriber ack");
    let (method, _args) = notify_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("first notify callback");
    assert_eq!(method, "first");

    host.unsubscribe(&subscriber, publisher_obj)
        .expect("libubox unsubscribe");
    recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Notify
            && find(&frame.payload, UbusAttr::Active).map(|attr| attr.payload) == Some(&[0][..])
    })
    .expect("publisher Active=0");
    let mut second = EnvBuilder::new();
    second.push_u32(UbusAttr::ObjId, publisher_obj);
    second.push_str(UbusAttr::Method, "second");
    second.push_data(empty.contents());
    publisher
        .send(&Frame::to_peer(
            MsgType::Notify,
            812,
            // hdr.peer 0: the broker ack echoes the request peer, and the
            // scenario tells the two acks apart by peer==0 (broker) vs
            // peer==subscriber-obj (forwarded subscriber ack).
            0,
            second.finish(),
        ))
        .expect("send second NOTIFY");
    let empty_ack = recv_until(&mut publisher, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Status && frame.hdr.seq == 812
    })
    .expect("second NOTIFY broker ack");
    assert_libubox_broker_notify_ack(
        &empty_ack,
        812,
        publisher_obj,
        &[],
        "post-unsubscribe NOTIFY broker ack",
    );
    assert!(matches!(
        notify_rx.recv_timeout(Duration::from_millis(300)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    drop(publisher);
    host.shutdown().expect("libubox host shutdown");
}

#[cfg(target_os = "linux")]
fn libubox_publisher_notify_acks_from_intree_subscriber_body(path: &str) {
    let Some(host) = libubox_host_or_skip(
        path,
        "ubusd_handshake libubox_publisher_notify_acks_from_intree_subscriber",
    ) else {
        return;
    };
    let publisher = host
        .add_object("lx.pub2", &["noop"], |_method, _args| {
            (UBUS_STATUS_OK, None)
        })
        .expect("add libubox publisher");
    let publisher_obj = publisher.id();
    let mut subscriber = raw_connection(path);
    let subscriber_obj = raw_add_anonymous(&mut subscriber, 820);
    let mut subscribe = EnvBuilder::new();
    subscribe.push_u32(UbusAttr::ObjId, subscriber_obj);
    subscribe.push_u32(UbusAttr::Target, publisher_obj);
    subscriber
        .send(&Frame::to_peer(
            MsgType::Subscribe,
            821,
            0,
            subscribe.finish(),
        ))
        .expect("subscribe in-tree subscriber");
    recv_until(&mut subscriber, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Status && frame.hdr.seq == 821
    })
    .expect("SUBSCRIBE status");

    let (fanout_tx, fanout_rx) = std::sync::mpsc::channel();
    let (unsubscribe_tx, unsubscribe_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || -> Result<(), String> {
        let fanout = recv_until(&mut subscriber, Duration::from_secs(5), |frame| {
            frame.hdr.ty == MsgType::Invoke
        })
        .map_err(|err| format!("fanout: {err}"))?;
        fanout_tx
            .send(fanout.clone())
            .map_err(|_| "fanout tx".to_owned())?;
        let mut ack = EnvBuilder::new();
        ack.push_u32(UbusAttr::ObjId, subscriber_obj);
        ack.push_i32(UbusAttr::Status, UBUS_STATUS_OK);
        subscriber
            .send(&Frame::to_peer(
                MsgType::Status,
                fanout.hdr.seq,
                fanout.hdr.peer,
                ack.finish(),
            ))
            .map_err(|err| format!("subscriber ack: {err:?}"))?;
        unsubscribe_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "unsubscribe signal".to_owned())?;
        let mut unsubscribe = EnvBuilder::new();
        unsubscribe.push_u32(UbusAttr::ObjId, subscriber_obj);
        unsubscribe.push_u32(UbusAttr::Target, publisher_obj);
        subscriber
            .send(&Frame::to_peer(
                MsgType::Unsubscribe,
                822,
                0,
                unsubscribe.finish(),
            ))
            .map_err(|err| format!("UNSUBSCRIBE: {err:?}"))?;
        recv_until(&mut subscriber, Duration::from_secs(5), |frame| {
            frame.hdr.ty == MsgType::Status && frame.hdr.seq == 822
        })
        .map_err(|err| format!("UNSUBSCRIBE status: {err}"))?;
        Ok(())
    });

    assert_eq!(
        host.notify(&publisher, "state", &[("s", "1")], 2000)
            .expect("libubox acknowledged notify"),
        UBUS_STATUS_OK
    );
    let fanout = fanout_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("in-tree subscriber fanout");
    expect_attr_sequence(
        &fanout.payload,
        &[
            UbusAttr::ObjId,
            UbusAttr::Method,
            UbusAttr::User,
            UbusAttr::Group,
            UbusAttr::Data,
        ],
        "acked libubox notify fanout",
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32()),
        Some(subscriber_obj)
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::Method).and_then(|attr| attr.as_str()),
        Some("state")
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::Data)
            .and_then(|attr| blobmsg_lookup(attr.payload, "s"))
            .and_then(|attr| attr.as_str()),
        Some("1")
    );
    unsubscribe_tx.send(()).expect("unsubscribe signal");
    join_owner(worker);
    host.shutdown().expect("libubox host shutdown");
}

#[cfg(target_os = "linux")]
fn libubox_publisher_notify_without_replies_stamps_no_reply_body(path: &str) {
    let Some(host) = libubox_host_or_skip(
        path,
        "ubusd_handshake libubox_publisher_notify_without_replies_stamps_no_reply",
    ) else {
        return;
    };
    let publisher = host
        .add_object("lx.pub3", &["noop"], |_method, _args| {
            (UBUS_STATUS_OK, None)
        })
        .expect("add libubox publisher");
    let publisher_obj = publisher.id();
    let mut subscriber = raw_connection(path);
    let subscriber_obj = raw_add_anonymous(&mut subscriber, 830);
    let mut subscribe = EnvBuilder::new();
    subscribe.push_u32(UbusAttr::ObjId, subscriber_obj);
    subscribe.push_u32(UbusAttr::Target, publisher_obj);
    subscriber
        .send(&Frame::to_peer(
            MsgType::Subscribe,
            831,
            0,
            subscribe.finish(),
        ))
        .expect("subscribe in-tree subscriber");
    recv_until(&mut subscriber, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Status && frame.hdr.seq == 831
    })
    .expect("SUBSCRIBE status");

    let (fanout_tx, fanout_rx) = std::sync::mpsc::channel();
    let (unsubscribe_tx, unsubscribe_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || -> Result<(), String> {
        let fanout = recv_until(&mut subscriber, Duration::from_secs(5), |frame| {
            frame.hdr.ty == MsgType::Invoke
        })
        .map_err(|err| format!("fanout: {err}"))?;
        fanout_tx.send(fanout).map_err(|_| "fanout tx".to_owned())?;
        unsubscribe_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "unsubscribe signal".to_owned())?;
        let mut unsubscribe = EnvBuilder::new();
        unsubscribe.push_u32(UbusAttr::ObjId, subscriber_obj);
        unsubscribe.push_u32(UbusAttr::Target, publisher_obj);
        subscriber
            .send(&Frame::to_peer(
                MsgType::Unsubscribe,
                832,
                0,
                unsubscribe.finish(),
            ))
            .map_err(|err| format!("UNSUBSCRIBE: {err:?}"))?;
        recv_until(&mut subscriber, Duration::from_secs(5), |frame| {
            frame.hdr.ty == MsgType::Status && frame.hdr.seq == 832
        })
        .map_err(|err| format!("UNSUBSCRIBE status: {err}"))?;
        Ok(())
    });

    assert_eq!(
        host.notify(&publisher, "state", &[("s", "1")], -1)
            .expect("libubox no-reply notify"),
        UBUS_STATUS_OK
    );
    let fanout = fanout_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("in-tree subscriber fanout");
    expect_attr_sequence(
        &fanout.payload,
        &[
            UbusAttr::NoReply,
            UbusAttr::ObjId,
            UbusAttr::Method,
            UbusAttr::User,
            UbusAttr::Group,
            UbusAttr::Data,
        ],
        "no-reply libubox notify fanout",
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::NoReply).map(|attr| attr.payload),
        Some(&[1][..])
    );
    unsubscribe_tx.send(()).expect("unsubscribe signal");
    join_owner(worker);
    host.shutdown().expect("libubox host shutdown");
}

#[cfg(target_os = "linux")]
fn libubox_event_listener_receives_intree_send_body(path: &str) {
    let Some(host) = libubox_host_or_skip(
        path,
        "ubusd_handshake libubox_event_listener_receives_intree_send",
    ) else {
        return;
    };
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let handler = host
        .register_event_handler("lx.ev.*", move |event, args| {
            event_tx
                .send((event.to_owned(), args.to_vec()))
                .expect("event callback channel");
        })
        .expect("register libubox event handler");
    let mut sender = raw_connection(path);
    let data = BlobMsgTable::build(|builder| {
        builder.put_str(Some("id"), "lx.ev.one");
        builder.open_table(Some("data"));
        builder.put_str(Some("x"), "y");
        builder.close_table();
    });
    let mut invoke = EnvBuilder::new();
    invoke.push_u32(UbusAttr::ObjId, EVENT_OBJECT_ID);
    invoke.push_str(UbusAttr::Method, "send");
    invoke.push_data(data.contents());
    send_and_expect_status(
        &mut sender,
        MsgType::Invoke,
        840,
        EVENT_OBJECT_ID,
        invoke.finish(),
        UBUS_STATUS_OK,
    );
    let (event, args) = event_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("libubox event callback");
    assert_eq!(event, "lx.ev.one");
    assert_eq!(
        blobmsg_lookup(&args, "x").and_then(|attr| attr.as_str()),
        Some("y")
    );
    drop(sender);
    host.unregister_event_handler(handler)
        .expect("unregister libubox event handler");
    host.shutdown().expect("libubox host shutdown");
}

#[cfg(target_os = "linux")]
fn libubox_event_send_reaches_intree_listener_body(path: &str) {
    let Some(host) = libubox_host_or_skip(
        path,
        "ubusd_handshake libubox_event_send_reaches_intree_listener",
    ) else {
        return;
    };
    let mut listener = raw_connection(path);
    let listener_obj = raw_add_anonymous(&mut listener, 850);
    raw_event_register(&mut listener, 851, listener_obj, "lx.rev.*");
    assert_eq!(
        host.send_event("lx.rev.hit", &[("z", "1")])
            .expect("libubox send event"),
        UBUS_STATUS_OK
    );
    let fanout = recv_until(&mut listener, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Invoke
            && find(&frame.payload, UbusAttr::Method).and_then(|attr| attr.as_str())
                == Some("lx.rev.hit")
    })
    .expect("in-tree event listener fanout");
    assert_eq!(fanout.hdr.peer, 0, "event fanout hdr.peer");
    expect_attr_sequence(
        &fanout.payload,
        &[UbusAttr::ObjId, UbusAttr::Method, UbusAttr::Data],
        "libubox event fanout",
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32()),
        Some(listener_obj)
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::Data)
            .and_then(|attr| blobmsg_lookup(attr.payload, "z"))
            .and_then(|attr| attr.as_str()),
        Some("1")
    );
    drop(listener);
    host.shutdown().expect("libubox host shutdown");
}

macro_rules! libubox_host_matrix_scenario {
    ($name:ident, $body:ident) => {
        #[cfg(target_os = "linux")]
        #[rstest]
        #[case::upstream(MatrixArm::Upstream)]
        #[case::rs(MatrixArm::Rs)]
        #[case::parity(MatrixArm::Parity)]
        #[case::golden(MatrixArm::Golden)]
        fn $name(#[case] arm: MatrixArm) {
            run_matrix_case(concat!("ubusd_handshake ", stringify!($name)), arm, &$body);
        }
    };
}

libubox_host_matrix_scenario!(
    libubox_server_answers_intree_invoke,
    libubox_server_answers_intree_invoke_body
);
libubox_host_matrix_scenario!(
    libubox_server_maps_handler_status_and_unknown_method,
    libubox_server_maps_handler_status_and_unknown_method_body
);
libubox_host_matrix_scenario!(
    libubox_server_deferred_reply_completes_after_gap,
    libubox_server_deferred_reply_completes_after_gap_body
);
libubox_host_matrix_scenario!(
    libubox_subscriber_receives_intree_notify,
    libubox_subscriber_receives_intree_notify_body
);
libubox_host_matrix_scenario!(
    libubox_subscriber_unsubscribe_halts_fanout,
    libubox_subscriber_unsubscribe_halts_fanout_body
);
libubox_host_matrix_scenario!(
    libubox_publisher_notify_acks_from_intree_subscriber,
    libubox_publisher_notify_acks_from_intree_subscriber_body
);
libubox_host_matrix_scenario!(
    libubox_publisher_notify_without_replies_stamps_no_reply,
    libubox_publisher_notify_without_replies_stamps_no_reply_body
);
libubox_host_matrix_scenario!(
    libubox_event_listener_receives_intree_send,
    libubox_event_listener_receives_intree_send_body
);
libubox_host_matrix_scenario!(
    libubox_event_send_reaches_intree_listener,
    libubox_event_send_reaches_intree_listener_body
);

fn subscribe_then_notify_body(path: &str) {
    let path = path.to_owned();

    let (id_tx, id_rx) = std::sync::mpsc::channel::<(u32, u32)>();
    let (subscribed_tx, subscribed_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let path_owner = path.clone();
    let owner = JoinOnDrop::new(std::thread::spawn(move || -> Result<(), String> {
        let transport =
            UnixUbusTransport::connect(&path_owner).map_err(|e| format!("owner connect: {e:?}"))?;
        let object = UbusObject::new("example.events")
            .method("noop", |_args| Ok(BlobMsgTable::build(|_| {})));
        let mut conn = UbusConnection::connect_and_register(transport, object)
            .map_err(|e| format!("register: {e:?}"))?;
        let obj_id = conn.object_id();
        let peer_id = conn
            .peer_id()
            .ok_or_else(|| "owner peer id missing".to_string())?;
        id_tx
            .send((obj_id, peer_id))
            .map_err(|_| "id tx".to_string())?;

        match subscribed_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => {}
            Err(_) => return Err("owner: subscriber-ready signal timeout".to_string()),
        }
        // NOTIFY shares upstream's INVOKE handler: ATTR_OBJID names the
        // publisher, ATTR_METHOD survives fan-out as the event name.
        let mut notify_env = EnvBuilder::new();
        notify_env.push_u32(UbusAttr::ObjId, obj_id);
        notify_env.push_str(UbusAttr::Method, "fanout");
        conn.transport_mut()
            .send(&Frame::to_peer(
                MsgType::Notify,
                1000,
                obj_id,
                notify_env.finish(),
            ))
            .map_err(|e| format!("notify: {e:?}"))?;
        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err("owner: done signal timeout".to_string())
            }
        }
    }));

    let (obj_id, publisher_peer_id) = id_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("owner reported obj_id");
    assert_ne!(obj_id, 0, "broker should assign a non-zero obj_id");

    // Upstream requires the subscriber to itself be a registered object.
    let sub_transport = UnixUbusTransport::connect(&path).expect("subscriber connect");
    let sub_object = UbusObject::new("example.events.subscriber")
        .method("noop", |_args| Ok(BlobMsgTable::build(|_| {})));
    let mut sub_conn = UbusConnection::connect_and_register(sub_transport, sub_object)
        .expect("subscriber register");
    let sub_obj_id = sub_conn.object_id();
    let sub = sub_conn.transport_mut();

    // SUBSCRIBE shape valid against both brokers: upstream reads only
    // the envelope (ATTR_OBJID = caller, ATTR_TARGET = publisher);
    // in-tree `ubusd` resolves the target via `hdr.peer` first, so
    // setting it to the publisher's obj_id keeps both happy.
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, sub_obj_id);
    env.push_u32(UbusAttr::Target, obj_id);
    sub.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Subscribe,
            seq: 11,
            peer: obj_id,
        },
        payload: env.finish(),
    })
    .expect("subscribe");
    let ack = recv_until(sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 11
    })
    .expect("subscribe ack");
    let ack_status = find(&ack.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("SUBSCRIBE ack must carry STATUS attr");
    assert_eq!(ack_status, 0, "SUBSCRIBE rejected: status={ack_status}");
    subscribed_tx.send(()).expect("subscribed signal");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut notify_frame = None;
    while Instant::now() < deadline {
        match sub.recv() {
            Ok(Some(f)) if f.hdr.ty == MsgType::Invoke => {
                notify_frame = Some(f);
                break;
            }
            Ok(Some(f)) => {
                assert!(
                    !matches!(f.hdr.ty, MsgType::Notify | MsgType::Invoke),
                    "fan-out arrived with unexpected MsgType {:?} (expected Invoke)",
                    f.hdr.ty,
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => panic!("subscriber recv: {e:?}"),
        }
    }
    let notify = notify_frame.expect("subscriber should receive the NOTIFY fan-out");
    assert_forwarded_invoke_no_data(
        &notify,
        1000,
        publisher_peer_id,
        sub_obj_id,
        "fanout",
        "NOTIFY fan-out",
    );

    let _ = done_tx.send(());
    owner.join();
    // Owner is gone; read the broker-minted Unsubscribe so the trailing
    // frame is captured deterministically on both brokers.
    recv_until(sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Unsubscribe
    })
    .expect("broker-minted Unsubscribe after publisher death");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn subscribe_then_notify_fans_out(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(subscribe_then_notify_fans_out)
        ),
        arm,
        &subscribe_then_notify_body,
    );
}

fn notify_with_data_forwards_blobmsg_last_body(path: &str) {
    let mut publisher = UnixUbusTransport::connect(path).expect("publisher connect");
    let pub_hello = recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("publisher HELLO");
    let (pub_obj, _) = raw_add_object_with_signature(
        &mut publisher,
        70,
        "example.notify.data",
        &signature_with_ping_method(),
    );

    let mut subscriber = UnixUbusTransport::connect(path).expect("subscriber connect");
    recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("subscriber HELLO");
    let sub_obj = raw_add_anonymous(&mut subscriber, 71);

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, sub_obj);
    env.push_u32(UbusAttr::Target, pub_obj);
    subscriber
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq: 72,
                peer: pub_obj,
            },
            payload: env.finish(),
        })
        .expect("subscribe");
    let ack = recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.seq == 72 && f.hdr.ty == MsgType::Status
    })
    .expect("subscribe ack");
    assert_eq!(
        find(&ack.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32),
        Some(UBUS_STATUS_OK)
    );

    let data = BlobMsgTable::build(|bb| {
        bb.put_str(Some("k"), "v");
    });
    let mut notify_env = EnvBuilder::new();
    notify_env.push_u32(UbusAttr::ObjId, pub_obj);
    notify_env.push_str(UbusAttr::Method, "fanout");
    notify_env.push_data(data.contents());
    publisher
        .send(&Frame::to_peer(
            MsgType::Notify,
            1000,
            pub_obj,
            notify_env.finish(),
        ))
        .expect("notify");

    let fanout = recv_until(&mut subscriber, Duration::from_secs(3), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("subscriber fan-out");
    assert_forwarded_invoke_with_data(
        &fanout,
        1000,
        pub_hello.hdr.peer,
        sub_obj,
        "fanout",
        data.contents(),
        "NOTIFY with data fan-out",
    );

    // Deterministic teardown: publisher closes first; subscriber reads
    // the broker-minted Unsubscribe so both transcripts capture it.
    drop(publisher);
    let unsub = recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Unsubscribe
    })
    .expect("broker-minted Unsubscribe after publisher death");
    assert_eq!(
        find(&unsub.payload, UbusAttr::Target).and_then(|a| a.as_u32()),
        Some(pub_obj),
        "Unsubscribe Target must be the dead publisher object"
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn notify_with_data_forwards_blobmsg_last(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(notify_with_data_forwards_blobmsg_last)
        ),
        arm,
        &notify_with_data_forwards_blobmsg_last_body,
    );
}

fn event_register_and_send_fans_out_body(path: &str) {
    // Listener registers an anonymous object then a catch-all pattern.
    let mut listener = UnixUbusTransport::connect(path).expect("listener connect");
    recv_until(&mut listener, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("listener HELLO");
    let listener_obj = raw_add_anonymous(&mut listener, 300);
    raw_event_register(&mut listener, 301, listener_obj, "*");

    // Separate publisher (so self-suppression doesn't hide the event).
    let mut publisher = UnixUbusTransport::connect(path).expect("publisher connect");
    recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("publisher HELLO");
    raw_event_send(&mut publisher, 302, "example.probe.event", 7);

    let fanout = recv_until(&mut listener, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("event fan-out");
    assert_event_fanout(
        &fanout,
        1,
        listener_obj,
        "example.probe.event",
        "send fan-out",
    );
    let data = find(&fanout.payload, UbusAttr::Data)
        .map(|a| a.payload)
        .unwrap_or(&[]);
    assert_eq!(
        blobmsg_lookup(data, "value").and_then(|r| r.as_i32()),
        Some(7),
        "fan-out Data carries the inner data table"
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn event_register_and_send_fans_out(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(event_register_and_send_fans_out)
        ),
        arm,
        &event_register_and_send_fans_out_body,
    );
}

fn event_prefix_pattern_filters_listeners_body(path: &str) {
    // Catch-all listener (pattern key "") and a "example." prefix
    // listener. Upstream walks its pattern AVL in key order, so ""
    // (catch-all) is always delivered before "example.".
    let mut all = UnixUbusTransport::connect(path).expect("catch-all connect");
    recv_until(&mut all, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("catch-all HELLO");
    let all_obj = raw_add_anonymous(&mut all, 310);
    raw_event_register(&mut all, 311, all_obj, "*");

    let mut prefix = UnixUbusTransport::connect(path).expect("prefix connect");
    recv_until(&mut prefix, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("prefix HELLO");
    let prefix_obj = raw_add_anonymous(&mut prefix, 312);
    raw_event_register(&mut prefix, 313, prefix_obj, "example.*");

    let mut publisher = UnixUbusTransport::connect(path).expect("publisher connect");
    recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("publisher HELLO");

    // Matching event: both listeners; catch-all seq 1, prefix seq 2.
    raw_event_send(&mut publisher, 314, "example.probe.event", 7);
    let all_first = recv_until(&mut all, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("catch-all fan-out 1");
    assert_event_fanout(&all_first, 1, all_obj, "example.probe.event", "catch-all 1");
    let prefix_first = recv_until(&mut prefix, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("prefix fan-out 1");
    assert_event_fanout(
        &prefix_first,
        2,
        prefix_obj,
        "example.probe.event",
        "prefix 1",
    );

    // Non-matching-for-prefix event: only the catch-all receives it, and
    // the global counter continues at 3. The prefix listener's stream
    // must NOT contain this event — enforced by the transcript byte-diff.
    raw_event_send(&mut publisher, 315, "other.event", 9);
    let all_second = recv_until(&mut all, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("catch-all fan-out 2");
    assert_event_fanout(&all_second, 3, all_obj, "other.event", "catch-all 2");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn event_prefix_pattern_filters_listeners(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(event_prefix_pattern_filters_listeners)
        ),
        arm,
        &event_prefix_pattern_filters_listeners_body,
    );
}

fn event_send_without_listeners_acks_status_ok_body(path: &str) {
    let mut publisher = UnixUbusTransport::connect(path).expect("publisher connect");
    recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("publisher HELLO");
    // No listeners registered: the send still acks STATUS(0) and fans
    // out to nobody. `raw_event_send` asserts the STATUS(0) ack.
    raw_event_send(&mut publisher, 320, "example.orphan.event", 5);
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn event_send_without_listeners_acks_status_ok(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(event_send_without_listeners_acks_status_ok)
        ),
        arm,
        &event_send_without_listeners_acks_status_ok_body,
    );
}

fn object_add_remove_broadcasts_on_register_and_remove_body(path: &str) {
    let mut listener = UnixUbusTransport::connect(path).expect("listener connect");
    recv_until(&mut listener, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("listener HELLO");
    let listener_obj = raw_add_anonymous(&mut listener, 330);
    raw_event_register(&mut listener, 331, listener_obj, "ubus.object.*");

    let mut owner = UnixUbusTransport::connect(path).expect("owner connect");
    recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("owner HELLO");
    let (obj_id, _) = raw_add_object_with_signature(
        &mut owner,
        332,
        "example.svc",
        &signature_with_ping_method(),
    );

    // Registration broadcasts ubus.object.add (global seq 1).
    let add = recv_until(&mut listener, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("ubus.object.add");
    assert_event_fanout(&add, 1, listener_obj, "ubus.object.add", "object.add");
    assert_object_event_payload(&add, obj_id, "example.svc", "object.add");

    // Explicit REMOVE_OBJECT broadcasts ubus.object.remove (global seq 2).
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj_id);
    owner
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 333,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send REMOVE_OBJECT");
    recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.seq == 333 && f.hdr.ty == MsgType::Status
    })
    .expect("REMOVE_OBJECT STATUS");

    let remove = recv_until(&mut listener, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("ubus.object.remove");
    assert_event_fanout(
        &remove,
        2,
        listener_obj,
        "ubus.object.remove",
        "object.remove",
    );
    assert_object_event_payload(&remove, obj_id, "example.svc", "object.remove");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn object_add_remove_broadcasts_on_register_and_remove(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(object_add_remove_broadcasts_on_register_and_remove)
        ),
        arm,
        &object_add_remove_broadcasts_on_register_and_remove_body,
    );
}

fn object_remove_broadcasts_on_owner_disconnect_body(path: &str) {
    let mut listener = UnixUbusTransport::connect(path).expect("listener connect");
    recv_until(&mut listener, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("listener HELLO");
    let listener_obj = raw_add_anonymous(&mut listener, 340);
    raw_event_register(&mut listener, 341, listener_obj, "ubus.object.*");

    let gone_obj = {
        // Owner registers a named object then drops WITHOUT REMOVE.
        let mut gone = UnixUbusTransport::connect(path).expect("gone connect");
        recv_until(&mut gone, Duration::from_secs(5), |f| {
            f.hdr.ty == MsgType::Hello
        })
        .expect("gone HELLO");
        let (obj_id, _) = raw_add_object_with_signature(
            &mut gone,
            342,
            "example.gone",
            &signature_with_ping_method(),
        );

        let add = recv_until(&mut listener, Duration::from_secs(5), |f| {
            f.hdr.ty == MsgType::Invoke
        })
        .expect("ubus.object.add");
        assert_event_fanout(&add, 1, listener_obj, "ubus.object.add", "object.add");
        assert_object_event_payload(&add, obj_id, "example.gone", "object.add");
        obj_id
        // drop `gone` → disconnect reap mints ubus.object.remove
    };

    // Read the reap-minted ubus.object.remove BEFORE the listener drops,
    // so the frame doesn't race the tap's close (determinism class).
    let remove = recv_until(&mut listener, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("ubus.object.remove after owner disconnect");
    assert_event_fanout(
        &remove,
        2,
        listener_obj,
        "ubus.object.remove",
        "object.remove",
    );
    assert_object_event_payload(&remove, gone_obj, "example.gone", "object.remove");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn object_remove_broadcasts_on_owner_disconnect(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(object_remove_broadcasts_on_owner_disconnect)
        ),
        arm,
        &object_remove_broadcasts_on_owner_disconnect_body,
    );
}

fn invoke_forwarded_to_owner_carries_caller_user_group_body(path: &str) {
    let mut owner = UnixUbusTransport::connect(path).expect("owner connect");
    recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("owner HELLO");
    let (obj_id, _) = raw_add_object_with_signature(
        &mut owner,
        80,
        "example.invoke.creds",
        &signature_with_ping_method(),
    );

    let mut caller = UnixUbusTransport::connect(path).expect("caller connect");
    let caller_hello = recv_until(&mut caller, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("caller HELLO");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj_id);
    env.push_str(UbusAttr::Method, "ping");
    caller
        .send(&Frame::to_peer(MsgType::Invoke, 1000, obj_id, env.finish()))
        .expect("send INVOKE");

    let forwarded = recv_until(&mut owner, Duration::from_secs(3), |f| {
        f.hdr.ty == MsgType::Invoke && f.hdr.seq == 1000
    })
    .expect("owner forwarded INVOKE");
    assert_forwarded_invoke_no_data(
        &forwarded,
        1000,
        caller_hello.hdr.peer,
        obj_id,
        "ping",
        "forwarded INVOKE",
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn invoke_forwarded_to_owner_carries_caller_user_group(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(invoke_forwarded_to_owner_carries_caller_user_group)
        ),
        arm,
        &invoke_forwarded_to_owner_carries_caller_user_group_body,
    );
}

// Method name "ninechars" (length 9) forces the inner METHOD attr to be
// 13 bytes — the outer envelope ends up non-4-aligned, so the broker
// must consume the trailing 3-byte pad on INVOKE forward or the next
// frame's msghdr is read at the wrong offset.
fn lookup_with_non_4_aligned_method_name_body(path: &str) {
    let path = path.to_owned();

    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example.align").method("ninechars", |_args| {
            Ok(BlobMsgTable::build(|bb| {
                bb.put_i32(Some("ok"), 1);
            }))
        })
    });
    owner.wait_ready();

    let transport = UnixUbusTransport::connect(&path).expect("caller connect");
    let mut client = UbusClient::connect(transport).expect("hello");
    let obj_id = client.lookup("example.align").expect("lookup");

    assert_eq!("ninechars".len(), 9);
    let reply = client
        .invoke(obj_id, "ninechars", &BlobMsgTable::empty())
        .expect("invoke");
    let ok = blobmsg_lookup(&reply, "ok")
        .expect("ok attribute present")
        .as_i32();
    assert_eq!(ok, Some(1));

    owner.shutdown();
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn lookup_with_non_4_aligned_method_name(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(lookup_with_non_4_aligned_method_name)
        ),
        arm,
        &lookup_with_non_4_aligned_method_name_body,
    );
}

/// Both brokers MUST greet a fresh peer with an unsolicited HELLO
/// carrying `seq=0` (no request to reply to) and a `peer` id in the
/// user range (>= 1025). System ids 0–1024 are reserved; lower ids
/// would let a misbehaving peer impersonate the broker itself.
fn unsolicited_hello_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    let hello = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    assert_eq!(hello.hdr.seq, 0, "unsolicited HELLO must use seq=0");
    assert!(
        hello.hdr.peer >= 1025,
        "broker assigned peer id {} below FIRST_PEER_ID (1025)",
        hello.hdr.peer
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn broker_pushes_hello_unsolicited_with_user_range_peer_id(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(broker_pushes_hello_unsolicited_with_user_range_peer_id)
        ),
        arm,
        &unsolicited_hello_body,
    );
}

/// PING round-trip via raw frames: the broker MUST reply to PING
/// with a DATA echo, then `STATUS(0)`, both carrying the request seq.
fn raw_ping_round_trip_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    let hello = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let peer_id = hello.hdr.peer;

    // 4-byte empty envelope (not bare-header) so the broker's stream
    // decoder doesn't desync on a back-to-back frame after this one.
    let env = EnvBuilder::new().finish();
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Ping,
                seq: 7,
                peer: peer_id,
            },
            payload: env,
        })
        .expect("send PING");

    let data = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.seq == 7 && f.hdr.ty == MsgType::Data
    })
    .expect("PING DATA reply");
    assert_eq!(data.hdr.peer, peer_id, "PING DATA must echo hdr.peer");
    assert_eq!(
        data.payload,
        EnvBuilder::new().finish(),
        "PING DATA must echo the request envelope"
    );

    let status = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.seq == 7 && f.hdr.ty == MsgType::Status
    })
    .expect("PING STATUS reply");
    let s = find(&status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, 0, "PING STATUS must be 0");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn raw_ping_round_trip(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!("ubusd_handshake ", stringify!(raw_ping_round_trip)),
        arm,
        &raw_ping_round_trip_body,
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn ping_replies_empty_data_then_status(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(ping_replies_empty_data_then_status)
        ),
        arm,
        &raw_ping_round_trip_body,
    );
}

fn broker_reply_echoes_request_peer_field_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");

    let env = EnvBuilder::new().finish();
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Ping,
                seq: 9,
                peer: 0,
            },
            payload: env,
        })
        .expect("send PING with peer=0");

    let data = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.seq == 9 && f.hdr.ty == MsgType::Data
    })
    .expect("PING DATA reply");
    assert_eq!(data.hdr.peer, 0, "DATA reply must echo request hdr.peer");

    let status = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.seq == 9 && f.hdr.ty == MsgType::Status
    })
    .expect("PING STATUS reply");
    assert_eq!(status.hdr.peer, 0, "reply must echo request hdr.peer");
    let s = find(&status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, UBUS_STATUS_OK, "PING STATUS must be OK");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn broker_reply_echoes_request_peer_field(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(broker_reply_echoes_request_peer_field)
        ),
        arm,
        &broker_reply_echoes_request_peer_field_body,
    );
}

fn lookup_all_on_empty_broker_reports_ok_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");

    let env = EnvBuilder::new().finish();
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 10,
                peer: 0,
            },
            payload: env,
        })
        .expect("send list-all LOOKUP");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match transport.recv() {
            Ok(Some(f)) if f.hdr.seq == 10 && f.hdr.ty == MsgType::Data => {
                panic!("empty list-all LOOKUP must not emit DATA: {:?}", f.hdr);
            }
            Ok(Some(f)) if f.hdr.seq == 10 && f.hdr.ty == MsgType::Status => {
                assert_eq!(f.hdr.peer, 0, "reply must echo request hdr.peer");
                let s = find(&f.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .expect("STATUS attr");
                assert_eq!(s, UBUS_STATUS_OK, "empty list-all LOOKUP must report OK");
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("recv: {e:?}"),
        }
    }
    panic!("empty list-all LOOKUP STATUS timeout");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn lookup_all_on_empty_broker_reports_ok(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(lookup_all_on_empty_broker_reports_ok)
        ),
        arm,
        &lookup_all_on_empty_broker_reports_ok_body,
    );
}

fn drain_raw_hello(stream: &mut UnixStream) {
    let mut rx = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => panic!("EOF before HELLO"),
            Ok(n) => {
                rx.extend_from_slice(&tmp[..n]);
                if let Ok((hello, consumed)) = Codec::read_frame(&rx) {
                    assert_eq!(hello.hdr.ty, MsgType::Hello, "unsolicited HELLO type");
                    rx.drain(..consumed);
                    assert!(rx.is_empty(), "unexpected bytes after HELLO");
                    return;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("read HELLO: {e:?}"),
        }
    }
}

fn expect_raw_peer_closed_without_ping_reply(stream: &mut UnixStream, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut rx = Vec::new();
    let mut tmp = [0u8; 1024];
    while Instant::now() < deadline {
        match stream.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => {
                rx.extend_from_slice(&tmp[..n]);
                while let Ok((f, consumed)) = Codec::read_frame(&rx) {
                    rx.drain(..consumed);
                    assert!(
                        !(f.hdr.ty == MsgType::Status && f.hdr.seq == 99),
                        "broker resynced past {what} and replied to follow-up PING"
                    );
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return,
            Err(e) => panic!("read after {what}: {e:?}"),
        }
    }
    panic!("broker must close peer after {what}");
}

fn assert_fresh_connection_hello_and_empty_lookup(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("fresh connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("fresh HELLO");
    transport
        .send(&Frame::to_broker(
            MsgType::Lookup,
            10,
            EnvBuilder::new().finish(),
        ))
        .expect("fresh empty LOOKUP");

    let status = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 10
    })
    .expect("fresh empty LOOKUP STATUS");
    let s = find(&status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, UBUS_STATUS_OK, "fresh empty LOOKUP status");
}

fn read_raw_at_least(
    stream: &mut UnixStream,
    rx: &mut Vec<u8>,
    len: usize,
    timeout: Duration,
    what: &str,
) {
    let deadline = Instant::now() + timeout;
    let mut tmp = [0u8; 1024];
    while rx.len() < len && Instant::now() < deadline {
        match stream.read(&mut tmp) {
            Ok(0) => panic!("EOF while reading {what}"),
            Ok(n) => rx.extend_from_slice(&tmp[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("read {what}: {e:?}"),
        }
    }
    assert!(
        rx.len() >= len,
        "timed out reading {what}: have {}, need {len}",
        rx.len()
    );
}

fn read_strict_raw_frame(
    stream: &mut UnixStream,
    rx: &mut Vec<u8>,
    timeout: Duration,
    pred: impl Fn(&Frame) -> bool,
    what: &str,
) -> Frame {
    let deadline = Instant::now() + timeout;
    let mut tmp = [0u8; 1024];
    loop {
        while rx.len() >= HEADER_SIZE {
            match Codec::read_frame(rx) {
                Ok((frame, consumed)) => {
                    rx.drain(..consumed);
                    if pred(&frame) {
                        return frame;
                    }
                }
                Err(UbusError::Short { .. }) => break,
                Err(e) => panic!("decode {what}: {e:?}"),
            }
        }
        assert!(Instant::now() < deadline, "timed out reading {what}");
        match stream.read(&mut tmp) {
            Ok(0) => panic!("EOF while reading {what}"),
            Ok(n) => rx.extend_from_slice(&tmp[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("read {what}: {e:?}"),
        }
    }
}

/// ADD_OBJECT (anonymous) on a raw `UnixStream`; returns the assigned
/// obj id. Used by the backpressure scenario, which needs raw fd control
/// (SO_RCVBUF sizing) that `UnixUbusTransport` doesn't expose.
fn raw_stream_add_anonymous(stream: &mut UnixStream, rx: &mut Vec<u8>, seq: u16) -> u32 {
    stream
        .write_all(&Codec::write_frame(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq,
                peer: 0,
            },
            payload: EnvBuilder::new().finish(),
        }))
        .expect("raw anon ADD_OBJECT send");
    let data = read_strict_raw_frame(
        stream,
        rx,
        Duration::from_secs(5),
        |f| f.hdr.seq == seq && f.hdr.ty == MsgType::Data,
        "raw anon ADD_OBJECT DATA",
    );
    let obj = find(&data.payload, UbusAttr::ObjId)
        .and_then(|a| a.as_u32())
        .expect("anon obj id");
    read_strict_raw_frame(
        stream,
        rx,
        Duration::from_secs(5),
        |f| f.hdr.seq == seq && f.hdr.ty == MsgType::Status,
        "raw anon ADD_OBJECT STATUS",
    );
    obj
}

/// SUBSCRIBE `own_obj` → `target` on a raw stream and read the STATUS(0)
/// ack. Upstream-parity shape: ObjId is the subscriber's own object,
/// Target / hdr.peer is the publisher.
fn raw_stream_subscribe(
    stream: &mut UnixStream,
    rx: &mut Vec<u8>,
    seq: u16,
    own_obj: u32,
    target: u32,
) {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, own_obj);
    env.push_u32(UbusAttr::Target, target);
    stream
        .write_all(&Codec::write_frame(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq,
                peer: target,
            },
            payload: env.finish(),
        }))
        .expect("raw SUBSCRIBE send");
    let ack = read_strict_raw_frame(
        stream,
        rx,
        Duration::from_secs(5),
        |f| f.hdr.seq == seq && f.hdr.ty == MsgType::Status,
        "raw SUBSCRIBE STATUS",
    );
    assert_eq!(
        find(&ack.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32),
        Some(UBUS_STATUS_OK),
        "SUBSCRIBE ack status"
    );
}

/// Liveness probe: a fresh connection handshakes and its PING is answered
/// (DATA echo + STATUS(0)). Proves the broker still serves other peers.
fn assert_fresh_connection_alive(path: &str) {
    let mut t = UnixUbusTransport::connect(path).expect("liveness fresh connect");
    recv_until(&mut t, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("liveness HELLO");
    t.send(&Frame::to_broker(
        MsgType::Ping,
        31337,
        EnvBuilder::new().finish(),
    ))
    .expect("liveness PING send");
    recv_until(&mut t, Duration::from_secs(5), |f| {
        f.hdr.seq == 31337 && f.hdr.ty == MsgType::Status
    })
    .expect("liveness PING STATUS");
}

fn bad_version_is_processed_not_fatal_body(path: &str) {
    let mut stream = UnixStream::connect(path).expect("bad-version connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");
    drain_raw_hello(&mut stream);

    let payload = EnvBuilder::new().finish();
    let request = Frame {
        hdr: Header {
            version: PROTO_VERSION.wrapping_add(1),
            ty: MsgType::Ping,
            seq: 7,
            peer: 0,
        },
        payload: payload.clone(),
    };
    let mut expected_data = Codec::write_frame(&request);
    expected_data[1] = MsgType::Data as u8;
    stream
        .write_all(&Codec::write_frame(&request))
        .expect("send version=1 PING");

    let mut rx = Vec::new();
    read_raw_at_least(
        &mut stream,
        &mut rx,
        expected_data.len(),
        Duration::from_secs(5),
        "version=1 PING DATA",
    );
    let data: Vec<u8> = rx.drain(..expected_data.len()).collect();
    assert_eq!(
        data, expected_data,
        "PING DATA must echo request version byte and payload"
    );

    let status = read_strict_raw_frame(
        &mut stream,
        &mut rx,
        Duration::from_secs(5),
        |f| f.hdr.ty == MsgType::Status && f.hdr.seq == 7,
        "version=1 PING STATUS",
    );
    assert_eq!(
        find(&status.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32),
        Some(UBUS_STATUS_OK),
        "version=1 PING STATUS"
    );

    let good = Frame::to_broker(MsgType::Ping, 8, payload);
    stream
        .write_all(&Codec::write_frame(&good))
        .expect("send follow-up version=0 PING");
    let data = read_strict_raw_frame(
        &mut stream,
        &mut rx,
        Duration::from_secs(5),
        |f| f.hdr.ty == MsgType::Data && f.hdr.seq == 8,
        "follow-up PING DATA",
    );
    assert_eq!(data.hdr.version, PROTO_VERSION);
    let status = read_strict_raw_frame(
        &mut stream,
        &mut rx,
        Duration::from_secs(5),
        |f| f.hdr.ty == MsgType::Status && f.hdr.seq == 8,
        "follow-up PING STATUS",
    );
    assert_eq!(
        find(&status.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32),
        Some(UBUS_STATUS_OK),
        "follow-up PING STATUS"
    );

    assert_fresh_connection_hello_and_empty_lookup(path);
}

// Version-skew input: the strict client codec rejects the reply DATA
// because upstream echoes version=1 there, so this scenario runs
// WITHOUT the tap/parity/golden oracles and compares that frame's raw
// bytes directly. Direct-harness 2-arm matrix.
#[rstest]
#[case::upstream(BrokerArm::Upstream)]
#[case::rs(BrokerArm::Rs)]
fn bad_version_is_processed_not_fatal(#[case] arm: BrokerArm) {
    let start: fn() -> std::io::Result<Option<UbusdHarness>> = match arm {
        BrokerArm::Upstream => UbusdHarness::start_upstream,
        BrokerArm::Rs => UbusdHarness::start_rust,
    };
    let harness = match start() {
        Ok(Some(h)) => h,
        Ok(None) => {
            skip::or_skip(
                concat!(
                    "ubusd_handshake ",
                    stringify!(bad_version_is_processed_not_fatal)
                ),
                "broker binary not reachable",
            );
            return;
        }
        Err(e) => panic!("broker start: {e:?}"),
    };
    let path = harness.socket_path().to_str().expect("utf-8 socket path");
    bad_version_is_processed_not_fatal_body(path);
}

fn oversized_declared_length_closes_peer_but_broker_survives_body(path: &str) {
    let mut stream = UnixStream::connect(path).expect("oversized connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");
    drain_raw_hello(&mut stream);

    let declared_len = (MAX_MSG_LEN as u32) + 4096;
    let aligned_len = ((declared_len as usize) + 3) & !3;
    let hdr = Header {
        version: PROTO_VERSION,
        ty: MsgType::Ping,
        seq: 42,
        peer: 0,
    };
    let mut bytes = Vec::with_capacity(HEADER_SIZE + aligned_len);
    bytes.extend_from_slice(&hdr.encode());
    bytes.extend_from_slice(&declared_len.to_be_bytes());
    bytes.resize(HEADER_SIZE + aligned_len, 0);
    let _ = stream.write_all(&bytes);
    let ping = Frame::to_broker(MsgType::Ping, 99, EnvBuilder::new().finish());
    let _ = stream.write_all(&Codec::write_frame(&ping));
    expect_raw_peer_closed_without_ping_reply(&mut stream, "oversized declared length");

    assert_fresh_connection_hello_and_empty_lookup(path);
}

// Deliberate-garbage input: the canonicalizer (correctly) refuses to
// decode the malformed c2b stream, so this scenario runs WITHOUT the
// tap/parity/golden oracles — behavioral liveness (peer closed, broker
// survives) is the whole assertion. Direct-harness 2-arm matrix.
#[rstest]
#[case::upstream(BrokerArm::Upstream)]
#[case::rs(BrokerArm::Rs)]
fn oversized_declared_length_closes_peer_but_broker_survives(#[case] arm: BrokerArm) {
    let start: fn() -> std::io::Result<Option<UbusdHarness>> = match arm {
        BrokerArm::Upstream => UbusdHarness::start_upstream,
        BrokerArm::Rs => UbusdHarness::start_rust,
    };
    let harness = match start() {
        Ok(Some(h)) => h,
        Ok(None) => {
            skip::or_skip(
                concat!(
                    "ubusd_handshake ",
                    stringify!(oversized_declared_length_closes_peer_but_broker_survives)
                ),
                "broker binary not reachable",
            );
            return;
        }
        Err(e) => panic!("broker start: {e:?}"),
    };
    let path = harness.socket_path().to_str().expect("utf-8 socket path");
    oversized_declared_length_closes_peer_but_broker_survives_body(path);
}

fn raw_ping_with_single_data_envelope(seq: u16, attr_len: usize) -> Vec<u8> {
    assert!(attr_len >= 8, "outer attr must fit one inner Data attr");
    let inner_len = attr_len - 4;
    let mut bytes = Vec::with_capacity(HEADER_SIZE + attr_len);
    bytes.extend_from_slice(
        &Header {
            version: PROTO_VERSION,
            ty: MsgType::Ping,
            seq,
            peer: 0,
        }
        .encode(),
    );
    bytes.extend_from_slice(&(attr_len as u32).to_be_bytes());
    bytes.extend_from_slice(&(((UbusAttr::Data as u32) << 24) | inner_len as u32).to_be_bytes());
    bytes.resize(HEADER_SIZE + attr_len, 0);
    bytes
}

fn ping_at_max_frame_size_is_answered_body(path: &str) {
    let mut stream = UnixStream::connect(path).expect("max-frame connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .expect("set write timeout");
    drain_raw_hello(&mut stream);

    let request = raw_ping_with_single_data_envelope(42, MAX_MSG_LEN);
    let expected_payload = request[HEADER_SIZE..].to_vec();
    stream.write_all(&request).expect("send max-frame PING");

    // This stays a direct-harness test: tapping/goldening a 1 MiB
    // transcript per arm buys no extra signal; the parity surface is the
    // boundary itself.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut rx = Vec::new();
    let mut tmp = [0u8; 64 * 1024];
    let mut saw_data = false;
    let mut saw_status = false;
    while Instant::now() < deadline && !(saw_data && saw_status) {
        while rx.len() >= HEADER_SIZE {
            match Codec::read_frame(&rx) {
                Ok((frame, consumed)) => {
                    rx.drain(..consumed);
                    if frame.hdr.seq == 42 && frame.hdr.ty == MsgType::Data {
                        assert_eq!(frame.payload.len(), MAX_MSG_LEN, "max PING DATA length");
                        assert_eq!(frame.payload, expected_payload, "max PING DATA echo");
                        saw_data = true;
                    } else if frame.hdr.seq == 42 && frame.hdr.ty == MsgType::Status {
                        assert_eq!(
                            find(&frame.payload, UbusAttr::Status)
                                .and_then(|a| a.as_u32())
                                .map(|u| u as i32),
                            Some(UBUS_STATUS_OK),
                            "max PING STATUS"
                        );
                        saw_status = true;
                    }
                }
                Err(UbusError::Short { .. }) => break,
                Err(e) => panic!("decode max PING reply: {e:?}"),
            }
        }
        if saw_data && saw_status {
            break;
        }
        match stream.read(&mut tmp) {
            Ok(0) => panic!("EOF while reading max PING reply"),
            Ok(n) => rx.extend_from_slice(&tmp[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read max PING reply: {e:?}"),
        }
    }
    assert!(saw_data, "max PING DATA reply missing");
    assert!(saw_status, "max PING STATUS reply missing");

    let follow_up = Frame::to_broker(MsgType::Ping, 43, EnvBuilder::new().finish());
    stream
        .write_all(&Codec::write_frame(&follow_up))
        .expect("send follow-up PING");
    read_strict_raw_frame(
        &mut stream,
        &mut rx,
        Duration::from_secs(5),
        |f| f.hdr.seq == 43 && f.hdr.ty == MsgType::Data,
        "follow-up PING DATA",
    );
    read_strict_raw_frame(
        &mut stream,
        &mut rx,
        Duration::from_secs(5),
        |f| f.hdr.seq == 43 && f.hdr.ty == MsgType::Status,
        "follow-up PING STATUS",
    );
}

// Direct-harness 2-arm boundary probe; see the body for why this is not
// tapped or goldenized.
#[rstest]
#[case::upstream(BrokerArm::Upstream)]
#[case::rs(BrokerArm::Rs)]
fn ping_at_max_frame_size_is_answered(#[case] arm: BrokerArm) {
    let start: fn() -> std::io::Result<Option<UbusdHarness>> = match arm {
        BrokerArm::Upstream => UbusdHarness::start_upstream,
        BrokerArm::Rs => UbusdHarness::start_rust,
    };
    let harness = match start() {
        Ok(Some(h)) => h,
        Ok(None) => {
            skip::or_skip(
                concat!(
                    "ubusd_handshake ",
                    stringify!(ping_at_max_frame_size_is_answered)
                ),
                "broker binary not reachable",
            );
            return;
        }
        Err(e) => panic!("broker start: {e:?}"),
    };
    let path = harness.socket_path().to_str().expect("utf-8 socket path");
    ping_at_max_frame_size_is_answered_body(path);
}

fn frame_just_over_max_size_closes_peer_but_broker_survives_body(path: &str) {
    let mut stream = UnixStream::connect(path).expect("just-over connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .expect("set write timeout");
    drain_raw_hello(&mut stream);

    let just_over = raw_ping_with_single_data_envelope(42, MAX_MSG_LEN + 4);
    // The broker may close the peer as soon as the oversized declared
    // length arrives (probed: upstream RSTs mid-write), so a write error
    // here IS the behavior under test — never unwrap it.
    let _ = stream.write_all(&just_over);
    let ping = Frame::to_broker(MsgType::Ping, 99, EnvBuilder::new().finish());
    let _ = stream.write_all(&Codec::write_frame(&ping));
    expect_raw_peer_closed_without_ping_reply(&mut stream, "just-over-max frame");

    assert_fresh_connection_hello_and_empty_lookup(path);
}

// Direct-harness 2-arm boundary probe: unlike the older oversized-length
// case this writes the complete body at exactly MAX_MSG_LEN + 4.
#[rstest]
#[case::upstream(BrokerArm::Upstream)]
#[case::rs(BrokerArm::Rs)]
fn frame_just_over_max_size_closes_peer_but_broker_survives(#[case] arm: BrokerArm) {
    let start: fn() -> std::io::Result<Option<UbusdHarness>> = match arm {
        BrokerArm::Upstream => UbusdHarness::start_upstream,
        BrokerArm::Rs => UbusdHarness::start_rust,
    };
    let harness = match start() {
        Ok(Some(h)) => h,
        Ok(None) => {
            skip::or_skip(
                concat!(
                    "ubusd_handshake ",
                    stringify!(frame_just_over_max_size_closes_peer_but_broker_survives)
                ),
                "broker binary not reachable",
            );
            return;
        }
        Err(e) => panic!("broker start: {e:?}"),
    };
    let path = harness.socket_path().to_str().expect("utf-8 socket path");
    frame_just_over_max_size_closes_peer_but_broker_survives_body(path);
}

// A subscriber that stops draining must not wedge the broker: throughout
// and after a sustained NOTIFY fan-out the publisher keeps getting its
// acks and a fresh peer still handshakes. How each broker sheds the
// backlog is a KNOWN, intentional divergence — probed live: rs *evicts*
// the stuck peer once its tx backlog exceeds `MAX_TX_BUF_BYTES` (heap
// safety; covered by `slow_subscriber_evicted_when_tx_buf_caps` in
// smoke.rs), while upstream `ubusd` silently *drops* fan-out for a
// client whose bounded tx ring is full and keeps it connected. Because
// the shed mechanism diverges and the byte stream is huge + eviction-
// point-dependent, this can't be a tapped byte-diff scenario; the
// cross-broker-common invariant (no wedge; others stay live) is the
// assertion surface. Direct-harness 2-arm. `evicted` is recorded for
// diagnostics, never asserted (it is rs-only).
fn slow_subscriber_does_not_wedge_broker_body(path: &str, arm: BrokerArm) {
    use std::os::fd::AsRawFd;

    // Publisher registers a named object to fan out from. (Accept 1 — the
    // harness bind probe is accept 0, which the tx-stall shim skips.)
    let mut publisher = UnixUbusTransport::connect(path).expect("publisher connect");
    recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("publisher HELLO");
    let (pub_obj, _) = raw_add_object_with_signature(
        &mut publisher,
        500,
        "example.flood",
        &signature_with_ping_method(),
    );

    // Slow subscriber (accept 2): subscribes, then never reads again.
    let mut slow = UnixStream::connect(path).expect("slow connect");
    if matches!(arm, BrokerArm::Rs) {
        // rs sheds by evicting once its per-peer tx backlog crosses
        // MAX_TX_BUF_BYTES; a shrunk kernel rcv-buf makes that crossing
        // reachable within a bounded flood. Upstream's shed point is
        // pinned by the stall shim instead, so its rcv-buf is irrelevant.
        let bfd = unsafe { rustix::fd::BorrowedFd::borrow_raw(slow.as_raw_fd()) };
        let _ = rustix::net::sockopt::set_socket_recv_buffer_size(bfd, 4096);
    }
    slow.set_read_timeout(Some(Duration::from_millis(50)))
        .expect("slow rd timeout");
    slow.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("slow wr timeout");
    let mut slow_rx = Vec::new();
    read_strict_raw_frame(
        &mut slow,
        &mut slow_rx,
        Duration::from_secs(5),
        |f| f.hdr.ty == MsgType::Hello,
        "slow HELLO",
    );
    let slow_obj = raw_stream_add_anonymous(&mut slow, &mut slow_rx, 510);
    raw_stream_subscribe(&mut slow, &mut slow_rx, 511, slow_obj, pub_obj);
    // From here the slow subscriber never reads again.

    // Flood NOTIFY in batches. Flow control is the
    // publisher's own acks, not a fixed sleep: after each batch we wait
    // until the broker has acked every notify sent so far, which bounds
    // the broker's rx backlog to one batch and proves it is still
    // dispatching. A publisher send that errors means the broker wedged
    // the *publisher* — a hard failure, not a shed subscriber.
    // Keep upstream's established 4 KiB flood unchanged. rs needs a
    // larger payload to cross its now-2 MiB tx cap within this bounded
    // scenario even after the kernel receive buffer fills.
    let body = vec![
        b'x';
        if matches!(arm, BrokerArm::Rs) {
            24 * 1024
        } else {
            4096
        }
    ];
    let body_str = std::str::from_utf8(&body).expect("ascii body");
    // 400 rs notifies × 24 KiB ≫ its shed point (4 KiB rcv-buf + 2 MiB tx
    // cap is crossed by ~86 frames); upstream keeps its 4 KiB flood and
    // drops fan-out instead of evicting.
    const BATCHES: usize = 25;
    const PER_BATCH: u16 = 16;
    let mut seq = 0u16;
    let mut acked = 0usize;
    for _ in 0..BATCHES {
        for _ in 0..PER_BATCH {
            let mut env = EnvBuilder::new();
            env.push_u32(UbusAttr::ObjId, pub_obj);
            env.push_str(UbusAttr::Method, "flood");
            env.push_str(UbusAttr::Data, body_str);
            let frame = Frame {
                hdr: Header {
                    version: PROTO_VERSION,
                    ty: MsgType::Notify,
                    seq,
                    peer: pub_obj,
                },
                payload: env.finish(),
            };
            seq = seq.wrapping_add(1);
            publisher
                .send(&frame)
                .expect("publisher must not wedge under fan-out backpressure");
        }
        // Wait for the broker to ack the whole batch. The broker acks
        // every NOTIFY with a STATUS (empty subscriber list once the slow
        // peer is shed), so a broker that stops acking has wedged.
        let sent = seq as usize;
        let deadline = Instant::now() + Duration::from_secs(5);
        while acked < sent && Instant::now() < deadline {
            match publisher.recv() {
                Ok(Some(f)) if f.hdr.ty == MsgType::Status => acked += 1,
                Ok(Some(_)) => {}
                Ok(None) => std::thread::yield_now(),
                Err(e) => panic!("publisher ack recv: {e:?}"),
            }
        }
        assert!(
            acked >= sent,
            "broker must keep acking the publisher (no wedge); acked {acked}/{sent}"
        );
    }

    // Shed behavior — the documented, intentional divergence, each pinned
    // deterministically. The slow subscriber never read during the flood.
    let mut probe = [0u8; 8192];
    let mut slow_bytes = 0usize;
    let mut evicted = false;
    let shed_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < shed_deadline {
        match slow.read(&mut probe) {
            Ok(0) => {
                evicted = true;
                break;
            }
            Ok(n) => slow_bytes += n,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                evicted = true;
                break;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No more bytes pending. For upstream (stalled but
                // connected) that is the steady state — stop probing.
                if matches!(arm, BrokerArm::Upstream) {
                    break;
                }
            }
            Err(e) => panic!("slow poll: {e:?}"),
        }
    }
    eprintln!(
        "slow_subscriber_does_not_wedge_broker[{arm:?}]: evicted={evicted} slow_bytes={slow_bytes}"
    );

    match arm {
        BrokerArm::Rs => {
            assert!(
                evicted,
                "rs must evict the stuck subscriber (EOF) once its tx backlog crosses \
                 MAX_TX_BUF_BYTES; drained {slow_bytes} B without EOF"
            );
        }
        BrokerArm::Upstream => {
            assert!(
                !evicted,
                "upstream must keep the stuck subscriber connected (it drops fan-out, \
                 never evicts); saw EOF after {slow_bytes} B"
            );
            // Fan-out past the stall budget was dropped: the subscriber
            // received at most the stall prefix, nowhere near the flood.
            assert!(
                slow_bytes < 64 * 1024,
                "upstream must drop fan-out past the {SLOW_STALL_AFTER}-byte stall budget; \
                 slow subscriber received {slow_bytes} B"
            );
        }
    }

    // Common no-wedge invariant: other peers stay live.
    assert_fresh_connection_alive(path);
    publisher
        .send(&Frame::to_broker(
            MsgType::Ping,
            9999,
            EnvBuilder::new().finish(),
        ))
        .expect("publisher PING send");
    recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.seq == 9999 && f.hdr.ty == MsgType::Status
    })
    .expect("publisher PING STATUS after flood");
}

/// Accept index of the slow subscriber as the tx-stall shim counts it.
/// The harness bind-readiness probe is accept 0, the publisher connects
/// next (accept 1), so the subscriber is accept 2. See `fault.c` and
/// `UbusdHarness::start_upstream_with_tx_stall`.
const SLOW_STALL_CONN: usize = 2;
/// Bytes upstream may write to the stalled subscriber before its fan-out
/// wedges. Comfortably clears HELLO + the anonymous ADD_OBJECT reply +
/// the SUBSCRIBE ack (~150 B), so the subscriber completes its handshake
/// and only the flood is shed.
const SLOW_STALL_AFTER: usize = 4096;

#[rstest]
#[case::upstream(BrokerArm::Upstream)]
#[case::rs(BrokerArm::Rs)]
fn slow_subscriber_does_not_wedge_broker(#[case] arm: BrokerArm) {
    // Upstream's shed point is pinned deterministically by the tx-stall
    // shim (upstream writes through libc, which the shim interposes). rs
    // bypasses libc via rustix, so its arm exercises the real
    // MAX_TX_BUF_BYTES eviction with a bounded, kernel-buffer-aware flood.
    let started = match arm {
        BrokerArm::Upstream => {
            UbusdHarness::start_upstream_with_tx_stall(SLOW_STALL_CONN, SLOW_STALL_AFTER)
        }
        BrokerArm::Rs => UbusdHarness::start_rust(),
    };
    let harness = match started {
        Ok(Some(h)) => h,
        Ok(None) => {
            skip::or_skip(
                concat!(
                    "ubusd_handshake ",
                    stringify!(slow_subscriber_does_not_wedge_broker)
                ),
                "broker binary not reachable",
            );
            return;
        }
        Err(e) => panic!("broker start: {e:?}"),
    };
    let path = harness.socket_path().to_str().expect("utf-8 socket path");
    slow_subscriber_does_not_wedge_broker_body(path, arm);
}

fn remove_object_without_objid_reports_invalid_argument_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    let hello = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let peer_id = hello.hdr.peer;

    let env = EnvBuilder::new().finish();
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 8,
                peer: peer_id,
            },
            payload: env,
        })
        .expect("send RemoveObject without ObjId");

    let status = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.seq == 8 && f.hdr.ty == MsgType::Status
    })
    .expect("RemoveObject STATUS reply");
    let s = find(&status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(
        s, UBUS_STATUS_INVALID_ARGUMENT,
        "RemoveObject without ObjId must report UBUS_STATUS_INVALID_ARGUMENT"
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn remove_object_without_objid_reports_invalid_argument(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(remove_object_without_objid_reports_invalid_argument)
        ),
        arm,
        &remove_object_without_objid_reports_invalid_argument_body,
    );
}

/// Builtin `ubus.monitor` system object id (`UBUS_SYSTEM_OBJECT_MONITOR`).
const MONITOR_OBJECT_ID: u32 = 3;

/// Send an INVOKE to the monitor builtin. The caller must read the resulting
/// mirror (when adding/removing) and STATUS reply in wire order.
fn send_monitor_ctl(transport: &mut UnixUbusTransport, seq: u16, method: &str) {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, MONITOR_OBJECT_ID);
    env.push_str(UbusAttr::Method, method);
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq,
                peer: MONITOR_OBJECT_ID,
            },
            payload: env.finish(),
        })
        .expect("send monitor control INVOKE");
}

/// Assert the fixed monitor envelope and return its mirrored inner attribute
/// stream (the MONITOR `DATA` payload).
struct MirrorShape {
    mirror_seq: u16,
    client: u32,
    peer: u32,
    seq: u16,
    ty: MsgType,
    send: bool,
}

fn assert_monitor_mirror<'a>(frame: &'a Frame, shape: MirrorShape, what: &str) -> &'a [u8] {
    assert_eq!(frame.hdr.ty, MsgType::Monitor, "{what} type");
    assert_eq!(frame.hdr.peer, 0, "{what} hdr.peer");
    assert_eq!(frame.hdr.seq, shape.mirror_seq, "{what} mirror seq");

    let inner = unwrap_envelope(&frame.payload).expect("valid monitor envelope");
    assert_eq!(
        iter_attrs(inner).map(|attr| attr.id).collect::<Vec<_>>(),
        vec![0, 1, 3, 4, 2, 5],
        "{what} attr order"
    );
    let monitor_attr = |id| {
        iter_attrs(inner)
            .find(|attr| attr.id == id)
            .map(|attr| attr.payload)
            .unwrap_or_else(|| panic!("{what} monitor attr {id}"))
    };
    assert_eq!(
        u32::from_be_bytes(monitor_attr(0).try_into().expect("CLIENT u32")),
        shape.client,
        "{what} CLIENT"
    );
    assert_eq!(
        u32::from_be_bytes(monitor_attr(1).try_into().expect("PEER u32")),
        shape.peer,
        "{what} PEER"
    );
    assert_eq!(
        u32::from_be_bytes(monitor_attr(3).try_into().expect("SEQ u32")),
        u32::from(shape.seq),
        "{what} SEQ"
    );
    assert_eq!(
        u32::from_be_bytes(monitor_attr(4).try_into().expect("TYPE u32")),
        shape.ty as u32,
        "{what} TYPE"
    );
    assert_eq!(monitor_attr(2), &[u8::from(shape.send)], "{what} SEND");
    monitor_attr(5)
}

fn monitor_mirrors_object_registration_and_invoke_body(path: &str) {
    let mut monitor = UnixUbusTransport::connect(path).expect("monitor connect");
    let monitor_peer = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("monitor HELLO")
    .hdr
    .peer;

    send_monitor_ctl(&mut monitor, 700, "add");
    let add_mirror = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("monitor add-ack mirror");
    let add_data = assert_monitor_mirror(
        &add_mirror,
        MirrorShape {
            mirror_seq: 1,
            client: monitor_peer,
            peer: MONITOR_OBJECT_ID,
            seq: 700,
            ty: MsgType::Status,
            send: true,
        },
        "monitor add-ack mirror",
    );
    assert_eq!(
        iter_attrs(add_data).map(|attr| attr.id).collect::<Vec<_>>(),
        vec![UbusAttr::Status as u8],
        "monitor add-ack mirrored DATA"
    );
    assert_eq!(
        iter_attrs(add_data).next().and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "monitor add-ack mirrored status"
    );
    let add_ack = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 700
    })
    .expect("monitor add ack");
    assert_eq!(
        find(&add_ack.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "monitor add ack status"
    );

    let mut owner = UnixUbusTransport::connect(path).expect("owner connect");
    let owner_peer = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("owner HELLO")
    .hdr
    .peer;
    let owner_hello = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("owner HELLO mirror");
    assert!(
        assert_monitor_mirror(
            &owner_hello,
            MirrorShape {
                mirror_seq: 2,
                client: owner_peer,
                peer: owner_peer,
                seq: 0,
                ty: MsgType::Hello,
                send: true,
            },
            "owner HELLO mirror",
        )
        .is_empty(),
        "HELLO mirror DATA"
    );

    let (obj_id, obj_type) = raw_add_object_with_signature(
        &mut owner,
        701,
        "example.monitor.ping",
        &signature_with_ping_method(),
    );
    let add_in = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("ADD_OBJECT inbound mirror");
    let add_in_data = assert_monitor_mirror(
        &add_in,
        MirrorShape {
            mirror_seq: 3,
            client: owner_peer,
            peer: 0,
            seq: 701,
            ty: MsgType::AddObject,
            send: false,
        },
        "ADD_OBJECT inbound mirror",
    );
    assert_eq!(
        iter_attrs(add_in_data)
            .map(|attr| attr.id)
            .collect::<Vec<_>>(),
        vec![UbusAttr::ObjPath as u8, UbusAttr::Signature as u8],
        "ADD_OBJECT inbound DATA"
    );
    let add_data = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("ADD_OBJECT DATA mirror");
    let add_data_inner = assert_monitor_mirror(
        &add_data,
        MirrorShape {
            mirror_seq: 4,
            client: owner_peer,
            peer: 0,
            seq: 701,
            ty: MsgType::Data,
            send: true,
        },
        "ADD_OBJECT DATA mirror",
    );
    assert_eq!(
        iter_attrs(add_data_inner)
            .map(|attr| attr.id)
            .collect::<Vec<_>>(),
        vec![UbusAttr::ObjId as u8, UbusAttr::ObjType as u8],
        "ADD_OBJECT DATA mirror payload"
    );
    assert_eq!(
        iter_attrs(add_data_inner)
            .find(|attr| attr.id == UbusAttr::ObjId as u8)
            .and_then(|attr| attr.as_u32()),
        Some(obj_id),
        "ADD_OBJECT mirrored ObjId"
    );
    assert_eq!(
        iter_attrs(add_data_inner)
            .find(|attr| attr.id == UbusAttr::ObjType as u8)
            .and_then(|attr| attr.as_u32()),
        Some(obj_type),
        "ADD_OBJECT mirrored ObjType"
    );
    let add_status = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("ADD_OBJECT STATUS mirror");
    assert_monitor_mirror(
        &add_status,
        MirrorShape {
            mirror_seq: 5,
            client: owner_peer,
            peer: 0,
            seq: 701,
            ty: MsgType::Status,
            send: true,
        },
        "ADD_OBJECT STATUS mirror",
    );

    let mut caller = UnixUbusTransport::connect(path).expect("caller connect");
    let caller_peer = recv_until(&mut caller, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("caller HELLO")
    .hdr
    .peer;
    let caller_hello = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("caller HELLO mirror");
    assert!(
        assert_monitor_mirror(
            &caller_hello,
            MirrorShape {
                mirror_seq: 6,
                client: caller_peer,
                peer: caller_peer,
                seq: 0,
                ty: MsgType::Hello,
                send: true,
            },
            "caller HELLO mirror",
        )
        .is_empty(),
        "caller HELLO mirror DATA"
    );

    let mut invoke = EnvBuilder::new();
    invoke.push_u32(UbusAttr::ObjId, obj_id);
    invoke.push_str(UbusAttr::Method, "ping");
    caller
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq: 702,
                peer: obj_id,
            },
            payload: invoke.finish(),
        })
        .expect("send caller INVOKE");
    let invoke_in = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("INVOKE inbound mirror");
    let invoke_in_data = assert_monitor_mirror(
        &invoke_in,
        MirrorShape {
            mirror_seq: 7,
            client: caller_peer,
            peer: obj_id,
            seq: 702,
            ty: MsgType::Invoke,
            send: false,
        },
        "INVOKE inbound mirror",
    );
    assert_eq!(
        iter_attrs(invoke_in_data)
            .map(|attr| attr.id)
            .collect::<Vec<_>>(),
        vec![UbusAttr::ObjId as u8, UbusAttr::Method as u8],
        "INVOKE inbound mirror DATA"
    );
    assert_eq!(
        iter_attrs(invoke_in_data)
            .find(|attr| attr.id == UbusAttr::ObjId as u8)
            .and_then(|attr| attr.as_u32()),
        Some(obj_id),
        "INVOKE inbound mirrored ObjId"
    );
    assert_eq!(
        iter_attrs(invoke_in_data)
            .find(|attr| attr.id == UbusAttr::Method as u8)
            .and_then(|attr| attr.as_str()),
        Some("ping"),
        "INVOKE inbound mirrored Method"
    );
    let invoke_out = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("forwarded INVOKE mirror");
    let invoke_out_data = assert_monitor_mirror(
        &invoke_out,
        MirrorShape {
            mirror_seq: 8,
            client: owner_peer,
            peer: caller_peer,
            seq: 702,
            ty: MsgType::Invoke,
            send: true,
        },
        "forwarded INVOKE mirror",
    );
    assert_eq!(
        iter_attrs(invoke_out_data)
            .map(|attr| attr.id)
            .collect::<Vec<_>>(),
        vec![
            UbusAttr::ObjId as u8,
            UbusAttr::Method as u8,
            UbusAttr::User as u8,
            UbusAttr::Group as u8,
        ],
        "forwarded INVOKE mirror DATA"
    );
    assert_eq!(
        iter_attrs(invoke_out_data)
            .find(|attr| attr.id == UbusAttr::ObjId as u8)
            .and_then(|attr| attr.as_u32()),
        Some(obj_id),
        "forwarded INVOKE mirrored ObjId"
    );
    assert_eq!(
        iter_attrs(invoke_out_data)
            .find(|attr| attr.id == UbusAttr::Method as u8)
            .and_then(|attr| attr.as_str()),
        Some("ping"),
        "forwarded INVOKE mirrored Method"
    );
    assert_eq!(
        iter_attrs(invoke_out_data)
            .find(|attr| attr.id == UbusAttr::User as u8)
            .and_then(|attr| attr.as_str()),
        Some("root"),
        "forwarded INVOKE mirrored User"
    );
    assert_eq!(
        iter_attrs(invoke_out_data)
            .find(|attr| attr.id == UbusAttr::Group as u8)
            .and_then(|attr| attr.as_str()),
        Some("root"),
        "forwarded INVOKE mirrored Group"
    );

    let forwarded = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke && f.hdr.seq == 702
    })
    .expect("forwarded INVOKE");
    assert_eq!(forwarded.hdr.peer, caller_peer, "forwarded INVOKE peer");
    expect_attr_sequence(
        &forwarded.payload,
        &[
            UbusAttr::ObjId,
            UbusAttr::Method,
            UbusAttr::User,
            UbusAttr::Group,
        ],
        "forwarded INVOKE",
    );
    let mut reply = EnvBuilder::new();
    reply.push_u32(UbusAttr::Status, UBUS_STATUS_OK as u32);
    reply.push_u32(UbusAttr::ObjId, obj_id);
    owner
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Status,
                seq: 702,
                peer: caller_peer,
            },
            payload: reply.finish(),
        })
        .expect("send owner STATUS reply");
    let reply_in = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("owner reply inbound mirror");
    let reply_in_data = assert_monitor_mirror(
        &reply_in,
        MirrorShape {
            mirror_seq: 9,
            client: owner_peer,
            peer: caller_peer,
            seq: 702,
            ty: MsgType::Status,
            send: false,
        },
        "owner reply inbound mirror",
    );
    assert_eq!(
        iter_attrs(reply_in_data)
            .map(|attr| attr.id)
            .collect::<Vec<_>>(),
        vec![UbusAttr::Status as u8, UbusAttr::ObjId as u8],
        "owner reply inbound mirror DATA"
    );
    let reply_out = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("caller reply delivered mirror");
    let reply_out_data = assert_monitor_mirror(
        &reply_out,
        MirrorShape {
            mirror_seq: 10,
            client: caller_peer,
            peer: obj_id,
            seq: 702,
            ty: MsgType::Status,
            send: true,
        },
        "caller reply delivered mirror",
    );
    assert_eq!(
        iter_attrs(reply_out_data)
            .map(|attr| attr.id)
            .collect::<Vec<_>>(),
        vec![UbusAttr::Status as u8, UbusAttr::ObjId as u8],
        "caller reply delivered mirror DATA"
    );
    let caller_status = recv_until(&mut caller, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 702
    })
    .expect("caller STATUS reply");
    assert_eq!(caller_status.hdr.peer, obj_id, "caller STATUS reply peer");
    assert_eq!(
        find(&caller_status.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "caller STATUS reply status"
    );

    drop(caller);
    drop(owner);
    drop(monitor);
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn monitor_mirrors_object_registration_and_invoke(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(monitor_mirrors_object_registration_and_invoke)
        ),
        arm,
        &monitor_mirrors_object_registration_and_invoke_body,
    );
}

fn monitor_registration_lifecycle_resets_seq_body(path: &str) {
    let mut monitor = UnixUbusTransport::connect(path).expect("monitor connect");
    let monitor_peer = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("monitor HELLO")
    .hdr
    .peer;

    send_monitor_ctl(&mut monitor, 710, "add");
    let add_mirror = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("initial add-ack mirror");
    assert_monitor_mirror(
        &add_mirror,
        MirrorShape {
            mirror_seq: 1,
            client: monitor_peer,
            peer: MONITOR_OBJECT_ID,
            seq: 710,
            ty: MsgType::Status,
            send: true,
        },
        "initial add-ack mirror",
    );
    let add_ack = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 710
    })
    .expect("initial add ack");
    assert_eq!(
        find(&add_ack.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "initial add ack status"
    );

    let mut client = UnixUbusTransport::connect(path).expect("client connect");
    let client_peer = recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("client HELLO")
    .hdr
    .peer;
    let hello_mirror = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("client HELLO mirror");
    assert_monitor_mirror(
        &hello_mirror,
        MirrorShape {
            mirror_seq: 2,
            client: client_peer,
            peer: client_peer,
            seq: 0,
            ty: MsgType::Hello,
            send: true,
        },
        "client HELLO mirror",
    );

    client
        .send(&Frame::to_broker(
            MsgType::Ping,
            711,
            EnvBuilder::new().finish(),
        ))
        .expect("send first PING");
    for (mirror_seq, ty, send) in [
        (3, MsgType::Ping, false),
        (4, MsgType::Data, true),
        (5, MsgType::Status, true),
    ] {
        let mirror = recv_until(&mut monitor, Duration::from_secs(5), |f| {
            f.hdr.ty == MsgType::Monitor
        })
        .expect("first PING mirror");
        assert_monitor_mirror(
            &mirror,
            MirrorShape {
                mirror_seq,
                client: client_peer,
                peer: 0,
                seq: 711,
                ty,
                send,
            },
            "first PING mirror",
        );
    }
    recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Data && f.hdr.seq == 711
    })
    .expect("first PING DATA");
    let first_ping_status = recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 711
    })
    .expect("first PING STATUS");
    assert_eq!(
        find(&first_ping_status.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "first PING status"
    );

    send_monitor_ctl(&mut monitor, 712, "remove");
    let remove_mirror = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("monitor remove inbound mirror");
    let remove_data = assert_monitor_mirror(
        &remove_mirror,
        MirrorShape {
            mirror_seq: 6,
            client: monitor_peer,
            peer: MONITOR_OBJECT_ID,
            seq: 712,
            ty: MsgType::Invoke,
            send: false,
        },
        "monitor remove inbound mirror",
    );
    assert_eq!(
        iter_attrs(remove_data)
            .map(|attr| attr.id)
            .collect::<Vec<_>>(),
        vec![UbusAttr::ObjId as u8, UbusAttr::Method as u8],
        "monitor remove mirrored DATA"
    );
    assert_eq!(
        iter_attrs(remove_data)
            .find(|attr| attr.id == UbusAttr::ObjId as u8)
            .and_then(|attr| attr.as_u32()),
        Some(MONITOR_OBJECT_ID),
        "monitor remove mirrored ObjId"
    );
    assert_eq!(
        iter_attrs(remove_data)
            .find(|attr| attr.id == UbusAttr::Method as u8)
            .and_then(|attr| attr.as_str()),
        Some("remove"),
        "monitor remove mirrored Method"
    );
    let remove_ack = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 712
    })
    .expect("monitor remove ack");
    assert_eq!(
        find(&remove_ack.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "monitor remove ack status"
    );

    client
        .send(&Frame::to_broker(
            MsgType::Ping,
            713,
            EnvBuilder::new().finish(),
        ))
        .expect("send PING after remove");
    recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Data && f.hdr.seq == 713
    })
    .expect("PING after remove DATA");
    let removed_ping_status = recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 713
    })
    .expect("PING after remove STATUS");
    assert_eq!(
        find(&removed_ping_status.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "PING after remove status"
    );

    send_monitor_ctl(&mut monitor, 714, "add");
    let readd_mirror = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Monitor
    })
    .expect("re-add ack mirror");
    assert_monitor_mirror(
        &readd_mirror,
        MirrorShape {
            mirror_seq: 1,
            client: monitor_peer,
            peer: MONITOR_OBJECT_ID,
            seq: 714,
            ty: MsgType::Status,
            send: true,
        },
        "re-add ack mirror",
    );
    let readd_ack = recv_until(&mut monitor, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 714
    })
    .expect("re-add ack");
    assert_eq!(
        find(&readd_ack.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "re-add ack status"
    );

    client
        .send(&Frame::to_broker(
            MsgType::Ping,
            715,
            EnvBuilder::new().finish(),
        ))
        .expect("send PING after re-add");
    for (mirror_seq, ty, send) in [
        (2, MsgType::Ping, false),
        (3, MsgType::Data, true),
        (4, MsgType::Status, true),
    ] {
        let mirror = recv_until(&mut monitor, Duration::from_secs(5), |f| {
            f.hdr.ty == MsgType::Monitor
        })
        .expect("PING after re-add mirror");
        assert_monitor_mirror(
            &mirror,
            MirrorShape {
                mirror_seq,
                client: client_peer,
                peer: 0,
                seq: 715,
                ty,
                send,
            },
            "PING after re-add mirror",
        );
    }
    recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Data && f.hdr.seq == 715
    })
    .expect("PING after re-add DATA");
    let readded_ping_status = recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 715
    })
    .expect("PING after re-add STATUS");
    assert_eq!(
        find(&readded_ping_status.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "PING after re-add status"
    );

    drop(client);
    drop(monitor);
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn monitor_registration_lifecycle_resets_seq(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(monitor_registration_lifecycle_resets_seq)
        ),
        arm,
        &monitor_registration_lifecycle_resets_seq_body,
    );
}

fn monitor_frame_from_client_replies_invalid_command_body(path: &str) {
    let mut client = UnixUbusTransport::connect(path).expect("client connect");
    recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("client HELLO");

    client
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Monitor,
                seq: 720,
                peer: 0,
            },
            payload: EnvBuilder::new().finish(),
        })
        .expect("send client MONITOR frame");
    let invalid = recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 720
    })
    .expect("client MONITOR invalid-command STATUS");
    assert_eq!(invalid.hdr.peer, 0, "invalid-command STATUS peer");
    assert_eq!(
        find(&invalid.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_INVALID_COMMAND as u32),
        "client MONITOR status"
    );

    client
        .send(&Frame::to_broker(
            MsgType::Ping,
            721,
            EnvBuilder::new().finish(),
        ))
        .expect("send PING after client MONITOR frame");
    recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Data && f.hdr.seq == 721
    })
    .expect("PING after client MONITOR DATA");
    let ping_status = recv_until(&mut client, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 721
    })
    .expect("PING after client MONITOR STATUS");
    assert_eq!(
        find(&ping_status.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
        Some(UBUS_STATUS_OK as u32),
        "PING after client MONITOR status"
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn monitor_frame_from_client_replies_invalid_command(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(monitor_frame_from_client_replies_invalid_command)
        ),
        arm,
        &monitor_frame_from_client_replies_invalid_command_body,
    );
}

/// Send ADD_OBJECT (no SIGNATURE, so the DATA payload stays OBJID-only
/// and byte-comparable with upstream) and assert the two-frame reply
/// shape via [`expect_data_then_status_ok`]. Returns the assigned id.
fn raw_add_object(transport: &mut UnixUbusTransport, seq: u16, path: &str) -> u32 {
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, path);
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send ADD_OBJECT");
    expect_data_then_status_ok(transport, seq, "ADD_OBJECT")
}

fn raw_add_anonymous(transport: &mut UnixUbusTransport, seq: u16) -> u32 {
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq,
                peer: 0,
            },
            payload: EnvBuilder::new().finish(),
        })
        .expect("send anonymous ADD_OBJECT");
    expect_data_then_status_ok(transport, seq, "anonymous ADD_OBJECT")
}

/// Builtin `ubus.event` system object id (`UBUS_SYSTEM_OBJECT_EVENT`).
const EVENT_OBJECT_ID: u32 = 1;

/// `ubus listen <pattern>`: INVOKE obj 1 `register` with DATA blobmsg
/// `{object, pattern}`; reads the STATUS(0) ack.
fn raw_event_register(
    transport: &mut UnixUbusTransport,
    seq: u16,
    listener_obj: u32,
    pattern: &str,
) {
    let data = BlobMsgTable::build(|b| {
        b.put_i32(Some("object"), listener_obj as i32);
        b.put_str(Some("pattern"), pattern);
    });
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, EVENT_OBJECT_ID);
    env.push_str(UbusAttr::Method, "register");
    env.push_data(data.contents());
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq,
                peer: EVENT_OBJECT_ID,
            },
            payload: env.finish(),
        })
        .expect("send event register");
    let ack = recv_until(transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == seq
    })
    .expect("event register ack");
    assert_eq!(
        find(&ack.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32),
        Some(UBUS_STATUS_OK),
        "event register ack status"
    );
}

/// `ubus send <id> {value}`: INVOKE obj 1 `send` with DATA blobmsg
/// `{id, data: {value}}`; reads the publisher's STATUS(0) ack (fan-out
/// lands on the listeners' sockets).
fn raw_event_send(transport: &mut UnixUbusTransport, seq: u16, event_name: &str, value: i32) {
    let data = BlobMsgTable::build(|b| {
        b.put_str(Some("id"), event_name);
        b.open_table(Some("data"));
        b.put_i32(Some("value"), value);
        b.close_table();
    });
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, EVENT_OBJECT_ID);
    env.push_str(UbusAttr::Method, "send");
    env.push_data(data.contents());
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq,
                peer: EVENT_OBJECT_ID,
            },
            payload: env.finish(),
        })
        .expect("send event send");
    let ack = recv_until(transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == seq
    })
    .expect("event send ack");
    assert_eq!(
        find(&ack.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32),
        Some(UBUS_STATUS_OK),
        "event send ack status"
    );
}

/// Assert a broker event fan-out INVOKE: `hdr.peer=0`, `hdr.seq` the
/// broker-global counter value, attrs `[ObjId(listener's own), Method
/// (event name), Data]`.
fn assert_event_fanout(frame: &Frame, seq: u16, listener_obj: u32, event_name: &str, what: &str) {
    assert_eq!(frame.hdr.ty, MsgType::Invoke, "{what} type");
    assert_eq!(frame.hdr.peer, 0, "{what} hdr.peer");
    assert_eq!(frame.hdr.seq, seq, "{what} seq");
    expect_attr_sequence(
        &frame.payload,
        &[UbusAttr::ObjId, UbusAttr::Method, UbusAttr::Data],
        what,
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(listener_obj),
        "{what} ObjId is the listener's own object"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Method).and_then(|a| a.as_str()),
        Some(event_name),
        "{what} event name"
    );
}

/// The `{id, path}` payload of a `ubus.object.add`/`remove` fan-out.
fn assert_object_event_payload(frame: &Frame, obj_id: u32, path: &str, what: &str) {
    let data = find(&frame.payload, UbusAttr::Data)
        .map(|a| a.payload)
        .unwrap_or(&[]);
    assert_eq!(
        blobmsg_lookup(data, "path").and_then(|r| r.as_str()),
        Some(path),
        "{what} payload path"
    );
    assert_eq!(
        blobmsg_lookup(data, "id")
            .and_then(|r| r.as_i32())
            .map(|v| v as u32),
        Some(obj_id),
        "{what} payload id"
    );
}

fn attr_id_sequence(payload: &[u8]) -> Vec<u8> {
    let inner = unwrap_envelope(payload).expect("valid envelope");
    iter_attrs(inner).map(|a| a.id).collect()
}

fn expect_attr_sequence(payload: &[u8], expected: &[UbusAttr], what: &str) {
    let expected: Vec<u8> = expected.iter().map(|id| *id as u8).collect();
    assert_eq!(attr_id_sequence(payload), expected, "{what} attr order");
}

fn subscriber_ids(payload: &[u8]) -> Vec<u32> {
    let subscribers = find(payload, UbusAttr::Subscribers).expect("Subscribers attr");
    ubus::blob::BlobAttr::iter(subscribers.payload)
        .map(|attr| {
            let attr = attr.expect("nested subscriber attr");
            assert_eq!(attr.id, 0, "subscriber nested attr id");
            assert_eq!(attr.payload.len(), 4, "subscriber nested attr payload");
            u32::from_be_bytes([
                attr.payload[0],
                attr.payload[1],
                attr.payload[2],
                attr.payload[3],
            ])
        })
        .collect()
}

fn assert_active_notify(frame: &Frame, seq: u16, obj_id: u32, active: u8, what: &str) {
    assert_eq!(frame.hdr.ty, MsgType::Notify, "{what} type");
    assert_eq!(frame.hdr.seq, seq, "{what} seq");
    assert_eq!(frame.hdr.peer, 0, "{what} hdr.peer");
    expect_attr_sequence(&frame.payload, &[UbusAttr::ObjId, UbusAttr::Active], what);
    assert_eq!(
        find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(obj_id),
        "{what} ObjId"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Active).map(|a| a.payload),
        Some(&[active][..]),
        "{what} Active"
    );
}

fn assert_notify_ack(frame: &Frame, seq: u16, publisher_obj: u32, subscribers: &[u32], what: &str) {
    assert_eq!(frame.hdr.ty, MsgType::Status, "{what} type");
    assert_eq!(frame.hdr.seq, seq, "{what} seq");
    assert_eq!(frame.hdr.peer, publisher_obj, "{what} hdr.peer");
    expect_attr_sequence(
        &frame.payload,
        &[UbusAttr::ObjId, UbusAttr::Subscribers, UbusAttr::Status],
        what,
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(publisher_obj),
        "{what} ObjId"
    );
    assert_eq!(
        subscriber_ids(&frame.payload),
        subscribers,
        "{what} Subscribers"
    );
    let s = find(&frame.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, UBUS_STATUS_OK, "{what} Status");
}

fn assert_forwarded_invoke_no_data(
    frame: &Frame,
    seq: u16,
    publisher_peer_id: u32,
    subscriber_obj_id: u32,
    method: &str,
    what: &str,
) {
    assert_eq!(frame.hdr.ty, MsgType::Invoke, "{what} type");
    assert_eq!(frame.hdr.seq, seq, "{what} seq");
    assert_eq!(frame.hdr.peer, publisher_peer_id, "{what} hdr.peer");
    expect_attr_sequence(
        &frame.payload,
        &[
            UbusAttr::ObjId,
            UbusAttr::Method,
            UbusAttr::User,
            UbusAttr::Group,
        ],
        what,
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(subscriber_obj_id),
        "{what} ObjId"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Method).and_then(|a| a.as_str()),
        Some(method),
        "{what} Method"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::User).and_then(|a| a.as_str()),
        Some("root"),
        "{what} User"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Group).and_then(|a| a.as_str()),
        Some("root"),
        "{what} Group"
    );
}

fn assert_forwarded_invoke_with_data(
    frame: &Frame,
    seq: u16,
    publisher_peer_id: u32,
    subscriber_obj_id: u32,
    method: &str,
    data: &[u8],
    what: &str,
) {
    assert_eq!(frame.hdr.ty, MsgType::Invoke, "{what} type");
    assert_eq!(frame.hdr.seq, seq, "{what} seq");
    assert_eq!(frame.hdr.peer, publisher_peer_id, "{what} hdr.peer");
    expect_attr_sequence(
        &frame.payload,
        &[
            UbusAttr::ObjId,
            UbusAttr::Method,
            UbusAttr::User,
            UbusAttr::Group,
            UbusAttr::Data,
        ],
        what,
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(subscriber_obj_id),
        "{what} ObjId"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Method).and_then(|a| a.as_str()),
        Some(method),
        "{what} Method"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::User).and_then(|a| a.as_str()),
        Some("root"),
        "{what} User"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Group).and_then(|a| a.as_str()),
        Some("root"),
        "{what} Group"
    );
    assert_eq!(
        find(&frame.payload, UbusAttr::Data).map(|a| a.payload),
        Some(data),
        "{what} Data"
    );
}

/// Assert the broker-originated ADD/REMOVE reply pair on `seq`: a DATA
/// frame carrying a non-zero OBJID must arrive strictly before a
/// STATUS(0), and that STATUS must NOT carry an OBJID attr (libubus
/// harvests the id from the DATA frame — the STATUS is status-only).
/// Returns the OBJID seen in the DATA frame.
fn expect_data_then_status_ok(transport: &mut UnixUbusTransport, seq: u16, what: &str) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut data_obj_id: Option<u32> = None;
    while Instant::now() < deadline {
        match transport.recv() {
            Ok(Some(f)) if f.hdr.seq == seq && f.hdr.ty == MsgType::Data => {
                let id = find(&f.payload, UbusAttr::ObjId)
                    .and_then(|a| a.as_u32())
                    .unwrap_or_else(|| panic!("{what} DATA must carry OBJID"));
                assert_ne!(id, 0, "{what} DATA OBJID must be non-zero");
                data_obj_id = Some(id);
            }
            Ok(Some(f)) if f.hdr.seq == seq && f.hdr.ty == MsgType::Status => {
                let id = data_obj_id.unwrap_or_else(|| panic!("{what} STATUS arrived before DATA"));
                let s = find(&f.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .expect("STATUS attr");
                assert_eq!(s, UBUS_STATUS_OK, "{what} STATUS must be 0");
                assert!(
                    find(&f.payload, UbusAttr::ObjId).is_none(),
                    "{what} STATUS must not carry OBJID — id rides the DATA frame"
                );
                return id;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("{what} recv: {e:?}"),
        }
    }
    panic!("{what}: DATA-then-STATUS reply timed out");
}

/// Assert a REMOVE_OBJECT error path on `seq`: a single STATUS with
/// `expected` and no preceding DATA frame.
fn expect_status_only(transport: &mut UnixUbusTransport, seq: u16, expected: i32, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match transport.recv() {
            Ok(Some(f)) if f.hdr.seq == seq && f.hdr.ty == MsgType::Data => {
                panic!("{what} must not emit a DATA frame: {:?}", f.hdr);
            }
            Ok(Some(f)) if f.hdr.seq == seq && f.hdr.ty == MsgType::Status => {
                let s = find(&f.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .expect("STATUS attr");
                assert_eq!(s, expected, "{what} status mismatch");
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("{what} recv: {e:?}"),
        }
    }
    panic!("{what}: STATUS reply timed out");
}

/// A successful ADD_OBJECT replies with DATA(OBJID) strictly before a
/// plain STATUS(0); libubus' `ubus_add_object` reads the id only from
/// the DATA frame, so a lone STATUS would fail a real client with
/// `UBUS_STATUS_NO_DATA`. No SIGNATURE, so upstream's DATA payload is
/// OBJID-only and byte-comparable with the rs broker.
fn add_object_replies_data_objid_then_status_ok_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let obj_id = raw_add_object(&mut transport, 40, "example.rawreg");
    assert_ne!(obj_id, 0, "broker must assign a non-zero obj id");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn add_object_replies_data_objid_then_status_ok(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(add_object_replies_data_objid_then_status_ok)
        ),
        arm,
        &add_object_replies_data_objid_then_status_ok_body,
    );
}

fn add_object_with_signature_replies_objid_and_objtype_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");

    let sig = signature_with_ping_method();
    let (obj_id_a, obj_type_a) =
        raw_add_object_with_signature(&mut transport, 45, "example.typed.a", &sig);
    let (obj_id_b, obj_type_b) =
        raw_add_object_with_signature(&mut transport, 46, "example.typed.b", &sig);

    assert_ne!(obj_id_a, 0);
    assert_ne!(obj_id_b, 0);
    assert_ne!(obj_type_a, 0);
    assert_ne!(obj_type_b, 0);
    assert_ne!(obj_id_a, obj_type_a);
    assert_ne!(obj_id_b, obj_type_b);
    assert_ne!(
        obj_type_a, obj_type_b,
        "byte-identical signatures must not deduplicate object types"
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn add_object_with_signature_replies_objid_and_objtype(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(add_object_with_signature_replies_objid_and_objtype)
        ),
        arm,
        &add_object_with_signature_replies_objid_and_objtype_body,
    );
}

/// Pathless ADD_OBJECT is how real libubus subscribers register their
/// anonymous notification object. Upstream still returns the normal
/// successful ADD_OBJECT pair: DATA(OBJID) then STATUS(0).
fn add_object_pathless_replies_data_objid_then_status_ok_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::AddObject,
                seq: 43,
                peer: 0,
            },
            payload: EnvBuilder::new().finish(),
        })
        .expect("send pathless ADD_OBJECT");
    let obj_id = expect_data_then_status_ok(&mut transport, 43, "pathless ADD_OBJECT");
    assert_ne!(obj_id, 0, "broker must assign a non-zero anonymous obj id");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn add_object_pathless_replies_data_objid_then_status_ok(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(add_object_pathless_replies_data_objid_then_status_ok)
        ),
        arm,
        &add_object_pathless_replies_data_objid_then_status_ok_body,
    );
}

/// REMOVE_OBJECT of an owned object replies with the same two-frame
/// shape: DATA(OBJID) then STATUS(0), on the same connection that
/// registered it.
fn remove_object_replies_data_objid_then_status_ok_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let obj_id = raw_add_object(&mut transport, 41, "example.rawreg");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj_id);
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 42,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send REMOVE_OBJECT");
    let removed = expect_data_then_status_ok(&mut transport, 42, "REMOVE_OBJECT");
    assert_eq!(
        removed, obj_id,
        "REMOVE_OBJECT DATA must carry the removed obj id"
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn remove_object_replies_data_objid_then_status_ok(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(remove_object_replies_data_objid_then_status_ok)
        ),
        arm,
        &remove_object_replies_data_objid_then_status_ok_body,
    );
}

fn remove_object_typed_echoes_add_objtype_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let sig = signature_with_ping_method();
    let (obj_id, obj_type) =
        raw_add_object_with_signature(&mut transport, 47, "example.typed.remove", &sig);

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj_id);
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 48,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send typed REMOVE_OBJECT");
    let (removed_id, removed_type) =
        expect_typed_data_then_status_ok(&mut transport, 48, "typed REMOVE_OBJECT");
    assert_eq!(removed_id, obj_id);
    assert_eq!(removed_type, obj_type);
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn remove_object_typed_echoes_add_objtype(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(remove_object_typed_echoes_add_objtype)
        ),
        arm,
        &remove_object_typed_echoes_add_objtype_body,
    );
}

fn lookup_exact_typed_carries_path_id_type_signature_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let sig = signature_with_ping_method();
    let (obj_id, obj_type) =
        raw_add_object_with_signature(&mut transport, 49, "example.typed.lookup", &sig);

    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "example.typed.lookup");
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 50,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send exact typed LOOKUP");

    let data = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.seq == 50 && f.hdr.ty == MsgType::Data
    })
    .expect("typed LOOKUP DATA");
    expect_attr_sequence(
        &data.payload,
        &[
            UbusAttr::ObjPath,
            UbusAttr::ObjId,
            UbusAttr::ObjType,
            UbusAttr::Signature,
        ],
        "typed LOOKUP DATA",
    );
    assert_eq!(
        find(&data.payload, UbusAttr::ObjPath).and_then(|a| a.as_str()),
        Some("example.typed.lookup")
    );
    assert_eq!(
        find(&data.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(obj_id)
    );
    assert_eq!(
        find(&data.payload, UbusAttr::ObjType).and_then(|a| a.as_u32()),
        Some(obj_type)
    );
    assert_eq!(
        find(&data.payload, UbusAttr::Signature).map(|a| a.as_blobmsg()),
        Some(sig.as_slice())
    );

    let status = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.seq == 50 && f.hdr.ty == MsgType::Status
    })
    .expect("typed LOOKUP STATUS");
    let s = find(&status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, UBUS_STATUS_OK);
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn lookup_exact_typed_carries_path_id_type_signature(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(lookup_exact_typed_carries_path_id_type_signature)
        ),
        arm,
        &lookup_exact_typed_carries_path_id_type_signature_body,
    );
}

fn lookup_exact_untyped_is_status_only_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let obj_id = raw_add_object(&mut transport, 51, "example.untyped.lookup");
    assert_ne!(obj_id, 0);

    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "example.untyped.lookup");
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 52,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send exact untyped LOOKUP");
    expect_status_only(&mut transport, 52, UBUS_STATUS_OK, "exact untyped LOOKUP");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn lookup_exact_untyped_is_status_only(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(lookup_exact_untyped_is_status_only)
        ),
        arm,
        &lookup_exact_untyped_is_status_only_body,
    );
}

fn lookup_all_lists_only_typed_objects_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let sig = signature_with_ping_method();
    let (typed_id, typed_type) =
        raw_add_object_with_signature(&mut transport, 53, "example.lookup.typed", &sig);
    let untyped_id = raw_add_object(&mut transport, 54, "example.lookup.untyped");
    let anon_id = raw_add_anonymous(&mut transport, 55);
    assert_ne!(untyped_id, typed_id);
    assert_ne!(anon_id, typed_id);

    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 56,
                peer: 0,
            },
            payload: EnvBuilder::new().finish(),
        })
        .expect("send list-all LOOKUP");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut paths = Vec::new();
    while Instant::now() < deadline {
        match transport.recv() {
            Ok(Some(f)) if f.hdr.seq == 56 && f.hdr.ty == MsgType::Data => {
                expect_attr_sequence(
                    &f.payload,
                    &[
                        UbusAttr::ObjPath,
                        UbusAttr::ObjId,
                        UbusAttr::ObjType,
                        UbusAttr::Signature,
                    ],
                    "list-all LOOKUP DATA",
                );
                let obj_path = find(&f.payload, UbusAttr::ObjPath)
                    .and_then(|a| a.as_str())
                    .expect("ObjPath attr")
                    .to_owned();
                assert_eq!(
                    find(&f.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
                    Some(typed_id),
                    "list-all must not include untyped or anonymous object ids"
                );
                assert_eq!(
                    find(&f.payload, UbusAttr::ObjType).and_then(|a| a.as_u32()),
                    Some(typed_type)
                );
                assert_eq!(
                    find(&f.payload, UbusAttr::Signature).map(|a| a.as_blobmsg()),
                    Some(sig.as_slice())
                );
                paths.push(obj_path);
            }
            Ok(Some(f)) if f.hdr.seq == 56 && f.hdr.ty == MsgType::Status => {
                let s = find(&f.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .expect("STATUS attr");
                assert_eq!(s, UBUS_STATUS_OK);
                assert_eq!(paths, vec!["example.lookup.typed"]);
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("list-all LOOKUP recv: {e:?}"),
        }
    }
    panic!("list-all LOOKUP STATUS timeout");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn lookup_all_lists_only_typed_objects(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(lookup_all_lists_only_typed_objects)
        ),
        arm,
        &lookup_all_lists_only_typed_objects_body,
    );
}

fn lookup_pattern_matches_subset_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let sig = signature_with_ping_method();
    // Upstream `ubusd` honours only a *trailing* `*` (prefix match); the
    // remainder is literal. Register two objects sharing the `example.a`
    // prefix plus one outside it, and confirm `example.a*` selects the
    // subset in path order and excludes `example.gamma`.
    let (alpha_id, alpha_type) =
        raw_add_object_with_signature(&mut transport, 57, "example.alpha", &sig);
    let (alpine_id, alpine_type) =
        raw_add_object_with_signature(&mut transport, 58, "example.alpine", &sig);
    let (gamma_id, _) = raw_add_object_with_signature(&mut transport, 59, "example.gamma", &sig);
    assert_ne!(alpha_id, alpine_id);
    assert_ne!(alpha_id, gamma_id);

    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "example.a*");
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 60,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send pattern LOOKUP");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut rows = Vec::new();
    while Instant::now() < deadline {
        match transport.recv() {
            Ok(Some(f)) if f.hdr.seq == 60 && f.hdr.ty == MsgType::Data => {
                expect_attr_sequence(
                    &f.payload,
                    &[
                        UbusAttr::ObjPath,
                        UbusAttr::ObjId,
                        UbusAttr::ObjType,
                        UbusAttr::Signature,
                    ],
                    "pattern LOOKUP DATA",
                );
                let obj_path = find(&f.payload, UbusAttr::ObjPath)
                    .and_then(|a| a.as_str())
                    .expect("ObjPath attr")
                    .to_owned();
                let obj_id = find(&f.payload, UbusAttr::ObjId)
                    .and_then(|a| a.as_u32())
                    .expect("ObjId attr");
                let obj_type = find(&f.payload, UbusAttr::ObjType)
                    .and_then(|a| a.as_u32())
                    .expect("ObjType attr");
                assert_eq!(
                    find(&f.payload, UbusAttr::Signature).map(|a| a.as_blobmsg()),
                    Some(sig.as_slice())
                );
                rows.push((obj_path, obj_id, obj_type));
            }
            Ok(Some(f)) if f.hdr.seq == 60 && f.hdr.ty == MsgType::Status => {
                let s = find(&f.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .expect("STATUS attr");
                assert_eq!(s, UBUS_STATUS_OK);
                assert_eq!(
                    rows,
                    vec![
                        ("example.alpha".to_string(), alpha_id, alpha_type),
                        ("example.alpine".to_string(), alpine_id, alpine_type),
                    ],
                    "trailing-* prefix LOOKUP returns matching typed objects in path order"
                );
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("pattern LOOKUP recv: {e:?}"),
        }
    }
    panic!("pattern LOOKUP STATUS timeout");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn lookup_pattern_matches_subset(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(lookup_pattern_matches_subset)
        ),
        arm,
        &lookup_pattern_matches_subset_body,
    );
}

fn lookup_pattern_no_match_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let sig = signature_with_ping_method();
    raw_add_object_with_signature(&mut transport, 61, "example.alpha", &sig);

    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "example.z*");
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Lookup,
                seq: 62,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send no-match pattern LOOKUP");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match transport.recv() {
            Ok(Some(f)) if f.hdr.seq == 62 && f.hdr.ty == MsgType::Data => {
                panic!("no-match pattern LOOKUP must not emit DATA: {:?}", f.hdr);
            }
            Ok(Some(f)) if f.hdr.seq == 62 && f.hdr.ty == MsgType::Status => {
                assert!(
                    find(&f.payload, UbusAttr::Status).is_some(),
                    "terminal STATUS must carry status attr"
                );
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("no-match pattern LOOKUP recv: {e:?}"),
        }
    }
    panic!("no-match pattern LOOKUP STATUS timeout");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn lookup_pattern_no_match(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!("ubusd_handshake ", stringify!(lookup_pattern_no_match)),
        arm,
        &lookup_pattern_no_match_body,
    );
}

/// REMOVE_OBJECT for an obj id no broker knows about reports
/// `UBUS_STATUS_NOT_FOUND` — a single STATUS, no DATA.
fn remove_object_unknown_objid_reports_not_found_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, 0x7fff_ffff);
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::RemoveObject,
                seq: 43,
                peer: 0,
            },
            payload: env.finish(),
        })
        .expect("send REMOVE_OBJECT unknown id");
    expect_status_only(
        &mut transport,
        43,
        UBUS_STATUS_NOT_FOUND,
        "REMOVE_OBJECT unknown id",
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn remove_object_unknown_objid_reports_not_found(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(remove_object_unknown_objid_reports_not_found)
        ),
        arm,
        &remove_object_unknown_objid_reports_not_found_body,
    );
}

/// REMOVE_OBJECT for an object owned by a *different* client reports
/// `UBUS_STATUS_PERMISSION_DENIED`. Owner A registers via `OwnerThread`;
/// a side `UbusClient::lookup` resolves A's obj id (mirrors the other
/// bodies); raw connection B — which owns nothing — tries to remove it.
fn remove_object_not_owner_reports_permission_denied_body(path: &str) {
    let path = path.to_owned();

    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example.rawreg.owned").method("ping", |_| Ok(BlobMsgTable::build(|_| {})))
    });
    owner.wait_ready();

    let probe_transport = UnixUbusTransport::connect(&path).expect("probe connect");
    let mut probe = UbusClient::connect(probe_transport).expect("probe hello");
    let obj_id = probe.lookup("example.rawreg.owned").expect("lookup");
    assert_ne!(obj_id, 0, "broker should assign a non-zero obj_id");

    let mut b = UnixUbusTransport::connect(&path).expect("b connect");
    recv_until(&mut b, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("b HELLO");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj_id);
    b.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::RemoveObject,
            seq: 44,
            peer: 0,
        },
        payload: env.finish(),
    })
    .expect("send REMOVE_OBJECT for A's obj");
    expect_status_only(
        &mut b,
        44,
        UBUS_STATUS_PERMISSION_DENIED,
        "REMOVE_OBJECT non-owner",
    );

    owner.shutdown();
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn remove_object_not_owner_reports_permission_denied(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(remove_object_not_owner_reports_permission_denied)
        ),
        arm,
        &remove_object_not_owner_reports_permission_denied_body,
    );
}

/// Upstream `ubusd` replies to a redundant client HELLO with
/// `STATUS = UBUS_STATUS_INVALID_COMMAND` (1) on the HELLO's seq.
/// The in-tree broker mirrors that bytes-for-bytes; any divergence
/// would let a libubus client decode the two brokers' replies
/// differently. Send HELLO+PING back-to-back, expect two STATUS
/// frames after the HELLO reply: PING → DATA echo, then status=0.
fn redundant_client_hello_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    let hello = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("unsolicited HELLO");
    let peer_id = hello.hdr.peer;

    // 4-byte empty envelope (not bare-header) so back-to-back sends
    // decode cleanly — bare headers are only safe at EOF.
    let env = EnvBuilder::new().finish();
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Hello,
                seq: 11,
                peer: peer_id,
            },
            payload: env.clone(),
        })
        .expect("send redundant HELLO");
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Ping,
                seq: 12,
                peer: peer_id,
            },
            payload: env,
        })
        .expect("send PING");

    let hello_reply = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 11
    })
    .expect("redundant-HELLO STATUS reply");
    let s = find(&hello_reply.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(
        s, UBUS_STATUS_INVALID_COMMAND,
        "redundant HELLO must yield UBUS_STATUS_INVALID_COMMAND (1)"
    );

    let ping_data = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Data && f.hdr.seq == 12
    })
    .expect("PING DATA reply");
    assert_eq!(ping_data.hdr.peer, peer_id, "PING DATA must echo hdr.peer");
    assert_eq!(
        ping_data.payload,
        EnvBuilder::new().finish(),
        "PING DATA must echo the request envelope"
    );

    let ping_reply = recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 12
    })
    .expect("PING STATUS reply");
    let s = find(&ping_reply.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, 0, "PING must succeed");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn redundant_client_hello_replies_with_invalid_command_status(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(redundant_client_hello_replies_with_invalid_command_status)
        ),
        arm,
        &redundant_client_hello_body,
    );
}

fn notify_ack_carries_subscriber_obj_ids_body(path: &str) {
    let mut owner = UnixUbusTransport::connect(path).expect("owner connect");
    recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("owner HELLO");
    let publisher_obj = raw_add_object(&mut owner, 70, "example.notify.ack");

    let mut sub = UnixUbusTransport::connect(path).expect("subscriber connect");
    recv_until(&mut sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("subscriber HELLO");
    let subscriber_obj = raw_add_anonymous(&mut sub, 71);

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, subscriber_obj);
    env.push_u32(UbusAttr::Target, publisher_obj);
    sub.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Subscribe,
            seq: 72,
            peer: publisher_obj,
        },
        payload: env.finish(),
    })
    .expect("send SUBSCRIBE");

    let active = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify && f.hdr.seq == 1
    })
    .expect("owner Active=1");
    assert_active_notify(&active, 1, publisher_obj, 1, "subscribe Active=1");
    let sub_status = recv_until(&mut sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 72
    })
    .expect("SUBSCRIBE STATUS");
    let s = find(&sub_status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, UBUS_STATUS_OK, "SUBSCRIBE status");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, publisher_obj);
    env.push_str(UbusAttr::Method, "fanout");
    owner
        .send(&Frame::to_peer(
            MsgType::Notify,
            73,
            publisher_obj,
            env.finish(),
        ))
        .expect("send NOTIFY");

    let ack = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 73
    })
    .expect("NOTIFY ack");
    assert_notify_ack(
        &ack,
        73,
        publisher_obj,
        &[subscriber_obj],
        "NOTIFY publisher ack",
    );

    // Deterministic teardown: close the publisher first and let the
    // subscriber READ the broker-minted Unsubscribe (object died) so
    // the frame lands in both brokers' transcripts instead of racing
    // the subscriber's own close.
    drop(owner);
    let unsub = recv_until(&mut sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Unsubscribe
    })
    .expect("broker-minted Unsubscribe after publisher death");
    assert_eq!(unsub.hdr.peer, 0, "broker-minted Unsubscribe peer");
    assert_eq!(
        find(&unsub.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(subscriber_obj),
        "Unsubscribe ObjId must be the subscriber's own object"
    );
    assert_eq!(
        find(&unsub.payload, UbusAttr::Target).and_then(|a| a.as_u32()),
        Some(publisher_obj),
        "Unsubscribe Target must be the dead publisher object"
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn notify_ack_carries_subscriber_obj_ids(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(notify_ack_carries_subscriber_obj_ids)
        ),
        arm,
        &notify_ack_carries_subscriber_obj_ids_body,
    );
}

fn notify_no_reply_int8_suppresses_publisher_ack_body(path: &str) {
    let mut publisher = UnixUbusTransport::connect(path).expect("publisher connect");
    let publisher_hello = recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("publisher HELLO");
    let (publisher_obj, _) = raw_add_object_with_signature(
        &mut publisher,
        80,
        "example.notify.no-reply.int8",
        &signature_with_ping_method(),
    );

    let mut subscriber = UnixUbusTransport::connect(path).expect("subscriber connect");
    recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("subscriber HELLO");
    let subscriber_obj = raw_add_anonymous(&mut subscriber, 81);
    let mut subscribe = EnvBuilder::new();
    subscribe.push_u32(UbusAttr::ObjId, subscriber_obj);
    subscribe.push_u32(UbusAttr::Target, publisher_obj);
    subscriber
        .send(&Frame::to_peer(
            MsgType::Subscribe,
            82,
            publisher_obj,
            subscribe.finish(),
        ))
        .expect("SUBSCRIBE");
    let active = recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify && f.hdr.seq == 1
    })
    .expect("publisher Active=1");
    assert_active_notify(&active, 1, publisher_obj, 1, "subscribe Active=1");
    recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 82
    })
    .expect("SUBSCRIBE STATUS");

    let mut notify = EnvBuilder::new();
    notify.push_u32(UbusAttr::ObjId, publisher_obj);
    notify.push_str(UbusAttr::Method, "evt1");
    notify.push_u8(UbusAttr::NoReply, 1);
    publisher
        .send(&Frame::to_peer(
            MsgType::Notify,
            83,
            publisher_obj,
            notify.finish(),
        ))
        .expect("NOTIFY NoReply");
    publisher
        .send(&Frame::to_peer(
            MsgType::Ping,
            84,
            publisher_obj,
            EnvBuilder::new().finish(),
        ))
        .expect("PING barrier");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_ping_status = false;
    while Instant::now() < deadline && !saw_ping_status {
        match publisher.recv() {
            Ok(Some(f)) if f.hdr.ty == MsgType::Status && f.hdr.seq == 83 => {
                panic!("NoReply NOTIFY must not send a publisher STATUS ack")
            }
            Ok(Some(f)) if f.hdr.ty == MsgType::Status && f.hdr.seq == 84 => {
                assert_eq!(
                    find(&f.payload, UbusAttr::Status)
                        .and_then(|a| a.as_u32())
                        .map(|u| u as i32),
                    Some(UBUS_STATUS_OK),
                    "PING barrier status"
                );
                saw_ping_status = true;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("publisher recv: {e:?}"),
        }
    }
    assert!(saw_ping_status, "PING barrier STATUS missing");

    let fanout = recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke && f.hdr.seq == 83
    })
    .expect("subscriber fan-out");
    assert_eq!(
        fanout.hdr.peer, publisher_hello.hdr.peer,
        "fan-out hdr.peer"
    );
    expect_attr_sequence(
        &fanout.payload,
        &[
            UbusAttr::NoReply,
            UbusAttr::ObjId,
            UbusAttr::Method,
            UbusAttr::User,
            UbusAttr::Group,
        ],
        "NoReply fan-out",
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::NoReply).map(|a| a.payload),
        Some(&[1][..]),
        "NoReply fan-out payload"
    );
    assert_eq!(
        find(&fanout.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(subscriber_obj),
        "NoReply fan-out ObjId"
    );

    drop(publisher);
    let unsub = recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Unsubscribe
    })
    .expect("broker-minted Unsubscribe after publisher death");
    assert_eq!(
        find(&unsub.payload, UbusAttr::Target).and_then(|a| a.as_u32()),
        Some(publisher_obj)
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn notify_no_reply_int8_suppresses_publisher_ack(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(notify_no_reply_int8_suppresses_publisher_ack)
        ),
        arm,
        &notify_no_reply_int8_suppresses_publisher_ack_body,
    );
}

fn notify_no_reply_u32_encoding_still_acks_body(path: &str) {
    let mut publisher = UnixUbusTransport::connect(path).expect("publisher connect");
    recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("publisher HELLO");
    let (publisher_obj, _) = raw_add_object_with_signature(
        &mut publisher,
        90,
        "example.notify.no-reply.u32",
        &signature_with_ping_method(),
    );

    let mut subscriber = UnixUbusTransport::connect(path).expect("subscriber connect");
    recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("subscriber HELLO");
    let subscriber_obj = raw_add_anonymous(&mut subscriber, 91);
    let mut subscribe = EnvBuilder::new();
    subscribe.push_u32(UbusAttr::ObjId, subscriber_obj);
    subscribe.push_u32(UbusAttr::Target, publisher_obj);
    subscriber
        .send(&Frame::to_peer(
            MsgType::Subscribe,
            92,
            publisher_obj,
            subscribe.finish(),
        ))
        .expect("SUBSCRIBE");
    let active = recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify && f.hdr.seq == 1
    })
    .expect("publisher Active=1");
    assert_active_notify(&active, 1, publisher_obj, 1, "subscribe Active=1");
    recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 92
    })
    .expect("SUBSCRIBE STATUS");

    let mut notify = EnvBuilder::new();
    notify.push_u32(UbusAttr::ObjId, publisher_obj);
    notify.push_str(UbusAttr::Method, "evt1");
    notify.push_u32(UbusAttr::NoReply, 1);
    publisher
        .send(&Frame::to_peer(
            MsgType::Notify,
            93,
            publisher_obj,
            notify.finish(),
        ))
        .expect("NOTIFY u32 NoReply");
    let ack = recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 93
    })
    .expect("NOTIFY ack");
    assert_notify_ack(
        &ack,
        93,
        publisher_obj,
        &[subscriber_obj],
        "u32 NoReply NOTIFY ack",
    );

    let fanout = recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke && f.hdr.seq == 93
    })
    .expect("subscriber fan-out");
    expect_attr_sequence(
        &fanout.payload,
        &[
            UbusAttr::ObjId,
            UbusAttr::Method,
            UbusAttr::User,
            UbusAttr::Group,
        ],
        "u32 NoReply fan-out",
    );
    assert!(find(&fanout.payload, UbusAttr::NoReply).is_none());

    drop(publisher);
    recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Unsubscribe
    })
    .expect("broker-minted Unsubscribe after publisher death");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn notify_no_reply_u32_encoding_still_acks(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(notify_no_reply_u32_encoding_still_acks)
        ),
        arm,
        &notify_no_reply_u32_encoding_still_acks_body,
    );
}

fn invoke_no_reply_attr_is_not_forwarded_to_owner_body(path: &str) {
    let mut owner = UnixUbusTransport::connect(path).expect("owner connect");
    recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("owner HELLO");
    let (owner_obj, _) = raw_add_object_with_signature(
        &mut owner,
        100,
        "example.invoke.no-reply",
        &signature_with_ping_method(),
    );

    let mut caller = UnixUbusTransport::connect(path).expect("caller connect");
    let caller_hello = recv_until(&mut caller, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("caller HELLO");
    let mut invoke = EnvBuilder::new();
    invoke.push_u32(UbusAttr::ObjId, owner_obj);
    invoke.push_str(UbusAttr::Method, "ping");
    invoke.push_u8(UbusAttr::NoReply, 1);
    caller
        .send(&Frame::to_peer(
            MsgType::Invoke,
            101,
            owner_obj,
            invoke.finish(),
        ))
        .expect("INVOKE NoReply");

    let forwarded = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke && f.hdr.seq == 101
    })
    .expect("forwarded INVOKE");
    assert_eq!(
        forwarded.hdr.peer, caller_hello.hdr.peer,
        "forwarded caller peer"
    );
    expect_attr_sequence(
        &forwarded.payload,
        &[
            UbusAttr::ObjId,
            UbusAttr::Method,
            UbusAttr::User,
            UbusAttr::Group,
        ],
        "forwarded NoReply INVOKE",
    );
    assert!(find(&forwarded.payload, UbusAttr::NoReply).is_none());

    let mut reply = EnvBuilder::new();
    reply.push_i32(UbusAttr::Status, UBUS_STATUS_OK);
    reply.push_u32(UbusAttr::ObjId, owner_obj);
    owner
        .send(&Frame::to_peer(
            MsgType::Status,
            101,
            forwarded.hdr.peer,
            reply.finish(),
        ))
        .expect("owner STATUS reply");
    let status = recv_until(&mut caller, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 101
    })
    .expect("caller STATUS reply");
    assert_eq!(status.hdr.peer, owner_obj, "routed STATUS peer");
    expect_attr_sequence(
        &status.payload,
        &[UbusAttr::Status, UbusAttr::ObjId],
        "routed NoReply INVOKE STATUS",
    );
    assert_eq!(
        find(&status.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32),
        Some(UBUS_STATUS_OK)
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn invoke_no_reply_attr_is_not_forwarded_to_owner(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(invoke_no_reply_attr_is_not_forwarded_to_owner)
        ),
        arm,
        &invoke_no_reply_attr_is_not_forwarded_to_owner_body,
    );
}

fn explicit_unsubscribe_acks_and_notifies_owner_body(path: &str) {
    let mut owner = UnixUbusTransport::connect(path).expect("owner connect");
    recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("owner HELLO");
    let (publisher_obj, _) = raw_add_object_with_signature(
        &mut owner,
        80,
        "example.unsubscribe.explicit",
        &signature_with_ping_method(),
    );

    let mut sub = UnixUbusTransport::connect(path).expect("subscriber connect");
    recv_until(&mut sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("subscriber HELLO");
    let subscriber_obj = raw_add_anonymous(&mut sub, 81);

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, subscriber_obj);
    env.push_u32(UbusAttr::Target, publisher_obj);
    sub.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Subscribe,
            seq: 82,
            peer: publisher_obj,
        },
        payload: env.finish(),
    })
    .expect("send SUBSCRIBE");

    let active_one = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify && f.hdr.seq == 1
    })
    .expect("owner Active=1");
    assert_active_notify(&active_one, 1, publisher_obj, 1, "subscribe Active=1");
    let sub_status = recv_until(&mut sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 82
    })
    .expect("SUBSCRIBE STATUS");
    let s = find(&sub_status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, UBUS_STATUS_OK, "SUBSCRIBE status");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, subscriber_obj);
    env.push_u32(UbusAttr::Target, publisher_obj);
    sub.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Unsubscribe,
            seq: 83,
            peer: publisher_obj,
        },
        payload: env.finish(),
    })
    .expect("send UNSUBSCRIBE");

    let unsub_status = recv_until(&mut sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 83
    })
    .expect("UNSUBSCRIBE STATUS");
    let s = find(&unsub_status.payload, UbusAttr::Status)
        .and_then(|a| a.as_u32())
        .map(|u| u as i32)
        .expect("STATUS attr");
    assert_eq!(s, UBUS_STATUS_OK, "UNSUBSCRIBE status");
    let active_zero = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify && f.hdr.seq == 2
    })
    .expect("owner Active=0");
    assert_active_notify(&active_zero, 2, publisher_obj, 0, "unsubscribe Active=0");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, publisher_obj);
    env.push_str(UbusAttr::Method, "fanout");
    owner
        .send(&Frame::to_peer(
            MsgType::Notify,
            84,
            publisher_obj,
            env.finish(),
        ))
        .expect("send post-unsubscribe NOTIFY");

    let ack = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 84
    })
    .expect("post-unsubscribe NOTIFY ack");
    assert_notify_ack(&ack, 84, publisher_obj, &[], "post-unsubscribe NOTIFY ack");
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn explicit_unsubscribe_acks_and_notifies_owner(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(explicit_unsubscribe_acks_and_notifies_owner)
        ),
        arm,
        &explicit_unsubscribe_acks_and_notifies_owner_body,
    );
}

fn notify_replies_route_back_to_publisher_body(path: &str) {
    let mut publisher = UnixUbusTransport::connect(path).expect("publisher connect");
    let publisher_hello = recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("publisher HELLO");
    let publisher_obj = raw_add_object_with_signature(
        &mut publisher,
        90,
        "example.notify.reply",
        &signature_with_ping_method(),
    )
    .0;

    let mut subscriber = UnixUbusTransport::connect(path).expect("subscriber connect");
    recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("subscriber HELLO");
    let subscriber_obj = raw_add_anonymous(&mut subscriber, 91);

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, subscriber_obj);
    env.push_u32(UbusAttr::Target, publisher_obj);
    subscriber
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq: 92,
                peer: publisher_obj,
            },
            payload: env.finish(),
        })
        .expect("send SUBSCRIBE");

    let active_one = recv_until(&mut publisher, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify && f.hdr.seq == 1
    })
    .expect("publisher Active=1");
    assert_active_notify(&active_one, 1, publisher_obj, 1, "subscribe Active=1");
    recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 92
    })
    .expect("SUBSCRIBE STATUS");

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, publisher_obj);
    env.push_str(UbusAttr::Method, "fanout");
    publisher
        .send(&Frame::to_peer(
            MsgType::Notify,
            93,
            publisher_obj,
            env.finish(),
        ))
        .expect("send NOTIFY");

    let fanout = recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Invoke
    })
    .expect("subscriber fan-out");
    assert_forwarded_invoke_no_data(
        &fanout,
        93,
        publisher_hello.hdr.peer,
        subscriber_obj,
        "fanout",
        "NOTIFY fan-out",
    );

    let reply = BlobMsgTable::build(|bb| {
        bb.put_str(Some("reply"), "ok");
    });
    let mut data_env = EnvBuilder::new();
    data_env.push_u32(UbusAttr::ObjId, subscriber_obj);
    data_env.push_data(reply.contents());
    subscriber
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Data,
                seq: fanout.hdr.seq,
                peer: fanout.hdr.peer,
            },
            payload: data_env.finish(),
        })
        .expect("send subscriber DATA reply");
    let mut status_env = EnvBuilder::new();
    status_env.push_u32(UbusAttr::ObjId, subscriber_obj);
    status_env.push_i32(UbusAttr::Status, UBUS_STATUS_OK);
    subscriber
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Status,
                seq: fanout.hdr.seq,
                peer: fanout.hdr.peer,
            },
            payload: status_env.finish(),
        })
        .expect("send subscriber STATUS reply");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_notify_ack = false;
    let mut saw_routed_data = false;
    let mut saw_routed_status = false;
    while Instant::now() < deadline && !(saw_notify_ack && saw_routed_data) {
        match publisher.recv() {
            Ok(Some(f)) if f.hdr.ty == MsgType::Status && f.hdr.seq == 93 => {
                assert_notify_ack(
                    &f,
                    93,
                    publisher_obj,
                    &[subscriber_obj],
                    "NOTIFY publisher ack",
                );
                saw_notify_ack = true;
            }
            Ok(Some(f)) if f.hdr.ty == MsgType::Data && f.hdr.seq == fanout.hdr.seq => {
                assert_eq!(
                    find(&f.payload, UbusAttr::Data).map(|a| a.payload),
                    Some(reply.contents()),
                    "routed subscriber DATA payload"
                );
                saw_routed_data = true;
            }
            Ok(Some(f)) if f.hdr.ty == MsgType::Status && f.hdr.seq == fanout.hdr.seq => {
                let s = find(&f.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .expect("routed STATUS attr");
                assert_eq!(s, UBUS_STATUS_OK, "routed subscriber STATUS");
                saw_routed_status = true;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("publisher recv: {e:?}"),
        }
    }
    assert!(
        saw_notify_ack,
        "publisher must receive NOTIFY Subscribers ack"
    );
    assert!(
        saw_routed_data,
        "publisher must receive routed subscriber DATA"
    );

    let drain_deadline = Instant::now() + Duration::from_millis(200);
    while !saw_routed_status && Instant::now() < drain_deadline {
        match publisher.recv() {
            Ok(Some(f)) if f.hdr.ty == MsgType::Status && f.hdr.seq == fanout.hdr.seq => {
                let s = find(&f.payload, UbusAttr::Status)
                    .and_then(|a| a.as_u32())
                    .map(|u| u as i32)
                    .expect("routed STATUS attr");
                assert_eq!(s, UBUS_STATUS_OK, "routed subscriber STATUS");
                saw_routed_status = true;
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("publisher drain: {e:?}"),
        }
    }

    // Deterministic teardown: close the publisher first and let the
    // subscriber read the broker-minted Unsubscribe for the dead object.
    drop(publisher);
    let unsub = recv_until(&mut subscriber, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Unsubscribe
    })
    .expect("broker-minted Unsubscribe after publisher death");
    assert_eq!(
        find(&unsub.payload, UbusAttr::Target).and_then(|a| a.as_u32()),
        Some(publisher_obj),
        "Unsubscribe Target must be the dead publisher object"
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn notify_replies_route_back_to_publisher(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(notify_replies_route_back_to_publisher)
        ),
        arm,
        &notify_replies_route_back_to_publisher_body,
    );
}

fn unsubscribe_or_disconnect_sends_active_zero_body(path: &str) {
    let mut owner = UnixUbusTransport::connect(path).expect("owner connect");
    recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("owner HELLO");
    let publisher_obj = raw_add_object(&mut owner, 80, "example.active.zero");

    let mut sub = UnixUbusTransport::connect(path).expect("subscriber connect");
    recv_until(&mut sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("subscriber HELLO");
    let subscriber_obj = raw_add_anonymous(&mut sub, 81);

    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, subscriber_obj);
    env.push_u32(UbusAttr::Target, publisher_obj);
    sub.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Subscribe,
            seq: 82,
            peer: publisher_obj,
        },
        payload: env.finish(),
    })
    .expect("send SUBSCRIBE");

    let active_one = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify && f.hdr.seq == 1
    })
    .expect("owner Active=1");
    assert_active_notify(&active_one, 1, publisher_obj, 1, "subscribe Active=1");
    recv_until(&mut sub, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 82
    })
    .expect("SUBSCRIBE STATUS");

    drop(sub);

    let active_zero = recv_until(&mut owner, Duration::from_secs(3), |f| {
        f.hdr.ty == MsgType::Notify && f.hdr.seq == 2
    })
    .expect("owner Active=0");
    assert_active_notify(
        &active_zero,
        2,
        publisher_obj,
        0,
        "subscriber disconnect Active=0",
    );
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn unsubscribe_or_disconnect_sends_active_zero(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(unsubscribe_or_disconnect_sends_active_zero)
        ),
        arm,
        &unsubscribe_or_disconnect_sends_active_zero_body,
    );
}

fn raw_connection(path: &str) -> UnixUbusTransport {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Hello
    })
    .expect("HELLO");
    transport
}

fn send_and_expect_status(
    transport: &mut UnixUbusTransport,
    ty: MsgType,
    seq: u16,
    peer: u32,
    payload: Vec<u8>,
    expected: i32,
) {
    transport
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty,
                seq,
                peer,
            },
            payload,
        })
        .expect("send request");
    let status = recv_until(transport, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == seq
    })
    .expect("STATUS");
    assert_eq!(
        find(&status.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|v| v as i32),
        Some(expected)
    );
}

fn invoke_error_body(path: &str, payload: Vec<u8>, peer: u32, expected: i32) {
    let mut caller = raw_connection(path);
    send_and_expect_status(&mut caller, MsgType::Invoke, 700, peer, payload, expected);
}

fn invoke_missing_method_attr_reports_invalid_argument_body(path: &str) {
    let mut owner = raw_connection(path);
    let obj = raw_add_object_with_signature(
        &mut owner,
        701,
        "example.invoke.missing.method",
        &signature_with_ping_method(),
    )
    .0;
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj);
    invoke_error_body(path, env.finish(), obj, UBUS_STATUS_INVALID_ARGUMENT);
}
fn invoke_missing_objid_attr_reports_invalid_argument_body(path: &str) {
    let mut owner = raw_connection(path);
    let obj = raw_add_object_with_signature(
        &mut owner,
        702,
        "example.invoke.missing.objid",
        &signature_with_ping_method(),
    )
    .0;
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::Method, "ping");
    invoke_error_body(path, env.finish(), obj, UBUS_STATUS_INVALID_ARGUMENT);
}
fn invoke_unknown_objid_reports_not_found_body(path: &str) {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, 0x00DE_AD01);
    env.push_str(UbusAttr::Method, "ping");
    invoke_error_body(path, env.finish(), 0, UBUS_STATUS_NOT_FOUND);
}
fn invoke_routed_by_attr_objid_not_header_peer_body(path: &str) {
    let path = path.to_owned();
    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example.invoke.route").method("ping", |_args| Ok(BlobMsgTable::empty()))
    });
    owner.wait_ready();
    let mut lookup =
        UbusClient::connect(UnixUbusTransport::connect(&path).expect("lookup connect"))
            .expect("lookup hello");
    let obj = lookup.lookup("example.invoke.route").expect("lookup");
    let mut caller = raw_connection(&path);
    let mut bad = EnvBuilder::new();
    bad.push_u32(UbusAttr::ObjId, 0x00DE_AD02);
    bad.push_str(UbusAttr::Method, "ping");
    send_and_expect_status(
        &mut caller,
        MsgType::Invoke,
        703,
        obj,
        bad.finish(),
        UBUS_STATUS_NOT_FOUND,
    );
    let mut good = EnvBuilder::new();
    good.push_u32(UbusAttr::ObjId, obj);
    good.push_str(UbusAttr::Method, "ping");
    good.push_data(BlobMsgTable::empty().contents());
    caller
        .send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Invoke,
                seq: 704,
                peer: 0,
            },
            payload: good.finish(),
        })
        .expect("send invoke");
    let mut data = false;
    let mut status = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !(data && status) {
        match caller.recv() {
            Ok(Some(f)) if f.hdr.seq == 704 && f.hdr.ty == MsgType::Data => data = true,
            Ok(Some(f)) if f.hdr.seq == 704 && f.hdr.ty == MsgType::Status => {
                assert_eq!(
                    find(&f.payload, UbusAttr::Status).and_then(|a| a.as_u32()),
                    Some(0)
                );
                status = true
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("recv: {e:?}"),
        }
    }
    assert!(data && status, "attr-routed INVOKE must complete");
    owner.shutdown();
}
fn event_object_unknown_method_reports_invalid_command_body(path: &str) {
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, 1);
    env.push_str(UbusAttr::Method, "bogus");
    invoke_error_body(path, env.finish(), 1, UBUS_STATUS_INVALID_COMMAND);
}

fn subscribe_error_body(path: &str, obj: u32, target: u32, include: bool, expected: i32) {
    let mut sub = raw_connection(path);
    let mut env = EnvBuilder::new();
    if include {
        env.push_u32(UbusAttr::ObjId, obj);
        env.push_u32(UbusAttr::Target, target);
    }
    send_and_expect_status(&mut sub, MsgType::Subscribe, 710, 0, env.finish(), expected);
}
fn subscribe_unknown_target_reports_not_found_body(path: &str) {
    let mut sub = raw_connection(path);
    let mine = raw_add_anonymous(&mut sub, 711);
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, mine);
    env.push_u32(UbusAttr::Target, 0x00DE_AD03);
    send_and_expect_status(
        &mut sub,
        MsgType::Subscribe,
        712,
        0,
        env.finish(),
        UBUS_STATUS_NOT_FOUND,
    );
}
fn subscribe_foreign_objid_reports_invalid_argument_body(path: &str) {
    let mut owner = raw_connection(path);
    let obj = raw_add_anonymous(&mut owner, 713);
    subscribe_error_body(path, obj, obj, true, UBUS_STATUS_INVALID_ARGUMENT);
}
fn subscribe_empty_envelope_reports_invalid_argument_body(path: &str) {
    subscribe_error_body(path, 0, 0, false, UBUS_STATUS_INVALID_ARGUMENT);
}
fn duplicate_subscribe_acks_without_second_active_notify_body(path: &str) {
    let mut owner = raw_connection(path);
    let target = raw_add_object(&mut owner, 714, "example.duplicate.sub");
    let mut sub = raw_connection(path);
    let mine = raw_add_anonymous(&mut sub, 715);
    for seq in [716, 717] {
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, mine);
        env.push_u32(UbusAttr::Target, target);
        send_and_expect_status(
            &mut sub,
            MsgType::Subscribe,
            seq,
            0,
            env.finish(),
            UBUS_STATUS_OK,
        );
    }
    let active = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify
            && find(&f.payload, UbusAttr::Active).map(|a| a.payload) == Some(&[1][..])
    })
    .expect("single Active=1");
    assert_active_notify(
        &active,
        active.hdr.seq,
        target,
        1,
        "duplicate subscribe Active=1",
    );
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        match owner.recv() {
            Ok(Some(f))
                if f.hdr.ty == MsgType::Notify
                    && find(&f.payload, UbusAttr::Active).map(|a| a.payload) == Some(&[1][..]) =>
            {
                panic!("duplicate SUBSCRIBE sent a second Active=1")
            }
            Ok(Some(_)) | Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("owner recv: {e:?}"),
        }
    }
    drop(sub);
    let zero = recv_until(&mut owner, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Notify
            && find(&f.payload, UbusAttr::Active).map(|a| a.payload) == Some(&[0][..])
    })
    .expect("Active=0");
    assert_active_notify(&zero, zero.hdr.seq, target, 0, "teardown Active=0");
}

fn unsubscribe_error_body(path: &str, obj: Option<u32>, target: Option<u32>, expected: i32) {
    let mut sub = raw_connection(path);
    let mut env = EnvBuilder::new();
    if let Some(v) = obj {
        env.push_u32(UbusAttr::ObjId, v);
    }
    if let Some(v) = target {
        env.push_u32(UbusAttr::Target, v);
    }
    send_and_expect_status(
        &mut sub,
        MsgType::Unsubscribe,
        720,
        0,
        env.finish(),
        expected,
    );
}
fn unsubscribe_no_subscription_reports_not_found_body(path: &str) {
    let mut owner = raw_connection(path);
    let target = raw_add_anonymous(&mut owner, 721);
    let mut sub = raw_connection(path);
    let mine = raw_add_anonymous(&mut sub, 722);
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, mine);
    env.push_u32(UbusAttr::Target, target);
    send_and_expect_status(
        &mut sub,
        MsgType::Unsubscribe,
        723,
        0,
        env.finish(),
        UBUS_STATUS_NOT_FOUND,
    );
}
fn unsubscribe_foreign_objid_reports_invalid_argument_body(path: &str) {
    let mut owner = raw_connection(path);
    let target = raw_add_anonymous(&mut owner, 724);
    unsubscribe_error_body(
        path,
        Some(target),
        Some(target),
        UBUS_STATUS_INVALID_ARGUMENT,
    );
}
fn unsubscribe_unknown_target_reports_not_found_body(path: &str) {
    let mut sub = raw_connection(path);
    let mine = raw_add_anonymous(&mut sub, 725);
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, mine);
    env.push_u32(UbusAttr::Target, 0x00DE_AD04);
    send_and_expect_status(
        &mut sub,
        MsgType::Unsubscribe,
        726,
        0,
        env.finish(),
        UBUS_STATUS_NOT_FOUND,
    );
}
fn unsubscribe_empty_envelope_reports_invalid_argument_body(path: &str) {
    unsubscribe_error_body(path, None, None, UBUS_STATUS_INVALID_ARGUMENT);
}

/// An empty ObjPath is a valid object registration, but an explicit
/// empty ObjPath in LOOKUP is rejected rather than treated as list-all.
fn add_object_empty_path_untyped_registers_body(path: &str) {
    let mut conn = raw_connection(path);
    raw_add_object(&mut conn, 730, "");
    let mut env = EnvBuilder::new();
    env.push_str(UbusAttr::ObjPath, "");
    conn.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Lookup,
            seq: 731,
            peer: 0,
        },
        payload: env.finish(),
    })
    .expect("lookup");
    expect_status_only(
        &mut conn,
        731,
        UBUS_STATUS_INVALID_ARGUMENT,
        "empty-path LOOKUP",
    );
}
fn add_object_empty_path_typed_registers_with_objtype_body(path: &str) {
    let mut conn = raw_connection(path);
    raw_add_object_with_signature(&mut conn, 733, "", &signature_with_ping_method());
}

fn notify_error_body(path: &str, obj: Option<u32>, method: Option<&str>, expected: i32) {
    let mut conn = raw_connection(path);
    let mut env = EnvBuilder::new();
    if let Some(v) = obj {
        env.push_u32(UbusAttr::ObjId, v);
    }
    if let Some(v) = method {
        env.push_str(UbusAttr::Method, v);
    }
    send_and_expect_status(&mut conn, MsgType::Notify, 740, 0, env.finish(), expected);
}
fn notify_missing_objid_reports_invalid_argument_body(path: &str) {
    notify_error_body(path, None, Some("event"), UBUS_STATUS_INVALID_ARGUMENT);
}
fn notify_missing_method_reports_invalid_argument_body(path: &str) {
    let mut owner = raw_connection(path);
    let obj = raw_add_anonymous(&mut owner, 741);
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, obj);
    send_and_expect_status(
        &mut owner,
        MsgType::Notify,
        742,
        0,
        env.finish(),
        UBUS_STATUS_INVALID_ARGUMENT,
    );
}
fn notify_unknown_objid_reports_not_found_body(path: &str) {
    notify_error_body(
        path,
        Some(0x00DE_AD05),
        Some("event"),
        UBUS_STATUS_NOT_FOUND,
    );
}
fn notify_by_non_owner_reports_permission_denied_body(path: &str) {
    let mut owner = raw_connection(path);
    let obj = raw_add_anonymous(&mut owner, 743);
    notify_error_body(
        path,
        Some(obj),
        Some("event"),
        UBUS_STATUS_PERMISSION_DENIED,
    );
}
fn lookup_wrong_typed_objpath_lists_all_body(path: &str) {
    let mut conn = raw_connection(path);
    let obj = raw_add_object_with_signature(
        &mut conn,
        750,
        "example.wrong.typed.path",
        &signature_with_ping_method(),
    )
    .0;
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjPath, 2);
    conn.send(&Frame {
        hdr: Header {
            version: PROTO_VERSION,
            ty: MsgType::Lookup,
            seq: 751,
            peer: 0,
        },
        payload: env.finish(),
    })
    .expect("lookup");
    let data = recv_until(&mut conn, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Data && f.hdr.seq == 751
    })
    .expect("listing DATA");
    assert_eq!(
        find(&data.payload, UbusAttr::ObjId).and_then(|a| a.as_u32()),
        Some(obj)
    );
    let status = recv_until(&mut conn, Duration::from_secs(5), |f| {
        f.hdr.ty == MsgType::Status && f.hdr.seq == 751
    })
    .expect("listing STATUS");
    assert_eq!(
        find(&status.payload, UbusAttr::Status).and_then(|a| a.as_u32()),
        Some(0)
    );
}

macro_rules! matrix_scenario {
    ($name:ident, $body:ident) => {
        #[rstest]
        #[case::upstream(MatrixArm::Upstream)]
        #[case::rs(MatrixArm::Rs)]
        #[case::parity(MatrixArm::Parity)]
        #[case::golden(MatrixArm::Golden)]
        fn $name(#[case] arm: MatrixArm) {
            run_matrix_case(concat!("ubusd_handshake ", stringify!($name)), arm, &$body);
        }
    };
}
matrix_scenario!(
    invoke_missing_method_attr_reports_invalid_argument,
    invoke_missing_method_attr_reports_invalid_argument_body
);
matrix_scenario!(
    invoke_missing_objid_attr_reports_invalid_argument,
    invoke_missing_objid_attr_reports_invalid_argument_body
);
matrix_scenario!(
    invoke_unknown_objid_reports_not_found,
    invoke_unknown_objid_reports_not_found_body
);
matrix_scenario!(
    invoke_routed_by_attr_objid_not_header_peer,
    invoke_routed_by_attr_objid_not_header_peer_body
);
matrix_scenario!(
    event_object_unknown_method_reports_invalid_command,
    event_object_unknown_method_reports_invalid_command_body
);
matrix_scenario!(
    subscribe_unknown_target_reports_not_found,
    subscribe_unknown_target_reports_not_found_body
);
matrix_scenario!(
    subscribe_foreign_objid_reports_invalid_argument,
    subscribe_foreign_objid_reports_invalid_argument_body
);
matrix_scenario!(
    subscribe_empty_envelope_reports_invalid_argument,
    subscribe_empty_envelope_reports_invalid_argument_body
);
matrix_scenario!(
    duplicate_subscribe_acks_without_second_active_notify,
    duplicate_subscribe_acks_without_second_active_notify_body
);
matrix_scenario!(
    unsubscribe_no_subscription_reports_not_found,
    unsubscribe_no_subscription_reports_not_found_body
);
matrix_scenario!(
    unsubscribe_foreign_objid_reports_invalid_argument,
    unsubscribe_foreign_objid_reports_invalid_argument_body
);
matrix_scenario!(
    unsubscribe_unknown_target_reports_not_found,
    unsubscribe_unknown_target_reports_not_found_body
);
matrix_scenario!(
    unsubscribe_empty_envelope_reports_invalid_argument,
    unsubscribe_empty_envelope_reports_invalid_argument_body
);
matrix_scenario!(
    add_object_empty_path_untyped_registers,
    add_object_empty_path_untyped_registers_body
);
matrix_scenario!(
    add_object_empty_path_typed_registers_with_objtype,
    add_object_empty_path_typed_registers_with_objtype_body
);
matrix_scenario!(
    notify_missing_objid_reports_invalid_argument,
    notify_missing_objid_reports_invalid_argument_body
);
matrix_scenario!(
    notify_missing_method_reports_invalid_argument,
    notify_missing_method_reports_invalid_argument_body
);
matrix_scenario!(
    notify_unknown_objid_reports_not_found,
    notify_unknown_objid_reports_not_found_body
);
matrix_scenario!(
    notify_by_non_owner_reports_permission_denied,
    notify_by_non_owner_reports_permission_denied_body
);
matrix_scenario!(
    lookup_wrong_typed_objpath_lists_all,
    lookup_wrong_typed_objpath_lists_all_body
);

/// Owner A registers `example`. C subscribes to A's obj-id (proves the
/// SubscriberRegistry has a live entry). A disconnects. A fresh peer's
/// LOOKUP must report NOT_FOUND, and C must not see any further NOTIFYs.
/// Both arms exercise the disconnect-reaper cascade — the highest-risk
/// divergence surface in the protocol.
fn disconnect_cascades_into_lookup_and_subscribers_body(path: &str) {
    let path = path.to_owned();

    let owner = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example").method("ping", |_| Ok(BlobMsgTable::build(|_| {})))
    });
    owner.wait_ready();

    // Look up A's obj-id via a separate client. A LOOKUP-from-A would
    // race A's poll_one against the lookup reply; LOOKUP from a side
    // peer keeps the dependency graph linear.
    let probe_transport = UnixUbusTransport::connect(&path).expect("probe connect");
    let mut probe = UbusClient::connect(probe_transport).expect("probe hello");
    let obj_id_a = probe.lookup("example").expect("a obj_id");

    // C: register itself as a subscriber object (upstream requires the
    // subscriber to be registered), then SUBSCRIBE to A's obj-id.
    let sub_transport = UnixUbusTransport::connect(&path).expect("c connect");
    let sub_object = UbusObject::new("example.disconnect.sub")
        .method("noop", |_| Ok(BlobMsgTable::build(|_| {})));
    let mut sub_conn =
        UbusConnection::connect_and_register(sub_transport, sub_object).expect("c register");
    let sub_obj_id = sub_conn.object_id();
    {
        let sub = sub_conn.transport_mut();
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, sub_obj_id);
        env.push_u32(UbusAttr::Target, obj_id_a);
        sub.send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq: 11,
                peer: obj_id_a,
            },
            payload: env.finish(),
        })
        .expect("subscribe");
        let ack = recv_until(sub, Duration::from_secs(5), |f| {
            f.hdr.ty == MsgType::Status && f.hdr.seq == 11
        })
        .expect("subscribe ack");
        let s = find(&ack.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32)
            .expect("STATUS attr");
        assert_eq!(s, 0, "subscribe failed: status={s}");
    }

    // The broker's unsubscribe proves it has reaped A and removed the
    // subscription. Use that protocol barrier before LOOKUP so scheduling
    // cannot change the number of requests captured by the parity tap.
    owner.shutdown();
    let unsub = recv_until(sub_conn.transport_mut(), Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Unsubscribe
    })
    .expect("broker-minted Unsubscribe after owner disconnect");
    assert_eq!(
        find(&unsub.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32()),
        Some(sub_obj_id)
    );
    assert_eq!(
        find(&unsub.payload, UbusAttr::Target).and_then(|attr| attr.as_u32()),
        Some(obj_id_a)
    );

    let lookup_transport = UnixUbusTransport::connect(&path).expect("b connect");
    let mut lookup_client = UbusClient::connect(lookup_transport).expect("b hello");
    assert!(
        matches!(
            lookup_client.lookup("example"),
            Err(UbusError::Status(UBUS_STATUS_NOT_FOUND))
        ),
        "LOOKUP must report example gone after owner disconnect's Unsubscribe"
    );

    // C drains for 200 ms. Nothing can NOTIFY (A is gone), but a
    // resurrected subscriber list could still leak something.
    let no_notify_deadline = Instant::now() + Duration::from_millis(200);
    let sub = sub_conn.transport_mut();
    while Instant::now() < no_notify_deadline {
        match sub.recv() {
            Ok(Some(f)) if matches!(f.hdr.ty, MsgType::Notify | MsgType::Invoke) => {
                panic!(
                    "unexpected NOTIFY/INVOKE on subscriber after owner disconnect: {:?}",
                    f.hdr
                );
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => break,
        }
    }
}

#[rstest]
#[case::upstream(MatrixArm::Upstream)]
#[case::rs(MatrixArm::Rs)]
#[case::parity(MatrixArm::Parity)]
#[case::golden(MatrixArm::Golden)]
fn disconnect_cascades_into_lookup_and_subscribers(#[case] arm: MatrixArm) {
    run_matrix_case(
        concat!(
            "ubusd_handshake ",
            stringify!(disconnect_cascades_into_lookup_and_subscribers)
        ),
        arm,
        &disconnect_cascades_into_lookup_and_subscribers_body,
    );
}

/// Last-writer-wins re-registration on the same path is rs-broker-
/// specific behaviour: upstream `ubusd` rejects path-collision
/// AddObject with `STATUS=2 = UBUS_STATUS_INVALID_ARGUMENT`, so the
/// rs broker's "displace + mint a fresh obj-id" path can't be matrix-
/// tested cross-broker. Keep this rs-only and document the
/// divergence at the entry point below.
///
/// What we assert end-to-end: after B re-registers, INVOKE on the
/// stale obj_id_a reports a NOT_FOUND Status, and a NOTIFY
/// emitted by A on its now-dead obj_id_a does not reach the
/// subscriber. (Both brokers would reject the NOTIFY at the owner
/// check, but the displacement happening at all is rs-specific.)
fn re_registration_purges_displaced_owner_body(path: &str) {
    let path = path.to_owned();

    // A registers example, captures obj_id_a, then waits for a signal
    // to send a NOTIFY on a caller-supplied obj-id (after B has
    // displaced A, the test signals A to NOTIFY on the now-dead
    // obj_id_a so we can assert C sees nothing).
    let (a_id_tx, a_id_rx) = std::sync::mpsc::channel::<u32>();
    let (a_notify_tx, a_notify_rx) = std::sync::mpsc::channel::<u32>();
    let (a_done_tx, a_done_rx) = std::sync::mpsc::channel::<()>();
    let path_a = path.clone();
    let owner_a = JoinOnDrop::new(std::thread::spawn(move || -> Result<(), String> {
        let transport =
            UnixUbusTransport::connect(&path_a).map_err(|e| format!("a connect: {e:?}"))?;
        let object = UbusObject::new("example").method("ping", |_| Ok(BlobMsgTable::build(|_| {})));
        let mut conn = UbusConnection::connect_and_register(transport, object)
            .map_err(|e| format!("a register: {e:?}"))?;
        a_id_tx
            .send(conn.object_id())
            .map_err(|_| "a id tx".to_string())?;
        let target = a_notify_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "a: notify signal timeout".to_string())?;
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, target);
        env.push_str(UbusAttr::Method, "fanout");
        conn.transport_mut()
            .send(&Frame::to_peer(MsgType::Notify, 1000, target, env.finish()))
            .map_err(|e| format!("a notify: {e:?}"))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Err(e) = conn.poll_one() {
                return Err(format!("a poll_one: {e:?}"));
            }
            match a_done_rx.recv_timeout(Duration::from_millis(5)) {
                Ok(()) => return Ok(()),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
        Err("a: deadline elapsed".into())
    }));
    let obj_id_a = a_id_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a obj_id");

    // C: register, subscribe to obj_id_a.
    let sub_transport = UnixUbusTransport::connect(&path).expect("c connect");
    let sub_object =
        UbusObject::new("example.rereg.sub").method("noop", |_| Ok(BlobMsgTable::build(|_| {})));
    let mut sub_conn =
        UbusConnection::connect_and_register(sub_transport, sub_object).expect("c register");
    let sub_obj_id = sub_conn.object_id();
    {
        let sub = sub_conn.transport_mut();
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, sub_obj_id);
        env.push_u32(UbusAttr::Target, obj_id_a);
        sub.send(&Frame {
            hdr: Header {
                version: PROTO_VERSION,
                ty: MsgType::Subscribe,
                seq: 21,
                peer: obj_id_a,
            },
            payload: env.finish(),
        })
        .expect("subscribe");
        let ack = recv_until(sub, Duration::from_secs(5), |f| {
            f.hdr.ty == MsgType::Status && f.hdr.seq == 21
        })
        .expect("subscribe ack");
        let s = find(&ack.payload, UbusAttr::Status)
            .and_then(|a| a.as_u32())
            .map(|u| u as i32)
            .expect("STATUS attr");
        assert_eq!(s, 0, "subscribe failed: status={s}");
    }

    // B: register example on the same path. Last-writer-wins yields a
    // fresh obj-id; the broker decommissions obj_id_a in the process.
    let owner_b = OwnerThread::spawn(path.clone(), || {
        UbusObject::new("example").method("ping", |_| Ok(BlobMsgTable::build(|_| {})))
    });
    owner_b.wait_ready();

    let probe_transport = UnixUbusTransport::connect(&path).expect("probe connect");
    let mut probe = UbusClient::connect(probe_transport).expect("probe hello");
    let obj_id_b = probe.lookup("example").expect("b obj_id");
    assert_ne!(
        obj_id_a, obj_id_b,
        "re-registration must mint a fresh obj-id"
    );

    // INVOKE on stale obj_id_a → NOT_FOUND Status from both brokers.
    let x_transport = UnixUbusTransport::connect(&path).expect("x connect");
    let mut x_client = UbusClient::connect(x_transport).expect("x hello");
    match x_client.invoke(obj_id_a, "ping", &BlobMsgTable::empty()) {
        Err(UbusError::Status(s)) => assert_eq!(
            s, UBUS_STATUS_NOT_FOUND,
            "stale obj_id_a must report UBUS_STATUS_NOT_FOUND"
        ),
        other => panic!("expected UBUS_STATUS_NOT_FOUND, got {other:?}"),
    }

    // Ask A to NOTIFY on obj_id_a. A no longer owns it (B does, on a
    // different obj-id), so the broker drops the NOTIFY. C sees
    // nothing — proves the displaced id is fully decommissioned.
    a_notify_tx.send(obj_id_a).expect("a notify signal");
    let no_notify_deadline = Instant::now() + Duration::from_millis(300);
    let sub = sub_conn.transport_mut();
    while Instant::now() < no_notify_deadline {
        match sub.recv() {
            Ok(Some(f)) if matches!(f.hdr.ty, MsgType::Notify | MsgType::Invoke) => {
                panic!(
                    "unexpected NOTIFY on stale obj_id_a after re-registration: {:?}",
                    f.hdr
                );
            }
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => break,
        }
    }

    let _ = a_done_tx.send(());
    owner_a.join();
    owner_b.shutdown();
}

/// rs-only: upstream `ubusd` rejects duplicate-path AddObject before
/// the displacement logic can run. See the body's docstring.
#[test]
fn re_registration_purges_displaced_owner_rs() {
    run_matrix_case(
        "ubusd_handshake re_registration_purges_displaced_owner_rs",
        MatrixArm::Rs,
        &re_registration_purges_displaced_owner_body,
    );
}

/// RAII wrapper around an owner thread for tests that drive HELLO+
/// ADD_OBJECT manually. On explicit `join()` we panic-propagate via
/// `join_owner`; on drop (e.g. cascading test panic) we eprintln the
/// owner's diagnostic so a vanished thread doesn't hide the real cause.
struct JoinOnDrop {
    handle: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl JoinOnDrop {
    fn new(handle: std::thread::JoinHandle<Result<(), String>>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn join(mut self) {
        if let Some(h) = self.handle.take() {
            join_owner(h);
        }
    }
}

impl Drop for JoinOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("owner thread error during drop: {e}"),
                Err(p) => eprintln!("owner thread panicked during drop: {p:?}"),
            }
        }
    }
}

fn duplicate_protocol_policy_body(path: &str) {
    let valid_empty = b"\0".as_slice();
    let missing = b"opus.probe.missing\0".as_slice();
    let invalid = b"invalid".as_slice();
    let trailing_garbage = b"\0invalid".as_slice();
    let cases = [
        (vec![valid_empty, missing], UBUS_STATUS_NOT_FOUND),
        (vec![missing, valid_empty], UBUS_STATUS_INVALID_ARGUMENT),
        (vec![valid_empty, invalid], UBUS_STATUS_INVALID_ARGUMENT),
        (vec![invalid, missing], UBUS_STATUS_NOT_FOUND),
        (vec![missing, trailing_garbage], UBUS_STATUS_NOT_FOUND),
        (
            vec![trailing_garbage, valid_empty],
            UBUS_STATUS_INVALID_ARGUMENT,
        ),
        (vec![invalid, trailing_garbage], UBUS_STATUS_OK),
        (
            vec![valid_empty, missing, valid_empty],
            UBUS_STATUS_INVALID_ARGUMENT,
        ),
    ];
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    for (index, (values, expected)) in cases.into_iter().enumerate() {
        let seq = 100 + index as u16;
        let mut env = EnvBuilder::new();
        for value in values {
            env.push_bytes_id(UbusAttr::ObjPath as u8, value);
        }
        transport
            .send(&Frame::to_broker(MsgType::Lookup, seq, env.finish()))
            .expect("send duplicate lookup");
        let reply = recv_until(&mut transport, Duration::from_secs(5), |frame| {
            frame.hdr.seq == seq && frame.hdr.ty == MsgType::Status
        })
        .expect("duplicate lookup status");
        assert_eq!(
            find(&reply.payload, UbusAttr::Status).and_then(|attr| attr.as_u32()),
            Some(expected as u32),
            "duplicate case {index}"
        );
    }
    let mut client =
        UbusClient::connect(UnixUbusTransport::connect(path).expect("connect duplicate client"))
            .expect("HELLO");
    let invalid_method = b"invalid".as_slice();
    for (values, expected) in [
        (
            vec![b"bogus\0".as_slice(), b"send\0".as_slice()],
            UBUS_STATUS_INVALID_ARGUMENT,
        ),
        (
            vec![b"send\0".as_slice(), b"bogus\0".as_slice()],
            UBUS_STATUS_INVALID_COMMAND,
        ),
        (
            vec![b"send\0".as_slice(), invalid_method],
            UBUS_STATUS_INVALID_ARGUMENT,
        ),
        (
            vec![invalid_method, b"bogus\0".as_slice()],
            UBUS_STATUS_INVALID_COMMAND,
        ),
    ] {
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, 1);
        for value in values {
            env.push_bytes_id(UbusAttr::Method as u8, value);
        }
        env.push_data(&[]);
        let result = client.request(MsgType::Invoke, 0, env, |_| {
            panic!("invalid event method must not return DATA")
        });
        assert!(matches!(result, Err(UbusError::Status(status)) if status == expected));
    }
    for reverse in [false, true] {
        let object = client.add_anonymous_object().expect("anonymous object");
        let good = object.to_be_bytes().to_vec();
        let missing = 0xf000_0001u32.to_be_bytes().to_vec();
        let (values, expected) = if reverse {
            (vec![missing, good], UBUS_STATUS_OK)
        } else {
            (vec![good, missing], UBUS_STATUS_NOT_FOUND)
        };
        let mut env = EnvBuilder::new();
        for value in values {
            env.push_bytes_id(UbusAttr::ObjId as u8, &value);
        }
        let mut removed = None;
        let result = client.request(MsgType::RemoveObject, 0, env, |frame| {
            removed = find(&frame.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32());
            Ok(())
        });
        if expected == UBUS_STATUS_OK {
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(removed, Some(object));
        } else {
            assert!(matches!(result, Err(UbusError::Status(status)) if status == expected));
            assert_eq!(removed, None);
        }
    }
}

matrix_scenario!(duplicate_protocol_policy, duplicate_protocol_policy_body);

// Malformed ID widths remain literal bytes on direct sockets: the golden
// normalizer deliberately rejects short IDs instead of rewriting them.
#[rstest]
#[case::upstream(BrokerArm::Upstream)]
#[case::rs(BrokerArm::Rs)]
fn duplicate_integer_policy_rejects_bad_widths(#[case] arm: BrokerArm) {
    let start = match arm {
        BrokerArm::Upstream => UbusdHarness::start_upstream,
        BrokerArm::Rs => UbusdHarness::start_rust,
    };
    let Some(harness) = start().expect("start broker") else {
        skip::or_skip(
            "duplicate_integer_policy_rejects_bad_widths",
            "broker binary not reachable",
        );
        return;
    };
    let mut client =
        UbusClient::connect(UnixUbusTransport::connect(harness.socket_path()).unwrap()).unwrap();
    for invalid in [vec![0], vec![0, 0, 0], vec![0xf0, 0, 0, 1, 0], vec![0; 8]] {
        for invalid_last in [false, true] {
            let object = client.add_anonymous_object().unwrap();
            let good = object.to_be_bytes();
            let mut env = EnvBuilder::new();
            for value in if invalid_last {
                [good.as_slice(), invalid.as_slice()]
            } else {
                [invalid.as_slice(), good.as_slice()]
            } {
                env.push_bytes_id(UbusAttr::ObjId as u8, value);
            }
            let mut removed = None;
            client
                .request(MsgType::RemoveObject, 0, env, |frame| {
                    removed = find(&frame.payload, UbusAttr::ObjId).and_then(|attr| attr.as_u32());
                    Ok(())
                })
                .expect("last valid integer is selected");
            assert_eq!(removed, Some(object));
        }
    }
}

// These fields are UNSPEC in the pinned C broker policy: arbitrary widths
// remain eligible and the last NoReply value's first byte controls the ACK.
fn duplicate_noreply_policy_body(path: &str) {
    let mut transport = UnixUbusTransport::connect(path).expect("connect");
    recv_until(&mut transport, Duration::from_secs(5), |frame| {
        frame.hdr.ty == MsgType::Hello
    })
    .expect("HELLO");
    let object = raw_add_anonymous(&mut transport, 10);
    let cases: [(&[u8], &[u8], bool); 4] = [
        (&[1], &[0, 0, 0, 1], true),
        (&[0, 0, 0, 1], &[1], false),
        (&[1], &[0, 1], true),
        (&[0, 0, 0, 1], &[1, 0], false),
    ];
    for (index, (first, last, expected_ack)) in cases.into_iter().enumerate() {
        let seq = 20 + index as u16 * 2;
        let mut env = EnvBuilder::new();
        env.push_u32(UbusAttr::ObjId, object);
        env.push_str(UbusAttr::Method, "probe");
        env.push_bytes_id(UbusAttr::NoReply as u8, first);
        env.push_bytes_id(UbusAttr::NoReply as u8, last);
        transport
            .send(&Frame::to_peer(MsgType::Notify, seq, object, env.finish()))
            .expect("duplicate NoReply NOTIFY");
        // A same-connection PING fences the preceding NOTIFY without sleeps.
        transport
            .send(&Frame::to_peer(
                MsgType::Ping,
                seq + 1,
                object,
                EnvBuilder::new().finish(),
            ))
            .expect("PING fence");
        let acknowledged = std::cell::Cell::new(false);
        recv_until(&mut transport, Duration::from_secs(5), |frame| {
            if frame.hdr.seq == seq && frame.hdr.ty == MsgType::Status {
                assert_eq!(
                    find(&frame.payload, UbusAttr::Status).and_then(|a| a.as_u32()),
                    Some(0)
                );
                acknowledged.set(true);
            }
            frame.hdr.seq == seq + 1 && frame.hdr.ty == MsgType::Status
        })
        .expect("PING fence STATUS");
        assert_eq!(
            acknowledged.get(),
            expected_ack,
            "NoReply duplicate case {index}"
        );
    }
}
matrix_scenario!(duplicate_noreply_policy, duplicate_noreply_policy_body);
