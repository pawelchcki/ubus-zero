//! Allocation diagnostic: cargo run --release -p ubusd --example footprint
//! Reports allocator calls on verified routing operations and retained churn memory.
//! Run outside timing comparisons: the tracking allocator intentionally adds overhead.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use ubus::{
    envelope::{EnvBuilder, UbusAttr},
    wire::{Frame, MsgType},
};
use ubusd::registry::{
    EventRegistry, MonitorRegistry, ObjectRegistry, PeerTable, SubscriberRegistry,
};
use ubusd::{acl::AclRegistry, peer::Peer, routing};

struct TrackingAllocator;
static ALLOCATION_CALLS: AtomicIsize = AtomicIsize::new(0);
static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, old, new_size) };
        if !new_ptr.is_null() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            LIVE_BYTES.fetch_add(new_size as isize - old.size() as isize, Ordering::Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn count_allocations(mut operation: impl FnMut()) -> isize {
    for _ in 0..100 {
        operation();
    }
    let before = ALLOCATION_CALLS.load(Ordering::Relaxed);
    for _ in 0..10_000 {
        operation();
    }
    ALLOCATION_CALLS.load(Ordering::Relaxed) - before
}

fn main() {
    let mut peers = PeerTable::new();
    let mut sockets = Vec::new();
    let mut add_peer = || {
        let (socket, other) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        sockets.push(other);
        peers
            .insert(Peer::new(
                socket,
                Some(0),
                Some("root".into()),
                Some("root".into()),
            ))
            .unwrap()
            .0
    };
    let caller = add_peer();
    let owner = add_peer();
    let mut objects = ObjectRegistry::new();
    let object = objects
        .insert("benchmark.echo".into(), owner, None)
        .unwrap()
        .0;
    let acl = AclRegistry::default();
    let mut subscribers = SubscriberRegistry::new();
    let mut events = EventRegistry::new();
    let mut monitors = MonitorRegistry::new();
    let ping = Frame::to_broker(MsgType::Ping, 10, EnvBuilder::new().finish());
    let mut env = EnvBuilder::new();
    env.push_u32(UbusAttr::ObjId, object.get());
    env.push_str(UbusAttr::Method, "echo");
    env.push_data(&[0; 64]);
    let invoke = Frame::to_broker(MsgType::Invoke, 11, env.finish());
    let mut dispatch = |frame: &Frame, expected| {
        let mut fd = None;
        let actions = routing::dispatch(
            frame,
            caller,
            &acl,
            0,
            &mut peers,
            &mut objects,
            &mut subscribers,
            &mut events,
            &mut monitors,
            &mut fd,
        );
        assert_eq!(actions.len(), expected);
        std::hint::black_box(actions);
    };
    let ping_calls = count_allocations(|| dispatch(&ping, 2));
    let invoke_calls = count_allocations(|| dispatch(&invoke, 1));

    let before = LIVE_BYTES.load(Ordering::Relaxed);
    let mut registry = ObjectRegistry::new();
    let mut retained = [0; 3];
    let mut completed = 0;
    for (index, target) in [1000, 2000, 4000].into_iter().enumerate() {
        while completed < target {
            let (id, replaced) = registry.insert("probe.churn".into(), owner, None).unwrap();
            assert!(replaced.is_none());
            assert!(registry.remove(id));
            completed += 1;
        }
        assert!(registry.lookup_exact("probe.churn").is_none());
        assert!(registry.named_objects_of(owner).is_empty());
        std::hint::black_box(&registry);
        retained[index] = LIVE_BYTES.load(Ordering::Relaxed) - before;
    }
    drop(registry);
    let after_drop = LIVE_BYTES.load(Ordering::Relaxed) - before;
    println!(
        "{}",
        serde_json::json!({
            "operations_per_case": 10000,
            "routing_allocator_calls": {"ping": ping_calls, "invoke_forward_64_bytes": invoke_calls},
            "churn_cycles": [1000, 2000, 4000], "live_objects_after_each_stage": 0,
            "retained_heap_bytes_after_churn": retained,
            "retained_heap_bytes_after_registry_drop": after_drop,
            "scope": "instrumented Rust routing only; excludes socket I/O, codec, and broker loop; not a timing benchmark"
        })
    );
}
