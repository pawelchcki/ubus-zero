//! Peer / object / subscription tables.
//!
//! Three lookup surfaces:
//! * [`PeerTable`] — owns the slab of accepted peers (`Vec<Option<Peer>>`)
//!   and a side map from peer-id to slot index. Slots back the storage
//!   so a `remove` is O(1) without renumbering live peers; the
//!   peer-id is the routing key on the wire and is what the broker's
//!   poll loop iterates over. Keeping them distinct lets the id
//!   allocator stay strictly monotonic (no reuse) while slot indices
//!   are recycled — a stale frame from a slow peer can't hit the
//!   newly-accepted occupant of the recycled slot.
//! * [`ObjectRegistry`] — `obj-id → owner peer-id` and `path → obj-id`.
//!   Both directions are needed: INVOKE looks up obj-id → owner;
//!   LOOKUP walks paths.
//! * [`SubscriberRegistry`] — `obj-id → Vec<subscriber peer-id>`.
//!   NOTIFY fans out to every entry; a peer's disconnect drains every
//!   list.
//!
//! All three keep monotonic id allocators with no reuse. ubusd uses
//! the IDs as routing keys *across* TCP-style streams; reusing one
//! after a disconnect would let a stale frame from a slow peer hit
//! the new owner of that id.
//!
//! [`PeerId`] and [`ObjectId`] are distinct newtypes so the compiler
//! refuses any axis-swap (passing a peer-id where an obj-id is
//! expected, or vice versa). Both wrap `NonZeroU32` because `0` is
//! the broker's reserved address on the wire — it is never a valid
//! routing target.

use core::num::NonZeroU32;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::broker::BrokerError;
use crate::peer::Peer;

/// Wire-routable peer-id. Distinct from [`ObjectId`] so the compiler
/// catches axis-swap at every call site.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
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
        self.0.get().fmt(f)
    }
}

/// Wire-routable object-id. See [`PeerId`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ObjectId(NonZeroU32);

impl ObjectId {
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

impl core::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.get().fmt(f)
    }
}

/// Lowest peer-id we hand out. `0` = "broker" (every client targets
/// requests there); the system range up to `1024` is reserved by the
/// libubus convention. We start at 1025 to match real ubusd, so
/// captured wire dumps from a mixed deployment are interchangeable.
pub const FIRST_PEER_ID: PeerId = PeerId(NonZeroU32::new(1025).unwrap());

/// Lowest client object id. Upstream reserves ids 1 (event), 2 (acl), and 3
/// (monitor) for system objects; never mint them for clients.
pub const FIRST_OBJ_ID: ObjectId = ObjectId(NonZeroU32::new(4).unwrap());

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Subscription {
    pub peer_id: PeerId,
    pub obj_id: ObjectId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectType {
    id: ObjectId,
    signature: Vec<u8>,
}

impl ObjectType {
    pub fn id(&self) -> ObjectId {
        self.id
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Debug)]
struct ObjectEntry {
    owner: PeerId,
    path: Option<String>,
    obj_type: Option<ObjectType>,
}

pub struct PeerTable {
    /// Slot storage. `None` means a recently-reaped slot waiting to
    /// be reused by the next accept — recycling avoids growing the
    /// vec when the peer count churns. Index here ≠ peer-id; the
    /// `id_to_slot` map below is the single source of truth for
    /// peer-id → slot resolution.
    slots: Vec<Option<Peer>>,
    id_to_slot: HashMap<PeerId, usize>,
    next_id: NonZeroU32,
}

impl Default for PeerTable {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            id_to_slot: HashMap::new(),
            next_id: FIRST_PEER_ID.0,
        }
    }
}

impl PeerTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh peer-id and place `peer` in a slot.
    ///
    /// Honours the no-reuse invariant in the module doc: refuses to
    /// hand out a recycled id rather than wrap silently. u32 space is
    /// ~4B accepts in a single broker session — exhaustion is
    /// unreachable in practice, but graceful refusal lets the broker
    /// stay up for every other peer if it ever happens.
    pub fn insert(&mut self, peer: Peer) -> Result<(PeerId, usize), BrokerError> {
        // Reserve the bumped value before issuing the current id, so
        // an overflow surfaces as a clean refusal — the would-be id is
        // never handed out and `next_id` is left untouched.
        let bumped = self
            .next_id
            .checked_add(1)
            .ok_or(BrokerError::PeerIdExhausted)?;
        let id = PeerId(self.next_id);
        self.next_id = bumped;
        let slot = match self.slots.iter().position(Option::is_none) {
            Some(i) => {
                self.slots[i] = Some(peer);
                i
            }
            None => {
                self.slots.push(Some(peer));
                self.slots.len() - 1
            }
        };
        self.id_to_slot.insert(id, slot);
        Ok((id, slot))
    }

    pub fn get(&self, id: PeerId) -> Option<&Peer> {
        let slot = *self.id_to_slot.get(&id)?;
        self.slots.get(slot).and_then(|p| p.as_ref())
    }

    pub fn get_mut(&mut self, id: PeerId) -> Option<&mut Peer> {
        let slot = *self.id_to_slot.get(&id)?;
        self.slots.get_mut(slot).and_then(|p| p.as_mut())
    }

    pub fn remove(&mut self, id: PeerId) -> Option<Peer> {
        let slot = self.id_to_slot.remove(&id)?;
        self.slots.get_mut(slot).and_then(|p| p.take())
    }

    /// Fill `buf` with the set of live peer-ids. Pulled into a
    /// caller-owned `Vec` so the borrow on `self` ends before
    /// downstream mutation. The caller is expected to reuse the
    /// buffer across ticks; the steady-state allocation cost is zero
    /// once the buffer's capacity stabilises.
    pub fn live_ids_into(&self, buf: &mut Vec<PeerId>) {
        buf.clear();
        buf.extend(self.id_to_slot.keys().copied());
    }

    /// Test-only fast-forward of the id allocator. Lets integration
    /// tests prove the `PeerIdExhausted` refusal path without spinning
    /// 4B accepts.
    #[doc(hidden)]
    pub fn __test_set_next_id(&mut self, id: NonZeroU32) {
        self.next_id = id;
    }
}

#[derive(Debug)]
pub struct ObjectRegistry {
    /// obj-id → (owner peer-id, optional path). Path is duplicated
    /// here so the disconnect reaper can drop `path → obj-id`
    /// without a reverse scan. Anonymous objects have no path and
    /// therefore never enter LOOKUP list-all.
    by_id: HashMap<ObjectId, ObjectEntry>,
    by_path: BTreeMap<String, ObjectId>,
    /// Live named registrations per owner. Monotonic IDs preserve upstream's
    /// newest-first order without retaining deleted registration history.
    named_by_owner: HashMap<PeerId, BTreeSet<ObjectId>>,
    /// Crate-visible only so the routing-test for AddObject exhaustion
    /// can fast-forward the allocator to its overflow boundary; not
    /// part of any public API.
    pub(crate) next_id: NonZeroU32,
}

impl Default for ObjectRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectRegistry {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            by_path: BTreeMap::new(),
            named_by_owner: HashMap::new(),
            next_id: FIRST_OBJ_ID.0,
        }
    }

    /// Insert `(path, owner)`. Replaces any prior registration at
    /// the same path (libubus does the same — last writer wins,
    /// quietly). Returns the new obj-id and, when a prior
    /// registration existed, `(prev_obj_id, prev_owner_peer_id)` so
    /// the caller can purge the displaced owner's `Peer::owned` list
    /// and any subscriber entries keyed at `prev_obj_id`.
    pub fn insert(
        &mut self,
        path: String,
        owner: PeerId,
        signature: Option<Vec<u8>>,
    ) -> Result<(ObjectId, Option<(ObjectId, PeerId)>), BrokerError> {
        let (id, obj_type) = self.allocate_object_and_type(signature)?;
        let replaced = self.by_path.get(&path).copied().map(|previous| {
            let owner = self.by_id[&previous].owner;
            self.remove(previous);
            (previous, owner)
        });
        self.by_id.insert(
            id,
            ObjectEntry {
                owner,
                path: Some(path.clone()),
                obj_type,
            },
        );
        self.by_path.insert(path, id);
        self.named_by_owner.entry(owner).or_default().insert(id);
        Ok((id, replaced))
    }

    /// Insert a pathless object. libubus subscribers register one of
    /// these as their own object so SUBSCRIBE can validate ownership,
    /// but LOOKUP must never list it because there is no name to
    /// publish.
    pub fn insert_anonymous(&mut self, owner: PeerId) -> Result<ObjectId, BrokerError> {
        let (id, obj_type) = self.allocate_object_and_type(None)?;
        self.by_id.insert(
            id,
            ObjectEntry {
                owner,
                path: None,
                obj_type,
            },
        );
        Ok(id)
    }

    fn allocate_object_and_type(
        &mut self,
        signature: Option<Vec<u8>>,
    ) -> Result<(ObjectId, Option<ObjectType>), BrokerError> {
        let obj_id = ObjectId(self.next_id);
        let after_obj = self
            .next_id
            .checked_add(1)
            .ok_or(BrokerError::ObjectIdExhausted)?;
        let Some(signature) = signature else {
            self.next_id = after_obj;
            return Ok((obj_id, None));
        };
        let type_id = ObjectId(after_obj);
        let after_type = after_obj
            .checked_add(1)
            .ok_or(BrokerError::ObjectIdExhausted)?;
        self.next_id = after_type;
        Ok((
            obj_id,
            Some(ObjectType {
                id: type_id,
                signature,
            }),
        ))
    }

    /// Look up by exact path. Prefix (trailing-`*`) lookup is handled
    /// in `routing::dispatch_lookup` via [`Self::any_path_with_prefix`]
    /// plus [`Self::iter_typed_paths`]; the dispatch path falls back to
    /// "list everything" when the LOOKUP frame omits a path.
    pub fn lookup_exact(&self, path: &str) -> Option<ObjectId> {
        self.by_path.get(path).copied()
    }

    /// Does any *named* object (typed or untyped) carry `prefix`?
    ///
    /// Upstream `ubusd`'s trailing-`*` LOOKUP sets its `found` flag for
    /// any path-prefix match — including untyped objects, which
    /// `ubusd_send_obj` then skips. So the broker answers `STATUS(OK)`
    /// with no DATA when only untyped objects match, and `NOT_FOUND`
    /// only when nothing carries the prefix at all. Anonymous objects
    /// have no path and never enter this set.
    pub fn any_path_with_prefix(&self, prefix: &str) -> bool {
        self.by_path
            .range::<str, _>((
                std::ops::Bound::Included(prefix),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .is_some_and(|(path, _)| path.starts_with(prefix))
    }

    /// Snapshot of every (obj_id, path) pair. Used by LOOKUP's
    /// list-everything shape, which then sorts to match upstream
    /// `ubusd`'s AVL-walk emission order.
    pub fn iter_typed_paths(&self) -> impl Iterator<Item = (ObjectId, &str, &ObjectType)> {
        self.by_path.iter().filter_map(|(path, id)| {
            Some((*id, path.as_str(), self.by_id.get(id)?.obj_type.as_ref()?))
        })
    }

    /// Lexically ordered typed prefix matches, without cloning/sorting paths.
    pub fn iter_typed_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (ObjectId, &'a str, &'a ObjectType)> {
        self.by_path
            .range::<str, _>((
                std::ops::Bound::Included(prefix),
                std::ops::Bound::Unbounded,
            ))
            .take_while(move |(path, _)| path.starts_with(prefix))
            .filter_map(|(path, id)| {
                Some((*id, path.as_str(), self.by_id.get(id)?.obj_type.as_ref()?))
            })
    }

    /// owner peer-id for an obj-id, if registered.
    pub fn owner_of(&self, obj_id: ObjectId) -> Option<PeerId> {
        self.by_id.get(&obj_id).map(|entry| entry.owner)
    }

    pub fn type_of(&self, obj_id: ObjectId) -> Option<&ObjectType> {
        self.by_id.get(&obj_id)?.obj_type.as_ref()
    }

    /// Path of a named object, or `None` for anonymous objects. Used to
    /// build `ubus.object.add`/`remove` event payloads, which must be
    /// read *before* the entry is dropped during REMOVE/disconnect.
    pub fn named_path(&self, obj_id: ObjectId) -> Option<&str> {
        self.by_id.get(&obj_id)?.path.as_deref()
    }

    /// Named objects currently owned by `peer`, newest registration first.
    /// Anonymous objects are absent by construction.
    pub fn named_objects_of(&self, peer: PeerId) -> Vec<(ObjectId, &str)> {
        self.named_by_owner
            .get(&peer)
            .into_iter()
            .flat_map(|ids| ids.iter().rev())
            .filter_map(|id| {
                let entry = self.by_id.get(id)?;
                (entry.owner == peer)
                    .then(|| entry.path.as_deref().map(|path| (*id, path)))
                    .flatten()
            })
            .collect()
    }

    /// Drop one obj-id. Returns whether an object existed; named
    /// objects also scrub their `path → obj-id` entry.
    pub fn remove(&mut self, obj_id: ObjectId) -> bool {
        let Some(entry) = self.by_id.remove(&obj_id) else {
            return false;
        };
        if let Some(path) = entry.path {
            self.by_path.remove(&path);
            if let Some(ids) = self.named_by_owner.get_mut(&entry.owner) {
                ids.remove(&obj_id);
                if ids.is_empty() {
                    self.named_by_owner.remove(&entry.owner);
                }
            }
        }
        true
    }

    /// Drop every object listed in `owned_ids`. Caller is expected to
    /// pass the peer's own [`Peer::owned`] list — that turns the
    /// reaper from `O(N_total_objects)` (scan everything) into
    /// `O(N_peer_objects)` (touch only what this peer registered).
    /// Returns the obj-ids that were actually removed (some entries
    /// may already have been dropped via REMOVE_OBJECT) so the
    /// subscriber registry can mirror the purge.
    pub fn drop_owned_by(&mut self, owned_ids: &[ObjectId]) -> Vec<ObjectId> {
        let mut removed = Vec::with_capacity(owned_ids.len());
        for id in owned_ids {
            if self.remove(*id) {
                removed.push(*id);
            }
        }
        removed
    }
}

#[derive(Debug, Default)]
pub struct SubscriberRegistry {
    /// obj-id → sorted list of subscribers. Sorted Vec keeps
    /// `subscribers_of` returning a contiguous slice (the NOTIFY
    /// fan-out path consumes that directly) while letting add/remove
    /// run in O(log N) lookup + a single shift, so a hot object with
    /// many subscribers no longer pays a linear scan per subscribe.
    ///
    /// The sort key is the whole `Subscription` — `(peer_id, obj_id)`,
    /// not `peer_id` alone. Upstream keys `target->subscribers` by the
    /// *subscriber object* (`ubus_subscription.subscriber`), and
    /// libubus permits several `ubus_subscriber` objects on one
    /// `ubus_context`, so two subscriber objects on the same connection
    /// are two distinct entries: both ids appear in the NOTIFY ack and
    /// both receive fan-out.
    by_obj: HashMap<ObjectId, Vec<Subscription>>,
}

impl SubscriberRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, obj_id: ObjectId, subscriber: PeerId, subscriber_obj: ObjectId) -> bool {
        let list = self.by_obj.entry(obj_id).or_default();
        let was_empty = list.is_empty();
        let sub = Subscription {
            peer_id: subscriber,
            obj_id: subscriber_obj,
        };
        match list.binary_search(&sub) {
            // Exact `(peer, subscriber_obj)` repeat: libubus re-issues
            // SUBSCRIBE idempotently, so this is a no-op rather than a
            // second fan-out target.
            Ok(_) => false,
            Err(pos) => {
                list.insert(pos, sub);
                was_empty
            }
        }
    }

    pub fn remove(
        &mut self,
        obj_id: ObjectId,
        subscriber: PeerId,
        subscriber_obj: ObjectId,
    ) -> (bool, bool) {
        let mut removed = false;
        let mut became_empty = false;
        let sub = Subscription {
            peer_id: subscriber,
            obj_id: subscriber_obj,
        };
        if let Some(list) = self.by_obj.get_mut(&obj_id) {
            if let Ok(pos) = list.binary_search(&sub) {
                list.remove(pos);
                removed = true;
                became_empty = list.is_empty();
            }
            if list.is_empty() {
                self.by_obj.remove(&obj_id);
            }
        }
        (removed, became_empty)
    }

    /// Drop every subscription whose *subscriber object* is `obj_id`
    /// (i.e. the removed object appears as `Subscription.obj_id`), for
    /// the targets listed in `subscribed_to` — the owner's
    /// [`crate::peer::Peer::subs`] mirror. Mirrors upstream's
    /// `obj->target_list` walk in `ubusd_free_object`.
    ///
    /// Returns `(targets_removed_from, targets_that_became_empty)`: the
    /// first lets the caller keep the peer's `subs` mirror honest, the
    /// second drives the publisher's `Active=0` subscribe-status notify.
    pub fn remove_subscriber_object(
        &mut self,
        subscriber: PeerId,
        obj_id: ObjectId,
        subscribed_to: &[ObjectId],
    ) -> (Vec<ObjectId>, Vec<ObjectId>) {
        let mut detached = Vec::new();
        let mut emptied = Vec::new();
        for target in subscribed_to {
            let (removed, became_empty) = self.remove(*target, subscriber, obj_id);
            if removed {
                detached.push(*target);
                if became_empty {
                    emptied.push(*target);
                }
            }
        }
        (detached, emptied)
    }

    pub fn subscribers_of(&self, obj_id: ObjectId) -> &[Subscription] {
        self.by_obj.get(&obj_id).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn remove_object(&mut self, obj_id: ObjectId) -> Vec<Subscription> {
        self.by_obj.remove(&obj_id).unwrap_or_default()
    }

    pub fn remove_objects(&mut self, obj_ids: &[ObjectId]) -> Vec<(ObjectId, Vec<Subscription>)> {
        obj_ids
            .iter()
            .filter_map(|obj_id| {
                let subscribers = self.remove_object(*obj_id);
                if subscribers.is_empty() {
                    None
                } else {
                    Some((*obj_id, subscribers))
                }
            })
            .collect()
    }

    /// Drop every subscription for `peer` (it disconnected). The
    /// caller passes:
    /// * `dead_objs` — obj-ids whose *owner* just left, so any
    ///   subscriber list keyed at those ids needs to vanish entirely.
    /// * `subscribed_to` — the disconnecting peer's own
    ///   [`Peer::subs`] list, so removing the peer from each of
    ///   *those* obj-ids' subscriber vectors is `O(S_peer)` instead
    ///   of scanning every still-alive obj-id in the registry.
    pub fn purge_peer(
        &mut self,
        peer: PeerId,
        dead_objs: &[ObjectId],
        subscribed_to: &[ObjectId],
    ) -> Vec<ObjectId> {
        let mut emptied_objects = Vec::new();
        for id in dead_objs {
            self.by_obj.remove(id);
        }
        for obj_id in subscribed_to {
            if let Some(list) = self.by_obj.get_mut(obj_id) {
                // A connection may hold several subscriber objects on
                // the same target, so drop every entry it owns — not
                // just the first one a keyed search lands on.
                let before = list.len();
                list.retain(|s| s.peer_id != peer);
                if list.len() != before && list.is_empty() {
                    emptied_objects.push(*obj_id);
                }
                if list.is_empty() {
                    self.by_obj.remove(obj_id);
                }
            }
        }
        emptied_objects
    }
}

/// One `ubus listen` registration. The listener's own object id is
/// stamped as `ObjId` in every fan-out INVOKE it receives; `peer_id`
/// is its connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventListener {
    /// Pattern with any single trailing `*` stripped. Empty = catch-all
    /// (`ubus listen` with no arg sends `"*"` → prefix `""`).
    pub prefix: String,
    /// True when the registered pattern ended in `*` (prefix match);
    /// false for an exact-name match. Upstream `ubusd` treats only a
    /// trailing `*` as a wildcard — `[`/`?` are literal, same as LOOKUP.
    pub partial: bool,
    pub peer_id: PeerId,
    pub obj_id: ObjectId,
}

impl EventListener {
    fn matches(&self, event_id: &str) -> bool {
        if self.partial {
            event_id.starts_with(&self.prefix)
        } else {
            event_id == self.prefix
        }
    }
}

/// Broker-global event bus: `ubus listen` registrations plus the single
/// monotonic fan-out sequence counter. Distinct from the per-client
/// subscription-notify counter (`Peer::next_notify_seq`); upstream keeps
/// event fan-out on its own broker-wide `obj_event_seq`.
#[derive(Debug)]
pub struct EventRegistry {
    listeners: BTreeMap<String, Vec<EventListener>>,
    next_seq: u16,
}

/// Registered monitor peers and their independent wire sequence counters.
#[derive(Debug, Default)]
pub struct MonitorRegistry {
    monitors: Vec<(PeerId, u16)>,
}

impl MonitorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-registration resets the counter and moves the monitor to the tail.
    pub fn add(&mut self, peer_id: PeerId) {
        self.remove(peer_id);
        self.monitors.push((peer_id, 1));
    }

    pub fn remove(&mut self, peer_id: PeerId) -> bool {
        let Some(pos) = self.monitors.iter().position(|(id, _)| *id == peer_id) else {
            return false;
        };
        self.monitors.remove(pos);
        true
    }

    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.remove(peer_id);
    }

    pub fn is_empty(&self) -> bool {
        self.monitors.is_empty()
    }

    /// Mint one sequence for every registered monitor, in registration order.
    pub fn mint_seqs(&mut self) -> Vec<(PeerId, u16)> {
        self.monitors
            .iter_mut()
            .map(|(id, next)| {
                let seq = *next;
                *next = next.wrapping_add(1);
                (*id, seq)
            })
            .collect()
    }
}

impl Default for EventRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EventRegistry {
    pub fn new() -> Self {
        // Upstream's first fan-out delivery carries seq 1.
        Self {
            listeners: BTreeMap::new(),
            next_seq: 1,
        }
    }

    /// Register a listener. libubus re-issues `register` idempotently;
    /// an exact duplicate (same peer, object, pattern) is a no-op so a
    /// refresh can't double-deliver.
    pub fn register(&mut self, prefix: String, partial: bool, peer_id: PeerId, obj_id: ObjectId) {
        let listeners = self.listeners.entry(prefix.clone()).or_default();
        if listeners.iter().any(|listener| {
            listener.peer_id == peer_id && listener.obj_id == obj_id && listener.partial == partial
        }) {
            return;
        }
        let at = listeners.partition_point(|listener| listener.obj_id <= obj_id);
        listeners.insert(
            at,
            EventListener {
                prefix,
                partial,
                peer_id,
                obj_id,
            },
        );
    }

    /// Drop every listener owned by `peer` (it disconnected).
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.listeners.retain(|_, listeners| {
            listeners.retain(|listener| listener.peer_id != peer_id);
            !listeners.is_empty()
        });
    }

    /// Drop every listener registered against `obj_id` (its object was
    /// removed). Upstream hangs each `event_source` off `obj->events`
    /// and frees the list in `ubusd_event_cleanup_object()`, called from
    /// `ubusd_free_object()` — so a REMOVE_OBJECT ends the registration,
    /// not just a disconnect.
    pub fn remove_object(&mut self, obj_id: ObjectId) {
        self.listeners.retain(|_, listeners| {
            listeners.retain(|listener| listener.obj_id != obj_id);
            !listeners.is_empty()
        });
    }

    /// Post-increment the global fan-out seq (wraps like any wire seq).
    pub fn next_seq(&mut self) -> u16 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        s
    }

    /// `(peer, listener_obj)` for every listener matching `event_id`, in
    /// pattern-key lexicographic order — the order upstream `ubusd`
    /// walks its pattern AVL, which the global seq numbering depends on.
    /// `exclude` drops the event's own originator (upstream's
    /// `ev->obj->client == cl` loop-back guard).
    pub fn matching_sorted(
        &self,
        event_id: &str,
        exclude: Option<PeerId>,
    ) -> Vec<(PeerId, ObjectId)> {
        let mut matches = Vec::new();
        let mut visit = |listeners: &[EventListener]| {
            matches.extend(
                listeners
                    .iter()
                    .filter(|listener| {
                        Some(listener.peer_id) != exclude && listener.matches(event_id)
                    })
                    .map(|listener| (listener.peer_id, listener.obj_id)),
            );
        };
        // Only prefixes can match. Avoid a length-driven quadratic search on
        // unusually long names by scanning the smaller live index instead.
        if event_id.len() < self.listeners.len() {
            for end in (0..=event_id.len()).filter(|&end| event_id.is_char_boundary(end)) {
                if let Some(listeners) = self.listeners.get(&event_id[..end]) {
                    visit(listeners);
                }
            }
        } else {
            for listeners in self.listeners.values() {
                visit(listeners);
            }
        }
        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u32) -> PeerId {
        PeerId::new(n).unwrap()
    }

    #[test]
    fn registration_churn_keeps_only_live_owner_entries() {
        let mut objects = ObjectRegistry::new();
        let owner = pid(1025);
        let survivor = objects.insert("keep".into(), owner, None).unwrap().0;
        for _ in 0..4096 {
            let first = objects.insert("churn".into(), owner, None).unwrap().0;
            let (second, replaced) = objects.insert("churn".into(), pid(1026), None).unwrap();
            assert_eq!(replaced, Some((first, owner)));
            assert!(objects.remove(second));
            assert_eq!(objects.named_by_owner.len(), 1);
            assert_eq!(objects.named_by_owner[&owner].len(), 1);
        }
        assert_eq!(objects.named_objects_of(owner), vec![(survivor, "keep")]);
        objects.drop_owned_by(&[survivor]);
        assert!(objects.named_by_owner.is_empty());
        assert!(objects.by_path.is_empty());
        assert!(objects.by_id.is_empty());
    }

    #[test]
    fn peer_ids_are_monotonic_no_reuse() {
        let mut tbl = PeerTable::new();
        let (id1, slot1) = tbl.insert(Peer::stub()).unwrap();
        let (id2, _) = tbl.insert(Peer::stub()).unwrap();
        assert_eq!(id1, FIRST_PEER_ID);
        assert_eq!(id2.get(), FIRST_PEER_ID.get() + 1);
        tbl.remove(id1);
        // Slot can be reused, but the id allocator keeps climbing.
        let (id3, slot3) = tbl.insert(Peer::stub()).unwrap();
        assert_eq!(id3.get(), FIRST_PEER_ID.get() + 2);
        assert_eq!(slot3, slot1, "slot should be recycled, id should not");
    }

    #[test]
    fn obj_registry_replaces_path_collision() {
        let mut reg = ObjectRegistry::new();
        let (id1, prev1) = reg.insert("example".into(), pid(1025), None).unwrap();
        let (id2, prev2) = reg.insert("example".into(), pid(1026), None).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(prev1, None);
        assert_eq!(prev2, Some((id1, pid(1025))));
        assert_eq!(reg.owner_of(id1), None);
        assert_eq!(reg.owner_of(id2), Some(pid(1026)));
    }

    #[test]
    fn anonymous_objects_have_owner_but_no_lookup_path() {
        let mut reg = ObjectRegistry::new();
        let anon = reg.insert_anonymous(pid(1025)).unwrap();
        let (named, _) = reg
            .insert("example".into(), pid(1026), Some(vec![1, 2, 3, 4]))
            .unwrap();

        assert_eq!(reg.owner_of(anon), Some(pid(1025)));
        assert_eq!(reg.lookup_exact("example"), Some(named));
        assert_eq!(
            reg.iter_typed_paths()
                .map(|(id, path, ty)| (id, path, ty.signature()))
                .collect::<Vec<_>>(),
            vec![(named, "example", &[1, 2, 3, 4][..])]
        );
    }

    #[test]
    fn named_objects_of_is_reverse_registration_order_and_skips_anonymous() {
        let mut reg = ObjectRegistry::new();
        let owner = pid(1025);
        let (first, _) = reg.insert("svc.first".into(), owner, None).unwrap();
        let _anonymous = reg.insert_anonymous(owner).unwrap();
        let (second, _) = reg.insert("svc.second".into(), owner, None).unwrap();

        assert_eq!(
            reg.named_objects_of(owner),
            vec![(second, "svc.second"), (first, "svc.first")]
        );
    }

    #[test]
    fn typed_objects_allocate_distinct_type_ids_from_object_id_space() {
        let mut reg = ObjectRegistry::new();
        let sig = vec![0xaa, 0xbb];

        let (id1, _) = reg
            .insert("example.one".into(), pid(1025), Some(sig.clone()))
            .unwrap();
        let (id2, _) = reg
            .insert("example.two".into(), pid(1025), Some(sig.clone()))
            .unwrap();

        let ty1 = reg.type_of(id1).expect("type for first object");
        let ty2 = reg.type_of(id2).expect("type for second object");
        assert_ne!(ty1.id(), id1);
        assert_ne!(ty2.id(), id2);
        assert_ne!(ty1.id(), ty2.id(), "types are never deduplicated");
        assert_eq!(id1.get(), FIRST_OBJ_ID.get());
        assert_eq!(ty1.id().get(), FIRST_OBJ_ID.get() + 1);
        assert_eq!(id2.get(), FIRST_OBJ_ID.get() + 2);
        assert_eq!(ty2.id().get(), FIRST_OBJ_ID.get() + 3);
        assert_eq!(ty1.signature(), sig.as_slice());
        assert_eq!(ty2.signature(), sig.as_slice());
    }

    #[test]
    fn drop_owned_by_reaps_anonymous_object_owner() {
        let mut reg = ObjectRegistry::new();
        let anon = reg.insert_anonymous(pid(1025)).unwrap();

        let dead = reg.drop_owned_by(&[anon]);

        assert_eq!(dead, vec![anon]);
        assert_eq!(reg.owner_of(anon), None);
        assert!(reg.iter_typed_paths().next().is_none());
    }

    #[test]
    fn drop_owned_by_cascades_into_subscribers() {
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = pid(1025);
        let bystander = pid(1026);
        let (id, _) = objs.insert("example".into(), owner, None).unwrap();
        subs.add(id, bystander, id);
        // The broker passes the owner's own `Peer::owned` list — here
        // we mirror that by handing in [id] explicitly.
        let dead = objs.drop_owned_by(&[id]);
        assert_eq!(dead, vec![id]);
        // Owner's subs list is empty: it didn't subscribe to anything.
        subs.purge_peer(owner, &dead, &[]);
        assert!(subs.subscribers_of(id).is_empty());
    }

    #[test]
    fn subscriber_disconnect_purges_only_self_keeping_other_subscribers() {
        // Cover the `subscribed_to` arm of purge_peer: a subscriber
        // disconnect must not leak a stale peer-id into a still-live
        // owner's subscriber list, but must also not evict any other
        // subscriber.
        let mut objs = ObjectRegistry::new();
        let mut subs = SubscriberRegistry::new();
        let owner = pid(1025);
        let leaver = pid(1026);
        let stayer = pid(1027);
        let (obj, _) = objs.insert("example.events".into(), owner, None).unwrap();
        subs.add(obj, leaver, obj);
        subs.add(obj, stayer, obj);
        assert_eq!(
            subs.subscribers_of(obj)
                .iter()
                .map(|s| s.peer_id)
                .collect::<Vec<_>>(),
            vec![leaver, stayer]
        );

        // Leaver disconnects: it owned nothing (dead_objs = []) and was
        // subscribed to one obj.
        subs.purge_peer(leaver, &[], &[obj]);

        assert_eq!(
            subs.subscribers_of(obj)
                .iter()
                .map(|s| s.peer_id)
                .collect::<Vec<_>>(),
            vec![stayer],
            "stayer must remain after leaver disconnect"
        );
    }

    #[test]
    fn peer_table_insert_at_u32_max_returns_exhausted() {
        let mut tbl = PeerTable::new();
        tbl.next_id = NonZeroU32::new(u32::MAX).unwrap();
        match tbl.insert(Peer::stub()) {
            Err(BrokerError::PeerIdExhausted) => {}
            other => panic!("expected PeerIdExhausted, got {other:?}"),
        }
        // The would-be id was never issued, so the next call still
        // sees the same exhausted state — no silent recycling.
        assert_eq!(tbl.next_id.get(), u32::MAX);
        assert!(tbl.id_to_slot.is_empty());
    }

    #[test]
    fn object_registry_insert_at_u32_max_returns_exhausted() {
        let mut reg = ObjectRegistry::new();
        reg.next_id = NonZeroU32::new(u32::MAX).unwrap();
        match reg.insert("example".into(), pid(1025), None) {
            Err(BrokerError::ObjectIdExhausted) => {}
            other => panic!("expected ObjectIdExhausted, got {other:?}"),
        }
        // Path map MUST be untouched — a failed insert that left a
        // half-purged prior registration would silently delete the
        // owner's existing object.
        assert!(reg.by_path.is_empty());
        assert!(reg.by_id.is_empty());
    }

    #[test]
    fn monitors_mint_in_registration_order_and_reset_on_readd() {
        let mut monitors = MonitorRegistry::new();
        monitors.add(pid(2));
        monitors.add(pid(3));
        assert_eq!(monitors.mint_seqs(), vec![(pid(2), 1), (pid(3), 1)]);
        monitors.add(pid(2));
        assert_eq!(monitors.mint_seqs(), vec![(pid(3), 2), (pid(2), 1)]);
        assert!(monitors.remove(pid(3)));
        assert!(!monitors.remove(pid(3)));
        assert_eq!(monitors.mint_seqs(), vec![(pid(2), 2)]);
    }
}
