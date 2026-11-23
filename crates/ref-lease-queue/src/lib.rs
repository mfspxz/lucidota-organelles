//! org-030 — Reference organelle: lease-queue (codon `lq`).
//!
//! A job queue with leases, a claim/complete lifecycle, and
//! idempotency keys (GAP-05 in the 2026-11-22 decomposition map:
//! six scoped softwares — FAC, WRK, EXC, EVD, VAN, MCP — hand-roll
//! the same machinery today: `factory-dispatch`'s persisted FIFO
//! queue and `factory-jobs`' job store, wreck-worker's JS
//! caps/lease/idempotency modules, the Exchange's claim lifecycle
//! in `claims.rs`, eventd's webhook retry queue, VanCan's dispatch
//! claim/lease state, and the MCP vending machine's single-use
//! tokens).  The Exchange's machinery is the semantics reference:
//! leases are minted with a TTL, completion re-checks lease expiry
//! before it is accepted, a sweep expires zombies and orphans, and
//! — the v0.7.2 lesson — a claimant that comes back re-attaches to
//! its own live lease instead of orphaning it.
//!
//! The contract this crate implements:
//!
//! * **Atomic single-winner claim.**  A queued item is claimed by
//!   exactly one claimant, even under parallel racing.  Claims go
//!   through the store's compare-and-swap on the item version; the
//!   in-memory backend's CAS is mutex-atomic and the SQLite
//!   backend's is a conditional `UPDATE`, atomic at the database
//!   level even across processes sharing one file.
//! * **Leases are time-bounded, and time is an input.**  The core
//!   state machine never reads a system clock: every operation
//!   takes the current time from the injected [`Clock`].  Lease
//!   expiry is evaluated lazily by every operation that touches a
//!   leased item, and in bulk by [`LeaseQueue::reap`].
//! * **Claim-resume.**  A claimant holding a live lease gets that
//!   same lease back from [`LeaseQueue::claim`] /
//!   [`LeaseQueue::resume_claim`] — never a second item, never a
//!   fresh lease on the same item.  A different claimant is refused
//!   while the lease is live.
//! * **Caller-supplied knobs only.**  Lease duration, the attempt
//!   cap, the backoff policy, and the exhausted-item action are all
//!   required construction data (see [`QueueConfig`]).  There is no
//!   `Default` for the configuration and no behaviour in this crate
//!   that a caller did not state.
//! * **Telemetry.**  Every state transition appends a
//!   [`QueueEvent`] to the queue's event log — enqueues, duplicate
//!   enqueues, claims, resumes, heartbeats, completions, failures,
//!   retry schedules, lease expiries, exhaustions — so the whole
//!   lifecycle drops into a receipt or an evidence log.
//!
//! Storage sits behind the [`Store`] trait.  [`MemoryStore`] is
//! the test/embedded backend; `SqliteStore` (feature `sqlite`,
//! native only) is the durable backend.  The state machine is
//! storage-agnostic and deterministic: same operation sequence +
//! same clock readings → same items, same events, byte-identical.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};

// ---------------------------------------------------------------------
// Configuration.  Every knob is required construction data; the
// crate states no defaults, because a default would be a behaviour
// the caller never chose.
// ---------------------------------------------------------------------

/// What happens to an item whose attempts are exhausted (by
/// failures, by lease expiries, or by one of each).  Caller-stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustedAction {
    /// The item is kept in state [`ItemState::Dead`] for
    /// inspection — the dead-letter queue.
    DeadLetter,
    /// The item record is removed from the store.  The removal is
    /// on the event log; the record is not.
    Discard,
}

/// The retry delay policy, as caller data.  Delays are computed
/// for the attempt that just failed (1-based): the failure of
/// attempt `n` schedules the next availability at
/// `now + delay_after(n)`.  The failure of the final allowed
/// attempt never consults the policy — the item is exhausted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BackoffPolicy {
    /// Every retry waits the same delay.
    Fixed { delay_ms: u64 },
    /// Attempt `n` waits `base_ms + step_ms * (n - 1)`.
    Linear { base_ms: u64, step_ms: u64 },
    /// Attempt `n` waits `min(cap_ms, base_ms * factor^(n-1))`.
    Exponential { base_ms: u64, factor: u32, cap_ms: u64 },
    /// Attempt `n` waits `delays_ms[n - 1]`.  Construction
    /// validates that the schedule covers every retry the attempt
    /// cap can produce (`delays_ms.len() >= max_attempts - 1`).
    Schedule { delays_ms: Vec<u64> },
}

impl BackoffPolicy {
    /// The delay after the failure of attempt `failed_attempt`
    /// (1-based).  Callers (the queue core) only consult this for
    /// `failed_attempt < max_attempts`; the `Schedule` fallback to
    /// the last entry exists so the function is total, and
    /// construction validation makes it unreachable in practice.
    pub fn delay_after(&self, failed_attempt: u32) -> u64 {
        let n = failed_attempt.max(1);
        match self {
            BackoffPolicy::Fixed { delay_ms } => *delay_ms,
            BackoffPolicy::Linear { base_ms, step_ms } => base_ms
                .saturating_add(step_ms.saturating_mul(u64::from(n - 1))),
            BackoffPolicy::Exponential {
                base_ms,
                factor,
                cap_ms,
            } => {
                let mut delay = *base_ms;
                for _ in 1..n {
                    delay = delay.saturating_mul(u64::from(*factor));
                    if delay >= *cap_ms {
                        return *cap_ms;
                    }
                }
                delay.min(*cap_ms)
            }
            BackoffPolicy::Schedule { delays_ms } => delays_ms
                .get((n - 1) as usize)
                .copied()
                .unwrap_or_else(|| delays_ms.last().copied().unwrap_or(0)),
        }
    }
}

/// The queue's complete configuration.  No `Default`, no optional
/// fields: construction requires every knob, stated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueConfig {
    /// How long a claim's lease lives before it expires, in
    /// milliseconds.  Must be > 0.
    pub lease_duration_ms: u64,
    /// Maximum number of claims an item may accumulate before it
    /// is exhausted.  Must be >= 1.
    pub max_attempts: u32,
    /// Retry delays after failed / expired attempts.
    pub backoff: BackoffPolicy,
    /// What happens when the attempt cap is reached.
    pub on_exhausted: ExhaustedAction,
}

impl QueueConfig {
    /// Validate the configuration as a whole.  [`LeaseQueue::new`]
    /// runs this and refuses an invalid configuration; the checks
    /// exist so a policy can never be *unstateable* at runtime
    /// (e.g. a retry schedule shorter than the retries the cap
    /// allows).
    pub fn validate(&self) -> Result<(), QueueError> {
        if self.lease_duration_ms == 0 {
            return Err(QueueError::Config(
                "lease_duration_ms must be > 0".to_string(),
            ));
        }
        if self.max_attempts == 0 {
            return Err(QueueError::Config("max_attempts must be >= 1".to_string()));
        }
        match &self.backoff {
            BackoffPolicy::Exponential { factor, .. } if *factor == 0 => {
                return Err(QueueError::Config(
                    "exponential backoff factor must be >= 1".to_string(),
                ));
            }
            BackoffPolicy::Schedule { delays_ms } => {
                let needed = self.max_attempts.saturating_sub(1) as usize;
                if delays_ms.len() < needed {
                    return Err(QueueError::Config(format!(
                        "backoff schedule has {} delays but max_attempts {} can require {needed}",
                        delays_ms.len(),
                        self.max_attempts
                    )));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Clock.  Time is an injected input: the core logic reads time
// only through this trait, never from the system.
// ---------------------------------------------------------------------

/// The queue's source of time, in epoch milliseconds.
pub trait Clock {
    fn now_ms(&self) -> i64;
}

/// A clock the caller drives by hand — the deterministic clock for
/// tests, simulations, and hosts that supply time as an input
/// (the organelle surface uses this, with `now_ms` taken from each
/// call's input).
#[derive(Debug, Default)]
pub struct ManualClock {
    now: std::sync::atomic::AtomicI64,
}

impl ManualClock {
    pub fn new(now_ms: i64) -> Self {
        Self {
            now: std::sync::atomic::AtomicI64::new(now_ms),
        }
    }
    pub fn set(&self, now_ms: i64) {
        self.now
            .store(now_ms, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn advance(&self, delta_ms: i64) {
        self.now
            .fetch_add(delta_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The system clock, for native callers that want wall time.
/// Not offered on wasm32, where `SystemTime` is not a clock the
/// platform guarantees — wasm hosts inject time as an input and
/// use [`ManualClock`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[cfg(not(target_arch = "wasm32"))]
impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------
// Items, leases, errors.
// ---------------------------------------------------------------------

/// The lifecycle state of a queued item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// Waiting to be claimed; claimable once
    /// `available_at_ms <= now`.
    Queued,
    /// Claimed; held under the item's live lease.
    Leased,
    /// Completed by its lease holder.  Terminal.
    Done,
    /// Attempts exhausted under
    /// [`ExhaustedAction::DeadLetter`].  Terminal.
    Dead,
}

/// One live lease on an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub lease_id: String,
    pub claimant: String,
    pub claimed_at_ms: i64,
    pub expires_at_ms: i64,
}

/// One queue item — the stored record.  `version` is the store's
/// compare-and-swap counter: it starts at 0 on enqueue and
/// increments on every mutation.  `seq` is the store-assigned
/// FIFO order (assigned by [`Store::insert`]; the value on a
/// freshly built item is ignored).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub state: ItemState,
    /// Number of claims made on this item so far.
    pub attempts: u32,
    pub version: u64,
    pub seq: u64,
    pub enqueued_at_ms: i64,
    /// Earliest time the item may be claimed.
    pub available_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    /// The result supplied to `complete`, once done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The most recent failure / expiry reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Everything that can go wrong, stated honestly.  A rejected
/// operation never mutates the item it names — with one documented
/// exception: `complete` / `fail` / `heartbeat` arriving after
/// lease expiry first run the item's expiry transition (the lease
/// *has* expired; the record says so) and only then return
/// [`QueueError::LeaseExpired`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    /// The queue configuration is invalid (construction-time).
    Config(String),
    /// An item with this id already exists (and the enqueue was
    /// not an idempotent replay of it).
    DuplicateId(String),
    /// No item with this id.
    NotFound(String),
    /// The item is not in a state that allows the operation.
    InvalidState(String),
    /// The named lease does not exist on the item, or belongs to a
    /// different claimant.  One variant for both: a caller learns
    /// "not yours", never whose it is.
    NotLeaseHolder(String),
    /// The lease existed but its expiry has passed.
    LeaseExpired(String),
    /// The storage backend failed.
    Store(String),
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueueError::Config(m) => write!(f, "lease-queue config: {m}"),
            QueueError::DuplicateId(id) => write!(f, "lease-queue: duplicate item id {id}"),
            QueueError::NotFound(id) => write!(f, "lease-queue: no item {id}"),
            QueueError::InvalidState(m) => write!(f, "lease-queue: invalid state: {m}"),
            QueueError::NotLeaseHolder(id) => {
                write!(f, "lease-queue: not the lease holder for item {id}")
            }
            QueueError::LeaseExpired(id) => {
                write!(f, "lease-queue: lease expired for item {id}")
            }
            QueueError::Store(m) => write!(f, "lease-queue store: {m}"),
        }
    }
}

impl std::error::Error for QueueError {}

// ---------------------------------------------------------------------
// Storage.  The state machine is written against this trait only.
// ---------------------------------------------------------------------

/// The storage contract.  Implementations must make [`Store::cas`]
/// atomic: it writes `item` (whose `version` is
/// `expected_version + 1`) iff the stored record for `item.id`
/// still has `expected_version`, and reports whether it wrote.
/// That single primitive is what makes claim single-winner.
pub trait Store {
    /// Insert a new item, assigning its FIFO `seq`; returns the
    /// stored record.  Fails with [`QueueError::DuplicateId`] if
    /// the id (or idempotency key) is already present.
    fn insert(&mut self, item: Item) -> Result<Item, QueueError>;
    /// Fetch one item by id.
    fn get(&mut self, id: &str) -> Result<Option<Item>, QueueError>;
    /// Fetch one item by idempotency key.
    fn get_by_idempotency_key(&mut self, key: &str) -> Result<Option<Item>, QueueError>;
    /// Every item, in `seq` (FIFO) order.
    fn list(&mut self) -> Result<Vec<Item>, QueueError>;
    /// Atomic compare-and-swap on the item version.
    fn cas(&mut self, expected_version: u64, item: Item) -> Result<bool, QueueError>;
    /// Remove an item; reports whether it existed.
    fn remove(&mut self, id: &str) -> Result<bool, QueueError>;
}

/// The in-memory backend: a map plus a sequence counter.  CAS is
/// atomic because every access runs under the queue's store lock
/// (and the version check is performed against the stored record,
/// so the primitive means what it says even if a future caller
/// drives the store directly).
#[derive(Debug, Default)]
pub struct MemoryStore {
    items: BTreeMap<String, Item>,
    next_seq: u64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn insert(&mut self, mut item: Item) -> Result<Item, QueueError> {
        if self.items.contains_key(&item.id) {
            return Err(QueueError::DuplicateId(item.id.clone()));
        }
        if let Some(key) = &item.idempotency_key {
            if self.items.values().any(|i| i.idempotency_key.as_ref() == Some(key)) {
                return Err(QueueError::DuplicateId(item.id.clone()));
            }
        }
        self.next_seq += 1;
        item.seq = self.next_seq;
        self.items.insert(item.id.clone(), item.clone());
        Ok(item)
    }

    fn get(&mut self, id: &str) -> Result<Option<Item>, QueueError> {
        Ok(self.items.get(id).cloned())
    }

    fn get_by_idempotency_key(&mut self, key: &str) -> Result<Option<Item>, QueueError> {
        Ok(self
            .items
            .values()
            .find(|i| i.idempotency_key.as_deref() == Some(key))
            .cloned())
    }

    fn list(&mut self) -> Result<Vec<Item>, QueueError> {
        let mut all: Vec<Item> = self.items.values().cloned().collect();
        all.sort_by_key(|i| i.seq);
        Ok(all)
    }

    fn cas(&mut self, expected_version: u64, item: Item) -> Result<bool, QueueError> {
        match self.items.get(&item.id) {
            Some(stored) if stored.version == expected_version && item.version == expected_version + 1 => {
                self.items.insert(item.id.clone(), item);
                Ok(true)
            }
            Some(_) => Ok(false),
            None => Err(QueueError::NotFound(item.id.clone())),
        }
    }

    fn remove(&mut self, id: &str) -> Result<bool, QueueError> {
        Ok(self.items.remove(id).is_some())
    }
}

// ---------------------------------------------------------------------
// Operation outcomes and the event log (telemetry).
// ---------------------------------------------------------------------

/// The result of an enqueue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum EnqueueOutcome {
    /// A new item entered the queue.
    Enqueued { item_id: String },
    /// An item with this idempotency key already exists; nothing
    /// was created.  Carries the existing item's id and state, so
    /// a replaying producer learns the original's fate.
    Duplicate { item_id: String, state: ItemState },
}

/// A successful claim (or claim-resume).  `attempt` is the item's
/// claim count including this claim; on a resume it is the count
/// of the original claim — a resume is not a new attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub item_id: String,
    pub lease_id: String,
    pub claimant: String,
    pub attempt: u32,
    pub claimed_at_ms: i64,
    pub expires_at_ms: i64,
    /// True when this is a re-attachment to the claimant's own
    /// live lease, not a fresh claim.
    pub resumed: bool,
    pub payload: Value,
}

/// The result of a `fail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum FailOutcome {
    /// The item is queued again, claimable at `available_at_ms`.
    RetryScheduled { available_at_ms: i64, attempts: u32 },
    /// The attempt cap was reached; the configured
    /// [`ExhaustedAction`] was applied.
    Exhausted { action: ExhaustedAction },
}

/// One item transitioned by a reap (or by lazy expiry inside
/// another operation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReapedItem {
    pub item_id: String,
    /// The claimant whose lease expired.
    pub claimant: String,
    /// Where the item went: `retry_scheduled` (claimable at
    /// `available_at_ms`) or `exhausted` (the configured action
    /// was applied; the item is `Dead` or removed).
    pub outcome: FailOutcome,
}

/// The kind of a [`QueueEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Enqueued,
    DuplicateEnqueue,
    Claimed,
    Resumed,
    Heartbeat,
    Completed,
    Failed,
    RetryScheduled,
    LeaseExpired,
    Exhausted,
    Discarded,
}

/// One recorded state transition.  The log is the queue's
/// telemetry: append-only within a queue instance, sequentially
/// numbered, timestamped from the injected clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueEvent {
    pub seq: u64,
    pub at_ms: i64,
    pub kind: EventKind,
    pub item_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimant: Option<String>,
    pub detail: String,
}

/// Item counts by state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub queued: u64,
    pub leased: u64,
    pub done: u64,
    pub dead: u64,
    pub total: u64,
}

// ---------------------------------------------------------------------
// The queue.
// ---------------------------------------------------------------------

/// A lease queue over a [`Store`], driven by an injected
/// [`Clock`].  All operations take `&self`: store access is
/// serialized internally, and each operation performs its whole
/// read–modify–write under one lock acquisition, on top of the
/// store's atomic CAS.
pub struct LeaseQueue<S: Store, C: Clock> {
    config: QueueConfig,
    store: Mutex<S>,
    clock: C,
    events: Mutex<Vec<QueueEvent>>,
    next_event_seq: Mutex<u64>,
}

impl<S: Store, C: Clock> LeaseQueue<S, C> {
    /// Build a queue.  The configuration is validated here and an
    /// invalid one is refused — there are no defaults to fall
    /// back to.
    pub fn new(config: QueueConfig, store: S, clock: C) -> Result<Self, QueueError> {
        config.validate()?;
        Ok(Self {
            config,
            store: Mutex::new(store),
            clock,
            events: Mutex::new(Vec::new()),
            next_event_seq: Mutex::new(0),
        })
    }

    pub fn config(&self) -> &QueueConfig {
        &self.config
    }

    pub fn clock(&self) -> &C {
        &self.clock
    }

    fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    fn emit(&self, at_ms: i64, kind: EventKind, item_id: &str, claimant: Option<&str>, detail: String) {
        let mut seq = self.next_event_seq.lock().expect("event seq lock");
        *seq += 1;
        let event = QueueEvent {
            seq: *seq,
            at_ms,
            kind,
            item_id: item_id.to_string(),
            claimant: claimant.map(str::to_string),
            detail,
        };
        self.events.lock().expect("event log lock").push(event);
    }

    /// The full event log, in order.
    pub fn events(&self) -> Vec<QueueEvent> {
        self.events.lock().expect("event log lock").clone()
    }

    /// Add an item to the queue.  With an idempotency key, a
    /// replayed enqueue (same key, any id) creates nothing and
    /// reports the existing item; reusing an *id* for a different
    /// item is [`QueueError::DuplicateId`].
    pub fn enqueue(
        &self,
        id: &str,
        payload: Value,
        idempotency_key: Option<&str>,
    ) -> Result<EnqueueOutcome, QueueError> {
        let now = self.now();
        let mut store = self.store.lock().expect("store lock");
        if let Some(key) = idempotency_key {
            if let Some(existing) = store.get_by_idempotency_key(key)? {
                self.emit(
                    now,
                    EventKind::DuplicateEnqueue,
                    &existing.id,
                    None,
                    format!("idempotency key replay; existing state {:?}", existing.state),
                );
                return Ok(EnqueueOutcome::Duplicate {
                    item_id: existing.id,
                    state: existing.state,
                });
            }
        }
        if store.get(id)?.is_some() {
            return Err(QueueError::DuplicateId(id.to_string()));
        }
        let item = Item {
            id: id.to_string(),
            payload,
            idempotency_key: idempotency_key.map(str::to_string),
            state: ItemState::Queued,
            attempts: 0,
            version: 0,
            seq: 0,
            enqueued_at_ms: now,
            available_at_ms: now,
            lease: None,
            result: None,
            last_error: None,
        };
        let stored = store.insert(item)?;
        self.emit(now, EventKind::Enqueued, &stored.id, None, "enqueued".to_string());
        Ok(EnqueueOutcome::Enqueued {
            item_id: stored.id,
        })
    }

    /// Claim the next available item for `claimant`.
    ///
    /// Order of business, all under one store lock: (1) every
    /// expired lease is transitioned (lazy reap), so a dead
    /// claimant's item is not stranded; (2) if `claimant` already
    /// holds a live lease, that lease is returned as a resume —
    /// a claimant never holds two; (3) the earliest-seq queued
    /// item with `available_at_ms <= now` is claimed via CAS.
    /// Returns `None` when nothing is claimable.
    pub fn claim(&self, claimant: &str) -> Result<Option<Claim>, QueueError> {
        let now = self.now();
        let mut store = self.store.lock().expect("store lock");
        self.reap_expired(&mut store, now)?;

        let items = store.list()?;
        // (2) Resume: this claimant's own live lease comes back.
        for item in &items {
            if item.state == ItemState::Leased {
                if let Some(lease) = &item.lease {
                    if lease.claimant == claimant && lease.expires_at_ms > now {
                        self.emit(
                            now,
                            EventKind::Resumed,
                            &item.id,
                            Some(claimant),
                            format!("lease {} re-attached", lease.lease_id),
                        );
                        return Ok(Some(Claim {
                            item_id: item.id.clone(),
                            lease_id: lease.lease_id.clone(),
                            claimant: claimant.to_string(),
                            attempt: item.attempts,
                            claimed_at_ms: lease.claimed_at_ms,
                            expires_at_ms: lease.expires_at_ms,
                            resumed: true,
                            payload: item.payload.clone(),
                        }));
                    }
                }
            }
        }
        // (3) Fresh claim, FIFO, CAS-guarded.
        for item in &items {
            if item.state != ItemState::Queued || item.available_at_ms > now {
                continue;
            }
            let attempt = item.attempts + 1;
            let lease_id = lease_id_for(&item.id, claimant, now, attempt, item.version + 1);
            let lease = Lease {
                lease_id: lease_id.clone(),
                claimant: claimant.to_string(),
                claimed_at_ms: now,
                expires_at_ms: now.saturating_add(self.config.lease_duration_ms as i64),
            };
            let mut claimed = item.clone();
            claimed.state = ItemState::Leased;
            claimed.attempts = attempt;
            claimed.version = item.version + 1;
            claimed.lease = Some(lease.clone());
            if store.cas(item.version, claimed)? {
                self.emit(
                    now,
                    EventKind::Claimed,
                    &item.id,
                    Some(claimant),
                    format!("attempt {attempt}, lease {lease_id}"),
                );
                return Ok(Some(Claim {
                    item_id: item.id.clone(),
                    lease_id,
                    claimant: claimant.to_string(),
                    attempt,
                    claimed_at_ms: lease.claimed_at_ms,
                    expires_at_ms: lease.expires_at_ms,
                    resumed: false,
                    payload: item.payload.clone(),
                }));
            }
            // CAS lost to a writer outside this lock (e.g. another
            // process on the same SQLite file): fall through and
            // try the next candidate.
        }
        Ok(None)
    }

    /// Re-attach `claimant` to its own live lease, if it has one.
    /// Unlike [`LeaseQueue::claim`], this never claims a new item.
    /// A lease that has expired is transitioned first, so a late
    /// resume is refused with `None`, not with a dead lease.
    pub fn resume_claim(&self, claimant: &str) -> Result<Option<Claim>, QueueError> {
        let now = self.now();
        let mut store = self.store.lock().expect("store lock");
        // Lazy-expire only this claimant's lease if it is stale.
        for item in store.list()? {
            if item.state == ItemState::Leased
                && item.lease.as_ref().map(|l| l.claimant.as_str()) == Some(claimant)
                && item.lease.as_ref().map(|l| l.expires_at_ms) <= Some(now)
            {
                self.expire_item(&mut store, &item, now)?;
            }
        }
        for item in store.list()? {
            if item.state == ItemState::Leased {
                if let Some(lease) = &item.lease {
                    if lease.claimant == claimant && lease.expires_at_ms > now {
                        self.emit(
                            now,
                            EventKind::Resumed,
                            &item.id,
                            Some(claimant),
                            format!("lease {} re-attached", lease.lease_id),
                        );
                        return Ok(Some(Claim {
                            item_id: item.id.clone(),
                            lease_id: lease.lease_id.clone(),
                            claimant: claimant.to_string(),
                            attempt: item.attempts,
                            claimed_at_ms: lease.claimed_at_ms,
                            expires_at_ms: lease.expires_at_ms,
                            resumed: true,
                            payload: item.payload.clone(),
                        }));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Extend the lease named by `lease_id` to
    /// `now + lease_duration_ms`.  Only the lease holder, only
    /// while the lease is live.
    pub fn heartbeat(&self, lease_id: &str, claimant: &str) -> Result<Lease, QueueError> {
        let now = self.now();
        let mut store = self.store.lock().expect("store lock");
        let item = self.load_leased_for_op(&mut store, lease_id, claimant, now)?;
        let mut updated = item.clone();
        let mut lease = item.lease.clone().expect("leased item has a lease");
        lease.expires_at_ms = now.saturating_add(self.config.lease_duration_ms as i64);
        updated.lease = Some(lease.clone());
        updated.version = item.version + 1;
        if !store.cas(item.version, updated)? {
            return Err(QueueError::Store(format!(
                "cas lost while heartbeating item {}",
                item.id
            )));
        }
        self.emit(
            now,
            EventKind::Heartbeat,
            &item.id,
            Some(claimant),
            format!("lease extended to {}", lease.expires_at_ms),
        );
        Ok(lease)
    }

    /// Complete the leased item with a result.  The Exchange's W4
    /// rule: a worker that outran its lease does not get its
    /// completion accepted — expiry is checked first, and a late
    /// completion is rejected with [`QueueError::LeaseExpired`].
    pub fn complete(
        &self,
        lease_id: &str,
        claimant: &str,
        result: Value,
    ) -> Result<Item, QueueError> {
        let now = self.now();
        let mut store = self.store.lock().expect("store lock");
        let item = self.load_leased_for_op(&mut store, lease_id, claimant, now)?;
        let mut updated = item.clone();
        updated.state = ItemState::Done;
        updated.result = Some(result);
        updated.lease = None;
        updated.version = item.version + 1;
        if !store.cas(item.version, updated.clone())? {
            return Err(QueueError::Store(format!(
                "cas lost while completing item {}",
                item.id
            )));
        }
        self.emit(
            now,
            EventKind::Completed,
            &item.id,
            Some(claimant),
            format!("completed on attempt {}", item.attempts),
        );
        Ok(updated)
    }

    /// Fail the leased item.  The attempt that just failed is the
    /// item's current claim count: if it reached the cap, the
    /// configured exhausted action applies; otherwise the item is
    /// queued again at `now + backoff.delay_after(attempts)`.
    pub fn fail(
        &self,
        lease_id: &str,
        claimant: &str,
        reason: &str,
    ) -> Result<FailOutcome, QueueError> {
        let now = self.now();
        let mut store = self.store.lock().expect("store lock");
        let item = self.load_leased_for_op(&mut store, lease_id, claimant, now)?;
        self.emit(
            now,
            EventKind::Failed,
            &item.id,
            Some(claimant),
            format!("attempt {} failed: {reason}", item.attempts),
        );
        self.retire_attempt(&mut store, &item, now, reason)
    }

    /// Transition every expired lease in the queue and report
    /// what moved.  This is the zombie sweep: an expired lease's
    /// item is re-queued under the backoff policy, or exhausted if
    /// its attempt cap was reached.
    pub fn reap(&self) -> Result<Vec<ReapedItem>, QueueError> {
        let now = self.now();
        let mut store = self.store.lock().expect("store lock");
        self.reap_expired(&mut store, now)
    }

    /// One item by id (no lazy expiry: reads report the record as
    /// stored; call [`LeaseQueue::reap`] to move stale leases).
    pub fn get(&self, id: &str) -> Result<Option<Item>, QueueError> {
        let mut store = self.store.lock().expect("store lock");
        store.get(id)
    }

    /// All items, FIFO order, optionally filtered by state.
    pub fn list(&self, state: Option<ItemState>) -> Result<Vec<Item>, QueueError> {
        let mut store = self.store.lock().expect("store lock");
        let all = store.list()?;
        Ok(match state {
            None => all,
            Some(s) => all.into_iter().filter(|i| i.state == s).collect(),
        })
    }

    /// Item counts by state.
    pub fn stats(&self) -> Result<Stats, QueueError> {
        let mut store = self.store.lock().expect("store lock");
        let mut stats = Stats::default();
        for item in store.list()? {
            stats.total += 1;
            match item.state {
                ItemState::Queued => stats.queued += 1,
                ItemState::Leased => stats.leased += 1,
                ItemState::Done => stats.done += 1,
                ItemState::Dead => stats.dead += 1,
            }
        }
        Ok(stats)
    }

    // -- internals ---------------------------------------------------

    /// Load the item leased under `lease_id` for a holder
    /// operation (heartbeat / complete / fail), checking in order:
    /// the item exists and is leased; the lease id matches; the
    /// claimant matches; the lease has not expired.  An expired
    /// lease is transitioned before the error is returned, so the
    /// record never claims a lease is live when it is not.
    fn load_leased_for_op(
        &self,
        store: &mut S,
        lease_id: &str,
        claimant: &str,
        now: i64,
    ) -> Result<Item, QueueError> {
        let item = store
            .list()?
            .into_iter()
            .find(|i| i.lease.as_ref().map(|l| l.lease_id.as_str()) == Some(lease_id))
            .ok_or_else(|| QueueError::NotLeaseHolder(lease_id.to_string()))?;
        if item.state != ItemState::Leased {
            return Err(QueueError::InvalidState(format!(
                "item {} is {:?}, not leased",
                item.id, item.state
            )));
        }
        let lease = item.lease.clone().expect("leased item has a lease");
        if lease.claimant != claimant {
            return Err(QueueError::NotLeaseHolder(item.id.clone()));
        }
        if lease.expires_at_ms <= now {
            self.expire_item(store, &item, now)?;
            return Err(QueueError::LeaseExpired(item.id.clone()));
        }
        Ok(item)
    }

    /// The shared tail of `fail` and lease expiry: the current
    /// attempt is over.  Exhausted → configured action; otherwise
    /// re-queue under the backoff policy.
    fn retire_attempt(
        &self,
        store: &mut S,
        item: &Item,
        now: i64,
        reason: &str,
    ) -> Result<FailOutcome, QueueError> {
        if item.attempts >= self.config.max_attempts {
            let action = self.config.on_exhausted;
            match action {
                ExhaustedAction::DeadLetter => {
                    let mut updated = item.clone();
                    updated.state = ItemState::Dead;
                    updated.lease = None;
                    updated.last_error = Some(reason.to_string());
                    updated.version = item.version + 1;
                    if !store.cas(item.version, updated)? {
                        return Err(QueueError::Store(format!(
                            "cas lost while exhausting item {}",
                            item.id
                        )));
                    }
                }
                ExhaustedAction::Discard => {
                    store.remove(&item.id)?;
                    self.emit(
                        now,
                        EventKind::Discarded,
                        &item.id,
                        None,
                        format!("attempts exhausted ({reason}); record discarded"),
                    );
                }
            }
            self.emit(
                now,
                EventKind::Exhausted,
                &item.id,
                None,
                format!("attempts {} reached cap {}", item.attempts, self.config.max_attempts),
            );
            return Ok(FailOutcome::Exhausted { action });
        }
        let delay = self.config.backoff.delay_after(item.attempts);
        let available_at_ms = now.saturating_add(delay as i64);
        let mut updated = item.clone();
        updated.state = ItemState::Queued;
        updated.lease = None;
        updated.last_error = Some(reason.to_string());
        updated.available_at_ms = available_at_ms;
        updated.version = item.version + 1;
        if !store.cas(item.version, updated)? {
            return Err(QueueError::Store(format!(
                "cas lost while requeueing item {}",
                item.id
            )));
        }
        self.emit(
            now,
            EventKind::RetryScheduled,
            &item.id,
            None,
            format!("attempt {} over ({reason}); available at {available_at_ms}", item.attempts),
        );
        Ok(FailOutcome::RetryScheduled {
            available_at_ms,
            attempts: item.attempts,
        })
    }

    /// Transition one leased item whose lease has expired.
    fn expire_item(&self, store: &mut S, item: &Item, now: i64) -> Result<ReapedItem, QueueError> {
        let lease = item.lease.clone().expect("leased item has a lease");
        self.emit(
            now,
            EventKind::LeaseExpired,
            &item.id,
            Some(&lease.claimant),
            format!("lease {} expired at {}", lease.lease_id, lease.expires_at_ms),
        );
        let outcome = self.retire_attempt(store, item, now, "lease expired")?;
        Ok(ReapedItem {
            item_id: item.id.clone(),
            claimant: lease.claimant,
            outcome,
        })
    }

    /// Transition every expired lease in the store.
    fn reap_expired(&self, store: &mut S, now: i64) -> Result<Vec<ReapedItem>, QueueError> {
        let mut reaped = Vec::new();
        for item in store.list()? {
            if item.state == ItemState::Leased
                && item.lease.as_ref().map(|l| l.expires_at_ms) <= Some(now)
            {
                reaped.push(self.expire_item(store, &item, now)?);
            }
        }
        Ok(reaped)
    }
}

/// Derive a lease id deterministically from the claim's facts:
/// sha256 over the canonical JSON of {item, claimant,
/// claimed_at_ms, attempt, version}.  Same claim → same id; the
/// id is a name for the claim, not a secret.
fn lease_id_for(item_id: &str, claimant: &str, claimed_at_ms: i64, attempt: u32, version: u64) -> String {
    let canonical = serde_json::json!({
        "item": item_id,
        "claimant": claimant,
        "claimed_at_ms": claimed_at_ms,
        "attempt": attempt,
        "version": version,
    });
    let bytes = serde_json::to_vec(&canonical).expect("claim facts are always serializable");
    format!("lease_{}", hex::encode(Sha256::digest(&bytes)))
}

// ---------------------------------------------------------------------
// SQLite backend (feature `sqlite`, native only).
// ---------------------------------------------------------------------

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
mod sqlite;

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub use sqlite::SqliteStore;

// ---------------------------------------------------------------------
// Organelle surface.  A stateful organelle: it owns one queue over
// the in-memory backend, driven by a ManualClock whose time each
// call supplies as `now_ms` — time is an input here too, so a host
// replaying calls replays the same queue.  The surface starts
// unconfigured and fails closed: until `configure` supplies the
// complete caller configuration, every queue op is rejected.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let now_prop = ("now_ms".to_string(), serde_json::json!({"type": "integer"}));
    let obj = |required: &[&str], mut props: Vec<(String, Value)>| {
        props.push(now_prop.clone());
        serde_json::json!({
            "type": "object",
            "required": required,
            "properties": Value::Object(props.into_iter().collect()),
        })
    };
    let prop = |name: &str, ty: &str| (name.to_string(), serde_json::json!({"type": ty}));
    let write = Some(MutationClass::Write);
    let read = Some(MutationClass::ReadOnly);
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "lease-queue".to_string(),
        codon: "lq".to_string(),
        version: "1.0.0".to_string(),
        description:
            "job queue with leases: atomic single-winner claim, claim-resume, heartbeat, \
             complete/fail with caller-supplied backoff, lease-expiry reap, idempotency keys; \
             all policy (lease duration, attempt cap, backoff, exhausted action) is \
             configuration the caller states in full"
                .to_string(),
        contracts: vec![
            Contract {
                op: "configure".to_string(),
                description: "supply the complete QueueConfig {lease_duration_ms, max_attempts, backoff, on_exhausted}; required once before any queue op; there are no defaults".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["config"],
                    "properties": {"config": {
                        "type": "object",
                        "required": ["lease_duration_ms", "max_attempts", "backoff", "on_exhausted"],
                        "properties": {
                            "lease_duration_ms": {"type": "integer", "minimum": 1},
                            "max_attempts": {"type": "integer", "minimum": 1},
                            "backoff": {"type": "object"},
                            "on_exhausted": {"enum": ["dead_letter", "discard"]}
                        }
                    }}
                }),
                mutation_class: write.clone(),
                required_capability: Some("lease.queue".to_string()),
            },
            Contract {
                op: "enqueue".to_string(),
                description: "enqueue {id, payload, idempotency_key?, now_ms} -> {outcome: enqueued|duplicate, ...}; a replayed idempotency key creates nothing".to_string(),
                input_schema: obj(&["id", "payload", "now_ms"], vec![prop("id", "string"), prop("idempotency_key", "string"), ("payload".to_string(), serde_json::json!({}))]),
                mutation_class: write.clone(),
                required_capability: Some("lease.queue".to_string()),
            },
            Contract {
                op: "claim".to_string(),
                description: "claim {claimant, now_ms} -> claim object or null; re-attaches the claimant's own live lease (resumed: true) before claiming anything new; expired leases are reaped first".to_string(),
                input_schema: obj(&["claimant", "now_ms"], vec![prop("claimant", "string")]),
                mutation_class: write.clone(),
                required_capability: Some("lease.queue".to_string()),
            },
            Contract {
                op: "resume".to_string(),
                description: "resume {claimant, now_ms} -> the claimant's live claim or null; never claims a new item".to_string(),
                input_schema: obj(&["claimant", "now_ms"], vec![prop("claimant", "string")]),
                mutation_class: write.clone(),
                required_capability: Some("lease.queue".to_string()),
            },
            Contract {
                op: "heartbeat".to_string(),
                description: "heartbeat {lease_id, claimant, now_ms} -> the lease, extended to now_ms + lease_duration_ms; holder only, live lease only".to_string(),
                input_schema: obj(&["lease_id", "claimant", "now_ms"], vec![prop("lease_id", "string"), prop("claimant", "string")]),
                mutation_class: write.clone(),
                required_capability: Some("lease.queue".to_string()),
            },
            Contract {
                op: "complete".to_string(),
                description: "complete {lease_id, claimant, result, now_ms} -> the done item; a completion after lease expiry is rejected".to_string(),
                input_schema: obj(&["lease_id", "claimant", "now_ms"], vec![prop("lease_id", "string"), prop("claimant", "string")]),
                mutation_class: write.clone(),
                required_capability: Some("lease.queue".to_string()),
            },
            Contract {
                op: "fail".to_string(),
                description: "fail {lease_id, claimant, reason, now_ms} -> retry_scheduled {available_at_ms} or exhausted {action}, per the configured backoff and attempt cap".to_string(),
                input_schema: obj(&["lease_id", "claimant", "now_ms"], vec![prop("lease_id", "string"), prop("claimant", "string"), prop("reason", "string")]),
                mutation_class: write.clone(),
                required_capability: Some("lease.queue".to_string()),
            },
            Contract {
                op: "reap".to_string(),
                description: "reap {now_ms} -> {reaped: [...]}: transition every expired lease (requeue under backoff, or the configured exhausted action)".to_string(),
                input_schema: obj(&["now_ms"], vec![]),
                mutation_class: write,
                required_capability: Some("lease.queue".to_string()),
            },
            Contract {
                op: "get".to_string(),
                description: "get {id} -> the item or null".to_string(),
                input_schema: serde_json::json!({"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "list".to_string(),
                description: "list {state?} -> all items in FIFO order, optionally filtered by state".to_string(),
                input_schema: serde_json::json!({"type": "object", "properties": {"state": {"type": "string"}}}),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "stats".to_string(),
                description: "stats {} -> item counts by state".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "events".to_string(),
                description: "events {} -> the queue's full event log (every state transition, in order)".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: read,
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::Write,
            declared_valence: Valence::Candidate,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: Transport::all().to_vec(),
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

#[cfg(feature = "organelle")]
pub struct LeaseQueueOrganelle {
    manifest: OrganelleManifest,
    inner: Mutex<Option<LeaseQueue<MemoryStore, ManualClock>>>,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> std::sync::Arc<dyn Organelle> {
    std::sync::Arc::new(LeaseQueueOrganelle {
        manifest: manifest(),
        inner: Mutex::new(None),
    })
}

/// An organelle whose queue is configured at construction —
/// for Rust hosts that build the surface themselves.
#[cfg(feature = "organelle")]
pub fn organelle_with(config: QueueConfig) -> Result<std::sync::Arc<dyn Organelle>, QueueError> {
    let queue = LeaseQueue::new(config, MemoryStore::new(), ManualClock::new(0))?;
    Ok(std::sync::Arc::new(LeaseQueueOrganelle {
        manifest: manifest(),
        inner: Mutex::new(Some(queue)),
    }))
}

#[cfg(feature = "organelle")]
fn rejected<T>(msg: impl Into<String>) -> Result<T, OrganelleError> {
    Err(OrganelleError::new("rejected", msg.into()))
}

#[cfg(feature = "organelle")]
fn req_str(input: &Value, field: &str) -> Result<String, OrganelleError> {
    match input[field].as_str() {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => rejected(format!("{field} must be a non-empty string")),
    }
}

#[cfg(feature = "organelle")]
fn req_now(input: &Value) -> Result<i64, OrganelleError> {
    match input["now_ms"].as_i64() {
        Some(n) => Ok(n),
        None => rejected("now_ms must be an integer (epoch milliseconds); time is an input"),
    }
}

#[cfg(feature = "organelle")]
impl Organelle for LeaseQueueOrganelle {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        if op == "configure" {
            let config: QueueConfig = serde_json::from_value(input["config"].clone())
                .map_err(|e| OrganelleError::new("rejected", format!("config: {e}")))?;
            let mut inner = self.inner.lock().expect("organelle lock");
            if inner.is_some() {
                return rejected("already configured");
            }
            let queue = LeaseQueue::new(config, MemoryStore::new(), ManualClock::new(0))
                .map_err(|e| OrganelleError::new("rejected", e.to_string()))?;
            *inner = Some(queue);
            return Ok(serde_json::json!({"ok": true}));
        }

        let inner = self.inner.lock().expect("organelle lock");
        let queue = match inner.as_ref() {
            Some(q) => q,
            None => {
                return rejected(
                    "lease-queue not configured: call configure with the complete config first",
                )
            }
        };
        let fail = |e: QueueError| OrganelleError::failed(e.to_string());
        fn to_json<T: Serialize>(v: &T) -> Result<Value, OrganelleError> {
            serde_json::to_value(v)
                .map_err(|e| OrganelleError::failed(format!("serialize: {e}")))
        }
        match op {
            "enqueue" => {
                queue.clock().set(req_now(&input)?);
                let id = req_str(&input, "id")?;
                if input["payload"].is_null() {
                    return rejected("payload is required");
                }
                let outcome = queue
                    .enqueue(&id, input["payload"].clone(), input["idempotency_key"].as_str())
                    .map_err(fail)?;
                to_json(&outcome)
            }
            "claim" => {
                queue.clock().set(req_now(&input)?);
                let claimant = req_str(&input, "claimant")?;
                match queue.claim(&claimant).map_err(fail)? {
                    Some(claim) => to_json(&claim),
                    None => Ok(Value::Null),
                }
            }
            "resume" => {
                queue.clock().set(req_now(&input)?);
                let claimant = req_str(&input, "claimant")?;
                match queue.resume_claim(&claimant).map_err(fail)? {
                    Some(claim) => to_json(&claim),
                    None => Ok(Value::Null),
                }
            }
            "heartbeat" => {
                queue.clock().set(req_now(&input)?);
                let lease = queue
                    .heartbeat(&req_str(&input, "lease_id")?, &req_str(&input, "claimant")?)
                    .map_err(fail)?;
                to_json(&lease)
            }
            "complete" => {
                queue.clock().set(req_now(&input)?);
                let item = queue
                    .complete(
                        &req_str(&input, "lease_id")?,
                        &req_str(&input, "claimant")?,
                        input["result"].clone(),
                    )
                    .map_err(fail)?;
                to_json(&item)
            }
            "fail" => {
                queue.clock().set(req_now(&input)?);
                let reason = input["reason"].as_str().unwrap_or("");
                let outcome = queue
                    .fail(
                        &req_str(&input, "lease_id")?,
                        &req_str(&input, "claimant")?,
                        reason,
                    )
                    .map_err(fail)?;
                to_json(&outcome)
            }
            "reap" => {
                queue.clock().set(req_now(&input)?);
                let reaped = queue.reap().map_err(fail)?;
                Ok(serde_json::json!({"reaped": to_json(&reaped)?}))
            }
            "get" => {
                let id = req_str(&input, "id")?;
                match queue.get(&id).map_err(fail)? {
                    Some(item) => to_json(&item),
                    None => Ok(Value::Null),
                }
            }
            "list" => {
                let state = match input["state"].as_str() {
                    None => None,
                    Some(s) => Some(
                        serde_json::from_value::<ItemState>(Value::String(s.to_string()))
                            .map_err(|e| {
                                OrganelleError::new("rejected", format!("state: {e}"))
                            })?,
                    ),
                };
                to_json(&queue.list(state).map_err(fail)?)
            }
            "stats" => to_json(&queue.stats().map_err(fail)?),
            "events" => to_json(&queue.events()),
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The five required proofs: (a) atomic single-winner claim
// under parallel racing, (b) lease expiry frees the item for
// reclaim, (c) claim-resume returns the same lease to the same
// claimant and refuses a different one, (d) complete-after-expiry
// is rejected, (e) retry/backoff follows caller data exactly.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    fn config(
        lease_duration_ms: u64,
        max_attempts: u32,
        backoff: BackoffPolicy,
        on_exhausted: ExhaustedAction,
    ) -> QueueConfig {
        QueueConfig {
            lease_duration_ms,
            max_attempts,
            backoff,
            on_exhausted,
        }
    }

    fn fixed(delay_ms: u64) -> BackoffPolicy {
        BackoffPolicy::Fixed { delay_ms }
    }

    fn queue(
        cfg: QueueConfig,
        clock: ManualClock,
    ) -> LeaseQueue<MemoryStore, ManualClock> {
        LeaseQueue::new(cfg, MemoryStore::new(), clock).unwrap()
    }

    // (a) Atomic single-winner claim under parallel racing.
    #[test]
    fn claim_is_single_winner_under_parallel_race() {
        let q = Arc::new(queue(
            config(60_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        ));
        q.enqueue("only-item", json!({"job": 1}), None).unwrap();
        let mut handles = Vec::new();
        for i in 0..16 {
            let q = q.clone();
            handles.push(std::thread::spawn(move || {
                q.claim(&format!("worker-{i}")).unwrap()
            }));
        }
        let results: Vec<Option<Claim>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners: Vec<&Claim> = results.iter().filter_map(|r| r.as_ref()).collect();
        assert_eq!(winners.len(), 1, "exactly one claimant may win the item");
        assert_eq!(winners[0].item_id, "only-item");
        assert_eq!(winners[0].attempt, 1);
        assert!(!winners[0].resumed);
        // The item's record agrees: one lease, one attempt.
        let item = q.get("only-item").unwrap().unwrap();
        assert_eq!(item.state, ItemState::Leased);
        assert_eq!(item.attempts, 1);
    }

    // (a, scaled) N items, M > N racers: exactly N claims, all
    // for distinct items.
    #[test]
    fn race_over_many_items_claims_each_once() {
        let q = Arc::new(queue(
            config(60_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        ));
        for n in 0..8 {
            q.enqueue(&format!("item-{n}"), json!(n), None).unwrap();
        }
        let mut handles = Vec::new();
        for i in 0..32 {
            let q = q.clone();
            handles.push(std::thread::spawn(move || {
                q.claim(&format!("worker-{i}")).unwrap()
            }));
        }
        let mut claimed_items: Vec<String> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter_map(|c| c.map(|claim| claim.item_id))
            .collect();
        claimed_items.sort();
        claimed_items.dedup();
        assert_eq!(claimed_items.len(), 8, "each item claimed exactly once");
        let stats = q.stats().unwrap();
        assert_eq!(stats.leased, 8);
        assert_eq!(stats.queued, 0);
    }

    // (b) Lease expiry frees the item for reclaim.
    #[test]
    fn lease_expiry_frees_item_for_reclaim() {
        let clock = ManualClock::new(0);
        let q = queue(
            config(1_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            clock,
        );
        q.enqueue("job", json!(1), None).unwrap();
        let first = q.claim("alice").unwrap().unwrap();
        assert_eq!(first.expires_at_ms, 1_000);
        // While the lease is live, nobody else can have the item.
        assert!(q.claim("bob").unwrap().is_none());
        // Past expiry, the sweep transitions the lease...
        q.clock().set(1_500);
        let reaped = q.reap().unwrap();
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].item_id, "job");
        assert_eq!(reaped[0].claimant, "alice");
        assert_eq!(
            reaped[0].outcome,
            FailOutcome::RetryScheduled {
                available_at_ms: 1_500,
                attempts: 1
            }
        );
        // ...and the item is claimable again, as attempt 2.
        let second = q.claim("bob").unwrap().unwrap();
        assert_eq!(second.attempt, 2);
        assert!(!second.resumed);
    }

    // (c) Claim-resume: same lease back to the same claimant,
    // refusal for everyone else.
    #[test]
    fn claim_resume_returns_same_lease_to_same_claimant_only() {
        let q = queue(
            config(10_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(100),
        );
        q.enqueue("job", json!(1), None).unwrap();
        let first = q.claim("alice").unwrap().unwrap();
        // Alice claims again (e.g. her process restarted): she
        // gets her own lease back, not a new item or a new lease.
        let resumed = q.claim("alice").unwrap().unwrap();
        assert!(resumed.resumed);
        assert_eq!(resumed.lease_id, first.lease_id);
        assert_eq!(resumed.attempt, 1, "a resume is not a new attempt");
        assert_eq!(resumed.claimed_at_ms, first.claimed_at_ms);
        // The explicit resume op agrees.
        let resumed2 = q.resume_claim("alice").unwrap().unwrap();
        assert_eq!(resumed2.lease_id, first.lease_id);
        // Bob is refused both ways while Alice's lease is live.
        assert!(q.resume_claim("bob").unwrap().is_none());
        assert!(q.claim("bob").unwrap().is_none());
        // And the item still shows exactly one attempt.
        assert_eq!(q.get("job").unwrap().unwrap().attempts, 1);
    }

    // (c, expiry edge) A resume after the lease expired is
    // refused; the item went back to the queue instead.
    #[test]
    fn resume_after_expiry_is_refused() {
        let q = queue(
            config(1_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        q.claim("alice").unwrap().unwrap();
        q.clock().set(2_000);
        assert!(q.resume_claim("alice").unwrap().is_none());
        // The stale lease was transitioned by the resume attempt:
        // the item is queued, claimable as attempt 2.
        let next = q.claim("alice").unwrap().unwrap();
        assert_eq!(next.attempt, 2);
        assert!(!next.resumed);
    }

    // (d) Complete-after-expiry is rejected.
    #[test]
    fn complete_after_expiry_is_rejected() {
        let q = queue(
            config(1_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        let claim = q.claim("alice").unwrap().unwrap();
        q.clock().set(1_000); // expires_at == now: expired
        let err = q
            .complete(&claim.lease_id, "alice", json!({"done": true}))
            .unwrap_err();
        assert_eq!(err, QueueError::LeaseExpired("job".to_string()));
        // The item was not completed; it went back to the queue
        // and someone else can pick it up.
        let item = q.get("job").unwrap().unwrap();
        assert_eq!(item.state, ItemState::Queued);
        assert_eq!(item.result, None);
        let next = q.claim("bob").unwrap().unwrap();
        assert_eq!(next.attempt, 2);
        // Bob's in-time completion is accepted.
        let done = q
            .complete(&next.lease_id, "bob", json!({"done": true}))
            .unwrap();
        assert_eq!(done.state, ItemState::Done);
        assert_eq!(done.result, Some(json!({"done": true})));
    }

    // (e) Retry/backoff follows caller data exactly: fixed.
    #[test]
    fn backoff_fixed_is_exact() {
        let q = queue(
            config(60_000, 3, fixed(500), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        let claim = q.claim("alice").unwrap().unwrap();
        q.clock().set(100);
        let outcome = q.fail(&claim.lease_id, "alice", "boom").unwrap();
        assert_eq!(
            outcome,
            FailOutcome::RetryScheduled {
                available_at_ms: 600,
                attempts: 1
            }
        );
        // Not a millisecond early.
        q.clock().set(599);
        assert!(q.claim("alice").unwrap().is_none());
        q.clock().set(600);
        let again = q.claim("alice").unwrap().unwrap();
        assert_eq!(again.attempt, 2);
    }

    // (e) Exponential with cap, to the millisecond.
    #[test]
    fn backoff_exponential_with_cap_is_exact() {
        let q = queue(
            config(
                60_000,
                5,
                BackoffPolicy::Exponential {
                    base_ms: 100,
                    factor: 2,
                    cap_ms: 250,
                },
                ExhaustedAction::DeadLetter,
            ),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        // Delays after attempts 1..4: 100, 200, 250 (400 capped), 250.
        let mut now = 0;
        for (attempt, delay) in [(1, 100), (2, 200), (3, 250), (4, 250)] {
            q.clock().set(now);
            let claim = q.claim("alice").unwrap().unwrap();
            assert_eq!(claim.attempt, attempt);
            let outcome = q.fail(&claim.lease_id, "alice", "boom").unwrap();
            assert_eq!(
                outcome,
                FailOutcome::RetryScheduled {
                    available_at_ms: now + delay,
                    attempts: attempt
                },
                "attempt {attempt} must wait exactly {delay}ms"
            );
            now += delay;
        }
        // The fifth failure reaches the cap: exhausted, dead.
        q.clock().set(now);
        let claim = q.claim("alice").unwrap().unwrap();
        assert_eq!(claim.attempt, 5);
        let outcome = q.fail(&claim.lease_id, "alice", "boom").unwrap();
        assert_eq!(
            outcome,
            FailOutcome::Exhausted {
                action: ExhaustedAction::DeadLetter
            }
        );
        assert_eq!(q.get("job").unwrap().unwrap().state, ItemState::Dead);
        assert!(q.claim("alice").unwrap().is_none());
    }

    // (e) A caller-supplied schedule is followed entry by entry.
    #[test]
    fn backoff_schedule_is_exact() {
        let policy = BackoffPolicy::Schedule {
            delays_ms: vec![10, 20, 30],
        };
        assert_eq!(policy.delay_after(1), 10);
        assert_eq!(policy.delay_after(2), 20);
        assert_eq!(policy.delay_after(3), 30);
        let q = queue(
            config(60_000, 4, policy, ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        let mut now = 0;
        for (attempt, delay) in [(1, 10), (2, 20), (3, 30)] {
            q.clock().set(now);
            let claim = q.claim("alice").unwrap().unwrap();
            let outcome = q.fail(&claim.lease_id, "alice", "x").unwrap();
            assert_eq!(
                outcome,
                FailOutcome::RetryScheduled {
                    available_at_ms: now + delay,
                    attempts: attempt
                }
            );
            now += delay;
        }
        q.clock().set(now);
        let claim = q.claim("alice").unwrap().unwrap();
        assert_eq!(claim.attempt, 4);
        assert_eq!(
            q.fail(&claim.lease_id, "alice", "x").unwrap(),
            FailOutcome::Exhausted {
                action: ExhaustedAction::DeadLetter
            }
        );
    }

    // (e) Linear, for completeness of the policy vocabulary.
    #[test]
    fn backoff_linear_is_exact() {
        let policy = BackoffPolicy::Linear {
            base_ms: 50,
            step_ms: 25,
        };
        assert_eq!(policy.delay_after(1), 50);
        assert_eq!(policy.delay_after(2), 75);
        assert_eq!(policy.delay_after(3), 100);
    }

    #[test]
    fn heartbeat_extends_lease() {
        let q = queue(
            config(1_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        let claim = q.claim("alice").unwrap().unwrap();
        assert_eq!(claim.expires_at_ms, 1_000);
        q.clock().set(900);
        let lease = q.heartbeat(&claim.lease_id, "alice").unwrap();
        assert_eq!(lease.expires_at_ms, 1_900);
        // Past the original expiry, the completion still lands.
        q.clock().set(1_500);
        let done = q.complete(&claim.lease_id, "alice", json!(true)).unwrap();
        assert_eq!(done.state, ItemState::Done);
    }

    #[test]
    fn only_the_holder_can_act_on_a_lease() {
        let q = queue(
            config(10_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        let claim = q.claim("alice").unwrap().unwrap();
        assert!(matches!(
            q.complete(&claim.lease_id, "bob", json!(true)),
            Err(QueueError::NotLeaseHolder(_))
        ));
        assert!(matches!(
            q.fail(&claim.lease_id, "bob", "nope"),
            Err(QueueError::NotLeaseHolder(_))
        ));
        assert!(matches!(
            q.heartbeat(&claim.lease_id, "bob"),
            Err(QueueError::NotLeaseHolder(_))
        ));
        assert!(matches!(
            q.heartbeat("lease_nonexistent", "alice"),
            Err(QueueError::NotLeaseHolder(_))
        ));
        // None of the refused operations touched the item.
        let item = q.get("job").unwrap().unwrap();
        assert_eq!(item.state, ItemState::Leased);
        assert_eq!(item.attempts, 1);
    }

    #[test]
    fn idempotent_enqueue_creates_nothing_twice() {
        let q = queue(
            config(10_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        let first = q
            .enqueue("item-a", json!(1), Some("key-1"))
            .unwrap();
        assert_eq!(
            first,
            EnqueueOutcome::Enqueued {
                item_id: "item-a".to_string()
            }
        );
        // Same key, different id: a replay, not a new item.
        let replay = q
            .enqueue("item-b", json!(2), Some("key-1"))
            .unwrap();
        assert_eq!(
            replay,
            EnqueueOutcome::Duplicate {
                item_id: "item-a".to_string(),
                state: ItemState::Queued
            }
        );
        assert_eq!(q.stats().unwrap().total, 1);
        assert!(q.get("item-b").unwrap().is_none());
        // Same id, no key: a genuine conflict.
        assert_eq!(
            q.enqueue("item-a", json!(3), None).unwrap_err(),
            QueueError::DuplicateId("item-a".to_string())
        );
    }

    #[test]
    fn exhausted_discard_removes_the_record() {
        let q = queue(
            config(10_000, 1, fixed(0), ExhaustedAction::Discard),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        let claim = q.claim("alice").unwrap().unwrap();
        let outcome = q.fail(&claim.lease_id, "alice", "fatal").unwrap();
        assert_eq!(
            outcome,
            FailOutcome::Exhausted {
                action: ExhaustedAction::Discard
            }
        );
        assert!(q.get("job").unwrap().is_none());
        assert_eq!(q.stats().unwrap().total, 0);
        // The removal is on the record even though the item is not.
        assert!(q
            .events()
            .iter()
            .any(|e| e.kind == EventKind::Discarded && e.item_id == "job"));
    }

    #[test]
    fn expiry_can_exhaust_too() {
        let q = queue(
            config(1_000, 1, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        q.claim("alice").unwrap().unwrap();
        q.clock().set(5_000);
        let reaped = q.reap().unwrap();
        assert_eq!(reaped.len(), 1);
        assert_eq!(
            reaped[0].outcome,
            FailOutcome::Exhausted {
                action: ExhaustedAction::DeadLetter
            }
        );
        assert_eq!(q.get("job").unwrap().unwrap().state, ItemState::Dead);
    }

    #[test]
    fn fifo_order_is_enqueue_order() {
        let q = queue(
            config(10_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        for id in ["first", "second", "third"] {
            q.enqueue(id, json!(id), None).unwrap();
        }
        assert_eq!(q.claim("a").unwrap().unwrap().item_id, "first");
        assert_eq!(q.claim("b").unwrap().unwrap().item_id, "second");
        assert_eq!(q.claim("c").unwrap().unwrap().item_id, "third");
    }

    #[test]
    fn config_validation_refuses_unstated_or_impossible_knobs() {
        let store = || MemoryStore::new();
        let clock = || ManualClock::new(0);
        assert!(LeaseQueue::new(
            config(0, 3, fixed(0), ExhaustedAction::DeadLetter),
            store(),
            clock()
        )
        .is_err());
        assert!(LeaseQueue::new(
            config(1_000, 0, fixed(0), ExhaustedAction::DeadLetter),
            store(),
            clock()
        )
        .is_err());
        // A schedule shorter than the retries the cap allows.
        assert!(LeaseQueue::new(
            config(
                1_000,
                4,
                BackoffPolicy::Schedule {
                    delays_ms: vec![10, 20]
                },
                ExhaustedAction::DeadLetter
            ),
            store(),
            clock()
        )
        .is_err());
        // A zero exponential factor.
        assert!(LeaseQueue::new(
            config(
                1_000,
                3,
                BackoffPolicy::Exponential {
                    base_ms: 100,
                    factor: 0,
                    cap_ms: 250
                },
                ExhaustedAction::DeadLetter
            ),
            store(),
            clock()
        )
        .is_err());
    }

    #[test]
    fn determinism_same_script_same_record() {
        let run = || {
            let q = queue(
                config(
                    1_000,
                    3,
                    BackoffPolicy::Exponential {
                        base_ms: 100,
                        factor: 2,
                        cap_ms: 250,
                    },
                    ExhaustedAction::DeadLetter,
                ),
                ManualClock::new(0),
            );
            q.enqueue("a", json!({"n": 1}), Some("k-a")).unwrap();
            q.enqueue("b", json!({"n": 2}), None).unwrap();
            let c1 = q.claim("alice").unwrap().unwrap();
            q.clock().set(50);
            q.fail(&c1.lease_id, "alice", "boom").unwrap();
            q.clock().set(200);
            let c2 = q.claim("bob").unwrap().unwrap();
            q.complete(&c2.lease_id, "bob", json!({"ok": true})).unwrap();
            q.clock().set(5_000);
            q.reap().unwrap();
            (
                serde_json::to_string(&q.list(None).unwrap()).unwrap(),
                serde_json::to_string(&q.events()).unwrap(),
            )
        };
        let (items1, events1) = run();
        let (items2, events2) = run();
        assert_eq!(items1, items2, "same script must produce identical items");
        assert_eq!(events1, events2, "same script must produce identical events");
    }

    #[test]
    fn event_log_covers_the_lifecycle() {
        let q = queue(
            config(1_000, 3, fixed(0), ExhaustedAction::DeadLetter),
            ManualClock::new(0),
        );
        q.enqueue("job", json!(1), None).unwrap();
        let claim = q.claim("alice").unwrap().unwrap();
        q.heartbeat(&claim.lease_id, "alice").unwrap();
        q.complete(&claim.lease_id, "alice", json!(true)).unwrap();
        let kinds: Vec<EventKind> = q.events().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                EventKind::Enqueued,
                EventKind::Claimed,
                EventKind::Heartbeat,
                EventKind::Completed
            ]
        );
        // Sequentially numbered, no gaps.
        let seqs: Vec<u64> = q.events().iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4]);
    }
}

#[cfg(all(test, feature = "sqlite", not(target_arch = "wasm32")))]
mod sqlite_tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    fn cfg() -> QueueConfig {
        QueueConfig {
            lease_duration_ms: 60_000,
            max_attempts: 3,
            backoff: BackoffPolicy::Fixed { delay_ms: 0 },
            on_exhausted: ExhaustedAction::DeadLetter,
        }
    }

    #[test]
    fn sqlite_in_memory_full_flow() {
        let q = LeaseQueue::new(cfg(), SqliteStore::in_memory().unwrap(), ManualClock::new(0))
            .unwrap();
        q.enqueue("job", json!({"x": 1}), Some("k1")).unwrap();
        // Idempotency holds on this backend too.
        assert_eq!(
            q.enqueue("other", json!(2), Some("k1")).unwrap(),
            EnqueueOutcome::Duplicate {
                item_id: "job".to_string(),
                state: ItemState::Queued
            }
        );
        let claim = q.claim("alice").unwrap().unwrap();
        let done = q
            .complete(&claim.lease_id, "alice", json!({"ok": true}))
            .unwrap();
        assert_eq!(done.state, ItemState::Done);
        assert_eq!(q.stats().unwrap().done, 1);
    }

    fn temp_db(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ref-lease-queue-test-{}-{name}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn sqlite_file_survives_reopen_with_lease_intact() {
        let path = temp_db("reopen");
        let lease_id;
        {
            let q = LeaseQueue::new(
                cfg(),
                SqliteStore::open(&path).unwrap(),
                ManualClock::new(0),
            )
            .unwrap();
            q.enqueue("job", json!(1), None).unwrap();
            lease_id = q.claim("alice").unwrap().unwrap().lease_id;
        }
        // A fresh queue over the same file sees the live lease and
        // resumes it — durability plus claim-resume together.
        let q = LeaseQueue::new(
            cfg(),
            SqliteStore::open(&path).unwrap(),
            ManualClock::new(10),
        )
        .unwrap();
        let resumed = q.resume_claim("alice").unwrap().unwrap();
        assert_eq!(resumed.lease_id, lease_id);
        assert_eq!(resumed.attempt, 1);
        let _ = std::fs::remove_file(&path);
    }

    // The strong atomicity proof: two independent queue instances
    // over two connections to the SAME file, racing threads —
    // the conditional-UPDATE CAS still yields exactly one winner.
    #[test]
    fn sqlite_cross_instance_claim_race_has_one_winner() {
        let path = temp_db("race");
        let mk = || {
            LeaseQueue::new(
                cfg(),
                SqliteStore::open(&path).unwrap(),
                ManualClock::new(0),
            )
            .unwrap()
        };
        let q1 = Arc::new(mk());
        let q2 = Arc::new(mk());
        q1.enqueue("only", json!(1), None).unwrap();
        let mut handles = Vec::new();
        for i in 0..16 {
            let q = if i % 2 == 0 { q1.clone() } else { q2.clone() };
            handles.push(std::thread::spawn(move || {
                q.claim(&format!("worker-{i}")).unwrap()
            }));
        }
        let winners = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|c| c.is_some())
            .count();
        assert_eq!(winners, 1, "one winner across two connections to one file");
        let item = q1.get("only").unwrap().unwrap();
        assert_eq!(item.state, ItemState::Leased);
        assert_eq!(item.attempts, 1);
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(all(test, feature = "organelle"))]
mod organelle_tests {
    use super::*;
    use organelle_host::Host;
    use serde_json::json;

    fn host_with() -> std::sync::Arc<Host> {
        let h = Host::new();
        h.register(organelle()).unwrap();
        h
    }

    fn config_json() -> Value {
        json!({
            "lease_duration_ms": 1000,
            "max_attempts": 2,
            "backoff": {"kind": "fixed", "delay_ms": 100},
            "on_exhausted": "dead_letter"
        })
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }

    #[test]
    fn unconfigured_surface_fails_closed() {
        let h = host_with();
        let ctx = CallContext::new("test", vec!["lease.queue".to_string()]);
        let err = h
            .call(
                &ctx,
                "lq",
                "enqueue",
                json!({"id": "x", "payload": 1, "now_ms": 0}),
            )
            .unwrap_err();
        // The call is well-formed, so the host runs it and the
        // organelle itself refuses: verdict Failed, not a gate
        // rejection — the surface is closed, not the request.
        assert_eq!(err.verdict, organelle_host::CallVerdict::Failed);
    }

    #[test]
    fn lifecycle_via_host() {
        let h = host_with();
        let ctx = CallContext::new("test", vec!["lease.queue".to_string()]);
        let call = |op: &str, input: Value| h.call(&ctx, "lq", op, input).unwrap().output;
        call("configure", json!({"config": config_json()}));
        // A second configure is refused.
        assert!(h
            .call(&ctx, "lq", "configure", json!({"config": config_json()}))
            .is_err());
        let enq = call(
            "enqueue",
            json!({"id": "job", "payload": {"n": 1}, "idempotency_key": "k1", "now_ms": 0}),
        );
        assert_eq!(enq["outcome"], json!("enqueued"));
        let claim = call("claim", json!({"claimant": "alice", "now_ms": 0}));
        assert_eq!(claim["item_id"], json!("job"));
        assert_eq!(claim["resumed"], json!(false));
        let lease_id = claim["lease_id"].as_str().unwrap().to_string();
        // Resume via the surface returns the same lease.
        let resumed = call("resume", json!({"claimant": "alice", "now_ms": 10}));
        assert_eq!(resumed["lease_id"], json!(lease_id));
        assert_eq!(resumed["resumed"], json!(true));
        // Fail → retry scheduled at exactly now + 100.
        let failed = call(
            "fail",
            json!({"lease_id": lease_id, "claimant": "alice", "reason": "boom", "now_ms": 20}),
        );
        assert_eq!(failed["outcome"], json!("retry_scheduled"));
        assert_eq!(failed["available_at_ms"], json!(120));
        // Claim at 120, complete, stats agree.
        let claim2 = call("claim", json!({"claimant": "bob", "now_ms": 120}));
        let done = call(
            "complete",
            json!({"lease_id": claim2["lease_id"], "claimant": "bob", "result": {"ok": true}, "now_ms": 130}),
        );
        assert_eq!(done["state"], json!("done"));
        let stats = call("stats", json!({}));
        assert_eq!(stats["done"], json!(1));
        assert_eq!(stats["total"], json!(1));
        let events = call("events", json!({}));
        assert!(events.as_array().unwrap().len() >= 5);
    }

    #[test]
    fn underspecified_config_rejected() {
        let h = host_with();
        let ctx = CallContext::new("test", vec!["lease.queue".to_string()]);
        // Missing backoff + on_exhausted: the config cannot be
        // left unstated.
        let err = h
            .call(
                &ctx,
                "lq",
                "configure",
                json!({"config": {"lease_duration_ms": 1000, "max_attempts": 2}}),
            )
            .unwrap_err();
        assert_eq!(err.verdict, organelle_host::CallVerdict::Rejected);
    }
}
