//! org-034 — Reference organelle: replay-registry (codon `rr`).
//!
//! A seen-seal registry: content seals (sha256 ids) are presented
//! once and only once; a second presentation of the same seal is
//! a replay, detected and reported with the original registration
//! record attached (GAP-09 in the 2026-11-22 decomposition map:
//! five scoped softwares — PL, WRK, EXC, EVD, MCP — hand-roll
//! replay / single-use-token / duplicate-event registries today:
//! the Exchange's envelope seal registry, proof-ledger's seal
//! handling, wreck's single-use tokens, eventd's duplicate-event
//! suppression, and the MCP vending machine's `jti` single-use
//! redemption).
//!
//! The proven production instance is the Exchange's: a durable
//! `seal_registry` table (seal → first_seen epoch ms) behind an
//! in-isolate map, `REPLAY_TTL_MS` of one hour, `REPLAY_MAX_SEEN`
//! of 10,000, replay → HTTP 409. This crate is that shape,
//! generalized and made honest in the four places the private
//! implementations are not:
//!
//! * **Instances are values, never globals.** A registry is a
//!   [`Registry`] constructed over a caller-supplied [`Store`]
//!   and a caller-supplied [`Retention`], and passed explicitly.
//!   There is no `static`, no `LazyLock`, no process-global set
//!   anywhere in this crate. The Exchange's harness-isolation
//!   fix (2026-11-22) is the lesson: its in-isolate seal map is a
//!   process global that parallel tests collided through, and
//!   the fix had to bolt on an `Env`-injected per-test set.
//!   Here, two registries are isolated *by construction* —
//!   isolation is a test below, not a configuration.
//! * **Retention is caller data, with no baked defaults.**
//!   TTL and capacity arrive in [`Retention`], validated at
//!   construction. The crate ships no TTL and no capacity of its
//!   own; the Exchange's one hour / 10,000 are *its* policy,
//!   expressed by its adopter as data.
//! * **Eviction is explicit and reported.** Nothing is ever
//!   evicted lazily inside `present` — the Exchange's silent
//!   `retain` sweep and its `LIMIT 500` prune are replaced by
//!   [`Registry::sweep`], an explicit operation that returns
//!   exactly the records it evicted. An expired-but-unswept seal
//!   is still a replay; only a sweep makes it new again.
//! * **Saturation fails closed.** At capacity, a *new* seal is
//!   refused with [`RegistryError::Saturated`] — never silently
//!   registered over an eviction, never silently dropped, and
//!   never misreported as a replay. (The Exchange's private
//!   shape agrees: at `REPLAY_MAX_SEEN` its check returns
//!   `"full"`, and its routes reject.) Replay detection for
//!   already-registered seals is never blocked by saturation.
//!
//! Time is an input everywhere: `present` and `sweep` take
//! `now_ms` from the caller and the core never reads a clock,
//! so scripted sequences replay to identical verdicts
//! (proven by test, across backends).
//!
//! Storage sits behind the [`Store`] trait. [`MemoryStore`] is
//! the test/embedded backend; `SqliteStore` (feature `sqlite`,
//! native only) is the durable backend. All registry logic
//! lives in the core over the trait, so verdicts are identical
//! — byte for byte — on every backend.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};

// ---------------------------------------------------------------------
// Seals.
// ---------------------------------------------------------------------

/// The sha256 of `content`, hex-encoded — the estate's seal for
/// a byte string. Stable across runs and processes (never a
/// process-local hash).
pub fn seal_of(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

/// Validate and normalize a seal: exactly 64 hex characters,
/// stored lowercase. Anything else is refused — a malformed
/// seal never enters the registry, so a caller bug cannot
/// register a seal that a later, well-formed presentation
/// would miss (or collide with).
fn normalize_seal(seal: &str) -> Result<String, RegistryError> {
    if seal.len() == 64 && seal.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(seal.to_ascii_lowercase())
    } else {
        Err(RegistryError::InvalidSeal(format!(
            "seal must be 64 hex characters, got {} bytes",
            seal.len()
        )))
    }
}

// ---------------------------------------------------------------------
// Core types.
// ---------------------------------------------------------------------

/// One registration: a seal, the instant it was first seen
/// (caller-supplied `now_ms` at its first presentation), and how
/// many times it has been presented in total, first presentation
/// included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub seal: String,
    pub first_seen_ms: i64,
    pub presentations: u64,
}

/// The verdict on a presentation. `Replay` carries the original
/// registration record: its `first_seen_ms` is the first
/// presentation's instant, and its `presentations` counts every
/// presentation including this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    First { record: Registration },
    Replay { record: Registration },
}

impl Verdict {
    pub fn is_first(&self) -> bool {
        matches!(self, Verdict::First { .. })
    }

    pub fn is_replay(&self) -> bool {
        matches!(self, Verdict::Replay { .. })
    }

    pub fn record(&self) -> &Registration {
        match self {
            Verdict::First { record } | Verdict::Replay { record } => record,
        }
    }
}

/// Caller-configured retention: how long a registration lives
/// (`ttl_ms`, measured from its `first_seen_ms`) and how many
/// registrations the registry holds at once (`capacity`).
/// Either may be `None` (unbounded in that dimension) — but the
/// choice is the caller's, stated at construction. This type
/// has no `Default` impl and the crate ships no preset values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retention {
    pub ttl_ms: Option<i64>,
    pub capacity: Option<u64>,
}

impl Retention {
    /// Construct and validate: a stated TTL must be positive,
    /// a stated capacity must hold at least one registration.
    pub fn new(ttl_ms: Option<i64>, capacity: Option<u64>) -> Result<Self, RegistryError> {
        if let Some(t) = ttl_ms {
            if t <= 0 {
                return Err(RegistryError::InvalidConfig(format!(
                    "ttl_ms must be positive when stated, got {t}"
                )));
            }
        }
        if let Some(c) = capacity {
            if c == 0 {
                return Err(RegistryError::InvalidConfig(
                    "capacity must be at least 1 when stated".to_string(),
                ));
            }
        }
        Ok(Self { ttl_ms, capacity })
    }

    /// No TTL, no capacity: registrations live until the store
    /// itself goes away. An explicit caller choice, not a
    /// default — registries are constructed with a `Retention`
    /// value either way.
    pub fn unbounded() -> Self {
        Self {
            ttl_ms: None,
            capacity: None,
        }
    }
}

/// Registry statistics: what is held, and the retention in
/// force. Counts are numbers on every read — a registry's mass
/// is never invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub count: u64,
    pub ttl_ms: Option<i64>,
    pub capacity: Option<u64>,
}

// ---------------------------------------------------------------------
// Errors.  Every failure is fail-closed: no error path registers
// a seal, evicts one, or reports a verdict that did not happen.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The presented seal is not 64 hex characters.
    InvalidSeal(String),
    /// The retention configuration is self-contradictory.
    InvalidConfig(String),
    /// The registry is at capacity and the presented seal is
    /// new. Nothing was registered and nothing was evicted;
    /// the remedy is an explicit `sweep` (or a larger capacity
    /// stated by the caller).
    Saturated { capacity: u64, count: u64 },
    /// The storage backend failed.
    Store(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::InvalidSeal(m) => write!(f, "invalid seal: {m}"),
            RegistryError::InvalidConfig(m) => write!(f, "invalid retention config: {m}"),
            RegistryError::Saturated { capacity, count } => write!(
                f,
                "registry saturated: {count} registrations at capacity {capacity}; new seal refused"
            ),
            RegistryError::Store(m) => write!(f, "store error: {m}"),
        }
    }
}

impl std::error::Error for RegistryError {}

// ---------------------------------------------------------------------
// Storage.  All registry logic lives in the core over this
// trait, so every backend answers identically.
// ---------------------------------------------------------------------

pub trait Store {
    /// The registration for `seal`, if present.
    fn get(&mut self, seal: &str) -> Result<Option<Registration>, RegistryError>;
    /// Insert `record` only if its seal is absent. Returns true
    /// when inserted (this presentation is the first), false
    /// when the seal was already present.
    fn insert_if_absent(&mut self, record: &Registration) -> Result<bool, RegistryError>;
    /// Replace the record for an existing seal (used to count a
    /// replay presentation).
    fn update(&mut self, record: &Registration) -> Result<(), RegistryError>;
    /// Remove and return the record for `seal`, if present.
    fn remove(&mut self, seal: &str) -> Result<Option<Registration>, RegistryError>;
    /// Every registration, sorted by seal.
    fn all(&mut self) -> Result<Vec<Registration>, RegistryError>;
    /// How many registrations are held.
    fn count(&mut self) -> Result<u64, RegistryError>;
}

/// The in-memory backend: B-tree map keyed by seal. The
/// test/embedded backend, and the backend of the organelle
/// surface's reference instance.
#[derive(Debug, Default)]
pub struct MemoryStore {
    records: BTreeMap<String, Registration>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(&mut self, seal: &str) -> Result<Option<Registration>, RegistryError> {
        Ok(self.records.get(seal).cloned())
    }

    fn insert_if_absent(&mut self, record: &Registration) -> Result<bool, RegistryError> {
        match self.records.entry(record.seal.clone()) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(record.clone());
                Ok(true)
            }
            std::collections::btree_map::Entry::Occupied(_) => Ok(false),
        }
    }

    fn update(&mut self, record: &Registration) -> Result<(), RegistryError> {
        self.records.insert(record.seal.clone(), record.clone());
        Ok(())
    }

    fn remove(&mut self, seal: &str) -> Result<Option<Registration>, RegistryError> {
        Ok(self.records.remove(seal))
    }

    fn all(&mut self) -> Result<Vec<Registration>, RegistryError> {
        Ok(self.records.values().cloned().collect())
    }

    fn count(&mut self) -> Result<u64, RegistryError> {
        Ok(self.records.len() as u64)
    }
}

// ---------------------------------------------------------------------
// The registry.  An explicit value: constructed over a store
// and a retention, owned by its caller, passed where needed.
// Two registries share nothing unless their caller deliberately
// built them over one store.
// ---------------------------------------------------------------------

pub struct Registry<S: Store> {
    store: S,
    retention: Retention,
}

impl<S: Store> Registry<S> {
    pub fn new(store: S, retention: Retention) -> Self {
        Self { store, retention }
    }

    pub fn retention(&self) -> Retention {
        self.retention
    }

    /// Present a seal at `now_ms` (caller-supplied; the core
    /// never reads a clock).
    ///
    /// * A seal never seen (or swept since) registers and
    ///   returns [`Verdict::First`].
    /// * A seal already held returns [`Verdict::Replay`] with
    ///   the original record — its first-seen instant and its
    ///   presentation count, this presentation included.
    /// * A *new* seal at capacity is refused with
    ///   [`RegistryError::Saturated`]: fail-closed, nothing
    ///   registered, nothing evicted. An already-held seal
    ///   still answers `Replay` at capacity — saturation blocks
    ///   learning new seals, never the detection of old ones.
    ///
    /// Expiry is *not* applied here: a seal past its TTL that
    /// has not been swept is still a replay. [`Registry::sweep`]
    /// is the only eviction path.
    pub fn present(&mut self, seal: &str, now_ms: i64) -> Result<Verdict, RegistryError> {
        let seal = normalize_seal(seal)?;
        if let Some(mut record) = self.store.get(&seal)? {
            record.presentations += 1;
            self.store.update(&record)?;
            return Ok(Verdict::Replay { record });
        }
        if let Some(capacity) = self.retention.capacity {
            let count = self.store.count()?;
            if count >= capacity {
                return Err(RegistryError::Saturated { capacity, count });
            }
        }
        let record = Registration {
            seal: seal.clone(),
            first_seen_ms: now_ms,
            presentations: 1,
        };
        if self.store.insert_if_absent(&record)? {
            return Ok(Verdict::First { record });
        }
        // The store reported the seal absent to `get` but
        // present to `insert_if_absent` — another writer over
        // the same store won the race. Answer as the replay it
        // is, from the record that won.
        let mut record = self.store.get(&seal)?.ok_or_else(|| {
            RegistryError::Store(
                "insert_if_absent reported an existing seal that get cannot find".to_string(),
            )
        })?;
        record.presentations += 1;
        self.store.update(&record)?;
        Ok(Verdict::Replay { record })
    }

    /// Look up a seal without presenting it: the registration
    /// if held, `None` if not. Registers nothing, counts
    /// nothing.
    pub fn check(&mut self, seal: &str) -> Result<Option<Registration>, RegistryError> {
        let seal = normalize_seal(seal)?;
        self.store.get(&seal)
    }

    /// The only eviction path, and an explicit one. Evicts, in
    /// order of application:
    ///
    /// 1. every registration expired at `now_ms` under the
    ///    stated TTL (age `now_ms - first_seen_ms >= ttl_ms`;
    ///    a registration is valid on
    ///    `[first_seen_ms, first_seen_ms + ttl_ms)`);
    /// 2. if a capacity is stated and the registry still holds
    ///    more than it (possible when a store populated under
    ///    one retention is opened under a smaller one), the
    ///    oldest registrations — by `first_seen_ms`, ties by
    ///    seal — until the count is at capacity.
    ///
    /// Returns exactly the records evicted, sorted by
    /// `(first_seen_ms, seal)`. A swept seal presented again
    /// registers as new.
    pub fn sweep(&mut self, now_ms: i64) -> Result<Vec<Registration>, RegistryError> {
        let mut all = self.store.all()?;
        let mut evicted: Vec<Registration> = Vec::new();
        if let Some(ttl) = self.retention.ttl_ms {
            let (expired, live): (Vec<Registration>, Vec<Registration>) =
                all.into_iter().partition(|r| {
                    now_ms.saturating_sub(r.first_seen_ms) >= ttl
                });
            evicted.extend(expired);
            all = live;
        }
        if let Some(capacity) = self.retention.capacity {
            if all.len() as u64 > capacity {
                let mut oldest_first = all.clone();
                oldest_first
                    .sort_by(|a, b| (a.first_seen_ms, &a.seal).cmp(&(b.first_seen_ms, &b.seal)));
                let excess = all.len() as u64 - capacity;
                evicted.extend(oldest_first.into_iter().take(excess as usize));
            }
        }
        for record in &evicted {
            self.store.remove(&record.seal)?;
        }
        evicted.sort_by(|a, b| (a.first_seen_ms, &a.seal).cmp(&(b.first_seen_ms, &b.seal)));
        Ok(evicted)
    }

    /// Count and the retention in force.
    pub fn stats(&mut self) -> Result<Stats, RegistryError> {
        Ok(Stats {
            count: self.store.count()?,
            ttl_ms: self.retention.ttl_ms,
            capacity: self.retention.capacity,
        })
    }
}

// ---------------------------------------------------------------------
// The shared wrapper: a registry behind a mutex, for callers
// whose presentations arrive on many threads (the organelle
// surface, worker isolate handlers, test harnesses). The mutex
// is what makes check-and-register atomic, so concurrent
// presentations of one seal yield exactly one `First`.
// ---------------------------------------------------------------------

pub struct SharedRegistry<S: Store> {
    inner: std::sync::Arc<std::sync::Mutex<Registry<S>>>,
}

// Manual Clone: cloning a SharedRegistry clones the Arc, not
// the store — no `S: Clone` bound is wanted or needed.
impl<S: Store> Clone for SharedRegistry<S> {
    fn clone(&self) -> Self {
        Self {
            inner: std::sync::Arc::clone(&self.inner),
        }
    }
}

impl<S: Store> SharedRegistry<S> {
    pub fn new(registry: Registry<S>) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(registry)),
        }
    }

    pub fn present(&self, seal: &str, now_ms: i64) -> Result<Verdict, RegistryError> {
        self.inner
            .lock()
            .expect("registry lock")
            .present(seal, now_ms)
    }

    pub fn check(&self, seal: &str) -> Result<Option<Registration>, RegistryError> {
        self.inner.lock().expect("registry lock").check(seal)
    }

    pub fn sweep(&self, now_ms: i64) -> Result<Vec<Registration>, RegistryError> {
        self.inner.lock().expect("registry lock").sweep(now_ms)
    }

    pub fn stats(&self) -> Result<Stats, RegistryError> {
        self.inner.lock().expect("registry lock").stats()
    }
}

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
mod sqlite;

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub use sqlite::SqliteStore;

// ---------------------------------------------------------------------
// Organelle surface.  A stateful organelle: it owns one
// registry over the in-memory backend. The registry is a field
// of the organelle value — no statics, and two organelle
// instances are two registries.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let obj = |required: &[&str], props: Vec<(String, serde_json::Value)>| {
        serde_json::json!({
            "type": "object",
            "required": required,
            "properties": serde_json::Value::Object(props.into_iter().collect()),
        })
    };
    let prop = |name: &str, ty: &str| {
        (
            name.to_string(),
            serde_json::json!({"type": ty}),
        )
    };
    let write = Some(MutationClass::Write);
    let read = Some(MutationClass::ReadOnly);
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "replay-registry".to_string(),
        codon: "rr".to_string(),
        version: "1.0.0".to_string(),
        description:
            "seen-seal registry: the first presentation of a sha256 seal registers it, \
             every later presentation is a replay verdict carrying the original \
             registration record; retention (TTL and/or capacity) is caller-supplied \
             data stated at construction; eviction happens only through an explicit \
             sweep that reports exactly what it evicted; at capacity a new seal is \
             refused (fail-closed saturation), never silently registered or dropped"
                .to_string(),
        contracts: vec![
            Contract {
                op: "present".to_string(),
                description: "present {seal, now_ms} -> {verdict: first|replay, record}: registers a new seal or detects a replay; the record carries first_seen_ms and the presentation count; now_ms is a required caller input (the registry reads no clock); a new seal at capacity errors as saturated".to_string(),
                input_schema: obj(&["seal", "now_ms"], vec![prop("seal", "string"), prop("now_ms", "integer")]),
                mutation_class: write.clone(),
                required_capability: Some("replay.registry".to_string()),
            },
            Contract {
                op: "check".to_string(),
                description: "check {seal} -> the registration or null; registers nothing, counts nothing".to_string(),
                input_schema: obj(&["seal"], vec![prop("seal", "string")]),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "sweep".to_string(),
                description: "sweep {now_ms} -> {evicted: [registration]}: the only eviction path; evicts TTL-expired registrations and, over capacity, the oldest; returns exactly what it evicted, sorted by (first_seen_ms, seal)".to_string(),
                input_schema: obj(&["now_ms"], vec![prop("now_ms", "integer")]),
                mutation_class: write.clone(),
                required_capability: Some("replay.registry".to_string()),
            },
            Contract {
                op: "stats".to_string(),
                description: "stats {} -> {count, ttl_ms, capacity}: how much the registry holds and the retention in force".to_string(),
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
pub struct ReplayRegistryOrganelle {
    manifest: OrganelleManifest,
    inner: SharedRegistry<MemoryStore>,
}

/// The organelle surface over a registry with the caller's
/// stated retention. This is the constructor adopters use:
/// retention is caller data, so it is an argument, not a
/// constant of the crate.
#[cfg(feature = "organelle")]
pub fn organelle_with(retention: Retention) -> std::sync::Arc<dyn Organelle> {
    std::sync::Arc::new(ReplayRegistryOrganelle {
        manifest: manifest(),
        inner: SharedRegistry::new(Registry::new(MemoryStore::new(), retention)),
    })
}

/// The reference surface instance, with unbounded retention —
/// stated here, in the open, as this instance's configuration.
/// Adopters with a retention policy (the Exchange's shape is
/// one hour / 10,000) construct with [`organelle_with`].
#[cfg(feature = "organelle")]
pub fn organelle() -> std::sync::Arc<dyn Organelle> {
    organelle_with(Retention::unbounded())
}

#[cfg(feature = "organelle")]
fn rejected<T>(msg: impl Into<String>) -> Result<T, OrganelleError> {
    Err(OrganelleError::new("rejected", msg.into()))
}

#[cfg(feature = "organelle")]
fn req_str(input: &serde_json::Value, field: &str) -> Result<String, OrganelleError> {
    match input[field].as_str() {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => rejected(format!("{field} must be a non-empty string")),
    }
}

#[cfg(feature = "organelle")]
fn req_i64(input: &serde_json::Value, field: &str) -> Result<i64, OrganelleError> {
    match input[field].as_i64() {
        Some(n) => Ok(n),
        None => rejected(format!(
            "{field} must be an integer (time is a caller input; the registry reads no clock)"
        )),
    }
}

#[cfg(feature = "organelle")]
fn fail<T>(e: RegistryError) -> Result<T, OrganelleError> {
    match e {
        RegistryError::InvalidSeal(m) | RegistryError::InvalidConfig(m) => {
            Err(OrganelleError::new("rejected", m))
        }
        RegistryError::Saturated { .. } => Err(OrganelleError::new("saturated", e.to_string())),
        RegistryError::Store(m) => Err(OrganelleError::failed(m)),
    }
}

#[cfg(feature = "organelle")]
impl Organelle for ReplayRegistryOrganelle {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, OrganelleError> {
        fn to_json<T: Serialize>(v: &T) -> Result<serde_json::Value, OrganelleError> {
            serde_json::to_value(v)
                .map_err(|e| OrganelleError::failed(format!("serialize: {e}")))
        }
        match op {
            "present" => {
                let seal = req_str(&input, "seal")?;
                let now_ms = req_i64(&input, "now_ms")?;
                match self.inner.present(&seal, now_ms) {
                    Ok(verdict) => to_json(&verdict),
                    Err(e) => fail(e),
                }
            }
            "check" => {
                let seal = req_str(&input, "seal")?;
                match self.inner.check(&seal) {
                    Ok(Some(record)) => to_json(&record),
                    Ok(None) => Ok(serde_json::Value::Null),
                    Err(e) => fail(e),
                }
            }
            "sweep" => {
                let now_ms = req_i64(&input, "now_ms")?;
                match self.inner.sweep(now_ms) {
                    Ok(evicted) => Ok(serde_json::json!({ "evicted": to_json(&evicted)? })),
                    Err(e) => fail(e),
                }
            }
            "stats" => match self.inner.stats() {
                Ok(stats) => to_json(&stats),
                Err(e) => fail(e),
            },
            other => rejected(format!("unknown op: {other}")),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The five required proofs are named for what they
// prove: first/replay, instance isolation, exact sweep,
// concurrent single-first, determinism.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(tag: &str) -> String {
        seal_of(tag.as_bytes())
    }

    fn registry(retention: Retention) -> Registry<MemoryStore> {
        Registry::new(MemoryStore::new(), retention)
    }

    // (a) First presentation registers; the second is a Replay
    // carrying the ORIGINAL record — the first-seen instant of
    // the first presentation, not of the replay.
    #[test]
    fn first_registers_second_replays_with_original_record() {
        let mut r = registry(Retention::unbounded());
        let s = seal("envelope-1");
        let v1 = r.present(&s, 1_000).unwrap();
        assert!(v1.is_first());
        assert_eq!(v1.record().seal, s);
        assert_eq!(v1.record().first_seen_ms, 1_000);
        assert_eq!(v1.record().presentations, 1);

        let v2 = r.present(&s, 2_000).unwrap();
        assert!(v2.is_replay());
        assert_eq!(v2.record().first_seen_ms, 1_000, "original first-seen, not the replay's");
        assert_eq!(v2.record().presentations, 2);

        let v3 = r.present(&s, 3_500).unwrap();
        assert!(v3.is_replay());
        assert_eq!(v3.record().first_seen_ms, 1_000);
        assert_eq!(v3.record().presentations, 3);

        // A different seal is independent.
        let other = r.present(&seal("envelope-2"), 3_500).unwrap();
        assert!(other.is_first());
        assert_eq!(r.stats().unwrap().count, 2);
    }

    // (b) Two registry instances never see each other's seals.
    // This is the property the Exchange's harness lacked when
    // its seal set was a process global: parallel tests minted
    // identical seals into one shared set and ate false 409s.
    // Here isolation is by construction — there is no global
    // to collide through.
    #[test]
    fn instances_are_isolated() {
        let mut a = registry(Retention::unbounded());
        let mut b = registry(Retention::unbounded());
        let s = seal("same-seal-both-registries");
        assert!(a.present(&s, 100).unwrap().is_first());
        // In a shared-global design this would be a false replay.
        assert!(b.present(&s, 100).unwrap().is_first());
        assert!(a.present(&s, 200).unwrap().is_replay());
        assert_eq!(b.check(&s).unwrap().unwrap().presentations, 1);
        // Sweeps are per-instance too.
        let mut a_ttl = Registry::new(
            MemoryStore::new(),
            Retention::new(Some(50), None).unwrap(),
        );
        assert!(a_ttl.present(&s, 0).unwrap().is_first());
        assert_eq!(a_ttl.sweep(100).unwrap().len(), 1);
        assert!(b.check(&s).unwrap().is_some(), "b's registration survives a's sweep");
    }

    // (c) Sweep evicts exactly the expired entries and reports
    // them; a swept seal registers as new afterwards.
    #[test]
    fn sweep_evicts_exactly_expired_and_reports() {
        let mut r = registry(Retention::new(Some(150), None).unwrap());
        let (s0, s1, s2) = (seal("t0"), seal("t100"), seal("t200"));
        r.present(&s0, 0).unwrap();
        r.present(&s1, 100).unwrap();
        r.present(&s2, 200).unwrap();
        // At t=250: ages are 250, 150, 50 against a TTL of 150.
        // Expiry is age >= ttl, so s0 and s1 go, s2 stays.
        let evicted = r.sweep(250).unwrap();
        let evicted_seals: Vec<&str> = evicted.iter().map(|r| r.seal.as_str()).collect();
        assert_eq!(evicted_seals, vec![s0.as_str(), s1.as_str()]);
        assert_eq!(evicted[0].first_seen_ms, 0);
        assert_eq!(evicted[1].first_seen_ms, 100);
        assert_eq!(r.stats().unwrap().count, 1);
        assert!(r.check(&s2).unwrap().is_some());
        // A swept seal registers as new, with a new first-seen.
        let v = r.present(&s0, 260).unwrap();
        assert!(v.is_first());
        assert_eq!(v.record().first_seen_ms, 260);
        // And a sweep that expires nothing reports nothing.
        assert!(r.sweep(300).unwrap().is_empty());
    }

    // (c, capacity arm) A store populated under a larger
    // retention, opened under a smaller capacity: sweep evicts
    // exactly the oldest down to capacity and reports them.
    #[test]
    fn sweep_evicts_oldest_down_to_capacity() {
        let mut store = MemoryStore::new();
        let seals: Vec<String> = (0..4).map(|i| seal(&format!("cap-{i}"))).collect();
        for (i, s) in seals.iter().enumerate() {
            store
                .insert_if_absent(&Registration {
                    seal: s.clone(),
                    first_seen_ms: (i as i64) * 10,
                    presentations: 1,
                })
                .unwrap();
        }
        let mut r = Registry::new(store, Retention::new(None, Some(2)).unwrap());
        let evicted = r.sweep(1_000).unwrap();
        let evicted_seals: Vec<&str> = evicted.iter().map(|r| r.seal.as_str()).collect();
        assert_eq!(evicted_seals, vec![seals[0].as_str(), seals[1].as_str()]);
        assert_eq!(r.stats().unwrap().count, 2);
        assert!(r.check(&seals[2]).unwrap().is_some());
        assert!(r.check(&seals[3]).unwrap().is_some());
    }

    // Saturation fails closed: at capacity a NEW seal is
    // refused — nothing registered, nothing evicted, the held
    // seal still detected as a replay — and the stated remedy
    // (an explicit sweep) is what unblocks registration.
    #[test]
    fn saturation_fails_closed() {
        let mut r = registry(Retention::new(Some(100), Some(1)).unwrap());
        let (held, newcomer) = (seal("held"), seal("newcomer"));
        assert!(r.present(&held, 0).unwrap().is_first());
        let err = r.present(&newcomer, 10).unwrap_err();
        assert_eq!(
            err,
            RegistryError::Saturated {
                capacity: 1,
                count: 1
            }
        );
        assert_eq!(r.stats().unwrap().count, 1, "saturation registered nothing");
        assert!(r.check(&newcomer).unwrap().is_none());
        assert!(
            r.present(&held, 20).unwrap().is_replay(),
            "replay detection is never blocked by saturation"
        );
        // The newcomer is still refused while the held seal is
        // live-but-unswept — even past its TTL. Expiry is the
        // sweep's job, not present's.
        assert!(matches!(
            r.present(&newcomer, 500),
            Err(RegistryError::Saturated { .. })
        ));
        let evicted = r.sweep(500).unwrap();
        assert_eq!(evicted.len(), 1);
        assert!(r.present(&newcomer, 500).unwrap().is_first());
    }

    // (d) Concurrent duplicate presentations of one seal yield
    // exactly one First and the rest Replay.
    #[test]
    fn concurrent_duplicates_exactly_one_first() {
        let shared = SharedRegistry::new(registry(Retention::unbounded()));
        let s = seal("raced-seal");
        let verdicts: Vec<Verdict> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let shared = shared.clone();
                    let s = s.clone();
                    scope.spawn(move || shared.present(&s, 42_000).unwrap())
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let firsts = verdicts.iter().filter(|v| v.is_first()).count();
        let replays = verdicts.iter().filter(|v| v.is_replay()).count();
        assert_eq!(firsts, 1, "exactly one winner");
        assert_eq!(replays, 15);
        assert!(verdicts
            .iter()
            .all(|v| v.record().first_seen_ms == 42_000));
        assert_eq!(shared.check(&s).unwrap().unwrap().presentations, 16);
    }

    // (e) Determinism: a scripted sequence of presents and
    // sweeps replays to byte-identical output on a fresh
    // registry — verdicts are a pure function of the script.
    #[test]
    fn determinism_scripted_sequences_byte_identical() {
        #[derive(Clone)]
        enum Op {
            Present(String, i64),
            Sweep(i64),
        }
        let script = vec![
            Op::Present(seal("alpha"), 0),
            Op::Present(seal("beta"), 10),
            Op::Present(seal("alpha"), 20),
            Op::Sweep(50),
            Op::Present(seal("gamma"), 60),
            Op::Present(seal("beta"), 70),
            Op::Sweep(1_000),
            Op::Present(seal("alpha"), 1_010),
            Op::Present(seal("alpha"), 1_020),
        ];
        let run = |script: &[Op]| -> Vec<String> {
            let mut r = registry(Retention::new(Some(100), Some(3)).unwrap());
            script
                .iter()
                .map(|op| match op {
                    Op::Present(s, t) => {
                        serde_json::to_string(&r.present(s, *t).unwrap()).unwrap()
                    }
                    Op::Sweep(t) => serde_json::to_string(&r.sweep(*t).unwrap()).unwrap(),
                })
                .collect()
        };
        let first = run(&script);
        let second = run(&script);
        assert_eq!(first, second);
        // The script exercised all three outcomes.
        assert!(first.iter().any(|s| s.contains("\"first\"")));
        assert!(first.iter().any(|s| s.contains("\"replay\"")));
    }

    // Malformed seals are refused at the door and register
    // nothing; well-formed seals are case-normalized.
    #[test]
    fn invalid_seals_refused() {
        let mut r = registry(Retention::unbounded());
        for bad in ["", "abc", "zz".repeat(32).as_str()] {
            assert!(
                matches!(r.present(bad, 0), Err(RegistryError::InvalidSeal(_))),
                "refused: {bad:?}"
            );
        }
        assert!(matches!(
            r.present(&"a".repeat(63), 0),
            Err(RegistryError::InvalidSeal(_))
        ));
        assert!(matches!(
            r.present(&"a".repeat(65), 0),
            Err(RegistryError::InvalidSeal(_))
        ));
        assert_eq!(r.stats().unwrap().count, 0);
        // Uppercase hex is the same seal, normalized.
        let lower = seal("case-test");
        let upper = lower.to_uppercase();
        assert!(r.present(&upper, 5).unwrap().is_first());
        assert!(r.present(&lower, 6).unwrap().is_replay());
    }

    // check() is a pure read: it neither registers nor counts.
    #[test]
    fn check_does_not_register() {
        let mut r = registry(Retention::unbounded());
        let s = seal("peeked");
        assert!(r.check(&s).unwrap().is_none());
        assert!(r.check(&s).unwrap().is_none());
        assert!(r.present(&s, 7).unwrap().is_first());
        assert_eq!(r.check(&s).unwrap().unwrap().presentations, 1);
    }

    // Retention is validated caller data: self-contradictory
    // values are refused at construction.
    #[test]
    fn retention_config_validates() {
        assert!(matches!(
            Retention::new(Some(0), None),
            Err(RegistryError::InvalidConfig(_))
        ));
        assert!(matches!(
            Retention::new(Some(-5), None),
            Err(RegistryError::InvalidConfig(_))
        ));
        assert!(matches!(
            Retention::new(None, Some(0)),
            Err(RegistryError::InvalidConfig(_))
        ));
        assert!(Retention::new(Some(1), Some(1)).is_ok());
        assert!(Retention::new(None, None).is_ok());
    }

    // seal_of is the estate's sha256 — the standard vectors.
    #[test]
    fn seal_of_is_sha256() {
        assert_eq!(
            seal_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            seal_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(seal_of(b"abc"), seal_of(b"abc"));
        assert_ne!(seal_of(b"abc"), seal_of(b"abd"));
    }

    #[cfg(feature = "organelle")]
    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }

    // The organelle surface keeps the same guarantees: first /
    // replay through handle(), the original record on replay,
    // capability required for writes, sweep reports evictions.
    #[cfg(feature = "organelle")]
    #[test]
    fn organelle_surface_round_trip() {
        use organelle_host::{CallContext, Host};
        let h = Host::new();
        h.register(organelle_with(
            Retention::new(Some(3_600_000), Some(10_000)).unwrap(),
        ))
        .unwrap();
        let ctx = CallContext::new("test", vec!["replay.registry".to_string()]);
        let s = seal("surface-envelope");
        let call = |ctx: &CallContext, op: &str, input: serde_json::Value| {
            h.call(ctx, "rr", op, input)
        };
        let out = call(
            &ctx,
            "present",
            serde_json::json!({"seal": s, "now_ms": 100}),
        )
        .unwrap()
        .output;
        assert_eq!(out["verdict"], "first");
        assert_eq!(out["record"]["first_seen_ms"], 100);
        let out = call(
            &ctx,
            "present",
            serde_json::json!({"seal": s, "now_ms": 200}),
        )
        .unwrap()
        .output;
        assert_eq!(out["verdict"], "replay");
        assert_eq!(out["record"]["first_seen_ms"], 100);
        assert_eq!(out["record"]["presentations"], 2);
        // Reads are capability-free; writes are not.
        let read_ctx = CallContext::new("reader", vec![]);
        let out = call(&read_ctx, "check", serde_json::json!({"seal": s}))
            .unwrap()
            .output;
        assert_eq!(out["first_seen_ms"], 100);
        assert!(call(
            &read_ctx,
            "present",
            serde_json::json!({"seal": seal("no-cap"), "now_ms": 1}),
        )
        .is_err());
        // Sweep reports exactly what it evicted.
        let out = call(&ctx, "sweep", serde_json::json!({"now_ms": 3_600_100}))
            .unwrap()
            .output;
        assert_eq!(out["evicted"].as_array().unwrap().len(), 1);
        assert_eq!(out["evicted"][0]["seal"], s);
        let out = call(&ctx, "stats", serde_json::json!({})).unwrap().output;
        assert_eq!(out["count"], 0);
        assert_eq!(out["ttl_ms"], 3_600_000);
        assert_eq!(out["capacity"], 10_000);
        // now_ms is a required input — no clock is read instead.
        assert!(call(&ctx, "present", serde_json::json!({"seal": s})).is_err());
    }
}
