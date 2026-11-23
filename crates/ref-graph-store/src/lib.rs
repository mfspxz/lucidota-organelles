//! org-033 — Reference organelle: graph-store-query (codon `gs`).
//!
//! Typed triple storage with traversal and temporal query
//! (GAP-08 in the 2026-11-22 decomposition map: five scoped
//! softwares — WRK, EXC, SDX, VAN, MCP — hand-roll graph storage
//! and query today: wreck's graph views, the Exchange's
//! evidence-graph SQLite store, SupDox's manual section graph,
//! VanCan's standalone graph checker, and the MCP graph server's
//! arbitrary-Cypher surface).
//!
//! The doctrine this crate implements is Zack's graph doctrine,
//! and it is enforced in the API, not in documentation:
//!
//! * **Ternary state, always attached.**  Every assertion carries
//!   a [`State`] — `Proven` | `Claimed` | `Unknown` — and a
//!   provenance reference.  There is NO query shape in this crate
//!   that returns a bare fact: every result element is a full
//!   [`Assertion`], state and provenance included.  An `Unknown`
//!   assertion is returned *as* unknown by every query — never
//!   silently dropped, never promoted, never coerced to false or
//!   to absence.  Unknown stays unknown.
//! * **Time is the fourth dimension, and it is data.**  Every
//!   assertion carries a validity interval
//!   (`valid_from_ms` inclusive, `valid_to_ms` exclusive; either
//!   side may be unbounded).  Temporal filtering takes the query
//!   time `T` as an input — the store never reads a clock.
//! * **No invented edges.**  The store contains exactly the
//!   assertions callers put in it.  Traversal follows asserted
//!   edges only, to exactly the depth the caller supplies.
//! * **Stable ids are content hashes.**  An assertion's id is the
//!   sha256 of its canonical content (subject, predicate, object,
//!   state, provenance, validity interval) — never a process-local
//!   hash, never a sequence number.  Same assertion, same id,
//!   every run, every backend.  Node ids follow the typed-traits
//!   rule: `sha256(canonical_json(thing))` (see [`thing_id`]).
//! * **Type vocabulary aligned with typed-traits-v1**
//!   (`~/workspace/coal-harbour-cute-city/typed-traits.json`):
//!   node classes and verbs are the schema's — see [`CLASSES`]
//!   and [`VERBS`].  The store itself accepts any non-empty
//!   predicate string (adopters with their own predicate sets —
//!   the Exchange, the MCP graph server — are not forced into one
//!   domain's verbs); the constants are the shared vocabulary,
//!   and a caller that wants the closed vocabulary enforced can
//!   gate assertion with `ref-policy-gate` (org-029).
//!
//! Storage sits behind the [`Store`] trait.  [`MemoryStore`] is
//! the test/embedded backend; `SqliteStore` (feature `sqlite`,
//! native only) is the durable backend.  All query logic lives in
//! the core over the store's full assertion set, sorted by
//! assertion id, so query results are identical — byte for byte —
//! on every backend and independent of insertion order.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};

// ---------------------------------------------------------------------
// Type vocabulary, aligned with typed-traits-v1
// (~/workspace/coal-harbour-cute-city/typed-traits.json).
// ---------------------------------------------------------------------

/// Node classes in typed-traits-v1.
pub const CLASSES: &[&str] = &[
    "Authority", "Community", "Funder", "Lease", "Operator", "Person", "Place", "Program",
    "Vehicle",
];

/// Verbs (predicates) in typed-traits-v1, in the schema's own
/// snake_case surface form (the compressed triples write
/// `contains`, `located_at`, `authorizes`, `operates`, …).
pub const VERBS: &[&str] = &[
    "does",
    "is_done_to",
    "touches",
    "located_at",
    "authorizes",
    "operates",
    "funds",
    "competes_with",
    "partners_with",
    "contains",
    "permits",
    "requires",
    "supports",
    "finds",
    "opens",
    "decides",
    "endorses",
    "leases",
    "binds",
    "expires",
    "renews",
    "lends",
    "subsidizes",
    "trains",
    "employs",
    "hosts",
    "patrols",
    "moves",
    "carries",
    "represents",
    "endorses_claimed",
];

/// The typed-traits id rule: `sha256(canonical_json(thing))`.
/// Canonical JSON here is serde_json's serialization of a
/// `Value` (object keys sorted — serde_json maps are B-trees
/// without the preserve-order feature), hashed as UTF-8 bytes.
/// Never a process-local hash: the same Thing has the same id
/// in every run.
pub fn thing_id(canonical_thing: &Value) -> String {
    let bytes = serde_json::to_vec(canonical_thing).expect("a Value serializes");
    hex::encode(Sha256::digest(&bytes))
}

// ---------------------------------------------------------------------
// Core types.
// ---------------------------------------------------------------------

/// Ternary assertion state.  `Unknown` is a first-class value:
/// it is stored, returned, and counted exactly like the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Proven,
    Claimed,
    Unknown,
}

/// One end of a triple.  A subject is always a [`Term::Node`]
/// (enforced at assertion time); an object may be a node or a
/// literal value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Term {
    Node { id: String },
    Literal { value: Value },
}

impl Term {
    pub fn node(id: impl Into<String>) -> Self {
        Term::Node { id: id.into() }
    }

    pub fn literal(value: Value) -> Self {
        Term::Literal { value }
    }

    /// The node id, if this term is a node.
    pub fn as_node(&self) -> Option<&str> {
        match self {
            Term::Node { id } => Some(id),
            Term::Literal { .. } => None,
        }
    }
}

/// A declared node (a Thing): id, class, and trait names, per
/// typed-traits-v1.  Declaration is bookkeeping for consumers
/// that type their nodes; assertions do not require the nodes
/// they mention to be declared (the store records what callers
/// assert — it does not invent, and it does not gatekeep).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDecl {
    pub id: String,
    pub class: String,
    pub traits: Vec<String>,
}

/// One asserted triple with its state, provenance, and validity
/// interval.  This is the ONLY shape any query in this crate
/// returns — there is no bare-fact projection.
///
/// The `id` is derived: sha256 over the canonical content.
/// Two assertions that differ in state, provenance, or validity
/// are different assertions and coexist; the graph records who
/// asserted what, in which state, on what evidence, for when.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assertion {
    pub id: String,
    pub subject: Term,
    pub predicate: String,
    pub object: Term,
    pub state: State,
    /// Provenance reference: where this assertion comes from
    /// (a source id, a receipt id, a document span — the
    /// caller's reference vocabulary).  Required, non-empty.
    pub provenance: String,
    /// Validity interval start, epoch milliseconds, inclusive.
    /// `None` = valid from the unbounded past.
    pub valid_from_ms: Option<i64>,
    /// Validity interval end, epoch milliseconds, exclusive.
    /// `None` = valid into the unbounded future.
    pub valid_to_ms: Option<i64>,
}

impl Assertion {
    /// Build an assertion, deriving its content-hash id.
    /// Validates the doctrine's structural rules: the subject
    /// must be a node, the predicate and provenance must be
    /// non-empty, and a stated interval must not be empty.
    pub fn new(
        subject: Term,
        predicate: impl Into<String>,
        object: Term,
        state: State,
        provenance: impl Into<String>,
        valid_from_ms: Option<i64>,
        valid_to_ms: Option<i64>,
    ) -> Result<Self, GraphError> {
        let predicate = predicate.into();
        let provenance = provenance.into();
        if subject.as_node().is_none() {
            return Err(GraphError::Invalid(
                "subject must be a node term; a literal cannot be a subject".to_string(),
            ));
        }
        if predicate.trim().is_empty() {
            return Err(GraphError::Invalid("predicate must be non-empty".to_string()));
        }
        if provenance.trim().is_empty() {
            return Err(GraphError::Invalid(
                "provenance must be a non-empty reference; an assertion without provenance \
                 does not enter the graph"
                    .to_string(),
            ));
        }
        if let (Some(from), Some(to)) = (valid_from_ms, valid_to_ms) {
            if from >= to {
                return Err(GraphError::Invalid(format!(
                    "validity interval [{from}, {to}) is empty"
                )));
            }
        }
        let mut a = Assertion {
            id: String::new(),
            subject,
            predicate,
            object,
            state,
            provenance,
            valid_from_ms,
            valid_to_ms,
        };
        a.id = a.content_id();
        Ok(a)
    }

    /// sha256 over the canonical content (everything but the id).
    fn content_id(&self) -> String {
        let canonical = serde_json::json!({
            "subject": self.subject,
            "predicate": self.predicate,
            "object": self.object,
            "state": self.state,
            "provenance": self.provenance,
            "valid_from_ms": self.valid_from_ms,
            "valid_to_ms": self.valid_to_ms,
        });
        thing_id(&canonical)
    }

    /// Is this assertion valid at time `t` (epoch ms)?
    /// Interval semantics: `valid_from_ms` inclusive,
    /// `valid_to_ms` exclusive, `None` unbounded.
    pub fn valid_at(&self, t: i64) -> bool {
        if let Some(from) = self.valid_from_ms {
            if t < from {
                return false;
            }
        }
        if let Some(to) = self.valid_to_ms {
            if t >= to {
                return false;
            }
        }
        true
    }
}

/// Errors.  `Invalid` is a caller error (the assertion or query
/// violates a structural rule); `Store` is a backend failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    Invalid(String),
    Store(String),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphError::Invalid(m) => write!(f, "invalid: {m}"),
            GraphError::Store(m) => write!(f, "store: {m}"),
        }
    }
}

impl std::error::Error for GraphError {}

// ---------------------------------------------------------------------
// Storage.  The core runs every query over the store's full,
// id-sorted assertion set, so results do not depend on the
// backend's indexing choices — identical on every backend, and
// independent of insertion order.
// ---------------------------------------------------------------------

pub trait Store {
    /// Insert an assertion; returns the stored record.  An
    /// assertion whose id is already present is a replay: the
    /// stored record is returned and nothing changes.
    fn put_assertion(&mut self, assertion: Assertion) -> Result<Assertion, GraphError>;
    /// Fetch one assertion by id.
    fn get_assertion(&mut self, id: &str) -> Result<Option<Assertion>, GraphError>;
    /// Every assertion, sorted by id.
    fn assertions(&mut self) -> Result<Vec<Assertion>, GraphError>;
    /// Insert or replace a node declaration (by id).
    fn put_node(&mut self, node: NodeDecl) -> Result<NodeDecl, GraphError>;
    /// Fetch one node declaration by id.
    fn get_node(&mut self, id: &str) -> Result<Option<NodeDecl>, GraphError>;
    /// Every node declaration, sorted by id.
    fn nodes(&mut self) -> Result<Vec<NodeDecl>, GraphError>;
}

/// The in-memory backend: two B-tree maps.  Iteration order is
/// id order by construction, which is what makes every query
/// over it deterministic.
#[derive(Debug, Default)]
pub struct MemoryStore {
    assertions: BTreeMap<String, Assertion>,
    nodes: BTreeMap<String, NodeDecl>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn put_assertion(&mut self, assertion: Assertion) -> Result<Assertion, GraphError> {
        match self.assertions.get(&assertion.id) {
            Some(existing) => Ok(existing.clone()),
            None => {
                let stored = assertion.clone();
                self.assertions.insert(assertion.id.clone(), assertion);
                Ok(stored)
            }
        }
    }

    fn get_assertion(&mut self, id: &str) -> Result<Option<Assertion>, GraphError> {
        Ok(self.assertions.get(id).cloned())
    }

    fn assertions(&mut self) -> Result<Vec<Assertion>, GraphError> {
        Ok(self.assertions.values().cloned().collect())
    }

    fn put_node(&mut self, node: NodeDecl) -> Result<NodeDecl, GraphError> {
        self.nodes.insert(node.id.clone(), node.clone());
        Ok(node)
    }

    fn get_node(&mut self, id: &str) -> Result<Option<NodeDecl>, GraphError> {
        Ok(self.nodes.get(id).cloned())
    }

    fn nodes(&mut self) -> Result<Vec<NodeDecl>, GraphError> {
        Ok(self.nodes.values().cloned().collect())
    }
}

// ---------------------------------------------------------------------
// Queries.  Every query returns full assertions — state and
// provenance attached, always.  `at_ms` is an input: `None`
// means no temporal filtering (the assertion set as asserted),
// `Some(t)` means only assertions valid at `t`.
// ---------------------------------------------------------------------

/// A lookup filter.  Every field is optional; a field left
/// `None` matches everything.  There is deliberately no state
/// field that could hide `Unknown` by default — callers who
/// want a state restriction ask for it explicitly and still
/// receive each returned assertion's state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Query {
    pub subject: Option<Term>,
    pub predicate: Option<String>,
    pub object: Option<Term>,
    pub at_ms: Option<i64>,
}

impl Query {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subject(mut self, subject: Term) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn predicate(mut self, predicate: impl Into<String>) -> Self {
        self.predicate = Some(predicate.into());
        self
    }

    pub fn object(mut self, object: Term) -> Self {
        self.object = Some(object);
        self
    }

    pub fn at(mut self, at_ms: i64) -> Self {
        self.at_ms = Some(at_ms);
        self
    }

    fn matches(&self, a: &Assertion) -> bool {
        if let Some(s) = &self.subject {
            if *s != a.subject {
                return false;
            }
        }
        if let Some(p) = &self.predicate {
            if *p != a.predicate {
                return false;
            }
        }
        if let Some(o) = &self.object {
            if *o != a.object {
                return false;
            }
        }
        if let Some(t) = self.at_ms {
            if !a.valid_at(t) {
                return false;
            }
        }
        true
    }
}

/// Traversal direction over node-to-node assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Follow subject → object.
    Out,
    /// Follow object → subject.
    In,
    /// Follow both.
    Both,
}

/// A node reached by traversal, with the depth at which it was
/// first reached (the start node is depth 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachedNode {
    pub id: String,
    pub depth: u32,
}

/// The result of a bounded traversal: every assertion traversed
/// (full assertions — state and provenance attached) and every
/// node reached, with depths.  Both lists are in deterministic
/// order (assertions by id, reached nodes by (depth, id)).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Traversal {
    pub assertions: Vec<Assertion>,
    pub reached: Vec<ReachedNode>,
}

/// Counts over the store — telemetry.  Assertions are counted
/// BY STATE, so a store's unknown mass is a number, never a
/// surprise (the hypertimeline's lesson: 153,057 nodes against
/// 306 assertions is a coverage fact, and it belongs in stats,
/// not in prose).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub assertions: usize,
    pub nodes: usize,
    pub by_state: BTreeMap<String, usize>,
}

/// The graph store core, generic over the storage backend.
pub struct GraphStore<S: Store> {
    store: S,
}

impl<S: Store> GraphStore<S> {
    pub fn new(store: S) -> Self {
        GraphStore { store }
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Assert a triple.  Returns the stored assertion (with its
    /// content-hash id).  Re-asserting identical content is a
    /// replay and returns the existing record.
    pub fn assert(
        &mut self,
        subject: Term,
        predicate: impl Into<String>,
        object: Term,
        state: State,
        provenance: impl Into<String>,
        valid_from_ms: Option<i64>,
        valid_to_ms: Option<i64>,
    ) -> Result<Assertion, GraphError> {
        let a = Assertion::new(
            subject,
            predicate,
            object,
            state,
            provenance,
            valid_from_ms,
            valid_to_ms,
        )?;
        self.store.put_assertion(a)
    }

    /// Insert a fully-formed assertion (validating that its id
    /// matches its content — a mismatched id is refused, so an
    /// assertion's name can never lie about its content).
    pub fn assert_raw(&mut self, assertion: Assertion) -> Result<Assertion, GraphError> {
        if assertion.id != assertion.content_id() {
            return Err(GraphError::Invalid(
                "assertion id does not match its content hash".to_string(),
            ));
        }
        self.store.put_assertion(assertion)
    }

    /// Fetch one assertion by id.
    pub fn get(&mut self, id: &str) -> Result<Option<Assertion>, GraphError> {
        self.store.get_assertion(id)
    }

    /// Declare a node (a Thing): id, class, traits.
    pub fn declare_node(
        &mut self,
        id: impl Into<String>,
        class: impl Into<String>,
        traits: Vec<String>,
    ) -> Result<NodeDecl, GraphError> {
        let id = id.into();
        let class = class.into();
        if id.trim().is_empty() {
            return Err(GraphError::Invalid("node id must be non-empty".to_string()));
        }
        if class.trim().is_empty() {
            return Err(GraphError::Invalid("node class must be non-empty".to_string()));
        }
        self.store.put_node(NodeDecl { id, class, traits })
    }

    pub fn get_node(&mut self, id: &str) -> Result<Option<NodeDecl>, GraphError> {
        self.store.get_node(id)
    }

    pub fn nodes(&mut self) -> Result<Vec<NodeDecl>, GraphError> {
        self.store.nodes()
    }

    /// Every assertion in the store, sorted by id.
    pub fn list(&mut self) -> Result<Vec<Assertion>, GraphError> {
        self.store.assertions()
    }

    /// Filtered lookup: point lookup when all three of
    /// subject/predicate/object are stated, predicate scan when
    /// only the predicate is, and every combination between.
    /// Results are sorted by assertion id.
    pub fn lookup(&mut self, query: &Query) -> Result<Vec<Assertion>, GraphError> {
        Ok(self
            .store
            .assertions()?
            .into_iter()
            .filter(|a| query.matches(a))
            .collect())
    }

    /// Point lookup: the exact triple, optionally at a time.
    pub fn point(
        &mut self,
        subject: &Term,
        predicate: &str,
        object: &Term,
        at_ms: Option<i64>,
    ) -> Result<Vec<Assertion>, GraphError> {
        self.lookup(&Query {
            subject: Some(subject.clone()),
            predicate: Some(predicate.to_string()),
            object: Some(object.clone()),
            at_ms,
        })
    }

    /// Predicate scan: every assertion with this predicate,
    /// optionally at a time.
    pub fn by_predicate(
        &mut self,
        predicate: &str,
        at_ms: Option<i64>,
    ) -> Result<Vec<Assertion>, GraphError> {
        self.lookup(&Query {
            predicate: Some(predicate.to_string()),
            at_ms,
            ..Query::default()
        })
    }

    /// One hop: every assertion touching `node` in the given
    /// direction (as subject for `Out`, as object for `In`,
    /// either for `Both`), optionally at a time.
    pub fn neighbors(
        &mut self,
        node: &str,
        direction: Direction,
        at_ms: Option<i64>,
    ) -> Result<Vec<Assertion>, GraphError> {
        let all = self.store.assertions()?;
        Ok(all
            .into_iter()
            .filter(|a| {
                if let Some(t) = at_ms {
                    if !a.valid_at(t) {
                        return false;
                    }
                }
                let as_subject = a.subject.as_node() == Some(node);
                let as_object = a.object.as_node() == Some(node);
                match direction {
                    Direction::Out => as_subject,
                    Direction::In => as_object,
                    Direction::Both => as_subject || as_object,
                }
            })
            .collect())
    }

    /// Bounded multi-hop traversal from `start` over
    /// node-to-node assertions.  `max_depth` is the caller's
    /// bound and it is exact: depth 0 returns no assertions and
    /// only the start node; depth 1 returns exactly the one-hop
    /// assertions; an assertion at hop `d` is included only if
    /// `d <= max_depth`.  Cycles terminate: a node is expanded
    /// at most once, at its shallowest depth.  Traversal
    /// follows asserted edges only — nothing is invented.
    pub fn traverse(
        &mut self,
        start: &str,
        max_depth: u32,
        direction: Direction,
        at_ms: Option<i64>,
    ) -> Result<Traversal, GraphError> {
        let all = self.store.assertions()?;
        let mut reached: BTreeMap<String, u32> = BTreeMap::new();
        reached.insert(start.to_string(), 0);
        let mut included: BTreeMap<String, Assertion> = BTreeMap::new();
        let mut frontier: BTreeSet<String> = BTreeSet::new();
        frontier.insert(start.to_string());

        for depth in 1..=max_depth {
            let mut next: BTreeSet<String> = BTreeSet::new();
            for a in &all {
                if let Some(t) = at_ms {
                    if !a.valid_at(t) {
                        continue;
                    }
                }
                let (from, to) = match (a.subject.as_node(), a.object.as_node()) {
                    (Some(s), Some(o)) => (s, o),
                    _ => continue, // literals are not traversable edges
                };
                let hops: &[(&str, &str)] = match direction {
                    Direction::Out => &[(from, to)],
                    Direction::In => &[(to, from)],
                    Direction::Both => &[(from, to), (to, from)],
                };
                for (f, t) in hops {
                    if frontier.contains(*f) {
                        included.entry(a.id.clone()).or_insert_with(|| a.clone());
                        if !reached.contains_key(*t) {
                            reached.insert((*t).to_string(), depth);
                            next.insert((*t).to_string());
                        }
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }

        let mut reached_vec: Vec<ReachedNode> = reached
            .into_iter()
            .map(|(id, depth)| ReachedNode { id, depth })
            .collect();
        reached_vec.sort_by(|x, y| (x.depth, &x.id).cmp(&(y.depth, &y.id)));
        Ok(Traversal {
            assertions: included.into_values().collect(),
            reached: reached_vec,
        })
    }

    /// Store counts, by state.
    pub fn stats(&mut self) -> Result<Stats, GraphError> {
        let all = self.store.assertions()?;
        let nodes = self.store.nodes()?;
        let mut by_state: BTreeMap<String, usize> = BTreeMap::new();
        for a in &all {
            let key = serde_json::to_value(a.state)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".to_string());
            *by_state.entry(key).or_insert(0) += 1;
        }
        Ok(Stats {
            assertions: all.len(),
            nodes: nodes.len(),
            by_state,
        })
    }
}

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
mod sqlite;

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub use sqlite::SqliteStore;

// ---------------------------------------------------------------------
// Organelle surface.  A stateful organelle: it owns one graph
// store over the in-memory backend.  Every op returns full
// assertions — the surface has no bare-fact projection either.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let term_schema = serde_json::json!({
        "description": "a node id string, or {\"node\": id}, or {\"literal\": value}",
    });
    let obj = |required: &[&str], props: Vec<(String, Value)>| {
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
        name: "graph-store".to_string(),
        codon: "gs".to_string(),
        version: "1.0.0".to_string(),
        description:
            "typed triple store with ternary state (proven/claimed/unknown), provenance, \
             and validity intervals on every assertion; point lookup, predicate scan, \
             one-hop and bounded traversal, temporal filtering; no query returns a bare \
             fact stripped of state or provenance"
                .to_string(),
        contracts: vec![
            Contract {
                op: "declare_node".to_string(),
                description: "declare_node {id, class, traits} -> the node declaration; class and traits use the typed-traits-v1 vocabulary".to_string(),
                input_schema: obj(&["id", "class"], vec![prop("id", "string"), prop("class", "string"), ("traits".to_string(), serde_json::json!({"type": "array", "items": {"type": "string"}}))]),
                mutation_class: write.clone(),
                required_capability: Some("graph.store".to_string()),
            },
            Contract {
                op: "assert".to_string(),
                description: "assert {subject, predicate, object, state, provenance, valid_from_ms?, valid_to_ms?} -> the stored assertion with its content-hash id; provenance is required and non-empty; re-asserting identical content is a replay".to_string(),
                input_schema: obj(&["subject", "predicate", "object", "state", "provenance"], vec![prop("subject", "string"), prop("predicate", "string"), ("object".to_string(), term_schema.clone()), ("state".to_string(), serde_json::json!({"enum": ["proven", "claimed", "unknown"]})), prop("provenance", "string"), prop("valid_from_ms", "integer"), prop("valid_to_ms", "integer")]),
                mutation_class: write.clone(),
                required_capability: Some("graph.store".to_string()),
            },
            Contract {
                op: "get".to_string(),
                description: "get {id} -> the assertion or null".to_string(),
                input_schema: obj(&["id"], vec![prop("id", "string")]),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "lookup".to_string(),
                description: "lookup {subject?, predicate?, object?, at_ms?} -> assertions matching every stated field (point lookup / predicate scan), each with state and provenance, sorted by id".to_string(),
                input_schema: obj(&[], vec![prop("subject", "string"), prop("predicate", "string"), ("object".to_string(), term_schema.clone()), prop("at_ms", "integer")]),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "neighbors".to_string(),
                description: "neighbors {node, direction?, at_ms?} -> one-hop assertions touching the node (direction out|in|both, default both)".to_string(),
                input_schema: obj(&["node"], vec![prop("node", "string"), ("direction".to_string(), serde_json::json!({"enum": ["out", "in", "both"]})), prop("at_ms", "integer")]),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "traverse".to_string(),
                description: "traverse {start, max_depth, direction?, at_ms?} -> {assertions, reached:[{id, depth}]}: bounded multi-hop traversal over node-to-node assertions; the depth bound is exact; every assertion carries state and provenance".to_string(),
                input_schema: obj(&["start", "max_depth"], vec![prop("start", "string"), prop("max_depth", "integer"), ("direction".to_string(), serde_json::json!({"enum": ["out", "in", "both"]})), prop("at_ms", "integer")]),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "stats".to_string(),
                description: "stats {} -> {assertions, nodes, by_state}: counts with the unknown mass as a number".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "list".to_string(),
                description: "list {} -> every assertion in the store, sorted by id".to_string(),
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
pub struct GraphStoreOrganelle {
    manifest: OrganelleManifest,
    inner: std::sync::Mutex<GraphStore<MemoryStore>>,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> std::sync::Arc<dyn Organelle> {
    std::sync::Arc::new(GraphStoreOrganelle {
        manifest: manifest(),
        inner: std::sync::Mutex::new(GraphStore::new(MemoryStore::new())),
    })
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
fn opt_i64(input: &Value, field: &str) -> Option<i64> {
    input[field].as_i64()
}

/// A term from surface JSON: a bare string is a node id;
/// `{"node": id}` is a node; `{"literal": v}` is a literal;
/// the Rust serde shape `{"kind": "node", "id": ...}` /
/// `{"kind": "literal", "value": ...}` is also accepted.
#[cfg(feature = "organelle")]
fn term_from_json(v: &Value) -> Result<Term, OrganelleError> {
    if let Some(s) = v.as_str() {
        return Ok(Term::node(s.to_string()));
    }
    if let Some(id) = v["node"].as_str() {
        return Ok(Term::node(id.to_string()));
    }
    if !v["literal"].is_null() {
        return Ok(Term::literal(v["literal"].clone()));
    }
    serde_json::from_value::<Term>(v.clone())
        .map_err(|e| OrganelleError::new("rejected", format!("term: {e}")))
}

#[cfg(feature = "organelle")]
fn direction_from_json(input: &Value) -> Result<Direction, OrganelleError> {
    match input["direction"].as_str() {
        None | Some("both") => Ok(Direction::Both),
        Some("out") => Ok(Direction::Out),
        Some("in") => Ok(Direction::In),
        Some(other) => rejected(format!("direction must be out|in|both, got {other}")),
    }
}

#[cfg(feature = "organelle")]
impl Organelle for GraphStoreOrganelle {
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
        let mut store = self.inner.lock().expect("organelle lock");
        let fail = |e: GraphError| match e {
            GraphError::Invalid(m) => OrganelleError::new("rejected", m),
            GraphError::Store(m) => OrganelleError::failed(m),
        };
        fn to_json<T: Serialize>(v: &T) -> Result<Value, OrganelleError> {
            serde_json::to_value(v)
                .map_err(|e| OrganelleError::failed(format!("serialize: {e}")))
        }
        match op {
            "declare_node" => {
                let id = req_str(&input, "id")?;
                let class = req_str(&input, "class")?;
                let traits: Vec<String> = serde_json::from_value(input["traits"].clone())
                    .unwrap_or_default();
                let node = store.declare_node(id, class, traits).map_err(fail)?;
                to_json(&node)
            }
            "assert" => {
                let subject = Term::node(req_str(&input, "subject")?);
                let predicate = req_str(&input, "predicate")?;
                let object = term_from_json(&input["object"])?;
                let state: State = serde_json::from_value(input["state"].clone()).map_err(|e| {
                    OrganelleError::new("rejected", format!("state: {e}"))
                })?;
                let provenance = req_str(&input, "provenance")?;
                let a = store
                    .assert(
                        subject,
                        predicate,
                        object,
                        state,
                        provenance,
                        opt_i64(&input, "valid_from_ms"),
                        opt_i64(&input, "valid_to_ms"),
                    )
                    .map_err(fail)?;
                to_json(&a)
            }
            "get" => {
                let id = req_str(&input, "id")?;
                match store.get(&id).map_err(fail)? {
                    Some(a) => to_json(&a),
                    None => Ok(Value::Null),
                }
            }
            "lookup" => {
                let mut q = Query::new();
                if let Some(s) = input["subject"].as_str() {
                    q.subject = Some(Term::node(s.to_string()));
                }
                if let Some(p) = input["predicate"].as_str() {
                    q.predicate = Some(p.to_string());
                }
                if !input["object"].is_null() {
                    q.object = Some(term_from_json(&input["object"])?);
                }
                q.at_ms = opt_i64(&input, "at_ms");
                let out = store.lookup(&q).map_err(fail)?;
                to_json(&out)
            }
            "neighbors" => {
                let node = req_str(&input, "node")?;
                let dir = direction_from_json(&input)?;
                let out = store
                    .neighbors(&node, dir, opt_i64(&input, "at_ms"))
                    .map_err(fail)?;
                to_json(&out)
            }
            "traverse" => {
                let start = req_str(&input, "start")?;
                let max_depth = match input["max_depth"].as_u64() {
                    Some(n) => n as u32,
                    None => return rejected("max_depth must be a non-negative integer"),
                };
                let dir = direction_from_json(&input)?;
                let out = store
                    .traverse(&start, max_depth, dir, opt_i64(&input, "at_ms"))
                    .map_err(fail)?;
                to_json(&out)
            }
            "stats" => {
                let s = store.stats().map_err(fail)?;
                to_json(&s)
            }
            "list" => {
                let out = store.list().map_err(fail)?;
                to_json(&out)
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The five required proofs: (a) ternary integrity — an
// Unknown assertion is returned AS unknown by every query shape;
// (b) temporal correctness; (c) traversal respects the caller's
// depth bound exactly; (d) provenance survives every query
// shape; (e) determinism — same store + same query =
// byte-identical result.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: &str) -> Term {
        Term::node(id.to_string())
    }

    /// The Harbour Green shape, straight from typed-traits.json:
    /// proven / claimed / unknown side by side.
    fn harbour_green() -> GraphStore<MemoryStore> {
        let mut g = GraphStore::new(MemoryStore::new());
        g.declare_node("harbour_green", "Place", vec!["Place".into()])
            .unwrap();
        g.declare_node("park_board", "Authority", vec!["Authority".into()])
            .unwrap();
        g.declare_node("cute_city", "Operator", vec!["Operator".into()])
            .unwrap();
        g.assert(
            n("harbour_green"),
            "contains",
            n("splash_pad"),
            State::Proven,
            "osm:way/12345",
            None,
            None,
        )
        .unwrap();
        g.assert(
            n("park_board"),
            "leases",
            n("restaurant_unit_1700sqft"),
            State::Claimed,
            "drive:00_COUNSEL_OVERVIEW_5490_ASH",
            None,
            None,
        )
        .unwrap();
        g.assert(
            n("park_board"),
            "permits",
            n("cute_city"),
            State::Unknown,
            "workflow:osint-location-acquisition step-4",
            None,
            None,
        )
        .unwrap();
        g.assert(
            n("fry"),
            "endorses",
            n("cute_city"),
            State::Unknown,
            "workflow:osint-location-acquisition step-7",
            None,
            None,
        )
        .unwrap();
        g
    }

    // (a) Ternary integrity: the Unknown assertions come back AS
    // unknown from every query shape — point, predicate scan,
    // filtered lookup, neighbors, traversal, list — never
    // dropped, never promoted.
    #[test]
    fn unknown_stays_unknown_in_every_query_shape() {
        let mut g = harbour_green();

        // Point lookup.
        let hits = g
            .point(&n("park_board"), "permits", &n("cute_city"), None)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].state, State::Unknown);

        // Predicate scan.
        let hits = g.by_predicate("endorses", None).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].state, State::Unknown);

        // Filtered lookup (subject only).
        let hits = g
            .lookup(&Query::new().subject(n("park_board")))
            .unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|a| a.state == State::Unknown));
        assert!(hits.iter().any(|a| a.state == State::Claimed));

        // Neighbors.
        let hits = g.neighbors("cute_city", Direction::In, None).unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|a| a.state == State::Unknown));

        // Traversal: unknown edges are traversed and reported
        // as unknown — the traversal does not pretend they are
        // proven, and does not refuse to walk them.
        let t = g.traverse("park_board", 1, Direction::Out, None).unwrap();
        assert_eq!(t.assertions.len(), 2);
        assert!(t.assertions.iter().any(|a| a.state == State::Unknown));

        // List.
        let all = g.list().unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(
            all.iter().filter(|a| a.state == State::Unknown).count(),
            2
        );

        // Stats count the unknown mass as a number.
        let stats = g.stats().unwrap();
        assert_eq!(stats.by_state.get("unknown"), Some(&2));
        assert_eq!(stats.by_state.get("proven"), Some(&1));
        assert_eq!(stats.by_state.get("claimed"), Some(&1));
    }

    // (b) Temporal correctness: [100, 200) — outside excluded,
    // inside included, bounds exact.
    #[test]
    fn temporal_filtering_bounds_are_exact() {
        let mut g = GraphStore::new(MemoryStore::new());
        g.assert(
            n("lease_a"),
            "binds",
            n("operator_a"),
            State::Proven,
            "doc:lease-a",
            Some(100),
            Some(200),
        )
        .unwrap();
        // An unbounded assertion alongside.
        g.assert(
            n("lease_a"),
            "binds",
            n("operator_b"),
            State::Claimed,
            "doc:lease-b",
            None,
            None,
        )
        .unwrap();

        let mut at = |t: i64| {
            g.lookup(&Query::new().predicate("binds").at(t))
                .unwrap()
                .len()
        };
        assert_eq!(at(50), 1); // bounded one not yet valid
        assert_eq!(at(99), 1);
        assert_eq!(at(100), 2); // valid_from inclusive
        assert_eq!(at(199), 2);
        assert_eq!(at(200), 1); // valid_to exclusive
        assert_eq!(at(10_000), 1);

        // No temporal filter: everything as asserted.
        assert_eq!(g.by_predicate("binds", None).unwrap().len(), 2);
        // Temporal filter applies to traversal too.
        let t = g.traverse("lease_a", 1, Direction::Out, Some(50)).unwrap();
        assert_eq!(t.assertions.len(), 1);
        let t = g.traverse("lease_a", 1, Direction::Out, Some(150)).unwrap();
        assert_eq!(t.assertions.len(), 2);
    }

    // (c) Traversal depth is exact: a chain A→B→C→D plus a
    // cycle D→B.  Depth 0/1/2/3 return exactly the hops stated;
    // the cycle terminates and B keeps its shallowest depth.
    #[test]
    fn traversal_depth_bound_is_exact() {
        let mut g = GraphStore::new(MemoryStore::new());
        for (s, o) in [("a", "b"), ("b", "c"), ("c", "d"), ("d", "b")] {
            g.assert(n(s), "touches", n(o), State::Claimed, "test:chain", None, None)
                .unwrap();
        }
        let t0 = g.traverse("a", 0, Direction::Out, None).unwrap();
        assert_eq!(t0.assertions.len(), 0);
        assert_eq!(t0.reached, vec![ReachedNode { id: "a".into(), depth: 0 }]);

        let t1 = g.traverse("a", 1, Direction::Out, None).unwrap();
        assert_eq!(t1.assertions.len(), 1);
        assert_eq!(t1.reached.len(), 2);

        let t2 = g.traverse("a", 2, Direction::Out, None).unwrap();
        assert_eq!(t2.assertions.len(), 2);
        assert_eq!(t2.reached.len(), 3);

        let t3 = g.traverse("a", 3, Direction::Out, None).unwrap();
        assert_eq!(t3.assertions.len(), 3);
        assert_eq!(t3.reached.len(), 4);
        // b was reached at depth 1 and stays there, despite the
        // d→b cycle edge at depth 3 also being included.
        assert_eq!(
            t3.reached.iter().find(|r| r.id == "b").unwrap().depth,
            1
        );

        // Depth beyond the graph's diameter changes nothing.
        let t9 = g.traverse("a", 9, Direction::Out, None).unwrap();
        assert_eq!(t9.assertions.len(), 4);
        assert_eq!(t9.reached.len(), 4);

        // In-direction: from d, depth 1 reaches c only.
        let ti = g.traverse("d", 1, Direction::In, None).unwrap();
        assert_eq!(ti.assertions.len(), 1);
        assert_eq!(ti.reached.len(), 2);
    }

    // (d) Provenance survives every query shape — checked on the
    // serialized form: every element of every result carries a
    // non-empty "provenance" and a "state".  This is the API's
    // hard rule, tested at the wire shape consumers see.
    #[test]
    fn provenance_and_state_survive_every_query_shape() {
        let mut g = harbour_green();
        let shapes: Vec<Value> = vec![
            serde_json::to_value(g.point(&n("park_board"), "permits", &n("cute_city"), None).unwrap()).unwrap(),
            serde_json::to_value(g.by_predicate("contains", None).unwrap()).unwrap(),
            serde_json::to_value(g.lookup(&Query::new().subject(n("park_board"))).unwrap()).unwrap(),
            serde_json::to_value(g.neighbors("cute_city", Direction::Both, None).unwrap()).unwrap(),
            serde_json::to_value(g.traverse("park_board", 2, Direction::Both, None).unwrap().assertions).unwrap(),
            serde_json::to_value(g.list().unwrap()).unwrap(),
        ];
        for shape in &shapes {
            let arr = shape.as_array().expect("query results are arrays");
            assert!(!arr.is_empty());
            for el in arr {
                assert_eq!(el["provenance"].as_str().map(str::is_empty), Some(false),
                    "every assertion carries a non-empty provenance: {el}");
                assert!(el["state"].is_string(), "every assertion carries its state: {el}");
            }
        }
    }

    // (e) Determinism: same content, different insertion order,
    // same queries → byte-identical serialized results.  (Ids
    // are content hashes and results are id-sorted, so insertion
    // order cannot leak into output.)
    #[test]
    fn determinism_byte_identical() {
        let facts: Vec<(Term, &str, Term, State, &str)> = vec![
            (n("harbour_green"), "contains", n("splash_pad"), State::Proven, "osm:1"),
            (n("park_board"), "leases", n("unit"), State::Claimed, "doc:2"),
            (n("park_board"), "permits", n("cute_city"), State::Unknown, "doc:3"),
            (n("cute_city"), "touches", n("harbour_green"), State::Claimed, "doc:4"),
            (n("cute_city"), "operates", n("tricycle_base"), State::Claimed, "doc:5"),
        ];
        let build = |order: &[usize]| {
            let mut g = GraphStore::new(MemoryStore::new());
            for &i in order {
                let (s, p, o, st, prov) = &facts[i];
                g.assert(s.clone(), *p, o.clone(), *st, *prov, None, None)
                    .unwrap();
            }
            g
        };
        let mut g1 = build(&[0, 1, 2, 3, 4]);
        let mut g2 = build(&[4, 2, 0, 3, 1]);
        let run = |g: &mut GraphStore<MemoryStore>| -> Vec<String> {
            vec![
                serde_json::to_string(&g.list().unwrap()).unwrap(),
                serde_json::to_string(&g.by_predicate("leases", None).unwrap()).unwrap(),
                serde_json::to_string(&g.lookup(&Query::new().subject(n("park_board"))).unwrap()).unwrap(),
                serde_json::to_string(&g.neighbors("cute_city", Direction::Both, None).unwrap()).unwrap(),
                serde_json::to_string(&g.traverse("park_board", 3, Direction::Both, None).unwrap()).unwrap(),
                serde_json::to_string(&g.stats().unwrap()).unwrap(),
            ]
        };
        assert_eq!(run(&mut g1), run(&mut g2));
        // And the same store queried twice is trivially stable.
        assert_eq!(run(&mut g1), run(&mut g1));
    }

    // Structural rules: no provenance, no entry; a literal
    // cannot be a subject; an empty interval is refused; a
    // tampered id is refused.
    #[test]
    fn structural_rules_fail_closed() {
        let mut g = GraphStore::new(MemoryStore::new());
        assert!(g
            .assert(n("a"), "touches", n("b"), State::Claimed, "  ", None, None)
            .is_err());
        assert!(g
            .assert(
                Term::literal(serde_json::json!(3)),
                "touches",
                n("b"),
                State::Claimed,
                "src",
                None,
                None
            )
            .is_err());
        assert!(g
            .assert(n("a"), "touches", n("b"), State::Claimed, "src", Some(200), Some(200))
            .is_err());
        // Replay of identical content returns the same record
        // and stores nothing new.
        let a1 = g
            .assert(n("a"), "touches", n("b"), State::Claimed, "src", None, None)
            .unwrap();
        let a2 = g
            .assert(n("a"), "touches", n("b"), State::Claimed, "src", None, None)
            .unwrap();
        assert_eq!(a1.id, a2.id);
        assert_eq!(g.list().unwrap().len(), 1);
        // Same triple, different state = a different assertion;
        // both are kept, neither overwrites the other.
        g.assert(n("a"), "touches", n("b"), State::Unknown, "src", None, None)
            .unwrap();
        assert_eq!(g.list().unwrap().len(), 2);
        // A forged id is refused.
        let mut forged = a1.clone();
        forged.id = "0".repeat(64);
        assert!(g.assert_raw(forged).is_err());
    }

    // The id rule: sha256 of canonical content — stable across
    // constructions, and thing_id follows typed-traits-v1.
    #[test]
    fn ids_are_content_hashes() {
        let a = Assertion::new(n("x"), "funds", n("y"), State::Unknown, "p", None, None).unwrap();
        let b = Assertion::new(n("x"), "funds", n("y"), State::Unknown, "p", None, None).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.id.len(), 64);
        let thing = serde_json::json!({"id": "cute_city", "type": "Operator"});
        assert_eq!(thing_id(&thing), thing_id(&thing.clone()));
    }

    #[cfg(feature = "organelle")]
    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }

    // The organelle surface keeps the same guarantees: an
    // Unknown assertion asserted and read back through handle()
    // is still Unknown, provenance attached.
    #[cfg(feature = "organelle")]
    #[test]
    fn organelle_surface_keeps_ternary_state() {
        use organelle_host::{CallContext, Host};
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["graph.store".to_string()]);
        let call = |op: &str, input: Value| h.call(&ctx, "gs", op, input).unwrap().output;
        let out = call(
            "assert",
            serde_json::json!({
                "subject": "park_board",
                "predicate": "permits",
                "object": {"node": "cute_city"},
                "state": "unknown",
                "provenance": "workflow:step-4",
            }),
        );
        assert_eq!(out["state"], "unknown");
        assert_eq!(out["provenance"], "workflow:step-4");
        let hits = call("lookup", serde_json::json!({"predicate": "permits"}));
        assert_eq!(hits.as_array().unwrap().len(), 1);
        assert_eq!(hits[0]["state"], "unknown");
        // Missing provenance is rejected at the surface too.
        assert!(h
            .call(
                &ctx,
                "gs",
                "assert",
                serde_json::json!({
                    "subject": "a", "predicate": "touches",
                    "object": "b", "state": "proven",
                }),
            )
            .is_err());
    }

    // Cross-backend determinism: the SQLite backend answers the
    // same queries byte-identically to the memory backend.
    #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
    #[test]
    fn sqlite_backend_matches_memory_backend() {
        let mut mem = harbour_green();
        let mut sql = GraphStore::new(SqliteStore::in_memory().unwrap());
        for a in mem.list().unwrap() {
            sql.assert_raw(a).unwrap();
        }
        for node in mem.nodes().unwrap() {
            sql.declare_node(node.id, node.class, node.traits).unwrap();
        }
        let run = |g: &mut GraphStore<MemoryStore>| -> Vec<String> {
            vec![
                serde_json::to_string(&g.list().unwrap()).unwrap(),
                serde_json::to_string(&g.traverse("park_board", 2, Direction::Both, None).unwrap()).unwrap(),
                serde_json::to_string(&g.stats().unwrap()).unwrap(),
            ]
        };
        let sql_run = {
            let mut out = Vec::new();
            out.push(serde_json::to_string(&sql.list().unwrap()).unwrap());
            out.push(serde_json::to_string(&sql.traverse("park_board", 2, Direction::Both, None).unwrap()).unwrap());
            out.push(serde_json::to_string(&sql.stats().unwrap()).unwrap());
            out
        };
        assert_eq!(run(&mut mem), sql_run);
    }
}
