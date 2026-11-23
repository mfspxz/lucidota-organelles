//! GO-50 Runtime Ontology Organelle — 50 core terms, 25 ObjectTypes, 25 ClientFunctions.
//!
//! ## GO-50 Terms (50 federation-wide interfaces)
//! Bootstrap terms with full definitions, type taxonomy, ternary valency defaults,
//! and parent hierarchies. Queryable via `OntologyStore` trait.
//!
//! ## O-25 Object-Types (domain packs) — UNIMPLEMENTED
//! Domain-specific ornament YAML packs (aerospace, automotive, etc.).
//!
//! ## C-25 Client Functions — UNIMPLEMENTED
//! Bespoke FSTs per client (LUCIDOTA, PALANTOUR, FlashLLM, cl0wnCar69).

use std::collections::HashMap;

// ── Ternary Valence ──────────────────────────────────────────────────────
// The canonical ternary type for crate convergence. Scattered enums
// (pt-oracle::Valence, pt-organelle-core::Valence, pt-council::Valency,
//  pt-percyphon::SlotValence) should converge onto this single type
//  via go-ontology re-exports.

/// Canonical ternary epistemic valence: -1 (Disproven/Tainted), 0 (Candidate/Unknown), +1 (Proven).
/// This is the single source of truth for ternary state across PALANTOUR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(i8)]
pub enum TernaryValence {
    /// -1: Disproven / Tainted — reduced confidence.
    Tainted = -1,
    /// 0: Candidate / Unknown — unverified.
    Candidate = 0,
    /// +1: Proven — verified against external source.
    Proven = 1,
}

impl TernaryValence {
    pub fn as_int(self) -> i8 {
        self as i8
    }

    pub fn from_int(v: i8) -> Self {
        match v {
            -1 => Self::Tainted,
            1 => Self::Proven,
            _ => Self::Candidate,
        }
    }

    /// For clarity in ternary logic: the three states as their canonical names.
    pub const PROVEN: i8 = 1;
    pub const CANDIDATE: i8 = 0;
    pub const TAINTED: i8 = -1;
}

// ── Core Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OntologyTerm {
    pub term: String,
    pub definition: String,
    /// Parent terms (hierarchy). Empty for root terms.
    pub parents: Vec<String>,
    pub term_type: TermType,
    /// Default ternary valence: -1 (Tainted), 0 (Candidate), or +1 (Proven).
    pub default_valence: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TermType {
    /// Discrete, identifiable things — 14 terms
    Object,
    /// State transitions in hypertime — 2 terms
    Event,
    /// Directed, valence-weighted relationships — 1 term
    Edge,
    /// Capability exposed through contract — 10 terms (incl MAMBA)
    Tool,
    /// Operational modality — 12 terms
    Mode,
    /// Hypertimeline dimension — 2 terms
    Time,
    /// Autonomous executor with bounded authority — 6 terms
    Agent,
    /// Deployment surface composing organelles — 3 terms
    Shell,
}

// ── Trait ────────────────────────────────────────────────────────────────

pub trait OntologyStore {
    fn resolve(&self, term: &str) -> Option<&OntologyTerm>;
    fn by_type(&self, term_type: TermType) -> Vec<&OntologyTerm>;
    fn children(&self, parent: &str) -> Vec<&OntologyTerm>;
    fn is_a(&self, child: &str, parent: &str) -> bool;
    fn all_terms(&self) -> Vec<&OntologyTerm>;
}

// ── InMemoryOntology ─────────────────────────────────────────────────────

pub struct InMemoryOntology {
    terms: HashMap<String, OntologyTerm>,
}

impl InMemoryOntology {
    pub fn new() -> Self {
        Self {
            terms: HashMap::new(),
        }
    }

    pub fn load_from_json(json_bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let raw: Vec<OntologyTerm> = serde_json::from_slice(json_bytes)?;
        let mut o = Self::new();
        for t in raw {
            o.terms.insert(t.term.clone(), t);
        }
        Ok(o)
    }

    /// Bootstrap all 50 core terms with proper valency defaults and parent hierarchies.
    ///
    /// Valency assignment rationale:
    /// - +1 (Proven): terms whose existence IS proof (RECEIPT, ATTESTATION, CAS, LEDGER, etc.)
    /// - -1 (Tainted): terms encoding untrusted/rejected material (VOID, REFUTATION, TRUFFLEPIG)
    /// - 0 (Candidate): everything else — neutral until receipt-backed
    pub fn bootstrap_core() -> Self {
        // ── Root terms ────────────────────────────────────────────────
        // These have no parents; they define the eight type axes.
        let roots: Vec<OntologyTerm> = vec![
            OntologyTerm {
                term: "OBJECT".into(),
                definition: "A discrete, identifiable thing with a CAS identity.".into(),
                parents: vec![],
                term_type: TermType::Object,
                default_valence: 0,
            },
            OntologyTerm {
                term: "EVENT".into(),
                definition: "A state transition recorded in hypertime with a receipt.".into(),
                parents: vec![],
                term_type: TermType::Event,
                default_valence: 0,
            },
            OntologyTerm {
                term: "EDGE".into(),
                definition: "A directed, valence-weighted relationship between two terms in the hypergraph.".into(),
                parents: vec![],
                term_type: TermType::Edge,
                default_valence: 0,
            },
            OntologyTerm {
                term: "TIME".into(),
                definition: "The hypertimeline dimension — a total ordering of events.".into(),
                parents: vec![],
                term_type: TermType::Time,
                default_valence: 0,
            },
            OntologyTerm {
                term: "TOOL".into(),
                definition: "A capability exposed through a contract boundary, hostable by any shell.".into(),
                parents: vec![],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "MODE".into(),
                definition: "An operational modality governing how agents, tools, and pipelines behave.".into(),
                parents: vec![],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "AGENT".into(),
                definition: "An autonomous executor with bounded authority, operating under receipts.".into(),
                parents: vec![],
                term_type: TermType::Agent,
                default_valence: 0,
            },
            OntologyTerm {
                term: "SHELL".into(),
                definition: "A deployment surface composing organelles into a runnable system.".into(),
                parents: vec![],
                term_type: TermType::Shell,
                default_valence: 0,
            },
        ];

        // ── OBJECT children (13 terms) ────────────────────────────────
        let objects: Vec<OntologyTerm> = vec![
            OntologyTerm {
                term: "RECEIPT".into(),
                definition: "A signed, hash-linked action record that proves work happened.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 1, // Proven: a receipt IS proof
            },
            OntologyTerm {
                term: "GATE".into(),
                definition: "An authority checkpoint that validates valence transitions between stages.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 0,
            },
            OntologyTerm {
                term: "GRAPH".into(),
                definition: "The canonical hypergraph with ternary-valence edges connecting all terms.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 0,
            },
            OntologyTerm {
                term: "CAS".into(),
                definition: "Content-Addressed Storage: every blob is its own hash, immutable and verifiable.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 1, // Proven: hash = proof of content
            },
            OntologyTerm {
                term: "QUEUE".into(),
                definition: "A durable, ordered work pipeline with priority weighting and dedup.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 0,
            },
            OntologyTerm {
                term: "ORGANELLE".into(),
                definition: "A single-purpose capability crate implementing the ToolOrganelle contract.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 0,
            },
            OntologyTerm {
                term: "CONTRACT".into(),
                definition: "A trait boundary between organelles, enforced by the type system.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 0,
            },
            OntologyTerm {
                term: "VOID".into(),
                definition: "A sealed tier, type-level inaccessible — data that cannot be read or promoted.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: -1, // Tainted: sealed = inaccessible
            },
            OntologyTerm {
                term: "LEDGER".into(),
                definition: "A signed transparency log providing an append-only audit trail.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 1, // Proven: transparency log is self-proving
            },
            OntologyTerm {
                term: "REFUTATION".into(),
                definition: "A signed certificate of a false claim — proves something is NOT true.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: -1, // Tainted: refutation encodes falsehood
            },
            OntologyTerm {
                term: "ATTESTATION".into(),
                definition: "An Ed25519-signed cryptographic proof binding a claim to an identity.".into(),
                parents: vec!["OBJECT".into()],
                term_type: TermType::Object,
                default_valence: 1, // Proven: a valid signature proves provenance
            },
            OntologyTerm {
                term: "SNOWBALL".into(),
                definition: "A priority queue with decay weighting — tasks lose priority over time unless promoted.".into(),
                parents: vec!["QUEUE".into()],
                term_type: TermType::Object,
                default_valence: 0,
            },
            OntologyTerm {
                term: "CHRONO_LEDGER".into(),
                definition: "A timestamped receipt ledger binding every record to hypertime.".into(),
                parents: vec!["LEDGER".into()],
                term_type: TermType::Object,
                default_valence: 1, // Proven: inherits from LEDGER
            },
        ];

        // ── EVENT children (1 term) ───────────────────────────────────
        let events: Vec<OntologyTerm> = vec![
            OntologyTerm {
                term: "WELD".into(),
                definition: "A feature-flag fusion point: compile-time composition of organelles into a shell at ship time.".into(),
                parents: vec!["EVENT".into()],
                term_type: TermType::Event,
                default_valence: 0,
            },
        ];

        // ── TIME children (1 term) ────────────────────────────────────
        let times: Vec<OntologyTerm> = vec![
            OntologyTerm {
                term: "HYPERTIME".into(),
                definition: "The total ordering dimension across all receipts — the canonical clock.".into(),
                parents: vec!["TIME".into()],
                term_type: TermType::Time,
                default_valence: 0,
            },
        ];

        // ── TOOL children (9 terms + MAMBA) ───────────────────────────
        let tools: Vec<OntologyTerm> = vec![
            OntologyTerm {
                term: "ORACLE".into(),
                definition: "A verification gate that evaluates claims against receipt evidence and promotes/demotes valence.".into(),
                parents: vec!["TOOL".into(), "GATE".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "RIVER".into(),
                definition: "Online machine learning via Hoeffding trees — continuous model adaptation from streaming data.".into(),
                parents: vec!["TOOL".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "DSPY".into(),
                definition: "A prompt compiler that evolves through execution feedback — self-optimizing LLM pipelines.".into(),
                parents: vec!["TOOL".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "BONSAI".into(),
                definition: "A ternary-aware 8B local model for on-device inference with epistemic state tracking.".into(),
                parents: vec!["TOOL".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "RESONANCE".into(),
                definition: "An evolutionary spectral engine — frequency-domain analysis for pattern detection.".into(),
                parents: vec!["TOOL".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "GHOST".into(),
                definition: "A credential provider — mints, manages, and burns anonymous burner credentials.".into(),
                parents: vec!["TOOL".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "TREELITE".into(),
                definition: "A lightweight decision tree runtime for fast classification at the edge.".into(),
                parents: vec!["TOOL".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "TRIPARTOKEN".into(),
                definition: "A three-lane tokenization system: FASTLANE tokens, SLOWLANE tokens, DEEPLANE research tokens.".into(),
                parents: vec!["TOOL".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
            OntologyTerm {
                term: "MAMBA".into(),
                definition: "A state-space model for efficient sequence modeling — linear-time inference.".into(),
                parents: vec!["TOOL".into()],
                term_type: TermType::Tool,
                default_valence: 0,
            },
        ];

        // ── MODE children (11 terms) ──────────────────────────────────
        let modes: Vec<OntologyTerm> = vec![
            OntologyTerm {
                term: "TERNARY".into(),
                definition: "Three-state epistemic logic: Proven (+1), Candidate (0), Tainted (-1). No booleans for epistemic state.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0, // Mode itself is neutral; the governed states carry the valences
            },
            OntologyTerm {
                term: "ABSURD".into(),
                definition: "Adaptive Bounded Scheduling with Unexpected Resource Dynamics — a self-tuning DAG executor.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "GAUNTLET".into(),
                definition: "An evolutionary survival pipeline — candidates compete, only the fittest survive to Proven.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "FORGE".into(),
                definition: "A deterministic attempt engine — retries with exponential backoff, receipts every attempt.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "COUNCIL".into(),
                definition: "An N-voter ensemble for audits — multiple models/agents vote, verdict by quorum.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "TICKLETRUNK".into(),
                definition: "Archive and provenance discipline — deterministic packaging with full audit chain.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "VENTURI".into(),
                definition: "A compression pipeline on the fast path — data flows through narrowing stages.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "NEEDLES".into(),
                definition: "A multi-lane reflex system — parallel execution paths with different latency budgets.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "FASTLANE".into(),
                definition: "The high-priority, low-latency execution path — critical tasks only.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "SLOWLANE".into(),
                definition: "The batch-oriented, high-throughput execution path — bulk processing.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
            OntologyTerm {
                term: "DEEPLANE".into(),
                definition: "The research and exploration path — experimental, no latency SLA.".into(),
                parents: vec!["MODE".into()],
                term_type: TermType::Mode,
                default_valence: 0,
            },
        ];

        // ── AGENT children (5 terms) ──────────────────────────────────
        let agents: Vec<OntologyTerm> = vec![
            OntologyTerm {
                term: "MNEME".into(),
                definition: "A metacognitive agent that learns from failures — self-correcting through memory of past errors.".into(),
                parents: vec!["AGENT".into()],
                term_type: TermType::Agent,
                default_valence: 0,
            },
            OntologyTerm {
                term: "INDY_READS".into(),
                definition: "An inotify-based reading watcher — monitors filesystem events and dispatches to pipelines.".into(),
                parents: vec!["AGENT".into()],
                term_type: TermType::Agent,
                default_valence: 0,
            },
            OntologyTerm {
                term: "OUROBOROS".into(),
                definition: "A self-chaining forge daemon — continuously feeds its own outputs back as inputs.".into(),
                parents: vec!["AGENT".into()],
                term_type: TermType::Agent,
                default_valence: 0,
            },
            OntologyTerm {
                term: "KRAMPUS".into(),
                definition: "A trust scoring agent with recency-weighted edges — punishes naughty, rewards nice.".into(),
                parents: vec!["AGENT".into()],
                term_type: TermType::Agent,
                default_valence: 0,
            },
            OntologyTerm {
                term: "TRUFFLEPIG".into(),
                definition: "A data harvesting pipeline agent — ingests untrusted external data, tags everything Tainted by default.".into(),
                parents: vec!["AGENT".into()],
                term_type: TermType::Agent,
                default_valence: -1, // Tainted: harvested data is untrusted
            },
        ];

        // ── SHELL children (2 terms) ──────────────────────────────────
        let shells: Vec<OntologyTerm> = vec![
            OntologyTerm {
                term: "IRONCLAW".into(),
                definition: "A local-model exocortex runtime — runs BONSAI and other on-device models with minimal overhead.".into(),
                parents: vec!["SHELL".into()],
                term_type: TermType::Shell,
                default_valence: 0,
            },
            OntologyTerm {
                term: "PERCYPHON".into(),
                definition: "A session-aware MCP server shell — hosts organelles behind a persona-aware membrane.".into(),
                parents: vec!["SHELL".into()],
                term_type: TermType::Shell,
                default_valence: 0,
            },
        ];

        let mut o = Self::new();

        // Insert roots first so parent resolution works
        for t in roots {
            o.terms.insert(t.term.clone(), t);
        }
        for t in objects {
            o.terms.insert(t.term.clone(), t);
        }
        for t in events {
            o.terms.insert(t.term.clone(), t);
        }
        for t in times {
            o.terms.insert(t.term.clone(), t);
        }
        for t in tools {
            o.terms.insert(t.term.clone(), t);
        }
        for t in modes {
            o.terms.insert(t.term.clone(), t);
        }
        for t in agents {
            o.terms.insert(t.term.clone(), t);
        }
        for t in shells {
            o.terms.insert(t.term.clone(), t);
        }

        o
    }
}

impl Default for InMemoryOntology {
    fn default() -> Self {
        Self::bootstrap_core()
    }
}

impl OntologyStore for InMemoryOntology {
    fn resolve(&self, term: &str) -> Option<&OntologyTerm> {
        self.terms.get(term)
    }

    fn by_type(&self, tt: TermType) -> Vec<&OntologyTerm> {
        self.terms
            .values()
            .filter(|t| t.term_type == tt)
            .collect()
    }

    fn children(&self, parent: &str) -> Vec<&OntologyTerm> {
        self.terms
            .values()
            .filter(|t| t.parents.contains(&parent.to_string()))
            .collect()
    }

    fn is_a(&self, child: &str, parent: &str) -> bool {
        let mut stack = vec![child.to_string()];
        let mut seen = std::collections::HashSet::new();
        while let Some(cur) = stack.pop() {
            if cur == parent {
                return true;
            }
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(t) = self.terms.get(&cur) {
                for p in &t.parents {
                    stack.push(p.clone());
                }
            }
        }
        false
    }

    fn all_terms(&self) -> Vec<&OntologyTerm> {
        self.terms.values().collect()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_50() {
        let o = InMemoryOntology::bootstrap_core();
        assert_eq!(o.all_terms().len(), 50, "must have exactly 50 bootstrapped terms");
    }

    #[test]
    fn resolve_ternary() {
        let o = InMemoryOntology::bootstrap_core();
        let t = o.resolve("TERNARY").expect("TERNARY must exist");
        assert!(t.definition.contains("Proven"));
        assert_eq!(t.term_type, TermType::Mode);
        assert_eq!(t.default_valence, 0, "TERNARY mode is neutral");
    }

    #[test]
    fn by_type_agents() {
        let ontology = InMemoryOntology::bootstrap_core();
        let agents = ontology.by_type(TermType::Agent);
        assert!(agents.iter().any(|t| t.term == "MNEME"));
        assert!(agents.iter().any(|t| t.term == "TRUFFLEPIG"));
        assert!(agents.iter().any(|t| t.term == "KRAMPUS"));
    }

    #[test]
    fn unknown_none() {
        assert!(InMemoryOntology::bootstrap_core().resolve("NOPE").is_none());
    }

    #[test]
    fn all_valence_in_range() {
        for t in InMemoryOntology::bootstrap_core().all_terms() {
            assert!(!t.definition.is_empty());
            assert!(
                t.default_valence >= -1 && t.default_valence <= 1,
                "term {} has valence {} outside [-1,1]",
                t.term,
                t.default_valence
            );
        }
    }

    #[test]
    fn proven_terms() {
        let o = InMemoryOntology::bootstrap_core();
        // Terms whose existence IS proof
        assert_eq!(o.resolve("RECEIPT").unwrap().default_valence, 1);
        assert_eq!(o.resolve("ATTESTATION").unwrap().default_valence, 1);
        assert_eq!(o.resolve("CAS").unwrap().default_valence, 1);
        assert_eq!(o.resolve("LEDGER").unwrap().default_valence, 1);
        assert_eq!(o.resolve("CHRONO_LEDGER").unwrap().default_valence, 1);
    }

    #[test]
    fn tainted_terms() {
        let o = InMemoryOntology::bootstrap_core();
        // Terms that encode untrusted/rejected material
        assert_eq!(o.resolve("VOID").unwrap().default_valence, -1);
        assert_eq!(o.resolve("REFUTATION").unwrap().default_valence, -1);
        assert_eq!(o.resolve("TRUFFLEPIG").unwrap().default_valence, -1);
    }

    #[test]
    fn hierarchy_is_a() {
        let o = InMemoryOntology::bootstrap_core();
        assert!(o.is_a("RECEIPT", "OBJECT"), "RECEIPT is-a OBJECT");
        assert!(o.is_a("SNOWBALL", "QUEUE"), "SNOWBALL is-a QUEUE");
        assert!(o.is_a("CHRONO_LEDGER", "LEDGER"), "CHRONO_LEDGER is-a LEDGER");
        assert!(o.is_a("PERCYPHON", "SHELL"), "PERCYPHON is-a SHELL");
        assert!(o.is_a("ORACLE", "TOOL"), "ORACLE is-a TOOL");
        assert!(o.is_a("ORACLE", "GATE"), "ORACLE is-a GATE");
        assert!(o.is_a("TERNARY", "MODE"), "TERNARY is-a MODE");
    }

    #[test]
    fn parent_children_symmetric() {
        let o = InMemoryOntology::bootstrap_core();
        let object_children = o.children("OBJECT");
        // OBJECT should have many children
        assert!(object_children.len() >= 11, "OBJECT must have 11+ children, got {}", object_children.len());
        assert!(object_children.iter().any(|t| t.term == "RECEIPT"));
        assert!(object_children.iter().any(|t| t.term == "QUEUE"));
    }

    #[test]
    fn ternary_valence_roundtrip() {
        assert_eq!(TernaryValence::Proven.as_int(), 1);
        assert_eq!(TernaryValence::Candidate.as_int(), 0);
        assert_eq!(TernaryValence::Tainted.as_int(), -1);
        assert_eq!(TernaryValence::from_int(1), TernaryValence::Proven);
        assert_eq!(TernaryValence::from_int(0), TernaryValence::Candidate);
        assert_eq!(TernaryValence::from_int(-1), TernaryValence::Tainted);
        assert_eq!(TernaryValence::from_int(99), TernaryValence::Candidate, "out of range → Candidate");
    }

    #[test]
    fn term_count_by_type() {
        let o = InMemoryOntology::bootstrap_core();
        // Rough counts: roots (8) + children by type
        let objects = o.by_type(TermType::Object).len();
        let agents = o.by_type(TermType::Agent).len();
        let modes = o.by_type(TermType::Mode).len();
        let tools = o.by_type(TermType::Tool).len();
        assert!(objects >= 14, "OBJECT terms: {}", objects);
        assert!(agents >= 6, "AGENT terms: {}", agents);
        assert!(modes >= 12, "MODE terms: {}", modes);
        assert!(tools >= 10, "TOOL terms: {}", tools);
    }
}
