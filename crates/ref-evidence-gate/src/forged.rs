//! pt-forged — Rust organelles forged from raw scripts via the forge pipeline.
//!
//! Every module here has PROVENANCE: it was a Python script in `scripts/`, judged
//! worth-incorporating by Leanstral, validated by the orchestrator, ported to Rust,
//! and ledgered with a PoUW token on pt-ledger. The module doc records the chain.

pub mod evidence_gate;

pub use evidence_gate::{classify_claim, classify_status, gate, ClaimClass, GateVerdict, StatusClass};
