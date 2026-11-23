//! evidence_gate — claim-classification authority gate. FORGED FROM A SCRIPT.
//!
//! ## Provenance (the forge chain)
//! - **source:** `scripts/status_ledger_evidence_gate.py` (308 loc, mutation_class: authority_gate)
//! - **Leanstral verdict:** PASS — "well-defined policy engine: classify claim scope
//!   via regex, check schema membership, validate status transitions, produce a
//!   structured verdict with blockers... reusable as a crate returning
//!   `Result<GateVerdict, Vec<Blocker>>`."
//! - **orchestrator decision:** VALIDATED (highest-value candidate; it feeds THE ORACLE)
//! - **PoUW grade:** Ledgered — a token is minted on pt-ledger for this port.
//!
//! ## What it does (the reusable concept, not the Python glue)
//! An anti-overclaim gate: a status claim is classified as a BROAD MYTH ("whole /
//! complete / 100% / production ready") vs a SCOPED-OK claim (names a specific
//! bounded surface). Broad myths without scope are blocked. A status string is
//! classified PASS / PARTIAL / UPGRADE / UNKNOWN. The verdict is structured and
//! serde-round-trippable — THE ORACLE consumes it. Pure logic, no I/O.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Broad, unfalsifiable "myth" language — the overclaim smell.
fn broad_myth_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(whole|entire|all\s+of|complete|completed|finished|100%|production\s+ready|system\s+complete|crowned\s+whole)\b").unwrap()
    })
}

/// Scoped, bounded claim language — names a specific surface, so it's checkable.
fn scoped_ok_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(golden path|single[- ]instruction|no[- ]materialization|regression gate|same[- ]lineage|canonical graph scanner|spine authority|proof kernel|status ledger|graph write fence)\b").unwrap()
    })
}

/// How a claim reads on the overclaim axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimClass {
    /// Names a specific bounded surface — admissible.
    Scoped,
    /// Broad "everything is done" language with no scope — blocked.
    BroadMyth,
    /// Broad language BUT also names a scope — allowed, flagged.
    BroadButScoped,
    /// Neither pattern — neutral.
    Neutral,
}

/// Classify a free-text status claim on the overclaim axis.
pub fn classify_claim(text: &str) -> ClaimClass {
    let broad = broad_myth_re().is_match(text);
    let scoped = scoped_ok_re().is_match(text);
    match (broad, scoped) {
        (true, true) => ClaimClass::BroadButScoped,
        (true, false) => ClaimClass::BroadMyth,
        (false, true) => ClaimClass::Scoped,
        (false, false) => ClaimClass::Neutral,
    }
}

/// Status-string classification (from the Python PASS/PARTIAL/UPGRADE sets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusClass {
    Pass,
    Partial,
    Upgrade,
    Unknown,
}

/// Classify a raw status string. The source distinguishes UPPERCASE terminal
/// verdicts (PASS set) from lowercase progress states (UPGRADE set) — note
/// "VERIFIED" (pass) vs "verified" (upgrade) is a deliberate case distinction,
/// so matching here is CASE-SENSITIVE (a forge-porting bug caught by the test).
pub fn classify_status(status: &str) -> StatusClass {
    let s = status.trim();
    const PASS: &[&str] = &["PASS", "REAL", "PASS_DRY_RUN", "VERIFIED", "SIGNED_OFF"];
    const UPGRADE: &[&str] = &[
        "verified",
        "executed",
        "dry_run_passed",
        "ready",
        "complete",
    ];
    const PARTIAL: &[&str] = &["blocked", "in_progress", "scaffolded"];
    if PASS.contains(&s) {
        StatusClass::Pass
    } else if UPGRADE.contains(&s) {
        StatusClass::Upgrade
    } else if PARTIAL.contains(&s) {
        StatusClass::Partial
    } else {
        StatusClass::Unknown
    }
}

/// The structured verdict THE ORACLE consumes. serde-round-trippable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateVerdict {
    pub admitted: bool,
    pub claim_class: ClaimClass,
    pub status_class: StatusClass,
    pub blockers: Vec<String>,
}

/// The gate: admit a (claim, status) pair or block it with reasons.
/// Rule (from the source policy): a BroadMyth claim is blocked unless it also
/// names a scope; an Unknown status is a blocker; everything else admits.
pub fn gate(claim_text: &str, status: &str, schema_recognized: bool) -> GateVerdict {
    let claim_class = classify_claim(claim_text);
    let status_class = classify_status(status);
    let mut blockers = Vec::new();

    if claim_class == ClaimClass::BroadMyth {
        blockers.push("broad_unscoped_overclaim".into());
    }
    if status_class == StatusClass::Unknown {
        blockers.push(format!("unrecognized_status:{status}"));
    }
    if !schema_recognized {
        blockers.push("schema_not_recognized".into());
    }

    GateVerdict {
        admitted: blockers.is_empty(),
        claim_class,
        status_class,
        blockers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_myth_is_caught() {
        assert_eq!(
            classify_claim("the whole system is 100% production ready"),
            ClaimClass::BroadMyth
        );
        assert_eq!(
            classify_claim("everything is complete and finished"),
            ClaimClass::BroadMyth
        );
    }

    #[test]
    fn scoped_claim_is_admissible() {
        assert_eq!(
            classify_claim("the golden path regression gate passes"),
            ClaimClass::Scoped
        );
        assert_eq!(
            classify_claim("status ledger proof kernel verified"),
            ClaimClass::Scoped
        );
    }

    #[test]
    fn broad_but_scoped_is_flagged_not_blocked() {
        // "complete" (broad) + "golden path" (scoped) → BroadButScoped, admitted.
        let c = classify_claim("the golden path is complete");
        assert_eq!(c, ClaimClass::BroadButScoped);
        let v = gate("the golden path is complete", "PASS", true);
        assert!(v.admitted, "a scoped claim survives broad language");
    }

    #[test]
    fn status_classification_matches_source_sets() {
        assert_eq!(classify_status("PASS"), StatusClass::Pass);
        assert_eq!(classify_status("verified"), StatusClass::Upgrade);
        assert_eq!(classify_status("blocked"), StatusClass::Partial);
        assert_eq!(classify_status("garbage"), StatusClass::Unknown);
    }

    #[test]
    fn gate_blocks_broad_overclaim() {
        let v = gate("the entire system is complete", "PASS", true);
        assert!(!v.admitted);
        assert!(v.blockers.iter().any(|b| b == "broad_unscoped_overclaim"));
    }

    #[test]
    fn gate_blocks_unknown_status_and_unrecognized_schema() {
        let v = gate("golden path check", "wat", false);
        assert!(!v.admitted);
        assert!(v
            .blockers
            .iter()
            .any(|b| b.starts_with("unrecognized_status")));
        assert!(v.blockers.iter().any(|b| b == "schema_not_recognized"));
    }

    #[test]
    fn clean_scoped_pass_admits() {
        let v = gate(
            "regression gate passed for the proof kernel",
            "VERIFIED",
            true,
        );
        assert!(v.admitted);
        assert!(v.blockers.is_empty());
    }

    #[test]
    fn verdict_is_serde_roundtrippable() {
        let v = gate("golden path", "PASS", true);
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}
