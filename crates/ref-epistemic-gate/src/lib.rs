//! Reference organelle: epistemic-gate (codon `eg`).
//!
//! pt-oracle's verification gate, harvested BY COPY from
//! `~/workspace/full-send/projects/pt-oracle/app/src/gate.rs`
//! (kept as `gate.rs`; the single adaptation is the valence import:
//! the gate now takes `TernaryValence` from `ref-ontology-terms` —
//! the harvested go-ontology — instead of the `go-ontology` path
//! dependency, which is exactly the convergence the source itself
//! documents).
//!
//! The gate promotes Candidate→Proven through receipt-based rule
//! evaluation:
//!
//! - [`VerificationGate`] is the seam: `verify` (evaluate a claim
//!   against evidence receipts, emit an [`OracleReceipt`]),
//!   `promote` (quorum of Proven receipts for an artifact hash),
//!   `demote` (a non-empty refutation taints).
//! - [`RuleEngine`] is the validator seam: rules are caller-supplied
//!   closures `Fn(&[u8], &[OracleReceipt]) -> VerificationResult`;
//!   the verdict ratio maps ≥0.67 → Proven, ≤0.33 → Tainted, else
//!   Candidate. No rules registered → Candidate, never Proven.
//! - [`Oracle`] is the reference gate: a `RuleEngine` pre-loaded
//!   with the `non_empty` rule, keeping every receipt it issues.
//!
//! The byte-span `Validator` in pt-oracle's `validator.rs` is NOT
//! part of this harvest: it is bound to pt-oracle's candidate store
//! and `pt-core` CAS types, so it does not extract cleanly as a
//! standalone piece (see APPLICATION.md). Callers plug span checks
//! in as `RuleEngine` rules — that is the seam the gate exposes.
//!
//! Everything below the re-exports is organelle glue (manifest +
//! trait surface), written for this crate; it is not harvested code.

mod gate;

pub use gate::{
    receipt_signing_payload, rule_non_empty, verify_receipt_signature, Oracle, OracleError,
    OracleReceipt, RuleEngine, Valence, VerificationGate, VerificationResult,
};

// ---------------------------------------------------------------------------
// Organelle trait surface (glue)
// ---------------------------------------------------------------------------

#[cfg(feature = "organelle")]
mod organelle_impl {
    use super::{Oracle, VerificationGate};
    use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
    use organelle_manifest::{
        Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
        MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
    };
    use serde_json::Value;
    use std::sync::Arc;

    fn manifest() -> OrganelleManifest {
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: "epistemic-gate".to_string(),
            codon: "eg".to_string(),
            version: "1.0.0".to_string(),
            description: "receipt-based Candidate→Proven verification gate (pt-oracle harvest)"
                .to_string(),
            contracts: vec![
                Contract {
                    op: "verify".to_string(),
                    description: "evaluate a claim (hex artifact hash, agent, claim text) and return the gate receipt".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "required": ["artifact_hash_hex", "agent", "claim"],
                        "properties": {
                            "artifact_hash_hex": {"type": "string"},
                            "agent": {"type": "string"},
                            "claim": {"type": "string"}
                        }
                    }),
                    mutation_class: None,
                    required_capability: None,
                },
                Contract {
                    op: "promote".to_string(),
                    description: "quorum check over Proven receipts for an artifact hash".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "required": ["artifact_hash_hex", "receipts", "quorum"],
                        "properties": {
                            "artifact_hash_hex": {"type": "string"},
                            "receipts": {"type": "array"},
                            "quorum": {"type": "integer", "minimum": 0}
                        }
                    }),
                    mutation_class: None,
                    required_capability: None,
                },
            ],
            authority: Authority {
                mutation_class: MutationClass::ReadOnly,
                declared_valence: Valence::Proven,
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

    pub struct EpistemicGate {
        manifest: OrganelleManifest,
    }

    pub fn organelle() -> Arc<dyn Organelle> {
        Arc::new(EpistemicGate {
            manifest: manifest(),
        })
    }

    fn hash32(hex_str: &str) -> Result<[u8; 32], OrganelleError> {
        let bytes = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| OrganelleError::failed("bad artifact_hash_hex"))?;
        bytes
            .try_into()
            .map_err(|_| OrganelleError::failed("artifact_hash_hex must be 32 bytes"))
    }

    impl Organelle for EpistemicGate {
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
            // The harvested Oracle is not Sync (its RuleEngine holds
            // boxed closures), so the glue constructs a fresh gate per
            // call; verify/promote are receipt-in/receipt-out and keep
            // no cross-call state the ops depend on.
            let mut oracle = Oracle::new();
            match op {
                "verify" => {
                    let hash = hash32(input["artifact_hash_hex"].as_str().unwrap_or(""))?;
                    let agent = input["agent"].as_str().unwrap_or("");
                    let claim = input["claim"].as_str().unwrap_or("");
                    let receipt = oracle
                        .verify(&hash, agent, claim.as_bytes(), &[])
                        .map_err(|e| OrganelleError::failed(e.to_string()))?;
                    Ok(serde_json::json!({
                        "verdict": receipt.verdict.as_int(),
                        "absurd_tag": receipt.absurd_tag,
                        "findings": receipt.findings
                    }))
                }
                "promote" => {
                    let hash = hash32(input["artifact_hash_hex"].as_str().unwrap_or(""))?;
                    let receipts: Vec<super::OracleReceipt> =
                        serde_json::from_value(input["receipts"].clone())
                            .map_err(|e| OrganelleError::failed(e.to_string()))?;
                    let quorum = input["quorum"].as_u64().unwrap_or(0) as usize;
                    let valence = oracle
                        .promote(&hash, &receipts, quorum)
                        .map_err(|e| OrganelleError::failed(e.to_string()))?;
                    Ok(serde_json::json!({"valence": valence.as_int()}))
                }
                _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
            }
        }
    }
}

#[cfg(feature = "organelle")]
pub use organelle_impl::organelle;
