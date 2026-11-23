//! Reference organelle: evidence-gate (codon `ev`).
//!
//! The anti-overclaim evidence gate, harvested BY COPY from
//! pt-forged (`~/workspace/full-send/projects/pt-crypto-infra/
//! app/pt-forged/src/`): `lib.rs` (9 lines, kept byte-identical as
//! `forged.rs`) and `evidence_gate.rs` (215 lines, kept
//! byte-identical under `forged/evidence_gate.rs`). The project
//! tree keeps its own code; this crate is the composable organelle
//! form. This file adds only re-exports and organelle glue.
//!
//! [`gate`] classifies a claim ([`classify_claim`]) and its status
//! ([`classify_status`]) and admits or blocks the pair with named
//! blockers, producing the [`GateVerdict`] "THE ORACLE consumes".
//! The crate contains no signing or attestation code — verdict
//! provenance is documentary here; `ref-verified-context` is the
//! wiring that signs verdicts with a `ref-keystore` key.
//!
//! Pure API: [`gate`], [`classify_claim`], [`classify_status`],
//! [`GateVerdict`], [`ClaimClass`], [`StatusClass`].

mod forged;

pub use forged::*;

// ---------------------------------------------------------------------------
// Organelle trait surface (glue)
// ---------------------------------------------------------------------------

#[cfg(feature = "organelle")]
mod organelle_impl {
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
            name: "evidence-gate".to_string(),
            codon: "ev".to_string(),
            version: "1.0.0".to_string(),
            description: "anti-overclaim claim/status evidence gate producing GateVerdicts (pt-forged harvest)".to_string(),
            contracts: vec![Contract {
                op: "gate".to_string(),
                description: "admit or block a (claim, status) pair, with named blockers".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["claim", "status"],
                    "properties": {
                        "claim": {"type": "string"},
                        "status": {"type": "string"},
                        "schema_recognized": {"type": "boolean"}
                    }
                }),
                mutation_class: None,
                required_capability: None,
            }],
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

    pub struct EvidenceGate {
        manifest: OrganelleManifest,
    }

    pub fn organelle() -> Arc<dyn Organelle> {
        Arc::new(EvidenceGate {
            manifest: manifest(),
        })
    }

    impl Organelle for EvidenceGate {
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
            let s = |k: &str| input[k].as_str().unwrap_or("").to_string();
            match op {
                "gate" => {
                    let verdict = super::gate(
                        &s("claim"),
                        &s("status"),
                        input["schema_recognized"].as_bool().unwrap_or(true),
                    );
                    Ok(serde_json::to_value(&verdict)
                        .map_err(|e| OrganelleError::failed(e.to_string()))?)
                }
                _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
            }
        }
    }
}

#[cfg(feature = "organelle")]
pub use organelle_impl::organelle;
