//! Reference organelle: verified-context (codon `vc`).
//!
//! The pt-compose wiring, harvested BY COPY from
//! `~/workspace/full-send/projects/pt-crypto-infra/app/pt-compose/src/lib.rs`
//! (kept byte-identical as `compose.rs`). It closes two gaps the
//! recovered pt crypto-infrastructure trio left open:
//!
//! 1. **Signed gate verdicts** — pt-forged's `GateVerdict` provenance
//!    was documentary only. [`sign_verdict`] signs the canonically
//!    serialized verdict with a pt-keystore role key;
//!    [`verify_signed_verdict`] re-checks the Ed25519 signature over
//!    the exact bytes before parsing the verdict back out. Tampering
//!    fails at verification, not at some later consumer.
//! 2. **Earned execution contexts** — pt-contracts' VM trusts
//!    `ExecutionContext.kernel_signature_valid`, a bool the caller
//!    used to merely assert. [`verified_context`] sets it from a real
//!    Ed25519 verification of the kernel signature against a
//!    keystore-held pubkey. A wrong signature honestly yields `false`
//!    and the VM refuses signature-gated scripts.
//!
//! Everything below the re-exports is organelle glue (manifest +
//! trait surface), written for this crate; it is not harvested code.

mod compose;

pub use compose::{sign_verdict, verified_context, verify_signed_verdict, ComposeError, SignedVerdict};

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
            name: "verified-context".to_string(),
            codon: "vc".to_string(),
            version: "1.0.0".to_string(),
            description: "signed gate verdicts + signature-earned execution contexts (pt-compose harvest)"
                .to_string(),
            contracts: vec![Contract {
                op: "verify_signed_verdict".to_string(),
                description:
                    "verify a SignedVerdict's Ed25519 signature and return the gate verdict"
                        .to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["signed_verdict"],
                    "properties": {
                        "signed_verdict": {"type": "object"}
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

    pub struct VerifiedContext {
        manifest: OrganelleManifest,
    }

    pub fn organelle() -> Arc<dyn Organelle> {
        Arc::new(VerifiedContext {
            manifest: manifest(),
        })
    }

    impl Organelle for VerifiedContext {
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
            match op {
                "verify_signed_verdict" => {
                    let sv: super::SignedVerdict = serde_json::from_value(input["signed_verdict"].clone())
                        .map_err(|e| OrganelleError::failed(e.to_string()))?;
                    match super::verify_signed_verdict(&sv) {
                        Ok(verdict) => Ok(serde_json::json!({
                            "valid": true,
                            "verdict": serde_json::to_value(&verdict)
                                .map_err(|e| OrganelleError::failed(e.to_string()))?
                        })),
                        Err(e) => Ok(serde_json::json!({
                            "valid": false,
                            "error": e.to_string()
                        })),
                    }
                }
                _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
            }
        }
    }
}

#[cfg(feature = "organelle")]
pub use organelle_impl::organelle;
