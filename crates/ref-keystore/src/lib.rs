//! Reference organelle: keystore (codon `ks`).
//!
//! Encrypted key-at-rest for the LUCIDOTA chain, harvested BY COPY
//! from pt-keystore (`~/workspace/full-send/projects/pt-crypto-infra/
//! app/pt-keystore/src/lib.rs`, 551 lines, kept byte-identical as
//! `keystore.rs`; `willow.rs` kept byte-identical under
//! `keystore/willow.rs`). The project tree keeps its own code; this
//! crate is the composable organelle form. `src/lib.rs` (this file)
//! adds only re-exports and organelle glue.
//!
//! The keystore holds the operator hierarchy — MASTER / PERSONAL /
//! VOID ✦ Ed25519 keys — encrypted at rest with XChaCha20-Poly1305,
//! the encryption key derived from a passphrase via Argon2id (the
//! file records its own `kdf_params`), entries AEAD-bound to
//! (role, pubkey), secret bytes zeroized on drop. It also carries
//! Willow provenance tokens ([`willow`]).
//!
//! Pure API: [`Keystore::create`] / [`Keystore::from_json`] /
//! [`Keystore::sign`] / [`Keystore::pubkey`], [`KeyRole`],
//! [`KdfParams`], [`willow::WillowProvenance`].

mod keystore;

pub use keystore::*;

// ---------------------------------------------------------------------------
// Organelle trait surface (glue)
// ---------------------------------------------------------------------------

#[cfg(feature = "organelle")]
mod organelle_impl {
    use super::KeyRole;
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
            name: "keystore".to_string(),
            codon: "ks".to_string(),
            version: "1.0.0".to_string(),
            description: "encrypted Ed25519 key-at-rest: MASTER/PERSONAL/VOID hierarchy + Willow provenance (pt-keystore harvest)".to_string(),
            contracts: vec![Contract {
                op: "roles".to_string(),
                description: "list the keystore's key hierarchy roles and their markers".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": [],
                    "properties": {}
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

    pub struct KeystoreOrganelle {
        manifest: OrganelleManifest,
    }

    pub fn organelle() -> Arc<dyn Organelle> {
        Arc::new(KeystoreOrganelle {
            manifest: manifest(),
        })
    }

    impl Organelle for KeystoreOrganelle {
        fn manifest(&self) -> OrganelleManifest {
            self.manifest.clone()
        }

        fn handle(
            &self,
            _ctx: &CallContext,
            _host: &dyn HostRef,
            op: &str,
            _input: Value,
        ) -> Result<Value, OrganelleError> {
            match op {
                // The stateless half of the keystore: signing and
                // unlocking need a live passphrase-held Keystore and
                // stay on the pure API.
                "roles" => {
                    let roles: Vec<Value> = [KeyRole::Master, KeyRole::Personal, KeyRole::Void]
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "role": r.as_str(),
                                "symbol": r.symbol()
                            })
                        })
                        .collect();
                    Ok(serde_json::json!({ "roles": roles }))
                }
                _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
            }
        }
    }
}

#[cfg(feature = "organelle")]
pub use organelle_impl::organelle;
