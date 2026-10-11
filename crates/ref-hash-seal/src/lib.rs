//! org-017 — Reference organelle: hash-seal (codon `hs`).
//!
//! Seals any JSON value with its SHA-256 over canonical JSON, and verifies
//! seals. ReadOnly, Proven — verification is recomputation.

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
        name: "hash-seal".to_string(),
        codon: "hs".to_string(),
        version: "1.0.0".to_string(),
        description: "reference content-sealing organelle (sha256)".to_string(),
        contracts: vec![
            Contract {
                op: "seal".to_string(),
                description: "seal a value with its sha256".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["data"]
                }),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "verify".to_string(),
                description: "verify a seal against data".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["data", "sha256"],
                    "properties": {"sha256": {"type": "string"}}
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

pub struct HashSeal {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(HashSeal { manifest: manifest() })
}

impl Organelle for HashSeal {
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
            "seal" => {
                let digest = organelle_manifest::hash_value(&input["data"]);
                Ok(serde_json::json!({
                    "sha256": digest,
                    "sealed_at": organelle_manifest::utc_now_iso(),
                }))
            }
            "verify" => {
                let digest = organelle_manifest::hash_value(&input["data"]);
                let claimed = input["sha256"].as_str().unwrap_or("");
                Ok(serde_json::json!({
                    "match": digest == claimed,
                    "computed": digest,
                }))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn h() -> (Arc<Host>, CallContext) {
        let h = Host::new();
        h.register(organelle()).unwrap();
        (h, CallContext::new("test", vec![]))
    }

    #[test]
    fn seal_then_verify() {
        let (h, ctx) = h();
        let data = serde_json::json!({"b": 2, "a": 1});
        let sealed = h.call(&ctx, "hs", "seal", serde_json::json!({"data": data})).unwrap().output;
        let digest = sealed["sha256"].as_str().unwrap().to_string();
        assert_eq!(digest.len(), 64);
        // Canonical: key order must not matter.
        let reordered = serde_json::json!({"a": 1, "b": 2});
        let v = h
            .call(&ctx, "hs", "verify", serde_json::json!({"data": reordered, "sha256": digest}))
            .unwrap()
            .output;
        assert_eq!(v["match"], serde_json::json!(true));
        let tampered = h
            .call(&ctx, "hs", "verify", serde_json::json!({"data": {"a": 1, "b": 3}, "sha256": digest}))
            .unwrap()
            .output;
        assert_eq!(tampered["match"], serde_json::json!(false));
    }

    #[test]
    fn known_digest() {
        let (h, ctx) = h();
        let sealed = h
            .call(&ctx, "hs", "seal", serde_json::json!({"data": "abc"}))
            .unwrap()
            .output;
        // sha256 of canonical JSON `"abc"` (with quotes).
        assert_eq!(
            sealed["sha256"],
            serde_json::json!(organelle_manifest::sha256_hex(b"\"abc\""))
        );
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
