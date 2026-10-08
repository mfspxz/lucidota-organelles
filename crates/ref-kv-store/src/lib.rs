//! org-013 — Reference organelle: kv-store (codon `kv`).
//!
//! In-memory key-value store. `get`/`list` are ReadOnly; `put`/`delete`
//! are Write and require the `kv.write` capability (per-contract authority
//! override — the organelle-level default stays ReadOnly).

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "kv-store".to_string(),
        codon: "kv".to_string(),
        version: "1.0.0".to_string(),
        description: "reference in-memory key-value organelle".to_string(),
        contracts: vec![
            Contract {
                op: "put".to_string(),
                description: "store value under key".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["key", "value"],
                    "properties": {"key": {"type": "string"}}
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("kv.write".to_string()),
            },
            Contract {
                op: "get".to_string(),
                description: "read value by key".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["key"],
                    "properties": {"key": {"type": "string"}}
                }),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "delete".to_string(),
                description: "delete key".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["key"],
                    "properties": {"key": {"type": "string"}}
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("kv.write".to_string()),
            },
            Contract {
                op: "list".to_string(),
                description: "list all keys".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: None,
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
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

pub struct KvStore {
    manifest: OrganelleManifest,
    data: Mutex<HashMap<String, Value>>,
}

/// Fresh kv-store instance.
pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(KvStore { manifest: manifest(), data: Mutex::new(HashMap::new()) })
}

impl Organelle for KvStore {
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
        let mut data = self.data.lock().unwrap();
        match op {
            "put" => {
                let key = input["key"].as_str().unwrap_or("").to_string();
                data.insert(key.clone(), input["value"].clone());
                Ok(serde_json::json!({"ok": true, "key": key}))
            }
            "get" => {
                let key = input["key"].as_str().unwrap_or("");
                match data.get(key) {
                    Some(v) => Ok(serde_json::json!({"found": true, "key": key, "value": v})),
                    None => Ok(serde_json::json!({"found": false, "key": key})),
                }
            }
            "delete" => {
                let key = input["key"].as_str().unwrap_or("");
                let existed = data.remove(key).is_some();
                Ok(serde_json::json!({"ok": true, "key": key, "existed": existed}))
            }
            "list" => {
                let mut keys: Vec<String> = data.keys().cloned().collect();
                keys.sort();
                Ok(serde_json::json!({"keys": keys, "count": keys.len()}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn host_with(caps_holder: bool) -> (Arc<Host>, CallContext) {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let caps = if caps_holder { vec!["kv.write".to_string()] } else { vec![] };
        (h, CallContext::new("test", caps))
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let (h, ctx) = host_with(true);
        h.call(&ctx, "kv", "put", serde_json::json!({"key": "a", "value": 1})).unwrap();
        let got = h.call(&ctx, "kv", "get", serde_json::json!({"key": "a"})).unwrap();
        assert_eq!(got["value"], serde_json::json!(1));
        let del = h.call(&ctx, "kv", "delete", serde_json::json!({"key": "a"})).unwrap();
        assert_eq!(del["existed"], serde_json::json!(true));
        let gone = h.call(&ctx, "kv", "get", serde_json::json!({"key": "a"})).unwrap();
        assert_eq!(gone["found"], serde_json::json!(false));
    }

    #[test]
    fn put_without_capability_denied() {
        let (h, ctx) = host_with(false);
        let e = h.call(&ctx, "kv", "put", serde_json::json!({"key": "a", "value": 1})).unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
        let list = h.call(&ctx, "kv", "list", serde_json::json!({})).unwrap();
        assert_eq!(list["count"], serde_json::json!(0));
    }

    #[test]
    fn list_sorted() {
        let (h, ctx) = host_with(true);
        for k in ["c", "a", "b"] {
            h.call(&ctx, "kv", "put", serde_json::json!({"key": k, "value": true})).unwrap();
        }
        let list = h.call(&ctx, "kv", "list", serde_json::json!({})).unwrap();
        assert_eq!(list["keys"], serde_json::json!(["a", "b", "c"]));
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
