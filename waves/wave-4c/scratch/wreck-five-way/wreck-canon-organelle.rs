//! wreck-canon as an organelle (Tier A native migration).
//!
//! The WHY layer: canonical standing rules with provenance as callable ops:
//!   get_rule     {id} -> rule or {found: false}
//!   active_rules {} -> non-superseded rules, id-sorted
//!   to_policy    {} -> governor Policy derived from active forbidding rules
//!   insert_rule  {rule} -> append a rule (Write; supersede, never mutate)
//!
//! Rules are append-only: a new version supersedes the old; history is kept.
//! The store is in-memory (ephemeral); the deployer seeds it via insert_rule
//! (or demo_canon for the auth-demo seed).
//! Execution personality: no fs, no network, no secrets. State: ephemeral
//! in-memory rule map (suspend checkpoints it, kill drops it).
//! Envelope: 1 cpu / 64 MB / 10 s wall-time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};

use crate::{CanonRule, CanonStore};

fn str_in(v: &Value, key: &str) -> Result<String, OrganelleError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| OrganelleError::failed(format!("missing string field {key:?}")))
}

fn obj_schema(props: Value, required: &[&str]) -> Value {
    serde_json::json!({ "type": "object", "properties": props, "required": required })
}

fn contract(op: &str, description: &str, schema: Value) -> Contract {
    Contract {
        op: op.to_string(),
        description: description.to_string(),
        input_schema: schema,
        mutation_class: None,
        required_capability: None,
    }
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "wreck-canon".to_string(),
        codon: "wc".to_string(),
        version: "0.1.0".to_string(),
        description: "wreck canonical rule authority: standing rules with provenance, supersede-not-mutate, policy derivation".to_string(),
        contracts: vec![
            contract(
                "get_rule",
                "fetch one rule by id (history kept, superseded included)",
                obj_schema(serde_json::json!({"id": {"type": "string"}}), &["id"]),
            ),
            contract(
                "active_rules",
                "non-superseded rules, id-sorted",
                obj_schema(serde_json::json!({}), &[]),
            ),
            contract(
                "to_policy",
                "derive a governor Policy from active contract-forbidding rules",
                obj_schema(serde_json::json!({}), &[]),
            ),
            Contract {
                op: "insert_rule".to_string(),
                description: "append a rule (a superseding id replaces the old one in active set)".to_string(),
                input_schema: obj_schema(serde_json::json!({"rule": {"type": "object"}}), &["rule"]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("wc.write".to_string()),
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

pub struct WreckCanon {
    manifest: OrganelleManifest,
    store: Mutex<CanonStore>,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(WreckCanon {
        manifest: manifest(),
        store: Mutex::new(CanonStore::new()),
    })
}

/// Seeded with the auth-demo canon (CANON-31, CANON-17). For demos/tests;
/// production deployments seed via insert_rule.
pub fn organelle_demo_seeded() -> Arc<dyn Organelle> {
    Arc::new(WreckCanon {
        manifest: manifest(),
        store: Mutex::new(crate::demo_canon()),
    })
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

impl Organelle for WreckCanon {
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
            "get_rule" => {
                let id = str_in(&input, "id")?;
                let s = self.store.lock().map_err(|e| failed(e.to_string()))?;
                match s.get(&id) {
                    Some(r) => Ok(serde_json::json!({"found": true, "rule": serde_json::to_value(r).map_err(|e| failed(e.to_string()))?})),
                    None => Ok(serde_json::json!({"found": false, "id": id})),
                }
            }
            "active_rules" => {
                let s = self.store.lock().map_err(|e| failed(e.to_string()))?;
                let rules: Vec<&CanonRule> = s.active();
                serde_json::to_value(&rules).map_err(|e| failed(e.to_string()))
            }
            "to_policy" => {
                let s = self.store.lock().map_err(|e| failed(e.to_string()))?;
                let p = s.to_policy();
                serde_json::to_value(&p).map_err(|e| failed(e.to_string()))
            }
            "insert_rule" => {
                let rule_v = input
                    .get("rule")
                    .ok_or_else(|| failed("missing field \"rule\"".to_string()))?;
                let rule: CanonRule =
                    serde_json::from_value(rule_v.clone()).map_err(|e| failed(e.to_string()))?;
                let mut s = self.store.lock().map_err(|e| failed(e.to_string()))?;
                s.insert(rule.clone());
                Ok(serde_json::json!({"inserted": true, "id": rule.id}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use organelle_manifest::validate_manifest_json;

    fn manifest_json() -> Value {
        let txt = include_str!("../../organelles/wreck-canon.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    fn rule_json(id: &str, supersedes: Option<&str>) -> Value {
        serde_json::json!({
            "id": id,
            "statement": "no agent may mutate auth error semantics",
            "authority": "contract C-17",
            "created": "2026-10-08",
            "supersedes": supersedes,
            "forbids_contract": "auth.error-semantics",
            "contract_file_patterns": ["src/auth_err*"]
        })
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "wreck-canon");
        assert_eq!(m.codon, "wc");
    }

    #[test]
    fn rust_manifest_matches_static_json() {
        let from_rust = serde_json::to_value(manifest()).unwrap();
        assert_eq!(from_rust, manifest_json(), "Rust manifest() and organelles/*.json must agree");
    }

    #[test]
    fn registers_and_serves_through_host_with_receipts() {
        let host = Host::new();
        host.register(organelle()).expect("registration must succeed");
        let ctx = CallContext::new("wc-test", vec!["wc.write".to_string()]);
        let ro = CallContext::new("wc-ro", vec![]);

        // write gate: insert without wc.write is refused
        assert!(host
            .call(&ro, "wc", "insert_rule", serde_json::json!({"rule": rule_json("R-1", None)}))
            .is_err());

        host.call(&ctx, "wc", "insert_rule", serde_json::json!({"rule": rule_json("R-1", None)}))
            .expect("insert R-1");
        host.call(&ctx, "wc", "insert_rule", serde_json::json!({"rule": rule_json("R-2", Some("R-1")))}))
            .expect("insert R-2 superseding R-1");

        // history kept: old rule still retrievable
        let g = host
            .call(&ro, "wc", "get_rule", serde_json::json!({"id": "R-1"}))
            .expect("get_rule");
        assert_eq!(g["found"], true);

        // active set: R-1 superseded out
        let a = host
            .call(&ro, "wc", "active_rules", serde_json::json!({}))
            .expect("active_rules");
        let ids: Vec<&str> = a.as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(!ids.contains(&"R-1"), "superseded rule must leave the active set");
        assert!(ids.contains(&"R-2"));

        // policy derives from active forbidding rules
        let p = host.call(&ro, "wc", "to_policy", serde_json::json!({})).expect("to_policy");
        assert_eq!(p["rules"].as_array().unwrap().len(), 1);
        assert_eq!(p["rules"][0]["id"], "R-2");

        // demo-seeded organelle carries CANON-31
        let host2 = Host::new();
        host2.register(organelle_demo_seeded()).expect("register seeded");
        let g2 = host2
            .call(&ro, "wc", "get_rule", serde_json::json!({"id": "CANON-31"}))
            .expect("get CANON-31");
        assert_eq!(g2["found"], true);

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 6, "register + calls = >=6 receipts, got {n}");
    }
}
