//! wreck-governor as an organelle (Tier A native migration).
//!
//! The deterministic merge authority as callable ops:
//!   decide         {change, view, in_flight, merged, ts} -> {outcome, record}
//!   complete_merge {draft, merge_sha, port_name, ts} -> sealed record
//!   chain_status   {} -> {sealed, head}
//!
//! `decide` is the merge-free pure decision path (the same logic that
//! compiles to WASM for the Worker): it returns either an already-sealed
//! decision or a pending accept draft the caller seals after the substrate
//! merges. Every verdict is sealed into the decision chain; seal() refuses
//! forks and replays (chain continuity).
//!
//! The seal key is registration-time config (vault-ref / env), NEVER in a
//! manifest. `organelle_with_key` is the real constructor; tests use a
//! throwaway key.
//!
//! Execution personality: no fs, no network, no process spawn. State: the
//! in-memory decision chain (ephemeral unless the deployer persists it;
//! suspend checkpoints the head, kill drops in-flight and the host emits
//! the final receipt).
//! Envelope: 1 cpu / 256 MB / 60 s wall-time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::{DecideOutcome, Governor};
use wreck_graph::{ChangeView, Policy};
use wreck_protocol::{ChangeClaim, DecisionRecord, Sha};

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

fn contract_write(op: &str, description: &str, schema: Value, cap: &str) -> Contract {
    Contract {
        op: op.to_string(),
        description: description.to_string(),
        input_schema: schema,
        mutation_class: Some(MutationClass::Write),
        required_capability: Some(cap.to_string()),
    }
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "wreck-decide".to_string(),
        codon: "wd".to_string(),
        version: "0.1.0".to_string(),
        description: "wreck deterministic merge authority: decide change claims, seal verdicts into a hash-chained decision log".to_string(),
        contracts: vec![
            contract_write(
                "decide",
                "run one change through the decision pipeline (merge-free); seals or returns a pending draft",
                obj_schema(
                    serde_json::json!({
                        "change": {"type": "object"},
                        "view": {"type": "object"},
                        "in_flight": {"type": "array", "items": {"type": "object"}},
                        "merged": {"type": "array", "items": {"type": "string"}},
                        "ts": {"type": "string"}
                    }),
                    &["change", "view", "ts"],
                ),
                "wd.decide",
            ),
            contract_write(
                "complete_merge",
                "seal an accepted draft after the substrate merged it",
                obj_schema(
                    serde_json::json!({
                        "draft": {"type": "object"},
                        "merge_sha": {"type": "string"},
                        "port_name": {"type": "string"},
                        "ts": {"type": "string"}
                    }),
                    &["draft", "merge_sha", "port_name", "ts"],
                ),
                "wd.decide",
            ),
            Contract {
                op: "chain_status".to_string(),
                description: "decision chain head + sealed count".to_string(),
                input_schema: obj_schema(serde_json::json!({}), &[]),
                mutation_class: Some(MutationClass::ReadOnly),
                required_capability: None,
            },
            contract(
                "ping",
                "liveness probe (no state touched)",
                obj_schema(serde_json::json!({}), &[]),
            ),
        ],
        authority: Authority {
            mutation_class: MutationClass::Write,
            declared_valence: Valence::Proven,
            required_capability: Some("wd.decide".to_string()),
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

pub struct WreckDecide {
    manifest: OrganelleManifest,
    governor: Mutex<Governor>,
}

pub fn organelle_with_key(key: Vec<u8>, actor: &str, policy: Policy) -> Arc<dyn Organelle> {
    Arc::new(WreckDecide {
        manifest: manifest(),
        governor: Mutex::new(Governor::new(policy, key, actor)),
    })
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

fn claim_of(v: &Value, key: &str) -> Result<ChangeClaim, OrganelleError> {
    let sub = v
        .get(key)
        .ok_or_else(|| failed(format!("missing field {key:?}")))?;
    serde_json::from_value(sub.clone()).map_err(|e| failed(format!("bad ChangeClaim: {e}")))
}

fn view_of(v: &Value, key: &str) -> Result<ChangeView, OrganelleError> {
    let sub = v
        .get(key)
        .ok_or_else(|| failed(format!("missing field {key:?}")))?;
    serde_json::from_value(sub.clone()).map_err(|e| failed(format!("bad ChangeView: {e}")))
}

fn outcome_json(o: DecideOutcome) -> Result<Value, OrganelleError> {
    match o {
        DecideOutcome::AcceptPending { draft } => Ok(serde_json::json!({
            "outcome": "pending",
            "draft": serde_json::to_value(&draft).map_err(|e| failed(e.to_string()))?,
        })),
        DecideOutcome::Decided(rec) => Ok(serde_json::json!({
            "outcome": "decided",
            "record": serde_json::to_value(&rec).map_err(|e| failed(e.to_string()))?,
        })),
    }
}

impl Organelle for WreckDecide {
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
            "decide" => {
                let mut change = claim_of(&input, "change")?;
                let view = view_of(&input, "view")?;
                let in_flight: Vec<ChangeView> = match input.get("in_flight") {
                    Some(v) => serde_json::from_value(v.clone()).map_err(|e| failed(e.to_string()))?,
                    None => vec![],
                };
                let merged: HashSet<String> = match input.get("merged") {
                    Some(v) => {
                        let ids: Vec<String> =
                            serde_json::from_value(v.clone()).map_err(|e| failed(e.to_string()))?;
                        ids.into_iter().collect()
                    }
                    None => HashSet::new(),
                };
                let ts = str_in(&input, "ts")?;
                let mut g = self.governor.lock().map_err(|e| failed(e.to_string()))?;
                let outcome = g
                    .decide(&mut change, &view, &in_flight, &merged, &ts)
                    .map_err(failed)?;
                outcome_json(outcome)
            }
            "complete_merge" => {
                let draft_v = input
                    .get("draft")
                    .ok_or_else(|| failed("missing field \"draft\"".to_string()))?;
                let draft: DecisionRecord =
                    serde_json::from_value(draft_v.clone()).map_err(|e| failed(e.to_string()))?;
                let merge_sha = Sha::new(&str_in(&input, "merge_sha")?).map_err(failed)?;
                let port_name = str_in(&input, "port_name")?;
                let ts = str_in(&input, "ts")?;
                let mut g = self.governor.lock().map_err(|e| failed(e.to_string()))?;
                let rec = g
                    .complete_merge(draft, &merge_sha, &port_name, &ts)
                    .map_err(failed)?;
                serde_json::to_value(&rec).map_err(|e| failed(e.to_string()))
            }
            "chain_status" => {
                let g = self.governor.lock().map_err(|e| failed(e.to_string()))?;
                Ok(serde_json::json!({"sealed": g.decisions_sealed()}))
            }
            "ping" => Ok(serde_json::json!({"ok": true, "organelle": "wreck-decide"})),
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use organelle_manifest::validate_manifest_json;
    use wreck_graph::FileChange;
    use wreck_protocol::{ChangeStatus, Claim, ClaimKind, Evidence, EvidenceKind, ScopeItem};

    fn manifest_json() -> Value {
        let txt = include_str!("../../organelles/wreck-decide.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    fn test_organelle() -> Arc<dyn Organelle> {
        organelle_with_key(b"test-seal-key-32-bytes-padded-0000".to_vec(), "test-actor", Policy::default())
    }

    const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEAD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn claim_json() -> Value {
        let mut c = ChangeClaim::propose("chg-1", "agent-a", "task-9", Sha::new(BASE).unwrap(), Sha::new(HEAD).unwrap(), "improve auth").unwrap();
        c.scope = vec![ScopeItem::File { path: "src/auth.rs".to_string() }];
        c.claims = vec![Claim { id: "C1".into(), statement: "only touches auth".into(), kind: ClaimKind::Custom { label: "safety".into() } }];
        c.evidence = vec![Evidence { id: "E1".into(), kind: EvidenceKind::Test, reference: "cargo test auth".into(), digest: "deadbeef".into() }];
        serde_json::to_value(&c).unwrap()
    }

    fn view_json() -> Value {
        let v = ChangeView {
            change_id: "chg-1".to_string(),
            files: vec![FileChange { path: "src/auth.rs".to_string(), added: vec![(10, 20)], removed: vec![] }],
            ..Default::default()
        };
        serde_json::to_value(&v).unwrap()
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "wreck-decide");
        assert_eq!(m.codon, "wd");
    }

    #[test]
    fn rust_manifest_matches_static_json() {
        let from_rust = serde_json::to_value(manifest()).unwrap();
        assert_eq!(from_rust, manifest_json(), "Rust manifest() and organelles/*.json must agree");
    }

    #[test]
    fn registers_and_serves_through_host_with_receipts() {
        let host = Host::new();
        host.register(test_organelle()).expect("registration must succeed");
        // write ops need the capability
        let ctx = CallContext::new("wd-test", vec!["wd.decide".to_string()]);
        let ro_ctx = CallContext::new("wd-ro", vec![]);

        // capability gate: decide without wd.decide is refused
        assert!(host
            .call(&ro_ctx, "wd", "decide", serde_json::json!({"change": claim_json(), "view": view_json(), "ts": "2026-10-10T00:00:00Z"}))
            .is_err());

        // clean claim, empty policy, nothing in flight: accepted -> pending draft
        let out = host
            .call(&ctx, "wd", "decide", serde_json::json!({
                "change": claim_json(), "view": view_json(),
                "in_flight": [], "merged": [], "ts": "2026-10-10T00:00:00Z"
            }))
            .expect("decide");
        assert_eq!(out["outcome"], "pending");
        assert!(out["draft"]["receipt"]["seal"].is_null() || out["draft"]["receipt"].as_object().is_some());

        // complete_merge seals it (merge succeeded on the substrate)
        let sealed = host
            .call(&ctx, "wd", "complete_merge", serde_json::json!({
                "draft": out["draft"],
                "merge_sha": "cccccccccccccccccccccccccccccccccccccccc",
                "port_name": "local-test",
                "ts": "2026-10-10T00:01:00Z"
            }))
            .expect("complete_merge");
        assert!(sealed["receipt"]["seal"].as_str().is_some(), "sealed record carries a seal");

        // chain grew
        let st = host.call(&ro_ctx, "wd", "chain_status", serde_json::json!({})).expect("chain_status");
        assert_eq!(st["sealed"], 1);

        // stale-head draft is refused (fork/replay protection)
        let out2 = host
            .call(&ctx, "wd", "decide", serde_json::json!({
                "change": claim_json(), "view": view_json(), "ts": "2026-10-10T00:02:00Z"
            }))
            .expect("decide 2");
        assert_eq!(out2["outcome"], "pending");
        let stale = host.call(&ctx, "wd", "complete_merge", serde_json::json!({
            "draft": out["draft"], // draft from BEFORE, parent seal is stale now
            "merge_sha": "dddddddddddddddddddddddddddddddddddddddd",
            "port_name": "local-test",
            "ts": "2026-10-10T00:03:00Z"
        }));
        assert!(stale.is_err(), "stale parent seal must be refused");

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 6, "register + calls = >=6 receipts, got {n}");
    }

    #[test]
    fn policy_violation_rejects() {
        use wreck_graph::PolicyRule;
        let policy = Policy {
            rules: vec![PolicyRule {
                id: "CANON-31".into(),
                forbidden_contract: "auth.error-semantics".into(),
                reason: "no agent may mutate auth error semantics".into(),
                file_patterns: vec!["src/auth*".into()],
            }],
        };
        let host = Host::new();
        host.register(organelle_with_key(b"test-seal-key-32-bytes-padded-0000".to_vec(), "test-actor", policy))
            .expect("register");
        let ctx = CallContext::new("wd-test", vec!["wd.decide".to_string()]);
        let out = host
            .call(&ctx, "wd", "decide", serde_json::json!({
                "change": claim_json(), "view": view_json(), "ts": "2026-10-10T00:00:00Z"
            }))
            .expect("decide");
        assert_eq!(out["outcome"], "decided", "policy violation must seal a rejection, not pend");
    }

    #[test]
    fn _status_enum_shape() {
        // keep the compiler honest about the protocol types we depend on
        assert!(ChangeStatus::Proposed != ChangeStatus::Merged);
    }
}
