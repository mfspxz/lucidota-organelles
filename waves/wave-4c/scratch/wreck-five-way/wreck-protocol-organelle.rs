//! wreck-protocol as an organelle (Tier A native migration).
//!
//! The change-claim lifecycle as callable ops (all pure, by-value):
//!   propose            {change_id, agent_id, task_id, base, head, intent} -> claim JSON
//!   transition         {claim, next} -> claim JSON with the legal status move applied
//!   validate_change_id {id} -> {valid: true}
//!   sha                {s} -> validated 40-hex sha string
//!   content_hash       {value} -> {sha256}
//!
//! The status machine is forward-only with no silent transitions; the
//! organelle enforces it by value (deserialize -> transition -> reserialize).
//! Execution personality: no fs, no network, no secrets, no state.
//! Stateless: suspend = no-op, kill = drop in-flight.
//! Envelope: 1 cpu / 64 MB / 10 s wall-time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::Arc;

use crate::{content_hash, ChangeClaim, ChangeStatus, Sha};

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
        name: "wreck-claim".to_string(),
        codon: "wl".to_string(),
        version: "0.1.0".to_string(),
        description: "wreck change-claim lifecycle: propose, forward-only status transitions, id/sha validation, content hashing".to_string(),
        contracts: vec![
            contract(
                "propose",
                "construct and validate a ChangeClaim (status PROPOSED)",
                obj_schema(
                    serde_json::json!({
                        "change_id": {"type": "string"},
                        "agent_id": {"type": "string"},
                        "task_id": {"type": "string"},
                        "base": {"type": "string"},
                        "head": {"type": "string"},
                        "intent": {"type": "string"}
                    }),
                    &["change_id", "agent_id", "task_id", "base", "head", "intent"],
                ),
            ),
            contract(
                "transition",
                "apply one legal forward status move to a claim (by value)",
                obj_schema(
                    serde_json::json!({
                        "claim": {"type": "object"},
                        "next": {"type": "string"}
                    }),
                    &["claim", "next"],
                ),
            ),
            contract(
                "validate_change_id",
                "validate a change id (2-63 chars, alnum plus . - _)",
                obj_schema(serde_json::json!({"id": {"type": "string"}}), &["id"]),
            ),
            contract(
                "sha",
                "validate a 40-hex git sha (lowercased)",
                obj_schema(serde_json::json!({"s": {"type": "string"}}), &["s"]),
            ),
            contract(
                "content_hash",
                "sha256 content hash of any JSON value",
                obj_schema(serde_json::json!({"value": {}}), &["value"]),
            ),
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

pub struct WreckClaim {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(WreckClaim { manifest: manifest() })
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

impl Organelle for WreckClaim {
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
            "propose" => {
                let base = Sha::new(&str_in(&input, "base")?).map_err(failed)?;
                let head = Sha::new(&str_in(&input, "head")?).map_err(failed)?;
                let claim = ChangeClaim::propose(
                    &str_in(&input, "change_id")?,
                    &str_in(&input, "agent_id")?,
                    &str_in(&input, "task_id")?,
                    base,
                    head,
                    &str_in(&input, "intent")?,
                )
                .map_err(failed)?;
                serde_json::to_value(&claim).map_err(|e| failed(e.to_string()))
            }
            "transition" => {
                let claim_v = input
                    .get("claim")
                    .ok_or_else(|| failed("missing field \"claim\"".to_string()))?;
                let mut claim: ChangeClaim =
                    serde_json::from_value(claim_v.clone()).map_err(|e| failed(e.to_string()))?;
                let next: ChangeStatus = serde_json::from_value(
                    input
                        .get("next")
                        .ok_or_else(|| failed("missing field \"next\"".to_string()))?
                        .clone(),
                )
                .map_err(|e| failed(format!("bad status: {e}")))?;
                claim.transition(next).map_err(failed)?;
                serde_json::to_value(&claim).map_err(|e| failed(e.to_string()))
            }
            "validate_change_id" => {
                ChangeClaim::validate_change_id(&str_in(&input, "id")?).map_err(failed)?;
                Ok(serde_json::json!({"valid": true}))
            }
            "sha" => {
                let sha = Sha::new(&str_in(&input, "s")?).map_err(failed)?;
                Ok(serde_json::json!({"sha": sha.as_str()}))
            }
            "content_hash" => {
                let v = input
                    .get("value")
                    .ok_or_else(|| failed("missing field \"value\"".to_string()))?;
                let h = content_hash(v).map_err(failed)?;
                Ok(serde_json::json!({"sha256": h}))
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
        let txt = include_str!("../../organelles/wreck-claim.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEAD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn propose_input() -> Value {
        serde_json::json!({
            "change_id": "chg-1", "agent_id": "agent-a", "task_id": "task-9",
            "base": BASE, "head": HEAD, "intent": "fix the thing"
        })
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "wreck-claim");
        assert_eq!(m.codon, "wl");
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
        let ctx = CallContext::new("wl-test", vec![]);

        let claim = host
            .call(&ctx, "wl", "propose", propose_input())
            .expect("propose");
        assert_eq!(claim["status"], "PROPOSED");
        assert_eq!(claim["change_id"], "chg-1");

        // forward move works (by value)
        let moved = host
            .call(&ctx, "wl", "transition", serde_json::json!({"claim": claim, "next": "OBSERVED"}))
            .expect("transition");
        assert_eq!(moved["status"], "OBSERVED");

        // illegal move is refused (skip from OBSERVED to MERGED)
        let bad = host.call(
            &ctx,
            "wl",
            "transition",
            serde_json::json!({"claim": moved, "next": "MERGED"}),
        );
        assert!(bad.is_err(), "skipping the forward chain must fail");

        let v = host
            .call(&ctx, "wl", "validate_change_id", serde_json::json!({"id": "chg-1"}))
            .expect("validate_change_id");
        assert_eq!(v["valid"], true);
        assert!(host
            .call(&ctx, "wl", "validate_change_id", serde_json::json!({"id": "!bad"}))
            .is_err());

        let s = host
            .call(&ctx, "wl", "sha", serde_json::json!({"s": BASE}))
            .expect("sha");
        assert_eq!(s["sha"], BASE);
        assert!(host
            .call(&ctx, "wl", "sha", serde_json::json!({"s": "nope"}))
            .is_err());

        let h = host
            .call(&ctx, "wl", "content_hash", serde_json::json!({"value": {"a": 1}}))
            .expect("content_hash");
        assert_eq!(h["sha256"].as_str().unwrap().len(), 64);

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 7, "register + calls = >=7 receipts, got {n}");
    }
}
