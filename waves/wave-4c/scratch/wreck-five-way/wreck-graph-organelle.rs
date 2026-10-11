//! wreck-graph as an organelle (Tier A native migration).
//!
//! Deterministic conflict analysis over change views (all pure):
//!   classify           {a, b, merged, policy} -> conflicts (empty = compatible pair)
//!   build_candidate    {views, merged, policy} -> {accepted, rejected}
//!   enclosing_functions {source, ranges} -> enclosing fn names for line ranges
//!
//! Conflict kinds: textual, semantic, dependency, policy. Classification is
//! deterministic and order-independent. Text is measured from diffs;
//! semantics are declared on the claim — the organelle never invents them.
//! Execution personality: no fs, no network, no secrets, no state.
//! Stateless: suspend = no-op, kill = drop in-flight.
//! Envelope: 1 cpu / 128 MB / 30 s wall-time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;

use crate::{build_candidate, classify, enclosing_functions, ChangeView, Policy};

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
        name: "wreck-conflict".to_string(),
        codon: "wg".to_string(),
        version: "0.1.0".to_string(),
        description: "wreck deterministic conflict analysis: classify change pairs, build merge candidates, map line ranges to enclosing functions".to_string(),
        contracts: vec![
            contract(
                "classify",
                "classify the relationship between two change views (empty = compatible)",
                obj_schema(
                    serde_json::json!({
                        "a": {"type": "object"},
                        "b": {"type": "object"},
                        "merged": {"type": "array", "items": {"type": "string"}},
                        "policy": {"type": "object"}
                    }),
                    &["a", "b"],
                ),
            ),
            contract(
                "build_candidate",
                "greedy deterministic merge candidate over views: accepted ids + rejections",
                obj_schema(
                    serde_json::json!({
                        "views": {"type": "array", "items": {"type": "object"}},
                        "merged": {"type": "array", "items": {"type": "string"}},
                        "policy": {"type": "object"}
                    }),
                    &["views"],
                ),
            ),
            contract(
                "enclosing_functions",
                "function names enclosing line ranges in Rust source",
                obj_schema(
                    serde_json::json!({
                        "source": {"type": "string"},
                        "ranges": {"type": "array", "items": {"type": "array", "items": {"type": "integer"}}}
                    }),
                    &["source", "ranges"],
                ),
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

pub struct WreckConflict {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(WreckConflict { manifest: manifest() })
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

fn view_of(v: &Value, key: &str) -> Result<ChangeView, OrganelleError> {
    let sub = v
        .get(key)
        .ok_or_else(|| failed(format!("missing field {key:?}")))?;
    serde_json::from_value(sub.clone()).map_err(|e| failed(format!("bad ChangeView in {key:?}: {e}")))
}

fn policy_of(input: &Value) -> Result<Policy, OrganelleError> {
    match input.get("policy") {
        Some(p) => serde_json::from_value(p.clone()).map_err(|e| failed(format!("bad policy: {e}"))),
        None => Ok(Policy::default()),
    }
}

fn merged_of(input: &Value) -> Result<HashSet<String>, OrganelleError> {
    match input.get("merged") {
        Some(m) => {
            let ids: Vec<String> =
                serde_json::from_value(m.clone()).map_err(|e| failed(format!("bad merged: {e}")))?;
            Ok(ids.into_iter().collect())
        }
        None => Ok(HashSet::new()),
    }
}

impl Organelle for WreckConflict {
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
            "classify" => {
                let a = view_of(&input, "a")?;
                let b = view_of(&input, "b")?;
                let merged = merged_of(&input)?;
                let policy = policy_of(&input)?;
                let conflicts = classify(&a, &b, &merged, &policy);
                serde_json::to_value(&conflicts).map_err(|e| failed(e.to_string()))
            }
            "build_candidate" => {
                let views_v = input
                    .get("views")
                    .ok_or_else(|| failed("missing field \"views\"".to_string()))?;
                let views: Vec<ChangeView> =
                    serde_json::from_value(views_v.clone()).map_err(|e| failed(e.to_string()))?;
                let merged = merged_of(&input)?;
                let policy = policy_of(&input)?;
                let (accepted, rejected) = build_candidate(views, &merged, &policy);
                Ok(serde_json::json!({"accepted": accepted, "rejected": rejected}))
            }
            "enclosing_functions" => {
                let source = input
                    .get("source")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| failed("missing string field \"source\"".to_string()))?;
                let ranges_v = input
                    .get("ranges")
                    .ok_or_else(|| failed("missing field \"ranges\"".to_string()))?;
                let ranges: Vec<(u32, u32)> =
                    serde_json::from_value(ranges_v.clone()).map_err(|e| failed(e.to_string()))?;
                let fns = enclosing_functions(source, &ranges);
                Ok(serde_json::json!({"functions": fns}))
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
    use wreck_protocol::ScopeItem;

    fn manifest_json() -> Value {
        let txt = include_str!("../../organelles/wreck-conflict.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    fn view(id: &str, file: &str, added: (u32, u32)) -> ChangeView {
        let mut v = ChangeView::from_scope(
            id,
            &[ScopeItem::File { path: file.to_string() }],
        );
        v.files = vec![crate::FileChange {
            path: file.to_string(),
            added: vec![added],
            removed: vec![],
        }];
        v
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "wreck-conflict");
        assert_eq!(m.codon, "wg");
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
        let ctx = CallContext::new("wg-test", vec![]);

        // disjoint ranges in the same file: no textual conflict
        let a = view("chg-a", "src/lib.rs", (10, 20));
        let b = view("chg-b", "src/lib.rs", (50, 60));
        let c = host
            .call(
                &ctx,
                "wg",
                "classify",
                serde_json::json!({"a": a, "b": b}),
            )
            .expect("classify");
        assert_eq!(c.as_array().unwrap().len(), 0);

        // overlapping ranges: textual conflict
        let d = view("chg-d", "src/lib.rs", (15, 25));
        let c2 = host
            .call(
                &ctx,
                "wg",
                "classify",
                serde_json::json!({"a": a, "b": d}),
            )
            .expect("classify overlap");
        assert!(c2.as_array().unwrap().len() >= 1);

        // build_candidate: a and b compatible, d conflicts with a
        let r = host
            .call(
                &ctx,
                "wg",
                "build_candidate",
                serde_json::json!({"views": [a, b, d]}),
            )
            .expect("build_candidate");
        let accepted = r["accepted"].as_array().unwrap();
        assert!(accepted.len() >= 2, "at least a and b accepted: {accepted:?}");

        // enclosing_functions on real source
        let src = "fn alpha() {}\nfn beta() {\n    let x = 1;\n}\n";
        let f = host
            .call(
                &ctx,
                "wg",
                "enclosing_functions",
                serde_json::json!({"source": src, "ranges": [[2, 3]]}),
            )
            .expect("enclosing_functions");
        assert!(f["functions"].as_array().unwrap().iter().any(|v| v == "beta"));

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 5, "register + calls = >=5 receipts, got {n}");
    }
}
