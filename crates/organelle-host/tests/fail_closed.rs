//! org-008 — Fail-closed behavior suite.
//!
//! Every refusal path must (a) refuse, and (b) leave a receipt.
//! "No silent pass" is asserted by counting: receipts_out - receipts_in
//! must equal the number of calls attempted, whatever their outcome.

use organelle_host::{
    CallContext, CallVerdict, Host, HostRef, Organelle, OrganelleError,
};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::Arc;

struct Probe {
    manifest: OrganelleManifest,
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "probe".to_string(),
        codon: "pb".to_string(),
        version: "1.0.0".to_string(),
        description: "fail-closed probe".to_string(),
        contracts: vec![
            Contract {
                op: "ping".to_string(),
                description: "ping".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["nonce"],
                    "properties": {"nonce": {"type": "string"}}
                }),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "armed".to_string(),
                description: "gated".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("probe.armed".to_string()),
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: organelle_manifest::Valence::Candidate,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: vec![Transport::Native],
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

impl Organelle for Probe {
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
            "ping" => Ok(serde_json::json!({"pong": input["nonce"]})),
            "armed" => Ok(serde_json::json!({"armed": true})),
            _ => Err(OrganelleError::not_found(op)),
        }
    }
}

fn host() -> Arc<Host> {
    let h = Host::new();
    h.register(Arc::new(Probe { manifest: manifest() })).unwrap();
    h
}

fn ctx(caps: &[&str]) -> CallContext {
    CallContext::new(
        "fail-closed-suite",
        caps.iter().map(|s| s.to_string()).collect(),
    )
}

#[test]
fn unauthorized_call_denied_with_receipt() {
    let h = host();
    let before = h.receipts().len();
    let e = h.call(&ctx(&[]), "pb", "armed", serde_json::json!({})).unwrap_err();
    assert_eq!(e.verdict, CallVerdict::Denied);
    assert!(!e.receipt_id.is_empty(), "denial without receipt = silent pass");
    assert_eq!(h.receipts().len(), before + 1);
    let r = h.receipts().last().unwrap().clone();
    assert_eq!(r.id, e.receipt_id);
    assert_eq!(r.verdict, CallVerdict::Denied);
}

#[test]
fn malformed_input_rejected_with_receipt() {
    let h = host();
    let before = h.receipts().len();
    // missing required "nonce"
    let e = h.call(&ctx(&[]), "pb", "ping", serde_json::json!({"nope": 1})).unwrap_err();
    assert_eq!(e.verdict, CallVerdict::Rejected);
    assert!(!e.receipt_id.is_empty());
    assert_eq!(h.receipts().len(), before + 1);
    // wrong type entirely
    let e2 = h.call(&ctx(&[]), "pb", "ping", serde_json::json!("a string")).unwrap_err();
    assert_eq!(e2.verdict, CallVerdict::Rejected);
}

#[test]
fn unknown_codon_and_op_denied_with_receipt() {
    let h = host();
    let before = h.receipts().len();
    let e1 = h.call(&ctx(&[]), "xx", "ping", serde_json::json!({})).unwrap_err();
    let e2 = h.call(&ctx(&[]), "pb", "nope", serde_json::json!({})).unwrap_err();
    assert_eq!(e1.verdict, CallVerdict::Denied);
    assert_eq!(e2.verdict, CallVerdict::Denied);
    assert!(!e1.receipt_id.is_empty() && !e2.receipt_id.is_empty());
    assert_eq!(h.receipts().len(), before + 2);
}

#[test]
fn authorized_call_succeeds() {
    let h = host();
    let out = h
        .call(&ctx(&["probe.armed"]), "pb", "armed", serde_json::json!({}))
        .unwrap();
    assert_eq!(out.output["armed"], serde_json::json!(true));
    let out2 = h
        .call(&ctx(&[]), "pb", "ping", serde_json::json!({"nonce": "n1"}))
        .unwrap();
    assert_eq!(out2.output["pong"], serde_json::json!("n1"));
}

#[test]
fn no_silent_pass_across_all_refusal_modes() {
    let h = host();
    let before = h.receipts().len();
    let attempts = [
        h.call(&ctx(&[]), "pb", "armed", serde_json::json!({})),      // denied: capability
        h.call(&ctx(&[]), "pb", "ping", serde_json::json!({})),       // rejected: schema
        h.call(&ctx(&[]), "zz", "ping", serde_json::json!({})),       // denied: codon
        h.call(&ctx(&[]), "pb", "missing", serde_json::json!({})),    // denied: op
    ];
    let mut receipted = 0;
    for a in attempts {
        let e = a.unwrap_err();
        assert!(!e.receipt_id.is_empty(), "call refused with no receipt id");
        receipted += 1;
    }
    assert_eq!(receipted, 4);
    assert_eq!(h.receipts().len(), before + 4, "every refusal must receipt");
    // ...and the chain still verifies end to end.
    assert!(h.verify_chain().is_ok());
}

#[test]
fn denial_receipts_are_content_addressed() {
    let h = host();
    let e = h.call(&ctx(&[]), "zz", "ping", serde_json::json!({})).unwrap_err();
    let r = h.receipts().last().unwrap().clone();
    assert_eq!(r.id, e.receipt_id);
    assert!(r.output_hash.starts_with("denied:"));
    // id recomputes from body (content addressing, not a random uuid)
    assert_eq!(r.id.len(), 64);
}
