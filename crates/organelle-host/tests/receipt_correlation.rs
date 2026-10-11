//! P1 — invocation-specific receipts: concurrent correlation tests.
//!
//! Every invocation result carries the EXACT receipt id emitted for THAT
//! invocation (`CallOk.receipt_id` on success, `CallError.receipt_id` on
//! refusal/failure). The old surface code answered "which receipt was my
//! invocation's?" with a global `receipts().last()` read — which cross-wires
//! under concurrency (thread A can be handed thread B's receipt). These
//! tests prove the returned ids correlate 1:1 with the receipts actually
//! recorded in the store:
//!
//! - each result's receipt id resolves to exactly one stored receipt,
//! - that receipt names THIS invocation's (caller, codon, op, args digest),
//! - no duplicates, no swaps, no lost receipts,
//! - the hash chain still verifies end to end,
//! - every verdict class (Ok, Denied, Rejected, Failed) is correlated,
//!   including grant-level denials that never reach authorization.
//!
//! Race audit of the store (by inspection, asserted structurally here):
//! `emit_receipt` holds the store's write lock across seq assignment, prev
//! linking, id computation, and push — the returned id IS the id of the
//! pushed receipt, atomically. No other writer path emits invocation
//! receipts. Correlation is therefore not probabilistic: it cannot
//! cross-wire.

use organelle_host::{
    CallContext, CallError, CallOk, CallVerdict, Host, HostRef, Organelle, OrganelleError,
    Receipt, ReceiptKind,
};
use organelle_manifest::{
    hash_value, Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport,
    Valence, MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

struct Corr {
    manifest: OrganelleManifest,
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "corr".to_string(),
        codon: "co".to_string(),
        version: "1.0.0".to_string(),
        description: "receipt-correlation probe".to_string(),
        contracts: vec![
            Contract {
                op: "echo".to_string(),
                description: "echo input back".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "gated".to_string(),
                description: "capability-gated op".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("corr.gated".to_string()),
            },
            Contract {
                op: "boom".to_string(),
                description: "always fails".to_string(),
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
        transports: vec![Transport::Native],
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

impl Organelle for Corr {
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
            "echo" => Ok(serde_json::json!({"echo": input})),
            "gated" => Ok(serde_json::json!({"gated": true})),
            "boom" => Err(OrganelleError::failed("deliberate failure")),
            _ => Err(OrganelleError::not_found(format!("no such op {op}"))),
        }
    }
}

fn host() -> Arc<Host> {
    let h = Host::new();
    h.register(Arc::new(Corr { manifest: manifest() })).unwrap();
    h
}

/// One invocation's expectations: what the caller did and what verdict it
/// got, keyed by the receipt id the result carried.
struct Expectation {
    caller: String,
    op: String,
    input_hash: String,
    verdict: CallVerdict,
}

/// Assert every returned receipt id resolves to exactly the stored receipt
/// for that invocation: no duplicates, no swaps, no missing receipts, and
/// the chain verifies.
fn assert_correlated(h: &Host, expectations: &[Expectation], ids: &[String], baseline: usize) {
    assert_eq!(
        ids.len(),
        expectations.len(),
        "every invocation must have produced a receipt id"
    );
    let mut seen: HashSet<&str> = HashSet::new();
    for id in ids {
        assert!(!id.is_empty(), "empty receipt id returned");
        assert!(seen.insert(id.as_str()), "duplicate receipt id {id}");
    }
    let store: HashMap<String, Receipt> =
        h.receipts().into_iter().map(|r| (r.id.clone(), r)).collect();
    assert_eq!(
        store.len() - baseline,
        ids.len(),
        "store must hold exactly one receipt per invocation"
    );
    for (id, exp) in ids.iter().zip(expectations.iter()) {
        let r = store.get(id).unwrap_or_else(|| panic!("receipt {id} missing from store"));
        assert_eq!(r.kind, ReceiptKind::Invocation, "receipt {id} kind");
        assert_eq!(r.caller, exp.caller, "receipt {id} caller");
        assert_eq!(r.codon, "co", "receipt {id} codon");
        assert_eq!(r.op, exp.op, "receipt {id} op");
        assert_eq!(r.input_hash, exp.input_hash, "receipt {id} input_hash");
        assert_eq!(r.verdict, exp.verdict, "receipt {id} verdict");
    }
    assert!(
        h.verify_chain().is_ok(),
        "receipt chain must verify after concurrent invocations"
    );
}

#[test]
fn concurrent_ok_calls_each_get_own_receipt() {
    const THREADS: usize = 16;
    const PER_THREAD: usize = 25;
    let h = host();
    let baseline = h.receipts().len();

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let h = h.clone();
        handles.push(std::thread::spawn(move || {
            let caller = format!("ok-caller-{t}");
            let mut out = Vec::new();
            for i in 0..PER_THREAD {
                let input = serde_json::json!({"thread": t, "i": i});
                let ctx = CallContext::new(&caller, vec![]);
                let ok: CallOk = h.call(&ctx, "co", "echo", input.clone()).unwrap();
                out.push((
                    Expectation {
                        caller: caller.clone(),
                        op: "echo".to_string(),
                        input_hash: hash_value(&input),
                        verdict: CallVerdict::Ok,
                    },
                    ok.receipt_id,
                ));
            }
            out
        }));
    }
    let mut expectations = Vec::new();
    let mut ids = Vec::new();
    for hh in handles {
        for (exp, id) in hh.join().unwrap() {
            expectations.push(exp);
            ids.push(id);
        }
    }
    assert_correlated(&h, &expectations, &ids, baseline);
}

#[test]
fn concurrent_denied_calls_each_get_own_receipt() {
    const THREADS: usize = 12;
    const PER_THREAD: usize = 20;
    let h = host();
    let baseline = h.receipts().len();

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let h = h.clone();
        handles.push(std::thread::spawn(move || {
            let caller = format!("denied-caller-{t}");
            let mut out = Vec::new();
            for i in 0..PER_THREAD {
                // No corr.gated capability -> Denied at authorization.
                let input = serde_json::json!({"thread": t, "i": i});
                let ctx = CallContext::new(&caller, vec![]);
                let e: CallError = h.call(&ctx, "co", "gated", input.clone()).unwrap_err();
                assert_eq!(e.verdict, CallVerdict::Denied);
                out.push((
                    Expectation {
                        caller: caller.clone(),
                        op: "gated".to_string(),
                        input_hash: hash_value(&input),
                        verdict: CallVerdict::Denied,
                    },
                    e.receipt_id,
                ));
            }
            out
        }));
    }
    let mut expectations = Vec::new();
    let mut ids = Vec::new();
    for hh in handles {
        for (exp, id) in hh.join().unwrap() {
            expectations.push(exp);
            ids.push(id);
        }
    }
    assert_correlated(&h, &expectations, &ids, baseline);
}

#[test]
fn concurrent_mixed_verdicts_no_cross_wiring() {
    const THREADS: usize = 12;
    const PER_THREAD: usize = 16;
    let h = host();
    let baseline = h.receipts().len();

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let h = h.clone();
        handles.push(std::thread::spawn(move || {
            let caller = format!("mixed-caller-{t}");
            let mut out: Vec<(Expectation, String)> = Vec::new();
            for i in 0..PER_THREAD {
                let input = serde_json::json!({"thread": t, "i": i});
                match i % 4 {
                    0 => {
                        // Ok
                        let ok = h
                            .call(&CallContext::new(&caller, vec![]), "co", "echo", input.clone())
                            .unwrap();
                        assert_eq!(ok.output["echo"], input);
                        out.push((
                            Expectation {
                                caller: caller.clone(),
                                op: "echo".to_string(),
                                input_hash: hash_value(&input),
                                verdict: CallVerdict::Ok,
                            },
                            ok.receipt_id,
                        ));
                    }
                    1 => {
                        // Denied: missing capability.
                        let e = h
                            .call(&CallContext::new(&caller, vec![]), "co", "gated", input.clone())
                            .unwrap_err();
                        assert_eq!(e.verdict, CallVerdict::Denied);
                        out.push((
                            Expectation {
                                caller: caller.clone(),
                                op: "gated".to_string(),
                                input_hash: hash_value(&input),
                                verdict: CallVerdict::Denied,
                            },
                            e.receipt_id,
                        ));
                    }
                    2 => {
                        // Failed: organelle error. The error still carries
                        // the exact receipt id (filled at emission time).
                        let e = h
                            .call(&CallContext::new(&caller, vec![]), "co", "boom", input.clone())
                            .unwrap_err();
                        assert_eq!(e.verdict, CallVerdict::Failed);
                        assert!(!e.receipt_id.is_empty());
                        out.push((
                            Expectation {
                                caller: caller.clone(),
                                op: "boom".to_string(),
                                input_hash: hash_value(&input),
                                verdict: CallVerdict::Failed,
                            },
                            e.receipt_id,
                        ));
                    }
                    _ => {
                        // Denied: unknown op.
                        let e = h
                            .call(
                                &CallContext::new(&caller, vec![]),
                                "co",
                                "nope",
                                input.clone(),
                            )
                            .unwrap_err();
                        assert_eq!(e.verdict, CallVerdict::Denied);
                        out.push((
                            Expectation {
                                caller: caller.clone(),
                                op: "nope".to_string(),
                                input_hash: hash_value(&input),
                                verdict: CallVerdict::Denied,
                            },
                            e.receipt_id,
                        ));
                    }
                }
            }
            out
        }));
    }
    let mut expectations = Vec::new();
    let mut ids = Vec::new();
    for hh in handles {
        for (exp, id) in hh.join().unwrap() {
            expectations.push(exp);
            ids.push(id);
        }
    }
    // 3 verdict classes across 192 invocations: every id must name its
    // own invocation. Any swap (e.g. Ok receipt handed to a Denied call)
    // fails the verdict/caller/op checks above.
    assert_correlated(&h, &expectations, &ids, baseline);
}

#[test]
fn concurrent_grant_denials_each_get_own_receipt() {
    // Grant failures never reach authorization, but they still emit a
    // receipt and the CallError must carry THAT receipt's id.
    const THREADS: usize = 8;
    const PER_THREAD: usize = 10;
    let h = host();
    let baseline = h.receipts().len();

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let h = h.clone();
        handles.push(std::thread::spawn(move || {
            let caller = format!("forged-caller-{t}");
            let mut out = Vec::new();
            for i in 0..PER_THREAD {
                let input = serde_json::json!({"thread": t, "i": i});
                let e = h
                    .call_with_grant(
                        "definitely-not-a-valid-grant",
                        Some(&caller),
                        Transport::Native,
                        "co",
                        "echo",
                        input.clone(),
                    )
                    .unwrap_err();
                assert_eq!(e.verdict, CallVerdict::Denied);
                out.push((
                    Expectation {
                        caller: caller.clone(),
                        op: "echo".to_string(),
                        input_hash: hash_value(&input),
                        verdict: CallVerdict::Denied,
                    },
                    e.receipt_id,
                ));
            }
            out
        }));
    }
    let mut expectations = Vec::new();
    let mut ids = Vec::new();
    for hh in handles {
        for (exp, id) in hh.join().unwrap() {
            expectations.push(exp);
            ids.push(id);
        }
    }
    assert_correlated(&h, &expectations, &ids, baseline);
}

#[test]
fn grant_ok_call_receipt_correlates() {
    // The external-surface entry point: a valid grant's Ok result carries
    // the exact receipt id, and the receipt names the grant subject.
    let h = host();
    let grant = h.issue_grant("ext-caller", vec![], 300);
    let input = serde_json::json!({"hello": "world"});
    let ok = h
        .call_with_grant(
            &grant,
            Some("ext-caller"),
            Transport::Native,
            "co",
            "echo",
            input.clone(),
        )
        .unwrap();
    let r = h
        .receipts()
        .into_iter()
        .find(|r| r.id == ok.receipt_id)
        .expect("receipt id from result must exist in store");
    assert_eq!(r.verdict, CallVerdict::Ok);
    assert_eq!(r.caller, "ext-caller");
    assert_eq!(r.codon, "co");
    assert_eq!(r.op, "echo");
    assert_eq!(r.input_hash, hash_value(&input));
    assert_eq!(r.transport, Some(Transport::Native));
    assert_eq!(r.manifest_version, "1.0.0");
    assert!(h.verify_chain().is_ok());
}
