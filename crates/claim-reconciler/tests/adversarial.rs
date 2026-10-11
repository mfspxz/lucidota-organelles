//! Adversarial suite for the claim-reconciler organelle.
//!
//! Each test attacks the doctrine guarantees through the real host path
//! (`Host::register` + `Host::call` with capability gating):
//!
//! 1. class closure with no evidence -> refused (error, not a claim)
//! 2. class closure with the reproducer replayed as "review" -> refused
//! 3. delete is impossible (no such op); supersede-without-link -> refused
//! 4. tampered event file -> verify detects
//! 5. supersede preserves the original receipt byte-identical
//!
//! Plus positive-path coverage: a well-evidenced closure grants, status
//! reports full history, and the checked-in manifest validates and matches
//! the compiled manifest.

use claim_reconciler::organelle;
use organelle_host::{CallContext, Host};
use organelle_manifest::validate_manifest_json;
use serde_json::{json, Value};
use std::sync::Arc;

fn tmp_store(tag: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "claim-reconciler-adv-{tag}-{}.jsonl",
        std::process::id()
    ));
    let s = p.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&s);
    s
}

fn writer() -> (Arc<Host>, CallContext) {
    let h = Host::new();
    h.register(organelle()).unwrap();
    let ctx = CallContext::new(
        "adv-test",
        vec!["claims.write".to_string(), "claims.class_close".to_string()],
    );
    (h, ctx)
}

fn ingest_claim(h: &Arc<Host>, ctx: &CallContext, store: &str) -> Value {
    h.call(
        ctx,
        "cr",
        "ingest-claim",
        json!({
            "store_path": store,
            "fix_evidence": ["evidence/ref-1", "evidence/ref-2"],
            "proof_script_path": "proofs/p1.py",
            "commit": "deadbeef",
        }),
    )
    .unwrap().output
}

fn good_evidence() -> Value {
    json!({
        "original_reproducer": {
            "evidence_ref": "probes/repro-1",
            "payload_hash": "aa11",
            "agent": "redteam-a",
        },
        "adversarial_variants": [
            {"evidence_ref": "probes/var-1", "payload_hash": "bb22", "agent": "redteam-a"},
            {"evidence_ref": "probes/var-2", "payload_hash": "cc33", "agent": "redteam-b"},
        ],
        "prior_bypass_corpus": {"corpus_ref": "corpus/bypasses-v3", "samples": 41},
        "independent_review": {
            "agent": "reviewer-x",
            "payload_hash": "dd44",
            "mode": "semantic",
            "independent_sampling": {"expected": "denied", "observed": "denied", "samples": 50},
        },
    })
}

// --- 1. class closure with no evidence is refused ---------------------------

#[test]
fn adv1_closure_without_evidence_refused() {
    let store = tmp_store("a1");
    let (h, ctx) = writer();
    ingest_claim(&h, &ctx, &store);
    let err = h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"store_path": store, "claim_id": "FC-1"}),
        )
        .unwrap_err();
    assert_eq!(format!("{:?}", err.verdict), "Failed");
    assert!(err.reason.contains("refused"), "reason: {}", err.reason);
    // The refusal is an audit event, not a claim: status stays instance-only.
    let st = h
        .call(
            &ctx,
            "cr",
            "claim-status",
            json!({"store_path": store, "claim_id": "FC-1"}),
        )
        .unwrap();
    assert_eq!(st.output["status"], json!("INSTANCE_ONLY"));
    assert_eq!(st.output["refusals"], json!(1));
}

// --- 2. reproducer replayed as "review" is refused --------------------------

#[test]
fn adv2_reproducer_replayed_as_review_refused() {
    let store = tmp_store("a2");
    let (h, ctx) = writer();
    ingest_claim(&h, &ctx, &store);
    // Same agent AND same payload as the reproducer, dressed as a review.
    let mut ev = good_evidence();
    ev["independent_review"] = json!({
        "agent": "redteam-a",
        "payload_hash": "aa11",
        "mode": "structural",
    });
    let err = h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"store_path": store, "claim_id": "FC-1", "evidence": ev}),
        )
        .unwrap_err();
    assert_eq!(format!("{:?}", err.verdict), "Failed");
    assert!(err.reason.contains("replay"), "reason: {}", err.reason);

    // Same payload, different agent: still a replay of the payload.
    let mut ev2 = good_evidence();
    ev2["independent_review"] = json!({
        "agent": "reviewer-y",
        "payload_hash": "aa11",
        "mode": "structural",
    });
    assert!(h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"store_path": store, "claim_id": "FC-1", "evidence": ev2}),
        )
        .is_err());

    let st = h
        .call(
            &ctx,
            "cr",
            "claim-status",
            json!({"store_path": store, "claim_id": "FC-1"}),
        )
        .unwrap();
    assert_eq!(st.output["status"], json!("INSTANCE_ONLY"));
    assert_eq!(st.output["refusals"], json!(2));
}

// --- 3. delete impossible; supersede-without-link refused --------------------

#[test]
fn adv3_no_delete_op_and_no_unlinked_supersede() {
    let store = tmp_store("a3");
    let (h, ctx) = writer();
    ingest_claim(&h, &ctx, &store);

    // There is no delete op: the host denies unknown ops at the gate.
    let err = h
        .call(
            &ctx,
            "cr",
            "delete",
            json!({"store_path": store, "claim_id": "FC-1"}),
        )
        .unwrap_err();
    assert_eq!(format!("{:?}", err.verdict), "Denied");

    // Supersede attempt with a defeats link but no defeating probe.
    let no_probe = h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "store_path": store,
            "defect_id": "D-1",
            "defeats_claim_id": "FC-1",
            "reproduces_fixed_behavior": true,
        }),
    );
    assert!(no_probe.is_err());

    // Defeating probe present but no reproduction confirmation.
    let no_repro = h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "store_path": store,
            "defect_id": "D-2",
            "defeats_claim_id": "FC-1",
            "defeating_probe": {"evidence_ref": "probes/bypass-1", "payload_hash": "ee55"},
        }),
    );
    assert!(no_repro.is_err());

    // Claim untouched by both attempts.
    let st = h
        .call(
            &ctx,
            "cr",
            "claim-status",
            json!({"store_path": store, "claim_id": "FC-1"}),
        )
        .unwrap();
    assert_eq!(st.output["status"], json!("INSTANCE_ONLY"));
    assert_eq!(st.output["superseded_by"], json!(null));
}

// --- 4. tampered event file is detected by verify ----------------------------

#[test]
fn adv4_tamper_detected_by_verify() {
    let store = tmp_store("a4");
    let (h, ctx) = writer();
    ingest_claim(&h, &ctx, &store);
    h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "store_path": store,
            "defect_id": "D-9",
            "defeats_claim_id": "FC-1",
            "defeating_probe": {"evidence_ref": "probes/bypass-9", "payload_hash": "ff66"},
            "reproduces_fixed_behavior": true,
        }),
    )
    .unwrap();

    let before = h
        .call(&ctx, "cr", "verify", json!({"store_path": store}))
        .unwrap();
    assert_eq!(before.output["ok"], json!(true));

    // Flip one byte in the first stored line (an attacker rewriting history).
    let raw = std::fs::read_to_string(&store).unwrap();
    let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
    let first = lines[0].clone();
    let tampered = first.replacen("FC-1", "FC-9", 1);
    assert_ne!(first, tampered);
    lines[0] = tampered;
    std::fs::write(&store, lines.join("\n") + "\n").unwrap();

    let after = h
        .call(&ctx, "cr", "verify", json!({"store_path": store}))
        .unwrap();
    assert_eq!(after.output["ok"], json!(false));
    assert_eq!(after.output["break_at_seq"], json!(0));
}

// --- 5. supersede preserves the original receipt byte-identical -------------

#[test]
fn adv5_supersede_preserves_original_receipt() {
    let store = tmp_store("a5");
    let (h, ctx) = writer();
    let r = ingest_claim(&h, &ctx, &store);
    let claim_seq = r["seq"].as_u64().unwrap();

    let raw_before = std::fs::read_to_string(&store).unwrap();
    let original_line = raw_before.lines().nth(claim_seq as usize).unwrap().to_string();

    h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "store_path": store,
            "defect_id": "D-5",
            "defeats_claim_id": "FC-1",
            "defeating_probe": {"evidence_ref": "probes/bypass-5", "payload_hash": "ab12"},
            "reproduces_fixed_behavior": true,
            "links": ["https://example.invalid/probe-log"],
        }),
    )
    .unwrap();

    let raw_after = std::fs::read_to_string(&store).unwrap();
    let original_line_after = raw_after.lines().nth(claim_seq as usize).unwrap();
    assert_eq!(original_line, original_line_after, "original receipt mutated");

    // Chain still verifies; status reports supersede with full linkage.
    let v = h
        .call(&ctx, "cr", "verify", json!({"store_path": store}))
        .unwrap();
    assert_eq!(v.output["ok"], json!(true));

    let st = h
        .call(
            &ctx,
            "cr",
            "claim-status",
            json!({"store_path": store, "claim_id": "FC-1"}),
        )
        .unwrap();
    assert_eq!(st.output["status"], json!("SUPERSEDED_BY_BYPASS"));
    assert_eq!(st.output["superseded_by"]["defect_id"], json!("D-5"));
    assert_eq!(
        st.output["superseded_by"]["supersedes_seq"],
        json!(claim_seq)
    );
    assert_eq!(
        st.output["superseded_by"]["defeating_probe"]["evidence_ref"],
        json!("probes/bypass-5")
    );
    // Original claim entry still present in history, first.
    assert_eq!(st.output["history"][0]["kind"], json!("claim-ingested"));
    assert_eq!(st.output["history"][0]["seq"], json!(claim_seq));
    assert!(st.output["history"].as_array().unwrap().len() >= 3);
}

// --- positive paths ---------------------------------------------------------

#[test]
fn positive_well_evidenced_closure_grants() {
    let store = tmp_store("pos");
    let (h, ctx) = writer();
    ingest_claim(&h, &ctx, &store);
    let out = h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"store_path": store, "claim_id": "FC-1", "evidence": good_evidence()}),
        )
        .unwrap();
    assert_eq!(out.output["status"], json!("CLASS_CLOSED"));
    let st = h
        .call(
            &ctx,
            "cr",
            "claim-status",
            json!({"store_path": store, "claim_id": "FC-1"}),
        )
        .unwrap();
    assert_eq!(st.output["status"], json!("CLASS_CLOSED"));
    assert!(st.output["class_closure"].is_object());
}

#[test]
fn positive_provenance_mode_requires_outside_verifier() {
    let store = tmp_store("prov");
    let (h, ctx) = writer();
    ingest_claim(&h, &ctx, &store); // actor is "adv-test"
    let mut ev = good_evidence();
    ev["independent_review"] = json!({
        "agent": "reviewer-z",
        "payload_hash": "dd99",
        "mode": "provenance",
        "external_verifier": "adv-test", // the writer itself: not outside control
    });
    assert!(h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"store_path": store, "claim_id": "FC-1", "evidence": ev}),
        )
        .is_err());
    // A genuinely outside verifier passes.
    ev["independent_review"]["external_verifier"] = json!("third-party-lab");
    let out = h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"store_path": store, "claim_id": "FC-1", "evidence": ev}),
        )
        .unwrap();
    assert_eq!(out.output["status"], json!("CLASS_CLOSED"));
}

#[test]
fn positive_semantic_mode_requires_independent_sampling() {
    let store = tmp_store("sem");
    let (h, ctx) = writer();
    ingest_claim(&h, &ctx, &store);
    let mut ev = good_evidence();
    ev["independent_review"] = json!({
        "agent": "reviewer-q",
        "payload_hash": "dd77",
        "mode": "semantic",
        // no independent_sampling
    });
    assert!(h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"store_path": store, "claim_id": "FC-1", "evidence": ev}),
        )
        .is_err());
}

#[test]
fn positive_superseded_claim_cannot_class_close() {
    let store = tmp_store("sc");
    let (h, ctx) = writer();
    ingest_claim(&h, &ctx, &store);
    h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "store_path": store,
            "defect_id": "D-1",
            "defeats_claim_id": "FC-1",
            "defeating_probe": {"evidence_ref": "probes/b", "payload_hash": "zz1"},
            "reproduces_fixed_behavior": true,
        }),
    )
    .unwrap();
    assert!(h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"store_path": store, "claim_id": "FC-1", "evidence": good_evidence()}),
        )
        .is_err());
}

// --- manifest conformance ---------------------------------------------------

#[test]
fn manifest_json_validates_and_matches_compiled() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../organelles/claim-reconciler.manifest.json"
    );
    let raw = std::fs::read_to_string(path)
        .expect("organelles/claim-reconciler.manifest.json must exist");
    let v: Value = serde_json::from_str(&raw).expect("manifest must be JSON");
    let validated = validate_manifest_json(&v).expect("manifest must validate");
    assert_eq!(validated.name, "claim-reconciler");
    assert_eq!(validated.codon, "cr");
    // The checked-in file must be exactly what the compiled manifest emits.
    let compiled: Value =
        serde_json::to_value(organelle().manifest()).expect("manifest serializable");
    assert_eq!(v, compiled, "checked-in manifest drifted from manifest()");
}
