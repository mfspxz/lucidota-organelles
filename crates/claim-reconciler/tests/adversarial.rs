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
//! 6. R3-V4 replay: an attacker with their own grant forges a claim into
//!    the operator's book (attributed, not hidden), fabricates a supersede
//!    with an invented probe (REFUSED), and self-attests class closure
//!    (REFUSED). Replaying the operator's token as another caller is denied.
//!
//! Plus positive-path coverage: a well-evidenced closure grants (with a
//! fresh attesting grant), status reports full history, and the checked-in
//! manifest validates and matches the compiled manifest.

use claim_reconciler::organelle;
use organelle_host::{CallContext, Host};
use organelle_manifest::{sha256_hex, validate_manifest_json};
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

/// Write a real probe artifact under the grant root; returns (path, sha256).
fn probe_artifact(tag: &str, bytes: &[u8]) -> (String, String) {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "claim-reconciler-advprobe-{tag}-{}.bin",
        std::process::id()
    ));
    std::fs::write(&p, bytes).unwrap();
    let s = p.to_string_lossy().into_owned();
    (s, sha256_hex(bytes))
}

fn writer() -> (Arc<Host>, CallContext) {
    let h = Host::new();
    h.register(organelle()).unwrap();
    // The organelle approves store paths through the host membrane:
    // tests allowlist the temp dir.
    h.set_write_roots(vec![std::env::temp_dir()]).unwrap();
    let ctx = CallContext::new(
        "adv-test",
        vec!["claims.write".to_string(), "claims.class_close".to_string()],
    );
    (h, ctx)
}

/// Open a store through the grant flow; returns (grant_token, grant_id).
fn open_store(h: &Arc<Host>, ctx: &CallContext, store: &str) -> (String, String) {
    let out = h
        .call(ctx, "cr", "open-store", json!({"store_path": store}))
        .unwrap()
        .output;
    (
        out["grant_token"].as_str().unwrap().to_string(),
        out["grant_id"].as_str().unwrap().to_string(),
    )
}

fn ingest_claim(h: &Arc<Host>, ctx: &CallContext, token: &str) -> Value {
    h.call(
        ctx,
        "cr",
        "ingest-claim",
        json!({
            "grant_token": token,
            "fix_evidence": ["evidence/ref-1", "evidence/ref-2"],
            "proof_script_path": "proofs/p1.py",
            "commit": "deadbeef",
        }),
    )
    .unwrap().output
}

/// A real, hash-matching defeating probe for `tag`.
fn real_probe(tag: &str) -> Value {
    let (apath, ph) = probe_artifact(tag, format!("defeating-probe-{tag}").as_bytes());
    json!({"evidence_ref": format!("probes/{tag}"), "payload_hash": ph, "artifact_path": apath})
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
    let (token, _) = open_store(&h, &ctx, &store);
    ingest_claim(&h, &ctx, &token);
    let err = h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"grant_token": token, "claim_id": "FC-1"}),
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
    let (token, _) = open_store(&h, &ctx, &store);
    ingest_claim(&h, &ctx, &token);
    // Same agent AND same payload as the reproducer, dressed as a review.
    // (A fresh attesting grant is used so the refusal is about the replay,
    // not about self-attestation.)
    let (token_b, _) = open_store(&h, &ctx, &store);
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
            json!({"grant_token": token_b, "claim_id": "FC-1", "evidence": ev}),
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
            json!({"grant_token": token_b, "claim_id": "FC-1", "evidence": ev2}),
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
    let (token, _) = open_store(&h, &ctx, &store);
    ingest_claim(&h, &ctx, &token);

    // There is no delete op: the host denies unknown ops at the gate.
    let err = h
        .call(
            &ctx,
            "cr",
            "delete",
            json!({"grant_token": token, "claim_id": "FC-1"}),
        )
        .unwrap_err();
    assert_eq!(format!("{:?}", err.verdict), "Denied");

    // Supersede attempt with a defeats link but no defeating probe.
    let no_probe = h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "grant_token": token,
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
            "grant_token": token,
            "defect_id": "D-2",
            "defeats_claim_id": "FC-1",
            "defeating_probe": {"evidence_ref": "probes/bypass-1", "payload_hash": "ee55"},
        }),
    );
    assert!(no_repro.is_err());

    // Invented probe: names a payload hash with no stored artifact.
    let invented = h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "grant_token": token,
            "defect_id": "D-3",
            "defeats_claim_id": "FC-1",
            "defeating_probe": {"evidence_ref": "probes/bypass-3", "payload_hash": "ee55", "artifact_path": "/tmp/claim-reconciler-never-written.bin"},
            "reproduces_fixed_behavior": true,
        }),
    );
    assert!(invented.is_err());

    // Claim untouched by all attempts.
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
    let (token, _) = open_store(&h, &ctx, &store);
    ingest_claim(&h, &ctx, &token);
    h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "grant_token": token,
            "defect_id": "D-9",
            "defeats_claim_id": "FC-1",
            "defeating_probe": real_probe("a4"),
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
    let (token, _) = open_store(&h, &ctx, &store);
    let r = ingest_claim(&h, &ctx, &token);
    let claim_seq = r["seq"].as_u64().unwrap();

    let raw_before = std::fs::read_to_string(&store).unwrap();
    let original_line = raw_before.lines().nth(claim_seq as usize).unwrap().to_string();

    h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "grant_token": token,
            "defect_id": "D-5",
            "defeats_claim_id": "FC-1",
            "defeating_probe": real_probe("a5"),
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
        json!("probes/a5")
    );
    assert!(st.output["superseded_by"]["defeating_probe"]["artifact_path"]
        .as_str()
        .unwrap()
        .ends_with(".bin"));
    // Original claim entry still present in history, first.
    assert_eq!(st.output["history"][0]["kind"], json!("claim-ingested"));
    assert_eq!(st.output["history"][0]["seq"], json!(claim_seq));
    assert!(st.output["history"].as_array().unwrap().len() >= 3);
}

// --- 6. R3-V4 attack replay -------------------------------------------------
//
// The round-3 finding: an attacker with their own grant could forge claims
// into the operator's book, fabricate SUPERSEDED_BY_BYPASS with invented
// probes, and self-attest CLASS_CLOSED — with verify reporting ok:true.
// Post-repair:
//   (a) the forged claim lands but is permanently attributed to the
//       attacker's grant (recorded_by) — visible, not hidden;
//   (b) the fabricated supersede with an invented probe is REFUSED;
//   (c) self-attested class closure is REFUSED (recording grant != attesting
//       grant); verify fails any hand-forged self-attestation;
//   (d) replaying the operator's token as a different caller is DENIED.

#[test]
fn adv6_r3_v4_attack_replay() {
    let store = tmp_store("r3v4");
    let h = Host::new();
    h.register(organelle()).unwrap();
    h.set_write_roots(vec![std::env::temp_dir()]).unwrap();
    let op_ctx = CallContext::new(
        "operator",
        vec!["claims.write".to_string(), "claims.class_close".to_string()],
    );
    let mallory_ctx = CallContext::new(
        "mallory",
        vec!["claims.write".to_string(), "claims.class_close".to_string()],
    );

    // Operator opens the book and records a legit claim.
    let (op_token, op_grant) = open_store(&h, &op_ctx, &store);
    let legit = h
        .call(
            &op_ctx,
            "cr",
            "ingest-claim",
            json!({
                "grant_token": op_token,
                "fix_evidence": ["operator/probe-7"],
                "proof_script_path": "proofs/legit.py",
                "commit": "a1b2c3d4",
                "description": "legit fix",
            }),
        )
        .unwrap()
        .output;
    assert_eq!(legit["claim_id"], json!("FC-1"));

    // (a) Mallory opens the SAME path with her own grant and forges FC-2.
    // The write lands (she holds claims.write on a shared filesystem) but
    // the forgery is permanently attributed to her grant.
    let (m_token, m_grant) = open_store(&h, &mallory_ctx, &store);
    assert_ne!(op_grant, m_grant);
    let forged = h
        .call(
            &mallory_ctx,
            "cr",
            "ingest-claim",
            json!({
                "grant_token": m_token,
                "claim_id": "FC-2",
                "fix_evidence": ["forged/evidence"],
                "proof_script_path": "/tmp/evil.sh",
                "commit": "00000000",
                "description": "forged claim planted in operator book",
            }),
        )
        .unwrap()
        .output;
    assert_eq!(forged["claim_id"], json!("FC-2"));
    let st2 = h
        .call(
            &op_ctx,
            "cr",
            "claim-status",
            json!({"store_path": store, "claim_id": "FC-2"}),
        )
        .unwrap();
    assert_eq!(st2.output["original_claim"]["recorded_by"], json!(m_grant));
    assert_ne!(st2.output["original_claim"]["recorded_by"], json!(op_grant));
    assert_eq!(st2.output["original_claim"]["actor"], json!("mallory"));

    // (b) Mallory fabricates a defeating defect against the real FC-1 with
    // an invented probe: REFUSED — no stored, hash-matching artifact.
    let fabricated = h.call(
        &mallory_ctx,
        "cr",
        "ingest-defect",
        json!({
            "grant_token": m_token,
            "defect_id": "D-FORGED-1",
            "defeats_claim_id": "FC-1",
            "defeating_probe": {"evidence_ref": "forged/probe", "payload_hash": "forged-hash", "artifact_path": "/tmp/claim-reconciler-never-written.bin", "output": "fake"},
            "reproduces_fixed_behavior": true,
        }),
    );
    assert!(fabricated.is_err());
    let st1 = h
        .call(
            &op_ctx,
            "cr",
            "claim-status",
            json!({"store_path": store, "claim_id": "FC-1"}),
        )
        .unwrap();
    assert_eq!(st1.output["status"], json!("INSTANCE_ONLY"));

    // (c) Mallory self-attests CLASS_CLOSED for her forged FC-2 with the
    // grant that recorded it: REFUSED.
    let self_attest = h.call(
        &mallory_ctx,
        "cr",
        "request-class-closure",
        json!({"grant_token": m_token, "claim_id": "FC-2", "evidence": good_evidence()}),
    );
    let err = self_attest.unwrap_err();
    assert!(err.reason.contains("self-attestation"), "reason: {}", err.reason);

    // (d) Mallory replays the OPERATOR's token as herself: DENIED.
    assert!(h
        .call(
            &mallory_ctx,
            "cr",
            "ingest-claim",
            json!({
                "grant_token": op_token,
                "fix_evidence": ["x"],
                "proof_script_path": "p",
                "commit": "c",
            }),
        )
        .is_err());

    // The chain verifies: what remains is attributed, well-formed history.
    let v = h
        .call(&op_ctx, "cr", "verify", json!({"store_path": store}))
        .unwrap();
    assert_eq!(v.output["ok"], json!(true));
}

// --- positive paths ---------------------------------------------------------

#[test]
fn positive_well_evidenced_closure_grants() {
    let store = tmp_store("pos");
    let (h, ctx) = writer();
    let (token_a, _) = open_store(&h, &ctx, &store);
    ingest_claim(&h, &ctx, &token_a);
    // The closure ceremony uses a FRESH grant: the recording grant may not
    // attest its own closure (self-attestation refusal).
    let (token_b, _) = open_store(&h, &ctx, &store);
    let out = h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"grant_token": token_b, "claim_id": "FC-1", "evidence": good_evidence()}),
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
    assert!(st.output["class_closure"]["attested_by"]
        .as_str()
        .unwrap()
        .starts_with("g-"));
}

#[test]
fn positive_provenance_mode_requires_outside_verifier() {
    let store = tmp_store("prov");
    let (h, ctx) = writer();
    let (token_a, _) = open_store(&h, &ctx, &store);
    ingest_claim(&h, &ctx, &token_a); // actor is "adv-test"
    let (token_b, _) = open_store(&h, &ctx, &store);
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
            json!({"grant_token": token_b, "claim_id": "FC-1", "evidence": ev}),
        )
        .is_err());
    // A genuinely outside verifier passes.
    ev["independent_review"]["external_verifier"] = json!("third-party-lab");
    let out = h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"grant_token": token_b, "claim_id": "FC-1", "evidence": ev}),
        )
        .unwrap();
    assert_eq!(out.output["status"], json!("CLASS_CLOSED"));
}

#[test]
fn positive_semantic_mode_requires_independent_sampling() {
    let store = tmp_store("sem");
    let (h, ctx) = writer();
    let (token, _) = open_store(&h, &ctx, &store);
    ingest_claim(&h, &ctx, &token);
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
            json!({"grant_token": token, "claim_id": "FC-1", "evidence": ev}),
        )
        .is_err());
}

#[test]
fn positive_superseded_claim_cannot_class_close() {
    let store = tmp_store("sc");
    let (h, ctx) = writer();
    let (token_a, _) = open_store(&h, &ctx, &store);
    ingest_claim(&h, &ctx, &token_a);
    h.call(
        &ctx,
        "cr",
        "ingest-defect",
        json!({
            "grant_token": token_a,
            "defect_id": "D-1",
            "defeats_claim_id": "FC-1",
            "defeating_probe": real_probe("sc"),
            "reproduces_fixed_behavior": true,
        }),
    )
    .unwrap();
    let (token_b, _) = open_store(&h, &ctx, &store);
    assert!(h
        .call(
            &ctx,
            "cr",
            "request-class-closure",
            json!({"grant_token": token_b, "claim_id": "FC-1", "evidence": good_evidence()}),
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
