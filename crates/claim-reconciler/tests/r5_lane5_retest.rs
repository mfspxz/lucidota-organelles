//! Round-5 lane-5 adversarial re-test: R3-V4 poisoning replay against the
//! lane-4 repair (grant-bound store handles + evidence provenance,
//! `open-store`/`close-store` + `grant_token` on write ops, probe artifact
//! resolution, per-grant self-attestation refusal).
//!
//! API under test (read from the repaired src/lib.rs, 2026-10-11 ~08:25 UTC):
//!   open-store {store_path, ttl_seconds?} -> {grant_token, grant_id, ...}
//!   write ops take {grant_token} instead of {store_path}
//!   close-store {grant_token} revokes; claim-status/verify keep {store_path}
//! All calls go through the real surface-grant path
//! (`Host::issue_grant` + `Host::call_with_grant`), and `open-store` is
//! mediated by the host write-root membrane (`set_write_roots`).
//!
//! Test naming convention (this file only):
//!   `r5_bypass_*` — PASSES means the attack SUCCEEDED against the repaired
//!                     organelle: a bypass is demonstrated and filed in the
//!                     defect register (CR-1..CR-4).
//!   `r5_held_*`   — PASSES means the attack was BLOCKED: a control holds.
//! A green suite here is NOT "all secure" — count the `r5_bypass_*`
//! passes; each one is a filed defect.

use claim_reconciler::organelle;
use organelle_host::{Host, Organelle};
use organelle_manifest::{sha256_hex, Transport};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// One shared write root for the whole test binary (tests run in one
/// process; book filenames are unique per test).
fn root_dir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("r5-lane5-root-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&p);
    p
}

fn book(tag: &str) -> String {
    root_dir()
        .join(format!("r5-lane5-{tag}.jsonl"))
        .to_string_lossy()
        .into_owned()
}

/// Host with the organelle registered and the write-root membrane
/// allowlisting our scratch root (mirrors the R3-V4 "same shared host").
fn host() -> Arc<Host> {
    let h = Host::new();
    h.register(organelle()).unwrap();
    h.set_write_roots(vec![root_dir()]).unwrap();
    h
}

/// Surface grants: operator (victim) and mallory (attacker), each with
/// their own legit grant — exactly the R3-V4 setup.
fn surface_grants(h: &Arc<Host>) -> (String, String) {
    let o = h.issue_grant(
        "operator",
        vec!["claims.write".to_string(), "claims.class_close".to_string()],
        300,
    );
    let a = h.issue_grant(
        "mallory",
        vec!["claims.write".to_string(), "claims.class_close".to_string()],
        300,
    );
    (o, a)
}

/// open-store through the surface-grant path. Returns the full output.
fn open_store(h: &Arc<Host>, sg: &str, caller: &str, store_path: &str) -> Value {
    h.call_with_grant(
        sg,
        Some(caller),
        Transport::Native,
        "cr",
        "open-store",
        json!({"store_path": store_path}),
    )
    .unwrap()
    .output
}

/// Call a write op with an organelle store token through the surface path.
fn wcall(
    h: &Arc<Host>,
    sg: &str,
    caller: &str,
    op: &str,
    mut input: Value,
    store_token: &str,
) -> Value {
    input["grant_token"] = json!(store_token);
    h.call_with_grant(sg, Some(caller), Transport::Native, "cr", op, input)
        .unwrap()
        .output
}

fn wcall_err(
    h: &Arc<Host>,
    sg: &str,
    caller: &str,
    op: &str,
    mut input: Value,
    store_token: &str,
) -> organelle_host::CallError {
    input["grant_token"] = json!(store_token);
    h.call_with_grant(sg, Some(caller), Transport::Native, "cr", op, input)
        .unwrap_err()
}

fn rcall(h: &Arc<Host>, sg: &str, caller: &str, op: &str, input: Value) -> Value {
    h.call_with_grant(sg, Some(caller), Transport::Native, "cr", op, input)
        .unwrap()
        .output
}

fn claim_input() -> Value {
    json!({
        "fix_evidence": ["operator/probe-7", "operator/receipt-12"],
        "proof_script_path": "/opt/op/proof.sh",
        "commit": "a1b2c3d4",
        "description": "legit fix for F-real",
    })
}

/// All-string evidence bundle: every "independent" party is a mallory
/// sockpuppet name. Passes the gate's nominal string-inequality checks.
fn forged_closure_evidence() -> Value {
    json!({
        "original_reproducer": {"agent": "mallory-a", "payload_hash": "ph-1", "evidence_ref": "er-1"},
        "adversarial_variants": [{"evidence_ref": "er-2", "payload_hash": "ph-2"}],
        "prior_bypass_corpus": {"corpus_ref": "forged-corpus"},
        "independent_review": {"agent": "mallory-b", "payload_hash": "ph-3", "mode": "structural"}
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// BYPASS CR-1: open-store is self-service — mallory opens the OPERATOR's
// live book and plants a forged claim in it. The grant binds caller->path
// but authorizes nothing about whether that caller may touch that path.
// R3-V4 (a) survives the repair (now costs one extra open-store call).
// ---------------------------------------------------------------------------

#[test]
fn r5_bypass_open_store_on_victims_book() {
    let b = book("cr1-book");
    let _ = std::fs::remove_file(&b);
    let h = host();
    let (og, ag) = surface_grants(&h);

    // Operator opens her book and records a legit claim.
    let tok_o = open_store(&h, &og, "operator", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    let r_o = wcall(&h, &og, "operator", "ingest-claim", claim_input(), &tok_o);
    assert_eq!(r_o["claim_id"], json!("FC-1"));

    // Mallory opens THE SAME PATH with her own grant. The membrane approves:
    // it is under the shared write root; there is no per-path ownership.
    let out_m = open_store(&h, &ag, "mallory", &b);
    let tok_m = out_m["grant_token"].as_str().unwrap().to_string();
    assert_ne!(tok_o, tok_m, "distinct tokens");
    assert_eq!(
        out_m["store_path"].as_str().unwrap(),
        open_store(&h, &og, "operator", &b)["store_path"].as_str().unwrap(),
        "same canonical book"
    );

    // Mallory plants the forged claim in the operator's live book.
    let mut forged = claim_input();
    forged["claim_id"] = json!("FC-2");
    forged["description"] = json!("forged claim planted in operator book");
    let r_a = wcall(&h, &ag, "mallory", "ingest-claim", forged, &tok_m);
    // PASSES = bypass: the forged claim landed in the victim's book.
    assert_eq!(r_a["ok"], json!(true));
    assert_eq!(r_a["claim_id"], json!("FC-2"));
    let raw = std::fs::read_to_string(&b).unwrap();
    assert!(raw.contains("\"actor\":\"mallory\""));
    // The operator's own grant is unaffected.
    let r_o2 = wcall(&h, &og, "operator", "ingest-claim", claim_input(), &tok_o);
    assert_eq!(r_o2["claim_id"], json!("FC-3"));
    let _ = std::fs::remove_file(&b);
}

// ---------------------------------------------------------------------------
// BYPASS CR-2: probe authenticity is hash-integrity only. Mallory mints a
// REAL artifact (exists, sha256 matches) whose CONTENT is fabricated, and
// defeats the operator's real claim with it. `reproduces_fixed_behavior`
// remains a self-asserted boolean the organelle cannot check.
// R3-V4 (b) survives: "invented strings" became "well-formed lying files".
// ---------------------------------------------------------------------------

#[test]
fn r5_bypass_wellformed_false_probe_defeats_real_claim() {
    let b = book("cr2-book");
    let _ = std::fs::remove_file(&b);
    let h = host();
    let (og, ag) = surface_grants(&h);

    let tok_o = open_store(&h, &og, "operator", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    let r_o = wcall(&h, &og, "operator", "ingest-claim", claim_input(), &tok_o);
    let legit_id = r_o["claim_id"].as_str().unwrap().to_string();

    // Mallory opens the victim's book (CR-1) and mints a lying artifact:
    // a real file, with a correctly computed hash, containing fiction.
    let tok_m = open_store(&h, &ag, "mallory", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    let artifact = root_dir().join("r5-lane5-cr2-probe.bin");
    std::fs::write(&artifact, b"totally real bypass output (not)").unwrap();
    let artifact_str = artifact.to_string_lossy().into_owned();
    let real_hash = sha256_hex(b"totally real bypass output (not)");

    let r = wcall(
        &h,
        &ag,
        "mallory",
        "ingest-defect",
        json!({
            "defect_id": "D-FORGED-1",
            "defeats_claim_id": legit_id,
            "defeating_probe": {
                "evidence_ref": "forged/probe",
                "payload_hash": real_hash,
                "artifact_path": artifact_str,
            },
            "reproduces_fixed_behavior": true,
        }),
        &tok_m,
    );
    // PASSES = bypass: the fabricated-but-well-formed probe killed FC-1.
    assert_eq!(r["ok"], json!(true));
    assert_eq!(r["superseded"], json!(legit_id));
    let st = rcall(
        &h,
        &og,
        "operator",
        "claim-status",
        json!({"store_path": b, "claim_id": legit_id}),
    );
    assert_eq!(st["status"], json!("SUPERSEDED_BY_BYPASS"));
    let _ = std::fs::remove_file(&b);
    let _ = std::fs::remove_file(&artifact);
}

// ---------------------------------------------------------------------------
// BYPASS CR-3: self-attestation refusal is per-GRANT, not per-caller, and
// grants are unlimited self-service. The refusal message even coaches the
// bypass: "open a fresh grant for the closure ceremony". Mallory records
// with grant 1, attests with grant 2 — same human, GRANTED.
// ---------------------------------------------------------------------------

#[test]
fn r5_bypass_second_grant_self_attestation() {
    let b = book("cr3-book");
    let _ = std::fs::remove_file(&b);
    let h = host();
    let (_og, ag) = surface_grants(&h);

    let tok_m1 = open_store(&h, &ag, "mallory", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    let mut forged = claim_input();
    forged["claim_id"] = json!("FC-2");
    wcall(&h, &ag, "mallory", "ingest-claim", forged, &tok_m1);

    // Control: attesting with the SAME grant is refused (the coded check).
    let err = wcall_err(
        &h,
        &ag,
        "mallory",
        "request-class-closure",
        json!({"claim_id": "FC-2", "evidence": forged_closure_evidence()}),
        &tok_m1,
    );
    assert!(
        err.reason.contains("open a fresh grant"),
        "refusal coaches the bypass, reason: {}",
        err.reason
    );

    // Bypass: a fresh self-service grant attests the same human's claim.
    let tok_m2 = open_store(&h, &ag, "mallory", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(tok_m1, tok_m2);
    let r = wcall(
        &h,
        &ag,
        "mallory",
        "request-class-closure",
        json!({"claim_id": "FC-2", "evidence": forged_closure_evidence()}),
        &tok_m2,
    );
    // PASSES = bypass: one human, two grants, self-attested CLASS_CLOSED.
    assert_eq!(r["ok"], json!(true));
    assert_eq!(r["status"], json!("CLASS_CLOSED"));
    let _ = std::fs::remove_file(&b);
}

// ---------------------------------------------------------------------------
// BYPASS CR-4: the full R3-V4 chain end-to-end against the repaired
// organelle. Every step the repair was supposed to break still succeeds;
// `verify` reports ok:true over the poisoned book and reconciliation shows
// the attacker's fiction as fact.
// ---------------------------------------------------------------------------

#[test]
fn r5_bypass_full_r3v4_chain_end_to_end() {
    let b = book("cr4-book");
    let _ = std::fs::remove_file(&b);
    let h = host();
    let (og, ag) = surface_grants(&h);

    // Operator: open + legit claim.
    let tok_o = open_store(&h, &og, "operator", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    let r_o = wcall(&h, &og, "operator", "ingest-claim", claim_input(), &tok_o);
    let legit_id = r_o["claim_id"].as_str().unwrap().to_string();

    // (a) Mallory opens the victim's book and forges FC-2 into it.
    let tok_m = open_store(&h, &ag, "mallory", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    let mut forged = claim_input();
    forged["claim_id"] = json!("FC-2");
    forged["description"] = json!("forged claim planted in operator book");
    assert_eq!(
        wcall(&h, &ag, "mallory", "ingest-claim", forged, &tok_m)["ok"],
        json!(true)
    );

    // (b) Fabricated-but-well-formed probe defeats the real FC-1.
    let artifact = root_dir().join("r5-lane5-cr4-probe.bin");
    std::fs::write(&artifact, b"forged bypass output").unwrap();
    let ph = sha256_hex(b"forged bypass output");
    let r_b = wcall(
        &h,
        &ag,
        "mallory",
        "ingest-defect",
        json!({
            "defect_id": "D-FORGED-1",
            "defeats_claim_id": legit_id,
            "defeating_probe": {
                "evidence_ref": "forged/probe",
                "payload_hash": ph,
                "artifact_path": artifact.to_string_lossy(),
            },
            "reproduces_fixed_behavior": true,
        }),
        &tok_m,
    );
    assert_eq!(r_b["superseded"], json!(legit_id));

    // (c) Self-attested closure via a second self-service grant.
    let tok_m2 = open_store(&h, &ag, "mallory", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    let r_c = wcall(
        &h,
        &ag,
        "mallory",
        "request-class-closure",
        json!({"claim_id": "FC-2", "evidence": forged_closure_evidence()}),
        &tok_m2,
    );
    assert_eq!(r_c["status"], json!("CLASS_CLOSED"));

    // (d) The trust anchor blesses the poisoned history.
    let v = rcall(&h, &ag, "mallory", "verify", json!({"store_path": b}));
    assert_eq!(v["ok"], json!(true));
    assert!(v["entries"].as_u64().unwrap() >= 5);

    // (e) Reconciliation reports the attacker's fiction.
    let s1 = rcall(
        &h,
        &og,
        "operator",
        "claim-status",
        json!({"store_path": b, "claim_id": legit_id}),
    );
    let s2 = rcall(
        &h,
        &og,
        "operator",
        "claim-status",
        json!({"store_path": b, "claim_id": "FC-2"}),
    );
    // PASSES = bypass: every R3-V4 step still succeeds end-to-end.
    assert_eq!(s1["status"], json!("SUPERSEDED_BY_BYPASS"));
    assert_eq!(s2["status"], json!("CLASS_CLOSED"));
    let _ = std::fs::remove_file(&b);
    let _ = std::fs::remove_file(&artifact);
}

// ---------------------------------------------------------------------------
// HELD: cross-caller store-token replay is denied on the surface-grant path.
// Mallory's surface grant + the operator's store token -> denied.
// ---------------------------------------------------------------------------

#[test]
fn r5_held_cross_caller_store_token_replay() {
    let b = book("held-replay");
    let _ = std::fs::remove_file(&b);
    let h = host();
    let (og, ag) = surface_grants(&h);
    let tok_o = open_store(&h, &og, "operator", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();

    let err = wcall_err(&h, &ag, "mallory", "ingest-claim", claim_input(), &tok_o);
    assert!(
        err.reason.contains("not issued to this caller"),
        "reason: {}",
        err.reason
    );
    // The legitimate holder is unaffected.
    assert_eq!(
        wcall(&h, &og, "operator", "ingest-claim", claim_input(), &tok_o)["ok"],
        json!(true)
    );
    let _ = std::fs::remove_file(&b);
}

// ---------------------------------------------------------------------------
// HELD: suspend() clears the grant registry — tokens are process-lifetime.
// ---------------------------------------------------------------------------

#[test]
fn r5_held_suspend_kills_grants() {
    let b = book("held-suspend");
    let _ = std::fs::remove_file(&b);
    let org = organelle();
    let h = Host::new();
    h.register(org.clone()).unwrap();
    h.set_write_roots(vec![root_dir()]).unwrap();
    let (og, _ag) = surface_grants(&h);
    let tok = open_store(&h, &og, "operator", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        wcall(&h, &og, "operator", "ingest-claim", claim_input(), &tok)["ok"],
        json!(true)
    );

    org.suspend(); // the documented invalidation boundary

    let err = wcall_err(&h, &og, "operator", "ingest-claim", claim_input(), &tok);
    assert!(
        err.reason.contains("unknown or expired"),
        "reason: {}",
        err.reason
    );
    let _ = std::fs::remove_file(&b);
}

// ---------------------------------------------------------------------------
// HELD: symlink escape at open-store is denied by the membrane (canonicalize
// the nearest existing ancestor; escapes land outside the roots).
// ---------------------------------------------------------------------------

#[test]
fn r5_held_symlink_escape_at_open_denied() {
    let h = host();
    let (og, _ag) = surface_grants(&h);
    let outside = std::env::temp_dir().join(format!("r5-lane5-outside-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&outside);
    let link = root_dir().join("r5-lane5-esc-link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let evil = link.join("evil.jsonl").to_string_lossy().into_owned();
    assert!(!evil.contains(".."));

    let err = h
        .call_with_grant(
            &og,
            Some("operator"),
            Transport::Native,
            "cr",
            "open-store",
            json!({"store_path": evil}),
        )
        .unwrap_err();
    assert!(
        !outside.join("evil.jsonl").exists(),
        "no file was created outside the root"
    );
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_dir_all(&outside);
}

// ---------------------------------------------------------------------------
// HELD: TTL is clamped to [60s, 24h] — ttl_seconds=1 does not mint a
// 1-second token, and huge values do not mint effectively-immortal ones.
// ---------------------------------------------------------------------------

#[test]
fn r5_held_ttl_clamp_min_max() {
    let b = book("held-ttl");
    let h = host();
    let (og, _ag) = surface_grants(&h);
    let now = now_unix();

    let tiny = h
        .call_with_grant(
            &og,
            Some("operator"),
            Transport::Native,
            "cr",
            "open-store",
            json!({"store_path": b, "ttl_seconds": 1}),
        )
        .unwrap()
        .output;
    let exp_tiny = tiny["expires_at"].as_u64().unwrap();
    assert!(
        (exp_tiny as i64 - now as i64 - 60).abs() <= 5,
        "ttl=1 clamped to 60s, got expires_at={exp_tiny} now={now}"
    );

    let huge = h
        .call_with_grant(
            &og,
            Some("operator"),
            Transport::Native,
            "cr",
            "open-store",
            json!({"store_path": b, "ttl_seconds": 999999999u64}),
        )
        .unwrap()
        .output;
    let exp_huge = huge["expires_at"].as_u64().unwrap();
    assert!(
        (exp_huge as i64 - now as i64 - 86400).abs() <= 5,
        "huge ttl clamped to 24h, got expires_at={exp_huge} now={now}"
    );
}

// ---------------------------------------------------------------------------
// HELD: a stranger cannot close (revoke) someone else's grant; the token
// stays live for its rightful holder afterwards.
// ---------------------------------------------------------------------------

#[test]
fn r5_held_stranger_cannot_close_foreign_grant() {
    let b = book("held-close");
    let _ = std::fs::remove_file(&b);
    let h = host();
    let (og, ag) = surface_grants(&h);
    let tok_o = open_store(&h, &og, "operator", &b)["grant_token"]
        .as_str()
        .unwrap()
        .to_string();

    let err = h
        .call_with_grant(
            &ag,
            Some("mallory"),
            Transport::Native,
            "cr",
            "close-store",
            json!({"grant_token": tok_o}),
        )
        .unwrap_err();

    // Rightful holder closes her own grant: revoked afterwards.
    let r = h
        .call_with_grant(
            &og,
            Some("operator"),
            Transport::Native,
            "cr",
            "close-store",
            json!({"grant_token": tok_o}),
        )
        .unwrap()
        .output;
    assert_eq!(r["ok"], json!(true));
    let err2 = wcall_err(&h, &og, "operator", "ingest-claim", claim_input(), &tok_o);
    assert!(err2.reason.contains("unknown or expired"));
    let _ = std::fs::remove_file(&b);
}

// ---------------------------------------------------------------------------
// HELD: non-canonical spellings canonicalize to ONE store at open-store
// time — "//" and "/./" yield distinct tokens bound to the same canonical
// path; writes interleave into a single chain, verify stays clean.
// ---------------------------------------------------------------------------

#[test]
fn r5_held_noncanonical_opens_share_canonical_store() {
    let h = host();
    let (og, _ag) = surface_grants(&h);
    let r = root_dir().to_string_lossy().into_owned();
    let form_a = format!("{r}//r5-lane5-nc.jsonl");
    let form_b = format!("{r}/./r5-lane5-nc.jsonl");
    let b = format!("{r}/r5-lane5-nc.jsonl");
    let _ = std::fs::remove_file(&b);

    let out_a = open_store(&h, &og, "operator", &form_a);
    let out_b = open_store(&h, &og, "operator", &form_b);
    assert_eq!(
        out_a["store_path"].as_str().unwrap(),
        out_b["store_path"].as_str().unwrap(),
        "one canonical path"
    );
    let ta = out_a["grant_token"].as_str().unwrap();
    let tb = out_b["grant_token"].as_str().unwrap();
    assert_ne!(ta, tb, "distinct unguessable tokens");

    assert_eq!(
        wcall(&h, &og, "operator", "ingest-claim", claim_input(), ta)["claim_id"],
        json!("FC-1")
    );
    // Same underlying book: the second claim is FC-2, not a fresh chain.
    assert_eq!(
        wcall(&h, &og, "operator", "ingest-claim", claim_input(), tb)["claim_id"],
        json!("FC-2")
    );
    let v = rcall(&h, &og, "operator", "verify", json!({"store_path": b}));
    assert_eq!(v["ok"], json!(true));
    assert_eq!(v["entries"], json!(2));
    let _ = std::fs::remove_file(&b);
}

// ---------------------------------------------------------------------------
// HELD: an expired surface grant is denied before the organelle is reached.
// ---------------------------------------------------------------------------

#[test]
fn r5_held_expired_surface_grant_denied() {
    let b = book("held-exp");
    let h = host();
    let dead = h.issue_grant("mallory", vec!["claims.write".to_string()], 0);
    let err = h
        .call_with_grant(
            &dead,
            Some("mallory"),
            Transport::Native,
            "cr",
            "open-store",
            json!({"store_path": b}),
        )
        .unwrap_err();
    assert!(err.reason.contains("expired"), "reason: {}", err.reason);
}
