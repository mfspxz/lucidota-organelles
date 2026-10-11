//! Round-6 lane-6: legacy-exemption investigation (panopticon round 15).
//!
//! Finding: `verify` exempted `claim-superseded` entries without
//! `artifact_path` ("pre-grant legacy"), so a direct filesystem append of a
//! forged supersede entry — no artifact, keyless chain correctly sealed —
//! passed `verify` (ok:true) and flipped the claim to SUPERSEDED_BY_BYPASS,
//! bypassing the organelle entirely.
//!
//! Post-fix contract asserted here:
//!   1. A forged supersede with NO artifact_path FAILS verify closed
//!      (ok:false, break_at_seq = forged seq, reason names artifact_path).
//!      The hash chain itself is intact, proving the failure is the closed
//!      exemption, not a bad seal.
//!   2. A legitimate supersede WITH a real, hash-matching probe artifact
//!      still verifies (no regression on the honest path).
//!   3. Pinned residual: `claim-status` is a read view, not an integrity
//!      oracle — it still reports SUPERSEDED_BY_BYPASS for the forged
//!      entry; `verify` is the check that catches it.

use claim_reconciler::organelle;
use organelle_host::{Host, Organelle};
use organelle_manifest::{canonical_json, sha256_hex, Transport};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

fn root_dir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("r6-lane6-root-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&p);
    p
}

fn book(tag: &str) -> String {
    root_dir()
        .join(format!("r6-lane6-{tag}.jsonl"))
        .to_string_lossy()
        .into_owned()
}

fn host() -> Arc<Host> {
    let h = Host::new();
    h.register(organelle()).unwrap();
    h.set_write_roots(vec![root_dir()]).unwrap();
    h
}

fn operator_grant(h: &Arc<Host>) -> String {
    h.issue_grant(
        "operator",
        vec!["claims.write".to_string(), "claims.class_close".to_string()],
        300,
    )
}

fn open_store(h: &Arc<Host>, sg: &str, store_path: &str) -> Value {
    h.call_with_grant(
        sg,
        Some("operator"),
        Transport::Native,
        "cr",
        "open-store",
        json!({"store_path": store_path}),
    )
    .unwrap()
    .output
}

fn wcall(h: &Arc<Host>, sg: &str, op: &str, mut input: Value, store_token: &str) -> Value {
    input["grant_token"] = json!(store_token);
    h.call_with_grant(sg, Some("operator"), Transport::Native, "cr", op, input)
        .unwrap()
        .output
}

fn rcall(h: &Arc<Host>, sg: &str, op: &str, input: Value) -> Value {
    h.call_with_grant(sg, Some("operator"), Transport::Native, "cr", op, input)
        .unwrap()
        .output
}

/// Direct filesystem append of a forged claim-superseded entry with NO
/// artifact_path, sealing the keyless chain exactly like `append_entry`
/// (sha256(prev_hash + seq + canonical(entry))). Returns the forged seq.
fn forge_supersede_no_artifact(book_path: &str, claim_id: &str, claim_seq: u64) -> u64 {
    let text = std::fs::read_to_string(book_path).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let seq = lines.len() as u64;
    let last: Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    let prev = last["entry_hash"].as_str().unwrap().to_string();
    let entry = json!({
        "kind": "claim-superseded",
        "claim_id": claim_id,
        "supersedes_seq": claim_seq,
        "defeating_probe": {"evidence_ref": "fs-direct-write", "payload_hash": "aa"},
        "forged_via": "direct-filesystem-write",
    });
    let preimage = format!("{prev}{seq}{}", canonical_json(&entry));
    let hash = sha256_hex(preimage.as_bytes());
    let line = canonical_json(&json!({
        "seq": seq, "prev_hash": prev, "entry": entry, "entry_hash": hash,
    }));
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(book_path)
        .unwrap();
    f.write_all((line + "\n").as_bytes()).unwrap();
    seq
}

fn ingest_claim(h: &Arc<Host>, sg: &str, token: &str) -> (String, u64) {
    let out = wcall(
        h,
        sg,
        "ingest-claim",
        json!({
            "fix_evidence": ["operator/probe-7"],
            "proof_script_path": "/opt/op/proof.sh",
            "commit": "a1b2c3d4",
            "description": "legit fix for F-real",
        }),
        token,
    );
    let cid = out["claim_id"].as_str().unwrap().to_string();
    (cid, 0) // first entry in a fresh book
}

// ---------------------------------------------------------------------------
// 1. The exemption is closed: forged supersede without artifact_path fails
//    verify.
// ---------------------------------------------------------------------------

#[test]
fn legacy_exemption_closed_forged_supersede_fails_verify() {
    let h = host();
    let og = operator_grant(&h);
    let b = book("forged");
    let o = open_store(&h, &og, &b);
    let token = o["grant_token"].as_str().unwrap();

    let (cid, claim_seq) = ingest_claim(&h, &og, token);

    // Attacker with direct filesystem write access appends a forged
    // supersede entry carrying no artifact_path (the "legacy" shape).
    let forged_seq = forge_supersede_no_artifact(&b, &cid, claim_seq);

    let v = rcall(&h, &og, "verify", json!({"store_path": b}));
    assert_eq!(
        v["ok"],
        json!(false),
        "legacy exemption still open: forged supersede without artifact_path passed verify: {v}"
    );
    assert_eq!(
        v["break_at_seq"],
        json!(forged_seq),
        "verify must break exactly at the forged entry, not earlier: {v}"
    );
    let reason = v["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("artifact_path"),
        "failure reason must name the missing artifact_path: {reason}"
    );

    // Pinned residual: claim-status is a read view, not an integrity
    // oracle. The forged entry still flips the status; verify is the
    // check that catches the forgery.
    let st = rcall(
        &h,
        &og,
        "claim-status",
        json!({"store_path": b, "claim_id": cid}),
    );
    assert_eq!(st["status"], json!("SUPERSEDED_BY_BYPASS"));

    let _ = std::fs::remove_file(&b);
}

// ---------------------------------------------------------------------------
// 2. No regression: honest supersede with a real, hash-matching artifact
//    still verifies.
// ---------------------------------------------------------------------------

#[test]
fn honest_supersede_with_real_artifact_still_verifies() {
    let h = host();
    let og = operator_grant(&h);
    let b = book("honest");
    let o = open_store(&h, &og, &b);
    let token = o["grant_token"].as_str().unwrap();

    let (cid, _) = ingest_claim(&h, &og, token);

    let artifact = root_dir().join("r6-lane6-honest-probe.bin");
    std::fs::write(&artifact, b"real defeating probe output").unwrap();
    let ph = sha256_hex(b"real defeating probe output");

    let d = wcall(
        &h,
        &og,
        "ingest-defect",
        json!({
            "defect_id": "FD-r6-honest",
            "defeats_claim_id": cid,
            "reproduces_fixed_behavior": true,
            "defeating_probe": {
                "evidence_ref": "probes/real",
                "payload_hash": ph,
                "artifact_path": artifact.to_string_lossy(),
            },
        }),
        token,
    );
    assert_eq!(d["superseded"], json!(cid));

    let v = rcall(&h, &og, "verify", json!({"store_path": b}));
    assert_eq!(v["ok"], json!(true), "honest supersede must verify: {v}");

    let _ = std::fs::remove_file(&b);
    let _ = std::fs::remove_file(&artifact);
}
