//! Signed gate receipts (ported 2026-11-23 from pt-oracle commit 1e22c3f).
//!
//! The forgery test below is the wave-1 named defect: hand-built receipts
//! used to promote. The tests pin the fixed behaviour: gate-issued receipts
//! promote, forged / tampered / foreign receipts do not, and third parties
//! can verify with the public key.

use ref_epistemic_gate::{
    verify_receipt_signature, Oracle, OracleReceipt, Valence, VerificationGate,
};

fn fabricated_receipt(agent: &str, signature: Option<Vec<u8>>) -> OracleReceipt {
    OracleReceipt {
        ts: 0,
        artifact_hash: [9u8; 32],
        agent: agent.into(),
        verdict: Valence::Proven,
        evidence_hashes: vec![],
        findings: vec!["I made this up".into()],
        absurd_tag: "oracle:v1:1".into(),
        signature,
    }
}

#[test]
fn fabricated_receipts_must_not_promote() {
    let mut oracle = Oracle::new();
    // unsigned fabrication
    let forged = vec![fabricated_receipt("mallory-1", None), fabricated_receipt("mallory-2", None)];
    assert_eq!(oracle.promote(&[9u8; 32], &forged, 2).unwrap(), Valence::Candidate);
    // garbage-signature fabrication
    let forged = vec![
        fabricated_receipt("mallory-1", Some(vec![7u8; 64])),
        fabricated_receipt("mallory-2", Some(vec![9u8; 64])),
    ];
    assert_eq!(oracle.promote(&[9u8; 32], &forged, 2).unwrap(), Valence::Candidate);
    assert!(!verify_receipt_signature(&forged[0], &oracle.public_key()));
}

#[test]
fn legit_gate_receipts_promote_and_verify_publicly() {
    let mut oracle = Oracle::new();
    let hash = [9u8; 32];
    let r1 = oracle.verify(&hash, "agent-a", b"a real claim", &[]).unwrap();
    let r2 = oracle.verify(&hash, "agent-b", b"another real claim", &[]).unwrap();
    // third-party check with only the gate's public key
    assert!(verify_receipt_signature(&r1, &oracle.public_key()));
    assert!(verify_receipt_signature(&r2, &oracle.public_key()));
    assert_eq!(oracle.promote(&hash, &[r1, r2], 2).unwrap(), Valence::Proven);
}

#[test]
fn tampered_receipt_is_rejected() {
    let mut oracle = Oracle::new();
    let hash = [9u8; 32];
    let legit = oracle.verify(&hash, "agent-a", b"a real claim", &[]).unwrap();
    // flip the agent identity after signing
    let mut tampered = legit.clone();
    tampered.agent = "mallory".into();
    assert!(!verify_receipt_signature(&tampered, &oracle.public_key()));
    assert_eq!(oracle.promote(&hash, &[tampered], 1).unwrap(), Valence::Candidate);
    // flip a finding after signing
    let mut tampered = legit;
    tampered.findings.push("extra finding".into());
    assert!(!verify_receipt_signature(&tampered, &oracle.public_key()));
    assert_eq!(oracle.promote(&hash, &[tampered], 1).unwrap(), Valence::Candidate);
}

#[test]
fn foreign_gate_receipt_is_rejected() {
    let mut mine = Oracle::new();
    let mut other = Oracle::new();
    let hash = [9u8; 32];
    let foreign = other.verify(&hash, "agent-a", b"a real claim", &[]).unwrap();
    assert!(verify_receipt_signature(&foreign, &other.public_key()));
    assert!(!verify_receipt_signature(&foreign, &mine.public_key()));
    assert_eq!(mine.promote(&hash, &[foreign], 1).unwrap(), Valence::Candidate);
}
