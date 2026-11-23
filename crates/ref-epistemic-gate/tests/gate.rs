//! Public-API gate assembly: verify → receipt → promote/demote,
//! mirroring pt-oracle's gate_assembly proof for the harvested gate.

use ref_epistemic_gate::{Oracle, OracleReceipt, Valence, VerificationGate};

#[test]
fn verify_promote_demote_flow() {
    let mut gate = Oracle::new();
    let hash = [7u8; 32];

    // A real claim verifies Proven under the reference rule set.
    let receipt = gate.verify(&hash, "tester", b"a real claim", &[]).unwrap();
    assert_eq!(receipt.verdict, Valence::Proven);
    assert_eq!(receipt.artifact_hash, hash);

    // One Proven receipt meets quorum 1, not quorum 2.
    assert_eq!(gate.promote(&hash, &[receipt], 1).unwrap(), Valence::Proven);
    let receipt2 = gate.verify(&hash, "tester", b"a real claim", &[]).unwrap();
    assert_eq!(
        gate.promote(&hash, &[receipt2.clone(), receipt2], 2).unwrap(),
        Valence::Proven
    );

    // An empty claim is Tainted by the non_empty rule.
    let bad = gate.verify(&hash, "tester", b"", &[]).unwrap();
    assert_eq!(bad.verdict, Valence::Tainted);

    // Demotion requires a non-empty refutation.
    assert!(gate.demote(&hash, b"").is_err());
    assert_eq!(gate.demote(&hash, b"refuted by capture 2").unwrap(), Valence::Tainted);

    // Receipts for a different artifact do not promote this one.
    let other: Vec<OracleReceipt> = vec![OracleReceipt {
        ts: 0,
        artifact_hash: [9u8; 32],
        agent: "a".into(),
        verdict: Valence::Proven,
        evidence_hashes: vec![],
        findings: vec![],
        absurd_tag: String::new(),
        signature: None,
    }];
    assert_eq!(gate.promote(&hash, &other, 1).unwrap(), Valence::Candidate);
}
