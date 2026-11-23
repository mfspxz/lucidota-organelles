//! End-to-end USE of pt-forged's real function, driven by the treatment
//! lane: run the evidence gate over realistic status claims of the kind
//! this estate actually writes, and print every verdict. Run with
//! `--nocapture` for the evidence table.

use ref_evidence_gate::gate;

#[test]
fn gate_over_realistic_claims() {
    let cases: &[(&str, &str, bool)] = &[
        // Broad unscoped overclaim — the thing this gate exists to stop.
        ("the whole system is 100% production ready", "PASS", true),
        // Scoped, checkable claims with terminal statuses.
        ("golden path regression gate passes on the proof kernel", "VERIFIED", true),
        ("status ledger spine authority check", "in_progress", true),
        // Broad wording saved by a named scope, killed by an unknown schema.
        ("the entire canonical graph scanner suite finished", "PASS", false),
        // Gibberish status never admits.
        ("golden path check", "done-ish", true),
    ];
    for (claim, status, schema) in cases {
        let v = gate(claim, status, *schema);
        println!(
            "claim={claim:?} status={status:?} schema={schema} -> admitted={} claim_class={:?} status_class={:?} blockers={:?}",
            v.admitted, v.claim_class, v.status_class, v.blockers
        );
    }
    // The headline behaviours:
    assert!(!gate("the whole system is 100% production ready", "PASS", true).admitted);
    assert!(gate("golden path regression gate passes on the proof kernel", "VERIFIED", true).admitted);
}
