//! org-007 hostile extension, typed variant (GO-50 Phase 1, family
//! F5 — closes F4-G6).
//!
//! The typed adapters implement `hostile_call`, but the hostile matrix
//! test builds untyped adapters only, so the typed hostile path was
//! implemented, not matrix-run. This test runs the typed hostile
//! suite (grant forgery, escalation, wrong caller, replay, expiry,
//! malformed, empty-grant (F6), cross-organelle, and the `tc.commit`
//! capability gate) against all four TYPED adapters: every hostile
//! case must produce the same denial verdict, the same denial
//! message, and the same receipt shape on native, unix-socket, MCP,
//! and REST.

use organelle_equivalence::*;

#[test]
fn typed_hostile_cases_deny_identically_on_all_transports() {
    let cases = build_typed_hostile_cases();
    assert_eq!(cases.len(), 10);

    let mut adapters: Vec<Box<dyn TransportAdapter>> = vec![
        Box::new(TypedNativeAdapter::new()),
        Box::new(TypedUnixAdapter::new()),
        Box::new(TypedMcpAdapter::new()),
        Box::new(TypedRestAdapter::new()),
    ];

    let report = run_hostile_equivalence(&cases, &mut adapters);
    println!("{}", report.summary());

    assert!(
        report.cross_transport_mismatches.is_empty(),
        "cross-transport receipt-shape mismatches:\n{}",
        report.cross_transport_mismatches.join("\n")
    );
    for t in &report.transports {
        assert!(
            t.failed == 0,
            "transport {} had {} failures:\n{}",
            t.transport,
            t.failed,
            t.failures.join("\n")
        );
    }
    assert!(report.all_green());
    // 10 cases x 4 transports, every case on every transport.
    assert_eq!(report.total_assertions(), 40);
}
