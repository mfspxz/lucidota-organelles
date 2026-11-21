//! org-007 (F4) — the typed scenario suite on all four transports,
//! through the dispatcher's typed projections; outputs AND receipt
//! payloads (truth + provenance) must agree across paths. Diff = fail.

use organelle_equivalence::*;

#[test]
fn typed_transports_agree_on_outputs_and_receipts() {
    let scenarios = build_typed_scenarios();
    assert_eq!(scenarios.len(), 12);

    let mut adapters: Vec<Box<dyn TransportAdapter>> = vec![
        Box::new(TypedNativeAdapter::new()),
        Box::new(TypedUnixAdapter::new()),
        Box::new(TypedMcpAdapter::new()),
        Box::new(TypedRestAdapter::new()),
    ];

    let report = run_typed_equivalence(&scenarios, &mut adapters);
    println!("{}", report.summary());

    assert!(
        report.base.cross_transport_diffs.is_empty(),
        "cross-transport output diffs:\n{}",
        report.base.cross_transport_diffs.join("\n")
    );
    assert!(
        report.receipt_diffs.is_empty(),
        "receipt payload diffs:\n{}",
        report.receipt_diffs.join("\n")
    );
    for t in &report.base.transports {
        assert!(
            t.failed == 0,
            "transport {} had {} failures:\n{}",
            t.transport,
            t.failed,
            t.failures.join("\n")
        );
    }
    assert!(report.all_green());
    // 12 scenarios x 4 transports = 48 output assertions, all passing.
    assert_eq!(report.base.total_assertions(), 48);
}

#[test]
fn receipt_payload_strips_transport_metadata() {
    // The payload comparison is meaningful only if it strips what
    // legitimately differs per transport (id, ts, seq, prev,
    // transport, produced_at) and keeps what must agree (domain
    // outcome + truth + provenance). Build two receipts for the same
    // invocation on different transports and prove the payloads are
    // equal while the receipts themselves differ.
    let mut native = TypedNativeAdapter::new();
    let mut mcp = TypedMcpAdapter::new();
    let input = serde_json::json!({"text": "abc"});
    let out_n = native
        .call("equivalence", &[], "th", "sha256", input.clone())
        .unwrap();
    let out_m = mcp.call("equivalence", &[], "th", "sha256", input).unwrap();
    assert_eq!(
        organelle_manifest::canonical_json(&out_n),
        organelle_manifest::canonical_json(&out_m)
    );
    let rn = native.last_receipt().expect("native receipt");
    let rm = mcp.last_receipt().expect("mcp receipt");
    // The receipts genuinely differ (different ids, transports).
    assert_ne!(rn.id, rm.id);
    assert_ne!(rn.transport, rm.transport);
    // The canonical domain payloads agree exactly.
    assert_eq!(
        organelle_manifest::canonical_json(&receipt_payload(&rn)),
        organelle_manifest::canonical_json(&receipt_payload(&rm))
    );
    // And the payload carries the typed facts: truth + provenance.
    let p = receipt_payload(&rn);
    assert_eq!(p["truth"]["status"], serde_json::json!("proven"));
    assert_eq!(
        p["provenance"]["source"],
        serde_json::json!("computed_locally")
    );
    assert_eq!(
        p["provenance"]["produced_by"],
        serde_json::json!("th@1.0.0")
    );
    assert!(p["provenance"].get("produced_at").is_none());
}
