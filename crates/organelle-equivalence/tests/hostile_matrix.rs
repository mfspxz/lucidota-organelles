//! org-007 hostile extension — adversarial authority equivalence.
//!
//! Every hostile case must produce the same denial verdict, the same
//! denial message, and the same receipt shape on all four transports.
//! A transport that allows what the others deny — or denies differently —
//! fails the matrix.

use organelle_equivalence::*;

fn unique_base() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("organelle-hx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn hostile_cases_deny_identically_on_all_transports() {
    let base = unique_base();
    let outbox = base.join("outbox").to_string_lossy().into_owned();
    let cas = base.join("cas").to_string_lossy().into_owned();
    let inside_ledger = base.join("hx.jsonl").to_string_lossy().into_owned();
    std::fs::create_dir_all(&outbox).unwrap();
    std::fs::create_dir_all(&cas).unwrap();
    // Deliberately outside the harness write roots (the roots cover `base`).
    let outside_ledger = std::env::temp_dir()
        .join(format!("organelle-hx-outside-{}", std::process::id()))
        .join("eq.jsonl")
        .to_string_lossy()
        .into_owned();

    // Deterministic stub mode for model-call on every transport.
    std::env::remove_var("MODEL_API_URL");

    let cases = build_hostile_cases(&inside_ledger, &outside_ledger);
    assert_eq!(cases.len(), 13);

    let mut adapters: Vec<Box<dyn TransportAdapter>> = vec![
        Box::new(NativeAdapter::new(&outbox, &cas)),
        Box::new(UnixAdapter::new(&outbox, &cas)),
        Box::new(McpAdapter::new(&outbox, &cas)),
        Box::new(RestAdapter::new(&outbox, &cas)),
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
    // 13 cases: 11 run on 4 transports, non-declared-transport on 3,
    // nq-declared-ok (positive control) on 1 = 48 per-transport assertions.
    // The 12 cross-transport receipt-shape comparisons pass silently on
    // green (they only add to the total as mismatches, like the happy path).
    assert_eq!(report.total_assertions(), 48);

    let _ = std::fs::remove_dir_all(&base);
}
