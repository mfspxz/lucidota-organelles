//! org-007 — the same scenario suite on all four transports; diff = fail.

use organelle_equivalence::*;

fn unique_base() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("organelle-eq-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn all_four_transports_agree() {
    let base = unique_base();
    let outbox = base.join("outbox").to_string_lossy().into_owned();
    let cas = base.join("cas").to_string_lossy().into_owned();
    let ledger = base.join("eq.jsonl").to_string_lossy().into_owned();
    std::fs::create_dir_all(&outbox).unwrap();
    std::fs::create_dir_all(&cas).unwrap();

    // Deterministic stub mode for model-call on every transport.
    std::env::remove_var("MODEL_API_URL");

    let port = spawn_fixture_server();
    let url = format!("http://127.0.0.1:{port}/");
    let scenarios = build_scenarios(&url, &ledger, &outbox);
    assert_eq!(scenarios.len(), 19);

    let mut adapters: Vec<Box<dyn TransportAdapter>> = vec![
        Box::new(NativeAdapter::new(&outbox, &cas)),
        Box::new(UnixAdapter::new(&outbox, &cas)),
        Box::new(McpAdapter::new(&outbox, &cas)),
        Box::new(RestAdapter::new(&outbox, &cas)),
    ];

    let report = run_equivalence(&scenarios, &mut adapters);
    println!("{}", report.summary());

    assert!(
        report.cross_transport_diffs.is_empty(),
        "cross-transport diffs:\n{}",
        report.cross_transport_diffs.join("\n")
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
    // 19 scenarios x 4 transports = 76 assertions, all passing.
    assert_eq!(report.total_assertions(), 76);

    let _ = std::fs::remove_dir_all(&base);
}
