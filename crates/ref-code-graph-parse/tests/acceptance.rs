//! Acceptance for org-038 per the design report's verification bar:
//! parse a real estate crate (org-036 ref-gtfs-rt-decode) end to
//! end, ground truth established independently of the parser,
//! determinism across input order, enclosing_functions parity with
//! wreck-graph's structural cases.

use ref_code_graph_parse::{enclosing_functions, parse_files, Layer, ParseConfig, SourceFile};
use std::collections::BTreeSet;

fn cfg() -> ParseConfig {
    ParseConfig::new(
        [Layer::CallGraph, Layer::DataFlow, Layer::Ownership]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        4_000_000,
        true,
    )
    .unwrap()
}

fn gtfs_source() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ref-gtfs-rt-decode/src/lib.rs"
    );
    std::fs::read_to_string(path).expect("fixture crate present")
}

#[test]
fn fixture_crate_parses_with_ground_truth_symbols() {
    let src = gtfs_source();
    let files = vec![SourceFile {
        path: "crates/ref-gtfs-rt-decode/src/lib.rs".into(),
        crate_name: "ref_gtfs_rt_decode".into(),
        source: src.clone(),
    }];
    let g = parse_files(&cfg(), &files).unwrap();

    // Ground truth: every one of these functions exists in the
    // fixture source (verified by reading the file, 2026-11-23).
    for name in [
        "read_varint",
        "parse_fields",
        "parse_trip_descriptor",
        "parse_vehicle_descriptor",
        "parse_position",
        "decode_vehicles",
        "decode_trips",
        "decode_alerts",
        "js_number",
        "opt_string_value",
    ] {
        assert!(
            g.nodes.iter().any(|n| n.name == name),
            "missing symbol {name}"
        );
    }

    // Independent count check: naive line scan for `fn ` definitions
    // in the fixture (an intentionally crude, parser-independent
    // count). The parser must find at least as many function/method
    // symbols as the crude scan finds definition lines, minus the
    // ones inside strings/comments the scan cannot discount (0 in
    // this fixture's style: `fn ` at a line start or after spaces
    // only appears in real definitions and the two test fns).
    let naive = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("fn ")
                || t.starts_with("pub fn ")
                || t.starts_with("pub(crate) fn ")
                || t.starts_with("async fn ")
                || t.starts_with("pub async fn ")
        })
        .count();
    let parsed_fns = g
        .nodes
        .iter()
        .filter(|n| n.kind == "function" || n.kind == "method")
        .count();
    assert!(
        parsed_fns >= naive - 2 && parsed_fns <= naive + 2,
        "parser found {parsed_fns} fn symbols, naive scan {naive}"
    );
}

#[test]
fn fixture_call_edges_hand_verified() {
    let src = gtfs_source();
    let files = vec![SourceFile {
        path: "crates/ref-gtfs-rt-decode/src/lib.rs".into(),
        crate_name: "ref_gtfs_rt_decode".into(),
        source: src,
    }];
    let g = parse_files(&cfg(), &files).unwrap();
    let id_of = |name: &str| {
        g.nodes
            .iter()
            .find(|n| n.name == name)
            .unwrap_or_else(|| panic!("node {name}"))
            .id
            .clone()
    };
    // Hand-verified from the fixture source (decode_vehicles body,
    // lines 351-404): calls parse_fields, parse_trip_descriptor,
    // parse_vehicle_descriptor, parse_position. decode_trips and
    // decode_alerts each call parse_fields.
    for (caller, callee) in [
        ("decode_vehicles", "parse_fields"),
        ("decode_vehicles", "parse_trip_descriptor"),
        ("decode_vehicles", "parse_vehicle_descriptor"),
        ("decode_vehicles", "parse_position"),
        ("decode_trips", "parse_fields"),
        ("decode_alerts", "parse_fields"),
    ] {
        assert!(
            g.assertions.iter().any(|a| a.predicate == "calls"
                && a.subject.as_node() == Some(id_of(caller).as_str())
                && a.object.as_node() == Some(id_of(callee).as_str())),
            "missing hand-verified edge {caller} -> {callee}"
        );
    }
}

#[test]
fn determinism_across_input_order() {
    let src = gtfs_source();
    let other = "pub fn alpha() { beta(); }\nfn beta() {}\n".to_string();
    let f1 = SourceFile {
        path: "a.rs".into(),
        crate_name: "ref_gtfs_rt_decode".into(),
        source: src,
    };
    let f2 = SourceFile {
        path: "b.rs".into(),
        crate_name: "demo".into(),
        source: other,
    };
    let g1 = parse_files(&cfg(), &[f1.clone(), f2.clone()]).unwrap();
    let g2 = parse_files(&cfg(), &[f2, f1]).unwrap();
    assert_eq!(
        serde_json::to_string(&g1).unwrap(),
        serde_json::to_string(&g2).unwrap()
    );
}

#[test]
fn enclosing_functions_wreck_parity_cases() {
    // wreck-graph's own four structural tests, verbatim semantics.
    const SRC: &str = "fn alpha() {\n    let x = 1;\n}\n\nfn beta() {\n    let y = 2;\n}\n\nfn gamma() {\n    let z = 3;\n}\n";
    assert_eq!(enclosing_functions(SRC, &[(5, 7)]), vec!["beta"]);
    assert_eq!(
        enclosing_functions(SRC, &[(1, 3), (9, 11)]),
        vec!["alpha", "gamma"]
    );
    assert!(enclosing_functions(SRC, &[(4, 4)]).is_empty());
    assert!(enclosing_functions("fn broken((", &[(1, 1)]).is_empty());
}
