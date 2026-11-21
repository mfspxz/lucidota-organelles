//! GO-50 Phase 1, family F4 — THE ACCEPTANCE TEST (the gate).
//!
//! Register ref-typed-hash ONCE via `TypedDispatcher::register_typed`
//! and prove it appears in every projection, then prove identical
//! valid input yields an equivalent result through every path:
//!   1. native registry discovery (`host.list_manifests` +
//!      `dispatcher.typed_manifests`)
//!   2. MCP `tools/list` (+ a `tools/call` through the typed path)
//!   3. REST `GET /v1/organelles` + `GET /v1/openapi.json` (+ a
//!      `POST /v1/organelle/call`)
//!   4. unix-socket typed call (the native/unix internal path)
//!   5. full typed equivalence: outputs + receipt payloads agree
//!      across all four transports
//! This test passing is Phase 1's decisive deliverable for F4.
//!
//! Family F5 extends the gate to the SECOND typed organelle
//! (ref-typed-commit, codon `tc`): both organelles are registered
//! once and both must appear everywhere, and the same tc commit
//! input must yield the same commit id on MCP, REST, and unix —
//! converting F4 §10's CLAIMED second-organelle generality into a
//! proven one. Step 5's matrix now carries tc scenarios too
//! (`build_typed_scenarios`, 12 scenarios).

use organelle_equivalence::*;
use organelle_host::Host;
use organelle_typed::{LockRegistry, TypedDispatcher};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

const ABC_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn dispatcher_with_typed_organelles() -> Arc<TypedDispatcher> {
    let host = Host::new();
    let d = TypedDispatcher::new(host, LockRegistry::with_go50());
    d.register_typed(ref_typed_hash::TypedHash::new())
        .expect("typed-hash must register");
    d.register_typed(ref_typed_commit::TypedCommit::new())
        .expect("typed-commit must register");
    Arc::new(d)
}

fn raw_http(port: u16, req: &str) -> (String, Value) {
    let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.lines().next().unwrap().to_string();
    (status, serde_json::from_str(body).unwrap())
}

fn http_get(port: u16, path: &str) -> (String, Value) {
    raw_http(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
    )
}

fn http_post_auth(port: u16, path: &str, grant: &str, body: &Value) -> (String, Value) {
    let text = serde_json::to_string(body).unwrap();
    raw_http(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {grant}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        ),
    )
}

#[test]
fn acceptance_register_once_appears_everywhere_and_agrees() {
    // --- register once ------------------------------------------------
    let d = dispatcher_with_typed_organelles();

    // --- 1. native registry discovery ---------------------------------
    let base_manifests = d.host().list_manifests();
    assert!(
        base_manifests.iter().any(|m| m.codon == "th"),
        "typed-hash must appear in host.list_manifests (native discovery)"
    );
    assert!(
        base_manifests.iter().any(|m| m.codon == "tc"),
        "typed-commit must appear in host.list_manifests (native discovery)"
    );
    let typed = d.typed_manifests();
    assert_eq!(typed.len(), 2, "typed registry holds exactly th + tc");
    let th = typed.iter().find(|m| m.base.codon == "th").unwrap();
    assert_eq!(th.typed_contracts.len(), 2);
    assert_eq!(
        th.ontology.go,
        vec!["TOOL", "PROCESS", "EVIDENCE", "IDENTITY"]
    );
    let tc = typed.iter().find(|m| m.base.codon == "tc").unwrap();
    assert_eq!(tc.typed_contracts.len(), 3);
    assert_eq!(
        tc.ontology.go,
        vec!["TOOL", "PROCESS", "EVIDENCE", "ANCHOR"]
    );

    // --- 2. MCP tools/list + tools/call --------------------------------
    let tools = surface_mcp::generate_tools_typed(&d);
    assert_eq!(tools.len(), 5);
    assert!(tools.iter().any(|t| t.name == "typed-hash.sha256"));
    assert!(tools.iter().any(|t| t.name == "typed-hash.verify"));
    assert!(tools.iter().any(|t| t.name == "typed-commit.commit"));
    assert!(tools.iter().any(|t| t.name == "typed-commit.get"));
    assert!(tools.iter().any(|t| t.name == "typed-commit.verify"));
    let list_msg = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    });
    let list_resp = surface_mcp::dispatch_typed(&d, &tools, &list_msg).expect("tools/list");
    let listed = list_resp["result"]["tools"].as_array().unwrap();
    assert_eq!(listed.len(), 5);
    assert!(listed.iter().any(|t| t["name"] == "typed-hash.sha256"));
    assert!(listed.iter().any(|t| t["name"] == "typed-commit.commit"));

    let grant = d.host().issue_grant("acceptance", vec![], 300);
    let call_msg = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "typed-hash.sha256",
                   "arguments": {"grant": grant, "caller": "acceptance", "text": "abc"}},
    });
    let call_resp = surface_mcp::dispatch_typed(&d, &tools, &call_msg).expect("tools/call");
    assert_eq!(call_resp["result"]["isError"], serde_json::json!(false));
    let mcp_text = call_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(mcp_text.contains(ABC_HEX), "{mcp_text}");
    assert_eq!(
        call_resp["result"]["truth"]["status"],
        serde_json::json!("proven")
    );

    // F5: the same register-once proof for the second organelle — a
    // tc.commit over MCP. The commit id is captured: REST and unix
    // must return the SAME id for the same input (content-addressed,
    // idempotent), proving cross-path agreement on tc, not just th.
    let grant_tc = d
        .host()
        .issue_grant("acceptance", vec!["tc.commit".to_string()], 300);
    let tc_call_msg = serde_json::json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "typed-commit.commit",
                   "arguments": {"grant": grant_tc, "caller": "acceptance",
                                 "key": "greeting", "value": "hello", "parent": ""}},
    });
    let tc_call_resp =
        surface_mcp::dispatch_typed(&d, &tools, &tc_call_msg).expect("tc tools/call");
    assert_eq!(tc_call_resp["result"]["isError"], serde_json::json!(false));
    let mcp_tc_text = tc_call_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    let mcp_tc_out: Value = serde_json::from_str(&mcp_tc_text).unwrap();
    let commit_id = mcp_tc_out["commit_id"].as_str().unwrap().to_string();
    assert_eq!(mcp_tc_out["seq"], serde_json::json!(1));
    assert_eq!(
        tc_call_resp["result"]["truth"]["status"],
        serde_json::json!("proven")
    );
    assert_eq!(
        tc_call_resp["result"]["provenance"]["produced_by"],
        serde_json::json!("tc@1.0.0")
    );

    // --- 3. REST /v1/organelles + /v1/openapi.json + call --------------
    let srv = surface_rest::spawn_typed(d.clone(), 0).unwrap();
    let (status, body) = http_get(srv.port(), "/v1/organelles");
    assert!(status.contains("200"), "{status}");
    let orgs = body["organelles"].as_array().unwrap();
    assert_eq!(orgs.len(), 2);
    let th_entry = orgs.iter().find(|o| o["base"]["codon"] == "th").unwrap();
    assert_eq!(
        th_entry["ontology"]["go"],
        serde_json::json!(["TOOL", "PROCESS", "EVIDENCE", "IDENTITY"])
    );
    let tc_entry = orgs.iter().find(|o| o["base"]["codon"] == "tc").unwrap();
    assert_eq!(
        tc_entry["ontology"]["go"],
        serde_json::json!(["TOOL", "PROCESS", "EVIDENCE", "ANCHOR"])
    );
    assert_eq!(tc_entry["typed_contracts"].as_array().unwrap().len(), 3);

    let (status, openapi) = http_get(srv.port(), "/v1/openapi.json");
    assert!(status.contains("200"), "{status}");
    assert_eq!(openapi["openapi"], serde_json::json!("3.0.0"));
    assert!(openapi["paths"]["/v1/organelle/th/sha256"].is_object());
    assert!(openapi["paths"]["/v1/organelle/th/verify"].is_object());
    assert_eq!(
        openapi["paths"]["/v1/organelle/th/sha256"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["required"],
        serde_json::json!(["algorithm", "hex", "input_bytes"])
    );
    assert!(openapi["paths"]["/v1/organelle/tc/commit"].is_object());
    assert!(openapi["paths"]["/v1/organelle/tc/get"].is_object());
    assert!(openapi["paths"]["/v1/organelle/tc/verify"].is_object());
    assert_eq!(
        openapi["paths"]["/v1/organelle/tc/commit"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["required"],
        serde_json::json!(["commit_id", "key", "value_hash", "parent", "seq"])
    );
    assert_eq!(
        openapi["paths"]["/v1/organelle/tc/commit"]["post"]["x-go50-ontology"]["go"],
        serde_json::json!(["TOOL", "PROCESS", "EVIDENCE", "ANCHOR"])
    );

    let grant2 = d.host().issue_grant("acceptance", vec![], 300);
    let (status, body) = http_post_auth(
        srv.port(),
        "/v1/organelle/call",
        &grant2,
        &serde_json::json!({
            "caller": "acceptance", "codon": "th", "op": "sha256",
            "input": {"text": "abc"},
        }),
    );
    assert!(status.contains("200"), "{status} {body}");
    assert_eq!(body["ok"], serde_json::json!(true));
    assert_eq!(body["output"]["hex"], serde_json::json!(ABC_HEX));
    assert_eq!(body["truth"]["status"], serde_json::json!("proven"));
    assert_eq!(
        body["provenance"]["produced_by"],
        serde_json::json!("th@1.0.0")
    );

    // F5: same commit over REST — the commit id must equal the MCP
    // one (content-addressed, idempotent across paths).
    let grant_tc2 = d
        .host()
        .issue_grant("acceptance", vec!["tc.commit".to_string()], 300);
    let (status, body) = http_post_auth(
        srv.port(),
        "/v1/organelle/call",
        &grant_tc2,
        &serde_json::json!({
            "caller": "acceptance", "codon": "tc", "op": "commit",
            "input": {"key": "greeting", "value": "hello", "parent": ""},
        }),
    );
    assert!(status.contains("200"), "{status} {body}");
    assert_eq!(body["ok"], serde_json::json!(true));
    assert_eq!(body["output"]["commit_id"], serde_json::json!(commit_id));
    assert_eq!(body["output"]["seq"], serde_json::json!(1));
    assert_eq!(body["truth"]["status"], serde_json::json!("proven"));
    assert_eq!(
        body["provenance"]["produced_by"],
        serde_json::json!("tc@1.0.0")
    );
    srv.shutdown();

    // --- 4. unix-socket typed call -------------------------------------
    let mut sock = std::env::temp_dir();
    sock.push(format!("organelle-acceptance-{}.sock", std::process::id()));
    let usrv = surface_unix::spawn_server_typed(d.clone(), &sock).unwrap();
    let grant3 = d.host().issue_grant("acceptance", vec![], 300);
    let uresp = surface_unix::UnixClient::call(
        &sock,
        &surface_unix::WireRequest {
            id: 1,
            caller: "acceptance".into(),
            grant: grant3,
            codon: "th".into(),
            op: "sha256".into(),
            input: serde_json::json!({"text": "abc"}),
        },
    )
    .unwrap();
    assert!(uresp.ok, "{uresp:?}");
    assert_eq!(uresp.output.unwrap()["hex"], serde_json::json!(ABC_HEX));
    assert_eq!(uresp.truth.unwrap()["status"], serde_json::json!("proven"));

    // F5: same commit over unix — same commit id a third time — then
    // a verify over the same socket, proving the committed state is
    // visible across ops on the shared dispatcher.
    let grant_tc3 = d
        .host()
        .issue_grant("acceptance", vec!["tc.commit".to_string()], 300);
    let ucresp = surface_unix::UnixClient::call(
        &sock,
        &surface_unix::WireRequest {
            id: 2,
            caller: "acceptance".into(),
            grant: grant_tc3,
            codon: "tc".into(),
            op: "commit".into(),
            input: serde_json::json!({"key": "greeting", "value": "hello", "parent": ""}),
        },
    )
    .unwrap();
    assert!(ucresp.ok, "{ucresp:?}");
    assert_eq!(
        ucresp.output.unwrap()["commit_id"],
        serde_json::json!(commit_id)
    );
    assert_eq!(ucresp.truth.unwrap()["status"], serde_json::json!("proven"));
    let grant4 = d.host().issue_grant("acceptance", vec![], 300);
    let uvresp = surface_unix::UnixClient::call(
        &sock,
        &surface_unix::WireRequest {
            id: 3,
            caller: "acceptance".into(),
            grant: grant4,
            codon: "tc".into(),
            op: "verify".into(),
            input: serde_json::json!({"commit_id": commit_id}),
        },
    )
    .unwrap();
    assert!(uvresp.ok, "{uvresp:?}");
    let vout = uvresp.output.unwrap();
    assert_eq!(vout["found"], serde_json::json!(true));
    assert_eq!(vout["hash_matches"], serde_json::json!(true));
    assert_eq!(vout["parent_known"], serde_json::json!(true));
    usrv.shutdown();

    // --- 5. full typed equivalence across all four transports ---------
    let scenarios = build_typed_scenarios();
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
        "output diffs:\n{}",
        report.base.cross_transport_diffs.join("\n")
    );
    assert!(
        report.receipt_diffs.is_empty(),
        "receipt diffs:\n{}",
        report.receipt_diffs.join("\n")
    );
    for t in &report.base.transports {
        assert_eq!(
            t.failed, 0,
            "transport {} failures: {:?}",
            t.transport, t.failures
        );
    }
    assert!(report.all_green());
}
