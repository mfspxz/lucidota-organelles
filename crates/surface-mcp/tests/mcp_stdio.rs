//! org-005 — MCP surface over a real child process speaking JSON-RPC 2.0.
//!
//! P0: the child authenticates callers with capability grants. The test
//! seeds the child's grant key via ORGANELLE_GRANT_KEY and mints grants
//! in-process with the same key (the operator's out-of-band issuance path).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;

/// Test-only grant key (NOT a secret — 32 zero bytes, hex).
const TEST_GRANT_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

fn test_host() -> Arc<organelle_host::Host> {
    organelle_host::Host::with_grant_key([0u8; 32])
}

/// Mint a grant the child will accept (same key as the child's).
fn grant(caller: &str, caps: &[&str]) -> String {
    test_host().issue_grant(
        caller,
        caps.iter().map(|s| s.to_string()).collect(),
        300,
    )
}

struct Mcp {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl Mcp {
    fn bin_path() -> std::path::PathBuf {
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_organelle_mcp_stdio") {
            return p.into();
        }
        // Fallback: <target>/debug/deps/<test> -> <target>/debug/organelle-mcp-stdio
        let mut p = std::env::current_exe().expect("current exe");
        p.pop();
        p.pop();
        p.push("organelle-mcp-stdio");
        p
    }

    fn spawn() -> Self {
        let bin = Self::bin_path();
        assert!(bin.exists(), "mcp stdio binary missing at {}", bin.display());
        let mut child = Command::new(bin)
            .env("ORGANELLE_GRANT_KEY", TEST_GRANT_KEY_HEX)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mcp stdio server");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Mcp { child, stdin, reader: BufReader::new(stdout), next_id: 1 }
    }

    fn request(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        let msg = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{}", serde_json::to_string(&msg).unwrap()).unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).unwrap()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn initialize_and_list() {
    let mut m = Mcp::spawn();
    let init = m.request("initialize", serde_json::json!({}));
    assert_eq!(init["result"]["serverInfo"]["name"], serde_json::json!("parkwreck-organelle-host"));
    let list = m.request("tools/list", serde_json::json!({}));
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 19, "{tools:?}"); // 4+1+1+1+2+2+2+1+1+1+1+2 across 12 organelles
}

#[test]
fn call_tool_ok() {
    let mut m = Mcp::spawn();
    let _ = m.request("initialize", serde_json::json!({}));
    let g = grant("mcp-test", &[]);
    let out = m.request(
        "tools/call",
        serde_json::json!({
            "name": "text-transform.transform",
            "arguments": {"text": "hi", "mode": "upper", "caller": "mcp-test", "grant": g},
        }),
    );
    assert_eq!(out["result"]["isError"], serde_json::json!(false));
    let text = out["result"]["content"][0]["text"].as_str().unwrap();
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(v["result"], serde_json::json!("HI"));
}

#[test]
fn call_denied_is_error_not_crash() {
    let mut m = Mcp::spawn();
    let _ = m.request("initialize", serde_json::json!({}));
    // No grant at all -> fail-closed denial, not a crash, not a pass.
    let out = m.request(
        "tools/call",
        serde_json::json!({
            "name": "kv-store.put",
            "arguments": {"key": "a", "value": 1, "caller": "mcp-test"},
        }),
    );
    assert_eq!(out["result"]["isError"], serde_json::json!(true));
    assert!(out["result"]["content"][0]["text"].as_str().unwrap().contains("Denied"));
}

#[test]
fn forged_grant_over_stdio_denied() {
    let mut m = Mcp::spawn();
    let _ = m.request("initialize", serde_json::json!({}));
    // Valid grant, then tamper the payload: signature must fail at the
    // real process boundary too.
    let good = grant("mcp-test", &["kv.write"]);
    let (payload_hex, tag) = good.split_once('.').unwrap();
    let mut chars: Vec<char> = payload_hex.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    let forged = format!("{}.{}", chars.into_iter().collect::<String>(), tag);
    let out = m.request(
        "tools/call",
        serde_json::json!({
            "name": "kv-store.put",
            "arguments": {"key": "a", "value": 1, "caller": "mcp-test", "grant": forged},
        }),
    );
    assert_eq!(out["result"]["isError"], serde_json::json!(true));
    let text = out["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Denied"), "{text}");
    assert!(text.contains("signature"), "{text}");
}

#[test]
fn unknown_tool_and_method() {
    let mut m = Mcp::spawn();
    let _ = m.request("initialize", serde_json::json!({}));
    let out = m.request("tools/call", serde_json::json!({"name": "nope.nope", "arguments": {}}));
    assert_eq!(out["error"]["code"], serde_json::json!(-32602));
    let out2 = m.request("frobnicate", serde_json::json!({}));
    assert_eq!(out2["error"]["code"], serde_json::json!(-32601));
}

#[test]
fn kv_state_within_session() {
    let mut m = Mcp::spawn();
    let _ = m.request("initialize", serde_json::json!({}));
    let g = grant("t", &["kv.write"]);
    let put = m.request(
        "tools/call",
        serde_json::json!({
            "name": "kv-store.put",
            "arguments": {"key": "k", "value": "v", "caller": "t", "grant": g},
        }),
    );
    assert_eq!(put["result"]["isError"], serde_json::json!(false));
    let g2 = grant("t", &[]);
    let get = m.request(
        "tools/call",
        serde_json::json!({
            "name": "kv-store.get",
            "arguments": {"key": "k", "caller": "t", "grant": g2},
        }),
    );
    let text = get["result"]["content"][0]["text"].as_str().unwrap();
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(v["value"], serde_json::json!("v"));
}
