//! org-005 — MCP surface generator.
//!
//! Generates MCP tool definitions from organelle manifests (one tool per
//! `codon.op`) and serves them over JSON-RPC 2.0 on stdio. The generator is
//! data-driven: `generate_tools(&host)` reflects whatever is registered.

use organelle_host::Host;
use serde_json::Value;
use std::io::{BufRead, Write};
use std::sync::Arc;

/// One generated MCP tool: `{organelle-name}.{op}`.
#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub codon: String,
    pub op: String,
}

/// Generate the tool list from currently registered (routed) manifests.
pub fn generate_tools(host: &Host) -> Vec<McpTool> {
    let mut tools = Vec::new();
    for m in host.list_manifests() {
        for c in &m.contracts {
            // The wire schema gains the envelope fields the server needs.
            //
            // P0: authority is unforgeable at this boundary. The envelope
            // carries ONLY a host-issued `grant` (plus an optional `caller`
            // identity claim, which is bound to the grant's subject). There
            // is no `capabilities` field: caller-supplied capability claims
            // are never honored.
            let mut schema = c.input_schema.clone();
            if let Some(obj) = schema.as_object_mut() {
                let props = obj
                    .entry("properties")
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if let Some(p) = props.as_object_mut() {
                    p.entry("grant").or_insert(serde_json::json!({"type": "string"}));
                    p.entry("caller").or_insert(serde_json::json!({"type": "string"}));
                }
            }
            tools.push(McpTool {
                name: format!("{}.{}", m.name, c.op),
                description: format!("{} — {}", m.description, c.description),
                input_schema: schema,
                codon: m.codon.clone(),
                op: c.op.clone(),
            });
        }
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

fn rpc_result(id: &Value, result: Value) -> Value {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: &Value, code: i64, message: String) -> Value {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Dispatch one JSON-RPC message against the host. Returns `None` for
/// notifications (no `id`) — the caller sends no response. Pure w.r.t. the
/// wire: `serve_stdio` is just this function over stdin/stdout, and the
/// equivalence harness calls it directly in-process.
pub fn dispatch(host: &Host, tools: &[McpTool], msg: &Value) -> Option<Value> {
    let id = msg.get("id")?.clone();
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let out = match method {
        "initialize" => rpc_result(
            &id,
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "parkwreck-organelle-host", "version": "1.0.0"},
            }),
        ),
        "tools/list" => rpc_result(
            &id,
            serde_json::json!({
                "tools": tools.iter().map(|t| serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                })).collect::<Vec<_>>(),
            }),
        ),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(Value::Object(serde_json::Map::new()));
            match tools.iter().find(|t| t.name == name) {
                None => rpc_error(&id, -32602, format!("unknown tool {name}")),
                Some(tool) => {
                    // P0: authenticate at the transport boundary. The grant
                    // is the only source of authority; any caller-supplied
                    // `capabilities` in the arguments are ignored (stripped
                    // like the rest of the envelope before schema dispatch).
                    let grant = args
                        .get("grant")
                        .and_then(|g| g.as_str())
                        .unwrap_or("")
                        .to_string();
                    let caller_claim = args
                        .get("caller")
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_string());
                    let mut input = args;
                    if let Some(obj) = input.as_object_mut() {
                        obj.remove("grant");
                        obj.remove("caller");
                        obj.remove("capabilities");
                    }
                    match host.call_with_grant(&grant, caller_claim.as_deref(), &tool.codon, &tool.op, input) {
                        Ok(output) => rpc_result(
                            &id,
                            serde_json::json!({
                                "content": [{"type": "text", "text": organelle_manifest::canonical_json(&output)}],
                                "isError": false,
                            }),
                        ),
                        Err(e) => rpc_result(
                            &id,
                            serde_json::json!({
                                "content": [{"type": "text", "text": format!("{:?}: {}", e.verdict, e.reason)}],
                                "isError": true,
                            }),
                        ),
                    }
                }
            }
        }
        "ping" => rpc_result(&id, serde_json::json!({})),
        _ => rpc_error(&id, -32601, format!("method not found: {method}")),
    };
    Some(out)
}

/// Serve JSON-RPC 2.0 over stdin/stdout (line-delimited). Handles
/// `initialize`, `tools/list`, `tools/call`, `ping`. Notifications (no id)
/// are acknowledged silently. Unknown methods -> -32601.
pub fn serve_stdio(host: Arc<Host>) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let tools = generate_tools(&host);
    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let out = rpc_error(&Value::Null, -32700, format!("parse error: {e}"));
                writeln!(stdout, "{}", serde_json::to_string(&out).unwrap())?;
                stdout.flush()?;
                continue;
            }
        };
        if let Some(out) = dispatch(&host, &tools, &msg) {
            writeln!(stdout, "{}", serde_json::to_string(&out).unwrap())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Arc<Host> {
        let h = Host::new();
        h.register(ref_kv_store::organelle()).unwrap();
        h.register(ref_text_transform::organelle()).unwrap();
        h.register(ref_hash_seal::organelle()).unwrap();
        h
    }

    #[test]
    fn generates_one_tool_per_op() {
        let h = host();
        let tools = generate_tools(&h);
        // kv: 4 ops, tt: 1, hs: 2
        assert_eq!(tools.len(), 7);
        assert!(tools.iter().any(|t| t.name == "kv-store.put"));
        assert!(tools.iter().any(|t| t.name == "text-transform.transform"));
        assert!(tools.iter().any(|t| t.name == "hash-seal.verify"));
        let put = tools.iter().find(|t| t.name == "kv-store.put").unwrap();
        assert_eq!(put.codon, "kv");
        assert_eq!(put.op, "put");
    }

    #[test]
    fn tool_schemas_carry_envelope() {
        let h = host();
        let tools = generate_tools(&h);
        let t = &tools[0];
        assert!(t.input_schema["properties"]["grant"].is_object());
        assert!(t.input_schema["properties"]["caller"].is_object());
        // The forgeable field is gone from the advertised schema.
        assert!(t.input_schema["properties"].get("capabilities").is_none());
    }

    /// tools/call with a grant-bearing envelope; returns the result text and
    /// whether the call errored.
    fn tools_call(
        h: &Host,
        tools: &[McpTool],
        id: u64,
        tool_name: &str,
        args: Value,
    ) -> (bool, String) {
        let msg = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool_name, "arguments": args},
        });
        let resp = dispatch(h, tools, &msg).expect("response");
        if let Some(err) = resp.get("error") {
            return (true, format!("jsonrpc: {err}"));
        }
        let result = &resp["result"];
        let is_error = result["isError"].as_bool().unwrap_or(false);
        let text = result["content"][0]["text"].as_str().unwrap_or("").to_string();
        (is_error, text)
    }

    fn kv_put_args(h: &Host, caller: &str, caps: &[&str], grant_override: Option<String>) -> Value {
        let grant = grant_override.unwrap_or_else(|| {
            h.issue_grant(caller, caps.iter().map(|s| s.to_string()).collect(), 300)
        });
        serde_json::json!({
            "grant": grant,
            "caller": caller,
            "key": "a",
            "value": 1,
        })
    }

    #[test]
    fn granted_call_succeeds() {
        let h = host();
        let tools = generate_tools(&h);
        let (is_err, text) = tools_call(
            &h, &tools, 1, "kv-store.put",
            kv_put_args(&h, "test", &["kv.write"], None),
        );
        assert!(!is_err, "{text}");
        assert!(text.contains("\"ok\":true"), "{text}");
    }

    #[test]
    fn forged_grant_denied() {
        let h = host();
        let tools = generate_tools(&h);
        let good = h.issue_grant("test", vec!["kv.write".to_string()], 300);
        let (payload_hex, tag) = good.split_once('.').unwrap();
        let mut chars: Vec<char> = payload_hex.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        let forged = format!("{}.{}", chars.into_iter().collect::<String>(), tag);
        let (is_err, text) = tools_call(
            &h, &tools, 1, "kv-store.put",
            kv_put_args(&h, "test", &["kv.write"], Some(forged)),
        );
        assert!(is_err);
        assert!(text.contains("Denied"), "{text}");
        assert!(text.contains("signature"), "{text}");
    }

    #[test]
    fn escalated_capability_denied() {
        let h = host();
        let tools = generate_tools(&h);
        // Valid grant, but it confers no kv.write -> authority denial.
        let (is_err, text) = tools_call(
            &h, &tools, 1, "kv-store.put",
            kv_put_args(&h, "test", &[], None),
        );
        assert!(is_err);
        assert!(text.contains("Denied"), "{text}");
        assert!(text.contains("kv.write"), "{text}");
    }

    #[test]
    fn caller_supplied_capabilities_ignored() {
        // Stuffing `capabilities` into the arguments must not confer
        // authority: the grant (empty here) is the only source.
        let h = host();
        let tools = generate_tools(&h);
        let mut args = kv_put_args(&h, "test", &[], None);
        args["capabilities"] = serde_json::json!(["kv.write", "admin.*"]);
        let (is_err, text) = tools_call(&h, &tools, 1, "kv-store.put", args);
        assert!(is_err);
        assert!(text.contains("Denied"), "{text}");
    }

    #[test]
    fn replayed_grant_denied() {
        let h = host();
        let tools = generate_tools(&h);
        let grant = h.issue_single_use_grant("test", vec!["kv.write".to_string()], 300);
        let mk = |id| {
            let msg_args = serde_json::json!({
                "grant": grant, "caller": "test", "key": "a", "value": 1,
            });
            (id, msg_args)
        };
        let (id1, a1) = mk(1);
        let (is_err1, t1) = tools_call(&h, &tools, id1, "kv-store.put", a1);
        assert!(!is_err1, "{t1}");
        let (id2, a2) = mk(2);
        let (is_err2, t2) = tools_call(&h, &tools, id2, "kv-store.put", a2);
        assert!(is_err2);
        assert!(t2.contains("Denied"), "{t2}");
        assert!(t2.contains("replay"), "{t2}");
    }

    #[test]
    fn wrong_caller_grant_denied() {
        let h = host();
        let tools = generate_tools(&h);
        // Grant issued to alice, presented as mallory.
        let grant = h.issue_grant("alice", vec!["kv.write".to_string()], 300);
        let args = serde_json::json!({
            "grant": grant, "caller": "mallory", "key": "a", "value": 1,
        });
        let (is_err, text) = tools_call(&h, &tools, 1, "kv-store.put", args);
        assert!(is_err);
        assert!(text.contains("Denied"), "{text}");
        assert!(text.contains("does not match grant subject"), "{text}");
    }

    #[test]
    fn missing_grant_denied_not_allowed() {
        let h = host();
        let tools = generate_tools(&h);
        let args = serde_json::json!({"caller": "test", "key": "a", "value": 1});
        let (is_err, text) = tools_call(&h, &tools, 1, "kv-store.put", args);
        assert!(is_err, "no auth material must never default-allow");
        assert!(text.contains("Denied"), "{text}");
    }
}
