//! org-005 — MCP surface generator.
//!
//! Generates MCP tool definitions from organelle manifests (one tool per
//! `codon.op`) and serves them over JSON-RPC 2.0 on stdio. The generator is
//! data-driven: `generate_tools(&host)` reflects whatever is registered.

use organelle_host::{CallContext, Host};
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
            let mut schema = c.input_schema.clone();
            if let Some(obj) = schema.as_object_mut() {
                let props = obj
                    .entry("properties")
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if let Some(p) = props.as_object_mut() {
                    p.entry("caller").or_insert(serde_json::json!({"type": "string"}));
                    p.entry("capabilities").or_insert(
                        serde_json::json!({"type": "array", "items": {"type": "string"}}),
                    );
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
                    let caller = args.get("caller").and_then(|c| c.as_str()).unwrap_or("mcp").to_string();
                    let caps: Vec<String> = args
                        .get("capabilities")
                        .and_then(|c| c.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let mut input = args;
                    if let Some(obj) = input.as_object_mut() {
                        obj.remove("caller");
                        obj.remove("capabilities");
                    }
                    let ctx = CallContext::new(caller, caps);
                    match host.call(&ctx, &tool.codon, &tool.op, input) {
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
        assert!(t.input_schema["properties"]["caller"].is_object());
    }
}
