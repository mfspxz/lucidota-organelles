//! org-005 — MCP surface generator.
//!
//! Generates MCP tool definitions from organelle manifests (one tool per
//! `codon.op`) and serves them over JSON-RPC 2.0 on stdio. The generator is
//! data-driven: `generate_tools(&host)` reflects whatever is registered.
//!
//! GO-50 Phase 1, family F4 — typed projection: `generate_tools_typed`
//! / `dispatch_typed` / `serve_stdio_typed` generate the same surface
//! from the universal dispatcher instead of the host registry. Single
//! source: [`organelle_typed::TypedDispatcher::typed_manifests`].
//! A typed organelle registered once via `register_typed` appears in
//! `tools/list` here with its ontology terms and typed output type in
//! the description, and `tools/call` routes through the dispatcher's
//! staged pipeline (ontology re-resolution, oracle/govern stages,
//! truth + provenance in the result) instead of calling the host
//! directly.

use organelle_host::Host;
use organelle_typed::{InvocationEnvelope, TypedDispatcher};
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

/// The wire schema gains the envelope fields the server needs.
///
/// P0: authority is unforgeable at this boundary. The envelope carries
/// ONLY a host-issued `grant` (plus an optional `caller` identity
/// claim, which is bound to the grant's subject). There is no
/// `capabilities` field: caller-supplied capability claims are never
/// honored. Shared by the untyped and typed generators so both
/// surfaces advertise exactly the same envelope.
fn with_envelope_fields(schema: &Value) -> Value {
    let mut schema = schema.clone();
    if let Some(obj) = schema.as_object_mut() {
        let props = obj
            .entry("properties")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(p) = props.as_object_mut() {
            p.entry("grant")
                .or_insert(serde_json::json!({"type": "string"}));
            p.entry("caller")
                .or_insert(serde_json::json!({"type": "string"}));
        }
    }
    schema
}

/// Generate the tool list from currently registered (routed) manifests.
pub fn generate_tools(host: &Host) -> Vec<McpTool> {
    let mut tools = Vec::new();
    for m in host.list_manifests() {
        for c in &m.contracts {
            tools.push(McpTool {
                name: format!("{}.{}", m.name, c.op),
                description: format!("{} — {}", m.description, c.description),
                input_schema: with_envelope_fields(&c.input_schema),
                codon: m.codon.clone(),
                op: c.op.clone(),
            });
        }
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

/// Generate the tool list from the typed dispatcher's registry —
/// the typed projection. Single source: `dispatcher.typed_manifests()`
/// (V1 manifests + typed contracts + schemas, sorted by codon). One
/// tool per typed `codon.op`, exactly as the untyped generator, plus
/// the typed facts in the description: the GO ontology terms and the
/// typed output type. The input schema is the contract's schema with
/// the same grant/caller envelope fields as the untyped surface.
pub fn generate_tools_typed(dispatcher: &TypedDispatcher) -> Vec<McpTool> {
    let mut tools = Vec::new();
    for m in dispatcher.typed_manifests() {
        for c in &m.base.contracts {
            let typed = m.typed_contract(&c.op);
            let mut description = format!("{} — {}", m.base.description, c.description);
            description.push_str(&format!(" [GO: {}]", m.ontology.go.join(", ")));
            if let Some(t) = typed {
                description.push_str(&format!(" [output: {}]", t.output_type));
            }
            let mut schema = with_envelope_fields(&c.input_schema);
            // F6-H5: the dispatcher rejects an empty caller at stage 1,
            // before grant verification, so a grant-only typed call can
            // never succeed — advertise `caller` as required on the
            // typed surface. The untyped surface genuinely allows
            // grant-only calls (caller from the grant subject), so only
            // the typed generator adds it.
            if let Some(obj) = schema.as_object_mut() {
                let req = obj
                    .entry("required")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Some(arr) = req.as_array_mut() {
                    if !arr.iter().any(|r| r == "caller") {
                        arr.push(Value::String("caller".to_string()));
                    }
                }
            }
            tools.push(McpTool {
                name: format!("{}.{}", m.base.name, c.op),
                description,
                input_schema: schema,
                codon: m.base.codon.clone(),
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
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));
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
                    match host.call_with_grant(
                        &grant,
                        caller_claim.as_deref(),
                        organelle_manifest::Transport::Mcp,
                        &tool.codon,
                        &tool.op,
                        input,
                    ) {
                        // P1: the receipt id rides with the invocation
                        // result — the exact receipt this call emitted.
                        Ok(ok) => rpc_result(
                            &id,
                            serde_json::json!({
                                "content": [{"type": "text", "text": organelle_manifest::canonical_json(&ok.output)}],
                                "isError": false,
                                "receipt": ok.receipt_id,
                            }),
                        ),
                        Err(e) => rpc_result(
                            &id,
                            serde_json::json!({
                                "content": [{"type": "text", "text": format!("{:?}: {}", e.verdict, e.reason)}],
                                "isError": true,
                                // F6-H2: the denial's receipt id rides
                                // with the error, like the REST and unix
                                // surfaces — a refusal without a receipt
                                // is a bug.
                                "receipt": e.receipt_id,
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

/// Dispatch one JSON-RPC message against the typed dispatcher.
/// Mirrors [`dispatch`] exactly (initialize / tools/list / tools/call
/// / ping, notifications silent, unknown methods -32601), except
/// `tools/call` routes through the dispatcher's staged pipeline
/// instead of the host directly — so ontology re-resolution, the
/// oracle/govern stages, and truth + provenance all run on the MCP
/// path. A successful call returns the output text plus the receipt
/// id AND the typed truth + provenance as separate result fields.
/// The grant is always passed through (even empty, so a missing grant
/// is denied by the host's grant verification, never default-allowed
/// onto the native path).
pub fn dispatch_typed(
    dispatcher: &TypedDispatcher,
    tools: &[McpTool],
    msg: &Value,
) -> Option<Value> {
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
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));
            match tools.iter().find(|t| t.name == name) {
                None => rpc_error(&id, -32602, format!("unknown tool {name}")),
                Some(tool) => {
                    let grant = args
                        .get("grant")
                        .and_then(|g| g.as_str())
                        .unwrap_or("")
                        .to_string();
                    let caller = args
                        .get("caller")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    let mut input = args;
                    if let Some(obj) = input.as_object_mut() {
                        obj.remove("grant");
                        obj.remove("caller");
                        obj.remove("capabilities");
                    }
                    let envelope = InvocationEnvelope {
                        caller,
                        codon: tool.codon.clone(),
                        op: tool.op.clone(),
                        input,
                        trace_id: None,
                        capabilities: Vec::new(),
                        transport: organelle_manifest::Transport::Mcp,
                        grant: Some(grant),
                    };
                    match dispatcher.dispatch(envelope) {
                        Ok(ok) => rpc_result(
                            &id,
                            serde_json::json!({
                                "content": [{"type": "text", "text": organelle_manifest::canonical_json(&ok.output)}],
                                "isError": false,
                                "receipt": ok.receipt_id,
                                "truth": ok.truth,
                                "provenance": ok.provenance,
                            }),
                        ),
                        Err(e) => rpc_result(
                            &id,
                            serde_json::json!({
                                "content": [{"type": "text", "text": format!("{}: {}", e.verdict(), e)}],
                                "isError": true,
                                // F6-H2: the denial's receipt id rides
                                // with the error, like the REST and unix
                                // surfaces (empty for pre-host refusals,
                                // which emit no receipt).
                                "receipt": e.receipt_id(),
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

/// Serve the typed projection over stdin/stdout (line-delimited
/// JSON-RPC 2.0). Mirrors [`serve_stdio`]: the tool list comes from
/// `generate_tools_typed` (the dispatcher's registry) and calls route
/// through [`dispatch_typed`].
pub fn serve_stdio_typed(dispatcher: Arc<TypedDispatcher>) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let tools = generate_tools_typed(&dispatcher);
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
        if let Some(out) = dispatch_typed(&dispatcher, &tools, &msg) {
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
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
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
            &h,
            &tools,
            1,
            "kv-store.put",
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
            &h,
            &tools,
            1,
            "kv-store.put",
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
            &h,
            &tools,
            1,
            "kv-store.put",
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

    // -- F4: typed projection (single source: typed_manifests()) --------

    fn typed_dispatcher() -> Arc<TypedDispatcher> {
        let h = Host::new();
        let d = TypedDispatcher::new(h, organelle_typed::LockRegistry::with_go50());
        d.register_typed(ref_typed_hash::TypedHash::new())
            .expect("typed-hash must register");
        Arc::new(d)
    }

    fn typed_tools_call(
        d: &TypedDispatcher,
        tools: &[McpTool],
        id: u64,
        tool_name: &str,
        args: Value,
    ) -> Value {
        let msg = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool_name, "arguments": args},
        });
        dispatch_typed(d, tools, &msg).expect("response")
    }

    #[test]
    fn typed_tools_generated_from_dispatcher() {
        let d = typed_dispatcher();
        let tools = generate_tools_typed(&d);
        assert_eq!(tools.len(), 2);
        let sha = tools
            .iter()
            .find(|t| t.name == "typed-hash.sha256")
            .expect("typed-hash.sha256");
        assert_eq!(sha.codon, "th");
        assert_eq!(sha.op, "sha256");
        // Typed facts in the description: GO terms + output type.
        assert!(sha.description.contains("TOOL"), "{}", sha.description);
        assert!(sha.description.contains("EVIDENCE"), "{}", sha.description);
        assert!(
            sha.description.contains("HashOutput::Sha256"),
            "{}",
            sha.description
        );
        // Same envelope as the untyped surface.
        assert!(sha.input_schema["properties"]["grant"].is_object());
        assert!(sha.input_schema["properties"]["caller"].is_object());
        assert!(sha.input_schema["properties"].get("capabilities").is_none());
        assert!(tools.iter().any(|t| t.name == "typed-hash.verify"));
    }

    #[test]
    fn typed_tools_list_via_dispatch() {
        let d = typed_dispatcher();
        let tools = generate_tools_typed(&d);
        let msg = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
        });
        let resp = dispatch_typed(&d, &tools, &msg).expect("response");
        let listed = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|t| t["name"] == "typed-hash.sha256"));
        assert!(listed.iter().any(|t| t["name"] == "typed-hash.verify"));
    }

    #[test]
    fn typed_call_returns_truth_and_provenance() {
        let d = typed_dispatcher();
        let tools = generate_tools_typed(&d);
        let grant = d.host().issue_grant("test", vec![], 300);
        let resp = typed_tools_call(
            &d,
            &tools,
            1,
            "typed-hash.sha256",
            serde_json::json!({"grant": grant, "caller": "test", "text": "abc"}),
        );
        let result = &resp["result"];
        assert_eq!(result["isError"], serde_json::json!(false));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            "{text}"
        );
        assert_eq!(result["truth"]["status"], serde_json::json!("proven"));
        assert_eq!(
            result["provenance"]["source"],
            serde_json::json!("computed_locally")
        );
        assert_eq!(
            result["provenance"]["produced_by"],
            serde_json::json!("th@1.0.0")
        );
        // The receipt id resolves to a receipt carrying the same
        // typed outcome.
        let rid = result["receipt"].as_str().unwrap();
        let r = d.host().receipt_by_id(rid).expect("receipt resolves");
        assert_eq!(r.codon, "th");
        assert_eq!(r.op, "sha256");
        assert_eq!(
            r.typed_outcome.as_ref().unwrap()["truth"]["status"],
            serde_json::json!("proven")
        );
    }

    #[test]
    fn typed_call_without_grant_denied() {
        let d = typed_dispatcher();
        let tools = generate_tools_typed(&d);
        let resp = typed_tools_call(
            &d,
            &tools,
            1,
            "typed-hash.sha256",
            serde_json::json!({"caller": "test", "text": "abc"}),
        );
        assert_eq!(resp["result"]["isError"], serde_json::json!(true));
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Denied"), "{text}");
    }

    #[test]
    fn typed_call_unknown_tool() {
        let d = typed_dispatcher();
        let tools = generate_tools_typed(&d);
        let resp = typed_tools_call(&d, &tools, 1, "kv-store.put", serde_json::json!({}));
        assert_eq!(resp["error"]["code"], serde_json::json!(-32602));
    }

    // -- F6: hostile review ----------------------------------------------

    /// F6-H2: a typed denial over MCP must carry the receipt id, like
    /// the REST and unix surfaces do. A refusal without a receipt is
    /// a bug (host doctrine) — the caller cannot audit the denial.
    #[test]
    fn f6_typed_denial_carries_receipt() {
        let d = typed_dispatcher();
        let tools = generate_tools_typed(&d);
        let resp = typed_tools_call(
            &d,
            &tools,
            1,
            "typed-hash.sha256",
            serde_json::json!({"caller": "test", "text": "abc"}),
        );
        assert_eq!(resp["result"]["isError"], serde_json::json!(true));
        let rid = resp["result"]["receipt"]
            .as_str()
            .expect("denial must carry a receipt id");
        assert!(!rid.is_empty());
        let r = d.host().receipt_by_id(rid).expect("receipt resolves");
        assert_eq!(r.codon, "th");
        assert_eq!(r.op, "sha256");
        assert_eq!(r.verdict, organelle_host::CallVerdict::Denied);
    }

    /// F6-H2 (untyped twin): the untyped MCP error arm drops the
    /// receipt id too.
    #[test]
    fn f6_untyped_denial_carries_receipt() {
        let h = host();
        let tools = generate_tools(&h);
        let msg = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "kv-store.put",
                       "arguments": {"caller": "test", "key": "a", "value": 1}},
        });
        let resp = dispatch(&h, &tools, &msg).expect("response");
        assert_eq!(resp["result"]["isError"], serde_json::json!(true));
        let rid = resp["result"]["receipt"]
            .as_str()
            .expect("denial must carry a receipt id");
        assert!(!rid.is_empty());
        let r = h.receipt_by_id(rid).expect("receipt resolves");
        assert_eq!(r.codon, "kv");
        assert_eq!(r.verdict, organelle_host::CallVerdict::Denied);
    }

    /// F6-H5: the typed MCP schema must advertise `caller` as
    /// required — the dispatcher rejects an empty caller at stage 1,
    /// before grant verification, so a grant-only typed call can
    /// never succeed. The untyped surface genuinely allows
    /// grant-only calls (caller from the grant subject), so only the
    /// typed generator changes.
    #[test]
    fn f6_typed_tool_schema_requires_caller() {
        let d = typed_dispatcher();
        let tools = generate_tools_typed(&d);
        for t in &tools {
            let req = t.input_schema["required"]
                .as_array()
                .expect("typed tool schema has required");
            assert!(
                req.iter().any(|r| r == "caller"),
                "tool {} must require caller: {}",
                t.name,
                t.input_schema
            );
        }
        // And the untyped schema still does not (grant-only is valid
        // there).
        let h = host();
        let untyped = generate_tools(&h);
        let put = untyped.iter().find(|t| t.name == "kv-store.put").unwrap();
        let req = put.input_schema["required"].as_array().unwrap();
        assert!(!req.iter().any(|r| r == "caller"));
    }

    /// F6 (prove-sound): smuggled `capabilities` on a typed MCP call
    /// are stripped before the envelope is built — if stripping
    /// broke, the dispatcher's grant-XOR-capabilities check would
    /// reject the call. A valid grant + smuggled caps succeeds.
    #[test]
    fn f6_typed_capabilities_smuggled_are_stripped() {
        let d = typed_dispatcher();
        let tools = generate_tools_typed(&d);
        let grant = d.host().issue_grant("test", vec![], 300);
        let resp = typed_tools_call(
            &d,
            &tools,
            1,
            "typed-hash.sha256",
            serde_json::json!({
                "grant": grant, "caller": "test", "text": "abc",
                "capabilities": ["admin.*", "hash"],
            }),
        );
        assert_eq!(resp["result"]["isError"], serde_json::json!(false));
        assert_eq!(
            resp["result"]["truth"]["status"],
            serde_json::json!("proven")
        );
    }
}
