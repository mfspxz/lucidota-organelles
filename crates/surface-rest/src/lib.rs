//! org-006 — REST + OpenAPI surface generator.
//!
//! Generates routes and an OpenAPI 3.0 document from organelle manifests,
//! served over a dependency-free hand-rolled HTTP/1.1 listener (std only).
//!
//! - `GET  /api/organelles`      — routed manifests
//! - `POST /api/organelle/call`  — `{caller, codon, op, input}` + `Authorization: Bearer <grant>`
//! - `GET  /openapi.json`        — generated OpenAPI 3.0
//! - `GET  /api/receipts?limit=N`— recent receipts (audit)
//!
//! P0: authority is unforgeable at this boundary. Callers authenticate with
//! a host-issued capability grant as a Bearer token; capabilities are
//! derived only from the verified grant. A `capabilities` field in the body
//! is rejected outright — authority is granted, never claimed.
//!
//! GO-50 Phase 1, family F4 — typed projection: `spawn_typed` serves the
//! `/v1/*` routes from the universal dispatcher instead of the host
//! registry. Single source: [`organelle_typed::TypedDispatcher::
//! typed_manifests`]. A typed organelle registered once via
//! `register_typed` appears in `GET /v1/organelles` (full V1 manifest,
//! ontology + typed contracts) and in the generated OpenAPI document
//! (`GET /v1/openapi.json`, per-op paths with typed response schemas),
//! and `POST /v1/organelle/call` routes through the dispatcher's staged
//! pipeline, returning truth + provenance with the output. The typed
//! server also serves the untyped `/api/*` routes (same host underneath).

use organelle_host::Host;
use organelle_typed::{InvocationEnvelope, TypedDispatcher};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

/// OpenAPI 3.0 generated from the host's routed manifests.
///
/// P0: the call operation takes no capability claims. Authority travels as
/// a host-issued grant in the `Authorization: Bearer` header.
pub fn openapi_json(host: &Host) -> Value {
    let mut paths = serde_json::Map::new();
    for m in host.list_manifests() {
        for c in &m.contracts {
            let path = format!("/api/organelle/{}/{}", m.codon, c.op);
            paths.insert(
                path,
                serde_json::json!({
                    "post": {
                        "summary": c.description,
                        "operationId": format!("{}.{}", m.name, c.op),
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["input"],
                                        "properties": {
                                            "caller": {"type": "string", "description": "claimed caller identity; must match the grant's subject"},
                                            "input": c.input_schema,
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "ok",
                                "content": {"application/json": {"schema": {"type": "object"}}}},
                            "400": {"description": "denied/rejected/failed"}
                        }
                    }
                }),
            );
        }
    }
    serde_json::json!({
        "openapi": "3.0.0",
        "info": {"title": "parkwreck-organelle-host", "version": "1.0.0"},
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "host-issued capability grant (see Host::issue_grant)",
                }
            }
        },
    })
}

/// OpenAPI 3.0 generated from the typed dispatcher's registry — the
/// typed projection. Single source: `dispatcher.typed_manifests()`.
/// Generated, never hand-written: one path per typed `codon.op` at
/// `/v1/organelle/{codon}/{op}`, with the contract's input schema in
/// the request body, the TYPED contract's `output_schema` in the 200
/// response, and the GO/DO/CO declarations as an `x-go50-ontology`
/// extension. Same bearerAuth security as the untyped document.
pub fn openapi_json_typed(dispatcher: &TypedDispatcher) -> Value {
    let mut paths = serde_json::Map::new();
    for m in dispatcher.typed_manifests() {
        for c in &m.base.contracts {
            let typed = m.typed_contract(&c.op);
            let response_schema = typed
                .map(|t| t.output_schema.clone())
                .unwrap_or_else(|| serde_json::json!({"type": "object"}));
            let path = format!("/v1/organelle/{}/{}", m.base.codon, c.op);
            paths.insert(
                path,
                serde_json::json!({
                    "post": {
                        "summary": c.description,
                        "operationId": format!("{}.{}", m.base.name, c.op),
                        "security": [{"bearerAuth": []}],
                        "x-go50-ontology": {
                            "go": m.ontology.go,
                            "domain": m.ontology.domain,
                            "client": m.ontology.client,
                        },
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        // F6-H5: `caller` is required on
                                        // the typed surface — the
                                        // dispatcher rejects an empty
                                        // caller at stage 1, so a
                                        // grant-only typed call can
                                        // never succeed. (The untyped
                                        // doc keeps caller optional:
                                        // grant-only calls are valid
                                        // there.)
                                        "required": ["caller", "input"],
                                        "properties": {
                                            "caller": {"type": "string", "description": "claimed caller identity; must match the grant's subject"},
                                            "input": c.input_schema,
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "ok",
                                "content": {"application/json": {"schema": response_schema}}},
                            "400": {"description": "denied/rejected/failed"}
                        }
                    }
                }),
            );
        }
    }
    serde_json::json!({
        "openapi": "3.0.0",
        "info": {"title": "parkwreck-organelle-host (typed)", "version": "1.0.0"},
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "host-issued capability grant (see Host::issue_grant)",
                }
            }
        },
    })
}

struct HttpRequest {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if head.len() > 65536 {
            return Err("header too large".to_string());
        }
        match stream.read(&mut one) {
            Ok(0) => return Err("eof".to_string()),
            Ok(_) => {
                head.push(one[0]);
                if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
                    break;
                }
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let request_line = lines.next().ok_or("empty request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?.to_string();
    let target = parts.next().ok_or("no target")?.to_string();
    let (path, query) = match target.find('?') {
        Some(i) => (target[..i].to_string(), target[i + 1..].to_string()),
        None => (target, String::new()),
    };
    let mut content_length = 0usize;
    let mut authorization: Option<String> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            if k.trim().eq_ignore_ascii_case("authorization") {
                authorization = Some(v.trim().to_string());
            }
        }
    }
    let content_length = content_length.min(8_388_608);
    let mut body = vec![0u8; content_length];
    let mut read = 0;
    while read < content_length {
        match stream.read(&mut body[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) => return Err(format!("read body: {e}")),
        }
    }
    body.truncate(read);
    Ok(HttpRequest {
        method,
        path,
        query,
        authorization,
        body,
    })
}

fn respond(stream: &mut TcpStream, status: u16, body: &Value) {
    let text = serde_json::to_string(body).unwrap();
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        if k == key {
            Some(v.to_string())
        } else {
            None
        }
    })
}

fn handle_conn(host: Arc<Host>, mut stream: TcpStream) {
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(_) => {
            respond(
                &mut stream,
                400,
                &serde_json::json!({"ok": false, "error": "bad request"}),
            );
            return;
        }
    };
    route_request(&host, req, stream);
}

/// Parse a call body: JSON, with no `capabilities` (P0:
/// caller-supplied capability claims are rejected outright —
/// authority comes only from the host-issued grant). Returns None
/// after responding 400. Shared by the `/call` routes and the
/// per-op routes (F6-H1).
fn parse_call_body(stream: &mut TcpStream, body: &[u8]) -> Option<Value> {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            respond(
                stream,
                400,
                &serde_json::json!({"ok": false, "error": format!("bad json: {e}")}),
            );
            return None;
        }
    };
    if v.get("capabilities").is_some() {
        respond(
            stream,
            400,
            &serde_json::json!({
                "ok": false,
                "error": {"verdict": "Rejected", "reason": "capabilities must be granted, not claimed"},
                "receipt": "",
            }),
        );
        return None;
    }
    Some(v)
}

/// The grant from the Authorization header (`Bearer <grant>`); empty
/// when absent, so the host's grant verification denies it — never
/// default-allow.
fn bearer_grant(req: &HttpRequest) -> &str {
    req.authorization
        .as_deref()
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

/// Split a per-op path (`/api/organelle/{codon}/{op}` or its `/v1/`
/// twin) into (codon, op). Exactly two non-empty segments after the
/// prefix; anything else — including the `/call` route itself — is
/// not a per-op path.
fn per_op_path<'a>(path: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let rest = path.strip_prefix(prefix)?;
    let (codon, op) = rest.split_once('/')?;
    if codon.is_empty() || op.is_empty() || op.contains('/') {
        return None;
    }
    Some((codon, op))
}

/// Execute an untyped call: grant from the Bearer token, caller +
/// input from the body, codon/op from the caller. Shared by
/// `POST /api/organelle/call` (codon/op in the body) and
/// `POST /api/organelle/{codon}/{op}` (codon/op in the path).
fn run_untyped_call(
    host: &Host,
    req: &HttpRequest,
    mut stream: TcpStream,
    body: Value,
    codon: &str,
    op: &str,
) {
    let grant = bearer_grant(req);
    let caller = body.get("caller").and_then(|c| c.as_str());
    let input = body.get("input").cloned().unwrap_or(Value::Null);
    match host.call_with_grant(
        grant,
        caller,
        organelle_manifest::Transport::Rest,
        codon,
        op,
        input,
    ) {
        Ok(ok) => {
            // P1: the receipt id comes from the invocation result —
            // the exact receipt this invocation emitted — never from
            // a global "latest receipt" read (which cross-wires under
            // concurrency).
            respond(
                &mut stream,
                200,
                &serde_json::json!({"ok": true, "output": ok.output, "receipt": ok.receipt_id}),
            );
        }
        Err(e) => {
            let status = match e.verdict {
                organelle_host::CallVerdict::Denied => 400,
                organelle_host::CallVerdict::Rejected => 400,
                organelle_host::CallVerdict::Failed => 400,
                organelle_host::CallVerdict::Ok => 200,
            };
            respond(
                &mut stream,
                status,
                &serde_json::json!({
                    "ok": false,
                    "error": {"verdict": format!("{:?}", e.verdict), "reason": e.reason},
                    "receipt": e.receipt_id,
                }),
            );
        }
    }
}

/// Execute a typed call through the dispatcher. Shared by
/// `POST /v1/organelle/call` (codon/op in the body) and
/// `POST /v1/organelle/{codon}/{op}` (codon/op in the path).
fn run_typed_call(
    dispatcher: &TypedDispatcher,
    req: &HttpRequest,
    mut stream: TcpStream,
    body: Value,
    codon: &str,
    op: &str,
) {
    // The grant travels as a Bearer token; an empty grant is passed
    // through as Some("") so the host's grant verification denies
    // it — never default-allowed onto the native path.
    let grant = bearer_grant(req);
    let caller = body.get("caller").and_then(|c| c.as_str()).unwrap_or("");
    let input = body.get("input").cloned().unwrap_or(Value::Null);
    let envelope = InvocationEnvelope {
        caller: caller.to_string(),
        codon: codon.to_string(),
        op: op.to_string(),
        input,
        trace_id: None,
        capabilities: Vec::new(),
        transport: organelle_manifest::Transport::Rest,
        grant: Some(grant.to_string()),
    };
    match dispatcher.dispatch(envelope) {
        Ok(ok) => {
            respond(
                &mut stream,
                200,
                &serde_json::json!({
                    "ok": true,
                    "output": ok.output,
                    "truth": ok.truth,
                    "provenance": ok.provenance,
                    "receipt": ok.receipt_id,
                }),
            );
        }
        Err(e) => {
            respond(
                &mut stream,
                400,
                &serde_json::json!({
                    "ok": false,
                    "error": {"verdict": e.verdict(), "reason": e.to_string()},
                    "receipt": e.receipt_id(),
                }),
            );
        }
    }
}

/// Route one parsed request against the host's untyped `/api/*`
/// routes. Split out of `handle_conn` so the typed server can serve
/// the same routes (same host underneath) alongside its `/v1/*`
/// routes.
fn route_request(host: &Arc<Host>, req: HttpRequest, mut stream: TcpStream) {
    // F6-H1: the per-op path the generated OpenAPI advertises
    // (POST /api/organelle/{codon}/{op}) — body {caller, input},
    // grant as Bearer, same P0 rules as the call route.
    if req.method == "POST" {
        if let Some((codon, op)) = per_op_path(&req.path, "/api/organelle/") {
            let Some(body) = parse_call_body(&mut stream, &req.body) else {
                return;
            };
            run_untyped_call(host, &req, stream, body, codon, op);
            return;
        }
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/organelles") => {
            let manifests: Vec<Value> = host
                .list_manifests()
                .iter()
                .map(|m| serde_json::to_value(m).unwrap())
                .collect();
            respond(
                &mut stream,
                200,
                &serde_json::json!({"ok": true, "organelles": manifests}),
            );
        }
        ("GET", "/openapi.json") => {
            respond(&mut stream, 200, &openapi_json(&host));
        }
        ("GET", "/api/receipts") => {
            let limit: usize = query_param(&req.query, "limit")
                .and_then(|s| s.parse().ok())
                .unwrap_or(50)
                .min(1000);
            let receipts = host.receipts();
            let tail: Vec<Value> = receipts
                .iter()
                .rev()
                .take(limit)
                .map(|r| serde_json::to_value(r).unwrap())
                .collect();
            respond(
                &mut stream,
                200,
                &serde_json::json!({"ok": true, "receipts": tail}),
            );
        }
        ("POST", "/api/organelle/call") => {
            let Some(body) = parse_call_body(&mut stream, &req.body) else {
                return;
            };
            let codon = body
                .get("codon")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            let op = body
                .get("op")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            run_untyped_call(host, &req, stream, body, &codon, &op);
        }
        _ => respond(
            &mut stream,
            404,
            &serde_json::json!({"ok": false, "error": "not found"}),
        ),
    }
}

/// Handle one connection on the typed server: the `/v1/*` routes come
/// from the dispatcher; everything else falls through to the untyped
/// `/api/*` routes on the same host.
fn handle_conn_typed(dispatcher: Arc<TypedDispatcher>, mut stream: TcpStream) {
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(_) => {
            respond(
                &mut stream,
                400,
                &serde_json::json!({"ok": false, "error": "bad request"}),
            );
            return;
        }
    };
    // F6-H1: the per-op path the generated OpenAPI advertises
    // (POST /v1/organelle/{codon}/{op}) — body {caller, input},
    // grant as Bearer, same P0 rules as the call route.
    if req.method == "POST" {
        if let Some((codon, op)) = per_op_path(&req.path, "/v1/organelle/") {
            let Some(body) = parse_call_body(&mut stream, &req.body) else {
                return;
            };
            run_typed_call(&dispatcher, &req, stream, body, codon, op);
            return;
        }
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/organelles") => {
            // Full V1 manifests (ontology + typed contracts), straight
            // from the dispatcher's registry — the single source.
            let manifests: Vec<Value> = dispatcher
                .typed_manifests()
                .iter()
                .map(|m| serde_json::to_value(m).unwrap())
                .collect();
            respond(
                &mut stream,
                200,
                &serde_json::json!({"ok": true, "organelles": manifests}),
            );
        }
        ("GET", "/v1/openapi.json") => {
            respond(&mut stream, 200, &openapi_json_typed(&dispatcher));
        }
        ("POST", "/v1/organelle/call") => {
            let Some(body) = parse_call_body(&mut stream, &req.body) else {
                return;
            };
            let codon = body
                .get("codon")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            let op = body
                .get("op")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            run_typed_call(&dispatcher, &req, stream, body, &codon, &op);
        }
        _ => route_request(dispatcher.host(), req, stream),
    }
}

pub struct RestHandle {
    port: u16,
    shutdown: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl RestHandle {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn shutdown(mut self) {
        let _ = self.shutdown.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Spawn the typed REST surface on 127.0.0.1 (port 0 = ephemeral).
/// Serves `GET /v1/organelles`, `GET /v1/openapi.json`,
/// `POST /v1/organelle/call`, and the per-op paths
/// `POST /v1/organelle/{codon}/{op}` from the dispatcher, plus the
/// untyped `/api/*` routes (including per-op
/// `POST /api/organelle/{codon}/{op}`) on the same host.
pub fn spawn_typed(dispatcher: Arc<TypedDispatcher>, port: u16) -> std::io::Result<RestHandle> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;
    listener.set_nonblocking(true)?;
    let actual = listener.local_addr()?.port();
    let (tx, rx) = mpsc::channel::<()>();
    let thread = thread::spawn(move || loop {
        if rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let d = dispatcher.clone();
                thread::spawn(move || handle_conn_typed(d, stream));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    });
    Ok(RestHandle {
        port: actual,
        shutdown: tx,
        thread: Some(thread),
    })
}

/// Spawn the REST surface on 127.0.0.1 (port 0 = ephemeral).
pub fn spawn(host: Arc<Host>, port: u16) -> std::io::Result<RestHandle> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;
    listener.set_nonblocking(true)?;
    let actual = listener.local_addr()?.port();
    let (tx, rx) = mpsc::channel::<()>();
    let thread = thread::spawn(move || loop {
        if rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let h = host.clone();
                thread::spawn(move || handle_conn(h, stream));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    });
    Ok(RestHandle {
        port: actual,
        shutdown: tx,
        thread: Some(thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn host() -> Arc<Host> {
        let h = Host::new();
        h.register(ref_text_transform::organelle()).unwrap();
        h.register(ref_kv_store::organelle()).unwrap();
        h
    }

    fn raw(port: u16, req: &str) -> (String, Value) {
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

    fn post_auth(port: u16, path: &str, grant: Option<&str>, body: &Value) -> (String, Value) {
        let text = serde_json::to_string(body).unwrap();
        let auth = grant
            .map(|g| format!("Authorization: Bearer {g}\r\n"))
            .unwrap_or_default();
        raw(
            port,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: x\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            ),
        )
    }

    fn get(port: u16, path: &str) -> (String, Value) {
        raw(
            port,
            &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        )
    }

    fn grant_for(h: &Host, caller: &str, caps: &[&str]) -> String {
        h.issue_grant(caller, caps.iter().map(|s| s.to_string()).collect(), 300)
    }

    #[test]
    fn lists_organelles() {
        let srv = spawn(host(), 0).unwrap();
        let (status, body) = get(srv.port(), "/api/organelles");
        assert!(status.contains("200"), "{status}");
        assert_eq!(body["organelles"].as_array().unwrap().len(), 2);
        srv.shutdown();
    }

    #[test]
    fn call_ok() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        let g = grant_for(&h, "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/call",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "codon": "tt", "op": "transform",
                "input": {"text": "hi", "mode": "upper"},
            }),
        );
        assert!(status.contains("200"), "{status}");
        assert_eq!(body["ok"], serde_json::json!(true));
        assert_eq!(body["output"]["result"], serde_json::json!("HI"));
        // P1: the returned receipt id is invocation-specific — it must name
        // THIS call in the host store, not just be non-empty.
        let rid = body["receipt"].as_str().unwrap();
        assert!(!rid.is_empty());
        let r = h
            .receipts()
            .into_iter()
            .find(|r| r.id == rid)
            .expect("returned receipt id must resolve in store");
        assert_eq!(r.caller, "t");
        assert_eq!(r.codon, "tt");
        assert_eq!(r.op, "transform");
        srv.shutdown();
    }

    #[test]
    fn granted_capability_allows_gated_op() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        let g = grant_for(&h, "t", &["kv.write"]);
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/call",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "codon": "kv", "op": "put",
                "input": {"key": "a", "value": 1},
            }),
        );
        assert!(status.contains("200"), "{status} {body}");
        assert_eq!(body["ok"], serde_json::json!(true));
        srv.shutdown();
    }

    #[test]
    fn call_denied_with_receipt() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        // Valid grant, but no kv.write -> host authority denial.
        let g = grant_for(&h, "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/call",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "codon": "kv", "op": "put",
                "input": {"key": "a", "value": 1},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["ok"], serde_json::json!(false));
        assert_eq!(body["error"]["verdict"], serde_json::json!("Denied"));
        // P1: the denial's receipt id is invocation-specific too.
        let rid = body["receipt"].as_str().unwrap();
        assert!(!rid.is_empty());
        let r = h
            .receipts()
            .into_iter()
            .find(|r| r.id == rid)
            .expect("denial receipt id must resolve in store");
        assert_eq!(format!("{:?}", r.verdict), "Denied");
        assert_eq!(r.caller, "t");
        assert_eq!(r.codon, "kv");
        assert_eq!(r.op, "put");
        srv.shutdown();
    }

    #[test]
    fn openapi_generated() {
        let srv = spawn(host(), 0).unwrap();
        let (status, body) = get(srv.port(), "/openapi.json");
        assert!(status.contains("200"), "{status}");
        assert_eq!(body["openapi"], serde_json::json!("3.0.0"));
        assert!(body["paths"]["/api/organelle/tt/transform"].is_object());
        assert!(body["paths"]["/api/organelle/kv/put"].is_object());
        // No capability claims in the advertised schema; bearer documented.
        let schema_props = &body["paths"]["/api/organelle/kv/put"]["post"]["requestBody"]
            ["content"]["application/json"]["schema"]["properties"];
        assert!(schema_props.get("capabilities").is_none());
        assert!(body["components"]["securitySchemes"]["bearerAuth"].is_object());
        srv.shutdown();
    }

    #[test]
    fn receipts_endpoint() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        let g = grant_for(&h, "t", &[]);
        let _ = post_auth(
            srv.port(),
            "/api/organelle/call",
            Some(&g),
            &serde_json::json!({"caller": "t", "codon": "tt", "op": "transform",
                "input": {"text": "a", "mode": "upper"}}),
        );
        let (status, body) = get(srv.port(), "/api/receipts?limit=5");
        assert!(status.contains("200"), "{status}");
        assert!(body["receipts"].as_array().unwrap().len() >= 1);
        srv.shutdown();
    }

    #[test]
    fn unknown_route_404() {
        let srv = spawn(host(), 0).unwrap();
        let (status, _) = get(srv.port(), "/nope");
        assert!(status.contains("404"), "{status}");
        srv.shutdown();
    }

    // -- P0 forged-capability tests: every forgery must be denied ---------

    #[test]
    fn forged_grant_denied() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        let good = grant_for(&h, "t", &["kv.write"]);
        let (payload_hex, tag) = good.split_once('.').unwrap();
        let mut chars: Vec<char> = payload_hex.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        let forged = format!("{}.{}", chars.into_iter().collect::<String>(), tag);
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/call",
            Some(&forged),
            &serde_json::json!({
                "caller": "t", "codon": "kv", "op": "put",
                "input": {"key": "a", "value": 1},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["error"]["verdict"], serde_json::json!("Denied"));
        assert!(body["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("signature"));
        assert!(!body["receipt"].as_str().unwrap().is_empty());
        srv.shutdown();
    }

    #[test]
    fn escalated_capability_denied() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        // Grant confers no kv.write; the gated op must stay denied.
        let g = grant_for(&h, "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/call",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "codon": "kv", "op": "put",
                "input": {"key": "a", "value": 1},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["error"]["verdict"], serde_json::json!("Denied"));
        assert!(body["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("kv.write"));
        srv.shutdown();
    }

    #[test]
    fn caller_supplied_capabilities_rejected() {
        // Capabilities in the body are not ignored — they are rejected.
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        let g = grant_for(&h, "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/call",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "capabilities": ["kv.write", "admin.*"],
                "codon": "kv", "op": "put",
                "input": {"key": "a", "value": 1},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["error"]["verdict"], serde_json::json!("Rejected"));
        srv.shutdown();
    }

    #[test]
    fn replayed_grant_denied() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        let g = h.issue_single_use_grant("t", vec!["kv.write".to_string()], 300);
        let body = serde_json::json!({
            "caller": "t", "codon": "kv", "op": "put",
            "input": {"key": "a", "value": 1},
        });
        let (s1, b1) = post_auth(srv.port(), "/api/organelle/call", Some(&g), &body);
        assert!(s1.contains("200"), "{s1} {b1}");
        let (s2, b2) = post_auth(srv.port(), "/api/organelle/call", Some(&g), &body);
        assert!(s2.contains("400"), "{s2}");
        assert_eq!(b2["error"]["verdict"], serde_json::json!("Denied"));
        assert!(b2["error"]["reason"].as_str().unwrap().contains("replay"));
        srv.shutdown();
    }

    #[test]
    fn wrong_caller_grant_denied() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        // Grant issued to alice, presented as mallory.
        let g = h.issue_grant("alice", vec!["kv.write".to_string()], 300);
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/call",
            Some(&g),
            &serde_json::json!({
                "caller": "mallory", "codon": "kv", "op": "put",
                "input": {"key": "a", "value": 1},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["error"]["verdict"], serde_json::json!("Denied"));
        assert!(body["error"]["reason"]
            .as_str()
            .unwrap()
            .contains("does not match grant subject"));
        srv.shutdown();
    }

    #[test]
    fn missing_grant_denied_not_allowed() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/call",
            None,
            &serde_json::json!({
                "caller": "t", "codon": "tt", "op": "transform",
                "input": {"text": "hi", "mode": "upper"},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["ok"], serde_json::json!(false));
        assert_eq!(body["error"]["verdict"], serde_json::json!("Denied"));
        srv.shutdown();
    }

    // -- F4: typed projection (single source: typed_manifests()) --------

    fn typed_dispatcher() -> Arc<TypedDispatcher> {
        let h = Host::new();
        let d = TypedDispatcher::new(h, organelle_typed::LockRegistry::with_go50());
        d.register_typed(ref_typed_hash::TypedHash::new())
            .expect("typed-hash must register");
        Arc::new(d)
    }

    #[test]
    fn v1_lists_typed_organelles() {
        let srv = spawn_typed(typed_dispatcher(), 0).unwrap();
        let (status, body) = get(srv.port(), "/v1/organelles");
        assert!(status.contains("200"), "{status}");
        let orgs = body["organelles"].as_array().unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0]["base"]["codon"], serde_json::json!("th"));
        assert_eq!(orgs[0]["base"]["name"], serde_json::json!("typed-hash"));
        // Full V1 manifest: ontology + typed contracts.
        assert_eq!(
            orgs[0]["ontology"]["go"],
            serde_json::json!(["TOOL", "PROCESS", "EVIDENCE", "IDENTITY"])
        );
        assert_eq!(orgs[0]["typed_contracts"].as_array().unwrap().len(), 2);
        assert_eq!(
            orgs[0]["typed_contracts"][0]["output_type"],
            serde_json::json!("HashOutput::Sha256")
        );
        srv.shutdown();
    }

    #[test]
    fn v1_openapi_generated_from_typed_manifests() {
        let srv = spawn_typed(typed_dispatcher(), 0).unwrap();
        let (status, body) = get(srv.port(), "/v1/openapi.json");
        assert!(status.contains("200"), "{status}");
        assert_eq!(body["openapi"], serde_json::json!("3.0.0"));
        let sha = &body["paths"]["/v1/organelle/th/sha256"]["post"];
        assert!(sha.is_object(), "{body}");
        assert_eq!(sha["operationId"], serde_json::json!("typed-hash.sha256"));
        // Typed response schema from the typed contract.
        assert_eq!(
            sha["responses"]["200"]["content"]["application/json"]["schema"]["required"],
            serde_json::json!(["algorithm", "hex", "input_bytes"])
        );
        // Ontology extension.
        assert_eq!(
            sha["x-go50-ontology"]["go"],
            serde_json::json!(["TOOL", "PROCESS", "EVIDENCE", "IDENTITY"])
        );
        // Input schema in the request body; no capability claims.
        let props = &sha["requestBody"]["content"]["application/json"]["schema"]["properties"];
        assert!(props["input"]["properties"]["text"].is_object());
        assert!(props.get("capabilities").is_none());
        assert!(body["paths"]["/v1/organelle/th/verify"].is_object());
        assert!(body["components"]["securitySchemes"]["bearerAuth"].is_object());
        srv.shutdown();
    }

    #[test]
    fn v1_call_ok_with_truth_and_provenance() {
        let d = typed_dispatcher();
        let srv = spawn_typed(d.clone(), 0).unwrap();
        let g = grant_for(d.host(), "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/v1/organelle/call",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "codon": "th", "op": "sha256",
                "input": {"text": "abc"},
            }),
        );
        assert!(status.contains("200"), "{status} {body}");
        assert_eq!(body["ok"], serde_json::json!(true));
        assert_eq!(
            body["output"]["hex"],
            serde_json::json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(body["truth"]["status"], serde_json::json!("proven"));
        assert_eq!(
            body["provenance"]["source"],
            serde_json::json!("computed_locally")
        );
        assert_eq!(
            body["provenance"]["produced_by"],
            serde_json::json!("th@1.0.0")
        );
        // The receipt id resolves and names this invocation.
        let rid = body["receipt"].as_str().unwrap();
        let r = d
            .host()
            .receipts()
            .into_iter()
            .find(|r| r.id == rid)
            .expect("receipt id must resolve in store");
        assert_eq!(r.codon, "th");
        assert_eq!(r.op, "sha256");
        assert_eq!(r.caller, "t");
        srv.shutdown();
    }

    #[test]
    fn v1_call_missing_grant_denied() {
        let srv = spawn_typed(typed_dispatcher(), 0).unwrap();
        let (status, body) = post_auth(
            srv.port(),
            "/v1/organelle/call",
            None,
            &serde_json::json!({
                "caller": "t", "codon": "th", "op": "sha256",
                "input": {"text": "abc"},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["ok"], serde_json::json!(false));
        assert_eq!(body["error"]["verdict"], serde_json::json!("Denied"));
        srv.shutdown();
    }

    #[test]
    fn v1_call_capabilities_rejected() {
        let d = typed_dispatcher();
        let srv = spawn_typed(d.clone(), 0).unwrap();
        let g = grant_for(d.host(), "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/v1/organelle/call",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "capabilities": ["admin.*"],
                "codon": "th", "op": "sha256",
                "input": {"text": "abc"},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["error"]["verdict"], serde_json::json!("Rejected"));
        srv.shutdown();
    }

    #[test]
    fn typed_server_still_serves_untyped_routes() {
        // The typed server is the same host underneath: /api/organelles
        // lists the base manifest of the typed organelle too.
        let srv = spawn_typed(typed_dispatcher(), 0).unwrap();
        let (status, body) = get(srv.port(), "/api/organelles");
        assert!(status.contains("200"), "{status}");
        let orgs = body["organelles"].as_array().unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0]["codon"], serde_json::json!("th"));
        srv.shutdown();
    }

    // -- F6: hostile review ----------------------------------------------

    /// F6-H1: the per-op path the generated OpenAPI advertises
    /// (`POST /v1/organelle/{codon}/{op}`) must actually be served —
    /// it 404s today, and the acceptance test only asserts the doc
    /// *contains* the path, never calls it.
    #[test]
    fn f6_v1_per_op_path_served() {
        let d = typed_dispatcher();
        let srv = spawn_typed(d.clone(), 0).unwrap();
        let g = grant_for(d.host(), "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/v1/organelle/th/sha256",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "input": {"text": "abc"},
            }),
        );
        assert!(status.contains("200"), "{status} {body}");
        assert_eq!(body["ok"], serde_json::json!(true));
        assert_eq!(
            body["output"]["hex"],
            serde_json::json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(body["truth"]["status"], serde_json::json!("proven"));
        let rid = body["receipt"].as_str().unwrap();
        let r = d
            .host()
            .receipts()
            .into_iter()
            .find(|r| r.id == rid)
            .expect("receipt id must resolve in store");
        assert_eq!(r.codon, "th");
        assert_eq!(r.op, "sha256");
        srv.shutdown();
    }

    /// F6-H1 (untyped twin): the untyped OpenAPI advertises the same
    /// per-op shape (`POST /api/organelle/{codon}/{op}`) and it 404s
    /// the same way.
    #[test]
    fn f6_per_op_path_served_untyped() {
        let h = host();
        let srv = spawn(h.clone(), 0).unwrap();
        let g = grant_for(&h, "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/api/organelle/tt/transform",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "input": {"text": "hi", "mode": "upper"},
            }),
        );
        assert!(status.contains("200"), "{status} {body}");
        assert_eq!(body["ok"], serde_json::json!(true));
        assert_eq!(body["output"]["result"], serde_json::json!("HI"));
        let rid = body["receipt"].as_str().unwrap();
        let r = h
            .receipts()
            .into_iter()
            .find(|r| r.id == rid)
            .expect("receipt id must resolve in store");
        assert_eq!(r.codon, "tt");
        assert_eq!(r.op, "transform");
        srv.shutdown();
    }

    /// F6-H1: the per-op route applies the same P0 rule as the call
    /// route — caller-supplied capabilities are rejected, not
    /// stripped or honored.
    #[test]
    fn f6_v1_per_op_capabilities_rejected() {
        let d = typed_dispatcher();
        let srv = spawn_typed(d.clone(), 0).unwrap();
        let g = grant_for(d.host(), "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/v1/organelle/th/sha256",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "capabilities": ["admin.*"],
                "input": {"text": "abc"},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["error"]["verdict"], serde_json::json!("Rejected"));
        srv.shutdown();
    }

    /// F6-H1: a per-op path with an unknown op is a 400 from the
    /// typed pipeline (rejected by authorize), not a 404 — the route
    /// exists, the op does not.
    #[test]
    fn f6_v1_per_op_unknown_op_is_400_not_404() {
        let d = typed_dispatcher();
        let srv = spawn_typed(d.clone(), 0).unwrap();
        let g = grant_for(d.host(), "t", &[]);
        let (status, body) = post_auth(
            srv.port(),
            "/v1/organelle/th/nope",
            Some(&g),
            &serde_json::json!({
                "caller": "t", "input": {"text": "abc"},
            }),
        );
        assert!(status.contains("400"), "{status} {body}");
        assert_eq!(body["ok"], serde_json::json!(false));
        srv.shutdown();
    }

    /// F6-H5: the typed OpenAPI must advertise `caller` as required —
    /// the dispatcher rejects an empty caller at stage 1, so a
    /// grant-only typed call can never succeed. (The untyped doc
    /// keeps caller optional: grant-only calls are valid there.)
    #[test]
    fn f6_v1_openapi_requires_caller() {
        let d = typed_dispatcher();
        let doc = openapi_json_typed(&d);
        let schema = &doc["paths"]["/v1/organelle/th/sha256"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"];
        let req = schema["required"].as_array().unwrap();
        assert!(req.iter().any(|r| r == "caller"), "{schema}");
        assert!(req.iter().any(|r| r == "input"), "{schema}");
    }
}
