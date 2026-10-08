//! org-006 — REST + OpenAPI surface generator.
//!
//! Generates routes and an OpenAPI 3.0 document from organelle manifests,
//! served over a dependency-free hand-rolled HTTP/1.1 listener (std only).
//!
//! - `GET  /api/organelles`      — routed manifests
//! - `POST /api/organelle/call`  — `{caller, capabilities, codon, op, input}`
//! - `GET  /openapi.json`        — generated OpenAPI 3.0
//! - `GET  /api/receipts?limit=N`— recent receipts (audit)

use organelle_host::{CallContext, Host};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

/// OpenAPI 3.0 generated from the host's routed manifests.
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
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["input"],
                                        "properties": {
                                            "caller": {"type": "string"},
                                            "capabilities": {"type": "array", "items": {"type": "string"}},
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
    })
}

struct HttpRequest {
    method: String,
    path: String,
    query: String,
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
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
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
    Ok(HttpRequest { method, path, query, body })
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
            respond(&mut stream, 400, &serde_json::json!({"ok": false, "error": "bad request"}));
            return;
        }
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/organelles") => {
            let manifests: Vec<Value> = host
                .list_manifests()
                .iter()
                .map(|m| serde_json::to_value(m).unwrap())
                .collect();
            respond(&mut stream, 200, &serde_json::json!({"ok": true, "organelles": manifests}));
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
            respond(&mut stream, 200, &serde_json::json!({"ok": true, "receipts": tail}));
        }
        ("POST", "/api/organelle/call") => {
            let body: Value = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    respond(
                        &mut stream,
                        400,
                        &serde_json::json!({"ok": false, "error": format!("bad json: {e}")}),
                    );
                    return;
                }
            };
            let caller = body.get("caller").and_then(|c| c.as_str()).unwrap_or("rest").to_string();
            let caps: Vec<String> = body
                .get("capabilities")
                .and_then(|c| c.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let codon = body.get("codon").and_then(|c| c.as_str()).unwrap_or("");
            let op = body.get("op").and_then(|c| c.as_str()).unwrap_or("");
            let input = body.get("input").cloned().unwrap_or(Value::Null);
            let ctx = CallContext::new(caller, caps);
            match host.call(&ctx, codon, op, input) {
                Ok(output) => {
                    let receipt = host.receipts().last().map(|r| r.id.clone()).unwrap_or_default();
                    respond(
                        &mut stream,
                        200,
                        &serde_json::json!({"ok": true, "output": output, "receipt": receipt}),
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
        _ => respond(&mut stream, 404, &serde_json::json!({"ok": false, "error": "not found"})),
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
    Ok(RestHandle { port: actual, shutdown: tx, thread: Some(thread) })
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

    fn post(port: u16, path: &str, body: &Value) -> (String, Value) {
        let text = serde_json::to_string(body).unwrap();
        raw(
            port,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            ),
        )
    }

    fn get(port: u16, path: &str) -> (String, Value) {
        raw(port, &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
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
        let srv = spawn(host(), 0).unwrap();
        let (status, body) = post(
            srv.port(),
            "/api/organelle/call",
            &serde_json::json!({
                "caller": "t", "codon": "tt", "op": "transform",
                "input": {"text": "hi", "mode": "upper"},
            }),
        );
        assert!(status.contains("200"), "{status}");
        assert_eq!(body["ok"], serde_json::json!(true));
        assert_eq!(body["output"]["result"], serde_json::json!("HI"));
        assert!(!body["receipt"].as_str().unwrap().is_empty());
        srv.shutdown();
    }

    #[test]
    fn call_denied_with_receipt() {
        let srv = spawn(host(), 0).unwrap();
        let (status, body) = post(
            srv.port(),
            "/api/organelle/call",
            &serde_json::json!({
                "caller": "t", "codon": "kv", "op": "put",
                "input": {"key": "a", "value": 1},
            }),
        );
        assert!(status.contains("400"), "{status}");
        assert_eq!(body["ok"], serde_json::json!(false));
        assert_eq!(body["error"]["verdict"], serde_json::json!("Denied"));
        assert!(!body["receipt"].as_str().unwrap().is_empty());
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
        srv.shutdown();
    }

    #[test]
    fn receipts_endpoint() {
        let srv = spawn(host(), 0).unwrap();
        let _ = post(
            srv.port(),
            "/api/organelle/call",
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
}
