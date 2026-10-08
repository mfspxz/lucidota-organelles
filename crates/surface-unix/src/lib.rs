//! org-004 — Unix socket IPC surface.
//!
//! A second membrane around the same host: JSON-lines over a unix socket.
//! The contract tests are transport-agnostic, so this surface runs the
//! identical scenarios as native/REST/MCP (see organelle-equivalence).

use organelle_host::{CallContext, Host};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

/// One call, JSON-lines encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRequest {
    pub id: u64,
    pub caller: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub codon: String,
    pub op: String,
    pub input: Value,
}

/// One result. `receipt` is always populated — even for refusals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireResponse {
    pub id: u64,
    pub ok: bool,
    pub output: Option<Value>,
    pub error: Option<WireError>,
    pub receipt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub verdict: String,
    pub reason: String,
}

fn handle_conn(host: Arc<Host>, stream: UnixStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<WireRequest>(trimmed) {
            Err(e) => WireResponse {
                id: 0,
                ok: false,
                output: None,
                error: Some(WireError {
                    verdict: "rejected".to_string(),
                    reason: format!("malformed request: {e}"),
                }),
                receipt: String::new(),
            },
            Ok(req) => {
                let ctx = CallContext::new(req.caller.clone(), req.capabilities.clone());
                match host.call(&ctx, &req.codon, &req.op, req.input) {
                    Ok(output) => {
                        let receipt = host.receipts().last().map(|r| r.id.clone()).unwrap_or_default();
                        WireResponse { id: req.id, ok: true, output: Some(output), error: None, receipt }
                    }
                    Err(e) => WireResponse {
                        id: req.id,
                        ok: false,
                        output: None,
                        error: Some(WireError {
                            verdict: format!("{:?}", e.verdict),
                            reason: e.reason,
                        }),
                        receipt: e.receipt_id,
                    },
                }
            }
        };
        let mut out = serde_json::to_string(&resp).unwrap();
        out.push('\n');
        if writer.write_all(out.as_bytes()).is_err() {
            break;
        }
    }
}

pub struct UnixServerHandle {
    path: PathBuf,
    shutdown: mpsc::Sender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl UnixServerHandle {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop the server and remove the socket file.
    pub fn shutdown(mut self) {
        let _ = self.shutdown.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Spawn the unix-socket surface on `path` (stale socket file removed).
/// Returns a handle; dropping the handle does NOT stop the server —
/// call `shutdown()` explicitly.
pub fn spawn_server(host: Arc<Host>, path: &Path) -> std::io::Result<UnixServerHandle> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    let (tx, rx) = mpsc::channel::<()>();
    let path_buf = path.to_path_buf();
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
    Ok(UnixServerHandle { path: path_buf, shutdown: tx, thread: Some(thread) })
}

pub struct UnixClient;

impl UnixClient {
    /// Single request/response round-trip.
    pub fn call(path: &Path, req: &WireRequest) -> std::io::Result<WireResponse> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut out = serde_json::to_string(req).unwrap();
        out.push('\n');
        stream.write_all(out.as_bytes())?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        serde_json::from_str(line.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_sock(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("organelle-unix-test-{tag}-{}.sock", std::process::id()));
        p
    }

    fn host() -> Arc<Host> {
        let h = Host::new();
        h.register(ref_text_transform::organelle()).unwrap();
        h.register(ref_kv_store::organelle()).unwrap();
        h
    }

    #[test]
    fn roundtrip_ok() {
        let path = tmp_sock("ok");
        let srv = spawn_server(host(), &path).unwrap();
        let resp = UnixClient::call(
            &path,
            &WireRequest {
                id: 1,
                caller: "test".into(),
                capabilities: vec![],
                codon: "tt".into(),
                op: "transform".into(),
                input: serde_json::json!({"text": "hi", "mode": "upper"}),
            },
        )
        .unwrap();
        assert!(resp.ok);
        assert_eq!(resp.output.unwrap()["result"], serde_json::json!("HI"));
        assert!(!resp.receipt.is_empty());
        srv.shutdown();
        assert!(!path.exists());
    }

    #[test]
    fn denial_crosses_socket_with_receipt() {
        let path = tmp_sock("denied");
        let srv = spawn_server(host(), &path).unwrap();
        let resp = UnixClient::call(
            &path,
            &WireRequest {
                id: 2,
                caller: "test".into(),
                capabilities: vec![],
                codon: "kv".into(),
                op: "put".into(),
                input: serde_json::json!({"key": "a", "value": 1}),
            },
        )
        .unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.unwrap().verdict, "Denied");
        assert!(!resp.receipt.is_empty());
        srv.shutdown();
    }

    #[test]
    fn malformed_request_rejected() {
        let path = tmp_sock("malformed");
        let srv = spawn_server(host(), &path).unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.write_all(b"not json\n").unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let resp: WireResponse = serde_json::from_str(line.trim()).unwrap();
        assert!(!resp.ok);
        srv.shutdown();
    }

    #[test]
    fn same_contract_as_native() {
        // The identical scenario through native and socket must agree
        // byte-for-byte (spot check; the full matrix is org-007).
        let h = host();
        let path = tmp_sock("parity");
        let srv = spawn_server(h.clone(), &path).unwrap();
        let input = serde_json::json!({"text": "Parity", "mode": "slug"});
        let ctx = CallContext::new("test", vec![]);
        let native = h.call(&ctx, "tt", "transform", input.clone()).unwrap();
        let via_socket = UnixClient::call(
            &path,
            &WireRequest { id: 9, caller: "test".into(), capabilities: vec![], codon: "tt".into(), op: "transform".into(), input },
        )
        .unwrap();
        assert_eq!(
            organelle_manifest::canonical_json(&native),
            organelle_manifest::canonical_json(&via_socket.output.unwrap())
        );
        srv.shutdown();
    }
}
