//! org-004 — Unix socket IPC surface.
//!
//! A second membrane around the same host: JSON-lines over a unix socket.
//! The contract tests are transport-agnostic, so this surface runs the
//! identical scenarios as native/REST/MCP (see organelle-equivalence).

use organelle_host::Host;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

/// One call, JSON-lines encoded.
///
/// P0: authority is unforgeable at this boundary. The request carries NO
/// capability claims — only a host-issued, HMAC-authenticated `grant`.
/// Capabilities are derived solely from the verified grant; unknown fields
/// (including any caller-supplied `capabilities`) are rejected outright.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequest {
    pub id: u64,
    /// Claimed caller identity; must match the grant's subject.
    pub caller: String,
    /// Host-issued capability grant (see `Host::issue_grant`). Empty or
    /// invalid -> denial, never default-allow.
    pub grant: String,
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
                // Authority comes ONLY from the grant. The claimed caller
                // identity is bound to the grant's subject inside
                // `call_with_grant`; a missing/invalid grant is denied.
                match host.call_with_grant(&req.grant, Some(&req.caller), &req.codon, &req.op, req.input) {
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
    use organelle_host::CallContext;

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

    fn req(id: u64, h: &Host, caller: &str, caps: &[&str], codon: &str, op: &str, input: Value) -> WireRequest {
        WireRequest {
            id,
            caller: caller.into(),
            grant: h.issue_grant(
                caller,
                caps.iter().map(|s| s.to_string()).collect(),
                300,
            ),
            codon: codon.into(),
            op: op.into(),
            input,
        }
    }

    #[test]
    fn roundtrip_ok() {
        let h = host();
        let path = tmp_sock("ok");
        let srv = spawn_server(h.clone(), &path).unwrap();
        let resp = UnixClient::call(
            &path,
            &req(1, &h, "test", &[], "tt", "transform",
                serde_json::json!({"text": "hi", "mode": "upper"})),
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
        let h = host();
        let path = tmp_sock("denied");
        let srv = spawn_server(h.clone(), &path).unwrap();
        // Valid grant, but no kv.write -> the host denies on authority.
        let resp = UnixClient::call(
            &path,
            &req(2, &h, "test", &[], "kv", "put",
                serde_json::json!({"key": "a", "value": 1})),
        )
        .unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.unwrap().verdict, "Denied");
        assert!(!resp.receipt.is_empty());
        srv.shutdown();
    }

    #[test]
    fn granted_capability_allows_gated_op() {
        let h = host();
        let path = tmp_sock("gated");
        let srv = spawn_server(h.clone(), &path).unwrap();
        let resp = UnixClient::call(
            &path,
            &req(3, &h, "test", &["kv.write"], "kv", "put",
                serde_json::json!({"key": "a", "value": 1})),
        )
        .unwrap();
        assert!(resp.ok, "{resp:?}");
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
            &req(9, &h, "test", &[], "tt", "transform", input),
        )
        .unwrap();
        assert_eq!(
            organelle_manifest::canonical_json(&native),
            organelle_manifest::canonical_json(&via_socket.output.unwrap())
        );
        srv.shutdown();
    }

    // -- P0 forged-capability tests: every forgery must be denied ---------

    fn raw_line(path: &Path, line: &str) -> WireResponse {
        let mut stream = UnixStream::connect(path).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut reader = BufReader::new(stream);
        let mut out = String::new();
        reader.read_line(&mut out).unwrap();
        serde_json::from_str(out.trim()).unwrap()
    }

    #[test]
    fn forged_grant_denied() {
        let h = host();
        let path = tmp_sock("forged");
        let srv = spawn_server(h.clone(), &path).unwrap();
        // Take a valid grant and flip a payload nibble: the signature
        // is checked before the payload is even decoded, so this must
        // fail as an invalid signature.
        let good = h.issue_grant("test", vec!["kv.write".to_string()], 300);
        let (payload_hex, tag) = good.split_once('.').unwrap();
        let mut chars: Vec<char> = payload_hex.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        let forged = format!("{}.{}", chars.into_iter().collect::<String>(), tag);
        let resp = UnixClient::call(
            &path,
            &WireRequest {
                id: 1, caller: "test".into(), grant: forged,
                codon: "kv".into(), op: "put".into(),
                input: serde_json::json!({"key": "a", "value": 1}),
            },
        )
        .unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_ref().unwrap().verdict, "Denied");
        assert!(resp.error.unwrap().reason.contains("signature"));
        assert!(!resp.receipt.is_empty());
        srv.shutdown();
    }

    #[test]
    fn escalated_capability_denied() {
        let h = host();
        let path = tmp_sock("escalate");
        let srv = spawn_server(h.clone(), &path).unwrap();
        // Grant confers only kv.read; kv.put requires kv.write.
        let resp = UnixClient::call(
            &path,
            &req(1, &h, "test", &["kv.read"], "kv", "put",
                serde_json::json!({"key": "a", "value": 1})),
        )
        .unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_ref().unwrap().verdict, "Denied");
        assert!(resp.error.unwrap().reason.contains("kv.write"));
        srv.shutdown();
    }

    #[test]
    fn caller_supplied_capabilities_rejected() {
        // The old forgeable field is gone: sending it is a malformed
        // request (input-rejected), not silently ignored.
        let h = host();
        let path = tmp_sock("capfield");
        let srv = spawn_server(h.clone(), &path).unwrap();
        let grant = h.issue_grant("test", vec![], 300);
        let line = serde_json::json!({
            "id": 1, "caller": "test", "grant": grant,
            "capabilities": ["kv.write", "admin.*"],
            "codon": "kv", "op": "put",
            "input": {"key": "a", "value": 1},
        })
        .to_string();
        let resp = raw_line(&path, &line);
        assert!(!resp.ok);
        assert_eq!(resp.error.as_ref().unwrap().verdict, "rejected");
        srv.shutdown();
    }

    #[test]
    fn replayed_grant_denied() {
        let h = host();
        let path = tmp_sock("replay");
        let srv = spawn_server(h.clone(), &path).unwrap();
        let grant = h.issue_single_use_grant("test", vec!["kv.write".to_string()], 300);
        let mk = |id| WireRequest {
            id, caller: "test".into(), grant: grant.clone(),
            codon: "kv".into(), op: "put".into(),
            input: serde_json::json!({"key": "a", "value": 1}),
        };
        let first = UnixClient::call(&path, &mk(1)).unwrap();
        assert!(first.ok, "{first:?}");
        let second = UnixClient::call(&path, &mk(2)).unwrap();
        assert!(!second.ok);
        assert_eq!(second.error.as_ref().unwrap().verdict, "Denied");
        assert!(second.error.unwrap().reason.contains("replay"));
        srv.shutdown();
    }

    #[test]
    fn wrong_caller_grant_denied() {
        let h = host();
        let path = tmp_sock("wrongcaller");
        let srv = spawn_server(h.clone(), &path).unwrap();
        // Grant issued to alice, presented as mallory.
        let grant = h.issue_grant("alice", vec!["kv.write".to_string()], 300);
        let resp = UnixClient::call(
            &path,
            &WireRequest {
                id: 1, caller: "mallory".into(), grant,
                codon: "kv".into(), op: "put".into(),
                input: serde_json::json!({"key": "a", "value": 1}),
            },
        )
        .unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_ref().unwrap().verdict, "Denied");
        assert!(resp.error.unwrap().reason.contains("does not match grant subject"));
        srv.shutdown();
    }

    #[test]
    fn missing_grant_denied_not_allowed() {
        let h = host();
        let path = tmp_sock("nogrant");
        let srv = spawn_server(h.clone(), &path).unwrap();
        let resp = UnixClient::call(
            &path,
            &WireRequest {
                id: 1, caller: "test".into(), grant: String::new(),
                codon: "tt".into(), op: "transform".into(),
                input: serde_json::json!({"text": "hi", "mode": "upper"}),
            },
        )
        .unwrap();
        assert!(!resp.ok, "no auth material must never default-allow");
        assert_eq!(resp.error.as_ref().unwrap().verdict, "Denied");
        srv.shutdown();
    }
}
