//! org-007 — Behavioral equivalence harness.
//!
//! The same scenario suite runs against all four transport surfaces
//! (native, unix-socket, MCP, REST). Rules:
//! - `Exact` scenarios: canonical output must equal the expected value AND
//!   agree byte-for-byte across every transport. Any diff = fail.
//! - `Matches` scenarios: the predicate must hold on every transport.
//! - `ErrContains` scenarios: every transport must refuse with a matching message.

use organelle_host::{CallContext, Host};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Scenario model
// ---------------------------------------------------------------------------

/// What "passing" means for one scenario on one transport.
pub enum Expectation {
    /// Canonical output equals this on every transport; cross-transport
    /// byte-equality is additionally enforced (diff = fail).
    Exact(Value),
    /// Predicate holds on every transport's output.
    Matches(Box<dyn Fn(&Value) -> Result<(), String> + Send>),
    /// Every transport must refuse; the refusal message contains this.
    ErrContains(String),
}

pub struct Scenario {
    pub name: &'static str,
    pub codon: &'static str,
    pub op: &'static str,
    pub input: Value,
    pub capabilities: Vec<String>,
    pub expect: Expectation,
}

/// One transport surface behind a uniform call signature.
pub trait TransportAdapter {
    fn name(&self) -> &'static str;
    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String>;
}

pub struct TransportReport {
    pub transport: &'static str,
    pub passed: usize,
    pub failed: usize,
    pub failures: Vec<String>,
}

pub struct EquivalenceReport {
    pub scenarios: usize,
    pub transports: Vec<TransportReport>,
    pub cross_transport_diffs: Vec<String>,
}

impl EquivalenceReport {
    pub fn all_green(&self) -> bool {
        self.transports.iter().all(|t| t.failed == 0) && self.cross_transport_diffs.is_empty()
    }

    pub fn total_assertions(&self) -> usize {
        self.transports.iter().map(|t| t.passed + t.failed).sum::<usize>()
            + self.cross_transport_diffs.len()
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "equivalence: {} scenarios x {} transports\n",
            self.scenarios,
            self.transports.len()
        );
        for t in &self.transports {
            s.push_str(&format!(
                "  {:12} passed {:3} failed {:3}\n",
                t.transport, t.passed, t.failed
            ));
            for f in &t.failures {
                s.push_str(&format!("    FAIL: {f}\n"));
            }
        }
        for d in &self.cross_transport_diffs {
            s.push_str(&format!("  CROSS-DIFF: {d}\n"));
        }
        s.push_str(if self.all_green() { "  VERDICT: GREEN\n" } else { "  VERDICT: RED\n" });
        s
    }
}

/// Run every scenario on every adapter, then cross-diff the Exact outputs.
pub fn run_equivalence(
    scenarios: &[Scenario],
    adapters: &mut [Box<dyn TransportAdapter>],
) -> EquivalenceReport {
    // exact_outputs[adapter_idx][exact_scenario_idx] = (name, canonical)
    let mut exact_outputs: Vec<Vec<(String, String)>> =
        vec![Vec::new(); adapters.len()];
    let mut reports = Vec::new();

    for (ai, adapter) in adapters.iter_mut().enumerate() {
        let mut rep = TransportReport {
            transport: adapter.name(),
            passed: 0,
            failed: 0,
            failures: Vec::new(),
        };
        for sc in scenarios {
            let res = adapter.call("equivalence", &sc.capabilities, sc.codon, sc.op, sc.input.clone());
            match (&sc.expect, res) {
                (Expectation::ErrContains(needle), Err(msg)) => {
                    if msg.contains(needle.as_str()) {
                        rep.passed += 1;
                    } else {
                        rep.failed += 1;
                        rep.failures.push(format!(
                            "{}: refusal message {msg:?} does not contain {needle:?}",
                            sc.name
                        ));
                    }
                }
                (Expectation::ErrContains(needle), Ok(out)) => {
                    rep.failed += 1;
                    rep.failures.push(format!(
                        "{}: expected refusal containing {needle:?}, got output {out}",
                        sc.name
                    ));
                }
                (_, Err(e)) => {
                    // Record a sentinel so Exact cross-diff indexing stays aligned.
                    if matches!(sc.expect, Expectation::Exact(_)) {
                        exact_outputs[ai].push((sc.name.to_string(), format!("TRANSPORT-ERROR: {e}")));
                    }
                    rep.failed += 1;
                    rep.failures.push(format!("{}: transport error: {e}", sc.name));
                }
                (Expectation::Exact(want), Ok(out)) => {
                    let got_c = organelle_manifest::canonical_json(&out);
                    let want_c = organelle_manifest::canonical_json(want);
                    exact_outputs[ai].push((sc.name.to_string(), got_c.clone()));
                    if got_c == want_c {
                        rep.passed += 1;
                    } else {
                        rep.failed += 1;
                        rep.failures.push(format!(
                            "{}: mismatch\n      got:  {got_c}\n      want: {want_c}",
                            sc.name
                        ));
                    }
                }
                (Expectation::Matches(pred), Ok(out)) => match pred(&out) {
                    Ok(()) => rep.passed += 1,
                    Err(e) => {
                        rep.failed += 1;
                        rep.failures.push(format!("{}: predicate failed: {e}", sc.name));
                    }
                },
            }
        }
        reports.push(rep);
    }

    // Cross-transport diff: every Exact scenario must be byte-identical.
    let mut diffs = Vec::new();
    if adapters.len() > 1 {
        let exact_names: Vec<&str> = scenarios
            .iter()
            .filter(|s| matches!(s.expect, Expectation::Exact(_)))
            .map(|s| s.name)
            .collect();
        for (i, name) in exact_names.iter().enumerate() {
            let first = &exact_outputs[0][i].1;
            for (ai, outs) in exact_outputs.iter().enumerate().skip(1) {
                if &outs[i].1 != first {
                    diffs.push(format!(
                        "scenario '{name}': '{}' != '{}'\n    {}: {}\n    {}: {}",
                        adapters[0].name(),
                        adapters[ai].name(),
                        adapters[0].name(),
                        first,
                        adapters[ai].name(),
                        outs[i].1,
                    ));
                }
            }
        }
    }

    EquivalenceReport { scenarios: scenarios.len(), transports: reports, cross_transport_diffs: diffs }
}

// ---------------------------------------------------------------------------
// Host factory: all 12 reference organelles, shared file dirs.
// ---------------------------------------------------------------------------

/// Build a host with all 12 reference organelles. `outbox_dir` / `cas_dir`
/// are shared across transports so file-backed outputs stay comparable.
pub fn build_host(outbox_dir: &str, cas_dir: &str) -> Arc<Host> {
    let h = Host::new();
    h.register(ref_kv_store::organelle()).unwrap();
    h.register(ref_http_fetch::organelle()).unwrap();
    h.register(ref_text_transform::organelle()).unwrap();
    h.register(ref_json_validate::organelle()).unwrap();
    h.register(ref_hash_seal::organelle()).unwrap();
    h.register(ref_time_oracle::organelle()).unwrap();
    h.register(ref_geo_point::organelle()).unwrap();
    h.register(ref_ledger_append::organelle()).unwrap();
    h.register(ref_notify::organelle_with_outbox(outbox_dir.to_string())).unwrap();
    h.register(ref_scrape_extract::organelle()).unwrap();
    h.register(ref_model_call::organelle()).unwrap();
    h.register(ref_file_cas::organelle_with_dir(cas_dir.to_string())).unwrap();
    h
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

pub struct NativeAdapter {
    host: Arc<Host>,
}

impl NativeAdapter {
    pub fn new(outbox_dir: &str, cas_dir: &str) -> Self {
        NativeAdapter { host: build_host(outbox_dir, cas_dir) }
    }
}

impl TransportAdapter for NativeAdapter {
    fn name(&self) -> &'static str {
        "native"
    }

    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let ctx = CallContext::new(caller, caps.to_vec());
        self.host
            .call(&ctx, codon, op, input)
            .map_err(|e| format!("{:?}: {}", e.verdict, e.reason))
    }
}

pub struct UnixAdapter {
    host: Arc<Host>,
    path: PathBuf,
    next_id: u64,
    _server: surface_unix::UnixServerHandle,
}

impl UnixAdapter {
    pub fn new(outbox_dir: &str, cas_dir: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("organelle-eq-{}.sock", std::process::id()));
        let host = build_host(outbox_dir, cas_dir);
        let server = surface_unix::spawn_server(host.clone(), &path)
            .expect("unix surface spawn");
        // Give the accept loop a moment to bind.
        std::thread::sleep(Duration::from_millis(50));
        UnixAdapter { host, path, next_id: 1, _server: server }
    }
}

impl TransportAdapter for UnixAdapter {
    fn name(&self) -> &'static str {
        "unix_socket"
    }

    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        // P0: authority comes from a host-issued grant, never from
        // caller-supplied claims on the wire.
        let grant = self.host.issue_grant(caller, caps.to_vec(), 300);
        let resp = surface_unix::UnixClient::call(
            &self.path,
            &surface_unix::WireRequest {
                id,
                caller: caller.to_string(),
                grant,
                codon: codon.to_string(),
                op: op.to_string(),
                input,
            },
        )
        .map_err(|e| format!("io: {e}"))?;
        if resp.ok {
            resp.output.ok_or_else(|| "ok without output".to_string())
        } else {
            let e = resp.error.unwrap();
            Err(format!("{}: {}", e.verdict, e.reason))
        }
    }
}

pub struct McpAdapter {
    host: Arc<Host>,
    tools: Vec<surface_mcp::McpTool>,
    next_id: u64,
}

impl McpAdapter {
    pub fn new(outbox_dir: &str, cas_dir: &str) -> Self {
        let host = build_host(outbox_dir, cas_dir);
        let tools = surface_mcp::generate_tools(&host);
        McpAdapter { host, tools, next_id: 1 }
    }
}

impl TransportAdapter for McpAdapter {
    fn name(&self) -> &'static str {
        "mcp"
    }

    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        // Find the generated tool for this codon.op (same mapping as stdio).
        let tool = self
            .tools
            .iter()
            .find(|t| t.codon == codon && t.op == op)
            .ok_or_else(|| format!("no MCP tool for {codon}.{op}"))?;
        let id = self.next_id;
        self.next_id += 1;
        // P0: the envelope carries a host-issued grant; capabilities are
        // derived from the grant, never from caller-supplied claims.
        let grant = self.host.issue_grant(caller, caps.to_vec(), 300);
        let mut args = input;
        if let Some(obj) = args.as_object_mut() {
            obj.insert("grant".to_string(), Value::String(grant));
            obj.insert("caller".to_string(), Value::String(caller.to_string()));
        }
        let msg = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool.name, "arguments": args},
        });
        let resp = surface_mcp::dispatch(&self.host, &self.tools, &msg)
            .ok_or_else(|| "no response (notification?)".to_string())?;
        if let Some(err) = resp.get("error") {
            return Err(format!("jsonrpc: {err}"));
        }
        let result = resp.get("result").ok_or("no result")?;
        let is_error = result.get("isError").and_then(|v| v.as_bool()).unwrap_or(false);
        let text = result["content"][0]["text"]
            .as_str()
            .ok_or("no content text")?;
        if is_error {
            Err(text.to_string())
        } else {
            serde_json::from_str(text).map_err(|e| format!("output parse: {e}"))
        }
    }
}

pub struct RestAdapter {
    host: Arc<Host>,
    base: String,
    _server: surface_rest::RestHandle,
}

impl RestAdapter {
    pub fn new(outbox_dir: &str, cas_dir: &str) -> Self {
        let host = build_host(outbox_dir, cas_dir);
        let server = surface_rest::spawn(host.clone(), 0).expect("rest spawn");
        let base = server.base_url();
        std::thread::sleep(Duration::from_millis(50));
        RestAdapter { host, base, _server: server }
    }

    fn post(&self, grant: &str, body: &Value) -> Result<Value, String> {
        let text = serde_json::to_string(body).map_err(|e| e.to_string())?;
        let host_port = self.base.trim_start_matches("http://");
        let mut s = TcpStream::connect(host_port).map_err(|e| format!("connect: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        // P0: authority travels as a host-issued grant in the Authorization
        // header — never as caller-supplied claims in the body.
        let req = format!(
            "POST /api/organelle/call HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {grant}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        );
        s.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).map_err(|e| format!("read: {e}"))?;
        let resp = String::from_utf8_lossy(&buf);
        let (_, resp_body) = resp.split_once("\r\n\r\n").ok_or("no body")?;
        serde_json::from_str(resp_body).map_err(|e| format!("parse: {e}"))
    }
}

impl TransportAdapter for RestAdapter {
    fn name(&self) -> &'static str {
        "rest"
    }

    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let body = serde_json::json!({
            "caller": caller,
            "codon": codon,
            "op": op,
            "input": input,
        });
        let grant = self.host.issue_grant(caller, caps.to_vec(), 300);
        let resp = self.post(&grant, &body)?;
        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            resp.get("output").cloned().ok_or_else(|| "ok without output".to_string())
        } else {
            let e = &resp["error"];
            Err(format!("{}: {}", e["verdict"].as_str().unwrap_or("?"), e["reason"].as_str().unwrap_or("?")))
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture HTTP server (deterministic page for hf/se scenarios)
// ---------------------------------------------------------------------------

pub const FIXTURE_HTML: &str = "<html><head><title>Fixture</title></head><body><p>Hello <a href=\"/x\">there</a></p></body></html>";

/// Spawn a deterministic fixture page server; returns its port. Serves
/// forever on a daemon thread (enough for the matrix).
pub fn spawn_fixture_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if let Ok(mut s) = conn {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let body = FIXTURE_HTML.as_bytes();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.write_all(body);
            }
        }
    });
    // Let it bind before callers connect.
    std::thread::sleep(Duration::from_millis(50));
    port
}

// ---------------------------------------------------------------------------
// The scenario suite
// ---------------------------------------------------------------------------

fn caps(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn pred<F>(f: F) -> Expectation
where
    F: Fn(&Value) -> Result<(), String> + Send + 'static,
{
    Expectation::Matches(Box::new(f))
}

/// Build the shared scenario suite. `fixture_url` = fixture page URL,
/// `ledger_path` = shared JSONL path for la-append, `outbox_dir` = shared
/// notify outbox (used by a predicate).
pub fn build_scenarios(
    fixture_url: &str,
    ledger_path: &str,
    outbox_dir: &str,
) -> Vec<Scenario> {
    let write_caps = caps(&["kv.write"]);
    let net_caps = caps(&["net.fetch"]);
    let ledger_caps = caps(&["ledger.write"]);
    let notify_caps = caps(&["notify.send"]);
    let model_caps = caps(&["model.call"]);
    let cas_caps = caps(&["cas.write"]);

    let fixture_len = FIXTURE_HTML.len();
    let hf_expected = serde_json::json!({
        "status": 200,
        "headers": [
            {"name": "Content-Length", "value": fixture_len.to_string()},
            {"name": "Connection", "value": "close"},
        ],
        "body": FIXTURE_HTML,
        "bytes": fixture_len,
        "truncated": false,
    });
    let se_expected = serde_json::json!({
        "url": fixture_url,
        "status": 200,
        "title": "Fixture",
        "text": "Hello there",
        "links": ["/x"],
        "bytes": fixture_len,
        "truncated": false,
    });
    let fc_id = organelle_manifest::sha256_hex(b"cas-content");
    let hs_digest = organelle_manifest::hash_value(&serde_json::json!("abc"));
    let outbox_owned = outbox_dir.to_string();

    vec![
        Scenario {
            name: "kv-put",
            codon: "kv",
            op: "put",
            input: serde_json::json!({"key": "eq1", "value": {"n": 1}}),
            capabilities: write_caps.clone(),
            expect: Expectation::Exact(serde_json::json!({"ok": true, "key": "eq1"})),
        },
        Scenario {
            name: "kv-get",
            codon: "kv",
            op: "get",
            input: serde_json::json!({"key": "eq1"}),
            capabilities: vec![],
            expect: Expectation::Exact(
                serde_json::json!({"found": true, "key": "eq1", "value": {"n": 1}}),
            ),
        },
        Scenario {
            name: "kv-list",
            codon: "kv",
            op: "list",
            input: serde_json::json!({}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({"keys": ["eq1"], "count": 1})),
        },
        Scenario {
            name: "kv-put-denied",
            codon: "kv",
            op: "put",
            input: serde_json::json!({"key": "nope", "value": 1}),
            capabilities: vec![],
            expect: Expectation::ErrContains("Denied".to_string()),
        },
        Scenario {
            name: "tt-upper",
            codon: "tt",
            op: "transform",
            input: serde_json::json!({"text": "hello", "mode": "upper"}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({"mode": "upper", "result": "HELLO"})),
        },
        Scenario {
            name: "tt-slug",
            codon: "tt",
            op: "transform",
            input: serde_json::json!({"text": "Hi There!", "mode": "slug"}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({"mode": "slug", "result": "hi-there"})),
        },
        Scenario {
            name: "jv-ok",
            codon: "jv",
            op: "validate",
            input: serde_json::json!({
                "value": {"a": 1},
                "schema": {"type": "object", "required": ["a"]},
            }),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({"valid": true, "errors": []})),
        },
        Scenario {
            name: "jv-bad",
            codon: "jv",
            op: "validate",
            input: serde_json::json!({
                "value": {},
                "schema": {"type": "object", "required": ["a"]},
            }),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({
                "valid": false, "errors": ["$: missing required property \"a\""],
            })),
        },
        Scenario {
            name: "hs-seal-shape",
            codon: "hs",
            op: "seal",
            input: serde_json::json!({"data": "abc"}),
            capabilities: vec![],
            expect: pred(|v| {
                let d = v["sha256"].as_str().ok_or("no sha256")?;
                if d.len() != 64 {
                    return Err("sha256 not 64 hex".into());
                }
                if !v["sealed_at"].as_str().unwrap_or("").ends_with('Z') {
                    return Err("sealed_at not ISO".into());
                }
                Ok(())
            }),
        },
        Scenario {
            name: "hs-verify",
            codon: "hs",
            op: "verify",
            input: serde_json::json!({"data": "abc", "sha256": hs_digest}),
            capabilities: vec![],
            expect: Expectation::Exact(
                serde_json::json!({"match": true, "computed": hs_digest}),
            ),
        },
        Scenario {
            name: "to-now",
            codon: "to",
            op: "now",
            input: serde_json::json!({}),
            capabilities: vec![],
            expect: pred(|v| {
                if !v["utc_iso"].as_str().unwrap_or("").ends_with('Z') {
                    return Err("utc_iso shape".into());
                }
                if v["unix_secs"].as_u64().unwrap_or(0) < 1_700_000_000 {
                    return Err("unix_secs too small".into());
                }
                Ok(())
            }),
        },
        Scenario {
            name: "gp-distance",
            codon: "gp",
            op: "distance",
            input: serde_json::json!({
                "lat1": 49.2827, "lon1": -123.1207,
                "lat2": 49.2067, "lon2": -122.9111,
            }),
            capabilities: vec![],
            expect: pred(|v| {
                let m = v["meters"].as_f64().ok_or("no meters")?;
                if !(15_000.0..20_000.0).contains(&m) {
                    return Err(format!("meters out of band: {m}"));
                }
                Ok(())
            }),
        },
        Scenario {
            name: "hf-fetch",
            codon: "hf",
            op: "fetch",
            input: serde_json::json!({"url": fixture_url}),
            capabilities: net_caps.clone(),
            expect: Expectation::Exact(hf_expected),
        },
        Scenario {
            name: "se-extract",
            codon: "se",
            op: "extract",
            input: serde_json::json!({"url": fixture_url}),
            capabilities: net_caps,
            expect: Expectation::Exact(se_expected),
        },
        Scenario {
            name: "la-append",
            codon: "la",
            op: "append",
            input: serde_json::json!({"entry": {"k": "v"}, "ledger_path": ledger_path}),
            capabilities: ledger_caps,
            expect: pred(|v| {
                if v["ok"] != serde_json::json!(true) {
                    return Err("not ok".into());
                }
                if v["entry_hash"].as_str().unwrap_or("").len() != 64 {
                    return Err("entry_hash shape".into());
                }
                Ok(())
            }),
        },
        Scenario {
            name: "nt-send",
            codon: "nt",
            op: "send",
            input: serde_json::json!({"channel": "eq", "title": "T", "body": "B"}),
            capabilities: notify_caps,
            expect: pred(move |v| {
                if v["queued"] != serde_json::json!(true) {
                    return Err("not queued".into());
                }
                if v["id"].as_str().unwrap_or("").len() != 64 {
                    return Err("id shape".into());
                }
                let p = v["outbox_path"].as_str().unwrap_or("");
                if !p.starts_with(&outbox_owned) {
                    return Err(format!("outbox_path outside shared dir: {p}"));
                }
                if !std::path::Path::new(p).exists() {
                    return Err("outbox file missing".into());
                }
                Ok(())
            }),
        },
        Scenario {
            name: "mc-stub",
            codon: "mc",
            op: "chat",
            input: serde_json::json!({
                "messages": [{"role": "user", "content": "ping"}],
            }),
            capabilities: model_caps,
            expect: Expectation::Exact(serde_json::json!({
                "reply": "stub-echo: ping",
                "model": "stub",
                "provider": "stub",
                "stub": true,
            })),
        },
        Scenario {
            name: "fc-put",
            codon: "fc",
            op: "put",
            input: serde_json::json!({"content": "cas-content"}),
            capabilities: cas_caps,
            expect: Expectation::Exact(
                serde_json::json!({"id": fc_id, "bytes": 11}),
            ),
        },
        Scenario {
            name: "fc-get",
            codon: "fc",
            op: "get",
            input: serde_json::json!({"id": fc_id}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({
                "found": true, "id": fc_id, "content": "cas-content",
            })),
        },
    ]
}
