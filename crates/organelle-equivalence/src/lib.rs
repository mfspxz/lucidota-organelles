//! org-007 — Behavioral equivalence harness.
//!
//! The same scenario suite runs against all four transport surfaces
//! (native, unix-socket, MCP, REST). Rules:
//! - `Exact` scenarios: canonical output must equal the expected value AND
//!   agree byte-for-byte across every transport. Any diff = fail.
//! - `Matches` scenarios: the predicate must hold on every transport.
//! - `ErrContains` scenarios: every transport must refuse with a matching message.
//!
//! GO-50 Phase 1, family F4 — typed extension: the same harness runs
//! typed scenarios (`build_typed_scenarios`) against the typed
//! adapters (`TypedNativeAdapter` / `TypedUnixAdapter` /
//! `TypedMcpAdapter` / `TypedRestAdapter`), which route through the
//! dispatcher's typed projections. `run_typed_equivalence` adds a
//! second comparison the untyped matrix does not need: receipt
//! payloads (canonical domain outcome + truth + provenance, with
//! transport-specific metadata stripped) must agree across paths.

use organelle_host::{CallContext, Host};
use organelle_typed::{InvocationEnvelope, LockRegistry, TypedDispatcher};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub mod hostile;
pub use hostile::{
    build_hostile_cases, build_hostile_host, build_hostile_token, build_typed_hostile_cases,
    register_hostile_organelles, run_hostile_equivalence, HostileCase, HostileExpect,
    HostileReport, HostileToken, HostileTransportReport,
};

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
    /// Present a hostile case: the token is built (and attacked) against
    /// this adapter's own host, then carried over this adapter's wire
    /// format exactly as a real attacker would present it. For
    /// [`HostileToken::ReplayedSingleUse`] the token is presented twice
    /// and the SECOND verdict is returned.
    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String>;
    /// The arrival transport this surface binds (never caller-supplied).
    fn arrival(&self) -> organelle_manifest::Transport;
    /// The most recent receipt this adapter's host emitted.
    fn last_receipt(&self) -> Option<organelle_host::Receipt>;
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
        self.transports
            .iter()
            .map(|t| t.passed + t.failed)
            .sum::<usize>()
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
        s.push_str(if self.all_green() {
            "  VERDICT: GREEN\n"
        } else {
            "  VERDICT: RED\n"
        });
        s
    }
}

/// Run every scenario on every adapter, then cross-diff the Exact outputs.
pub fn run_equivalence(
    scenarios: &[Scenario],
    adapters: &mut [Box<dyn TransportAdapter>],
) -> EquivalenceReport {
    // exact_outputs[adapter_idx][exact_scenario_idx] = (name, canonical)
    let mut exact_outputs: Vec<Vec<(String, String)>> = vec![Vec::new(); adapters.len()];
    let mut reports = Vec::new();

    for (ai, adapter) in adapters.iter_mut().enumerate() {
        let mut rep = TransportReport {
            transport: adapter.name(),
            passed: 0,
            failed: 0,
            failures: Vec::new(),
        };
        for sc in scenarios {
            let res = adapter.call(
                "equivalence",
                &sc.capabilities,
                sc.codon,
                sc.op,
                sc.input.clone(),
            );
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
                        exact_outputs[ai]
                            .push((sc.name.to_string(), format!("TRANSPORT-ERROR: {e}")));
                    }
                    rep.failed += 1;
                    rep.failures
                        .push(format!("{}: transport error: {e}", sc.name));
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
                        rep.failures
                            .push(format!("{}: predicate failed: {e}", sc.name));
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

    EquivalenceReport {
        scenarios: scenarios.len(),
        transports: reports,
        cross_transport_diffs: diffs,
    }
}

// ---------------------------------------------------------------------------
// Host factory: all 12 reference organelles, shared file dirs.
// ---------------------------------------------------------------------------

/// Build a host with all 12 reference organelles. `outbox_dir` / `cas_dir`
/// are shared across transports so file-backed outputs stay comparable.
///
/// P1 lane 3: the harness declares the side-effect policy every deployment
/// needs — write roots covering the shared dirs (their parents; the ledger
/// path is a sibling) and an egress allowlist for the fixture HTTP server
/// (localhost only). Without these the membrane defaults to deny-all and
/// the file/network scenarios fail closed, by design.
pub fn build_host(outbox_dir: &str, cas_dir: &str) -> Arc<Host> {
    let h = Host::new();
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    for d in [outbox_dir, cas_dir] {
        if let Some(parent) = std::path::Path::new(d).parent() {
            if !roots.contains(&parent.to_path_buf()) {
                roots.push(parent.to_path_buf());
            }
        }
    }
    h.set_write_roots(roots)
        .expect("equivalence write roots must canonicalize");
    h.set_egress_policy(
        organelle_host::EgressPolicy::allowlist(&["127.0.0.1", "localhost"])
            .expect("equivalence egress allowlist parses"),
    );
    h.register(ref_kv_store::organelle()).unwrap();
    h.register(ref_http_fetch::organelle()).unwrap();
    h.register(ref_text_transform::organelle()).unwrap();
    h.register(ref_json_validate::organelle()).unwrap();
    h.register(ref_hash_seal::organelle()).unwrap();
    h.register(ref_time_oracle::organelle()).unwrap();
    h.register(ref_geo_point::organelle()).unwrap();
    h.register(ref_ledger_append::organelle()).unwrap();
    h.register(ref_notify::organelle_with_outbox(outbox_dir.to_string()))
        .unwrap();
    h.register(ref_scrape_extract::organelle()).unwrap();
    h.register(ref_model_call::organelle()).unwrap();
    h.register(ref_file_cas::organelle_with_dir(cas_dir.to_string()))
        .unwrap();
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
        NativeAdapter {
            host: hostile::build_hostile_host(outbox_dir, cas_dir),
        }
    }

    fn present(
        &self,
        caller_claim: &str,
        token: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        self.host
            .call_with_grant(
                token,
                Some(caller_claim),
                organelle_manifest::Transport::Native,
                codon,
                op,
                input,
            )
            .map(|ok| ok.output)
            .map_err(|e| format!("{:?}: {}", e.verdict, e.reason))
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
            .map(|ok| ok.output)
            .map_err(|e| format!("{:?}: {}", e.verdict, e.reason))
    }

    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String> {
        let token = hostile::build_hostile_token(&self.host, case);
        if case.token == hostile::HostileToken::ReplayedSingleUse {
            // First presentation is honored; the asserted verdict is the replay's.
            let _ = self.present(
                case.caller_claim,
                &token,
                case.codon,
                case.op,
                case.input.clone(),
            );
        }
        self.present(
            case.caller_claim,
            &token,
            case.codon,
            case.op,
            case.input.clone(),
        )
    }

    fn arrival(&self) -> organelle_manifest::Transport {
        organelle_manifest::Transport::Native
    }

    fn last_receipt(&self) -> Option<organelle_host::Receipt> {
        self.host.receipts().last().cloned()
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
        let host = hostile::build_hostile_host(outbox_dir, cas_dir);
        let server = surface_unix::spawn_server(host.clone(), &path).expect("unix surface spawn");
        // Give the accept loop a moment to bind.
        std::thread::sleep(Duration::from_millis(50));
        UnixAdapter {
            host,
            path,
            next_id: 1,
            _server: server,
        }
    }

    fn present(
        &mut self,
        caller_claim: &str,
        token: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        // P0: authority comes from a host-issued grant, never from
        // caller-supplied claims on the wire.
        let resp = surface_unix::UnixClient::call(
            &self.path,
            &surface_unix::WireRequest {
                id,
                caller: caller_claim.to_string(),
                grant: token.to_string(),
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
        let grant = self.host.issue_grant(caller, caps.to_vec(), 300);
        self.present(caller, &grant, codon, op, input)
    }

    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String> {
        let token = hostile::build_hostile_token(&self.host, case);
        if case.token == hostile::HostileToken::ReplayedSingleUse {
            let _ = self.present(
                case.caller_claim,
                &token,
                case.codon,
                case.op,
                case.input.clone(),
            );
        }
        self.present(
            case.caller_claim,
            &token,
            case.codon,
            case.op,
            case.input.clone(),
        )
    }

    fn arrival(&self) -> organelle_manifest::Transport {
        organelle_manifest::Transport::UnixSocket
    }

    fn last_receipt(&self) -> Option<organelle_host::Receipt> {
        self.host.receipts().last().cloned()
    }
}

pub struct McpAdapter {
    host: Arc<Host>,
    tools: Vec<surface_mcp::McpTool>,
    next_id: u64,
}

impl McpAdapter {
    pub fn new(outbox_dir: &str, cas_dir: &str) -> Self {
        let host = hostile::build_hostile_host(outbox_dir, cas_dir);
        let tools = surface_mcp::generate_tools(&host);
        McpAdapter {
            host,
            tools,
            next_id: 1,
        }
    }

    fn present(
        &mut self,
        caller_claim: &str,
        token: &str,
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
        let mut args = input;
        if let Some(obj) = args.as_object_mut() {
            obj.insert("grant".to_string(), Value::String(token.to_string()));
            obj.insert(
                "caller".to_string(),
                Value::String(caller_claim.to_string()),
            );
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
        let is_error = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
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
        let grant = self.host.issue_grant(caller, caps.to_vec(), 300);
        self.present(caller, &grant, codon, op, input)
    }

    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String> {
        let token = hostile::build_hostile_token(&self.host, case);
        if case.token == hostile::HostileToken::ReplayedSingleUse {
            let _ = self.present(
                case.caller_claim,
                &token,
                case.codon,
                case.op,
                case.input.clone(),
            );
        }
        self.present(
            case.caller_claim,
            &token,
            case.codon,
            case.op,
            case.input.clone(),
        )
    }

    fn arrival(&self) -> organelle_manifest::Transport {
        organelle_manifest::Transport::Mcp
    }

    fn last_receipt(&self) -> Option<organelle_host::Receipt> {
        self.host.receipts().last().cloned()
    }
}

pub struct RestAdapter {
    host: Arc<Host>,
    base: String,
    _server: surface_rest::RestHandle,
}

impl RestAdapter {
    pub fn new(outbox_dir: &str, cas_dir: &str) -> Self {
        let host = hostile::build_hostile_host(outbox_dir, cas_dir);
        let server = surface_rest::spawn(host.clone(), 0).expect("rest spawn");
        let base = server.base_url();
        std::thread::sleep(Duration::from_millis(50));
        RestAdapter {
            host,
            base,
            _server: server,
        }
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
        s.write_all(req.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).map_err(|e| format!("read: {e}"))?;
        let resp = String::from_utf8_lossy(&buf);
        let (_, resp_body) = resp.split_once("\r\n\r\n").ok_or("no body")?;
        serde_json::from_str(resp_body).map_err(|e| format!("parse: {e}"))
    }

    fn present(
        &mut self,
        caller_claim: &str,
        token: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let body = serde_json::json!({
            "caller": caller_claim,
            "codon": codon,
            "op": op,
            "input": input,
        });
        let resp = self.post(token, &body)?;
        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            resp.get("output")
                .cloned()
                .ok_or_else(|| "ok without output".to_string())
        } else {
            let e = &resp["error"];
            Err(format!(
                "{}: {}",
                e["verdict"].as_str().unwrap_or("?"),
                e["reason"].as_str().unwrap_or("?")
            ))
        }
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
        let grant = self.host.issue_grant(caller, caps.to_vec(), 300);
        self.present(caller, &grant, codon, op, input)
    }

    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String> {
        let token = hostile::build_hostile_token(&self.host, case);
        if case.token == hostile::HostileToken::ReplayedSingleUse {
            let _ = self.present(
                case.caller_claim,
                &token,
                case.codon,
                case.op,
                case.input.clone(),
            );
        }
        self.present(
            case.caller_claim,
            &token,
            case.codon,
            case.op,
            case.input.clone(),
        )
    }

    fn arrival(&self) -> organelle_manifest::Transport {
        organelle_manifest::Transport::Rest
    }

    fn last_receipt(&self) -> Option<organelle_host::Receipt> {
        self.host.receipts().last().cloned()
    }
}

// ---------------------------------------------------------------------------
// Typed adapters (F4): the same four transports, through the dispatcher
// ---------------------------------------------------------------------------

/// Build a host + typed dispatcher with ref-typed-hash registered once
/// via `register_typed` — the typed projection's single registration.
/// Each typed adapter owns its own dispatcher (mirroring the untyped
/// adapters, which each own their own host).
pub fn build_typed_dispatcher() -> Arc<TypedDispatcher> {
    let host = Host::new();
    let d = TypedDispatcher::new(host, LockRegistry::with_go50());
    d.register_typed(ref_typed_hash::TypedHash::new())
        .expect("typed-hash must register");
    // F5: the second typed organelle — every typed adapter (and the
    // acceptance test's equivalence pass) now proves projections for
    // TWO organelles, not one.
    d.register_typed(ref_typed_commit::TypedCommit::new())
        .expect("typed-commit must register");
    Arc::new(d)
}

fn typed_err(e: organelle_typed::TypedDispatchError) -> String {
    format!("{}: {}", e.verdict(), e)
}

pub struct TypedNativeAdapter {
    dispatcher: Arc<TypedDispatcher>,
}

impl TypedNativeAdapter {
    pub fn new() -> Self {
        TypedNativeAdapter {
            dispatcher: build_typed_dispatcher(),
        }
    }

    fn present(
        &self,
        caller_claim: &str,
        token: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let envelope = InvocationEnvelope {
            caller: caller_claim.to_string(),
            codon: codon.to_string(),
            op: op.to_string(),
            input,
            trace_id: None,
            capabilities: Vec::new(),
            transport: organelle_manifest::Transport::Native,
            grant: Some(token.to_string()),
        };
        self.dispatcher
            .dispatch(envelope)
            .map(|ok| ok.output)
            .map_err(typed_err)
    }
}

impl Default for TypedNativeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportAdapter for TypedNativeAdapter {
    fn name(&self) -> &'static str {
        "typed-native"
    }

    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let mut env = InvocationEnvelope::native(caller, codon, op, input);
        env.capabilities = caps.to_vec();
        self.dispatcher
            .dispatch(env)
            .map(|ok| ok.output)
            .map_err(typed_err)
    }

    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String> {
        let token = hostile::build_hostile_token(self.dispatcher.host(), case);
        if case.token == hostile::HostileToken::ReplayedSingleUse {
            let _ = self.present(
                case.caller_claim,
                &token,
                case.codon,
                case.op,
                case.input.clone(),
            );
        }
        self.present(
            case.caller_claim,
            &token,
            case.codon,
            case.op,
            case.input.clone(),
        )
    }

    fn arrival(&self) -> organelle_manifest::Transport {
        organelle_manifest::Transport::Native
    }

    fn last_receipt(&self) -> Option<organelle_host::Receipt> {
        self.dispatcher.host().receipts().last().cloned()
    }
}

pub struct TypedUnixAdapter {
    dispatcher: Arc<TypedDispatcher>,
    path: PathBuf,
    next_id: u64,
    _server: surface_unix::UnixServerHandle,
}

impl TypedUnixAdapter {
    pub fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("organelle-eq-typed-{}.sock", std::process::id()));
        let dispatcher = build_typed_dispatcher();
        let server =
            surface_unix::spawn_server_typed(dispatcher.clone(), &path).expect("typed unix spawn");
        std::thread::sleep(Duration::from_millis(50));
        TypedUnixAdapter {
            dispatcher,
            path,
            next_id: 1,
            _server: server,
        }
    }

    fn present(
        &mut self,
        caller_claim: &str,
        token: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let resp = surface_unix::UnixClient::call(
            &self.path,
            &surface_unix::WireRequest {
                id,
                caller: caller_claim.to_string(),
                grant: token.to_string(),
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

impl TransportAdapter for TypedUnixAdapter {
    fn name(&self) -> &'static str {
        "typed-unix_socket"
    }

    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let grant = self
            .dispatcher
            .host()
            .issue_grant(caller, caps.to_vec(), 300);
        self.present(caller, &grant, codon, op, input)
    }

    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String> {
        let token = hostile::build_hostile_token(self.dispatcher.host(), case);
        if case.token == hostile::HostileToken::ReplayedSingleUse {
            let _ = self.present(
                case.caller_claim,
                &token,
                case.codon,
                case.op,
                case.input.clone(),
            );
        }
        self.present(
            case.caller_claim,
            &token,
            case.codon,
            case.op,
            case.input.clone(),
        )
    }

    fn arrival(&self) -> organelle_manifest::Transport {
        organelle_manifest::Transport::UnixSocket
    }

    fn last_receipt(&self) -> Option<organelle_host::Receipt> {
        self.dispatcher.host().receipts().last().cloned()
    }
}

pub struct TypedMcpAdapter {
    dispatcher: Arc<TypedDispatcher>,
    tools: Vec<surface_mcp::McpTool>,
    next_id: u64,
}

impl TypedMcpAdapter {
    pub fn new() -> Self {
        let dispatcher = build_typed_dispatcher();
        let tools = surface_mcp::generate_tools_typed(&dispatcher);
        TypedMcpAdapter {
            dispatcher,
            tools,
            next_id: 1,
        }
    }

    fn present(
        &mut self,
        caller_claim: &str,
        token: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let tool = self
            .tools
            .iter()
            .find(|t| t.codon == codon && t.op == op)
            .ok_or_else(|| format!("no MCP tool for {codon}.{op}"))?;
        let id = self.next_id;
        self.next_id += 1;
        let mut args = input;
        if let Some(obj) = args.as_object_mut() {
            obj.insert("grant".to_string(), Value::String(token.to_string()));
            obj.insert(
                "caller".to_string(),
                Value::String(caller_claim.to_string()),
            );
        }
        let msg = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool.name, "arguments": args},
        });
        let resp = surface_mcp::dispatch_typed(&self.dispatcher, &self.tools, &msg)
            .ok_or_else(|| "no response (notification?)".to_string())?;
        if let Some(err) = resp.get("error") {
            return Err(format!("jsonrpc: {err}"));
        }
        let result = resp.get("result").ok_or("no result")?;
        let is_error = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
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

impl TransportAdapter for TypedMcpAdapter {
    fn name(&self) -> &'static str {
        "typed-mcp"
    }

    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let grant = self
            .dispatcher
            .host()
            .issue_grant(caller, caps.to_vec(), 300);
        self.present(caller, &grant, codon, op, input)
    }

    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String> {
        let token = hostile::build_hostile_token(self.dispatcher.host(), case);
        if case.token == hostile::HostileToken::ReplayedSingleUse {
            let _ = self.present(
                case.caller_claim,
                &token,
                case.codon,
                case.op,
                case.input.clone(),
            );
        }
        self.present(
            case.caller_claim,
            &token,
            case.codon,
            case.op,
            case.input.clone(),
        )
    }

    fn arrival(&self) -> organelle_manifest::Transport {
        organelle_manifest::Transport::Mcp
    }

    fn last_receipt(&self) -> Option<organelle_host::Receipt> {
        self.dispatcher.host().receipts().last().cloned()
    }
}

pub struct TypedRestAdapter {
    dispatcher: Arc<TypedDispatcher>,
    base: String,
    _server: surface_rest::RestHandle,
}

impl TypedRestAdapter {
    pub fn new() -> Self {
        let dispatcher = build_typed_dispatcher();
        let server = surface_rest::spawn_typed(dispatcher.clone(), 0).expect("typed rest spawn");
        let base = server.base_url();
        std::thread::sleep(Duration::from_millis(50));
        TypedRestAdapter {
            dispatcher,
            base,
            _server: server,
        }
    }

    fn post(&self, grant: &str, body: &Value) -> Result<Value, String> {
        let text = serde_json::to_string(body).map_err(|e| e.to_string())?;
        let host_port = self.base.trim_start_matches("http://");
        let mut s = TcpStream::connect(host_port).map_err(|e| format!("connect: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        let req = format!(
            "POST /v1/organelle/call HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {grant}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
            text.len()
        );
        s.write_all(req.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).map_err(|e| format!("read: {e}"))?;
        let resp = String::from_utf8_lossy(&buf);
        let (_, resp_body) = resp.split_once("\r\n\r\n").ok_or("no body")?;
        serde_json::from_str(resp_body).map_err(|e| format!("parse: {e}"))
    }

    fn present(
        &mut self,
        caller_claim: &str,
        token: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let body = serde_json::json!({
            "caller": caller_claim,
            "codon": codon,
            "op": op,
            "input": input,
        });
        let resp = self.post(token, &body)?;
        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            resp.get("output")
                .cloned()
                .ok_or_else(|| "ok without output".to_string())
        } else {
            let e = &resp["error"];
            Err(format!(
                "{}: {}",
                e["verdict"].as_str().unwrap_or("?"),
                e["reason"].as_str().unwrap_or("?")
            ))
        }
    }
}

impl TransportAdapter for TypedRestAdapter {
    fn name(&self) -> &'static str {
        "typed-rest"
    }

    fn call(
        &mut self,
        caller: &str,
        caps: &[String],
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, String> {
        let grant = self
            .dispatcher
            .host()
            .issue_grant(caller, caps.to_vec(), 300);
        self.present(caller, &grant, codon, op, input)
    }

    fn hostile_call(&mut self, case: &hostile::HostileCase) -> Result<Value, String> {
        let token = hostile::build_hostile_token(self.dispatcher.host(), case);
        if case.token == hostile::HostileToken::ReplayedSingleUse {
            let _ = self.present(
                case.caller_claim,
                &token,
                case.codon,
                case.op,
                case.input.clone(),
            );
        }
        self.present(
            case.caller_claim,
            &token,
            case.codon,
            case.op,
            case.input.clone(),
        )
    }

    fn arrival(&self) -> organelle_manifest::Transport {
        organelle_manifest::Transport::Rest
    }

    fn last_receipt(&self) -> Option<organelle_host::Receipt> {
        self.dispatcher.host().receipts().last().cloned()
    }
}

// ---------------------------------------------------------------------------
// Typed receipt comparison (F4)
// ---------------------------------------------------------------------------

/// The canonical domain payload of a receipt: everything that must
/// agree across transports for the same invocation, with
/// transport-specific metadata stripped — receipt id, timestamp, seq,
/// chain prev, arrival transport — and the provenance production
/// timestamp, which differs per call by nature. Truth + provenance
/// (minus `produced_at`) ARE part of the payload: they must match
/// across paths. A receipt with no typed outcome (untyped calls,
/// refusals) carries null truth/provenance.
pub fn receipt_payload(r: &organelle_host::Receipt) -> Value {
    let (truth, provenance) = match &r.typed_outcome {
        Some(t) => {
            let mut prov = t.get("provenance").cloned().unwrap_or(Value::Null);
            if let Some(obj) = prov.as_object_mut() {
                obj.remove("produced_at");
            }
            (t.get("truth").cloned().unwrap_or(Value::Null), prov)
        }
        None => (Value::Null, Value::Null),
    };
    serde_json::json!({
        "codon": r.codon,
        "op": r.op,
        "caller": r.caller,
        "verdict": format!("{:?}", r.verdict),
        "valence": format!("{:?}", r.valence),
        "input_hash": r.input_hash,
        "output_hash": r.output_hash,
        // F6-H10: the granted caps are part of the domain outcome —
        // stripping them made cross-transport capability differences
        // invisible to the typed matrix.
        "granted_capabilities": r.granted_capabilities,
        "truth": truth,
        "provenance": provenance,
    })
}

pub struct TypedEquivalenceReport {
    pub base: EquivalenceReport,
    pub receipt_diffs: Vec<String>,
}

impl TypedEquivalenceReport {
    pub fn all_green(&self) -> bool {
        self.base.all_green() && self.receipt_diffs.is_empty()
    }

    pub fn summary(&self) -> String {
        let mut s = self.base.summary();
        s.push_str(&format!(
            "  receipt payloads: {} diff(s)\n",
            self.receipt_diffs.len()
        ));
        for d in &self.receipt_diffs {
            s.push_str(&format!("  RECEIPT-DIFF: {d}\n"));
        }
        s.push_str(if self.all_green() {
            "  TYPED VERDICT: GREEN\n"
        } else {
            "  TYPED VERDICT: RED\n"
        });
        s
    }
}

/// Run typed scenarios on every adapter, then compare receipt
/// payloads. Output equivalence runs through the existing
/// [`run_equivalence`] (no second harness); receipt equivalence is a
/// second pass over the same scenarios — the typed scenarios are
/// pure/deterministic, so a second pass costs nothing and keeps the
/// two comparisons separate. Each adapter's `last_receipt` after its
/// call is that call's receipt (single-threaded runner).
pub fn run_typed_equivalence(
    scenarios: &[Scenario],
    adapters: &mut [Box<dyn TransportAdapter>],
) -> TypedEquivalenceReport {
    let base = run_equivalence(scenarios, adapters);
    let mut payloads: Vec<Vec<(String, String)>> = vec![Vec::new(); adapters.len()];
    for (ai, adapter) in adapters.iter_mut().enumerate() {
        for sc in scenarios {
            let _ = adapter.call(
                "equivalence",
                &sc.capabilities,
                sc.codon,
                sc.op,
                sc.input.clone(),
            );
            let payload = adapter
                .last_receipt()
                .map(|r| organelle_manifest::canonical_json(&receipt_payload(&r)))
                .unwrap_or_else(|| "NO-RECEIPT".to_string());
            payloads[ai].push((sc.name.to_string(), payload));
        }
    }
    let mut receipt_diffs = Vec::new();
    if adapters.len() > 1 {
        for (i, sc) in scenarios.iter().enumerate() {
            let first = &payloads[0][i].1;
            for (ai, outs) in payloads.iter().enumerate().skip(1) {
                if &outs[i].1 != first {
                    receipt_diffs.push(format!(
                        "scenario '{}': receipt payload '{}' != '{}'\n    {}: {}\n    {}: {}",
                        sc.name,
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
    TypedEquivalenceReport {
        base,
        receipt_diffs,
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
pub fn build_scenarios(fixture_url: &str, ledger_path: &str, outbox_dir: &str) -> Vec<Scenario> {
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
            expect: Expectation::Exact(serde_json::json!({"match": true, "computed": hs_digest})),
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
            expect: Expectation::Exact(serde_json::json!({"id": fc_id, "bytes": 11})),
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

/// Typed scenario suite (F4): ref-typed-hash (`th`) through the typed
/// adapters. Pure/deterministic, so both the output pass and the
/// receipt pass of [`run_typed_equivalence`] run the same inputs.
/// Known vectors: sha256("abc") and sha256("abd") are the standard
/// test vectors; sha256("") is the empty-string vector.
pub fn build_typed_scenarios() -> Vec<Scenario> {
    let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let abd = "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9";
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    // F5: expected tc values, computed with the organelle's own pure
    // helpers (the oracle shares the hash functions; the organelle's
    // unit tests verify those helpers against independently built
    // records, so this is not circular). Both commits name their
    // parent EXPLICITLY (genesis "" for the first) so the receipt
    // pass — which re-runs every scenario — is idempotent too:
    // idempotency is by the full (key, value, parent) triple, and a
    // bare re-commit would parent onto the moving head instead.
    // "A second pass costs nothing" stays literally true.
    let tc_vh1 = ref_typed_commit::value_hash_for(&serde_json::json!("hello"));
    let tc_id1 = ref_typed_commit::commit_id_for("greeting", &tc_vh1, "");
    let tc_vh2 = ref_typed_commit::value_hash_for(&serde_json::json!("goodbye"));
    let tc_id2 = ref_typed_commit::commit_id_for("farewell", &tc_vh2, &tc_id1);
    let tc_caps = caps(&["tc.commit"]);
    let tc_unknown = "00".repeat(32);
    vec![
        Scenario {
            name: "th-sha256-abc",
            codon: "th",
            op: "sha256",
            input: serde_json::json!({"text": "abc"}),
            capabilities: vec![],
            expect: Expectation::Exact(
                serde_json::json!({"algorithm": "sha256", "hex": abc, "input_bytes": 3}),
            ),
        },
        Scenario {
            name: "th-sha256-empty",
            codon: "th",
            op: "sha256",
            input: serde_json::json!({"text": ""}),
            capabilities: vec![],
            expect: Expectation::Exact(
                serde_json::json!({"algorithm": "sha256", "hex": empty, "input_bytes": 0}),
            ),
        },
        Scenario {
            name: "th-verify-match",
            codon: "th",
            op: "verify",
            input: serde_json::json!({"text": "abc", "expected_hex": abc}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({"matches": true, "hex": abc})),
        },
        Scenario {
            name: "th-verify-mismatch",
            codon: "th",
            op: "verify",
            input: serde_json::json!({"text": "abd", "expected_hex": abc}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({"matches": false, "hex": abd})),
        },
        Scenario {
            name: "th-verify-missing-field",
            codon: "th",
            op: "verify",
            input: serde_json::json!({"text": "abc"}),
            capabilities: vec![],
            expect: Expectation::ErrContains("Rejected".to_string()),
        },
        // --- tc (typed-commit): the second typed organelle -----------
        // Order matters: commit-basic runs first (genesis), the rest
        // read the state it creates. Every adapter runs the same
        // sequence on its own fresh store, so all outputs agree.
        Scenario {
            name: "tc-commit-basic",
            codon: "tc",
            op: "commit",
            input: serde_json::json!({"key": "greeting", "value": "hello", "parent": ""}),
            capabilities: tc_caps.clone(),
            expect: Expectation::Exact(serde_json::json!({
                "commit_id": tc_id1, "key": "greeting",
                "value_hash": tc_vh1, "parent": "", "seq": 1,
            })),
        },
        Scenario {
            name: "tc-commit-second",
            codon: "tc",
            op: "commit",
            input: serde_json::json!({"key": "farewell", "value": "goodbye", "parent": tc_id1}),
            capabilities: tc_caps.clone(),
            expect: Expectation::Exact(serde_json::json!({
                "commit_id": tc_id2, "key": "farewell",
                "value_hash": tc_vh2, "parent": tc_id1, "seq": 2,
            })),
        },
        Scenario {
            name: "tc-get-after-commit",
            codon: "tc",
            op: "get",
            input: serde_json::json!({"commit_id": tc_id1}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({
                "found": true, "commit_id": tc_id1,
                "key": "greeting", "value": "hello",
            })),
        },
        Scenario {
            name: "tc-verify-after-commit",
            codon: "tc",
            op: "verify",
            input: serde_json::json!({"commit_id": tc_id1}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({
                "found": true, "commit_id": tc_id1,
                "hash_matches": true, "parent_known": true,
            })),
        },
        Scenario {
            name: "tc-verify-unknown",
            codon: "tc",
            op: "verify",
            input: serde_json::json!({"commit_id": tc_unknown}),
            capabilities: vec![],
            expect: Expectation::Exact(serde_json::json!({
                "found": false, "commit_id": tc_unknown,
                "hash_matches": false, "parent_known": false,
            })),
        },
        Scenario {
            name: "tc-commit-denied-no-cap",
            codon: "tc",
            op: "commit",
            input: serde_json::json!({"key": "x", "value": 1}),
            capabilities: vec![],
            expect: Expectation::ErrContains("Denied".to_string()),
        },
        Scenario {
            name: "tc-commit-missing-field",
            codon: "tc",
            op: "commit",
            input: serde_json::json!({"key": "x"}),
            capabilities: tc_caps.clone(),
            expect: Expectation::ErrContains("Rejected".to_string()),
        },
    ]
}

// -- F6: hostile review -------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::{CallVerdict, Receipt, ReceiptKind};
    use organelle_manifest::{Transport, Valence};

    fn receipt_with_caps(caps: Vec<String>) -> Receipt {
        Receipt {
            id: "r1".to_string(),
            ts: "2026-11-18T00:00:00.000000Z".to_string(),
            seq: 1,
            kind: ReceiptKind::Invocation,
            codon: "th".to_string(),
            op: "sha256".to_string(),
            manifest_version: "1.0.0".to_string(),
            caller: "test".to_string(),
            granted_capabilities: caps,
            transport: Some(Transport::Mcp),
            input_hash: "aa".to_string(),
            output_hash: "bb".to_string(),
            verdict: CallVerdict::Ok,
            valence: Valence::Proven,
            typed_outcome: Some(serde_json::json!({
                "truth": {"status": "proven", "basis": "test"},
                "provenance": {
                    "source": "computed_locally",
                    "input_hash": "aa",
                    "produced_by": "th@1.0.0",
                    "produced_at": "2026-11-18T00:00:00.000000Z"
                }
            })),
            prev: "GENESIS".to_string(),
            note: None,
        }
    }

    /// F6-H10: the receipt payload must keep `granted_capabilities`.
    /// The payload is the typed matrix's comparison surface; stripping
    /// the caps makes cross-transport capability differences invisible
    /// (e.g. one transport binding wider authority than another).
    #[test]
    fn f6_receipt_payload_keeps_granted_capabilities() {
        let a = receipt_with_caps(vec!["equivalence".to_string()]);
        let b = receipt_with_caps(vec!["equivalence".to_string(), "admin.*".to_string()]);
        let pa = receipt_payload(&a);
        let pb = receipt_payload(&b);
        assert_eq!(
            pa["granted_capabilities"],
            serde_json::json!(["equivalence"]),
            "payload must carry the granted caps"
        );
        assert_ne!(
            organelle_manifest::canonical_json(&pa),
            organelle_manifest::canonical_json(&pb),
            "receipts differing only in granted caps must differ in payload"
        );
    }
}
