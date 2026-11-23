//! org-031 — Reference organelle: edge-worker-shell (codon `ew`).
//!
//! The thin Cloudflare Workers shell every estate worker
//! re-implements today (GAP-07 in the 2026-11-22 decomposition
//! map: five scoped softwares — WRK, EXC, RTR, TRN, TEN — need it;
//! tentacle-corp alone writes the same shell five times in JS:
//! the edge webhook router, the private ledger viewer, the status
//! ingest, the heartbeat receiver, the Odin map worker — each with
//! its own copy of the secret gate, its own routing, its own
//! error shapes).  The one PROVEN production instance of the
//! pattern in Rust is the Exchange's worker
//! (`~/workspace/exchange/rs/exchange-worker`): thin glue that
//! translates Workers HTTP / scheduled events into core calls and
//! touches nothing else.  This crate is that glue, generalised:
//!
//! * **A small router** — method + path patterns with `:param`
//!   segments and a trailing `*wildcard`.  No match is an honest
//!   404 envelope; a path that exists under other methods is a
//!   405 with an `Allow` header, never a misleading 404.
//! * **A fail-closed secret gate** — the ctcc-router / TEN
//!   pattern, as middleware that runs *before* routing, so an
//!   unauthenticated request is rejected before any handler runs
//!   and learns nothing about which routes exist.  The comparison
//!   is timing-safe (constant-time over the longer input, length
//!   difference folded in).  No secret configured → deny.
//!   Empty presented value → deny.  There is no configuration in
//!   which the gate fails open, and no default secret, header, or
//!   exemption: every knob is required construction data.
//! * **JSON in/out helpers with honest error envelopes** — the
//!   estate shape: success is `{"ok": true, ...}`, failure is
//!   `{"ok": false, "error": "<code>", "message": "<detail>"}`.
//!   A handler error becomes its envelope; nothing is swallowed
//!   into a bare 500 with no body.
//! * **Binding access composed over `ref-cf-storage`** — handlers
//!   receive a [`Ctx`] whose KV / D1 / R2 / Queue accessors are
//!   org-027's `wasm_bindings` types, resolved from the worker
//!   env the glue was handed.  The shell adds no storage code of
//!   its own.
//! * **Fetch + scheduled entry points** — the core dispatch
//!   ([`Shell::handle`] / [`Shell::handle_scheduled`]) is
//!   runtime-agnostic and driven natively in this crate's tests
//!   through a mock env; the `workers` feature adds the thin
//!   workers-rs glue ([`workers_glue`]) that converts real
//!   Workers requests/events into core calls, exactly the
//!   exchange-worker shape.
//!
//! A new worker is then: shell + organelles + route handlers,
//! nothing else — see `examples/minimal-worker/` for the whole
//! of one.
//!
//! Caller-supplied knobs only: the gate's header name, secret
//! binding name, and exempt paths are all required fields of
//! [`GateConfig`]; the router has no built-in routes (not even a
//! health route — a worker that wants one registers it and, if
//! it should be public, exempts it).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};

// ---------------------------------------------------------------------
// Requests and responses.  Runtime-agnostic values: the workers
// glue converts platform types into these, native tests construct
// them directly, and a future runtime only owes the same
// conversion.
// ---------------------------------------------------------------------

/// One HTTP request, as the shell sees it.  Header names are
/// stored lowercased (HTTP header names are case-insensitive;
/// the constructors and the glue normalise so lookups never
/// depend on the sender's casing).  `path` carries no query
/// string; query pairs live in `query`, percent-decoded.
/// Route params are not part of construction — the router fills
/// them during dispatch, and handlers read them via
/// [`ShellRequest::param`].
#[derive(Debug, Clone, PartialEq)]
pub struct ShellRequest {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    params: BTreeMap<String, String>,
}

impl ShellRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        ShellRequest {
            method: method.into().to_ascii_uppercase(),
            path: path.into(),
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
            params: BTreeMap::new(),
        }
    }

    /// Split a raw request target (`/v1/items?tag=a&tag=b`) into
    /// path + decoded query pairs.
    pub fn from_target(method: impl Into<String>, target: &str) -> Self {
        let (path, raw_query) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target, ""),
        };
        let mut req = ShellRequest::new(method, path);
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            req.query.push((percent_decode(k), percent_decode(v)));
        }
        req
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn with_json_body(self, value: &Value) -> Self {
        let bytes = serde_json::to_vec(value).expect("a Value always serializes");
        self.with_header("content-type", "application/json")
            .with_body(bytes)
    }

    /// The first value of a header, by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The first value of a query parameter.
    pub fn query_first(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// A route parameter captured by the router (`:id`,
    /// `*rest`).  `None` until dispatch, and for names the
    /// matched pattern does not declare.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(|s| s.as_str())
    }

    pub fn body_text(&self) -> Result<&str, ShellError> {
        std::str::from_utf8(&self.body).map_err(|_| {
            ShellError::bad_request("request body is not valid UTF-8")
        })
    }

    /// Parse the body as JSON.  An empty body is an error, not a
    /// silent `null` — handlers that accept empty bodies read
    /// `body` themselves and state so.
    pub fn body_json(&self) -> Result<Value, ShellError> {
        if self.body.is_empty() {
            return Err(ShellError::bad_request("request body is empty, expected JSON"));
        }
        serde_json::from_slice(&self.body)
            .map_err(|e| ShellError::bad_request(format!("request body is not valid JSON: {e}")))
    }

    pub fn body_as<T: serde::de::DeserializeOwned>(&self) -> Result<T, ShellError> {
        let value = self.body_json()?;
        serde_json::from_value(value)
            .map_err(|e| ShellError::bad_request(format!("request body shape: {e}")))
    }
}

/// A response-body stream: byte chunks in order, with a string
/// error for a body that dies mid-flight (the consumer renders
/// the failure; the shell never silently truncates).  `Send` on
/// native; on wasm32 the bound is dropped — a Worker's streams
/// are single-threaded values, the same per-target pattern as
/// ref-https-transport's `ChunkStream`.
#[cfg(not(target_arch = "wasm32"))]
pub type ShellStream =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<Vec<u8>, String>> + Send>>;
#[cfg(target_arch = "wasm32")]
pub type ShellStream =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<Vec<u8>, String>>>>;

/// A streaming response body, carried beside the buffered body
/// of a [`ShellResponse`].  A newtype so the response can keep a
/// useful `Debug` without pretending a stream is printable data.
pub struct ShellBodyStream(pub ShellStream);

impl ShellBodyStream {
    pub fn new(stream: ShellStream) -> Self {
        ShellBodyStream(stream)
    }

    pub fn into_inner(self) -> ShellStream {
        self.0
    }
}

impl std::fmt::Debug for ShellBodyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<stream>")
    }
}

/// One HTTP response, as the shell produces it.  A response is
/// either buffered (`body`, `stream: None`) or streaming
/// (`stream: Some(..)`, `body` empty) — the runtime glue answers
/// a streaming response with a streamed body, never a buffered
/// copy.  (No `Clone`/`PartialEq`: a live stream is neither.)
#[derive(Debug)]
pub struct ShellResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub stream: Option<ShellBodyStream>,
}

impl ShellResponse {
    pub fn bytes(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        ShellResponse {
            status,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: body.into(),
            stream: None,
        }
    }

    /// A streaming response: the status and headers are final
    /// when the handler returns; the body arrives as the stream
    /// yields it.
    pub fn stream(status: u16, content_type: &str, stream: ShellStream) -> Self {
        ShellResponse {
            status,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: Vec::new(),
            stream: Some(ShellBodyStream::new(stream)),
        }
    }

    pub fn text(status: u16, text: impl Into<String>) -> Self {
        ShellResponse::bytes(status, "text/plain; charset=utf-8", text.into().into_bytes())
    }

    /// A success envelope: `{"ok": true, ...}`.  An object value
    /// is merged into the envelope (its own `ok`, if any, is
    /// overwritten — the envelope is the shell's word, not the
    /// handler's); any other value rides under `data`.
    pub fn ok(value: Value) -> Self {
        ShellResponse::ok_with_status(200, value)
    }

    pub fn ok_with_status(status: u16, value: Value) -> Self {
        let envelope = match value {
            Value::Object(mut map) => {
                map.insert("ok".to_string(), Value::Bool(true));
                Value::Object(map)
            }
            other => serde_json::json!({"ok": true, "data": other}),
        };
        ShellResponse::raw_json(status, &envelope)
    }

    /// A JSON body with no envelope — for handlers whose route
    /// contract is a bare document (a status.json, a feed).
    pub fn raw_json(status: u16, value: &Value) -> Self {
        let bytes = serde_json::to_vec(value).expect("a Value always serializes");
        ShellResponse::bytes(status, "application/json", bytes)
    }

    /// The honest error envelope:
    /// `{"ok": false, "error": code, "message": detail}`.
    /// `message` is omitted when empty — never present-but-blank.
    pub fn error(status: u16, code: &str, message: &str) -> Self {
        let mut envelope = serde_json::json!({"ok": false, "error": code});
        if !message.is_empty() {
            envelope["message"] = Value::String(message.to_string());
        }
        ShellResponse::raw_json(status, &envelope)
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.into()));
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn body_json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// A handler error, carried as (status, code, message) and
/// rendered by the shell as an error envelope.  The constructors
/// cover the statuses the estate's workers actually return; the
/// fields are public so a handler can state any other status
/// without a wrapper type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl ShellError {
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        ShellError {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        ShellError::new(400, "bad_request", message)
    }

    pub fn unauthorized() -> Self {
        // No message: the gate's refusal must not narrate itself.
        ShellError::new(401, "unauthorized", "")
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        ShellError::new(403, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        ShellError::new(404, "not_found", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        ShellError::new(500, "internal", message)
    }

    pub fn into_response(self) -> ShellResponse {
        ShellResponse::error(self.status, &self.code, &self.message)
    }
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)
    }
}

impl std::error::Error for ShellError {}

/// Minimal percent-decoding for query pairs (`%XX`, `+` for
/// space).  Invalid sequences pass through literally — a query
/// string is data, not a validity gate.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi * 16 + lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------
// Timing-safe equality — the TEN / ctcc-router pattern in Rust.
// The JS originals early-return on length mismatch; this one does
// not: it folds the length difference into the accumulator and
// always scans the longer input, so neither content nor length
// leaks through an early exit.  (ref-credential-broker's verify
// uses the same construction.)
// ---------------------------------------------------------------------

pub fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: usize = a.len() ^ b.len();
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = if i < a.len() { a[i] } else { 0 };
        let y = if i < b.len() { b[i] } else { 0 };
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

// ---------------------------------------------------------------------
// Router.  Patterns are `/`-separated: a literal segment matches
// itself, `:name` captures one segment, and a trailing `*name`
// captures the rest of the path (possibly empty).  Matching is
// over raw path segments — the Workers URL path arrives
// percent-encoded and TEN's routes are plain ASCII, so the shell
// does not decode before matching (params may therefore carry
// encodings; handlers that care decode).
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Segment {
    Literal(String),
    Param(String),
    Wildcard(String),
}

#[derive(Clone)]
struct Route {
    method: String,
    pattern: String,
    segments: Vec<Segment>,
    handler: Handler,
}

fn parse_pattern(pattern: &str) -> Result<Vec<Segment>, ShellError> {
    if !pattern.starts_with('/') {
        return Err(ShellError::internal(format!(
            "route pattern must start with '/': {pattern}"
        )));
    }
    let parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let mut segments = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        if let Some(name) = part.strip_prefix(':') {
            if name.is_empty() {
                return Err(ShellError::internal(format!(
                    "route pattern has an empty param name: {pattern}"
                )));
            }
            segments.push(Segment::Param(name.to_string()));
        } else if let Some(name) = part.strip_prefix('*') {
            if name.is_empty() || i + 1 != parts.len() {
                return Err(ShellError::internal(format!(
                    "route pattern wildcard must be the last segment and named: {pattern}"
                )));
            }
            segments.push(Segment::Wildcard(name.to_string()));
        } else {
            segments.push(Segment::Literal(part.to_string()));
        }
    }
    Ok(segments)
}

/// Match one pattern against a path.  On success, the captured
/// params.  Pure and allocation-light; also exposed as data
/// through the organelle surface (`match_route`).
fn match_segments(segments: &[Segment], path: &str) -> Option<BTreeMap<String, String>> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut params = BTreeMap::new();
    let mut i = 0;
    for seg in segments {
        match seg {
            Segment::Literal(lit) => {
                if parts.get(i).copied() != Some(lit.as_str()) {
                    return None;
                }
                i += 1;
            }
            Segment::Param(name) => {
                let part = parts.get(i).copied()?;
                params.insert(name.clone(), part.to_string());
                i += 1;
            }
            Segment::Wildcard(name) => {
                params.insert(name.clone(), parts[i..].join("/"));
                i = parts.len();
            }
        }
    }
    if i == parts.len() {
        Some(params)
    } else {
        None
    }
}

/// The outcome of a route lookup, stated honestly: a handler, a
/// known path under the wrong method, or nothing.
enum RouteOutcome {
    Matched(Handler, BTreeMap<String, String>),
    MethodNotAllowed(Vec<String>),
    NotFound,
}

#[derive(Default)]
struct Router {
    routes: Vec<Route>,
}

impl Router {
    fn add(&mut self, method: &str, pattern: &str, handler: Handler) -> Result<(), ShellError> {
        let segments = parse_pattern(pattern)?;
        let method = method.to_ascii_uppercase();
        if self
            .routes
            .iter()
            .any(|r| r.method == method && r.pattern == pattern)
        {
            return Err(ShellError::internal(format!(
                "duplicate route: {method} {pattern}"
            )));
        }
        self.routes.push(Route {
            method,
            pattern: pattern.to_string(),
            segments,
            handler,
        });
        Ok(())
    }

    fn lookup(&self, method: &str, path: &str) -> RouteOutcome {
        let mut allowed: Vec<String> = Vec::new();
        for route in &self.routes {
            if let Some(params) = match_segments(&route.segments, path) {
                if route.method == method {
                    return RouteOutcome::Matched(route.handler.clone(), params);
                }
                if !allowed.contains(&route.method) {
                    allowed.push(route.method.clone());
                }
            }
        }
        if allowed.is_empty() {
            RouteOutcome::NotFound
        } else {
            allowed.sort();
            RouteOutcome::MethodNotAllowed(allowed)
        }
    }
}

// ---------------------------------------------------------------------
// The secret gate.  Fail-closed in every direction the estate's
// JS shells are: no configured secret in the env → deny; missing
// or empty presented value → deny; mismatch → deny.  Exemptions
// are exact paths or `prefix/*` patterns, stated by the caller —
// the gate ships none of its own.
// ---------------------------------------------------------------------

/// Gate configuration.  Every field is required: the header the
/// secret arrives in, the env binding that holds the expected
/// secret, the exempt paths, and whether the ledger-viewer-style
/// `?key=` query fallback is accepted (stated explicitly because
/// a secret in a URL is a different exposure than a header —
/// some estate shells accept it, most must not).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    pub header: String,
    pub secret_env: String,
    pub exempt: Vec<String>,
    pub query_param: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecretGate {
    config: GateConfig,
}

impl SecretGate {
    pub fn new(config: GateConfig) -> Result<Self, ShellError> {
        if config.header.trim().is_empty() {
            return Err(ShellError::internal("gate header name must not be empty"));
        }
        if config.secret_env.trim().is_empty() {
            return Err(ShellError::internal("gate secret_env must not be empty"));
        }
        Ok(SecretGate { config })
    }

    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    fn is_exempt(&self, path: &str) -> bool {
        self.config.exempt.iter().any(|ex| match ex.strip_suffix("/*") {
            Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")),
            None => path == ex,
        })
    }

    /// True when the request may proceed.  Exemption is checked
    /// first (an exempt path is public by the caller's stated
    /// policy, secret or no secret); everything else needs the
    /// configured secret to exist and the presented value to
    /// match it in timing-safe comparison.
    pub fn allows(&self, req: &ShellRequest, env: &dyn ShellEnv) -> bool {
        if self.is_exempt(&req.path) {
            return true;
        }
        let expected = match env.secret(&self.config.secret_env) {
            Some(s) if !s.is_empty() => s,
            _ => return false, // fail closed: no secret configured = deny all
        };
        let presented = req
            .header(&self.config.header)
            .map(|s| s.to_string())
            .or_else(|| {
                self.config
                    .query_param
                    .as_ref()
                    .and_then(|name| req.query_first(name).map(|s| s.to_string()))
            });
        match presented {
            Some(given) if !given.is_empty() => {
                timing_safe_eq(given.as_bytes(), expected.as_bytes())
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------
// The environment: what a handler may reach.  Secrets and vars by
// name (the workers glue reads them from the real Env; tests use
// MockEnv), and — on wasm32 — the raw env value, from which the
// ref-cf-storage bindings are resolved.
// ---------------------------------------------------------------------

pub trait ShellEnv: Send + Sync {
    /// A secret binding's value.  `None` when the binding does
    /// not exist — the gate treats that as deny, never as empty.
    fn secret(&self, name: &str) -> Option<String>;
    /// A plaintext var binding's value.
    fn var(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }
    /// The raw platform env object (wasm32 Workers only), for
    /// `ref_cf_storage::wasm_bindings::CfBindings`.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn raw_env(&self) -> Option<wasm_bindgen::JsValue> {
        None
    }
}

/// An in-memory env for tests and native embeddings: the mock
/// runtime the shell's own test-suite drives, and the one
/// consumers' tests should use too.
#[derive(Debug, Default, Clone)]
pub struct MockEnv {
    pub secrets: BTreeMap<String, String>,
    pub vars: BTreeMap<String, String>,
}

impl MockEnv {
    pub fn new() -> Self {
        MockEnv::default()
    }

    pub fn with_secret(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.secrets.insert(name.into(), value.into());
        self
    }

    pub fn with_var(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.vars.insert(name.into(), value.into());
        self
    }
}

impl ShellEnv for MockEnv {
    fn secret(&self, name: &str) -> Option<String> {
        self.secrets.get(name).cloned()
    }

    fn var(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }
}

/// What a handler receives alongside its request: the env, and
/// through it the storage bindings.  Cloneable and cheap — the
/// env is shared, bindings are resolved per call.
#[derive(Clone)]
pub struct Ctx {
    env: Arc<dyn ShellEnv>,
}

impl Ctx {
    pub fn new(env: Arc<dyn ShellEnv>) -> Self {
        Ctx { env }
    }

    pub fn env(&self) -> &dyn ShellEnv {
        self.env.as_ref()
    }

    pub fn secret(&self, name: &str) -> Option<String> {
        self.env.secret(name)
    }

    pub fn var(&self, name: &str) -> Option<String> {
        self.env.var(name)
    }

    /// The composed storage bindings (org-027) over this
    /// request's env.  wasm32 only — the bindings are platform
    /// objects; native handlers use the REST client from
    /// ref-cf-storage directly.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub fn cf(&self) -> Result<ref_cf_storage::wasm_bindings::CfBindings, ShellError> {
        let raw = self.env.raw_env().ok_or_else(|| {
            ShellError::internal("this env does not expose a Workers env object")
        })?;
        Ok(ref_cf_storage::wasm_bindings::CfBindings::new(raw))
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub fn kv(
        &self,
        binding: &str,
    ) -> Result<ref_cf_storage::wasm_bindings::WasmKv, ShellError> {
        self.cf()?
            .kv(binding)
            .map_err(|e| ShellError::internal(format!("kv binding {binding}: {e}")))
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub fn d1(
        &self,
        binding: &str,
    ) -> Result<ref_cf_storage::wasm_bindings::WasmD1, ShellError> {
        self.cf()?
            .d1(binding)
            .map_err(|e| ShellError::internal(format!("d1 binding {binding}: {e}")))
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub fn r2(
        &self,
        binding: &str,
    ) -> Result<ref_cf_storage::wasm_bindings::WasmR2, ShellError> {
        self.cf()?
            .r2(binding)
            .map_err(|e| ShellError::internal(format!("r2 binding {binding}: {e}")))
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub fn queue(
        &self,
        binding: &str,
    ) -> Result<ref_cf_storage::wasm_bindings::WasmQueue, ShellError> {
        self.cf()?
            .queue(binding)
            .map_err(|e| ShellError::internal(format!("queue binding {binding}: {e}")))
    }
}

// ---------------------------------------------------------------------
// The shell itself.  Builder-shaped: routes and scheduled
// handlers register fluently, the gate is stated once, and
// dispatch is the whole runtime.
// ---------------------------------------------------------------------

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<ShellResponse, ShellError>>>>;
pub type Handler = Arc<dyn Fn(ShellRequest, Ctx) -> HandlerFuture + Send + Sync>;
pub type ScheduledFuture = Pin<Box<dyn Future<Output = Result<(), ShellError>>>>;
pub type ScheduledHandler = Arc<dyn Fn(Ctx) -> ScheduledFuture + Send + Sync>;

pub struct Shell {
    router: Router,
    gate: Option<SecretGate>,
    scheduled: Vec<(String, ScheduledHandler)>,
}

impl Default for Shell {
    fn default() -> Self {
        Shell::new()
    }
}

impl Shell {
    pub fn new() -> Self {
        Shell {
            router: Router::default(),
            gate: None,
            scheduled: Vec::new(),
        }
    }

    /// Register a route.  Panics on a malformed pattern or a
    /// duplicate — route tables are construction data, and a
    /// worker that cannot state its routes should not boot.
    /// (The fallible core is `Router::add`; the organelle
    /// surface's `match_route` op validates pattern data without
    /// panicking.)
    pub fn route<F, Fut>(mut self, method: &str, pattern: &str, handler: F) -> Self
    where
        F: Fn(ShellRequest, Ctx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ShellResponse, ShellError>> + 'static,
    {
        let handler: Handler = Arc::new(move |req, ctx| {
            Box::pin(handler(req, ctx)) as HandlerFuture
        });
        self.router
            .add(method, pattern, handler)
            .unwrap_or_else(|e| panic!("ref-edge-worker-shell: {e}"));
        self
    }

    /// Install the secret gate.  Without this call the shell is
    /// ungated — a legitimate shape for a purely public worker,
    /// and a stated one: the absence is the caller's choice, not
    /// a default the shell slipped in.
    pub fn gate(mut self, config: GateConfig) -> Self {
        self.gate = Some(
            SecretGate::new(config)
                .unwrap_or_else(|e| panic!("ref-edge-worker-shell: {e}")),
        );
        self
    }

    /// Register a scheduled handler for an exact cron string
    /// (the string Workers reports for the event, e.g.
    /// `"*/30 * * * *"`).  Dispatch is by exact match — a cron
    /// the shell does not know is an error the glue logs, never
    /// a silent run of some other handler.
    pub fn scheduled<F, Fut>(mut self, cron: &str, handler: F) -> Self
    where
        F: Fn(Ctx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ShellError>> + 'static,
    {
        let handler: ScheduledHandler =
            Arc::new(move |ctx| Box::pin(handler(ctx)) as ScheduledFuture);
        self.scheduled.push((cron.to_string(), handler));
        self
    }

    pub fn gate_config(&self) -> Option<&GateConfig> {
        self.gate.as_ref().map(|g| g.config())
    }

    /// The fetch dispatch: gate, then route, then handler.
    /// Every failure is an honest envelope — gate refusals are
    /// 401 `unauthorized` with no detail, unknown paths 404,
    /// wrong methods 405 with `Allow`, handler errors their own
    /// stated envelope.
    pub async fn handle(&self, req: ShellRequest, env: Arc<dyn ShellEnv>) -> ShellResponse {
        if let Some(gate) = &self.gate {
            if !gate.allows(&req, env.as_ref()) {
                return ShellError::unauthorized().into_response();
            }
        }
        let ctx = Ctx::new(env);
        match self.router.lookup(&req.method, &req.path) {
            RouteOutcome::Matched(handler, params) => {
                let mut req = req;
                req.params = params;
                match handler(req, ctx).await {
                    Ok(resp) => resp,
                    Err(e) => e.into_response(),
                }
            }
            RouteOutcome::MethodNotAllowed(allowed) => ShellError::new(
                405,
                "method_not_allowed",
                format!("{} is not available for {}", req.method, req.path),
            )
            .into_response()
            .with_header("allow", allowed.join(", ")),
            RouteOutcome::NotFound => ShellError::not_found(format!(
                "no route for {} {}",
                req.method, req.path
            ))
            .into_response(),
        }
    }

    /// The scheduled dispatch.  Scheduled events carry no
    /// request and no presented secret — the platform only fires
    /// them for the deployed worker's own triggers — so the gate
    /// does not apply; what applies is exact cron matching.
    pub async fn handle_scheduled(
        &self,
        cron: &str,
        env: Arc<dyn ShellEnv>,
    ) -> Result<(), ShellError> {
        let ctx = Ctx::new(env);
        let mut ran = false;
        for (pattern, handler) in &self.scheduled {
            if pattern == cron {
                handler(ctx.clone()).await?;
                ran = true;
            }
        }
        if ran {
            Ok(())
        } else {
            Err(ShellError::not_found(format!(
                "no scheduled handler for cron {cron:?}"
            )))
        }
    }
}

// ---------------------------------------------------------------------
// Organelle surface.  The shell's runtime is code (closures are
// not data), so the surface exposes its pure, replayable pieces:
// route matching over a route table stated as data, the
// timing-safe comparison, and the two envelope builders.  A host
// can therefore validate a worker's route table and gate maths
// without running a worker.  All four ops are pure functions of
// their input.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let route_obj = serde_json::json!({
        "type": "object",
        "required": ["method", "pattern"],
        "properties": {
            "method": {"type": "string"},
            "pattern": {"type": "string"}
        }
    });
    let read = Some(MutationClass::ReadOnly);
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "edge-worker-shell".to_string(),
        codon: "ew".to_string(),
        version: "1.0.0".to_string(),
        description:
            "the thin Workers shell as pure, replayable pieces: route matching over a \
             route table stated as data (literal, :param and trailing *wildcard \
             segments; honest matched / method-not-allowed / not-found outcomes), \
             timing-safe secret comparison, and the estate's ok / error JSON envelope \
             builders; the runtime itself (router + fail-closed gate + fetch/scheduled \
             dispatch + ref-cf-storage bindings) is the crate's Rust API"
                .to_string(),
        contracts: vec![
            Contract {
                op: "match_route".to_string(),
                description: "match_route {routes: [{method, pattern}], method, path} -> {matched, pattern?, params, allowed_methods}; a path known under other methods reports them instead of pretending not-found".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["routes", "method", "path"],
                    "properties": {
                        "routes": {"type": "array", "items": route_obj},
                        "method": {"type": "string"},
                        "path": {"type": "string"}
                    }
                }),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "secret_eq".to_string(),
                description: "secret_eq {a, b} -> {equal}: the gate's timing-safe comparison (constant-time over the longer input, length difference folded in); the host owns custody of both values — the op compares, it does not store".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["a", "b"],
                    "properties": {
                        "a": {"type": "string"},
                        "b": {"type": "string"}
                    }
                }),
                mutation_class: read.clone(),
                required_capability: Some("edge.shell".to_string()),
            },
            Contract {
                op: "ok_envelope".to_string(),
                description: "ok_envelope {value, status?} -> {status, body}: the success envelope ({\"ok\": true, ...}) exactly as ShellResponse::ok renders it".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["value"],
                    "properties": {
                        "value": {},
                        "status": {"type": "integer"}
                    }
                }),
                mutation_class: read.clone(),
                required_capability: None,
            },
            Contract {
                op: "error_envelope".to_string(),
                description: "error_envelope {status, code, message?} -> {status, body}: the honest error envelope ({\"ok\": false, \"error\": code, \"message\": ...}) exactly as ShellResponse::error renders it".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["status", "code"],
                    "properties": {
                        "status": {"type": "integer"},
                        "code": {"type": "string"},
                        "message": {"type": "string"}
                    }
                }),
                mutation_class: read,
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: Valence::Candidate,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: Transport::all().to_vec(),
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

#[cfg(feature = "organelle")]
pub struct EdgeWorkerShell {
    manifest: OrganelleManifest,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(EdgeWorkerShell {
        manifest: manifest(),
    })
}

#[cfg(feature = "organelle")]
impl Organelle for EdgeWorkerShell {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "match_route" => {
                let method = input["method"].as_str().ok_or_else(|| {
                    OrganelleError::new("rejected", "method must be a string")
                })?;
                let path = input["path"].as_str().ok_or_else(|| {
                    OrganelleError::new("rejected", "path must be a string")
                })?;
                let routes = input["routes"].as_array().ok_or_else(|| {
                    OrganelleError::new("rejected", "routes must be an array")
                })?;
                let mut allowed: Vec<String> = Vec::new();
                for route in routes {
                    let rmethod = route["method"].as_str().ok_or_else(|| {
                        OrganelleError::new("rejected", "route method must be a string")
                    })?;
                    let pattern = route["pattern"].as_str().ok_or_else(|| {
                        OrganelleError::new("rejected", "route pattern must be a string")
                    })?;
                    let segments = parse_pattern(pattern).map_err(|e| {
                        OrganelleError::new("rejected", format!("pattern {pattern}: {}", e.message))
                    })?;
                    if let Some(params) = match_segments(&segments, path) {
                        if rmethod.eq_ignore_ascii_case(method) {
                            return Ok(serde_json::json!({
                                "matched": true,
                                "pattern": pattern,
                                "params": params,
                                "allowed_methods": [rmethod.to_ascii_uppercase()],
                            }));
                        }
                        let upper = rmethod.to_ascii_uppercase();
                        if !allowed.contains(&upper) {
                            allowed.push(upper);
                        }
                    }
                }
                allowed.sort();
                Ok(serde_json::json!({
                    "matched": false,
                    "params": {},
                    "allowed_methods": allowed,
                }))
            }
            "secret_eq" => {
                if !ctx.capabilities.iter().any(|c| c == "edge.shell") {
                    return Err(OrganelleError::new(
                        "denied",
                        "secret_eq requires the edge.shell capability",
                    ));
                }
                let a = input["a"].as_str().ok_or_else(|| {
                    OrganelleError::new("rejected", "a must be a string")
                })?;
                let b = input["b"].as_str().ok_or_else(|| {
                    OrganelleError::new("rejected", "b must be a string")
                })?;
                Ok(serde_json::json!({"equal": timing_safe_eq(a.as_bytes(), b.as_bytes())}))
            }
            "ok_envelope" => {
                let status = input["status"].as_u64().unwrap_or(200) as u16;
                let resp = ShellResponse::ok_with_status(status, input["value"].clone());
                Ok(serde_json::json!({"status": resp.status, "body": resp.body_json()}))
            }
            "error_envelope" => {
                let status = input["status"].as_u64().ok_or_else(|| {
                    OrganelleError::new("rejected", "status must be an integer")
                })? as u16;
                let code = input["code"].as_str().ok_or_else(|| {
                    OrganelleError::new("rejected", "code must be a string")
                })?;
                let message = input["message"].as_str().unwrap_or("");
                let resp = ShellResponse::error(status, code, message);
                Ok(serde_json::json!({"status": resp.status, "body": resp.body_json()}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Workers runtime glue (feature `workers`, wasm32 only).  This is
// the exchange-worker shape, generalised: convert the platform
// request into a ShellRequest, dispatch, convert back; convert
// the scheduled event's cron string and dispatch.  Nothing else
// lives here — a behaviour that matters belongs in the core,
// where native tests can reach it.
// ---------------------------------------------------------------------

#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    feature = "workers"
))]
pub mod workers_glue {
    use super::*;
    use wasm_bindgen::JsValue;

    /// The real Workers env as a [`ShellEnv`]: secrets and vars
    /// read through workers-rs, and the raw env object exposed
    /// for the ref-cf-storage bindings.
    pub struct WorkersEnv {
        env: worker::Env,
    }

    impl WorkersEnv {
        pub fn new(env: worker::Env) -> Self {
            WorkersEnv { env }
        }

        pub fn worker_env(&self) -> &worker::Env {
            &self.env
        }
    }

    impl ShellEnv for WorkersEnv {
        fn secret(&self, name: &str) -> Option<String> {
            self.env.secret(name).ok().map(|s| s.to_string())
        }

        fn var(&self, name: &str) -> Option<String> {
            self.env.var(name).ok().map(|s| s.to_string())
        }

        fn raw_env(&self) -> Option<JsValue> {
            // `Env` is a wasm-bindgen extern type with several
            // `AsRef` impls (JsValue, Object, itself); name the
            // one the bindings composition needs.
            let raw: &JsValue = self.env.as_ref();
            Some(raw.clone())
        }
    }

    /// The fetch entry point a consumer's `#[event(fetch)]`
    /// function calls.  Body reading follows the proven
    /// exchange-worker practice: text for the methods that carry
    /// bodies (the estate's edge APIs are JSON/text; a binary
    /// body is a consumer-side concern, stated in
    /// APPLICATION.md).
    pub async fn fetch_dispatch(
        shell: &Shell,
        mut req: worker::Request,
        env: worker::Env,
    ) -> worker::Result<worker::Response> {
        let url = req.url()?;
        let mut shell_req = ShellRequest::new(req.method().to_string(), url.path());
        for (k, v) in url.query_pairs() {
            shell_req.query.push((k.into_owned(), v.into_owned()));
        }
        for (k, v) in req.headers().entries() {
            shell_req.headers.push((k.to_ascii_lowercase(), v));
        }
        if !matches!(req.method(), worker::Method::Get | worker::Method::Head) {
            let text = req.text().await?;
            shell_req.body = text.into_bytes();
        }
        let resp = shell
            .handle(shell_req, Arc::new(WorkersEnv::new(env)))
            .await;
        let headers = worker::Headers::new();
        for (k, v) in &resp.headers {
            let _ = headers.set(k, v);
        }
        if let Some(stream) = resp.stream {
            // A streaming response is answered with a streamed
            // body: the chunks reach the client as they are
            // produced, and a mid-stream error terminates the
            // body — the consumer's sentinel discipline (the
            // ai-router's ": router upstream aborted") rides in
            // the chunk sequence itself, never as a status change
            // after the head has gone out.
            return worker::Response::from_stream(stream.into_inner())
                .map(|r| r.with_status(resp.status).with_headers(headers));
        }
        worker::Response::from_bytes(resp.body)
            .map(|r| r.with_status(resp.status).with_headers(headers))
    }

    /// The scheduled entry point a consumer's
    /// `#[event(scheduled)]` function calls.  A scheduled event
    /// has no caller to answer to: an unknown cron or a handler
    /// error is logged, never swallowed silently and never
    /// retried by running a different handler.
    pub async fn scheduled_dispatch(
        shell: &Shell,
        event: worker::ScheduledEvent,
        env: worker::Env,
    ) {
        let cron = event.cron();
        match shell
            .handle_scheduled(&cron, Arc::new(WorkersEnv::new(env)))
            .await
        {
            Ok(()) => worker::console_log!("edge-worker-shell: cron {cron} done"),
            Err(e) => worker::console_log!("edge-worker-shell: cron {cron} fault: {e}"),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The mock runtime is MockEnv + a std-only block_on: the
// shell's futures are driven to completion on the test thread,
// and every handler future in this suite resolves without real
// I/O, so park/unpark is a complete executor here.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Wake};
        struct ThreadWaker(std::thread::Thread);
        impl Wake for ThreadWaker {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = std::task::Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    const SECRET: &str = "test-secret-value";

    fn gate() -> GateConfig {
        GateConfig {
            header: "x-heartbeat-secret".to_string(),
            secret_env: "HEARTBEAT_SECRET".to_string(),
            exempt: vec![],
            query_param: None,
        }
    }

    fn env_with_secret() -> Arc<dyn ShellEnv> {
        Arc::new(MockEnv::new().with_secret("HEARTBEAT_SECRET", SECRET))
    }

    fn authed(target: &str) -> ShellRequest {
        ShellRequest::from_target("GET", target).with_header("x-heartbeat-secret", SECRET)
    }

    /// A shell with one gated route whose handler records that
    /// it ran — the witness for every gate test.
    fn witnessed_shell(ran: Arc<AtomicBool>) -> Shell {
        Shell::new().gate(gate()).route("GET", "/v1/ping", move |_req, _ctx| {
            let ran = ran.clone();
            async move {
                ran.store(true, Ordering::SeqCst);
                Ok(ShellResponse::ok(json!({"pong": true})))
            }
        })
    }

    #[test]
    fn unauthenticated_request_is_rejected_before_any_handler_runs() {
        let ran = Arc::new(AtomicBool::new(false));
        let shell = witnessed_shell(ran.clone());
        let resp = block_on(shell.handle(ShellRequest::new("GET", "/v1/ping"), env_with_secret()));
        assert_eq!(resp.status, 401);
        assert_eq!(resp.body_json(), json!({"ok": false, "error": "unauthorized"}));
        assert!(!ran.load(Ordering::SeqCst), "handler must not run");
    }

    #[test]
    fn wrong_secret_is_rejected_before_any_handler_runs() {
        let ran = Arc::new(AtomicBool::new(false));
        let shell = witnessed_shell(ran.clone());
        let req = ShellRequest::new("GET", "/v1/ping")
            .with_header("x-heartbeat-secret", "test-secret-valuf"); // one char off
        let resp = block_on(shell.handle(req, env_with_secret()));
        assert_eq!(resp.status, 401);
        assert!(!ran.load(Ordering::SeqCst), "handler must not run");
    }

    #[test]
    fn correct_secret_passes_and_handler_runs() {
        let ran = Arc::new(AtomicBool::new(false));
        let shell = witnessed_shell(ran.clone());
        let resp = block_on(shell.handle(authed("/v1/ping"), env_with_secret()));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body_json(), json!({"ok": true, "pong": true}));
        assert!(ran.load(Ordering::SeqCst));
    }

    #[test]
    fn gate_fails_closed_when_no_secret_is_configured() {
        let ran = Arc::new(AtomicBool::new(false));
        let shell = witnessed_shell(ran.clone());
        // The env has no HEARTBEAT_SECRET at all: even a request
        // presenting a value is denied.
        let env: Arc<dyn ShellEnv> = Arc::new(MockEnv::new());
        let resp = block_on(shell.handle(authed("/v1/ping"), env));
        assert_eq!(resp.status, 401);
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[test]
    fn gate_fails_closed_on_empty_presented_value() {
        let ran = Arc::new(AtomicBool::new(false));
        let shell = witnessed_shell(ran);
        let req = ShellRequest::new("GET", "/v1/ping").with_header("x-heartbeat-secret", "");
        let resp = block_on(shell.handle(req, env_with_secret()));
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn unauthenticated_unknown_path_is_401_not_404() {
        // The gate runs before routing: an unauthenticated caller
        // learns nothing about which routes exist.
        let shell = witnessed_shell(Arc::new(AtomicBool::new(false)));
        let resp = block_on(shell.handle(
            ShellRequest::new("GET", "/v1/does-not-exist"),
            env_with_secret(),
        ));
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn exempt_path_is_public_and_the_rest_stays_gated() {
        let ran = Arc::new(AtomicBool::new(false));
        let health_ran = ran.clone();
        let shell = Shell::new()
            .gate(GateConfig {
                exempt: vec!["/health".to_string()],
                ..gate()
            })
            .route("GET", "/health", move |_req, _ctx| {
                let health_ran = health_ran.clone();
                async move {
                    health_ran.store(true, Ordering::SeqCst);
                    Ok(ShellResponse::ok(json!({"up": true})))
                }
            })
            .route("GET", "/v1/ping", |_req, _ctx| async {
                Ok(ShellResponse::ok(json!({"pong": true})))
            });
        let resp = block_on(shell.handle(ShellRequest::new("GET", "/health"), env_with_secret()));
        assert_eq!(resp.status, 200);
        assert!(ran.load(Ordering::SeqCst));
        let resp = block_on(shell.handle(ShellRequest::new("GET", "/v1/ping"), env_with_secret()));
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn query_param_fallback_only_when_configured() {
        let shell = Shell::new()
            .gate(GateConfig {
                query_param: Some("key".to_string()),
                ..gate()
            })
            .route("GET", "/v1/ping", |_req, _ctx| async {
                Ok(ShellResponse::ok(json!({"pong": true})))
            });
        let target = format!("/v1/ping?key={SECRET}");
        let resp = block_on(shell.handle(ShellRequest::from_target("GET", &target), env_with_secret()));
        assert_eq!(resp.status, 200);

        // The same request against a header-only gate is denied:
        // the fallback is a stated knob, not a default.
        let shell = witnessed_shell(Arc::new(AtomicBool::new(false)));
        let resp = block_on(shell.handle(ShellRequest::from_target("GET", &target), env_with_secret()));
        assert_eq!(resp.status, 401);
    }

    #[test]
    fn route_params_are_extracted() {
        let shell = Shell::new()
            .route("GET", "/v1/items/:id", |req, _ctx| async move {
                Ok(ShellResponse::ok(json!({"id": req.param("id")})))
            })
            .route("GET", "/files/*rest", |req, _ctx| async move {
                Ok(ShellResponse::ok(json!({"rest": req.param("rest")})))
            });
        let env: Arc<dyn ShellEnv> = Arc::new(MockEnv::new());
        let resp = block_on(shell.handle(ShellRequest::new("GET", "/v1/items/abc-123"), env.clone()));
        assert_eq!(resp.body_json(), json!({"ok": true, "id": "abc-123"}));
        let resp = block_on(shell.handle(ShellRequest::new("GET", "/files/a/b/c.txt"), env));
        assert_eq!(resp.body_json(), json!({"ok": true, "rest": "a/b/c.txt"}));
    }

    #[test]
    fn unknown_route_is_an_honest_404_envelope() {
        let shell = Shell::new().route("GET", "/v1/ping", |_req, _ctx| async {
            Ok(ShellResponse::ok(json!({})))
        });
        let env: Arc<dyn ShellEnv> = Arc::new(MockEnv::new());
        let resp = block_on(shell.handle(ShellRequest::new("GET", "/v1/nope"), env));
        assert_eq!(resp.status, 404);
        let body = resp.body_json();
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["error"], json!("not_found"));
        assert!(body["message"].as_str().unwrap().contains("/v1/nope"));
    }

    #[test]
    fn known_path_wrong_method_is_405_with_allow() {
        let shell = Shell::new()
            .route("POST", "/v1/jobs", |_req, _ctx| async {
                Ok(ShellResponse::ok(json!({})))
            })
            .route("DELETE", "/v1/jobs", |_req, _ctx| async {
                Ok(ShellResponse::ok(json!({})))
            });
        let env: Arc<dyn ShellEnv> = Arc::new(MockEnv::new());
        let resp = block_on(shell.handle(ShellRequest::new("GET", "/v1/jobs"), env));
        assert_eq!(resp.status, 405);
        assert_eq!(resp.body_json()["error"], json!("method_not_allowed"));
        let allow = resp.header("allow").unwrap();
        assert!(allow.contains("POST") && allow.contains("DELETE"));
    }

    #[test]
    fn handler_error_becomes_its_envelope() {
        let shell = Shell::new().route("GET", "/v1/admin", |_req, _ctx| async {
            Err(ShellError::forbidden("not your worker"))
        });
        let env: Arc<dyn ShellEnv> = Arc::new(MockEnv::new());
        let resp = block_on(shell.handle(ShellRequest::new("GET", "/v1/admin"), env));
        assert_eq!(resp.status, 403);
        assert_eq!(
            resp.body_json(),
            json!({"ok": false, "error": "forbidden", "message": "not your worker"})
        );
    }

    #[test]
    fn handler_reads_json_body_and_ctx_secrets() {
        let shell = Shell::new().route("POST", "/v1/echo", |req, ctx| async move {
            let body = req.body_as::<Value>()?;
            let who = ctx.var("WORKER_NAME").unwrap_or_default();
            Ok(ShellResponse::ok(json!({"echo": body, "worker": who})))
        });
        let env: Arc<dyn ShellEnv> =
            Arc::new(MockEnv::new().with_var("WORKER_NAME", "edge-test"));
        let req = ShellRequest::new("POST", "/v1/echo").with_json_body(&json!({"n": 41}));
        let resp = block_on(shell.handle(req, env));
        assert_eq!(
            resp.body_json(),
            json!({"ok": true, "echo": {"n": 41}, "worker": "edge-test"})
        );

        // A malformed body is a 400 from the handler's own
        // body_as error, rendered as an envelope — not a panic.
        let req = ShellRequest::new("POST", "/v1/echo").with_body(b"{not json".to_vec());
        let env: Arc<dyn ShellEnv> = Arc::new(MockEnv::new());
        let resp = block_on(shell.handle(req, env));
        assert_eq!(resp.status, 400);
        assert_eq!(resp.body_json()["error"], json!("bad_request"));
    }

    #[test]
    fn scheduled_dispatch_matches_exact_cron() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let t = ticks.clone();
        let shell = Shell::new().scheduled("*/30 * * * *", move |_ctx| {
            let t = t.clone();
            async move {
                t.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });
        let env: Arc<dyn ShellEnv> = Arc::new(MockEnv::new());
        assert!(block_on(shell.handle_scheduled("*/30 * * * *", env.clone())).is_ok());
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
        let err = block_on(shell.handle_scheduled("0 0 * * *", env)).unwrap_err();
        assert_eq!(err.status, 404);
        assert_eq!(ticks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timing_safe_eq_cases() {
        assert!(timing_safe_eq(b"abc", b"abc"));
        assert!(!timing_safe_eq(b"abc", b"abd"));
        assert!(!timing_safe_eq(b"abc", b"ab"));
        assert!(!timing_safe_eq(b"ab", b"abc"));
        assert!(!timing_safe_eq(b"", b"x"));
        assert!(timing_safe_eq(b"", b""));
        // The gate never lets the empty==empty case through: it
        // denies empty presented values and unconfigured secrets
        // before comparing (covered by the gate tests above).
    }

    #[test]
    fn target_parsing_decodes_query_pairs() {
        let req = ShellRequest::from_target("get", "/v1/x?tag=a%20b&tag=c+d&empty=");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/v1/x");
        assert_eq!(req.query_first("tag"), Some("a b"));
        assert_eq!(req.query.len(), 3);
        assert_eq!(req.query[1].1, "c d");
        assert_eq!(req.query_first("empty"), Some(""));
    }

    #[cfg(feature = "organelle")]
    #[test]
    fn organelle_surface_matches_and_compares() {
        use std::path::PathBuf;
        struct NullHost;
        impl HostRef for NullHost {
            fn call_organelle(
                &self,
                _caller_codon: &str,
                _caller_trace: &str,
                _codon: &str,
                _op: &str,
                _input: Value,
            ) -> Result<Value, OrganelleError> {
                Err(OrganelleError::failed("null host"))
            }
            fn approve_write_path(&self, _raw: &str) -> Result<PathBuf, OrganelleError> {
                Err(OrganelleError::new("denied", "null host approves nothing"))
            }
            fn approve_egress(&self, _url: &str) -> Result<(), OrganelleError> {
                Err(OrganelleError::new("denied", "null host approves nothing"))
            }
        }
        let org = organelle();
        let host = NullHost;
        assert_eq!(org.manifest().codon, "ew");
        let ctx = CallContext::new("test", vec!["edge.shell".to_string()]);

        let out = org
            .handle(
                &ctx,
                &host,
                "match_route",
                json!({
                    "routes": [
                        {"method": "GET", "pattern": "/v1/items/:id"},
                        {"method": "POST", "pattern": "/v1/items/:id"}
                    ],
                    "method": "GET",
                    "path": "/v1/items/42"
                }),
            )
            .unwrap();
        assert_eq!(out["matched"], json!(true));
        assert_eq!(out["params"]["id"], json!("42"));

        let out = org
            .handle(
                &ctx,
                &host,
                "match_route",
                json!({
                    "routes": [{"method": "POST", "pattern": "/v1/items/:id"}],
                    "method": "GET",
                    "path": "/v1/items/42"
                }),
            )
            .unwrap();
        assert_eq!(out["matched"], json!(false));
        assert_eq!(out["allowed_methods"], json!(["POST"]));

        let out = org
            .handle(&ctx, &host, "secret_eq", json!({"a": "s3cret", "b": "s3cret"}))
            .unwrap();
        assert_eq!(out["equal"], json!(true));

        // Without the capability the comparison is denied.
        let bare = CallContext::new("test", vec![]);
        let err = org
            .handle(&bare, &host, "secret_eq", json!({"a": "x", "b": "x"}))
            .unwrap_err();
        assert_eq!(err.code, "denied");

        let out = org
            .handle(
                &ctx,
                &host,
                "error_envelope",
                json!({"status": 401, "code": "unauthorized"}),
            )
            .unwrap();
        assert_eq!(out["body"], json!({"ok": false, "error": "unauthorized"}));
    }
}

#[cfg(test)]
mod stream_tests {
    use super::tests::block_on;
    use super::*;
    use std::collections::VecDeque;

    struct VecStream {
        items: VecDeque<Result<Vec<u8>, String>>,
    }

    impl futures_core::Stream for VecStream {
        type Item = Result<Vec<u8>, String>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.items.pop_front())
        }
    }

    #[test]
    fn streaming_response_passes_through_the_shell_intact() {
        let shell = Shell::new().route("GET", "/v1/stream", |_req, _ctx| async {
            let items: VecDeque<Result<Vec<u8>, String>> = vec![
                Ok(b"data: one\n\n".to_vec()),
                Ok(b"data: two\n\n".to_vec()),
                Err("upstream died".to_string()),
            ]
            .into();
            Ok(ShellResponse::stream(
                200,
                "text/event-stream",
                Box::pin(VecStream { items }),
            ))
        });
        let mut resp = block_on(shell.handle(
            ShellRequest::new("GET", "/v1/stream"),
            Arc::new(MockEnv::new()),
        ));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("content-type"), Some("text/event-stream"));
        assert!(resp.body.is_empty(), "a streaming response is not buffered");
        let stream = resp.stream.take().expect("stream present").into_inner();
        let items = block_on(async move {
            let mut stream = stream;
            let mut out = vec![];
            while let Some(item) =
                std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
            {
                out.push(item);
            }
            out
        });
        // Order and the mid-stream error both survive the shell.
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_deref().unwrap(), &b"data: one\n\n"[..]);
        assert_eq!(items[1].as_deref().unwrap(), &b"data: two\n\n"[..]);
        assert_eq!(items[2].as_ref().unwrap_err(), "upstream died");
    }

    #[test]
    fn buffered_responses_have_no_stream() {
        let resp = ShellResponse::text(200, "hello");
        assert!(resp.stream.is_none());
        assert_eq!(resp.body, b"hello");
    }
}
