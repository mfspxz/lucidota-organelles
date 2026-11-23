//! org-027 — Reference organelle: cf-storage (codon `cs`).
//!
//! Cloudflare storage bindings behind one trait surface (GAP-02 in
//! the 2026-11-22 decomposition map: eight scoped softwares — SUB,
//! PL, WRK, EXC, RTR, TRN, SDX, TEN — hand-roll KV / D1 / R2 / Queues
//! access today, in JS worker shells, Python CLIs, and per-system
//! Rust).  `ref-kv-store` (org-013), `ref-file-cas` (org-024) and
//! `ref-ledger-append` (org-020) are the store contracts; this crate
//! is the Cloudflare edge backend family behind those shapes.
//!
//! Two backends, one operation surface:
//!
//! * **Native — Cloudflare REST API v4** via `ref-https-transport`
//!   (ureq 3 + rustls; no native-tls, no openssl).  Blocking,
//!   synchronous traits ([`KvStore`], [`D1Store`], [`R2Store`],
//!   [`QueueStore`]) implemented by [`CfRestClient`].  Credentials
//!   are *injected* into the client constructor — this crate never
//!   reads a token from disk, from the environment, or from a vault,
//!   and never prints one (the client's `Debug` redacts it).
//! * **`wasm32-unknown-unknown` — Workers runtime bindings**
//!   ([`wasm_bindings::CfBindings`]): the caller hands over the
//!   worker's `env` object; KV / D1 / R2 / Queue bindings are driven
//!   through `wasm-bindgen` / `js-sys` reflection (the
//!   ref-entropy-source pattern, not the workers-rs tree).  Bindings
//!   are promise-based, so this face is `async` — the same honest
//!   split `ref-https-transport` makes between `send_blocking` and
//!   `send_async`.  R2 streaming is exposed at this face: `get`
//!   returns the object handle whose `body` ReadableStream is passed
//!   through untouched, and `put` accepts a raw stream `JsValue`.
//!
//! Honest error taxonomy ([`CfError`]): `Transport` means no HTTP
//! response exists (DNS / TLS / timeout / connection, from the
//! transport layer); `Auth` means Cloudflare answered 401/403;
//! `Api` means Cloudflare answered with `success: false` or another
//! error status, with the API's own error codes preserved;
//! `InvalidRequest` is a client-side refusal before any call;
//! `Binding` is a Workers-binding-layer failure (missing binding,
//! wrong type, JS exception); `Unsupported` is a call shape this
//! target cannot serve.  Nothing in this crate panics on an API
//! response.
//!
//! The organelle surface (feature `organelle`) speaks the REST face:
//! ops take a `binding` field carrying the namespace / database /
//! bucket / queue *id* and run through an injected [`CfRestClient`].
//! On wasm32 the REST face cannot block, so organelle ops there fail
//! with `Unsupported` from the transport — wasm consumers use
//! [`wasm_bindings::CfBindings`] directly.  Values on the organelle
//! surface are text (`value_text`); binary payloads use the Rust API.

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use ref_https_transport::{HttpsRequest, HttpsTransport, Method, TransportError};
use serde_json::Value;
use std::fmt;
#[cfg(feature = "organelle")]
use std::sync::Arc;

pub const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// REST response cap.  KV values can be 25 MB and R2 objects far
/// larger; the cap is generous and truncation is surfaced, never
/// silent (a truncated D1/KV envelope fails JSON parsing and is
/// reported as an API-shape error, not swallowed).
pub const DEFAULT_MAX_BYTES: usize = 64 * 1_048_576;

// ---------------------------------------------------------------------
// Error taxonomy.
// ---------------------------------------------------------------------

/// One error entry from a Cloudflare v4 API envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfApiError {
    pub code: i64,
    pub message: String,
}

impl fmt::Display for CfApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfError {
    /// No HTTP response exists (transport layer failure).
    Transport(TransportError),
    /// Cloudflare answered 401 or 403: the injected credential was
    /// rejected or lacks the scope for this call.
    Auth { status: u16, errors: Vec<CfApiError> },
    /// Cloudflare answered with `success: false` or another error
    /// status.  The API's own error codes are preserved.
    Api { status: u16, errors: Vec<CfApiError> },
    /// Client-side refusal before any call (empty key, bad id, …).
    InvalidRequest(String),
    /// Workers-binding-layer failure: missing binding, wrong type,
    /// or a JS exception from the runtime object.
    Binding(String),
    /// This target/backend cannot serve the call shape.
    Unsupported(String),
}

impl fmt::Display for CfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CfError::Transport(e) => write!(f, "cf-storage: transport: {e}"),
            CfError::Auth { status, errors } => {
                write!(f, "cf-storage: auth rejected (HTTP {status}): {}", join_errors(errors))
            }
            CfError::Api { status, errors } => {
                write!(f, "cf-storage: api error (HTTP {status}): {}", join_errors(errors))
            }
            CfError::InvalidRequest(m) => write!(f, "cf-storage: invalid request: {m}"),
            CfError::Binding(m) => write!(f, "cf-storage: binding failure: {m}"),
            CfError::Unsupported(m) => write!(f, "cf-storage: unsupported: {m}"),
        }
    }
}

impl std::error::Error for CfError {}

impl From<TransportError> for CfError {
    fn from(e: TransportError) -> Self {
        CfError::Transport(e)
    }
}

fn join_errors(errors: &[CfApiError]) -> String {
    if errors.is_empty() {
        return "no error detail in response".to_string();
    }
    errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------
// Shared types.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KvPutOptions {
    /// Seconds from now until the key expires (KV minimum 60).
    pub expiration_ttl: Option<u64>,
    /// Absolute unix-seconds expiry.
    pub expiration: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KvListOptions {
    pub prefix: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvKey {
    pub name: String,
    pub expiration: Option<i64>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvListPage {
    pub keys: Vec<KvKey>,
    pub list_complete: bool,
    /// Pass back as `cursor` for the next page; `None` when complete.
    pub cursor: Option<String>,
}

/// D1 statement metadata (the REST `meta` object; fields absent from
/// a response stay `None` rather than being invented).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct D1Meta {
    pub changed_db: Option<bool>,
    pub changes: Option<i64>,
    pub last_row_id: Option<i64>,
    pub rows_read: Option<i64>,
    pub rows_written: Option<i64>,
    pub duration_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct D1Result {
    pub results: Vec<Value>,
    pub meta: D1Meta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R2Object {
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub etag: Option<String>,
    pub size: Option<u64>,
}

impl R2Object {
    pub fn body_text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

// ---------------------------------------------------------------------
// The trait surface (synchronous; implemented by the REST client).
// ---------------------------------------------------------------------

/// Key/value storage (Cloudflare KV semantics): `binding` is the
/// namespace id on the REST face.
pub trait KvStore {
    fn kv_get(&self, binding: &str, key: &str) -> Result<Option<Vec<u8>>, CfError>;
    fn kv_put(
        &self,
        binding: &str,
        key: &str,
        value: &[u8],
        opts: &KvPutOptions,
    ) -> Result<(), CfError>;
    fn kv_delete(&self, binding: &str, key: &str) -> Result<(), CfError>;
    fn kv_list(&self, binding: &str, opts: &KvListOptions) -> Result<KvListPage, CfError>;

    fn kv_get_text(&self, binding: &str, key: &str) -> Result<Option<String>, CfError> {
        Ok(self
            .kv_get(binding, key)?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }
}

/// SQL storage (Cloudflare D1 semantics): `binding` is the database
/// id (uuid) on the REST face.
pub trait D1Store {
    /// Run a statement expected to return rows (SELECT-shaped).  The
    /// endpoint executes any SQL; read intent is the caller's
    /// contract, documented at the organelle surface.
    fn d1_query(
        &self,
        binding: &str,
        sql: &str,
        params: &[Value],
    ) -> Result<D1Result, CfError>;
    /// Run a statement for its effects; returns statement metadata.
    fn d1_execute(&self, binding: &str, sql: &str, params: &[Value]) -> Result<D1Meta, CfError>;
}

/// Object storage (Cloudflare R2 semantics): `binding` is the bucket
/// name on the REST face.
pub trait R2Store {
    fn r2_get(&self, binding: &str, key: &str) -> Result<Option<R2Object>, CfError>;
    fn r2_put(
        &self,
        binding: &str,
        key: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<(), CfError>;
    fn r2_delete(&self, binding: &str, key: &str) -> Result<(), CfError>;
}

/// Message queues (Cloudflare Queues semantics): `binding` is the
/// queue id on the REST face.
pub trait QueueStore {
    fn queue_send(&self, binding: &str, body: &Value) -> Result<(), CfError>;
    fn queue_send_text(&self, binding: &str, body: &str) -> Result<(), CfError>;
}

// ---------------------------------------------------------------------
// Percent-encoding for path segments (keys are caller data; never let
// one reshape the URL).
// ---------------------------------------------------------------------

fn pct_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && b == b'/');
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn require_nonempty(what: &str, v: &str) -> Result<(), CfError> {
    if v.is_empty() {
        return Err(CfError::InvalidRequest(format!("{what} must not be empty")));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Native backend: Cloudflare REST API v4 via ref-https-transport.
// ---------------------------------------------------------------------

/// Cloudflare REST API client.  The account id and API token are
/// injected by the caller at construction; the crate never sources
/// them itself and never prints them.
pub struct CfRestClient {
    account_id: String,
    token: String,
    api_base: String,
    transport: std::sync::Arc<dyn HttpsTransport + Send + Sync>,
    timeout_ms: u64,
    max_bytes: usize,
}

// The token is a secret: Debug shows the shape, never the value.
impl fmt::Debug for CfRestClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CfRestClient")
            .field("account_id", &self.account_id)
            .field("token", &"<redacted>")
            .field("api_base", &self.api_base)
            .finish()
    }
}

impl CfRestClient {
    /// Client on the platform default transport (ureq/rustls native;
    /// `Unsupported` from the transport on wasm32).
    pub fn new(account_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self::with_transport(
            account_id,
            token,
            std::sync::Arc::new(ref_https_transport::HostTransport),
        )
    }

    /// Client on a caller-supplied transport (fixtures, recorders,
    /// tests).  This is the seam the recorded-shape tests use.
    pub fn with_transport(
        account_id: impl Into<String>,
        token: impl Into<String>,
        transport: std::sync::Arc<dyn HttpsTransport + Send + Sync>,
    ) -> Self {
        CfRestClient {
            account_id: account_id.into(),
            token: token.into(),
            api_base: DEFAULT_API_BASE.to_string(),
            transport,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }

    /// Override the API base (local fixtures / recorded endpoints).
    pub fn api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into().trim_end_matches('/').to_string();
        self
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    fn url(&self, path: &str) -> String {
        format!("{}/accounts/{}{}", self.api_base, self.account_id, path)
    }

    /// One HTTP round trip.  Any status comes back as an outcome;
    /// classification is the caller's step (KV/R2 reads treat 404 as
    /// data, envelope endpoints do not).
    fn round_trip(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), CfError> {
        let mut req = HttpsRequest::new(method, self.url(path))
            .header("Authorization", format!("Bearer {}", self.token))
            .timeout_ms(self.timeout_ms)
            .max_bytes(self.max_bytes);
        // Local fixtures speak plain http; the real API base is
        // https and never takes this branch.
        if self.api_base.starts_with("http://") {
            req = req.allow_http(true);
        }
        if let Some(ct) = content_type {
            req = req.header("Content-Type", ct);
        }
        if let Some(b) = body {
            req = req.body(b);
        }
        let resp = self.transport.send(&req)?;
        Ok((resp.status, resp.headers, resp.body))
    }

    /// Round trip for a JSON-envelope endpoint: returns the envelope's
    /// `result` on success; classifies 401/403 as `Auth`, any other
    /// failure envelope or error status as `Api`.
    fn envelope(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
    ) -> Result<Value, CfError> {
        let (status, _headers, bytes) = self.round_trip(method, path, body, content_type)?;
        parse_envelope(status, &bytes)
    }

    fn json_body(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap_or_default()
    }
}

/// Classify one v4 envelope response.  `Ok(result)` only when the
/// status is 2xx AND the envelope says `success: true`.
fn parse_envelope(status: u16, bytes: &[u8]) -> Result<Value, CfError> {
    let parsed: Option<Value> = serde_json::from_slice(bytes).ok();
    let errors: Vec<CfApiError> = parsed
        .as_ref()
        .and_then(|v| v["errors"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|e| CfApiError {
            code: e["code"].as_i64().unwrap_or(0),
            message: e["message"].as_str().unwrap_or("").to_string(),
        })
        .collect();
    if status == 401 || status == 403 {
        return Err(CfError::Auth { status, errors });
    }
    let success = parsed
        .as_ref()
        .and_then(|v| v["success"].as_bool())
        .unwrap_or(false);
    if !(200..300).contains(&status) || !success {
        let errors = if errors.is_empty() {
            vec![CfApiError {
                code: 0,
                message: format!(
                    "HTTP {status} without a Cloudflare error envelope: {}",
                    String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
                ),
            }]
        } else {
            errors
        };
        return Err(CfError::Api { status, errors });
    }
    Ok(parsed
        .and_then(|v| v.get("result").cloned())
        .unwrap_or(Value::Null))
}

fn meta_from(v: &Value) -> D1Meta {
    D1Meta {
        changed_db: v["changed_db"].as_bool(),
        changes: v["changes"].as_i64(),
        last_row_id: v["last_row_id"].as_i64(),
        rows_read: v["rows_read"].as_i64(),
        rows_written: v["rows_written"].as_i64(),
        duration_ms: v["duration"].as_f64(),
    }
}

/// Parse one D1 statement result out of the envelope `result` array.
fn d1_statement(result: Value, status_what: &str) -> Result<(Vec<Value>, D1Meta), CfError> {
    let arr = result.as_array().cloned().unwrap_or_default();
    let first = arr.into_iter().next().unwrap_or(Value::Null);
    if first["success"].as_bool() == Some(false) {
        let msg = first["error"]
            .as_str()
            .unwrap_or("D1 statement failed without an error message")
            .to_string();
        return Err(CfError::Api {
            status: 200,
            errors: vec![CfApiError {
                code: 0,
                message: format!("{status_what}: {msg}"),
            }],
        });
    }
    let rows = first["results"].as_array().cloned().unwrap_or_default();
    Ok((rows, meta_from(&first["meta"])))
}

impl KvStore for CfRestClient {
    fn kv_get(&self, binding: &str, key: &str) -> Result<Option<Vec<u8>>, CfError> {
        require_nonempty("namespace id", binding)?;
        require_nonempty("key", key)?;
        let path = format!(
            "/storage/kv/namespaces/{}/values/{}",
            pct_encode(binding, false),
            pct_encode(key, false)
        );
        let (status, _h, bytes) = self.round_trip(Method::Get, &path, None, None)?;
        match status {
            200 => Ok(Some(bytes)),
            // KV answers a missing key with 404 (error 10009): that is
            // a miss, not a failure.
            404 => Ok(None),
            _ => {
                parse_envelope(status, &bytes)?;
                Ok(None) // unreachable in practice; envelope errors above
            }
        }
    }

    fn kv_put(
        &self,
        binding: &str,
        key: &str,
        value: &[u8],
        opts: &KvPutOptions,
    ) -> Result<(), CfError> {
        require_nonempty("namespace id", binding)?;
        require_nonempty("key", key)?;
        let mut path = format!(
            "/storage/kv/namespaces/{}/values/{}",
            pct_encode(binding, false),
            pct_encode(key, false)
        );
        let mut q: Vec<String> = vec![];
        if let Some(ttl) = opts.expiration_ttl {
            q.push(format!("expiration_ttl={ttl}"));
        }
        if let Some(exp) = opts.expiration {
            q.push(format!("expiration={exp}"));
        }
        if !q.is_empty() {
            path = format!("{path}?{}", q.join("&"));
        }
        self.envelope(
            Method::Put,
            &path,
            Some(value.to_vec()),
            Some("application/octet-stream"),
        )?;
        Ok(())
    }

    fn kv_delete(&self, binding: &str, key: &str) -> Result<(), CfError> {
        require_nonempty("namespace id", binding)?;
        require_nonempty("key", key)?;
        let path = format!(
            "/storage/kv/namespaces/{}/values/{}",
            pct_encode(binding, false),
            pct_encode(key, false)
        );
        let (status, _h, bytes) = self.round_trip(Method::Delete, &path, None, None)?;
        // Delete is idempotent here: a 404 for an already-absent key
        // is the desired end state, not an error.
        if status == 404 {
            return Ok(());
        }
        parse_envelope(status, &bytes)?;
        Ok(())
    }

    fn kv_list(&self, binding: &str, opts: &KvListOptions) -> Result<KvListPage, CfError> {
        require_nonempty("namespace id", binding)?;
        let mut path = format!(
            "/storage/kv/namespaces/{}/keys",
            pct_encode(binding, false)
        );
        let mut q: Vec<String> = vec![];
        if let Some(p) = &opts.prefix {
            q.push(format!("prefix={}", pct_encode(p, false)));
        }
        if let Some(l) = opts.limit {
            q.push(format!("limit={l}"));
        }
        if let Some(c) = &opts.cursor {
            q.push(format!("cursor={}", pct_encode(c, false)));
        }
        if !q.is_empty() {
            path = format!("{path}?{}", q.join("&"));
        }
        let result = self.envelope(Method::Get, &path, None, None)?;
        let keys = result["keys"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|k| KvKey {
                name: k["name"].as_str().unwrap_or("").to_string(),
                expiration: k["expiration"].as_i64(),
                metadata: if k["metadata"].is_null() {
                    None
                } else {
                    Some(k["metadata"].clone())
                },
            })
            .collect();
        Ok(KvListPage {
            keys,
            list_complete: result["list_complete"].as_bool().unwrap_or(false),
            cursor: result["cursor"].as_str().map(|s| s.to_string()),
        })
    }
}

impl D1Store for CfRestClient {
    fn d1_query(
        &self,
        binding: &str,
        sql: &str,
        params: &[Value],
    ) -> Result<D1Result, CfError> {
        require_nonempty("database id", binding)?;
        require_nonempty("sql", sql)?;
        let path = format!(
            "/d1/database/{}/query",
            pct_encode(binding, false)
        );
        let body = serde_json::json!({"sql": sql, "params": params});
        let result = self.envelope(
            Method::Post,
            &path,
            Some(Self::json_body(&body)),
            Some("application/json"),
        )?;
        let (results, meta) = d1_statement(result, "d1 query")?;
        Ok(D1Result { results, meta })
    }

    fn d1_execute(&self, binding: &str, sql: &str, params: &[Value]) -> Result<D1Meta, CfError> {
        require_nonempty("database id", binding)?;
        require_nonempty("sql", sql)?;
        let path = format!(
            "/d1/database/{}/execute",
            pct_encode(binding, false)
        );
        let body = serde_json::json!({"sql": sql, "params": params});
        let result = self.envelope(
            Method::Post,
            &path,
            Some(Self::json_body(&body)),
            Some("application/json"),
        )?;
        let (_rows, meta) = d1_statement(result, "d1 execute")?;
        Ok(meta)
    }
}

impl R2Store for CfRestClient {
    fn r2_get(&self, binding: &str, key: &str) -> Result<Option<R2Object>, CfError> {
        require_nonempty("bucket", binding)?;
        require_nonempty("key", key)?;
        let path = format!(
            "/r2/buckets/{}/objects/{}",
            pct_encode(binding, false),
            pct_encode(key, true)
        );
        let (status, headers, bytes) = self.round_trip(Method::Get, &path, None, None)?;
        match status {
            200 => {
                let header = |name: &str| {
                    headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.clone())
                };
                Ok(Some(R2Object {
                    size: Some(bytes.len() as u64),
                    body: bytes,
                    content_type: header("content-type"),
                    etag: header("etag"),
                }))
            }
            404 => Ok(None),
            _ => {
                parse_envelope(status, &bytes)?;
                Ok(None) // unreachable in practice
            }
        }
    }

    fn r2_put(
        &self,
        binding: &str,
        key: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<(), CfError> {
        require_nonempty("bucket", binding)?;
        require_nonempty("key", key)?;
        let path = format!(
            "/r2/buckets/{}/objects/{}",
            pct_encode(binding, false),
            pct_encode(key, true)
        );
        let (status, _h, bytes) = self.round_trip(
            Method::Put,
            &path,
            Some(body.to_vec()),
            Some(content_type.unwrap_or("application/octet-stream")),
        )?;
        if (200..300).contains(&status) {
            // The object PUT answers with a JSON envelope on success,
            // but a bare 2xx is success whatever the body shape; only
            // an explicit success:false demotes it.
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                if v["success"].as_bool() == Some(false) {
                    parse_envelope(status, &bytes)?;
                }
            }
            return Ok(());
        }
        parse_envelope(status, &bytes)?;
        Ok(())
    }

    fn r2_delete(&self, binding: &str, key: &str) -> Result<(), CfError> {
        require_nonempty("bucket", binding)?;
        require_nonempty("key", key)?;
        let path = format!(
            "/r2/buckets/{}/objects/{}",
            pct_encode(binding, false),
            pct_encode(key, true)
        );
        let (status, _h, bytes) = self.round_trip(Method::Delete, &path, None, None)?;
        if status == 404 || (200..300).contains(&status) {
            return Ok(());
        }
        parse_envelope(status, &bytes)?;
        Ok(())
    }
}

impl QueueStore for CfRestClient {
    fn queue_send(&self, binding: &str, body: &Value) -> Result<(), CfError> {
        require_nonempty("queue id", binding)?;
        let path = format!("/queues/{}/messages", pct_encode(binding, false));
        let payload = serde_json::json!({"body": body});
        self.envelope(
            Method::Post,
            &path,
            Some(Self::json_body(&payload)),
            Some("application/json"),
        )?;
        Ok(())
    }

    fn queue_send_text(&self, binding: &str, body: &str) -> Result<(), CfError> {
        require_nonempty("queue id", binding)?;
        let path = format!("/queues/{}/messages", pct_encode(binding, false));
        let payload = serde_json::json!({"body": body, "content_type": "text"});
        self.envelope(
            Method::Post,
            &path,
            Some(Self::json_body(&payload)),
            Some("application/json"),
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Wasm backend: Workers runtime bindings via wasm-bindgen / js-sys.
//
// The caller (the worker's entry point) owns the `env` object and
// hands it over once: `CfBindings::new(env)`.  Each accessor resolves
// one named binding off it and checks the expected methods exist, so
// a missing or mistyped binding fails as `CfError::Binding` at
// lookup time, not as a JS TypeError mid-operation.
// ---------------------------------------------------------------------

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod wasm_bindings {
    use super::*;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    fn binding_err(what: &str, e: JsValue) -> CfError {
        CfError::Binding(format!("{what}: {e:?}"))
    }

    fn get_prop(obj: &JsValue, name: &str) -> Result<JsValue, CfError> {
        js_sys::Reflect::get(obj, &JsValue::from_str(name))
            .map_err(|e| binding_err(&format!("read property {name}"), e))
    }

    fn call0(obj: &JsValue, method: &str) -> Result<JsValue, CfError> {
        call(obj, method, &js_sys::Array::new())
    }

    fn call1(obj: &JsValue, method: &str, a: &JsValue) -> Result<JsValue, CfError> {
        let args = js_sys::Array::new();
        args.push(a);
        call(obj, method, &args)
    }

    fn call2(obj: &JsValue, method: &str, a: &JsValue, b: &JsValue) -> Result<JsValue, CfError> {
        let args = js_sys::Array::new();
        args.push(a);
        args.push(b);
        call(obj, method, &args)
    }

    fn call(obj: &JsValue, method: &str, args: &js_sys::Array) -> Result<JsValue, CfError> {
        let f = get_prop(obj, method)?;
        let func: &js_sys::Function = f
            .dyn_ref()
            .ok_or_else(|| CfError::Binding(format!("binding member {method} is not a function")))?;
        js_sys::Reflect::apply(func, obj, args)
            .map_err(|e| binding_err(&format!("call {method}"), e))
    }

    async fn awaited(v: JsValue, what: &str) -> Result<JsValue, CfError> {
        let promise: js_sys::Promise = v
            .dyn_into()
            .map_err(|_| CfError::Binding(format!("{what} did not return a promise")))?;
        JsFuture::from(promise)
            .await
            .map_err(|e| binding_err(what, e))
    }

    fn json_parse(text: &str) -> Result<JsValue, CfError> {
        js_sys::JSON::parse(text).map_err(|e| binding_err("JSON.parse", e))
    }

    fn value_to_js(v: &Value) -> Result<JsValue, CfError> {
        json_parse(&serde_json::to_string(v).unwrap_or_else(|_| "null".to_string()))
    }

    fn js_to_value(v: &JsValue) -> Value {
        let text = js_sys::JSON::stringify(v)
            .ok()
            .map(|s| String::from(s))
            .unwrap_or_else(|| "null".to_string());
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    fn resolve_binding(env: &JsValue, name: &str, methods: &[&str]) -> Result<JsValue, CfError> {
        if name.is_empty() {
            return Err(CfError::InvalidRequest(
                "binding name must not be empty".to_string(),
            ));
        }
        let b = get_prop(env, name)?;
        if b.is_undefined() || b.is_null() {
            return Err(CfError::Binding(format!(
                "no binding named {name} on the worker env"
            )));
        }
        for m in methods {
            let f = get_prop(&b, m)?;
            if f.dyn_ref::<js_sys::Function>().is_none() {
                return Err(CfError::Binding(format!(
                    "binding {name} has no method {m} (wrong binding type?)"
                )));
            }
        }
        Ok(b)
    }

    /// The worker's binding set.  Construct once from the `env`
    /// object the runtime passes to the fetch/scheduled handler.
    pub struct CfBindings {
        env: JsValue,
    }

    impl CfBindings {
        pub fn new(env: JsValue) -> Self {
            CfBindings { env }
        }

        pub fn kv(&self, binding: &str) -> Result<WasmKv, CfError> {
            Ok(WasmKv {
                inner: resolve_binding(&self.env, binding, &["get", "put", "delete", "list"])?,
            })
        }

        pub fn d1(&self, binding: &str) -> Result<WasmD1, CfError> {
            Ok(WasmD1 {
                inner: resolve_binding(&self.env, binding, &["prepare"])?,
            })
        }

        pub fn r2(&self, binding: &str) -> Result<WasmR2, CfError> {
            Ok(WasmR2 {
                inner: resolve_binding(&self.env, binding, &["get", "put", "delete", "head"])?,
            })
        }

        pub fn queue(&self, binding: &str) -> Result<WasmQueue, CfError> {
            Ok(WasmQueue {
                inner: resolve_binding(&self.env, binding, &["send"])?,
            })
        }
    }

    // -- KV ------------------------------------------------------------

    pub struct WasmKv {
        inner: JsValue,
    }

    impl WasmKv {
        pub async fn get_text(&self, key: &str) -> Result<Option<String>, CfError> {
            require_nonempty("key", key)?;
            let p = call2(
                &self.inner,
                "get",
                &JsValue::from_str(key),
                &JsValue::from_str("text"),
            )?;
            let v = awaited(p, "kv.get").await?;
            if v.is_null() || v.is_undefined() {
                return Ok(None);
            }
            Ok(v.as_string())
        }

        pub async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, CfError> {
            require_nonempty("key", key)?;
            let p = call2(
                &self.inner,
                "get",
                &JsValue::from_str(key),
                &JsValue::from_str("arrayBuffer"),
            )?;
            let v = awaited(p, "kv.get").await?;
            if v.is_null() || v.is_undefined() {
                return Ok(None);
            }
            Ok(Some(js_sys::Uint8Array::new(&v).to_vec()))
        }

        pub async fn put_text(
            &self,
            key: &str,
            value: &str,
            opts: &KvPutOptions,
        ) -> Result<(), CfError> {
            self.put_js(key, &JsValue::from_str(value), opts).await
        }

        pub async fn put_bytes(
            &self,
            key: &str,
            value: &[u8],
            opts: &KvPutOptions,
        ) -> Result<(), CfError> {
            let arr = js_sys::Uint8Array::from(value);
            self.put_js(key, &arr.into(), opts).await
        }

        async fn put_js(
            &self,
            key: &str,
            value: &JsValue,
            opts: &KvPutOptions,
        ) -> Result<(), CfError> {
            require_nonempty("key", key)?;
            let options = js_sys::Object::new();
            if let Some(ttl) = opts.expiration_ttl {
                js_sys::Reflect::set(
                    &options,
                    &JsValue::from_str("expirationTtl"),
                    &JsValue::from_f64(ttl as f64),
                )
                .map_err(|e| binding_err("set expirationTtl", e))?;
            }
            if let Some(exp) = opts.expiration {
                js_sys::Reflect::set(
                    &options,
                    &JsValue::from_str("expiration"),
                    &JsValue::from_f64(exp as f64),
                )
                .map_err(|e| binding_err("set expiration", e))?;
            }
            let args = js_sys::Array::new();
            args.push(&JsValue::from_str(key));
            args.push(value);
            args.push(&options.into());
            let p = call(&self.inner, "put", &args)?;
            awaited(p, "kv.put").await?;
            Ok(())
        }

        pub async fn delete(&self, key: &str) -> Result<(), CfError> {
            require_nonempty("key", key)?;
            let p = call1(&self.inner, "delete", &JsValue::from_str(key))?;
            awaited(p, "kv.delete").await?;
            Ok(())
        }

        pub async fn list(&self, opts: &KvListOptions) -> Result<KvListPage, CfError> {
            let options = js_sys::Object::new();
            if let Some(p) = &opts.prefix {
                js_sys::Reflect::set(
                    &options,
                    &JsValue::from_str("prefix"),
                    &JsValue::from_str(p),
                )
                .map_err(|e| binding_err("set prefix", e))?;
            }
            if let Some(l) = opts.limit {
                js_sys::Reflect::set(
                    &options,
                    &JsValue::from_str("limit"),
                    &JsValue::from_f64(l as f64),
                )
                .map_err(|e| binding_err("set limit", e))?;
            }
            if let Some(c) = &opts.cursor {
                js_sys::Reflect::set(
                    &options,
                    &JsValue::from_str("cursor"),
                    &JsValue::from_str(c),
                )
                .map_err(|e| binding_err("set cursor", e))?;
            }
            let p = call1(&self.inner, "list", &options.into())?;
            let v = awaited(p, "kv.list").await?;
            let page = js_to_value(&v);
            let keys = page["keys"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|k| KvKey {
                    name: k["name"].as_str().unwrap_or("").to_string(),
                    expiration: k["expiration"].as_i64(),
                    metadata: if k["metadata"].is_null() {
                        None
                    } else {
                        Some(k["metadata"].clone())
                    },
                })
                .collect();
            Ok(KvListPage {
                keys,
                list_complete: page["list_complete"].as_bool().unwrap_or(false),
                cursor: page["cursor"].as_str().map(|s| s.to_string()),
            })
        }
    }

    // -- D1 ------------------------------------------------------------

    pub struct WasmD1 {
        inner: JsValue,
    }

    impl WasmD1 {
        fn prepare_bound(&self, sql: &str, params: &[Value]) -> Result<JsValue, CfError> {
            require_nonempty("sql", sql)?;
            let stmt = call1(&self.inner, "prepare", &JsValue::from_str(sql))?;
            if params.is_empty() {
                return Ok(stmt);
            }
            let args = js_sys::Array::new();
            for p in params {
                args.push(&value_to_js(p)?);
            }
            call(&stmt, "bind", &args)
        }

        pub async fn query(
            &self,
            sql: &str,
            params: &[Value],
        ) -> Result<D1Result, CfError> {
            let stmt = self.prepare_bound(sql, params)?;
            let p = call0(&stmt, "all")?;
            let v = awaited(p, "d1.all").await?;
            let out = js_to_value(&v);
            if out["success"].as_bool() == Some(false) {
                return Err(CfError::Binding(format!(
                    "d1 query failed: {}",
                    out["error"].as_str().unwrap_or("unknown error")
                )));
            }
            Ok(D1Result {
                results: out["results"].as_array().cloned().unwrap_or_default(),
                meta: meta_from(&out["meta"]),
            })
        }

        pub async fn execute(&self, sql: &str, params: &[Value]) -> Result<D1Meta, CfError> {
            let stmt = self.prepare_bound(sql, params)?;
            let p = call0(&stmt, "run")?;
            let v = awaited(p, "d1.run").await?;
            let out = js_to_value(&v);
            if out["success"].as_bool() == Some(false) {
                return Err(CfError::Binding(format!(
                    "d1 execute failed: {}",
                    out["error"].as_str().unwrap_or("unknown error")
                )));
            }
            Ok(meta_from(&out["meta"]))
        }
    }

    // -- R2 ------------------------------------------------------------

    pub struct WasmR2 {
        inner: JsValue,
    }

    /// A live R2 object handle.  Metadata is read synchronously off
    /// the object; the body is available as bytes, as text, or as the
    /// raw ReadableStream (`body_stream`) for streaming consumers —
    /// the stream is passed through untouched, never buffered here.
    pub struct WasmR2Object {
        inner: JsValue,
    }

    impl WasmR2Object {
        pub fn key(&self) -> String {
            get_prop(&self.inner, "key")
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default()
        }

        pub fn size(&self) -> Option<u64> {
            get_prop(&self.inner, "size")
                .ok()
                .and_then(|v| v.as_f64())
                .map(|n| n as u64)
        }

        pub fn etag(&self) -> Option<String> {
            get_prop(&self.inner, "etag")
                .ok()
                .and_then(|v| v.as_string())
        }

        pub fn content_type(&self) -> Option<String> {
            let meta = get_prop(&self.inner, "httpMetadata").ok()?;
            get_prop(&meta, "contentType")
                .ok()
                .and_then(|v| v.as_string())
        }

        /// The raw `ReadableStream` body, for streaming consumers.
        pub fn body_stream(&self) -> Result<JsValue, CfError> {
            get_prop(&self.inner, "body")
        }

        pub async fn bytes(&self) -> Result<Vec<u8>, CfError> {
            let p = call0(&self.inner, "arrayBuffer")?;
            let v = awaited(p, "r2.arrayBuffer").await?;
            Ok(js_sys::Uint8Array::new(&v).to_vec())
        }

        pub async fn text(&self) -> Result<String, CfError> {
            let p = call0(&self.inner, "text")?;
            let v = awaited(p, "r2.text").await?;
            v.as_string()
                .ok_or_else(|| CfError::Binding("r2.text resolved to a non-string".to_string()))
        }
    }

    /// What a wasm `r2_put` can carry: buffered bytes/text, or a raw
    /// stream/value handed straight to the binding (streaming puts).
    pub enum R2PutData<'a> {
        Bytes(&'a [u8]),
        Text(&'a str),
        Raw(JsValue),
    }

    impl WasmR2 {
        pub async fn get(&self, key: &str) -> Result<Option<WasmR2Object>, CfError> {
            require_nonempty("key", key)?;
            let p = call1(&self.inner, "get", &JsValue::from_str(key))?;
            let v = awaited(p, "r2.get").await?;
            if v.is_null() || v.is_undefined() {
                return Ok(None);
            }
            Ok(Some(WasmR2Object { inner: v }))
        }

        /// Metadata only (`head`): `Some` without a body stream.
        pub async fn head(&self, key: &str) -> Result<Option<WasmR2Object>, CfError> {
            require_nonempty("key", key)?;
            let p = call1(&self.inner, "head", &JsValue::from_str(key))?;
            let v = awaited(p, "r2.head").await?;
            if v.is_null() || v.is_undefined() {
                return Ok(None);
            }
            Ok(Some(WasmR2Object { inner: v }))
        }

        pub async fn put(
            &self,
            key: &str,
            data: R2PutData<'_>,
            content_type: Option<&str>,
        ) -> Result<(), CfError> {
            require_nonempty("key", key)?;
            let value: JsValue = match data {
                R2PutData::Bytes(b) => js_sys::Uint8Array::from(b).into(),
                R2PutData::Text(t) => JsValue::from_str(t),
                R2PutData::Raw(v) => v,
            };
            let args = js_sys::Array::new();
            args.push(&JsValue::from_str(key));
            args.push(&value);
            if let Some(ct) = content_type {
                let meta = js_sys::Object::new();
                js_sys::Reflect::set(
                    &meta,
                    &JsValue::from_str("contentType"),
                    &JsValue::from_str(ct),
                )
                .map_err(|e| binding_err("set contentType", e))?;
                let options = js_sys::Object::new();
                js_sys::Reflect::set(
                    &options,
                    &JsValue::from_str("httpMetadata"),
                    &meta.into(),
                )
                .map_err(|e| binding_err("set httpMetadata", e))?;
                args.push(&options.into());
            }
            let p = call(&self.inner, "put", &args)?;
            awaited(p, "r2.put").await?;
            Ok(())
        }

        pub async fn delete(&self, key: &str) -> Result<(), CfError> {
            require_nonempty("key", key)?;
            let p = call1(&self.inner, "delete", &JsValue::from_str(key))?;
            awaited(p, "r2.delete").await?;
            Ok(())
        }
    }

    // -- Queues --------------------------------------------------------

    pub struct WasmQueue {
        inner: JsValue,
    }

    impl WasmQueue {
        pub async fn send(&self, body: &Value) -> Result<(), CfError> {
            let js = value_to_js(body)?;
            let p = call1(&self.inner, "send", &js)?;
            awaited(p, "queue.send").await?;
            Ok(())
        }

        pub async fn send_text(&self, body: &str) -> Result<(), CfError> {
            let options = js_sys::Object::new();
            js_sys::Reflect::set(
                &options,
                &JsValue::from_str("contentType"),
                &JsValue::from_str("text"),
            )
            .map_err(|e| binding_err("set contentType", e))?;
            let p = call2(
                &self.inner,
                "send",
                &JsValue::from_str(body),
                &options.into(),
            )?;
            awaited(p, "queue.send").await?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------
// Organelle trait surface (codon `cs`).
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let binding_key = serde_json::json!({
        "type": "object",
        "required": ["binding"],
        "properties": {
            "binding": {"type": "string", "minLength": 1},
            "key": {"type": "string", "minLength": 1}
        }
    });
    let binding_sql = serde_json::json!({
        "type": "object",
        "required": ["binding", "sql"],
        "properties": {
            "binding": {"type": "string", "minLength": 1},
            "sql": {"type": "string", "minLength": 1},
            "params": {"type": "array"}
        }
    });
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "cf-storage".to_string(),
        codon: "cs".to_string(),
        version: "1.0.0".to_string(),
        description:
            "Cloudflare storage backends (KV / D1 / R2 / Queues) behind the estate store contracts, via the REST API"
                .to_string(),
        contracts: vec![
            Contract {
                op: "kv_get".to_string(),
                description: "read a KV value by key (binding = namespace id); value returned as text".to_string(),
                input_schema: binding_key.clone(),
                mutation_class: None,
                required_capability: Some("cf.kv.read".to_string()),
            },
            Contract {
                op: "kv_put".to_string(),
                description: "write a KV value (binding = namespace id); value_text, optional expiration_ttl seconds".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["binding", "key", "value_text"],
                    "properties": {
                        "binding": {"type": "string", "minLength": 1},
                        "key": {"type": "string", "minLength": 1},
                        "value_text": {"type": "string"},
                        "expiration_ttl": {"type": "integer", "minimum": 60}
                    }
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cf.kv.write".to_string()),
            },
            Contract {
                op: "kv_delete".to_string(),
                description: "delete a KV key (binding = namespace id); idempotent".to_string(),
                input_schema: binding_key.clone(),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cf.kv.write".to_string()),
            },
            Contract {
                op: "kv_list".to_string(),
                description: "list KV keys (binding = namespace id); optional prefix / limit / cursor".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["binding"],
                    "properties": {
                        "binding": {"type": "string", "minLength": 1},
                        "prefix": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1},
                        "cursor": {"type": "string"}
                    }
                }),
                mutation_class: None,
                required_capability: Some("cf.kv.read".to_string()),
            },
            Contract {
                op: "d1_query".to_string(),
                description: "run a row-returning D1 statement (binding = database id); the endpoint executes any SQL — read intent is the caller's contract".to_string(),
                input_schema: binding_sql.clone(),
                mutation_class: None,
                required_capability: Some("cf.d1.read".to_string()),
            },
            Contract {
                op: "d1_execute".to_string(),
                description: "run a D1 statement for its effects (binding = database id); returns statement metadata".to_string(),
                input_schema: binding_sql.clone(),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cf.d1.write".to_string()),
            },
            Contract {
                op: "r2_get".to_string(),
                description: "read an R2 object (binding = bucket name); body returned as text".to_string(),
                input_schema: binding_key.clone(),
                mutation_class: None,
                required_capability: Some("cf.r2.read".to_string()),
            },
            Contract {
                op: "r2_put".to_string(),
                description: "write an R2 object (binding = bucket name); value_text, optional content_type".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["binding", "key", "value_text"],
                    "properties": {
                        "binding": {"type": "string", "minLength": 1},
                        "key": {"type": "string", "minLength": 1},
                        "value_text": {"type": "string"},
                        "content_type": {"type": "string"}
                    }
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cf.r2.write".to_string()),
            },
            Contract {
                op: "r2_delete".to_string(),
                description: "delete an R2 object (binding = bucket name); idempotent".to_string(),
                input_schema: binding_key.clone(),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cf.r2.write".to_string()),
            },
            Contract {
                op: "queue_send".to_string(),
                description: "send one message to a Queue (binding = queue id); body is any JSON value".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["binding", "body"],
                    "properties": {
                        "binding": {"type": "string", "minLength": 1}
                    }
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cf.queue.send".to_string()),
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::Write,
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
pub struct CfStorage {
    manifest: OrganelleManifest,
    client: Option<std::sync::Arc<CfRestClient>>,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> Arc<dyn Organelle> {
    // Configuration is injected by the host process through its
    // environment: CF_ACCOUNT_ID + CF_API_TOKEN.  The crate reads
    // nothing else and nothing from disk.  Absent either, the
    // organelle registers unconfigured and every op fails honestly.
    let client = match (
        std::env::var("CF_ACCOUNT_ID"),
        std::env::var("CF_API_TOKEN"),
    ) {
        (Ok(acct), Ok(token)) if !acct.is_empty() && !token.is_empty() => {
            Some(std::sync::Arc::new(CfRestClient::new(acct, token)))
        }
        _ => None,
    };
    Arc::new(CfStorage {
        manifest: manifest(),
        client,
    })
}

#[cfg(feature = "organelle")]
pub fn organelle_with_client(client: std::sync::Arc<CfRestClient>) -> Arc<dyn Organelle> {
    Arc::new(CfStorage {
        manifest: manifest(),
        client: Some(client),
    })
}

#[cfg(feature = "organelle")]
impl CfStorage {
    fn client(&self) -> Result<&CfRestClient, OrganelleError> {
        self.client.as_deref().ok_or_else(|| {
            OrganelleError::failed(
                "cf-storage: not configured (inject a CfRestClient or set CF_ACCOUNT_ID + CF_API_TOKEN in the host environment)",
            )
        })
    }
}

#[cfg(feature = "organelle")]
fn meta_json(m: &D1Meta) -> Value {
    serde_json::json!({
        "changed_db": m.changed_db,
        "changes": m.changes,
        "last_row_id": m.last_row_id,
        "rows_read": m.rows_read,
        "rows_written": m.rows_written,
        "duration_ms": m.duration_ms,
    })
}

#[cfg(feature = "organelle")]
impl Organelle for CfStorage {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        let binding = input["binding"].as_str().unwrap_or("");
        let key = input["key"].as_str().unwrap_or("");
        let fail = |e: CfError| OrganelleError::failed(e.to_string());
        match op {
            "kv_get" => {
                let v = self
                    .client()?
                    .kv_get(binding, key)
                    .map_err(fail)?;
                match v {
                    Some(bytes) => Ok(serde_json::json!({
                        "found": true,
                        "value_text": String::from_utf8_lossy(&bytes),
                        "bytes": bytes.len(),
                    })),
                    None => Ok(serde_json::json!({"found": false})),
                }
            }
            "kv_put" => {
                let value = input["value_text"].as_str().unwrap_or("");
                let opts = KvPutOptions {
                    expiration_ttl: input["expiration_ttl"].as_u64(),
                    expiration: None,
                };
                self.client()?
                    .kv_put(binding, key, value.as_bytes(), &opts)
                    .map_err(fail)?;
                Ok(serde_json::json!({"ok": true, "bytes": value.len()}))
            }
            "kv_delete" => {
                self.client()?.kv_delete(binding, key).map_err(fail)?;
                Ok(serde_json::json!({"ok": true}))
            }
            "kv_list" => {
                let opts = KvListOptions {
                    prefix: input["prefix"].as_str().map(|s| s.to_string()),
                    limit: input["limit"].as_u64().map(|n| n as u32),
                    cursor: input["cursor"].as_str().map(|s| s.to_string()),
                };
                let page = self.client()?.kv_list(binding, &opts).map_err(fail)?;
                Ok(serde_json::json!({
                    "keys": page.keys.iter().map(|k| serde_json::json!({
                        "name": k.name,
                        "expiration": k.expiration,
                        "metadata": k.metadata,
                    })).collect::<Vec<_>>(),
                    "list_complete": page.list_complete,
                    "cursor": page.cursor,
                }))
            }
            "d1_query" => {
                let sql = input["sql"].as_str().unwrap_or("");
                let params: Vec<Value> =
                    input["params"].as_array().cloned().unwrap_or_default();
                let r = self
                    .client()?
                    .d1_query(binding, sql, &params)
                    .map_err(fail)?;
                Ok(serde_json::json!({
                    "results": r.results,
                    "meta": meta_json(&r.meta),
                }))
            }
            "d1_execute" => {
                let sql = input["sql"].as_str().unwrap_or("");
                let params: Vec<Value> =
                    input["params"].as_array().cloned().unwrap_or_default();
                let m = self
                    .client()?
                    .d1_execute(binding, sql, &params)
                    .map_err(fail)?;
                Ok(serde_json::json!({"meta": meta_json(&m)}))
            }
            "r2_get" => {
                let v = self.client()?.r2_get(binding, key).map_err(fail)?;
                match v {
                    Some(obj) => Ok(serde_json::json!({
                        "found": true,
                        "value_text": obj.body_text_lossy(),
                        "bytes": obj.body.len(),
                        "content_type": obj.content_type,
                        "etag": obj.etag,
                    })),
                    None => Ok(serde_json::json!({"found": false})),
                }
            }
            "r2_put" => {
                let value = input["value_text"].as_str().unwrap_or("");
                self.client()?
                    .r2_put(
                        binding,
                        key,
                        value.as_bytes(),
                        input["content_type"].as_str(),
                    )
                    .map_err(fail)?;
                Ok(serde_json::json!({"ok": true, "bytes": value.len()}))
            }
            "r2_delete" => {
                self.client()?.r2_delete(binding, key).map_err(fail)?;
                Ok(serde_json::json!({"ok": true}))
            }
            "queue_send" => {
                self.client()?
                    .queue_send(binding, &input["body"])
                    .map_err(fail)?;
                Ok(serde_json::json!({"ok": true}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  Deterministic and offline: a recorded transport replays
// Cloudflare-shaped responses and records every request, so URL
// construction, the auth header, envelope parsing and the error
// taxonomy are all exercised without the live account.  The live
// proof is examples/live_d1.rs (env-gated, read-only).
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ref_https_transport::HttpsResponse;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct Recorded {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    pub(crate) struct Rule {
        pub(crate) method: &'static str,
        pub(crate) path_part: &'static str,
        pub(crate) status: u16,
        pub(crate) headers: Vec<(String, String)>,
        pub(crate) body: Vec<u8>,
    }

    pub(crate) struct RecordedTransport {
        rules: Vec<Rule>,
        seen: Mutex<Vec<Recorded>>,
    }

    impl RecordedTransport {
        pub(crate) fn new(rules: Vec<Rule>) -> std::sync::Arc<Self> {
            std::sync::Arc::new(RecordedTransport {
                rules,
                seen: Mutex::new(vec![]),
            })
        }

        fn last(&self) -> Recorded {
            let seen = self.seen.lock().unwrap();
            let r = seen.last().expect("at least one request recorded");
            Recorded {
                method: r.method.clone(),
                url: r.url.clone(),
                headers: r.headers.clone(),
                body: r.body.clone(),
            }
        }
    }

    impl HttpsTransport for RecordedTransport {
        fn send(&self, req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
            self.seen.lock().unwrap().push(Recorded {
                method: req.method.as_str().to_string(),
                url: req.url.clone(),
                headers: req.headers.clone(),
                body: req.body.clone().unwrap_or_default(),
            });
            for rule in &self.rules {
                if rule.method == req.method.as_str() && req.url.contains(rule.path_part) {
                    return Ok(HttpsResponse {
                        status: rule.status,
                        headers: rule.headers.clone(),
                        body: rule.body.clone(),
                        truncated: false,
                    });
                }
            }
            Err(TransportError::Network(format!(
                "recorded transport: no rule for {} {}",
                req.method.as_str(),
                req.url
            )))
        }
    }

    pub(crate) fn envelope_ok(result: Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "success": true, "errors": [], "messages": [], "result": result
        }))
        .unwrap()
    }

    pub(crate) fn envelope_err(code: i64, message: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "success": false,
            "errors": [{"code": code, "message": message}],
            "messages": [],
            "result": null
        }))
        .unwrap()
    }

    fn client(t: std::sync::Arc<RecordedTransport>) -> CfRestClient {
        CfRestClient::with_transport("acct-test", "test-token", t)
            .api_base("https://api.cloudflare.com/client/v4")
    }

    #[test]
    fn pct_encode_keeps_keys_out_of_the_path() {
        assert_eq!(pct_encode("a b/c", false), "a%20b%2Fc");
        assert_eq!(pct_encode("a b/c", true), "a%20b/c");
        assert_eq!(pct_encode("plain-key_1.~", false), "plain-key_1.~");
    }

    #[test]
    fn kv_roundtrip_and_request_shape() {
        let t = RecordedTransport::new(vec![
            Rule {
                method: "PUT",
                path_part: "/values/k1",
                status: 200,
                headers: vec![],
                body: envelope_ok(Value::Null),
            },
            Rule {
                method: "GET",
                path_part: "/values/k1",
                status: 200,
                headers: vec![],
                body: b"hello kv".to_vec(),
            },
            Rule {
                method: "DELETE",
                path_part: "/values/k1",
                status: 200,
                headers: vec![],
                body: envelope_ok(Value::Null),
            },
        ]);
        let c = client(t.clone());
        c.kv_put(
            "ns1",
            "k1",
            b"hello kv",
            &KvPutOptions {
                expiration_ttl: Some(120),
                expiration: None,
            },
        )
        .unwrap();
        let put = t.last();
        assert_eq!(put.method, "PUT");
        assert!(put.url.contains("expiration_ttl=120"), "{}", put.url);
        assert!(put
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer test-token"));
        assert_eq!(put.body, b"hello kv");

        let got = c.kv_get("ns1", "k1").unwrap();
        assert_eq!(got, Some(b"hello kv".to_vec()));
        c.kv_delete("ns1", "k1").unwrap();
    }

    #[test]
    fn kv_missing_key_is_none_not_error() {
        let t = RecordedTransport::new(vec![Rule {
            method: "GET",
            path_part: "/values/nope",
            status: 404,
            headers: vec![],
            body: envelope_err(10009, "key not found"),
        }]);
        let c = client(t);
        assert_eq!(c.kv_get("ns1", "nope").unwrap(), None);
    }

    #[test]
    fn kv_list_parses_page_and_cursor() {
        let t = RecordedTransport::new(vec![Rule {
            method: "GET",
            path_part: "/keys",
            status: 200,
            headers: vec![],
            body: envelope_ok(serde_json::json!({
                "keys": [
                    {"name": "a", "expiration": 1893456000, "metadata": {"x": 1}},
                    {"name": "b"}
                ],
                "list_complete": false,
                "cursor": "cursor-2"
            })),
        }]);
        let c = client(t.clone());
        let page = c
            .kv_list(
                "ns1",
                &KvListOptions {
                    prefix: Some("a".to_string()),
                    limit: Some(2),
                    cursor: None,
                },
            )
            .unwrap();
        assert_eq!(page.keys.len(), 2);
        assert_eq!(page.keys[0].name, "a");
        assert_eq!(page.keys[0].expiration, Some(1893456000));
        assert_eq!(page.keys[1].metadata, None);
        assert!(!page.list_complete);
        assert_eq!(page.cursor.as_deref(), Some("cursor-2"));
        assert!(t.last().url.contains("prefix=a"), "{}", t.last().url);
    }

    #[test]
    fn d1_query_parses_rows_and_meta() {
        let t = RecordedTransport::new(vec![Rule {
            method: "POST",
            path_part: "/d1/database/db1/query",
            status: 200,
            headers: vec![],
            body: envelope_ok(serde_json::json!([{
                "success": true,
                "results": [{"one": 1}, {"one": 2}],
                "meta": {
                    "changed_db": false, "changes": 0, "last_row_id": 0,
                    "rows_read": 2, "rows_written": 0, "duration": 0.42
                }
            }])),
        }]);
        let c = client(t.clone());
        let r = c
            .d1_query("db1", "SELECT one FROM t WHERE x = ?", &[serde_json::json!(7)])
            .unwrap();
        assert_eq!(r.results.len(), 2);
        assert_eq!(r.results[1]["one"], serde_json::json!(2));
        assert_eq!(r.meta.rows_read, Some(2));
        assert_eq!(r.meta.duration_ms, Some(0.42));
        let sent: Value = serde_json::from_slice(&t.last().body).unwrap();
        assert_eq!(sent["sql"], serde_json::json!("SELECT one FROM t WHERE x = ?"));
        assert_eq!(sent["params"], serde_json::json!([7]));
    }

    #[test]
    fn d1_statement_failure_is_api_error() {
        let t = RecordedTransport::new(vec![Rule {
            method: "POST",
            path_part: "/query",
            status: 200,
            headers: vec![],
            body: envelope_ok(serde_json::json!([{
                "success": false,
                "error": "no such table: nope",
                "results": [],
                "meta": {}
            }])),
        }]);
        let c = client(t);
        let e = c.d1_query("db1", "SELECT * FROM nope", &[]).unwrap_err();
        match e {
            CfError::Api { errors, .. } => {
                assert!(errors[0].message.contains("no such table"), "{errors:?}")
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn d1_execute_returns_meta() {
        let t = RecordedTransport::new(vec![Rule {
            method: "POST",
            path_part: "/execute",
            status: 200,
            headers: vec![],
            body: envelope_ok(serde_json::json!([{
                "success": true,
                "results": [],
                "meta": {"changed_db": true, "changes": 3, "last_row_id": 9,
                          "rows_read": 0, "rows_written": 3, "duration": 1.5}
            }])),
        }]);
        let c = client(t);
        let m = c
            .d1_execute("db1", "INSERT INTO t VALUES (1)", &[])
            .unwrap();
        assert_eq!(m.changes, Some(3));
        assert_eq!(m.last_row_id, Some(9));
        assert_eq!(m.changed_db, Some(true));
    }

    #[test]
    fn r2_get_put_delete() {
        let t = RecordedTransport::new(vec![
            Rule {
                method: "PUT",
                path_part: "/objects/dir/file.txt",
                status: 200,
                headers: vec![],
                body: envelope_ok(serde_json::json!({"key": "dir/file.txt"})),
            },
            Rule {
                method: "GET",
                path_part: "/objects/dir/file.txt",
                status: 200,
                headers: vec![
                    ("content-type".to_string(), "text/plain".to_string()),
                    ("etag".to_string(), "\"abc\"".to_string()),
                ],
                body: b"object body".to_vec(),
            },
            Rule {
                method: "DELETE",
                path_part: "/objects/dir/file.txt",
                status: 200,
                headers: vec![],
                body: envelope_ok(Value::Null),
            },
            Rule {
                method: "GET",
                path_part: "/objects/absent",
                status: 404,
                headers: vec![],
                body: envelope_err(10007, "object not found"),
            },
        ]);
        let c = client(t.clone());
        c.r2_put("bucket1", "dir/file.txt", b"object body", Some("text/plain"))
            .unwrap();
        let put = t.last();
        assert!(put
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "text/plain"));
        let obj = c.r2_get("bucket1", "dir/file.txt").unwrap().unwrap();
        assert_eq!(obj.body, b"object body");
        assert_eq!(obj.content_type.as_deref(), Some("text/plain"));
        assert_eq!(obj.etag.as_deref(), Some("\"abc\""));
        assert_eq!(c.r2_get("bucket1", "absent").unwrap(), None);
        c.r2_delete("bucket1", "dir/file.txt").unwrap();
    }

    #[test]
    fn queue_send_shapes() {
        let t = RecordedTransport::new(vec![Rule {
            method: "POST",
            path_part: "/queues/q1/messages",
            status: 200,
            headers: vec![],
            body: envelope_ok(Value::Null),
        }]);
        let c = client(t.clone());
        c.queue_send("q1", &serde_json::json!({"kind": "push"})).unwrap();
        let sent: Value = serde_json::from_slice(&t.last().body).unwrap();
        assert_eq!(sent["body"], serde_json::json!({"kind": "push"}));
        c.queue_send_text("q1", "plain").unwrap();
        let sent: Value = serde_json::from_slice(&t.last().body).unwrap();
        assert_eq!(sent["body"], serde_json::json!("plain"));
        assert_eq!(sent["content_type"], serde_json::json!("text"));
    }

    #[test]
    fn auth_and_api_taxonomy() {
        let t = RecordedTransport::new(vec![
            Rule {
                method: "GET",
                path_part: "/values/auth",
                status: 401,
                headers: vec![],
                body: envelope_err(10000, "Authentication error"),
            },
            Rule {
                method: "GET",
                path_part: "/keys",
                status: 400,
                headers: vec![],
                body: envelope_err(10048, "invalid namespace"),
            },
        ]);
        let c = client(t);
        // kv_get only special-cases 404; 401 must surface as Auth.
        match c.kv_get("ns1", "auth") {
            Err(CfError::Auth { status: 401, errors }) => {
                assert_eq!(errors[0].code, 10000);
            }
            other => panic!("expected Auth error, got {other:?}"),
        }
        match c.kv_list("ns1", &KvListOptions::default()) {
            Err(CfError::Api { status: 400, errors }) => {
                assert_eq!(errors[0].code, 10048);
                assert!(errors[0].message.contains("invalid namespace"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn transport_failure_is_transport_variant() {
        let t = RecordedTransport::new(vec![]);
        let c = client(t);
        match c.kv_get("ns1", "k") {
            Err(CfError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[test]
    fn empty_names_are_invalid_requests() {
        let t = RecordedTransport::new(vec![]);
        let c = client(t);
        assert!(matches!(
            c.kv_get("", "k"),
            Err(CfError::InvalidRequest(_))
        ));
        assert!(matches!(
            c.d1_query("db", "", &[]),
            Err(CfError::InvalidRequest(_))
        ));
        assert!(matches!(
            c.r2_get("b", ""),
            Err(CfError::InvalidRequest(_))
        ));
    }

    #[test]
    fn client_debug_redacts_token() {
        let t = RecordedTransport::new(vec![]);
        let c = client(t);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(!dbg.contains("test-token"), "{dbg}");
    }
}

#[cfg(all(test, feature = "organelle"))]
mod organelle_tests {
    use super::tests::{envelope_ok, RecordedTransport, Rule};
    use super::*;
    use organelle_host::Host;

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }

    #[test]
    fn unconfigured_organelle_fails_honestly() {
        let h = Host::new();
        h.register(Arc::new(CfStorage {
            manifest: manifest(),
            client: None,
        }))
        .unwrap();
        let ctx = CallContext::new("test", vec!["cf.kv.read".to_string()]);
        let e = h
            .call(
                &ctx,
                "cs",
                "kv_get",
                serde_json::json!({"binding": "ns1", "key": "k"}),
            )
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
        assert!(e.reason.contains("not configured"), "{}", e.reason);
    }

    #[test]
    fn ops_roundtrip_through_host() {
        let t = RecordedTransport::new(vec![
            Rule {
                method: "PUT",
                path_part: "/values/k1",
                status: 200,
                headers: vec![],
                body: envelope_ok(Value::Null),
            },
            Rule {
                method: "GET",
                path_part: "/values/k1",
                status: 200,
                headers: vec![],
                body: b"via organelle".to_vec(),
            },
        ]);
        let client = std::sync::Arc::new(CfRestClient::with_transport(
            "acct-test",
            "test-token",
            t,
        ));
        let h = Host::new();
        h.register(organelle_with_client(client)).unwrap();

        let writer = CallContext::new("writer", vec!["cf.kv.write".to_string()]);
        let put = h
            .call(
                &writer,
                "cs",
                "kv_put",
                serde_json::json!({"binding": "ns1", "key": "k1", "value_text": "via organelle"}),
            )
            .unwrap()
            .output;
        assert_eq!(put["ok"], serde_json::json!(true));

        let reader = CallContext::new("reader", vec!["cf.kv.read".to_string()]);
        let got = h
            .call(
                &reader,
                "cs",
                "kv_get",
                serde_json::json!({"binding": "ns1", "key": "k1"}),
            )
            .unwrap()
            .output;
        assert_eq!(got["found"], serde_json::json!(true));
        assert_eq!(got["value_text"], serde_json::json!("via organelle"));

        // Write without the write capability is denied by the host
        // before the organelle runs.
        let e = h
            .call(
                &reader,
                "cs",
                "kv_put",
                serde_json::json!({"binding": "ns1", "key": "k1", "value_text": "x"}),
            )
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
    }
}
