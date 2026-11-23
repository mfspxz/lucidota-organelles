//! org-039 — Reference organelle: Mem0 client (codon `m0`).
//!
//! The estate's Rust face for the Mem0 hosted platform
//! (https://api.mem0.ai): add, search, list, get, and delete over
//! org-026's HTTPS transport, with org-028's credential discipline
//! and org-035's receipt discipline.  It replaces the throwaway
//! Python import driver (`~/workspace/mem0-import/driver.py`) as
//! the durable way anything here talks to Mem0.
//!
//! # The API version is caller data — never silently picked
//!
//! The estate's live deployment runs the REST **v1** shapes: they
//! are what the 2026-11-23 import proved against the production
//! API (2,376 submissions, event receipts, a verified search).
//! The current Mem0 docs lead with **v3** (manual §3.8.2, §4.8):
//! add and search moved to `/v3/memories/…` paths, list became a
//! POST returning a paginated envelope, entity IDs nest inside a
//! `filters` object on search and list, and the search threshold
//! default moved to 0.1.  The migration guide states v1/v2
//! endpoints continue to work — there is no forced migration.
//!
//! So [`Mem0Config`] carries an explicit [`ApiVersion`], stated by
//! the caller next to the base URL, and every receipt records the
//! version that served the call.  The v1 shapes are byte-tested
//! against tonight's proven traffic.  The v3 shapes are built from
//! the manual's pinned doc snapshot (sha-pinned in APPLICATION.md)
//! and unit-tested against those documented shapes; they are
//! **doc-derived, not live-proven**, and the report says so.
//! Get and delete use the `/v1/memories/{id}/` management paths
//! under both versions — that mixed versioning is the docs' own
//! (§3.8.2: "the rest are v1 management paths").
//!
//! # Async honesty
//!
//! `add` is asynchronous on the server: the response is an event
//! receipt (`PENDING` + `event_id`), not memories.  Extraction
//! runs server-side and lands later; callers observe landed
//! memories by polling search/list.  [`AddOutcome`] therefore
//! carries the event records and nothing that pretends the
//! memories already exist.
//!
//! # Credential discipline (org-028's rules)
//!
//! The API key is injected at construction as a [`Mem0ApiKey`]:
//! header-only placement (`Authorization: Token <key>`), no
//! `Display`, a redacted `Debug`, a zeroing `Drop`, and no path
//! into receipts, errors, or logs.  The test suite's grep test
//! runs every op with a loud fixture key and proves it reaches
//! the wire (in the header) and appears in **no** output shape.
//!
//! # Receipts
//!
//! One [`Mem0Receipt`] per call in the estate `calls.jsonl`
//! shape: endpoint, op, version, status, HTTP status, latency,
//! scope ids, and result ids/counts.  Never the key; never memory
//! content — a receipt names *that* a search returned 3 records,
//! never what they say.
//!
//! # Errors are typed and honest
//!
//! HTTP 429 is [`Mem0Error::RateLimited`] (estate rule: callers
//! stop, nobody hammers).  A transport failure is
//! [`Mem0Error::Transport`] — it is never disguised as an empty
//! result; an empty result is a 200 with zero records, and the
//! two are distinguishable in the type.

use ref_https_transport::{HttpsRequest, HttpsResponse, HttpsTransport, Method, TransportError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
#[cfg(any(feature = "organelle", test))]
use std::sync::Arc;

// ---------------------------------------------------------------------
// Time helpers.  Receipts carry the estate's ISO-8601 UTC shape
// ("2026-11-23T03:46:05Z"); the conversion is done by hand so the
// crate needs no date dependency, and it is exact (proleptic
// Gregorian, Howard Hinnant's civil-from-days algorithm).  Copied
// from org-035, including its wasm clock resolution.
// ---------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// wasm32-unknown-unknown has no std clock: `SystemTime::now()`
/// and `Instant::now()` trap with `unreachable` (proven
/// 2026-11-23 — in a Worker the trap is error 1101 on every
/// request).  The host's `Date` is the clock on that target.
#[cfg(target_arch = "wasm32")]
fn now_unix_ms() -> i64 {
    js_sys::Date::now() as i64
}

/// A latency mark.  Native: std `Instant`.  wasm32: the host
/// `Date` clock in milliseconds (wall clock — latency figures are
/// telemetry, and `Date` is the only clock the target has).
#[cfg(not(target_arch = "wasm32"))]
struct Mark(Instant);
#[cfg(target_arch = "wasm32")]
struct Mark(f64);

fn mark_now() -> Mark {
    #[cfg(not(target_arch = "wasm32"))]
    {
        Mark(Instant::now())
    }
    #[cfg(target_arch = "wasm32")]
    {
        Mark(js_sys::Date::now())
    }
}

impl Mark {
    fn elapsed_ms(&self) -> u64 {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.0.elapsed().as_millis() as u64
        }
        #[cfg(target_arch = "wasm32")]
        {
            (js_sys::Date::now() - self.0).max(0.0) as u64
        }
    }
}

/// (year, month, day, hour, minute, second) in UTC for a Unix
/// timestamp in seconds.
fn civil_from_unix(unix_s: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_s.div_euclid(86_400);
    let secs = unix_s.rem_euclid(86_400);
    let (h, mi, s) = (
        (secs / 3600) as u32,
        ((secs % 3600) / 60) as u32,
        (secs % 60) as u32,
    );
    // Civil from days (Hinnant): shift epoch to 0000-03-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

/// ISO-8601 UTC timestamp ("2026-11-23T03:46:05Z") for receipt `ts`.
fn iso_ts(unix_ms: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix_ms.div_euclid(1000));
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Compact timestamp for call ids ("20261123T034605"), the estate
/// usage-log shape.
fn compact_ts(unix_ms: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix_ms.div_euclid(1000));
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}")
}

// ---------------------------------------------------------------------
// Configuration — caller-supplied data, stated in full.  No serde
// defaults, no Default impls: what the caller did not state does
// not happen.
// ---------------------------------------------------------------------

/// Which Mem0 REST API shape family a call uses.  Part of the
/// endpoint config, stated by the caller on every client — this
/// crate never picks one silently (see the crate docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiVersion {
    /// The shapes the estate's 2026-11-23 import proved live:
    /// `POST /v1/memories/`, `POST /v1/memories/search/`,
    /// `GET /v1/memories/?user_id=…` (bare-array response).
    V1,
    /// The shapes the current docs lead with (manual §3.8.2):
    /// `POST /v3/memories/add/`, `POST /v3/memories/search/` and
    /// `POST /v3/memories/` with entity IDs nested in `filters`
    /// and a paginated list envelope.  Doc-derived, unit-tested
    /// against the documented shapes, not live-proven.
    V3,
}

impl ApiVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiVersion::V1 => "v1",
            ApiVersion::V3 => "v3",
        }
    }
}

/// Everything about where calls go and how big they may be.
/// `base_url` carries scheme + host (and any prefix the caller's
/// deployment needs) with **no** version segment — the version is
/// [`Mem0Config::version`], so the two can never disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mem0Config {
    /// e.g. `"https://api.mem0.ai"`.  Caller data; nothing about
    /// the endpoint is baked into this crate.
    pub base_url: String,
    /// The shape family every call from this client uses.
    pub version: ApiVersion,
    /// Whole-transfer timeout per call, handed to org-026.
    pub timeout_ms: u64,
    /// Response body cap per call, handed to org-026.
    pub max_response_bytes: usize,
}

impl Mem0Config {
    pub fn new(
        base_url: impl Into<String>,
        version: ApiVersion,
        timeout_ms: u64,
        max_response_bytes: usize,
    ) -> Self {
        Mem0Config {
            base_url: base_url.into(),
            version,
            timeout_ms,
            max_response_bytes,
        }
    }

    fn base_trimmed(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }
}

// ---------------------------------------------------------------------
// The API key.  Org-028's discipline: constructed at the
// injection point, spent only into the Authorization header,
// exposed nowhere else.
// ---------------------------------------------------------------------

/// A Mem0 API key.  Deliberately has no `Display`, a redacted
/// `Debug`, and a `Drop` that zeroes its buffer (best-effort —
/// the allocator may have copied it before, which is why the
/// real discipline is that it never leaves this crate's request
/// builder at all).
pub struct Mem0ApiKey(String);

impl Mem0ApiKey {
    pub fn new(value: impl Into<String>) -> Self {
        Mem0ApiKey(value.into())
    }

    /// The one door to the value, `pub(crate)`: the request
    /// builder spends it into the `Authorization` header.
    /// Nothing outside this crate can call this.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Mem0ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mem0ApiKey(<redacted>)")
    }
}

impl Drop for Mem0ApiKey {
    fn drop(&mut self) {
        // Zero the buffer before it is freed.
        let bytes = unsafe { self.0.as_mut_vec() };
        for b in bytes.iter_mut() {
            *b = 0;
        }
        self.0.clear();
    }
}

// ---------------------------------------------------------------------
// Scope — the entity IDs every call is scoped to.  Caller data on
// every call; Mem0 requires at least one on add/search/list, and
// the client enforces that before any send.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

impl Scope {
    pub fn new() -> Self {
        Scope::default()
    }

    pub fn user(id: impl Into<String>) -> Self {
        Scope {
            user_id: Some(id.into()),
            agent_id: None,
            run_id: None,
        }
    }

    pub fn with_user(mut self, id: impl Into<String>) -> Self {
        self.user_id = Some(id.into());
        self
    }

    pub fn with_agent(mut self, id: impl Into<String>) -> Self {
        self.agent_id = Some(id.into());
        self
    }

    pub fn with_run(mut self, id: impl Into<String>) -> Self {
        self.run_id = Some(id.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.user_id.is_none() && self.agent_id.is_none() && self.run_id.is_none()
    }

    fn require_non_empty(&self, op: &str) -> Result<(), Mem0Error> {
        if self.is_empty() {
            return Err(Mem0Error::InvalidRequest(format!(
                "{op} requires at least one of user_id / agent_id / run_id"
            )));
        }
        Ok(())
    }

    /// The scope as a JSON object of just the stated ids — the
    /// `filters` body on v3 search/list, merged top-level on v1.
    fn as_json(&self) -> Map<String, Value> {
        let mut m = Map::new();
        if let Some(u) = &self.user_id {
            m.insert("user_id".to_string(), json!(u));
        }
        if let Some(a) = &self.agent_id {
            m.insert("agent_id".to_string(), json!(a));
        }
        if let Some(r) = &self.run_id {
            m.insert("run_id".to_string(), json!(r));
        }
        m
    }
}

// ---------------------------------------------------------------------
// Requests and records.
// ---------------------------------------------------------------------

/// One chat message in an `add` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

impl Message {
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Message {
            role: role.into(),
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Message::new("user", content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Message::new("assistant", content)
    }
}

/// An `add` call: messages to extract memories from, the scope
/// they belong to, and optional caller metadata (stored with the
/// extracted memories; the import driver used `{"source": …}`).
#[derive(Debug, Clone, PartialEq)]
pub struct AddRequest {
    pub messages: Vec<Message>,
    pub scope: Scope,
    pub metadata: Option<Value>,
}

impl AddRequest {
    pub fn new(messages: Vec<Message>, scope: Scope) -> Self {
        AddRequest {
            messages,
            scope,
            metadata: None,
        }
    }

    pub fn metadata(mut self, metadata: Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// A `search` call.  `threshold` is caller data: when stated it
/// is sent; when not stated the server default applies (0.1 on
/// v3 per manual §4.3) — this crate bakes in no threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchRequest {
    pub query: String,
    pub scope: Scope,
    pub threshold: Option<f64>,
}

impl SearchRequest {
    pub fn new(query: impl Into<String>, scope: Scope) -> Self {
        SearchRequest {
            query: query.into(),
            scope,
            threshold: None,
        }
    }

    pub fn threshold(mut self, threshold: f64) -> Self {
        self.threshold = Some(threshold);
        self
    }
}

/// A `list` call.  `page` / `page_size` are caller data, sent
/// only when stated (query parameters on v1, body fields on v3).
#[derive(Debug, Clone, PartialEq)]
pub struct ListRequest {
    pub scope: Scope,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

impl ListRequest {
    pub fn new(scope: Scope) -> Self {
        ListRequest {
            scope,
            page: None,
            page_size: None,
        }
    }

    pub fn page(mut self, page: u32) -> Self {
        self.page = Some(page);
        self
    }

    pub fn page_size(mut self, page_size: u32) -> Self {
        self.page_size = Some(page_size);
        self
    }
}

/// One memory record as the API returns it.  Fields the API adds
/// beyond these (`hash`, `expiration_date`, …) are not modelled;
/// a record that lacks `id` or `memory` is a decode error, never
/// a silently half-empty record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub id: String,
    pub memory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Search relevance score; present on search results only.
    /// On v3 this is a multi-signal fusion score (manual §4.3) —
    /// comparable for ranking, not against v1-era thresholds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// One event record from an `add` response: the server queued
/// (or ran) one extraction event.  `status` is the server's own
/// string — `"PENDING"` on the proven v1 shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// The outcome of an `add` call: event receipts, **not**
/// memories.  Extraction is server-side and asynchronous — the
/// memories these events produce are observed later through
/// search/list.  Anything that presents an `AddOutcome` as
/// stored memories is lying; the type refuses to help.
#[derive(Debug, Clone, PartialEq)]
pub struct AddOutcome {
    pub events: Vec<AddEvent>,
}

impl AddOutcome {
    /// True when every event reports the queued state.
    pub fn all_pending(&self) -> bool {
        !self.events.is_empty() && self.events.iter().all(|e| e.status == "PENDING")
    }

    pub fn event_ids(&self) -> Vec<&str> {
        self.events
            .iter()
            .filter_map(|e| e.event_id.as_deref())
            .collect()
    }
}

/// The outcome of a `list` call.  `count` / `next` / `previous`
/// come from the paginated envelope when the server sends one
/// (the v3 shape, and current v1 deployments); a bare-array
/// response (tonight's proven v1 probe) yields `count = None`
/// and no cursors — the absence is reported, not papered over.
#[derive(Debug, Clone, PartialEq)]
pub struct ListOutcome {
    pub memories: Vec<MemoryRecord>,
    pub count: Option<u64>,
    pub next: Option<String>,
    pub previous: Option<String>,
}

/// The outcome of a `delete` call: the server's own message
/// when it sends one (`"Memory deleted successfully!"` on the
/// documented shape), `None` on an empty body.
#[derive(Debug, Clone, PartialEq)]
pub struct DeleteOutcome {
    pub message: Option<String>,
}

// ---------------------------------------------------------------------
// Errors — typed, and honest about which layer failed.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Mem0Error {
    /// The request was refused before any send: no scope ids,
    /// an empty query, an empty message list, an empty memory
    /// id.  Nothing reached the transport.
    InvalidRequest(String),
    /// HTTP 429.  Estate rule: the caller stops; this client
    /// never retries on its own.  `retry_after_ms` is the
    /// server's `Retry-After` when it sent one.
    RateLimited { retry_after_ms: Option<u64> },
    /// Any other non-2xx HTTP status.  `body` is the server's
    /// response body, lossy-decoded and truncated — it is the
    /// server's text, shown because debugging without it is
    /// guesswork; it can never contain the key (the key travels
    /// in a header, and Mem0 does not echo it).
    Http { status: u16, body: String },
    /// No response exists: DNS, TLS, timeout, proxy refusal.
    /// Distinct from an empty result in the type itself — a
    /// failed search is an `Err`, never an empty `Vec`.
    Transport(TransportError),
    /// A 2xx response whose body was not the documented shape.
    Decode(String),
}

impl fmt::Display for Mem0Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mem0Error::InvalidRequest(m) => write!(f, "mem0-client: invalid request: {m}"),
            Mem0Error::RateLimited { retry_after_ms } => match retry_after_ms {
                Some(ms) => write!(f, "mem0-client: rate limited (429), retry after {ms} ms"),
                None => write!(f, "mem0-client: rate limited (429)"),
            },
            Mem0Error::Http { status, body } => {
                write!(f, "mem0-client: HTTP {status}: {body}")
            }
            Mem0Error::Transport(e) => write!(f, "mem0-client: transport failure: {e}"),
            Mem0Error::Decode(m) => write!(f, "mem0-client: undecodable response: {m}"),
        }
    }
}

impl std::error::Error for Mem0Error {}

impl From<TransportError> for Mem0Error {
    fn from(e: TransportError) -> Self {
        Mem0Error::Transport(e)
    }
}

// ---------------------------------------------------------------------
// Receipts — one per call, in the estate usage-log shape.
// ---------------------------------------------------------------------

/// One call's receipt: the `calls.jsonl` record.  Field names
/// and the success/error conventions follow the estate logs
/// (`status` is `"ok"` / `"error"`, `error` present only on
/// failures); `op`, `version`, and the id/count fields are this
/// contract's extensions.  Never the key; never memory content.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Mem0Receipt {
    pub call_id: String,
    pub tool: String,
    /// `"add"` / `"search"` / `"list"` / `"get"` / `"delete"`.
    pub op: String,
    /// The API shape family that served the call (`"v1"` /
    /// `"v3"`) — the version choice is on every receipt, never
    /// silent.
    pub version: String,
    /// The full request URL.  Safe to log: the key travels in a
    /// header, never in the URL.
    pub endpoint: String,
    pub status: String,
    pub http: Option<u16>,
    pub latency_ms: u64,
    pub ts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// The `add` event id (first event, when the server sent
    /// several the receipt names the first; the outcome carries
    /// them all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// The target of a `get` / `delete`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_id: Option<String>,
    /// Records returned by a `search` / `list` — a count, never
    /// content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Where receipts go.  Implementations are best-effort by design
/// (the estate CLIs' log appends swallow I/O errors rather than
/// failing the call they describe); a sink that needs durability
/// should say so in its own docs.
pub trait ReceiptSink: Send + Sync {
    fn record(&self, receipt: &Mem0Receipt);
}

/// Receipts go nowhere.
pub struct NoopSink;

impl ReceiptSink for NoopSink {
    fn record(&self, _receipt: &Mem0Receipt) {}
}

/// Receipts accumulate in memory — tests, and hosts that batch
/// their own persistence.
#[derive(Default)]
pub struct MemorySink {
    receipts: std::sync::Mutex<Vec<Mem0Receipt>>,
}

impl MemorySink {
    pub fn new() -> Self {
        MemorySink::default()
    }

    pub fn receipts(&self) -> Vec<Mem0Receipt> {
        self.receipts.lock().unwrap().clone()
    }
}

impl ReceiptSink for MemorySink {
    fn record(&self, receipt: &Mem0Receipt) {
        self.receipts.lock().unwrap().push(receipt.clone());
    }
}

/// Receipts append as JSON lines to a file — the estate
/// usage-log sink.  Append failures are counted, not hidden and
/// not fatal: [`JsonlFileSink::dropped`] reports how many
/// receipts never landed.
#[cfg(not(target_arch = "wasm32"))]
pub struct JsonlFileSink {
    path: std::path::PathBuf,
    dropped: AtomicU64,
}

#[cfg(not(target_arch = "wasm32"))]
impl JsonlFileSink {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        JsonlFileSink {
            path: path.into(),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ReceiptSink for JsonlFileSink {
    fn record(&self, receipt: &Mem0Receipt) {
        use std::io::Write as _;
        let line = match serde_json::to_string(receipt) {
            Ok(l) => l,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                return;
            }
        };
        let appended = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if appended.is_err() {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
}

// ---------------------------------------------------------------------
// The async transport seam (org-035's pattern).  org-026's
// `HttpsTransport` is synchronous; on wasm32 a send is a host
// `fetch`, which is a promise — the blocking face of org-026
// reports itself `Unsupported` there.  This trait is the same
// request/response contract with the send as a future.  The
// client's policy — request shapes, status mapping, receipts —
// is shared verbatim between the two drivers; only the send
// itself differs.
// ---------------------------------------------------------------------

/// The future an async send returns.  On native targets it is
/// `Send` (the ureq-backed future is).  On wasm32 it cannot be:
/// the host fetch future (`JsFuture`) is built on
/// `Rc<RefCell<..>>`, and the host itself is single-threaded —
/// so the bound is stated per-target rather than faked with an
/// unsafe assertion.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub type TransportFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub type TransportFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + 'a>>;

/// An HTTPS transport whose send is a future.  Implementations
/// must honour the org-026 contract exactly: any HTTP status is
/// an `Ok` response; `Err` means no response exists.
pub trait AsyncHttpsTransport: Send + Sync {
    fn send_async<'a>(
        &'a self,
        req: &'a HttpsRequest,
    ) -> TransportFuture<'a, Result<HttpsResponse, TransportError>>;
}

/// The bridge: org-026's `HostTransport` over its async host
/// send.  Natively this delegates to the same ureq client the
/// blocking send uses; on wasm32 it is the host `fetch` — the
/// only send a Worker can perform.
impl AsyncHttpsTransport for ref_https_transport::HostTransport {
    fn send_async<'a>(
        &'a self,
        req: &'a HttpsRequest,
    ) -> TransportFuture<'a, Result<HttpsResponse, TransportError>> {
        Box::pin(ref_https_transport::send_async(req))
    }
}

/// Adapter: a synchronous transport serving the async seam by
/// answering from its blocking send.  For native embedders and
/// test doubles whose send never actually waits; on wasm32 a
/// blocking send is `Unsupported`, so this adapter is honest
/// there too — it surfaces the same error the sync path would.
pub struct AsyncFromSync<T: HttpsTransport> {
    pub inner: T,
}

impl<T: HttpsTransport> AsyncFromSync<T> {
    pub fn new(inner: T) -> Self {
        AsyncFromSync { inner }
    }
}

impl<T: HttpsTransport + Send + Sync> AsyncHttpsTransport for AsyncFromSync<T> {
    fn send_async<'a>(
        &'a self,
        req: &'a HttpsRequest,
    ) -> TransportFuture<'a, Result<HttpsResponse, TransportError>> {
        Box::pin(async move { self.inner.send(req) })
    }
}

// ---------------------------------------------------------------------
// Wire shapes.  The builders below are the ONLY place request
// bytes are formed, and the parsers the only place response
// bytes are read — the sync and async drivers share both.
// ---------------------------------------------------------------------

/// Percent-encode one URL component (query value or path
/// segment): unreserved bytes pass, everything else is `%XX`.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// What a call needs for its receipt before the send: the op
/// name, the scope it ran under, and the get/delete target.
struct CallMeta {
    op: &'static str,
    scope: Scope,
    memory_id: Option<String>,
}

/// The parsed-outcome facts a receipt records: the first event
/// id (add) or the record count (search/list).
#[derive(Default)]
struct OutcomeFacts {
    event_id: Option<String>,
    result_count: Option<usize>,
}

fn messages_json(messages: &[Message]) -> Value {
    Value::Array(
        messages
            .iter()
            .map(|m| json!({"role": m.role, "content": m.content}))
            .collect(),
    )
}

/// Truncate a server error body for the `Http` error: enough to
/// debug with, never a full page of HTML.
fn body_excerpt(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut out: String = text.chars().take(512).collect();
    if text.chars().count() > 512 {
        out.push_str("…");
    }
    out
}

fn parse_retry_after(resp: &HttpsResponse) -> Option<u64> {
    let raw = resp.header("retry-after")?.trim();
    // Seconds form (the delta-seconds grammar); the HTTP-date
    // form is not converted — reported as absent, not guessed.
    raw.parse::<u64>().ok().map(|s| s.saturating_mul(1000))
}

fn parse_memory_record(v: &Value) -> Result<MemoryRecord, Mem0Error> {
    serde_json::from_value(v.clone()).map_err(|e| {
        Mem0Error::Decode(format!("memory record does not match the documented shape: {e}"))
    })
}

/// Parse a list-shaped response body: the paginated envelope
/// (`{"count":…,"next":…,"previous":…,"results":[…]}`) or a
/// bare array of records.  Both are real server shapes (the
/// envelope is the documented current one; tonight's v1 probe
/// returned the bare array), so both parse — anything else is a
/// decode error.
fn parse_record_list(body: &[u8]) -> Result<ListOutcome, Mem0Error> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| Mem0Error::Decode(format!("response is not JSON: {e}")))?;
    match &value {
        Value::Array(items) => {
            let memories = items
                .iter()
                .map(parse_memory_record)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ListOutcome {
                memories,
                count: None,
                next: None,
                previous: None,
            })
        }
        Value::Object(map) => {
            let results = map.get("results").ok_or_else(|| {
                Mem0Error::Decode("list envelope has no \"results\" array".to_string())
            })?;
            let items = results.as_array().ok_or_else(|| {
                Mem0Error::Decode("list envelope \"results\" is not an array".to_string())
            })?;
            let memories = items
                .iter()
                .map(parse_memory_record)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ListOutcome {
                memories,
                count: map.get("count").and_then(|c| c.as_u64()),
                next: map
                    .get("next")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string()),
                previous: map
                    .get("previous")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string()),
            })
        }
        _ => Err(Mem0Error::Decode(
            "list response is neither an array nor an envelope object".to_string(),
        )),
    }
}

/// Parse an `add` response: an array of event records (the
/// proven v1 shape) or a single event object (the documented
/// v3 shape — "the response is an event ID and a PENDING
/// status", manual §3.8.1).
fn parse_add_events(body: &[u8]) -> Result<Vec<AddEvent>, Mem0Error> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| Mem0Error::Decode(format!("add response is not JSON: {e}")))?;
    let items: Vec<Value> = match &value {
        Value::Array(items) => items.clone(),
        Value::Object(_) => vec![value.clone()],
        _ => {
            return Err(Mem0Error::Decode(
                "add response is neither an event array nor an event object".to_string(),
            ))
        }
    };
    items
        .iter()
        .map(|v| {
            serde_json::from_value(v.clone()).map_err(|e| {
                Mem0Error::Decode(format!("add event does not match the documented shape: {e}"))
            })
        })
        .collect()
}

// ---------------------------------------------------------------------
// The client.
// ---------------------------------------------------------------------

/// A Mem0 client: config + key + transport + receipt sink.
/// Generic over the transport so tests drive it with stubs and
/// hosts drive it with org-026's `HostTransport` (or any
/// [`AsyncHttpsTransport`] through the async driver).
pub struct Mem0Client<T, S: ReceiptSink> {
    config: Mem0Config,
    key: Mem0ApiKey,
    transport: T,
    sink: S,
    seq: AtomicU64,
}

impl<T, S: ReceiptSink> Mem0Client<T, S> {
    pub fn new(config: Mem0Config, key: Mem0ApiKey, transport: T, sink: S) -> Self {
        Mem0Client {
            config,
            key,
            transport,
            sink,
            seq: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &Mem0Config {
        &self.config
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    // -- request builders (shared by both drivers) ---------------

    fn build_http(&self, method: Method, url: String, body: Option<Value>) -> HttpsRequest {
        let mut req = HttpsRequest::new(method, url)
            .header("Authorization", format!("Token {}", self.key.expose()))
            .timeout_ms(self.config.timeout_ms)
            .max_bytes(self.config.max_response_bytes);
        if let Some(body) = body {
            req = req
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(&body).unwrap_or_default());
        }
        req
    }

    fn build_add(&self, req: &AddRequest) -> Result<(HttpsRequest, CallMeta), Mem0Error> {
        if req.messages.is_empty() {
            return Err(Mem0Error::InvalidRequest(
                "add requires at least one message".to_string(),
            ));
        }
        req.scope.require_non_empty("add")?;
        let mut body = Map::new();
        body.insert("messages".to_string(), messages_json(&req.messages));
        // Scope ids ride top-level on add under both versions:
        // the filters nesting is documented for search and list
        // (manual §4.8), and the proven v1 driver sent them
        // top-level.
        for (k, v) in req.scope.as_json() {
            body.insert(k, v);
        }
        if let Some(metadata) = &req.metadata {
            body.insert("metadata".to_string(), metadata.clone());
        }
        let url = match self.config.version {
            ApiVersion::V1 => format!("{}/v1/memories/", self.config.base_trimmed()),
            ApiVersion::V3 => format!("{}/v3/memories/add/", self.config.base_trimmed()),
        };
        Ok((
            self.build_http(Method::Post, url, Some(Value::Object(body))),
            CallMeta {
                op: "add",
                scope: req.scope.clone(),
                memory_id: None,
            },
        ))
    }

    fn build_search(&self, req: &SearchRequest) -> Result<(HttpsRequest, CallMeta), Mem0Error> {
        if req.query.trim().is_empty() {
            return Err(Mem0Error::InvalidRequest(
                "search requires a non-empty query".to_string(),
            ));
        }
        req.scope.require_non_empty("search")?;
        let mut body = Map::new();
        body.insert("query".to_string(), json!(req.query));
        match self.config.version {
            ApiVersion::V1 => {
                for (k, v) in req.scope.as_json() {
                    body.insert(k, v);
                }
            }
            ApiVersion::V3 => {
                // v3: entity IDs nest inside `filters`
                // (manual §3.8.1, §4.8).
                body.insert("filters".to_string(), Value::Object(req.scope.as_json()));
            }
        }
        if let Some(threshold) = req.threshold {
            body.insert("threshold".to_string(), json!(threshold));
        }
        let url = match self.config.version {
            ApiVersion::V1 => format!("{}/v1/memories/search/", self.config.base_trimmed()),
            ApiVersion::V3 => format!("{}/v3/memories/search/", self.config.base_trimmed()),
        };
        Ok((
            self.build_http(Method::Post, url, Some(Value::Object(body))),
            CallMeta {
                op: "search",
                scope: req.scope.clone(),
                memory_id: None,
            },
        ))
    }

    fn build_list(&self, req: &ListRequest) -> Result<(HttpsRequest, CallMeta), Mem0Error> {
        req.scope.require_non_empty("list")?;
        let (http_req, meta) = match self.config.version {
            ApiVersion::V1 => {
                // GET with query parameters — the exact shape
                // tonight's probe proved (`?user_id=zack`).
                let mut params: Vec<String> = Vec::new();
                if let Some(u) = &req.scope.user_id {
                    params.push(format!("user_id={}", url_encode(u)));
                }
                if let Some(a) = &req.scope.agent_id {
                    params.push(format!("agent_id={}", url_encode(a)));
                }
                if let Some(r) = &req.scope.run_id {
                    params.push(format!("run_id={}", url_encode(r)));
                }
                if let Some(p) = req.page {
                    params.push(format!("page={p}"));
                }
                if let Some(ps) = req.page_size {
                    params.push(format!("page_size={ps}"));
                }
                let url = format!(
                    "{}/v1/memories/?{}",
                    self.config.base_trimmed(),
                    params.join("&")
                );
                (
                    self.build_http(Method::Get, url, None),
                    CallMeta {
                        op: "list",
                        scope: req.scope.clone(),
                        memory_id: None,
                    },
                )
            }
            ApiVersion::V3 => {
                // POST with filters + pagination (manual §3.8.2).
                let mut body = Map::new();
                body.insert("filters".to_string(), Value::Object(req.scope.as_json()));
                if let Some(p) = req.page {
                    body.insert("page".to_string(), json!(p));
                }
                if let Some(ps) = req.page_size {
                    body.insert("page_size".to_string(), json!(ps));
                }
                let url = format!("{}/v3/memories/", self.config.base_trimmed());
                (
                    self.build_http(Method::Post, url, Some(Value::Object(body))),
                    CallMeta {
                        op: "list",
                        scope: req.scope.clone(),
                        memory_id: None,
                    },
                )
            }
        };
        Ok((http_req, meta))
    }

    fn build_get(&self, memory_id: &str) -> Result<(HttpsRequest, CallMeta), Mem0Error> {
        if memory_id.trim().is_empty() {
            return Err(Mem0Error::InvalidRequest(
                "get requires a memory id".to_string(),
            ));
        }
        // Get is a v1 management path under both versions
        // (manual §3.8.2).
        let url = format!(
            "{}/v1/memories/{}/",
            self.config.base_trimmed(),
            url_encode(memory_id)
        );
        Ok((
            self.build_http(Method::Get, url, None),
            CallMeta {
                op: "get",
                scope: Scope::new(),
                memory_id: Some(memory_id.to_string()),
            },
        ))
    }

    fn build_delete(&self, memory_id: &str) -> Result<(HttpsRequest, CallMeta), Mem0Error> {
        if memory_id.trim().is_empty() {
            return Err(Mem0Error::InvalidRequest(
                "delete requires a memory id".to_string(),
            ));
        }
        // Delete is a v1 management path under both versions
        // (manual §3.8.2).
        let url = format!(
            "{}/v1/memories/{}/",
            self.config.base_trimmed(),
            url_encode(memory_id)
        );
        Ok((
            self.build_http(Method::Delete, url, None),
            CallMeta {
                op: "delete",
                scope: Scope::new(),
                memory_id: Some(memory_id.to_string()),
            },
        ))
    }

    // -- the shared finish: status mapping + parse + receipt ----

    fn finish<Out>(
        &self,
        meta: &CallMeta,
        endpoint: &str,
        started: Mark,
        result: Result<HttpsResponse, TransportError>,
        parse: impl FnOnce(&HttpsResponse) -> Result<(Out, OutcomeFacts), Mem0Error>,
    ) -> Result<Out, Mem0Error> {
        let now = now_unix_ms();
        let latency_ms = started.elapsed_ms();
        let mut receipt = Mem0Receipt {
            call_id: String::new(), // filled below, needs seq + now
            tool: "ref-mem0-client".to_string(),
            op: meta.op.to_string(),
            version: self.config.version.as_str().to_string(),
            endpoint: endpoint.to_string(),
            status: "error".to_string(),
            http: None,
            latency_ms,
            ts: iso_ts(now),
            user_id: meta.scope.user_id.clone(),
            agent_id: meta.scope.agent_id.clone(),
            run_id: meta.scope.run_id.clone(),
            event_id: None,
            memory_id: meta.memory_id.clone(),
            result_count: None,
            error: None,
        };
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let digest = Sha256::digest(format!("{seq}|{now}|{}|{endpoint}", meta.op).as_bytes());
        receipt.call_id = format!(
            "m0-{}-{:06}-{}",
            compact_ts(now),
            seq,
            &hex::encode(digest)[..6]
        );

        let outcome = (|| -> Result<Out, Mem0Error> {
            let resp = result.map_err(Mem0Error::from)?;
            receipt.http = Some(resp.status);
            if resp.status == 429 {
                return Err(Mem0Error::RateLimited {
                    retry_after_ms: parse_retry_after(&resp),
                });
            }
            if !(200..300).contains(&resp.status) {
                return Err(Mem0Error::Http {
                    status: resp.status,
                    body: body_excerpt(&resp.body),
                });
            }
            let (out, facts) = parse(&resp)?;
            receipt.event_id = facts.event_id;
            receipt.result_count = facts.result_count;
            Ok(out)
        })();

        match &outcome {
            Ok(_) => receipt.status = "ok".to_string(),
            Err(e) => receipt.error = Some(e.to_string()),
        }
        self.sink.record(&receipt);
        outcome
    }
}

/// The synchronous driver: org-026's blocking transport seam.
impl<T: HttpsTransport, S: ReceiptSink> Mem0Client<T, S> {
    pub fn add(&self, req: &AddRequest) -> Result<AddOutcome, Mem0Error> {
        let (http_req, meta) = self.build_add(req)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send(&http_req);
        self.finish(&meta, &endpoint, started, result, |resp| {
            let events = parse_add_events(&resp.body)?;
            let facts = OutcomeFacts {
                event_id: events.first().and_then(|e| e.event_id.clone()),
                result_count: None,
            };
            Ok((AddOutcome { events }, facts))
        })
    }

    pub fn search(&self, req: &SearchRequest) -> Result<Vec<MemoryRecord>, Mem0Error> {
        let (http_req, meta) = self.build_search(req)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send(&http_req);
        self.finish(&meta, &endpoint, started, result, |resp| {
            let list = parse_record_list(&resp.body)?;
            let facts = OutcomeFacts {
                event_id: None,
                result_count: Some(list.memories.len()),
            };
            Ok((list.memories, facts))
        })
    }

    pub fn list(&self, req: &ListRequest) -> Result<ListOutcome, Mem0Error> {
        let (http_req, meta) = self.build_list(req)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send(&http_req);
        self.finish(&meta, &endpoint, started, result, |resp| {
            let list = parse_record_list(&resp.body)?;
            let facts = OutcomeFacts {
                event_id: None,
                result_count: Some(list.memories.len()),
            };
            Ok((list, facts))
        })
    }

    pub fn get(&self, memory_id: &str) -> Result<MemoryRecord, Mem0Error> {
        let (http_req, meta) = self.build_get(memory_id)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send(&http_req);
        self.finish(&meta, &endpoint, started, result, |resp| {
            let value: Value = serde_json::from_slice(&resp.body)
                .map_err(|e| Mem0Error::Decode(format!("get response is not JSON: {e}")))?;
            let record = parse_memory_record(&value)?;
            Ok((record, OutcomeFacts::default()))
        })
    }

    pub fn delete(&self, memory_id: &str) -> Result<DeleteOutcome, Mem0Error> {
        let (http_req, meta) = self.build_delete(memory_id)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send(&http_req);
        self.finish(&meta, &endpoint, started, result, |resp| {
            let message = if resp.body.is_empty() {
                None
            } else {
                serde_json::from_slice::<Value>(&resp.body)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
            };
            Ok((DeleteOutcome { message }, OutcomeFacts::default()))
        })
    }
}

/// The asynchronous driver: the same builders, the same finish —
/// only the send awaits.  This is the driver a Worker (or any
/// host whose only send is a promise) uses.
impl<T: AsyncHttpsTransport, S: ReceiptSink> Mem0Client<T, S> {
    pub async fn add_async(&self, req: &AddRequest) -> Result<AddOutcome, Mem0Error> {
        let (http_req, meta) = self.build_add(req)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send_async(&http_req).await;
        self.finish(&meta, &endpoint, started, result, |resp| {
            let events = parse_add_events(&resp.body)?;
            let facts = OutcomeFacts {
                event_id: events.first().and_then(|e| e.event_id.clone()),
                result_count: None,
            };
            Ok((AddOutcome { events }, facts))
        })
    }

    pub async fn search_async(&self, req: &SearchRequest) -> Result<Vec<MemoryRecord>, Mem0Error> {
        let (http_req, meta) = self.build_search(req)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send_async(&http_req).await;
        self.finish(&meta, &endpoint, started, result, |resp| {
            let list = parse_record_list(&resp.body)?;
            let facts = OutcomeFacts {
                event_id: None,
                result_count: Some(list.memories.len()),
            };
            Ok((list.memories, facts))
        })
    }

    pub async fn list_async(&self, req: &ListRequest) -> Result<ListOutcome, Mem0Error> {
        let (http_req, meta) = self.build_list(req)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send_async(&http_req).await;
        self.finish(&meta, &endpoint, started, result, |resp| {
            let list = parse_record_list(&resp.body)?;
            let facts = OutcomeFacts {
                event_id: None,
                result_count: Some(list.memories.len()),
            };
            Ok((list, facts))
        })
    }

    pub async fn get_async(&self, memory_id: &str) -> Result<MemoryRecord, Mem0Error> {
        let (http_req, meta) = self.build_get(memory_id)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send_async(&http_req).await;
        self.finish(&meta, &endpoint, started, result, |resp| {
            let value: Value = serde_json::from_slice(&resp.body)
                .map_err(|e| Mem0Error::Decode(format!("get response is not JSON: {e}")))?;
            let record = parse_memory_record(&value)?;
            Ok((record, OutcomeFacts::default()))
        })
    }

    pub async fn delete_async(&self, memory_id: &str) -> Result<DeleteOutcome, Mem0Error> {
        let (http_req, meta) = self.build_delete(memory_id)?;
        let endpoint = http_req.url.clone();
        let started = mark_now();
        let result = self.transport.send_async(&http_req).await;
        self.finish(&meta, &endpoint, started, result, |resp| {
            let message = if resp.body.is_empty() {
                None
            } else {
                serde_json::from_slice::<Value>(&resp.body)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
            };
            Ok((DeleteOutcome { message }, OutcomeFacts::default()))
        })
    }
}

/// The platform-default constructor: org-026's `HostTransport`.
/// Sync calls ride the blocking send (native); the async driver
/// rides the host `fetch` bridge — the only send a Worker has.
impl<S: ReceiptSink> Mem0Client<ref_https_transport::HostTransport, S> {
    pub fn host(config: Mem0Config, key: Mem0ApiKey, sink: S) -> Self {
        Mem0Client::new(config, key, ref_https_transport::HostTransport, sink)
    }
}

// ---------------------------------------------------------------------
// Organelle surface (feature `organelle`).  ExternalEffect: add
// and delete mutate state on Mem0's servers.  The surface drives
// the synchronous client; hosts on async-only transports use the
// library API directly.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let scope_props = json!({
        "user_id": {"type": "string", "minLength": 1},
        "agent_id": {"type": "string", "minLength": 1},
        "run_id": {"type": "string", "minLength": 1}
    });
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "mem0-client".to_string(),
        codon: "m0".to_string(),
        version: "1.0.0".to_string(),
        description: "Mem0 hosted-platform client: add (async event receipt), search, list, get, delete over org-026 transport; API version is caller config (v1 live-proven 2026-11-23, v3 doc-derived); key is header-only and never logged".to_string(),
        contracts: vec![
            Contract {
                op: "add".to_string(),
                description: "submit messages for server-side extraction; returns event receipts (PENDING + event_id), NOT stored memories — extraction is asynchronous".to_string(),
                input_schema: json!({
                    "type": "object",
                    "required": ["messages"],
                    "properties": {
                        "messages": {
                            "type": "array", "minItems": 1,
                            "items": {
                                "type": "object", "required": ["role", "content"],
                                "properties": {
                                    "role": {"type": "string", "minLength": 1},
                                    "content": {"type": "string"}
                                }
                            }
                        },
                        "user_id": scope_props["user_id"],
                        "agent_id": scope_props["agent_id"],
                        "run_id": scope_props["run_id"],
                        "metadata": {"type": "object"}
                    }
                }),
                mutation_class: Some(MutationClass::ExternalEffect),
                required_capability: None,
            },
            Contract {
                op: "search".to_string(),
                description: "search memories in a scope; returns records (id, memory, score, metadata) — a transport failure is an error, never an empty list".to_string(),
                input_schema: json!({
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": {"type": "string", "minLength": 1},
                        "user_id": scope_props["user_id"],
                        "agent_id": scope_props["agent_id"],
                        "run_id": scope_props["run_id"],
                        "threshold": {"type": "number"}
                    }
                }),
                mutation_class: Some(MutationClass::ReadOnly),
                required_capability: None,
            },
            Contract {
                op: "list".to_string(),
                description: "list memories in a scope; returns records plus envelope count/cursors when the server sends them".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "user_id": scope_props["user_id"],
                        "agent_id": scope_props["agent_id"],
                        "run_id": scope_props["run_id"],
                        "page": {"type": "integer", "minimum": 1},
                        "page_size": {"type": "integer", "minimum": 1}
                    }
                }),
                mutation_class: Some(MutationClass::ReadOnly),
                required_capability: None,
            },
            Contract {
                op: "get".to_string(),
                description: "fetch one memory by id (v1 management path under both API versions)".to_string(),
                input_schema: json!({
                    "type": "object",
                    "required": ["memory_id"],
                    "properties": {"memory_id": {"type": "string", "minLength": 1}}
                }),
                mutation_class: Some(MutationClass::ReadOnly),
                required_capability: None,
            },
            Contract {
                op: "delete".to_string(),
                description: "delete one memory by id (v1 management path under both API versions)".to_string(),
                input_schema: json!({
                    "type": "object",
                    "required": ["memory_id"],
                    "properties": {"memory_id": {"type": "string", "minLength": 1}}
                }),
                mutation_class: Some(MutationClass::ExternalEffect),
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ExternalEffect,
            declared_valence: Valence::Proven,
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
pub struct Mem0ClientOrganelle<T, S>
where
    T: HttpsTransport + Send + Sync,
    S: ReceiptSink,
{
    manifest: OrganelleManifest,
    client: Arc<Mem0Client<T, S>>,
}

#[cfg(feature = "organelle")]
pub fn organelle_with_client<T, S>(client: Arc<Mem0Client<T, S>>) -> Arc<dyn Organelle>
where
    T: HttpsTransport + Send + Sync + 'static,
    S: ReceiptSink + 'static,
{
    Arc::new(Mem0ClientOrganelle {
        manifest: manifest(),
        client,
    })
}

/// The fail-closed default surface: no client configured.
/// Every op errors with the configuration message and nothing
/// is sent anywhere — a Mem0 key is never invented, defaulted,
/// or read from the environment by this crate.
#[cfg(feature = "organelle")]
pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(UnconfiguredMem0 {
        manifest: manifest(),
    })
}

#[cfg(feature = "organelle")]
struct UnconfiguredMem0 {
    manifest: OrganelleManifest,
}

#[cfg(feature = "organelle")]
impl Organelle for UnconfiguredMem0 {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        _input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "add" | "search" | "list" | "get" | "delete" => Err(OrganelleError::failed(
                "ref-mem0-client: not configured — construct with organelle_with_client \
                 (config + key are caller-supplied; none are defaulted)",
            )),
            other => Err(OrganelleError::not_found(format!("unknown op {other}"))),
        }
    }
}

#[cfg(feature = "organelle")]
fn scope_from(input: &Value) -> Scope {
    let mut scope = Scope::new();
    if let Some(u) = input["user_id"].as_str() {
        scope.user_id = Some(u.to_string());
    }
    if let Some(a) = input["agent_id"].as_str() {
        scope.agent_id = Some(a.to_string());
    }
    if let Some(r) = input["run_id"].as_str() {
        scope.run_id = Some(r.to_string());
    }
    scope
}

#[cfg(feature = "organelle")]
fn failed(e: Mem0Error) -> OrganelleError {
    OrganelleError::failed(e.to_string())
}

#[cfg(feature = "organelle")]
impl<T, S> Organelle for Mem0ClientOrganelle<T, S>
where
    T: HttpsTransport + Send + Sync,
    S: ReceiptSink,
{
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        // Egress: the configured endpoint must pass the host's
        // allowlist before any send (the org-023 / org-026
        // policy seam).
        host.approve_egress(&self.client.config().base_url)?;
        match op {
            "add" => {
                let messages: Vec<Message> = input["messages"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .map(|m| Message {
                                role: m["role"].as_str().unwrap_or("").to_string(),
                                content: m["content"].as_str().unwrap_or("").to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut req = AddRequest::new(messages, scope_from(&input));
                if !input["metadata"].is_null() {
                    req = req.metadata(input["metadata"].clone());
                }
                let out = self.client.add(&req).map_err(failed)?;
                Ok(json!({
                    "events": serde_json::to_value(&out.events).unwrap_or(Value::Null),
                    "all_pending": out.all_pending(),
                    "stub": false,
                }))
            }
            "search" => {
                let query = input["query"].as_str().unwrap_or("");
                let mut req = SearchRequest::new(query, scope_from(&input));
                if let Some(t) = input["threshold"].as_f64() {
                    req = req.threshold(t);
                }
                let records = self.client.search(&req).map_err(failed)?;
                Ok(json!({
                    "results": serde_json::to_value(&records).unwrap_or(Value::Null),
                    "count": records.len(),
                    "stub": false,
                }))
            }
            "list" => {
                let mut req = ListRequest::new(scope_from(&input));
                if let Some(p) = input["page"].as_u64() {
                    req = req.page(p as u32);
                }
                if let Some(ps) = input["page_size"].as_u64() {
                    req = req.page_size(ps as u32);
                }
                let out = self.client.list(&req).map_err(failed)?;
                Ok(json!({
                    "memories": serde_json::to_value(&out.memories).unwrap_or(Value::Null),
                    "count": out.count,
                    "next": out.next,
                    "previous": out.previous,
                    "stub": false,
                }))
            }
            "get" => {
                let id = input["memory_id"].as_str().unwrap_or("");
                let record = self.client.get(id).map_err(failed)?;
                Ok(serde_json::to_value(&record).unwrap_or(Value::Null))
            }
            "delete" => {
                let id = input["memory_id"].as_str().unwrap_or("");
                let out = self.client.delete(id).map_err(failed)?;
                Ok(json!({"deleted": true, "message": out.message, "stub": false}))
            }
            other => Err(OrganelleError::not_found(format!("unknown op {other}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  Stub transports only — deterministic and offline.  The
// canned responses are the shapes the live API returned (v1) or
// the manual documents (v3) on 2026-11-23.  The live proof is a
// separate env-gated integration test (tests/live_mem0.rs).
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The loud fixture key (org-028's discipline): if it ever
    /// shows up in an output, the grep test cannot miss it.
    const LOUD_KEY: &str = "m0-LOUD-FIXTURE-KEY-7f3a9c-DO-NOT-SHIP";

    const ADD_V1_RESPONSE: &str = r#"[{"message":"Memory processing has been queued for background execution","status":"PENDING","event_id":"11111111-2222-3333-4444-555555555555"}]"#;
    const RECORD_JSON: &str = r#"{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","memory":"Zack prefers terse replies with receipts.","user_id":"zack","metadata":{"source":"MEMORY.md"},"categories":["preferences"],"created_at":"2026-11-23T09:00:00Z","updated_at":"2026-11-23T09:00:00Z"}"#;

    /// A transport that records every request and answers from
    /// a script of canned responses (or one transport error).
    struct StubTransport {
        sent: Mutex<Vec<HttpsRequest>>,
        script: Mutex<Vec<Result<HttpsResponse, TransportError>>>,
    }

    impl StubTransport {
        fn new(script: Vec<Result<HttpsResponse, TransportError>>) -> Self {
            StubTransport {
                sent: Mutex::new(Vec::new()),
                script: Mutex::new(script),
            }
        }

        fn respond(status: u16, body: &str) -> Self {
            Self::new(vec![Ok(HttpsResponse {
                status,
                headers: vec![],
                body: body.as_bytes().to_vec(),
                truncated: false,
            })])
        }

        fn sent(&self) -> Vec<HttpsRequest> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl HttpsTransport for StubTransport {
        fn send(&self, req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
            self.sent.lock().unwrap().push(req.clone());
            let mut script = self.script.lock().unwrap();
            if script.is_empty() {
                return Ok(HttpsResponse {
                    status: 200,
                    headers: vec![],
                    body: b"null".to_vec(),
                    truncated: false,
                });
            }
            script.remove(0)
        }
    }

    /// The same stub serving the async seam.
    struct StubAsyncTransport(StubTransport);

    impl AsyncHttpsTransport for StubAsyncTransport {
        fn send_async<'a>(
            &'a self,
            req: &'a HttpsRequest,
        ) -> TransportFuture<'a, Result<HttpsResponse, TransportError>> {
            Box::pin(async move { self.0.send(req) })
        }
    }

    /// A park/unpark block_on (the org-031/org-035 test pattern),
    /// so the async drivers are testable with no executor dep.
    fn block_on<F: Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Wake};
        struct ThreadWaker(std::thread::Thread);
        impl Wake for ThreadWaker {
            fn wake(self: Arc<Self>) {
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

    fn v1_config() -> Mem0Config {
        Mem0Config::new("https://api.mem0.ai", ApiVersion::V1, 120_000, 1_048_576)
    }

    fn v3_config() -> Mem0Config {
        Mem0Config::new("https://api.mem0.ai", ApiVersion::V3, 120_000, 1_048_576)
    }

    fn client_with(
        config: Mem0Config,
        transport: StubTransport,
    ) -> Mem0Client<StubTransport, MemorySink> {
        Mem0Client::new(config, Mem0ApiKey::new(LOUD_KEY), transport, MemorySink::new())
    }

    fn body_json(req: &HttpsRequest) -> Value {
        serde_json::from_slice(req.body.as_deref().unwrap_or(&[])).expect("request body is JSON")
    }

    /// Read a header off a built request (org-026's `header()`
    /// on `HttpsRequest` is the builder; the field is the read).
    fn req_header<'a>(req: &'a HttpsRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    // -- v1: the proven shapes -----------------------------------

    #[test]
    fn v1_add_request_matches_the_proven_driver_payload() {
        let client = client_with(v1_config(), StubTransport::respond(200, ADD_V1_RESPONSE));
        let req = AddRequest::new(
            vec![Message::user("Zack's phone number is 236-979-8735.")],
            Scope::user("zack"),
        )
        .metadata(json!({"source": "USER.md"}));
        let out = client.add(&req).unwrap();

        // The outcome is an event receipt, honestly PENDING.
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.events[0].status, "PENDING");
        assert_eq!(
            out.events[0].event_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert!(out.all_pending());

        // The request is the driver's proven call: same method,
        // same URL, same header placement, and a body that is
        // value-identical to what the Python driver sent.
        let sent = client.transport.sent();
        assert_eq!(sent.len(), 1);
        let wire = &sent[0];
        assert_eq!(wire.method, Method::Post);
        assert_eq!(wire.url, "https://api.mem0.ai/v1/memories/");
        assert_eq!(
            req_header(wire, "authorization"),
            Some(format!("Token {LOUD_KEY}").as_str())
        );
        let driver_payload = json!({
            "messages": [{"role": "user", "content": "Zack's phone number is 236-979-8735."}],
            "user_id": "zack",
            "metadata": {"source": "USER.md"}
        });
        assert_eq!(body_json(wire), driver_payload);
        // Byte-exact under serde_json's canonical key order.
        assert_eq!(
            String::from_utf8(wire.body.clone().unwrap()).unwrap(),
            r#"{"messages":[{"content":"Zack's phone number is 236-979-8735.","role":"user"}],"metadata":{"source":"USER.md"},"user_id":"zack"}"#
        );

        // One receipt, ok, naming the event — and nothing else.
        let receipts = client.sink().receipts();
        assert_eq!(receipts.len(), 1);
        let r = &receipts[0];
        assert_eq!(r.op, "add");
        assert_eq!(r.version, "v1");
        assert_eq!(r.status, "ok");
        assert_eq!(r.http, Some(200));
        assert_eq!(
            r.event_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(r.user_id.as_deref(), Some("zack"));
        assert_eq!(r.tool, "ref-mem0-client");
        assert!(r.call_id.starts_with("m0-"));
    }

    #[test]
    fn v1_list_get_uses_the_proven_probe_url_and_parses_bare_array() {
        let body = format!("[{RECORD_JSON}]");
        let client = client_with(v1_config(), StubTransport::respond(200, &body));
        let out = client.list(&ListRequest::new(Scope::user("zack"))).unwrap();
        let sent = client.transport.sent();
        assert_eq!(sent[0].method, Method::Get);
        assert_eq!(sent[0].url, "https://api.mem0.ai/v1/memories/?user_id=zack");
        assert_eq!(out.memories.len(), 1);
        assert_eq!(out.memories[0].id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert_eq!(out.memories[0].user_id.as_deref(), Some("zack"));
        // Bare array: no envelope facts exist, and none are faked.
        assert_eq!(out.count, None);
        assert_eq!(out.next, None);
    }

    #[test]
    fn v1_list_empty_array_is_an_empty_result_not_an_error() {
        let client = client_with(v1_config(), StubTransport::respond(200, "[]"));
        let out = client.list(&ListRequest::new(Scope::user("zack"))).unwrap();
        assert!(out.memories.is_empty());
        let receipts = client.sink().receipts();
        assert_eq!(receipts[0].status, "ok");
        assert_eq!(receipts[0].result_count, Some(0));
    }

    #[test]
    fn v1_search_sends_scope_top_level_and_parses_results() {
        let body = format!(
            r#"{{"results":[{{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","memory":"Zack prefers terse replies with receipts.","user_id":"zack","score":0.91}}]}}"#
        );
        let client = client_with(v1_config(), StubTransport::respond(200, &body));
        let records = client
            .search(&SearchRequest::new("preferences", Scope::user("zack")))
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].score, Some(0.91));
        let sent = client.transport.sent();
        assert_eq!(sent[0].url, "https://api.mem0.ai/v1/memories/search/");
        assert_eq!(
            body_json(&sent[0]),
            json!({"query": "preferences", "user_id": "zack"})
        );
        let receipts = client.sink().receipts();
        assert_eq!(receipts[0].result_count, Some(1));
    }

    #[test]
    fn get_and_delete_use_the_v1_management_path() {
        let client = client_with(
            v1_config(),
            StubTransport::new(vec![
                Ok(HttpsResponse {
                    status: 200,
                    headers: vec![],
                    body: RECORD_JSON.as_bytes().to_vec(),
                    truncated: false,
                }),
                Ok(HttpsResponse {
                    status: 200,
                    headers: vec![],
                    body: br#"{"message":"Memory deleted successfully!"}"#.to_vec(),
                    truncated: false,
                }),
            ]),
        );
        let record = client.get("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(record.memory, "Zack prefers terse replies with receipts.");
        let deleted = client.delete("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(deleted.message.as_deref(), Some("Memory deleted successfully!"));
        let sent = client.transport.sent();
        assert_eq!(sent[0].method, Method::Get);
        assert_eq!(
            sent[0].url,
            "https://api.mem0.ai/v1/memories/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/"
        );
        assert_eq!(sent[1].method, Method::Delete);
        assert_eq!(sent[1].url, sent[0].url);
        let receipts = client.sink().receipts();
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            receipts[1].memory_id.as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
    }

    // -- v3: the documented shapes (doc-derived, not live-proven)

    #[test]
    fn v3_add_uses_the_v3_path_and_parses_a_single_event_object() {
        let client = client_with(
            v3_config(),
            StubTransport::respond(
                200,
                r#"{"event_id":"99999999-8888-7777-6666-555555555555","status":"PENDING","message":"queued"}"#,
            ),
        );
        let out = client
            .add(&AddRequest::new(
                vec![Message::user("hello")],
                Scope::user("zack"),
            ))
            .unwrap();
        let sent = client.transport.sent();
        assert_eq!(sent[0].url, "https://api.mem0.ai/v3/memories/add/");
        assert_eq!(out.events.len(), 1);
        assert_eq!(
            out.events[0].event_id.as_deref(),
            Some("99999999-8888-7777-6666-555555555555")
        );
        let receipts = client.sink().receipts();
        assert_eq!(receipts[0].version, "v3");
    }

    #[test]
    fn v3_search_nests_entity_ids_in_filters() {
        let client = client_with(v3_config(), StubTransport::respond(200, r#"{"results":[]}"#));
        let records = client
            .search(
                &SearchRequest::new("preferences", Scope::user("zack").with_agent("lucidota"))
                    .threshold(0.5),
            )
            .unwrap();
        assert!(records.is_empty());
        let sent = client.transport.sent();
        assert_eq!(sent[0].url, "https://api.mem0.ai/v3/memories/search/");
        assert_eq!(
            body_json(&sent[0]),
            json!({
                "query": "preferences",
                "filters": {"user_id": "zack", "agent_id": "lucidota"},
                "threshold": 0.5
            })
        );
    }

    #[test]
    fn v3_list_posts_filters_and_parses_the_paginated_envelope() {
        let body = format!(
            r#"{{"count":1,"next":null,"previous":null,"results":[{RECORD_JSON}]}}"#
        );
        let client = client_with(v3_config(), StubTransport::respond(200, &body));
        let out = client
            .list(&ListRequest::new(Scope::user("zack")).page(2).page_size(50))
            .unwrap();
        let sent = client.transport.sent();
        assert_eq!(sent[0].method, Method::Post);
        assert_eq!(sent[0].url, "https://api.mem0.ai/v3/memories/");
        assert_eq!(
            body_json(&sent[0]),
            json!({"filters": {"user_id": "zack"}, "page": 2, "page_size": 50})
        );
        assert_eq!(out.memories.len(), 1);
        assert_eq!(out.count, Some(1));
        assert_eq!(out.next, None);
    }

    #[test]
    fn v3_get_and_delete_stay_on_the_v1_management_paths() {
        // The docs' own mixed versioning (manual §3.8.2): there
        // is no v3 get/delete path; the client must not invent
        // one.
        let client = client_with(
            v3_config(),
            StubTransport::new(vec![
                Ok(HttpsResponse {
                    status: 200,
                    headers: vec![],
                    body: RECORD_JSON.as_bytes().to_vec(),
                    truncated: false,
                }),
                Ok(HttpsResponse {
                    status: 200,
                    headers: vec![],
                    body: b"".to_vec(),
                    truncated: false,
                }),
            ]),
        );
        client.get("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let deleted = client.delete("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(deleted.message, None); // empty body, honestly None
        let sent = client.transport.sent();
        assert!(sent[0].url.starts_with("https://api.mem0.ai/v1/memories/"));
        assert!(sent[1].url.starts_with("https://api.mem0.ai/v1/memories/"));
    }

    // -- validation, errors, and the transport/empty distinction -

    #[test]
    fn scope_is_required_and_nothing_is_sent_without_one() {
        let client = client_with(v1_config(), StubTransport::respond(200, "[]"));
        let err = client
            .add(&AddRequest::new(vec![Message::user("x")], Scope::new()))
            .unwrap_err();
        assert!(matches!(err, Mem0Error::InvalidRequest(_)));
        let err = client.search(&SearchRequest::new("q", Scope::new())).unwrap_err();
        assert!(matches!(err, Mem0Error::InvalidRequest(_)));
        let err = client.list(&ListRequest::new(Scope::new())).unwrap_err();
        assert!(matches!(err, Mem0Error::InvalidRequest(_)));
        assert!(client.transport.sent().is_empty(), "nothing was sent");
        assert!(
            client.sink().receipts().is_empty(),
            "a call that never happened leaves no receipt"
        );
    }

    #[test]
    fn rate_limited_is_typed_and_carries_retry_after() {
        let client = client_with(
            v1_config(),
            StubTransport::new(vec![Ok(HttpsResponse {
                status: 429,
                headers: vec![("Retry-After".to_string(), "30".to_string())],
                body: br#"{"detail":"rate limited"}"#.to_vec(),
                truncated: false,
            })]),
        );
        let err = client
            .search(&SearchRequest::new("q", Scope::user("zack")))
            .unwrap_err();
        assert_eq!(
            err,
            Mem0Error::RateLimited {
                retry_after_ms: Some(30_000)
            }
        );
        let receipts = client.sink().receipts();
        assert_eq!(receipts[0].status, "error");
        assert_eq!(receipts[0].http, Some(429));
        assert!(receipts[0].error.as_deref().unwrap().contains("rate limited"));
    }

    #[test]
    fn http_error_is_typed_with_status_and_body() {
        let client = client_with(
            v1_config(),
            StubTransport::respond(401, r#"{"detail":"Invalid API key"}"#),
        );
        let err = client.list(&ListRequest::new(Scope::user("zack"))).unwrap_err();
        match err {
            Mem0Error::Http { status, body } => {
                assert_eq!(status, 401);
                assert!(body.contains("Invalid API key"));
            }
            other => panic!("expected Http error, got {other:?}"),
        }
    }

    #[test]
    fn transport_failure_is_an_error_never_an_empty_result() {
        let client = client_with(
            v1_config(),
            StubTransport::new(vec![Err(TransportError::Network("proxy refused".to_string()))]),
        );
        let err = client
            .search(&SearchRequest::new("q", Scope::user("zack")))
            .unwrap_err();
        assert!(matches!(err, Mem0Error::Transport(_)));
        let receipts = client.sink().receipts();
        assert_eq!(receipts[0].status, "error");
        assert_eq!(receipts[0].http, None);
        assert_eq!(receipts[0].result_count, None);
    }

    #[test]
    fn garbage_response_is_a_decode_error() {
        let client = client_with(v1_config(), StubTransport::respond(200, "not json at all"));
        let err = client.list(&ListRequest::new(Scope::user("zack"))).unwrap_err();
        assert!(matches!(err, Mem0Error::Decode(_)));
    }

    // -- the async driver -----------------------------------------

    #[test]
    fn async_add_sends_identical_bytes_and_parses_identically() {
        let transport = StubAsyncTransport(StubTransport::respond(200, ADD_V1_RESPONSE));
        let client = Mem0Client::new(
            v1_config(),
            Mem0ApiKey::new(LOUD_KEY),
            transport,
            MemorySink::new(),
        );
        let out = block_on(client.add_async(&AddRequest::new(
            vec![Message::user("Zack's phone number is 236-979-8735.")],
            Scope::user("zack"),
        )))
        .unwrap();
        assert!(out.all_pending());
        let sent = client.transport.0.sent();
        assert_eq!(sent[0].url, "https://api.mem0.ai/v1/memories/");
        assert_eq!(
            body_json(&sent[0]),
            json!({
                "messages": [{"role": "user", "content": "Zack's phone number is 236-979-8735."}],
                "user_id": "zack"
            })
        );
        assert_eq!(client.sink().receipts().len(), 1);
    }

    // -- the grep test: the key reaches the wire and nothing else

    #[test]
    fn grep_test_key_on_the_wire_and_nowhere_else() {
        let client = client_with(
            v1_config(),
            StubTransport::new(vec![
                Ok(HttpsResponse {
                    status: 200,
                    headers: vec![],
                    body: ADD_V1_RESPONSE.as_bytes().to_vec(),
                    truncated: false,
                }),
                Ok(HttpsResponse {
                    status: 200,
                    headers: vec![],
                    body: format!("{{\"results\":[{RECORD_JSON}]}}").into_bytes(),
                    truncated: false,
                }),
                Ok(HttpsResponse {
                    status: 429,
                    headers: vec![],
                    body: b"slow down".to_vec(),
                    truncated: false,
                }),
                Err(TransportError::Network("proxy refused".to_string())),
            ]),
        );
        // (a) Every op runs against the loud key.
        client
            .add(&AddRequest::new(vec![Message::user("hello")], Scope::user("zack")))
            .unwrap();
        let records = client
            .search(&SearchRequest::new("preferences", Scope::user("zack")))
            .unwrap();
        assert_eq!(records.len(), 1);
        let err429 = client
            .search(&SearchRequest::new("again", Scope::user("zack")))
            .unwrap_err();
        let err_transport = client.list(&ListRequest::new(Scope::user("zack"))).unwrap_err();

        // (b) The key DID reach the wire — in the header, on
        // every request.  Placement is proven, not assumed.
        let sent = client.transport.sent();
        assert_eq!(sent.len(), 4);
        for wire in &sent {
            assert_eq!(
                req_header(wire, "authorization"),
                Some(format!("Token {LOUD_KEY}").as_str()),
                "every request must carry the key in the Authorization header"
            );
            assert!(
                !wire.url.contains(LOUD_KEY),
                "the key must never ride in a URL"
            );
        }

        // (c) And it appears in NO output shape: not in any
        // receipt (serialized or Debug), not in either error's
        // Display or Debug, not in the key's own Debug, not in
        // the config's Debug.
        let receipts = client.sink().receipts();
        assert_eq!(receipts.len(), 4);
        for r in &receipts {
            let serialized = serde_json::to_string(r).unwrap();
            assert!(!serialized.contains(LOUD_KEY), "key leaked into a receipt: {serialized}");
            assert!(!format!("{r:?}").contains(LOUD_KEY));
        }
        for e in [&err429, &err_transport] {
            assert!(!e.to_string().contains(LOUD_KEY), "key leaked into an error: {e}");
            assert!(!format!("{e:?}").contains(LOUD_KEY));
        }
        assert_eq!(format!("{:?}", Mem0ApiKey::new(LOUD_KEY)), "Mem0ApiKey(<redacted>)");
        assert!(!format!("{:?}", v1_config()).contains(LOUD_KEY));

        // (d) Receipts carry ids and counts, never content: the
        // searched record's text appears in no receipt either.
        for r in &receipts {
            let serialized = serde_json::to_string(r).unwrap();
            assert!(
                !serialized.contains("Zack prefers terse replies"),
                "memory content leaked into a receipt: {serialized}"
            );
        }
    }

    // -- time ------------------------------------------------------

    #[test]
    fn iso_ts_is_exact() {
        // 2026-11-23T09:47:00Z — the import morning.
        assert_eq!(iso_ts(1_795_427_220_000), "2026-11-23T09:47:00Z");
        assert_eq!(iso_ts(0), "1970-01-01T00:00:00Z");
    }

    #[cfg(feature = "organelle")]
    #[test]
    fn unconfigured_surface_fails_closed_and_names_its_codon() {
        let org = organelle();
        assert_eq!(org.manifest().codon, "m0");
        assert_eq!(org.manifest().name, "mem0-client");
        // handle() needs a CallContext + HostRef; the fail-closed
        // property is structural (UnconfiguredMem0 holds no
        // client at all), so manifest + type inspection is the
        // assertion available without a host.  The configured
        // surface is exercised by hosts.
    }
}
