//! org-035 — Reference organelle: model-call-live (codon `ml`).
//!
//! The production OpenAI-compatible model call (GAP-10 in the
//! 2026-11-22 decomposition map).  `ref-model-call` (org-023) is
//! the contract and an honest stub; the estate's real
//! implementation is the ai-router's single JS file
//! (`free-stack/workers/ai-router.js`), un-decomposed, with FAC /
//! EXC / SKZ each wiring their own provider HTTP beside it.  This
//! crate is that implementation as an organelle: provider lanes
//! as caller-supplied data, exact-model binding, failover, and —
//! the contract this crate exists to keep — **substitution is
//! never silent**.
//!
//! ## The pin contract (2026-11-23, the NIM fix)
//!
//! A model string of the form `"<lane>/<model-id>"` is a PIN
//! (prefix aliases are caller data — the router's `nim → nvidia`
//! is one entry in [`RouterConfig::aliases`], not a constant of
//! this crate).  A pinned request is attempted **only** on that
//! lane with **only** that model: no strategy pick, no pool
//! rotation, no cross-lane failover.  If the pin cannot be served
//! — lane down, guard denial, credential failure, failover-class
//! HTTP status — the call fails with
//! [`ModelCallError::PinFailed`], which names the lane and the
//! model.  Before this contract existed, 34/34 dossier calls
//! requesting the 550B through the router were silently served by
//! smaller models because no code path read `body.model` for
//! routing; the diagnosis is written into `ai-router.js` above
//! `parseModelPin`, and this crate is its organelle form.
//!
//! Pinned or not, every response reports
//! [`ChatResponse::model_requested`] (what the caller wrote),
//! [`ChatResponse::model_sent`] (what the serving lane was
//! asked), and [`ChatResponse::model_served`] (the provider's own
//! `model` field in its response body), plus
//! [`ChatResponse::substituted`] — true exactly when a served
//! model is known and differs from the model the caller asked to
//! be served (the pin's model, or the raw requested string when
//! unpinned).  A provider that answers a pin with a different
//! model field therefore produces `substituted: true` on a
//! successful response — loud, in-band, and receipted — instead
//! of a silent swap.
//!
//! ## Receipts
//!
//! Every attempt — success, HTTP failure, transport failure,
//! credential failure, guard denial — appends one [`CallReceipt`]
//! to the caller's [`ReceiptSink`], in the estate usage-log shape
//! (the `calls.jsonl` schema of `~/workspace/nvidia-usage/` and
//! `~/workspace/openrouter-usage/`: `call_id`, `model`,
//! `model_returned`, `status`, `http`, token counts,
//! `latency_ms`, ISO-8601 `ts`, `tool`, `error` on failures),
//! extended with the honesty fields this contract needs (`lane`,
//! `pinned`, `substituted`, `attempt`).  A call that made three
//! attempts leaves three receipts; failures cost quota in the
//! real world and they are receipted like it here.
//!
//! ## Configuration is data
//!
//! Lane order (the walk order is the config's lane order), each
//! lane's model pool, the per-lane model-selection strategy, pin
//! aliases, per-model timeouts, and the failover policy are all
//! stated in full in [`RouterConfig`].  The config structs have
//! no serde defaults and no `Default` impls: a config that does
//! not state its own behaviour does not deserialize, and
//! [`ModelCaller::new`] validates what was stated.  This crate
//! ships no lane definitions, no provider URLs, no model names,
//! and no presets — the ai-router's current values are the
//! adopter's config to write (APPLICATION.md shows them).
//!
//! ## Composition
//!
//! * Transport: any [`HttpsTransport`] (org-026) for the
//!   synchronous [`ModelCaller::chat`], or any
//!   [`AsyncHttpsTransport`] for [`ModelCaller::chat_async`].
//!   [`HostTransport`] implements both: natively over ureq,
//!   and on wasm the async seam rides org-026's host fetch —
//!   the only send a Worker can perform.
//! * Credentials: lanes name a [`CredentialRef`] (org-028's
//!   identifier type); values arrive through the injected
//!   [`CredentialResolver`].  This crate hardcodes no keys and
//!   reads no files, env, or vault for them.
//! * Breaker/quota: the plain-callback [`CallGuard`] trait —
//!   `admit` before an attempt, `record_outcome` after.  The
//!   `guard-bq` feature adapts org-032's `SyncBreaker` /
//!   `SyncQuota` to it ([`BreakerQuotaGuard`]); with no guard,
//!   [`NoGuard`] admits everything and records nothing.
//!
//! ## Scope, stated plainly
//!
//! The whole-body drivers ([`ModelCaller::chat`] /
//! [`ModelCaller::chat_async`]) refuse a `stream: true` request
//! with [`ModelCallError::Unsupported`] before any attempt —
//! never silently downgraded to a buffered call.  Streaming is
//! served by the dedicated drivers ([`ModelCaller::chat_stream`]
//! / [`ModelCaller::chat_stream_async`]) over the streaming
//! transport seams ([`StreamTransport`] /
//! [`AsyncStreamTransport`]): the walk, pin, and failover policy
//! are the whole-body drivers' shared steps, a 2xx head hands
//! the caller a live chunk stream (a peek at the first events
//! surfaces the provider's stated model — unknown when the
//! stream does not state one, never guessed), and a non-2xx head
//! is drained and classified exactly like a whole-body response.
//! A caller whose transport does not implement the streaming
//! seams has no streaming driver: the refusal is the behavior
//! there, unchanged.  OpenAI-compatible lanes only; providers
//! needing request/response translation (the router's Gemini
//! lane) belong behind a translating transport or a future
//! strategy, not hidden inside this core.

use ref_credential_broker::CredentialRef;
use ref_https_transport::{
    ChunkStream, HttpsRequest, HttpsResponse, HttpsTransport, Method, StreamResponse,
    SyncStreamResponse, TransportError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
// Gregorian, Howard Hinnant's civil-from-days algorithm).
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
/// request). The host's `Date` is the clock on that target.
#[cfg(target_arch = "wasm32")]
fn now_unix_ms() -> i64 {
    js_sys::Date::now() as i64
}

/// A latency mark for the chat drivers. Native: std `Instant`.
/// wasm32: the host `Date` clock in milliseconds (wall clock —
/// latency figures are telemetry, and `Date` is the only clock
/// the target has).
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
/// usage-log shape (`nv-20261007T174616-…`).
fn compact_ts(unix_ms: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix_ms.div_euclid(1000));
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}")
}

// ---------------------------------------------------------------------
// Configuration — caller-supplied data, stated in full.  No serde
// defaults, no Default impls: what the caller did not state does
// not happen.
// ---------------------------------------------------------------------

/// How a lane picks which of its models to try first.  The pick
/// leads the attempt order; the rest of the pool follows in
/// listed order (the router's `orderModelsForRequest` shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ModelStrategy {
    /// Try the pool in listed order.
    PoolOrder,
    /// First matching rule wins; no match → `fallback`.  This is
    /// the data form of the router's `selectNvidiaModel`: its
    /// dense rule (`prompt ≥ 4000 OR max_out ≥ 4096 → dense`) is
    /// two rules naming the same model, its small rule
    /// (`prompt < 1000 AND max_out ≤ 512 → bolt`) is one, and its
    /// vision rule is a rule with `vision: true`.  Prompt tokens
    /// are the router's estimate (content chars / 4); output
    /// budget is the request's `max_tokens`, or 1024 when unset
    /// (the router's documented assumption, restated by the
    /// caller here every time it is relied on).
    SizeRules {
        rules: Vec<SizeRule>,
        fallback: String,
    },
}

/// One size rule: every stated condition must hold (AND).  An
/// unstated condition does not constrain the match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeRule {
    pub model: String,
    /// Match only requests whose content does / does not carry
    /// image parts (`image_url` / `input_image` content items).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<bool>,
    /// Estimated prompt tokens must be ≥ this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_prompt_tokens: Option<u64>,
    /// Estimated prompt tokens must be < this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens_below: Option<u64>,
    /// Requested output budget must be ≥ this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_output_tokens: Option<u64>,
    /// Requested output budget must be ≤ this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
}

impl SizeRule {
    fn matches(&self, prompt_tokens: u64, output_budget: u64, vision: bool) -> bool {
        if let Some(v) = self.vision {
            if v != vision {
                return false;
            }
        }
        if let Some(min) = self.min_prompt_tokens {
            if prompt_tokens < min {
                return false;
            }
        }
        if let Some(below) = self.prompt_tokens_below {
            if prompt_tokens >= below {
                return false;
            }
        }
        if let Some(min) = self.min_output_tokens {
            if output_budget < min {
                return false;
            }
        }
        if let Some(max) = self.max_output_tokens {
            if output_budget > max {
                return false;
            }
        }
        true
    }
}

/// One provider lane: an OpenAI-compatible base URL, the models
/// it may be asked for, and how it behaves.  All fields are
/// required — a lane that does not state its timeout or its
/// 429 behaviour does not deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lane {
    /// Lane name; pins address lanes by this name (or an alias).
    pub name: String,
    /// OpenAI-compatible base, e.g. `https://…/v1`.  The caller
    /// POSTs `{base_url}/chat/completions`.
    pub base_url: String,
    /// Credential reference (org-028 identifier) resolved through
    /// the caller's [`CredentialResolver`], or `None` for a
    /// keyless lane.
    #[serde(deserialize_with = "de_credential_ref")]
    pub credential: Option<CredentialRef>,
    /// The model pool, in caller preference order.
    pub models: Vec<String>,
    /// How the first attempt's model is picked from the pool.
    pub strategy: ModelStrategy,
    /// Per-attempt timeout when no per-model override applies.
    pub timeout_ms: u64,
    /// Per-model timeout overrides, as (model, timeout_ms) data —
    /// the router's `NVIDIA_MODEL_TIMEOUTS` shape.
    pub model_timeouts_ms: Vec<(String, u64)>,
    /// Response body cap handed to the transport.
    pub max_response_bytes: usize,
    /// Permit a plain-`http://` base URL (local fixtures only;
    /// the transport refuses http otherwise).
    pub allow_http: bool,
    /// A 429 aborts the whole lane instead of rotating models
    /// (the router's NVIDIA rule: its 429s are account-level, so
    /// rotation cannot help).  Stated per lane, never assumed.
    pub abort_lane_on_429: bool,
}

/// Deserialization bridge for [`CredentialRef`]: org-028's
/// type is Serialize-only (its values are identifiers, and the
/// broker never deserializes one), so the wire shape
/// (`{"name": …, "scope": …}`) is read here and rebuilt through
/// org-028's validating constructor.
fn de_credential_ref<'de, D>(
    deserializer: D,
) -> Result<Option<CredentialRef>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wire {
        name: String,
        scope: String,
    }
    match Option::<Wire>::deserialize(deserializer)? {
        None => Ok(None),
        Some(w) => CredentialRef::new(w.name, w.scope)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

impl Lane {
    /// The attempt timeout for one model: per-model override if
    /// stated, else the lane's.
    pub fn timeout_for(&self, model: &str) -> u64 {
        self.model_timeouts_ms
            .iter()
            .find(|(m, _)| m == model)
            .map(|(_, ms)| *ms)
            .unwrap_or(self.timeout_ms)
    }

    /// Attempt order for one request: the strategy pick first,
    /// then the rest of the pool in listed order.
    fn attempt_order(&self, prompt_tokens: u64, output_budget: u64, vision: bool) -> Vec<String> {
        let pick = match &self.strategy {
            ModelStrategy::PoolOrder => self.models[0].clone(),
            ModelStrategy::SizeRules { rules, fallback } => rules
                .iter()
                .find(|r| r.matches(prompt_tokens, output_budget, vision))
                .map(|r| r.model.clone())
                .unwrap_or_else(|| fallback.clone()),
        };
        let mut order = vec![pick.clone()];
        for m in &self.models {
            if *m != pick {
                order.push(m.clone());
            }
        }
        order
    }
}

/// Which failures move the walk to the next model / lane.  The
/// router's values (fail over on 401/403/404/429, any 5xx,
/// timeout and network error; 400/413/422 are caller-caused and
/// return immediately) are the adopter's to state — see
/// APPLICATION.md.  A status that is neither listed nor 5xx
/// (when `failover_on_5xx`) is terminal: the provider's answer
/// is returned as [`ModelCallError::ProviderError`] at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverPolicy {
    pub failover_statuses: Vec<u16>,
    pub failover_on_5xx: bool,
    pub failover_on_transport_error: bool,
    /// Cap on total attempts across the whole walk; `None` walks
    /// every lane and model the config offers.
    pub max_attempts: Option<usize>,
}

impl FailoverPolicy {
    fn status_fails_over(&self, status: u16) -> bool {
        self.failover_statuses.contains(&status)
            || (self.failover_on_5xx && (500..600).contains(&status))
    }
}

/// The whole routing configuration.  Lane order in `lanes` IS
/// the failover walk order — there is no priority field and no
/// hidden reordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterConfig {
    pub lanes: Vec<Lane>,
    /// Pin-prefix aliases as (alias, lane name) data — the
    /// router's `nim → nvidia` lives here when the caller wants
    /// it.
    pub aliases: Vec<(String, String)>,
    pub failover: FailoverPolicy,
}

impl RouterConfig {
    /// Resolve a pin prefix: alias first, then a lane name
    /// itself (the router accepts both).
    fn resolve_lane_name<'a>(&'a self, prefix: &str) -> Option<&'a str> {
        if let Some((_, target)) = self.aliases.iter().find(|(a, _)| a == prefix) {
            return Some(target.as_str());
        }
        self.lanes
            .iter()
            .find(|l| l.name == prefix)
            .map(|l| l.name.as_str())
    }

    pub fn lane(&self, name: &str) -> Option<&Lane> {
        self.lanes.iter().find(|l| l.name == name)
    }

    fn validate(&self) -> Result<(), ModelCallError> {
        if self.lanes.is_empty() {
            return Err(ModelCallError::InvalidConfig(
                "config states no lanes".to_string(),
            ));
        }
        let mut names: Vec<&str> = Vec::new();
        for lane in &self.lanes {
            if lane.name.is_empty() {
                return Err(ModelCallError::InvalidConfig(
                    "a lane has an empty name".to_string(),
                ));
            }
            if names.contains(&lane.name.as_str()) {
                return Err(ModelCallError::InvalidConfig(format!(
                    "duplicate lane name {}",
                    lane.name
                )));
            }
            names.push(lane.name.as_str());
            if lane.models.is_empty() {
                return Err(ModelCallError::InvalidConfig(format!(
                    "lane {} states no models",
                    lane.name
                )));
            }
            if lane.timeout_ms == 0 {
                return Err(ModelCallError::InvalidConfig(format!(
                    "lane {} states timeout_ms 0",
                    lane.name
                )));
            }
            if lane.max_response_bytes == 0 {
                return Err(ModelCallError::InvalidConfig(format!(
                    "lane {} states max_response_bytes 0",
                    lane.name
                )));
            }
            let (scheme, rest) = lane.base_url.split_once("://").ok_or_else(|| {
                ModelCallError::InvalidConfig(format!(
                    "lane {} base_url has no scheme: {}",
                    lane.name, lane.base_url
                ))
            })?;
            match scheme {
                "https" => {}
                "http" if lane.allow_http => {}
                "http" => {
                    return Err(ModelCallError::InvalidConfig(format!(
                        "lane {} base_url is http but allow_http is false",
                        lane.name
                    )))
                }
                other => {
                    return Err(ModelCallError::InvalidConfig(format!(
                        "lane {} base_url scheme {other} is not https",
                        lane.name
                    )))
                }
            }
            if rest.split(['/', '?', '#']).next().unwrap_or("").is_empty() {
                return Err(ModelCallError::InvalidConfig(format!(
                    "lane {} base_url has no host: {}",
                    lane.name, lane.base_url
                )));
            }
            if let ModelStrategy::SizeRules { rules, fallback } = &lane.strategy {
                for m in rules.iter().map(|r| &r.model).chain(std::iter::once(fallback)) {
                    if !lane.models.contains(m) {
                        return Err(ModelCallError::InvalidConfig(format!(
                            "lane {} strategy names model {m} which is not in its pool",
                            lane.name
                        )));
                    }
                }
            }
            for (m, _) in &lane.model_timeouts_ms {
                if !lane.models.contains(m) {
                    return Err(ModelCallError::InvalidConfig(format!(
                        "lane {} times out model {m} which is not in its pool",
                        lane.name
                    )));
                }
            }
        }
        for (alias, target) in &self.aliases {
            if alias.is_empty() || target.is_empty() {
                return Err(ModelCallError::InvalidConfig(
                    "an alias states an empty name or target".to_string(),
                ));
            }
            if !names.contains(&target.as_str()) {
                return Err(ModelCallError::InvalidConfig(format!(
                    "alias {alias} targets unknown lane {target}"
                )));
            }
        }
        Ok(())
    }
}

/// A parsed pin: the lane and model a `"<lane>/<model-id>"`
/// model string binds the call to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pin {
    pub lane: String,
    pub model: String,
    /// The model string exactly as the caller wrote it.
    pub raw: String,
}

/// Parse a pin the router's way: split at the FIRST `/`; the
/// prefix must resolve (alias or lane name) to a configured
/// lane, and the remainder — which may itself contain `/`, as
/// full model ids do — is the pinned model.  Anything else is
/// not a pin and returns `None`.
pub fn parse_pin(model: &str, config: &RouterConfig) -> Option<Pin> {
    let slash = model.find('/')?;
    if slash == 0 {
        return None;
    }
    let prefix = &model[..slash];
    let pinned_model = &model[slash + 1..];
    if pinned_model.is_empty() {
        return None;
    }
    let lane = config.resolve_lane_name(prefix)?;
    Some(Pin {
        lane: lane.to_string(),
        model: pinned_model.to_string(),
        raw: model.to_string(),
    })
}

// ---------------------------------------------------------------------
// Requests and responses.
// ---------------------------------------------------------------------

/// One chat message.  `content` is the OpenAI shape: a string,
/// or an array of content parts (text / image_url / …) passed
/// through untouched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: Value,
}

impl ChatMessage {
    pub fn text(role: impl Into<String>, content: impl Into<String>) -> Self {
        ChatMessage {
            role: role.into(),
            content: Value::String(content.into()),
        }
    }

    /// Characters of text content (string content, plus `text`
    /// parts of array content) — the prompt-size measure the
    /// router's estimate and the usage logs' `prompt_chars`
    /// both use.
    fn text_chars(&self) -> usize {
        match &self.content {
            Value::String(s) => s.chars().count(),
            Value::Array(parts) => parts
                .iter()
                .filter(|p| p["type"] == "text")
                .filter_map(|p| p["text"].as_str())
                .map(|t| t.chars().count())
                .sum(),
            _ => 0,
        }
    }

    fn has_vision_part(&self) -> bool {
        match &self.content {
            Value::Array(parts) => parts
                .iter()
                .any(|p| p["type"] == "image_url" || p["type"] == "input_image"),
            _ => false,
        }
    }
}

/// A chat-completions request.  `model` may carry a pin
/// (`"<lane>/<model-id>"`), a plain model id (reported, and
/// compared against the served model, but — as in the router —
/// not used for routing when unpinned), or nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f64>,
    /// Streaming requests are served only by the streaming
    /// drivers (`chat_stream` / `chat_stream_async`); the
    /// whole-body drivers refuse this flag, never silently
    /// buffer it (see the crate docs).
    pub stream: bool,
    /// Why this call exists; carried onto every receipt, the
    /// estate usage logs' `purpose` field.
    pub purpose: Option<String>,
    /// Extra provider fields merged into the request body.
    /// Reserved keys (`model`, `messages`, `stream`,
    /// `max_tokens`, `temperature`) are written by the caller
    /// core and win over anything stated here.
    pub extra: serde_json::Map<String, Value>,
}

impl ChatRequest {
    pub fn new(messages: Vec<ChatMessage>) -> Self {
        ChatRequest {
            model: None,
            messages,
            max_tokens: None,
            temperature: None,
            stream: false,
            purpose: None,
            extra: serde_json::Map::new(),
        }
    }

    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    pub fn max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = Some(n);
        self
    }

    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    fn prompt_chars(&self) -> usize {
        self.messages.iter().map(|m| m.text_chars()).sum()
    }

    fn has_vision(&self) -> bool {
        self.messages.iter().any(|m| m.has_vision_part())
    }
}

/// Token accounting as the provider reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

/// What one attempt did.  The full vector rides on every
/// response and every terminal error — the walk is never
/// summarised away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attempt {
    pub lane: String,
    pub model: String,
    pub outcome: AttemptOutcome,
    pub http_status: Option<u16>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AttemptOutcome {
    Success,
    /// Failover-class HTTP status; the walk moved on.
    HttpStatus { status: u16 },
    /// Terminal HTTP status (caller-caused class); the walk
    /// stopped and the provider's answer was returned.
    CallerError { status: u16 },
    /// No response exists (DNS / TLS / timeout / network).
    TransportError { message: String },
    /// A 2xx whose body was not a chat completion.
    ParseError { message: String },
    /// The lane's credential could not be resolved; nothing
    /// was sent.
    CredentialError { message: String },
    /// The caller's guard refused admission; nothing was sent.
    GuardDenied { reason: String },
}

impl AttemptOutcome {
    fn is_success(&self) -> bool {
        matches!(self, AttemptOutcome::Success)
    }

    /// The receipt `error` string for a failed attempt; `None`
    /// on success (the estate logs omit the field on `ok`).
    fn error_string(&self) -> Option<String> {
        match self {
            AttemptOutcome::Success => None,
            AttemptOutcome::HttpStatus { status } => Some(format!("HTTP {status}")),
            AttemptOutcome::CallerError { status } => Some(format!("HTTP {status}")),
            AttemptOutcome::TransportError { message } => Some(message.clone()),
            AttemptOutcome::ParseError { message } => Some(message.clone()),
            AttemptOutcome::CredentialError { message } => Some(message.clone()),
            AttemptOutcome::GuardDenied { reason } => {
                Some(format!("guard denied: {reason}"))
            }
        }
    }
}

/// A completed chat call.  The honesty fields are the point:
/// what was asked, what was sent, what served, and whether
/// those differ — plus the full attempt walk that got there.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChatResponse {
    /// `choices[0].message.content`; when the provider left it
    /// empty and supplied `reasoning_content` instead (the NIM
    /// reasoning models' habit), the reasoning content — the
    /// substitution of field for field is the provider's own
    /// shape, reported here so callers know it happened.
    pub content: String,
    pub content_from_reasoning: bool,
    /// The lane that served.
    pub lane: String,
    /// The model string exactly as the caller wrote it.
    pub model_requested: Option<String>,
    /// The model id sent to the serving lane.
    pub model_sent: String,
    /// The provider's own `model` field from its response
    /// body; `None` when the provider did not state one.
    pub model_served: Option<String>,
    /// True exactly when a served model is known and differs
    /// from the model the caller asked to be served (the
    /// pin's model when pinned, else the raw requested
    /// string).  Never guessed: an unstated served model is
    /// `false` here and visible as `model_served: None`.
    pub substituted: bool,
    /// The pin in force, when the request was pinned.
    pub pin: Option<Pin>,
    pub http_status: u16,
    pub usage: Option<Usage>,
    pub attempts: Vec<Attempt>,
    /// The provider's full response body, untouched.
    pub raw: Value,
}

// ---------------------------------------------------------------------
// Errors.  No variant ever carries a credential value: variants
// are built from lane names, model ids, statuses, and
// backend/transport text, and resolver implementors are bound
// by the same rule (see CredentialResolver).
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelCallError {
    /// The stated configuration does not validate.
    InvalidConfig(String),
    /// The request itself is malformed (no messages, …).
    InvalidRequest(String),
    /// A call shape this crate does not serve (streaming in v1).
    Unsupported(String),
    /// The pin could not be served and no substitution was
    /// attempted.  Names the lane and the model — a pin is a
    /// contract, and its failure is loud or it is not a pin.
    PinFailed {
        lane: String,
        model: String,
        attempts: Vec<Attempt>,
        message: String,
    },
    /// A terminal (caller-caused class) provider status: the
    /// provider's answer, returned at once without failover.
    ProviderError {
        lane: String,
        model: String,
        status: u16,
        body: String,
        attempts: Vec<Attempt>,
    },
    /// The whole walk failed.  `attempts` is the full record.
    AllLanesFailed {
        attempts: Vec<Attempt>,
        message: String,
    },
    /// A credential could not be resolved (surfaced directly
    /// only when it happens before any attempt exists — inside
    /// the walk it is an attempt outcome).
    Credential(String),
}

impl fmt::Display for ModelCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModelCallError::InvalidConfig(m) => {
                write!(f, "model-call-live: invalid config: {m}")
            }
            ModelCallError::InvalidRequest(m) => {
                write!(f, "model-call-live: invalid request: {m}")
            }
            ModelCallError::Unsupported(m) => {
                write!(f, "model-call-live: unsupported: {m}")
            }
            ModelCallError::PinFailed {
                lane,
                model,
                message,
                ..
            } => write!(
                f,
                "model-call-live: pinned model failed on its lane; no substitution attempted: lane {lane}, model {model}: {message}"
            ),
            ModelCallError::ProviderError {
                lane,
                model,
                status,
                body,
                ..
            } => write!(
                f,
                "model-call-live: provider returned terminal HTTP {status} on lane {lane} model {model}: {body}"
            ),
            ModelCallError::AllLanesFailed { message, .. } => {
                write!(f, "model-call-live: all lanes failed: {message}")
            }
            ModelCallError::Credential(m) => {
                write!(f, "model-call-live: credential: {m}")
            }
        }
    }
}

impl std::error::Error for ModelCallError {}

// ---------------------------------------------------------------------
// Credentials.  Lanes name a CredentialRef (org-028); the value
// arrives through the host's resolver.  The discipline mirrors
// org-028's SecretValue: redacted Debug, zeroing Drop, and the
// value's only sanctioned use is attachment to the outgoing
// request inside this crate.
// ---------------------------------------------------------------------

/// A resolved credential value in transit.  Constructed by
/// resolver implementors, consumed by this crate's header
/// attachment, exposed nowhere else by this crate: receipts,
/// errors, and Debug strings never contain it.
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        SecretString(value.into())
    }

    /// The one door to the value.  Sanctioned callers: resolver
    /// implementors building a [`ResolvedAuth`], and this
    /// crate's request attachment.  Never log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(<redacted>)")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        let bytes = unsafe { self.0.as_mut_vec() };
        for b in bytes.iter_mut() {
            *b = 0;
        }
        self.0.clear();
    }
}

/// How a resolved credential attaches to the request — the
/// org-028 `Placement` shape, header placements only (a value
/// in a URL lands in logs; there is deliberately no URL
/// variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStyle {
    /// `Authorization: Bearer <value>`
    Bearer,
    /// `<name>: <value>` (e.g. `x-api-key`, `x-goog-api-key`)
    Header(String),
}

impl AuthStyle {
    pub fn header_name(&self) -> &str {
        match self {
            AuthStyle::Bearer => "Authorization",
            AuthStyle::Header(name) => name.as_str(),
        }
    }

    fn attach(&self, req: &mut HttpsRequest, value: &SecretString) {
        // Resolved auth wins: any caller-stated copy of the
        // same header is replaced, never duplicated alongside.
        let name = self.header_name().to_string();
        req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
        let v = match self {
            AuthStyle::Bearer => format!("Bearer {}", value.expose()),
            AuthStyle::Header(_) => value.expose().to_string(),
        };
        req.headers.push((name, v));
    }
}

/// A credential after resolution: the value plus how it
/// attaches.  Manual `Debug` — redacted by construction.
pub struct ResolvedAuth {
    pub style: AuthStyle,
    pub value: SecretString,
}

impl ResolvedAuth {
    pub fn bearer(value: impl Into<String>) -> Self {
        ResolvedAuth {
            style: AuthStyle::Bearer,
            value: SecretString::new(value),
        }
    }

    pub fn header(name: impl Into<String>, value: impl Into<String>) -> Self {
        ResolvedAuth {
            style: AuthStyle::Header(name.into()),
            value: SecretString::new(value),
        }
    }
}

impl fmt::Debug for ResolvedAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedAuth")
            .field("style", &self.style)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Resolves a lane's [`CredentialRef`] to an attachable auth.
/// Implemented by the host over its own provisioning — the
/// estate's dynamic-credential surrogate (authd), a vault, a
/// file the host chose — composed with org-028's broker where
/// the broker itself holds the backend.  Implementors must
/// never embed a credential value in an error string.
pub trait CredentialResolver: Send + Sync {
    fn resolve(&self, reference: &CredentialRef) -> Result<ResolvedAuth, ModelCallError>;
}

/// The fail-closed default: resolves nothing.  A lane naming a
/// credential fails its attempt with a credential error; a
/// keyless lane is unaffected.
pub struct NoCredentials;

impl CredentialResolver for NoCredentials {
    fn resolve(&self, reference: &CredentialRef) -> Result<ResolvedAuth, ModelCallError> {
        Err(ModelCallError::Credential(format!(
            "no credential resolver configured; cannot resolve {reference} (fail-closed)"
        )))
    }
}

/// In-memory resolver: the provisioning side (host process,
/// tests) inserts resolved auth under a reference.  Values are
/// held as plain strings here and minted into [`SecretString`]
/// per resolve — this is a convenience for hosts that already
/// hold the value in process, not a store to persist.
#[derive(Default)]
pub struct MemoryCredentials {
    entries: Vec<(CredentialRef, AuthStyle, String)>,
}

impl MemoryCredentials {
    pub fn new() -> Self {
        MemoryCredentials { entries: vec![] }
    }

    pub fn insert(
        &mut self,
        reference: CredentialRef,
        style: AuthStyle,
        value: impl Into<String>,
    ) -> &mut Self {
        self.entries.push((reference, style, value.into()));
        self
    }
}

impl CredentialResolver for MemoryCredentials {
    fn resolve(&self, reference: &CredentialRef) -> Result<ResolvedAuth, ModelCallError> {
        self.entries
            .iter()
            .find(|(r, _, _)| r == reference)
            .map(|(_, style, value)| ResolvedAuth {
                style: style.clone(),
                value: SecretString::new(value.clone()),
            })
            .ok_or_else(|| {
                ModelCallError::Credential(format!(
                    "unknown credential ref {reference} (fail-closed)"
                ))
            })
    }
}

// ---------------------------------------------------------------------
// Breaker/quota composition: plain callbacks.  The caller (or
// the guard-bq adapter over org-032) decides admission before
// an attempt and hears every attempt's outcome after it.
// ---------------------------------------------------------------------

/// Why a guard refused admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardDenial {
    pub reason: String,
    pub retry_at_ms: Option<i64>,
}

/// Admission + outcome callbacks around each attempt.  A
/// denial is an attempt outcome (receipted, walked past on
/// unpinned calls, fatal on pins) — never a silent skip.
pub trait CallGuard: Send + Sync {
    fn admit(&self, lane: &str, now_ms: i64) -> Result<(), GuardDenial>;
    fn record_outcome(&self, lane: &str, now_ms: i64, success: bool);
}

/// The default guard: admits everything, records nothing.
pub struct NoGuard;

impl CallGuard for NoGuard {
    fn admit(&self, _lane: &str, _now_ms: i64) -> Result<(), GuardDenial> {
        Ok(())
    }
    fn record_outcome(&self, _lane: &str, _now_ms: i64, _success: bool) {}
}

#[cfg(feature = "guard-bq")]
pub use bq_guard::BreakerQuotaGuard;

#[cfg(feature = "guard-bq")]
mod bq_guard {
    use super::*;
    use ref_breaker_quota::{Admission, SyncBreaker, SyncQuota};
    use std::collections::BTreeMap;

    /// [`CallGuard`] over org-032's state machines: per-lane
    /// `SyncBreaker` + `SyncQuota`, registered by the caller
    /// with the caller's own configs (org-032 ships no
    /// thresholds; neither does this adapter).
    ///
    /// Admission order is quota first, then breaker: a quota
    /// denial never touches the breaker, while a breaker
    /// denial after a quota grant spends one unit of quota —
    /// bounded, visible in the quota's own trace, and healed
    /// at the window reset.  (The reverse order can leak a
    /// half-open probe slot, which does not self-heal.)
    /// Outcomes are reported to the breaker only; quota
    /// consumption is the admission itself, success or not —
    /// a failed call still cost the provider budget.
    #[derive(Default)]
    pub struct BreakerQuotaGuard {
        breakers: BTreeMap<String, SyncBreaker>,
        quotas: BTreeMap<String, SyncQuota>,
    }

    impl BreakerQuotaGuard {
        pub fn new() -> Self {
            BreakerQuotaGuard::default()
        }

        pub fn register_breaker(
            &mut self,
            lane: impl Into<String>,
            breaker: ref_breaker_quota::Breaker,
        ) -> &mut Self {
            self.breakers
                .insert(lane.into(), SyncBreaker::new(breaker));
            self
        }

        pub fn register_quota(
            &mut self,
            lane: impl Into<String>,
            quota: ref_breaker_quota::QuotaMeter,
        ) -> &mut Self {
            self.quotas.insert(lane.into(), SyncQuota::new(quota));
            self
        }
    }

    impl CallGuard for BreakerQuotaGuard {
        fn admit(&self, lane: &str, now_ms: i64) -> Result<(), GuardDenial> {
            if let Some(q) = self.quotas.get(lane) {
                let out = q.try_consume(now_ms, 1);
                if !out.granted {
                    return Err(GuardDenial {
                        reason: format!(
                            "quota exhausted on lane {lane} ({} used, {} remaining in window)",
                            out.used, out.remaining
                        ),
                        retry_at_ms: out.retry_at_ms,
                    });
                }
            }
            if let Some(b) = self.breakers.get(lane) {
                match b.admit(now_ms) {
                    Admission::Allowed | Admission::AllowedProbe => {}
                    Admission::Denied {
                        retry_at_ms,
                        reason,
                    } => {
                        return Err(GuardDenial {
                            reason: format!("breaker denied on lane {lane}: {reason:?}"),
                            retry_at_ms,
                        });
                    }
                }
            }
            Ok(())
        }

        fn record_outcome(&self, lane: &str, now_ms: i64, success: bool) {
            if let Some(b) = self.breakers.get(lane) {
                if success {
                    b.record_success(now_ms);
                } else {
                    b.record_failure(now_ms, 0);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Receipts — one per attempt, in the estate usage-log shape.
// ---------------------------------------------------------------------

/// One attempt's receipt: the `calls.jsonl` record.  Field
/// names and the success/error conventions follow the estate
/// logs (`model` is the model sent on this attempt,
/// `model_returned` the provider's own model field, `error`
/// present only on failures); `lane`, `pinned`, `substituted`,
/// `attempt`, and `endpoint` are this contract's extensions.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CallReceipt {
    pub call_id: String,
    /// The model sent to the provider on this attempt.
    pub model: String,
    /// The model string exactly as the caller wrote it.
    pub model_requested: Option<String>,
    /// The provider's `model` field; `None` when no response
    /// stated one (including every transport-level failure).
    pub model_returned: Option<String>,
    pub lane: String,
    pub pinned: bool,
    pub substituted: bool,
    pub status: String,
    pub http: Option<u16>,
    pub prompt_chars: usize,
    pub max_tokens_requested: Option<u32>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub latency_ms: u64,
    pub ts: String,
    pub tool: String,
    /// 1-based position of this attempt within its call.
    pub attempt: usize,
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Where receipts go.  Implementations are best-effort by
/// design (the estate CLIs' log appends swallow I/O errors
/// rather than failing the call they describe); a sink that
/// needs durability should say so in its own docs.
pub trait ReceiptSink: Send + Sync {
    fn record(&self, receipt: &CallReceipt);
}

/// Receipts go nowhere.
pub struct NoopSink;

impl ReceiptSink for NoopSink {
    fn record(&self, _receipt: &CallReceipt) {}
}

/// Receipts accumulate in memory — tests, and hosts that batch
/// their own persistence.
#[derive(Default)]
pub struct MemorySink {
    receipts: std::sync::Mutex<Vec<CallReceipt>>,
}

impl MemorySink {
    pub fn new() -> Self {
        MemorySink::default()
    }

    pub fn receipts(&self) -> Vec<CallReceipt> {
        self.receipts.lock().unwrap().clone()
    }
}

impl ReceiptSink for MemorySink {
    fn record(&self, receipt: &CallReceipt) {
        self.receipts.lock().unwrap().push(receipt.clone());
    }
}

/// Receipts append as JSON lines to a file — the estate
/// usage-log sink.  Append failures are counted, not hidden
/// and not fatal: [`JsonlFileSink::dropped`] reports how many
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
    fn record(&self, receipt: &CallReceipt) {
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
// The async transport seam.  org-026's `HttpsTransport` is
// synchronous; on wasm32 a send is a host `fetch`, which is a
// promise — the blocking face of org-026 reports itself
// `Unsupported` there.  This trait is the same request/response
// contract with the send as a future, so the caller's walk can
// run on hosts whose only send is async (Workers).  The walk's
// policy — pin, failover, substitution, receipts — lives in the
// caller and is shared verbatim between the two drivers; only
// the send itself differs.
// ---------------------------------------------------------------------

/// The future an async send returns.  On native targets it
/// is `Send` (the ureq-backed future is).  On wasm32 it cannot
/// be: the host fetch future (`JsFuture`) is built on
/// `Rc<RefCell<..>>`, and the host itself is single-threaded —
/// so the bound is stated per-target rather than faked with an
/// unsafe assertion.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub type TransportFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;
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
/// only send a Worker can perform.  This impl is what makes
/// `ModelCaller::chat_async` work on a deployed Worker with the
/// platform default transport.
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
// The streaming transport seams.  Same contract as the whole-body
// seams, split at the response head (org-026's streaming types):
// any HTTP status is an `Ok` head; `Err` means no response
// exists.  A caller built over a transport that implements only
// the whole-body seams has no streaming driver — the refusal is
// structural, not a runtime branch.
// ---------------------------------------------------------------------

/// A transport that can open a response as a blocking chunk
/// iterator (native hosts, test doubles).
pub trait StreamTransport: Send + Sync {
    fn send_stream(&self, req: &HttpsRequest) -> Result<SyncStreamResponse, TransportError>;
}

/// A transport that can open a response as an async chunk
/// stream (the wasm host's fetch; native embedders whose sends
/// are futures).
pub trait AsyncStreamTransport: Send + Sync {
    fn send_stream_async<'a>(
        &'a self,
        req: &'a HttpsRequest,
    ) -> TransportFuture<'a, Result<StreamResponse, TransportError>>;
}

/// The bridges: org-026's `HostTransport` over its streaming
/// sends — the blocking face natively (ureq reader), the async
/// face on the host fetch.
impl StreamTransport for ref_https_transport::HostTransport {
    fn send_stream(&self, req: &HttpsRequest) -> Result<SyncStreamResponse, TransportError> {
        ref_https_transport::send_stream_blocking(req)
    }
}

impl AsyncStreamTransport for ref_https_transport::HostTransport {
    fn send_stream_async<'a>(
        &'a self,
        req: &'a HttpsRequest,
    ) -> TransportFuture<'a, Result<StreamResponse, TransportError>> {
        Box::pin(ref_https_transport::send_stream_async(req))
    }
}

// ---------------------------------------------------------------------
// Streaming results.  The walk's honesty fields ride in
// `StreamMeta`, shared by both drivers; only the chunk source
// differs (iterator vs stream).  `model_served` is read off the
// stream's own events by the driver's peek — the provider's
// stated model, or `None` (unknown) when the stream's first
// events state none.  It is never filled from the request.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StreamMeta {
    /// The lane that served.
    pub lane: String,
    /// The model string exactly as the caller wrote it.
    pub model_requested: Option<String>,
    /// The model id sent to the serving lane.
    pub model_sent: String,
    /// The provider's `model` field as stated in the stream's
    /// own data; `None` when the peeked events state none.
    pub model_served: Option<String>,
    /// True exactly when a served model is known and differs
    /// from the model the caller asked to be served.
    pub substituted: bool,
    /// The pin in force, when the request was pinned.
    pub pin: Option<Pin>,
    pub http_status: u16,
    pub attempts: Vec<Attempt>,
}

/// A streaming call that reached a serving lane, async face:
/// the chunk stream is live — the peeked prefix first, then the
/// upstream's remaining chunks, then its error if it dies.
pub struct ChatStreamResponse {
    pub meta: StreamMeta,
    pub chunks: ChunkStream,
}

/// A streaming call that reached a serving lane, blocking face.
pub struct ChatSyncStreamResponse {
    pub meta: StreamMeta,
    pub chunks: Box<dyn Iterator<Item = Result<Vec<u8>, TransportError>> + Send>,
}

impl std::fmt::Debug for ChatStreamResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatStreamResponse")
            .field("meta", &self.meta)
            .field("chunks", &"<stream>")
            .finish()
    }
}

impl std::fmt::Debug for ChatSyncStreamResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSyncStreamResponse")
            .field("meta", &self.meta)
            .field("chunks", &"<iterator>")
            .finish()
    }
}

// ---------------------------------------------------------------------
// The SSE peek.  To surface `model_served` the driver reads the
// stream's opening events before handing the stream over.  The
// peek is bounded (events and bytes), the bytes it consumed are
// replayed to the consumer ahead of the rest, and the scan is
// chunk-boundary blind: it works on the reassembled byte stream,
// splitting events on blank lines exactly as an SSE reader does.
// ---------------------------------------------------------------------

const PEEK_MAX_EVENTS: usize = 16;
const PEEK_MAX_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct SseScan {
    buf: Vec<u8>,
    events: usize,
    model: Option<String>,
}

impl SseScan {
    fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
        loop {
            let Some(end) = event_end(&self.buf) else {
                break;
            };
            let event: Vec<u8> = self.buf.drain(..end).collect();
            self.events += 1;
            if self.model.is_none() {
                self.model = event_model(&event);
            }
        }
    }

    /// The peek may stop: a model is known, or the bounds are hit.
    fn settled(&self) -> bool {
        self.model.is_some() || self.events >= PEEK_MAX_EVENTS || self.buf.len() >= PEEK_MAX_BYTES
    }

    /// At end of stream, a trailing event with no closing blank
    /// line still counts — providers that omit the final blank
    /// line state their model in it.
    fn finish(mut self) -> Option<String> {
        if self.model.is_none() && !self.buf.is_empty() {
            self.model = event_model(&self.buf);
        }
        self.model
    }
}

/// Byte index just past the first event-terminating blank line
/// (`\n\n`, or `\r\n\r\n` / mixed), or `None` when the buffer
/// holds no complete event yet.
fn event_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            // A blank line: the next byte starts a new line that
            // is immediately terminated (or a \r\n pair is).
            let rest = &buf[i + 1..];
            if rest.first() == Some(&b'\n') {
                return Some(i + 2);
            }
            if rest.first() == Some(&b'\r') && rest.get(1) == Some(&b'\n') {
                return Some(i + 3);
            }
        }
        i += 1;
    }
    None
}

/// The `model` a single SSE event states: its `data:` lines
/// joined, parsed as JSON, the top-level string `model` field.
/// `[DONE]` and non-JSON data state nothing.
fn event_model(event: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(event);
    let mut data = String::new();
    for line in text.lines() {
        if let Some(d) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(d.trim_start());
        }
    }
    if data.is_empty() || data == "[DONE]" {
        return None;
    }
    let v: Value = serde_json::from_str(&data).ok()?;
    v.get("model").and_then(|m| m.as_str()).map(|s| s.to_string())
}

/// The async chunk stream the async driver returns: the peeked
/// prefix, then a one-shot error if the peek met one, then the
/// upstream's own remaining chunks.
struct PrefixStream {
    prefix: std::collections::VecDeque<Result<Vec<u8>, TransportError>>,
    err_once: Option<TransportError>,
    rest: Option<ChunkStream>,
}

impl futures_core::Stream for PrefixStream {
    type Item = Result<Vec<u8>, TransportError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        if let Some(item) = self.prefix.pop_front() {
            return Poll::Ready(Some(item));
        }
        if let Some(e) = self.err_once.take() {
            return Poll::Ready(Some(Err(e)));
        }
        match &mut self.rest {
            Some(rest) => rest.as_mut().poll_next(cx),
            None => Poll::Ready(None),
        }
    }
}

/// A planned walk: the pin resolution and the (lane, model)
/// attempt order, computed once by `ModelCaller::plan` and
/// shared by the synchronous and asynchronous drivers.
struct WalkPlan<'a> {
    pin: Option<Pin>,
    asked_model: Option<String>,
    walk: Vec<(&'a Lane, String)>,
}

/// How one recorded attempt outcome steers the walk.
enum Flow {
    /// Move to the next walk entry.
    Continue,
    /// Stop walking; finish with the attempts on record.
    Break,
    /// The walk is decided: this is the call's result.
    Done(Result<ChatResponse, ModelCallError>),
}

// ---------------------------------------------------------------------
// The caller.  Generic over the injected transport, credential
// resolver, guard, and receipt sink — every seam is a value the
// host supplies, and nothing in this crate reaches around them.
// ---------------------------------------------------------------------

pub struct ModelCaller<T, C, G, S> {
    config: RouterConfig,
    transport: T,
    credentials: C,
    guard: G,
    sink: S,
    seq: AtomicU64,
}

impl<T, C, G, S> ModelCaller<T, C, G, S>
where
    C: CredentialResolver,
    G: CallGuard,
    S: ReceiptSink,
{
    /// Build a caller over a validated configuration.  A config
    /// that does not validate is refused here, before any call.
    pub fn new(
        config: RouterConfig,
        transport: T,
        credentials: C,
        guard: G,
        sink: S,
    ) -> Result<Self, ModelCallError> {
        config.validate()?;
        Ok(ModelCaller {
            config,
            transport,
            credentials,
            guard,
            sink,
            seq: AtomicU64::new(0),
        })
    }

    /// The fail-closed default for the bare organelle surface:
    /// no lanes, so every call is an `InvalidConfig` error and
    /// nothing is ever sent.
    #[cfg(feature = "organelle")]
    fn unconfigured(transport: T, credentials: C, guard: G, sink: S) -> Self {
        ModelCaller {
            config: RouterConfig {
                lanes: vec![],
                aliases: vec![],
                failover: FailoverPolicy {
                    failover_statuses: vec![],
                    failover_on_5xx: false,
                    failover_on_transport_error: false,
                    max_attempts: None,
                },
            },
            transport,
            credentials,
            guard,
            sink,
            seq: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &RouterConfig {
        &self.config
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Validate the request and compute the walk.  Every
    /// refusal the drivers share happens here, before any send:
    /// no lanes (the fail-closed default), a call shape the
    /// driver does not serve, an empty message list.
    fn plan(&self, req: &ChatRequest) -> Result<WalkPlan<'_>, ModelCallError> {
        self.plan_mode(req, false)
    }

    /// The streaming drivers' plan: identical to [`Self::plan`]
    /// except the call-shape rule inverts — these drivers serve
    /// `stream: true` and nothing else.
    fn plan_stream(&self, req: &ChatRequest) -> Result<WalkPlan<'_>, ModelCallError> {
        self.plan_mode(req, true)
    }

    fn plan_mode(
        &self,
        req: &ChatRequest,
        streaming: bool,
    ) -> Result<WalkPlan<'_>, ModelCallError> {
        if self.config.lanes.is_empty() {
            return Err(ModelCallError::InvalidConfig(
                "no lanes configured (fail-closed default); construct the caller with a stated RouterConfig".to_string(),
            ));
        }
        if streaming && !req.stream {
            return Err(ModelCallError::Unsupported(
                "the streaming drivers serve stream: true requests only; use chat/chat_async for whole-body calls".to_string(),
            ));
        }
        if !streaming && req.stream {
            return Err(ModelCallError::Unsupported(
                "stream: true is not served by model-call-live v1 (whole-body transport); refusing rather than silently buffering".to_string(),
            ));
        }
        if req.messages.is_empty() {
            return Err(ModelCallError::InvalidRequest(
                "request states no messages".to_string(),
            ));
        }

        let pin = req
            .model
            .as_deref()
            .and_then(|m| parse_pin(m, &self.config));
        // The model the caller asked to be served, for the
        // substitution comparison: the pin's model when pinned,
        // else the raw requested string (the router's rule).
        let asked_model: Option<String> = match &pin {
            Some(p) => Some(p.model.clone()),
            None => req.model.clone(),
        };

        let prompt_chars = req.prompt_chars();
        let prompt_tokens_est = (prompt_chars / 4) as u64;
        let output_budget = req.max_tokens.map(|n| n as u64).unwrap_or(1024);
        let vision = req.has_vision();

        // The walk: (lane, model) pairs in attempt order.  A pin
        // is exactly one pair — that is the whole of its meaning.
        let mut walk: Vec<(&Lane, String)> = Vec::new();
        match &pin {
            Some(p) => {
                let lane = self
                    .config
                    .lane(&p.lane)
                    .expect("parse_pin resolved a configured lane");
                walk.push((lane, p.model.clone()));
            }
            None => {
                for lane in &self.config.lanes {
                    for model in lane.attempt_order(prompt_tokens_est, output_budget, vision) {
                        walk.push((lane, model));
                    }
                }
            }
        }

        Ok(WalkPlan {
            pin,
            asked_model,
            walk,
        })
    }

    /// Everything before the send for one walk entry: guard
    /// admission, credential resolution, request construction.
    /// Returns the request to send, or `None` when the entry
    /// resolved without a send (its attempt is already on
    /// record).  A pin failure here is fatal by contract and
    /// returns as the error.
    #[allow(clippy::too_many_arguments)]
    fn prepare_attempt<'l>(
        &self,
        req: &ChatRequest,
        plan: &WalkPlan<'_>,
        lane: &'l Lane,
        model: &str,
        attempt_no: usize,
        attempts: &mut Vec<Attempt>,
        skip_lanes: &mut Vec<&'l str>,
        wire_stream: bool,
    ) -> Result<Option<HttpsRequest>, ModelCallError> {
        // Guard admission.  A denial is an attempt — it is
        // traced, receipted, and (on a pin) fatal.
        if let Err(denial) = self.guard.admit(&lane.name, now_unix_ms()) {
            let attempt = Attempt {
                lane: lane.name.clone(),
                model: model.to_string(),
                outcome: AttemptOutcome::GuardDenied {
                    reason: denial.reason.clone(),
                },
                http_status: None,
                latency_ms: 0,
            };
            self.emit_receipt(
                req,
                &attempt,
                attempt_no,
                plan.pin.is_some(),
                None,
                None,
                None,
            );
            attempts.push(attempt);
            if plan.pin.is_some() {
                return Err(self.pin_failed(
                    &plan.pin,
                    std::mem::take(attempts),
                    format!("guard denied: {}", denial.reason),
                ));
            }
            // The guard judges lanes, not models: a denial
            // stands for the lane's remaining models too.
            skip_lanes.push(lane.name.as_str());
            return Ok(None);
        }

        // Credential resolution for this lane, once per lane
        // (a failure skips the lane's remaining models: the
        // same ref would fail identically for each).
        let mut http_req = HttpsRequest::new(
            Method::Post,
            format!("{}/chat/completions", lane.base_url.trim_end_matches('/')),
        )
        .timeout_ms(lane.timeout_for(model))
        .max_bytes(lane.max_response_bytes)
        .allow_http(lane.allow_http);
        http_req
            .headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        if let Some(cref) = &lane.credential {
            match self.credentials.resolve(cref) {
                Ok(auth) => auth.style.attach(&mut http_req, &auth.value),
                Err(e) => {
                    let attempt = Attempt {
                        lane: lane.name.clone(),
                        model: model.to_string(),
                        outcome: AttemptOutcome::CredentialError {
                            message: e.to_string(),
                        },
                        http_status: None,
                        latency_ms: 0,
                    };
                    self.emit_receipt(
                        req,
                        &attempt,
                        attempt_no,
                        plan.pin.is_some(),
                        None,
                        None,
                        None,
                    );
                    attempts.push(attempt);
                    if plan.pin.is_some() {
                        return Err(self.pin_failed(
                            &plan.pin,
                            std::mem::take(attempts),
                            e.to_string(),
                        ));
                    }
                    // Skip the rest of this lane's models:
                    // they share the same unresolvable ref.
                    skip_lanes.push(lane.name.as_str());
                    return Ok(None);
                }
            }
        }

        // The provider body: extra fields first, reserved
        // keys written by the core over them.
        let mut body = serde_json::Map::new();
        for (k, v) in &req.extra {
            body.insert(k.clone(), v.clone());
        }
        body.insert("model".to_string(), Value::String(model.to_string()));
        body.insert(
            "messages".to_string(),
            serde_json::to_value(&req.messages).unwrap_or(Value::Null),
        );
        body.insert("stream".to_string(), Value::Bool(wire_stream));
        if let Some(n) = req.max_tokens {
            body.insert("max_tokens".to_string(), Value::from(n));
        }
        if let Some(t) = req.temperature {
            body.insert(
                "temperature".to_string(),
                serde_json::Number::from_f64(t).map(Value::Number).unwrap_or(Value::Null),
            );
        }
        http_req.body = Some(
            serde_json::to_vec(&Value::Object(body)).unwrap_or_default(),
        );

        Ok(Some(http_req))
    }

    /// Record one send's outcome — guard accounting, the
    /// receipt, and the walk's next step.  This is the whole of
    /// the response-side policy (success and substitution, pin
    /// loudness, failover statuses, terminal caller errors);
    /// the sync and async drivers share it verbatim.
    #[allow(clippy::too_many_arguments)]
    fn record_outcome<'l>(
        &self,
        req: &ChatRequest,
        plan: &WalkPlan<'_>,
        lane: &'l Lane,
        model: &str,
        attempt_no: usize,
        sent: Result<HttpsResponse, TransportError>,
        latency_ms: u64,
        attempts: &mut Vec<Attempt>,
        skip_lanes: &mut Vec<&'l str>,
    ) -> Flow {
        match sent {
            Err(te) => {
                let attempt = Attempt {
                    lane: lane.name.clone(),
                    model: model.to_string(),
                    outcome: AttemptOutcome::TransportError {
                        message: te.to_string(),
                    },
                    http_status: None,
                    latency_ms,
                };
                self.guard
                    .record_outcome(&lane.name, now_unix_ms(), false);
                self.emit_receipt(
                    req,
                    &attempt,
                    attempt_no,
                    plan.pin.is_some(),
                    None,
                    None,
                    None,
                );
                attempts.push(attempt);
                if plan.pin.is_some() {
                    return Flow::Done(Err(self.pin_failed(
                        &plan.pin,
                        std::mem::take(attempts),
                        te.to_string(),
                    )));
                }
                if !self.config.failover.failover_on_transport_error {
                    return Flow::Break;
                }
                Flow::Continue
            }
            Ok(resp) => {
                let status = resp.status;
                if (200..300).contains(&status) {
                    match parse_completion(&resp.body) {
                        Ok((content, from_reasoning, served, usage, raw)) => {
                            let attempt = Attempt {
                                lane: lane.name.clone(),
                                model: model.to_string(),
                                outcome: AttemptOutcome::Success,
                                http_status: Some(status),
                                latency_ms,
                            };
                            let substituted = match (&served, &plan.asked_model) {
                                (Some(s), Some(a)) => s != a,
                                _ => false,
                            };
                            self.guard
                                .record_outcome(&lane.name, now_unix_ms(), true);
                            self.emit_receipt(
                                req,
                                &attempt,
                                attempt_no,
                                plan.pin.is_some(),
                                served.clone(),
                                usage,
                                Some(substituted),
                            );
                            attempts.push(attempt);
                            Flow::Done(Ok(ChatResponse {
                                content,
                                content_from_reasoning: from_reasoning,
                                lane: lane.name.clone(),
                                model_requested: req.model.clone(),
                                model_sent: model.to_string(),
                                model_served: served,
                                substituted,
                                pin: plan.pin.clone(),
                                http_status: status,
                                usage,
                                attempts: std::mem::take(attempts),
                                raw,
                            }))
                        }
                        Err(msg) => {
                            let attempt = Attempt {
                                lane: lane.name.clone(),
                                model: model.to_string(),
                                outcome: AttemptOutcome::ParseError { message: msg },
                                http_status: Some(status),
                                latency_ms,
                            };
                            self.guard
                                .record_outcome(&lane.name, now_unix_ms(), false);
                            self.emit_receipt(
                                req,
                                &attempt,
                                attempt_no,
                                plan.pin.is_some(),
                                None,
                                None,
                                None,
                            );
                            attempts.push(attempt);
                            if plan.pin.is_some() {
                                return Flow::Done(Err(self.pin_failed(
                                    &plan.pin,
                                    std::mem::take(attempts),
                                    "provider answered the pin with an unparseable completion".to_string(),
                                )));
                            }
                            Flow::Continue
                        }
                    }
                } else if self.config.failover.status_fails_over(status) {
                    let attempt = Attempt {
                        lane: lane.name.clone(),
                        model: model.to_string(),
                        outcome: AttemptOutcome::HttpStatus { status },
                        http_status: Some(status),
                        latency_ms,
                    };
                    self.guard
                        .record_outcome(&lane.name, now_unix_ms(), false);
                    self.emit_receipt(
                        req,
                        &attempt,
                        attempt_no,
                        plan.pin.is_some(),
                        None,
                        None,
                        None,
                    );
                    attempts.push(attempt);
                    if plan.pin.is_some() {
                        return Flow::Done(Err(self.pin_failed(
                            &plan.pin,
                            std::mem::take(attempts),
                            format!("provider returned HTTP {status}"),
                        )));
                    }
                    if status == 429 && lane.abort_lane_on_429 {
                        // Account-level 429: rotating this
                        // lane's models cannot help (the
                        // router's stated NVIDIA rule).
                        skip_lanes.push(lane.name.as_str());
                    }
                    Flow::Continue
                } else {
                    // Terminal status: the provider's answer
                    // stands, at once (the router's
                    // caller-caused rule).
                    let attempt = Attempt {
                        lane: lane.name.clone(),
                        model: model.to_string(),
                        outcome: AttemptOutcome::CallerError { status },
                        http_status: Some(status),
                        latency_ms,
                    };
                    self.guard
                        .record_outcome(&lane.name, now_unix_ms(), false);
                    self.emit_receipt(
                        req,
                        &attempt,
                        attempt_no,
                        plan.pin.is_some(),
                        None,
                        None,
                        None,
                    );
                    attempts.push(attempt);
                    Flow::Done(Err(ModelCallError::ProviderError {
                        lane: lane.name.clone(),
                        model: model.to_string(),
                        status,
                        body: resp.body_text_lossy(),
                        attempts: std::mem::take(attempts),
                    }))
                }
            }
        }
    }

    /// Record a streaming attempt that reached a serving (2xx)
    /// head: the success half of `record_outcome`, with the
    /// served model read off the stream by the peek and no usage
    /// (a stream's opening states none; the JS records its
    /// streaming successes with zero tokens for the same reason).
    /// Returns the result's meta with the attempts moved in.
    #[allow(clippy::too_many_arguments)]
    fn record_stream_success(
        &self,
        req: &ChatRequest,
        plan: &WalkPlan<'_>,
        lane: &Lane,
        model: &str,
        attempt_no: usize,
        status: u16,
        latency_ms: u64,
        served: Option<String>,
        attempts: &mut Vec<Attempt>,
    ) -> StreamMeta {
        let attempt = Attempt {
            lane: lane.name.clone(),
            model: model.to_string(),
            outcome: AttemptOutcome::Success,
            http_status: Some(status),
            latency_ms,
        };
        let substituted = match (&served, &plan.asked_model) {
            (Some(s), Some(a)) => s != a,
            _ => false,
        };
        self.guard
            .record_outcome(&lane.name, now_unix_ms(), true);
        self.emit_receipt(
            req,
            &attempt,
            attempt_no,
            plan.pin.is_some(),
            served.clone(),
            None,
            Some(substituted),
        );
        attempts.push(attempt);
        StreamMeta {
            lane: lane.name.clone(),
            model_requested: req.model.clone(),
            model_sent: model.to_string(),
            model_served: served,
            substituted,
            pin: plan.pin.clone(),
            http_status: status,
            attempts: std::mem::take(attempts),
        }
    }

    /// A streaming walk reuses `record_outcome` for every
    /// non-serving outcome; its `Flow::Done` there always carries
    /// an error (a whole-body success cannot arise from a
    /// transport error or a non-2xx head).  An `Ok` would be a
    /// driver bug — surfaced, never swallowed.
    fn stream_done_err(result: Result<ChatResponse, ModelCallError>) -> ModelCallError {
        match result {
            Err(e) => e,
            Ok(_) => ModelCallError::Unsupported(
                "internal: a whole-body outcome surfaced in a streaming walk".to_string(),
            ),
        }
    }

    /// The walk ended with no serving attempt: the pin's loud
    /// failure, or the all-lanes summary over the attempts on
    /// record.
    fn finish(
        &self,
        plan: WalkPlan<'_>,
        attempts: Vec<Attempt>,
    ) -> Result<ChatResponse, ModelCallError> {
        match &plan.pin {
            Some(_) => Err(self.pin_failed(&plan.pin, attempts, "the pinned lane made no attempt".to_string())),
            None => {
                let summary = attempts
                    .iter()
                    .map(|a| {
                        format!(
                            "{}:{} → {}",
                            a.lane,
                            a.model,
                            a.outcome.error_string().unwrap_or_else(|| "ok".to_string())
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(ModelCallError::AllLanesFailed {
                    message: summary,
                    attempts,
                })
            }
        }
    }

    fn pin_failed(
        &self,
        pin: &Option<Pin>,
        attempts: Vec<Attempt>,
        message: String,
    ) -> ModelCallError {
        let pin = pin.as_ref().expect("pin_failed called with a pin");
        ModelCallError::PinFailed {
            lane: pin.lane.clone(),
            model: pin.model.clone(),
            attempts,
            message,
        }
    }

    /// Append this attempt's receipt to the sink.  Receipts
    /// are written for every attempt outcome, before the walk
    /// moves on — a crash mid-walk still leaves the attempts
    /// that happened on the record.
    fn emit_receipt(
        &self,
        req: &ChatRequest,
        attempt: &Attempt,
        attempt_no: usize,
        pinned: bool,
        model_returned: Option<String>,
        usage: Option<Usage>,
        substituted: Option<bool>,
    ) {
        let now = now_unix_ms();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let ok = attempt.outcome.is_success();
        // Unique per attempt across caller instances too: the
        // estate shape (prefix + timestamp + discriminator)
        // with a short content hash as the discriminator.
        let digest = Sha256::digest(
            format!("{seq}|{now}|{}|{}", attempt.lane, attempt.model).as_bytes(),
        );
        let call_id = format!(
            "mc-{}-{:06}-{}",
            compact_ts(now),
            seq,
            &hex::encode(digest)[..6]
        );
        self.sink.record(&CallReceipt {
            call_id,
            model: attempt.model.clone(),
            model_requested: req.model.clone(),
            model_returned,
            lane: attempt.lane.clone(),
            pinned,
            substituted: substituted.unwrap_or(false),
            status: if ok { "ok" } else { "error" }.to_string(),
            http: attempt.http_status,
            prompt_chars: req.prompt_chars(),
            max_tokens_requested: req.max_tokens,
            prompt_tokens: usage.and_then(|u| u.prompt_tokens),
            completion_tokens: usage.and_then(|u| u.completion_tokens),
            total_tokens: usage.and_then(|u| u.total_tokens),
            latency_ms: attempt.latency_ms,
            ts: iso_ts(now),
            tool: "ref-model-call-live".to_string(),
            attempt: attempt_no,
            endpoint: "/chat/completions".to_string(),
            purpose: req.purpose.clone(),
            error: attempt.outcome.error_string(),
        });
    }
}

impl<T, C, G, S> ModelCaller<T, C, G, S>
where
    T: HttpsTransport + Send + Sync,
    C: CredentialResolver,
    G: CallGuard,
    S: ReceiptSink,
{
    /// Perform one chat call under the pin / failover /
    /// substitution contract described in the crate docs.
    /// The walk is planned once (`plan`), each entry prepared
    /// (`prepare_attempt`), and each send's outcome recorded
    /// (`record_outcome`) — the same shared steps the async
    /// driver runs; only the send differs.
    pub fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, ModelCallError> {
        let plan = self.plan(req)?;
        let mut attempts: Vec<Attempt> = Vec::new();
        let mut skip_lanes: Vec<&str> = Vec::new();
        for (lane, model) in &plan.walk {
            if skip_lanes.contains(&lane.name.as_str()) {
                continue;
            }
            if let Some(cap) = self.config.failover.max_attempts {
                if attempts.len() >= cap {
                    break;
                }
            }
            let attempt_no = attempts.len() + 1;
            let Some(http_req) = self.prepare_attempt(
                req,
                &plan,
                lane,
                model,
                attempt_no,
                &mut attempts,
                &mut skip_lanes,
                false,
            )? else {
                continue;
            };
            let started = mark_now();
            let sent = self.transport.send(&http_req);
            let latency_ms = started.elapsed_ms();
            match self.record_outcome(
                req,
                &plan,
                lane,
                model,
                attempt_no,
                sent,
                latency_ms,
                &mut attempts,
                &mut skip_lanes,
            ) {
                Flow::Continue => continue,
                Flow::Break => break,
                Flow::Done(result) => return result,
            }
        }
        self.finish(plan, attempts)
    }
}

impl<T, C, G, S> ModelCaller<T, C, G, S>
where
    T: AsyncHttpsTransport,
    C: CredentialResolver,
    G: CallGuard,
    S: ReceiptSink,
{
    /// The asynchronous twin of [`ModelCaller::chat`]: the
    /// identical plan, preparation, outcome recording, and
    /// finish — the pin / failover / substitution / receipt
    /// policy is the shared code above, not a second copy.
    /// The only difference is the send itself, awaited on the
    /// [`AsyncHttpsTransport`] seam.  This is the path a
    /// wasm32 host (a Worker) runs: its only send is the async
    /// host fetch behind org-026's `send_async`, reached via
    /// the `HostTransport` bridge impl.
    pub async fn chat_async(&self, req: &ChatRequest) -> Result<ChatResponse, ModelCallError> {
        let plan = self.plan(req)?;
        let mut attempts: Vec<Attempt> = Vec::new();
        let mut skip_lanes: Vec<&str> = Vec::new();
        for (lane, model) in &plan.walk {
            if skip_lanes.contains(&lane.name.as_str()) {
                continue;
            }
            if let Some(cap) = self.config.failover.max_attempts {
                if attempts.len() >= cap {
                    break;
                }
            }
            let attempt_no = attempts.len() + 1;
            let Some(http_req) = self.prepare_attempt(
                req,
                &plan,
                lane,
                model,
                attempt_no,
                &mut attempts,
                &mut skip_lanes,
                false,
            )? else {
                continue;
            };
            let started = mark_now();
            let sent = self.transport.send_async(&http_req).await;
            let latency_ms = started.elapsed_ms();
            match self.record_outcome(
                req,
                &plan,
                lane,
                model,
                attempt_no,
                sent,
                latency_ms,
                &mut attempts,
                &mut skip_lanes,
            ) {
                Flow::Continue => continue,
                Flow::Break => break,
                Flow::Done(result) => return result,
            }
        }
        self.finish(plan, attempts)
    }
}




/// Drain a non-2xx stream head's body, bounded by the lane's
/// cap, for classification as a whole-body response.  A chunk
/// error mid-drain leaves the partial body flagged truncated —
/// the failover classification never reads the body, and a
/// terminal status shows what arrived.
fn drain_sync(
    chunks: &mut (dyn Iterator<Item = Result<Vec<u8>, TransportError>> + Send),
    cap: usize,
) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(item) = chunks.next() {
        match item {
            Ok(bytes) => {
                let room = cap.saturating_sub(body.len());
                if bytes.len() > room {
                    body.extend_from_slice(&bytes[..room]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&bytes);
            }
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    (body, truncated)
}

/// The async twin of [`drain_sync`].
async fn drain_async(chunks: &mut ChunkStream, cap: usize) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(item) = next_chunk(chunks).await {
        match item {
            Ok(bytes) => {
                let room = cap.saturating_sub(body.len());
                if bytes.len() > room {
                    body.extend_from_slice(&bytes[..room]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&bytes);
            }
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    (body, truncated)
}

/// Pull the next chunk off an async chunk stream.
async fn next_chunk(stream: &mut ChunkStream) -> Option<Result<Vec<u8>, TransportError>> {
    std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

impl<T, C, G, S> ModelCaller<T, C, G, S>
where
    T: StreamTransport,
    C: CredentialResolver,
    G: CallGuard,
    S: ReceiptSink,
{
    /// Perform one streaming chat call.  The walk is the
    /// whole-body drivers' walk — same plan (inverted shape
    /// rule), same preparation (with `stream: true` on the
    /// wire), same outcome recording for every non-serving
    /// outcome.  The difference is the serving outcome: a 2xx
    /// head is a success the moment it lands (the JS records its
    /// streaming success at exactly that point), the driver
    /// peeks at the opening events to surface the provider's
    /// stated model, and the caller receives the live stream —
    /// peeked prefix first.  A stream that dies after its head
    /// is the consumer's to observe (its error rides the chunk
    /// sequence); the walk never resumes — there is no lane hop
    /// mid-stream, on a pin or off one.
    pub fn chat_stream(&self, req: &ChatRequest) -> Result<ChatSyncStreamResponse, ModelCallError> {
        let plan = self.plan_stream(req)?;
        let mut attempts: Vec<Attempt> = Vec::new();
        let mut skip_lanes: Vec<&str> = Vec::new();
        for (lane, model) in &plan.walk {
            if skip_lanes.contains(&lane.name.as_str()) {
                continue;
            }
            if let Some(cap) = self.config.failover.max_attempts {
                if attempts.len() >= cap {
                    break;
                }
            }
            let attempt_no = attempts.len() + 1;
            let Some(http_req) = self.prepare_attempt(
                req,
                &plan,
                lane,
                model,
                attempt_no,
                &mut attempts,
                &mut skip_lanes,
                true,
            )? else {
                continue;
            };
            let started = mark_now();
            let head = self.transport.send_stream(&http_req);
            let latency_ms = started.elapsed_ms();
            let mut resp = match head {
                Err(te) => match self.record_outcome(
                    req,
                    &plan,
                    lane,
                    model,
                    attempt_no,
                    Err(te),
                    latency_ms,
                    &mut attempts,
                    &mut skip_lanes,
                ) {
                    Flow::Continue => continue,
                    Flow::Break => break,
                    Flow::Done(r) => return Err(Self::stream_done_err(r)),
                },
                Ok(r) => r,
            };
            if (200..300).contains(&resp.status) {
                let status = resp.status;
                let mut prefix: Vec<Result<Vec<u8>, TransportError>> = Vec::new();
                let mut scan = SseScan::default();
                let mut peek_err: Option<TransportError> = None;
                let mut eof = false;
                while !scan.settled() {
                    match resp.chunks.next() {
                        Some(Ok(bytes)) => {
                            scan.feed(&bytes);
                            prefix.push(Ok(bytes));
                        }
                        Some(Err(e)) => {
                            peek_err = Some(e);
                            break;
                        }
                        None => {
                            eof = true;
                            break;
                        }
                    }
                }
                let served = if eof { scan.finish() } else { scan.model };
                let meta = self.record_stream_success(
                    req,
                    &plan,
                    lane,
                    model,
                    attempt_no,
                    status,
                    latency_ms,
                    served,
                    &mut attempts,
                );
                let rest: Box<dyn Iterator<Item = Result<Vec<u8>, TransportError>> + Send> =
                    if let Some(e) = peek_err {
                        Box::new(std::iter::once(Err(e)))
                    } else if eof {
                        Box::new(std::iter::empty())
                    } else {
                        resp.chunks
                    };
                return Ok(ChatSyncStreamResponse {
                    meta,
                    chunks: Box::new(prefix.into_iter().chain(rest)),
                });
            }
            let (body, truncated) = drain_sync(&mut *resp.chunks, lane.max_response_bytes);
            let full = HttpsResponse {
                status: resp.status,
                headers: resp.headers,
                body,
                truncated,
            };
            match self.record_outcome(
                req,
                &plan,
                lane,
                model,
                attempt_no,
                Ok(full),
                latency_ms,
                &mut attempts,
                &mut skip_lanes,
            ) {
                Flow::Continue => continue,
                Flow::Break => break,
                Flow::Done(r) => return Err(Self::stream_done_err(r)),
            }
        }
        // finish() only ever errs (the pin's loud failure or the
        // all-lanes summary); stream_done_err states the Ok arm
        // as the driver bug it would be.
        Err(Self::stream_done_err(self.finish(plan, attempts)))
    }
}

impl<T, C, G, S> ModelCaller<T, C, G, S>
where
    T: AsyncStreamTransport,
    C: CredentialResolver,
    G: CallGuard,
    S: ReceiptSink,
{
    /// The asynchronous twin of [`ModelCaller::chat_stream`]:
    /// identical plan, preparation, peek, and outcome recording;
    /// only the send and the chunk pulls are awaited.  This is
    /// the streaming path a wasm32 host (a Worker) runs, over
    /// org-026's host fetch behind the `HostTransport` bridge.
    pub async fn chat_stream_async(
        &self,
        req: &ChatRequest,
    ) -> Result<ChatStreamResponse, ModelCallError> {
        let plan = self.plan_stream(req)?;
        let mut attempts: Vec<Attempt> = Vec::new();
        let mut skip_lanes: Vec<&str> = Vec::new();
        for (lane, model) in &plan.walk {
            if skip_lanes.contains(&lane.name.as_str()) {
                continue;
            }
            if let Some(cap) = self.config.failover.max_attempts {
                if attempts.len() >= cap {
                    break;
                }
            }
            let attempt_no = attempts.len() + 1;
            let Some(http_req) = self.prepare_attempt(
                req,
                &plan,
                lane,
                model,
                attempt_no,
                &mut attempts,
                &mut skip_lanes,
                true,
            )? else {
                continue;
            };
            let started = mark_now();
            let head = self.transport.send_stream_async(&http_req).await;
            let latency_ms = started.elapsed_ms();
            let mut resp = match head {
                Err(te) => match self.record_outcome(
                    req,
                    &plan,
                    lane,
                    model,
                    attempt_no,
                    Err(te),
                    latency_ms,
                    &mut attempts,
                    &mut skip_lanes,
                ) {
                    Flow::Continue => continue,
                    Flow::Break => break,
                    Flow::Done(r) => return Err(Self::stream_done_err(r)),
                },
                Ok(r) => r,
            };
            if (200..300).contains(&resp.status) {
                let status = resp.status;
                let mut prefix: Vec<Result<Vec<u8>, TransportError>> = Vec::new();
                let mut scan = SseScan::default();
                let mut peek_err: Option<TransportError> = None;
                let mut eof = false;
                while !scan.settled() {
                    match next_chunk(&mut resp.chunks).await {
                        Some(Ok(bytes)) => {
                            scan.feed(&bytes);
                            prefix.push(Ok(bytes));
                        }
                        Some(Err(e)) => {
                            peek_err = Some(e);
                            break;
                        }
                        None => {
                            eof = true;
                            break;
                        }
                    }
                }
                let served = if eof { scan.finish() } else { scan.model };
                let meta = self.record_stream_success(
                    req,
                    &plan,
                    lane,
                    model,
                    attempt_no,
                    status,
                    latency_ms,
                    served,
                    &mut attempts,
                );
                let rest = if peek_err.is_some() || eof {
                    None
                } else {
                    Some(resp.chunks)
                };
                return Ok(ChatStreamResponse {
                    meta,
                    chunks: Box::pin(PrefixStream {
                        prefix: prefix.into(),
                        err_once: peek_err,
                        rest,
                    }),
                });
            }
            let (body, truncated) = drain_async(&mut resp.chunks, lane.max_response_bytes).await;
            let full = HttpsResponse {
                status: resp.status,
                headers: resp.headers,
                body,
                truncated,
            };
            match self.record_outcome(
                req,
                &plan,
                lane,
                model,
                attempt_no,
                Ok(full),
                latency_ms,
                &mut attempts,
                &mut skip_lanes,
            ) {
                Flow::Continue => continue,
                Flow::Break => break,
                Flow::Done(r) => return Err(Self::stream_done_err(r)),
            }
        }
        // finish() only ever errs (the pin's loud failure or the
        // all-lanes summary); stream_done_err states the Ok arm
        // as the driver bug it would be.
        Err(Self::stream_done_err(self.finish(plan, attempts)))
    }
}

/// Parse a 2xx body as an OpenAI chat completion.  Returns
/// (content, content_from_reasoning, served model, usage, raw).
fn parse_completion(
    body: &[u8],
) -> Result<(String, bool, Option<String>, Option<Usage>, Value), String> {
    let raw: Value = serde_json::from_slice(body)
        .map_err(|e| format!("provider 2xx body is not JSON: {e}"))?;
    let message = &raw["choices"][0]["message"];
    if message.is_null() {
        return Err("provider 2xx body has no choices[0].message".to_string());
    }
    let (content, from_reasoning) = match message["content"].as_str() {
        Some(c) if !c.is_empty() => (c.to_string(), false),
        _ => match message["reasoning_content"].as_str() {
            Some(r) => (r.to_string(), true),
            None => (String::new(), false),
        },
    };
    let served = raw["model"].as_str().map(|s| s.to_string());
    let usage = if raw["usage"].is_object() {
        Some(Usage {
            prompt_tokens: raw["usage"]["prompt_tokens"].as_u64(),
            completion_tokens: raw["usage"]["completion_tokens"].as_u64(),
            total_tokens: raw["usage"]["total_tokens"].as_u64(),
        })
    } else {
        None
    };
    Ok((content, from_reasoning, served, usage, raw))
}

impl<C, G, S> ModelCaller<ref_https_transport::HostTransport, C, G, S>
where
    C: CredentialResolver,
    G: CallGuard,
    S: ReceiptSink,
{
    /// A caller on the platform default transport (org-026's
    /// ureq/rustls client natively).  On wasm32 the blocking
    /// send reports itself honestly as unsupported; there,
    /// drive the same caller with `chat_async` —
    /// `HostTransport` also implements [`AsyncHttpsTransport`]
    /// over org-026's async host fetch.
    pub fn host(
        config: RouterConfig,
        credentials: C,
        guard: G,
        sink: S,
    ) -> Result<Self, ModelCallError> {
        ModelCaller::new(config, ref_https_transport::HostTransport, credentials, guard, sink)
    }
}

// ---------------------------------------------------------------------
// Organelle trait surface (codon `ml`).  The caller is injected —
// a router configuration is a deployment decision, not a
// constant of this crate.  The bare `organelle()` surface is
// the fail-closed default: no lanes configured, every call an
// honest error.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "model-call-live".to_string(),
        codon: "ml".to_string(),
        version: "1.0.0".to_string(),
        description:
            "production OpenAI-compatible model call: caller-configured lanes, exact-model pins, loud substitution, per-attempt receipts (GAP-10)"
                .to_string(),
        contracts: vec![Contract {
            op: "chat".to_string(),
            description:
                "chat completion under the pin/substitution contract; output reports requested, sent, and served models and the full attempt walk"
                    .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["messages"],
                "properties": {
                    "messages": {
                        "type": "array", "minItems": 1,
                        "items": {
                            "type": "object", "required": ["role", "content"],
                            "properties": {
                                "role": {"type": "string"},
                                "content": {}
                            }
                        }
                    },
                    "model": {"type": "string"},
                    "max_tokens": {"type": "integer", "minimum": 1},
                    "temperature": {"type": "number"},
                    "purpose": {"type": "string"}
                }
            }),
            mutation_class: Some(MutationClass::ExternalEffect),
            required_capability: Some("model.call".to_string()),
        }],
        authority: Authority {
            mutation_class: MutationClass::ExternalEffect,
            declared_valence: Valence::Candidate,
            required_capability: Some("model.call".to_string()),
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
pub struct ModelCallLiveOrganelle<T, C, G, S>
where
    T: HttpsTransport + Send + Sync,
    C: CredentialResolver,
    G: CallGuard,
    S: ReceiptSink,
{
    manifest: OrganelleManifest,
    caller: Arc<ModelCaller<T, C, G, S>>,
}

#[cfg(feature = "organelle")]
pub fn organelle_with_caller<T, C, G, S>(
    caller: Arc<ModelCaller<T, C, G, S>>,
) -> Arc<dyn Organelle>
where
    T: HttpsTransport + Send + Sync + 'static,
    C: CredentialResolver + 'static,
    G: CallGuard + 'static,
    S: ReceiptSink + 'static,
{
    Arc::new(ModelCallLiveOrganelle {
        manifest: manifest(),
        caller,
    })
}

/// The fail-closed default surface: a caller with no lanes.
/// Every `chat` call errors with the configuration message and
/// nothing is sent anywhere.
#[cfg(feature = "organelle")]
pub fn organelle() -> Arc<dyn Organelle> {
    let caller = ModelCaller::unconfigured(
        ref_https_transport::HostTransport,
        NoCredentials,
        NoGuard,
        NoopSink,
    );
    Arc::new(ModelCallLiveOrganelle {
        manifest: manifest(),
        caller: Arc::new(caller),
    })
}

#[cfg(feature = "organelle")]
impl<T, C, G, S> Organelle for ModelCallLiveOrganelle<T, C, G, S>
where
    T: HttpsTransport + Send + Sync,
    C: CredentialResolver,
    G: CallGuard,
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
        if op != "chat" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        // Egress: every configured lane's base must pass the
        // host's allowlist before any send (the org-023 / org-026
        // policy seam).  An unconfigured caller has no lanes and
        // fails in chat() without any approval being relevant.
        for lane in &self.caller.config().lanes {
            host.approve_egress(&lane.base_url)?;
        }
        let messages: Vec<ChatMessage> = input["messages"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|m| ChatMessage {
                        role: m["role"].as_str().unwrap_or("").to_string(),
                        content: m["content"].clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut req = ChatRequest::new(messages);
        if let Some(m) = input["model"].as_str() {
            req.model = Some(m.to_string());
        }
        if let Some(n) = input["max_tokens"].as_u64() {
            req.max_tokens = Some(n as u32);
        }
        if let Some(t) = input["temperature"].as_f64() {
            req.temperature = Some(t);
        }
        if let Some(p) = input["purpose"].as_str() {
            req.purpose = Some(p.to_string());
        }
        match self.caller.chat(&req) {
            Ok(r) => Ok(serde_json::json!({
                "reply": r.content,
                "content_from_reasoning": r.content_from_reasoning,
                "lane": r.lane,
                "model_requested": r.model_requested,
                "model_sent": r.model_sent,
                "model_served": r.model_served,
                "substituted": r.substituted,
                "pinned": r.pin.as_ref().map(|p| serde_json::json!({
                    "lane": p.lane, "model": p.model, "raw": p.raw,
                })),
                "http_status": r.http_status,
                "usage": r.usage.map(|u| serde_json::json!({
                    "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                    "total_tokens": u.total_tokens,
                })),
                "attempts": serde_json::to_value(&r.attempts).unwrap_or(Value::Null),
                "stub": false,
            })),
            Err(e) => Err(OrganelleError::failed(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The mock-transport tests are deterministic and offline;
// the fixture test runs a real local HTTP server through the
// real org-026 transport; the live NIM proof is a separate
// env-gated integration test (tests/live_nim.rs).
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ref_https_transport::{HttpsResponse, TransportError};
    use std::sync::Mutex;

    #[derive(Clone)]
    pub(crate) struct ScriptedTransport {
        requests: Arc<Mutex<Vec<HttpsRequest>>>,
        handler:
            Arc<dyn Fn(&HttpsRequest) -> Result<HttpsResponse, TransportError> + Send + Sync>,
    }

    impl ScriptedTransport {
        pub(crate) fn new(
            handler: impl Fn(&HttpsRequest) -> Result<HttpsResponse, TransportError>
                + Send
                + Sync
                + 'static,
        ) -> Self {
            ScriptedTransport {
                requests: Arc::new(Mutex::new(vec![])),
                handler: Arc::new(handler),
            }
        }

        pub(crate) fn sent(&self) -> Vec<HttpsRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl HttpsTransport for ScriptedTransport {
        fn send(&self, req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
            self.requests.lock().unwrap().push(req.clone());
            (self.handler)(req)
        }
    }

    /// The same script through the async seam: the async
    /// proofs below drive `chat_async` over the identical
    /// handler, so a sync/async divergence can only come from
    /// the walk itself.
    impl AsyncHttpsTransport for ScriptedTransport {
        fn send_async<'a>(
            &'a self,
            req: &'a HttpsRequest,
        ) -> TransportFuture<'a, Result<HttpsResponse, TransportError>> {
            Box::pin(async move { self.send(req) })
        }
    }

    /// A park/unpark block_on (the org-031 test pattern),
    /// sufficient for futures that resolve without real I/O
    /// waits.
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

    pub(crate) fn ok_json(model: &str, content: &str) -> HttpsResponse {
        let body = serde_json::json!({
            "model": model,
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        });
        HttpsResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
            truncated: false,
        }
    }

    pub(crate) fn status_resp(status: u16) -> HttpsResponse {
        HttpsResponse {
            status,
            headers: vec![],
            body: br#"{"error":{"message":"nope"}}"#.to_vec(),
            truncated: false,
        }
    }

    pub(crate) fn echo_model(req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
        let body: Value = serde_json::from_slice(req.body.as_deref().unwrap_or(b"{}")).unwrap();
        let model = body["model"].as_str().unwrap_or("").to_string();
        Ok(ok_json(&model, "hello"))
    }

    pub(crate) fn sent_model(req: &HttpsRequest) -> String {
        let body: Value = serde_json::from_slice(req.body.as_deref().unwrap_or(b"{}")).unwrap();
        body["model"].as_str().unwrap_or("").to_string()
    }

    pub(crate) fn lane(name: &str, models: &[&str]) -> Lane {
        Lane {
            name: name.to_string(),
            base_url: format!("https://{name}.test/v1"),
            credential: None,
            models: models.iter().map(|s| s.to_string()).collect(),
            strategy: ModelStrategy::PoolOrder,
            timeout_ms: 5_000,
            model_timeouts_ms: vec![],
            max_response_bytes: 1_048_576,
            allow_http: false,
            abort_lane_on_429: false,
        }
    }

    pub(crate) fn policy() -> FailoverPolicy {
        FailoverPolicy {
            failover_statuses: vec![401, 403, 404, 429],
            failover_on_5xx: true,
            failover_on_transport_error: true,
            max_attempts: None,
        }
    }

    pub(crate) fn config(lanes: Vec<Lane>) -> RouterConfig {
        RouterConfig {
            lanes,
            aliases: vec![],
            failover: policy(),
        }
    }

    pub(crate) fn req() -> ChatRequest {
        ChatRequest::new(vec![ChatMessage::text("user", "say hello")])
    }

    pub(crate) type TestCaller = ModelCaller<ScriptedTransport, MemoryCredentials, NoGuard, MemorySink>;

    pub(crate) fn caller(config: RouterConfig, transport: ScriptedTransport) -> TestCaller {
        ModelCaller::new(
            config,
            transport,
            MemoryCredentials::new(),
            NoGuard,
            MemorySink::new(),
        )
        .unwrap()
    }

    // -- time ----------------------------------------------------

    #[test]
    fn iso_ts_is_exact() {
        assert_eq!(iso_ts(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_ts(1_735_689_600_000), "2025-01-01T00:00:00Z");
        assert_eq!(iso_ts(1_795_405_565_000), "2026-11-23T03:46:05Z");
        assert_eq!(compact_ts(1_795_405_565_000), "20261123T034605");
    }

    // -- pins ------------------------------------------------------

    fn nvidia_config() -> RouterConfig {
        let mut cfg = config(vec![
            lane(
                "nvidia",
                &["nvidia/nemotron-3-ultra-550b-a55b", "nvidia/nemotron-3.5-bolt-e4b"],
            ),
            lane("groq", &["llama-3.3-70b-versatile"]),
        ]);
        cfg.aliases = vec![("nim".to_string(), "nvidia".to_string())];
        cfg
    }

    #[test]
    fn parse_pin_shapes() {
        let cfg = nvidia_config();
        let p = parse_pin("nim/nvidia/nemotron-3-ultra-550b-a55b", &cfg).unwrap();
        assert_eq!(p.lane, "nvidia");
        assert_eq!(p.model, "nvidia/nemotron-3-ultra-550b-a55b");
        let p2 = parse_pin("nvidia/meta/llama-3.3-70b-instruct", &cfg).unwrap();
        assert_eq!(p2.lane, "nvidia");
        assert_eq!(p2.model, "meta/llama-3.3-70b-instruct");
        // Unknown prefix → not a pin (the router's rule).
        assert!(parse_pin("openai/gpt-5", &cfg).is_none());
        assert!(parse_pin("plain-model", &cfg).is_none());
        assert!(parse_pin("/leading-slash", &cfg).is_none());
        assert!(parse_pin("nvidia/", &cfg).is_none());
    }

    #[test]
    fn pin_success_is_exact_and_unsubstituted() {
        let transport = ScriptedTransport::new(echo_model);
        let probe = transport.clone();
        let c = caller(nvidia_config(), transport);
        let out = c
            .chat(&req().model("nim/nvidia/nemotron-3-ultra-550b-a55b"))
            .unwrap();
        assert_eq!(out.lane, "nvidia");
        assert_eq!(out.model_sent, "nvidia/nemotron-3-ultra-550b-a55b");
        assert_eq!(
            out.model_served.as_deref(),
            Some("nvidia/nemotron-3-ultra-550b-a55b")
        );
        assert!(!out.substituted);
        assert_eq!(out.pin.as_ref().unwrap().lane, "nvidia");
        let sent = probe.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].url.starts_with("https://nvidia.test/"));
        assert_eq!(sent_model(&sent[0]), "nvidia/nemotron-3-ultra-550b-a55b");
    }

    /// Required proof (a): a failing pin is attempted ONLY on
    /// its lane, and the error names the pin.
    #[test]
    fn pin_failure_is_loud_and_attempted_alone() {
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("nvidia.test") {
                Err(TransportError::Network("connection refused".to_string()))
            } else {
                echo_model(req)
            }
        });
        let probe = transport.clone();
        let c = caller(nvidia_config(), transport);
        let err = c
            .chat(&req().model("nim/nvidia/nemotron-3-ultra-550b-a55b"))
            .unwrap_err();
        match &err {
            ModelCallError::PinFailed {
                lane,
                model,
                attempts,
                ..
            } => {
                assert_eq!(lane, "nvidia");
                assert_eq!(model, "nvidia/nemotron-3-ultra-550b-a55b");
                assert_eq!(attempts.len(), 1);
            }
            other => panic!("expected PinFailed, got {other}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("nvidia"), "error names the lane: {msg}");
        assert!(
            msg.contains("nvidia/nemotron-3-ultra-550b-a55b"),
            "error names the model: {msg}"
        );
        assert!(msg.contains("no substitution attempted"), "{msg}");
        // Exactly one request was sent, to the pinned lane only.
        let sent = probe.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].url.starts_with("https://nvidia.test/"));
        // And the failed attempt left its receipt.
        let receipts = c.sink().receipts();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, "error");
        assert!(receipts[0].pinned);
    }

    #[test]
    fn pin_http_failure_is_loud_too() {
        let transport = ScriptedTransport::new(|_req| Ok(status_resp(503)));
        let c = caller(nvidia_config(), transport);
        let err = c
            .chat(&req().model("nvidia/nvidia/nemotron-3-ultra-550b-a55b"))
            .unwrap_err();
        assert!(matches!(err, ModelCallError::PinFailed { .. }));
    }

    #[test]
    fn pin_credential_failure_sends_nothing() {
        let mut nvidia = lane("nvidia", &["nvidia/nemotron-3-ultra-550b-a55b"]);
        nvidia.credential = Some(CredentialRef::new("nvidia-nim", "nim").unwrap());
        let transport = ScriptedTransport::new(echo_model);
        let probe = transport.clone();
        let c: ModelCaller<ScriptedTransport, NoCredentials, NoGuard, MemorySink> =
            ModelCaller::new(
                config(vec![nvidia, lane("groq", &["llama"])]),
                transport,
                NoCredentials,
                NoGuard,
                MemorySink::new(),
            )
            .unwrap();
        let err = c
            .chat(&req().model("nvidia/nvidia/nemotron-3-ultra-550b-a55b"))
            .unwrap_err();
        assert!(matches!(err, ModelCallError::PinFailed { .. }));
        assert_eq!(probe.sent().len(), 0);
        let receipts = c.sink().receipts();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].error.as_deref().unwrap().contains("credential"));
    }

    /// A provider that answers a pin with a DIFFERENT model
    /// field has substituted, and the response says so in-band.
    #[test]
    fn pin_answered_by_another_model_is_loud_substitution() {
        let transport = ScriptedTransport::new(|_req| {
            Ok(ok_json("poolside/laguna-xs-2.1", "sneaky"))
        });
        let c = caller(nvidia_config(), transport);
        let out = c
            .chat(&req().model("nim/nvidia/nemotron-3-ultra-550b-a55b"))
            .unwrap();
        assert!(out.substituted);
        assert_eq!(
            out.model_served.as_deref(),
            Some("poolside/laguna-xs-2.1")
        );
        assert!(c.sink().receipts()[0].substituted);
    }

    // -- unpinned failover ----------------------------------------

    /// Required proof (b): unpinned failover follows caller lane
    /// order, and a different serving model is reported with
    /// substituted = true and both names present.
    #[test]
    fn unpinned_failover_follows_order_and_reports_substitution() {
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("a.test") {
                Ok(status_resp(503))
            } else {
                echo_model(req)
            }
        });
        let c = caller(
            config(vec![lane("a", &["a-model"]), lane("b", &["b-model"])]),
            transport,
        );
        let out = c.chat(&req().model("a-model")).unwrap();
        assert_eq!(out.lane, "b");
        assert_eq!(out.model_requested.as_deref(), Some("a-model"));
        assert_eq!(out.model_sent, "b-model");
        assert_eq!(out.model_served.as_deref(), Some("b-model"));
        assert!(out.substituted);
        assert_eq!(out.attempts.len(), 2);
        assert_eq!(out.attempts[0].lane, "a");
        assert_eq!(out.attempts[1].lane, "b");
    }

    #[test]
    fn unpinned_matching_model_is_not_substitution() {
        let transport = ScriptedTransport::new(echo_model);
        let c = caller(config(vec![lane("a", &["a-model"])]), transport);
        let out = c.chat(&req()).unwrap();
        assert_eq!(out.model_served.as_deref(), Some("a-model"));
        assert!(!out.substituted);
    }

    #[test]
    fn intra_lane_pool_failover() {
        let transport = ScriptedTransport::new(|req| {
            if sent_model(req) == "m1" {
                Ok(status_resp(500))
            } else {
                echo_model(req)
            }
        });
        let c = caller(config(vec![lane("a", &["m1", "m2"])]), transport);
        let out = c.chat(&req()).unwrap();
        assert_eq!(out.model_sent, "m2");
        assert_eq!(out.attempts.len(), 2);
        assert!(out.attempts.iter().all(|a| a.lane == "a"));
    }

    #[test]
    fn caller_error_status_is_terminal() {
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("a.test") {
                Ok(status_resp(400))
            } else {
                echo_model(req)
            }
        });
        let probe = transport.clone();
        let c = caller(
            config(vec![lane("a", &["a-model"]), lane("b", &["b-model"])]),
            transport,
        );
        let err = c.chat(&req()).unwrap_err();
        match err {
            ModelCallError::ProviderError { status, .. } => assert_eq!(status, 400),
            other => panic!("expected ProviderError, got {other}"),
        }
        assert_eq!(probe.sent().len(), 1);
    }

    #[test]
    fn abort_lane_on_429_skips_the_pool() {
        let mut a = lane("a", &["m1", "m2"]);
        a.abort_lane_on_429 = true;
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("a.test") {
                Ok(status_resp(429))
            } else {
                echo_model(req)
            }
        });
        let c = caller(config(vec![a, lane("b", &["b-model"])]), transport);
        let out = c.chat(&req()).unwrap();
        assert_eq!(out.lane, "b");
        assert_eq!(out.attempts.len(), 2);
        assert_eq!(out.attempts[0].model, "m1");
    }

    #[test]
    fn max_attempts_caps_the_walk() {
        let mut cfg = config(vec![
            lane("a", &["a-model"]),
            lane("b", &["b-model"]),
            lane("c", &["c-model"]),
        ]);
        cfg.failover.max_attempts = Some(2);
        let transport = ScriptedTransport::new(|_req| Ok(status_resp(503)));
        let c = caller(cfg, transport);
        let err = c.chat(&req()).unwrap_err();
        match err {
            ModelCallError::AllLanesFailed { attempts, .. } => {
                assert_eq!(attempts.len(), 2)
            }
            other => panic!("expected AllLanesFailed, got {other}"),
        }
    }

    #[test]
    fn size_rules_express_the_router_pick() {
        let mut nvidia = lane(
            "nvidia",
            &[
                "nvidia/nemotron-3-ultra-550b-a55b",
                "nvidia/nemotron-3.5-bolt-e4b",
                "poolside/laguna-xs-2.1",
            ],
        );
        nvidia.strategy = ModelStrategy::SizeRules {
            rules: vec![
                SizeRule {
                    model: "nvidia/nemotron-3-ultra-550b-a55b".to_string(),
                    vision: None,
                    min_prompt_tokens: Some(4000),
                    prompt_tokens_below: None,
                    min_output_tokens: None,
                    max_output_tokens: None,
                },
                SizeRule {
                    model: "nvidia/nemotron-3-ultra-550b-a55b".to_string(),
                    vision: None,
                    min_prompt_tokens: None,
                    prompt_tokens_below: None,
                    min_output_tokens: Some(4096),
                    max_output_tokens: None,
                },
                SizeRule {
                    model: "nvidia/nemotron-3.5-bolt-e4b".to_string(),
                    vision: None,
                    min_prompt_tokens: None,
                    prompt_tokens_below: Some(1000),
                    min_output_tokens: None,
                    max_output_tokens: Some(512),
                },
            ],
            fallback: "poolside/laguna-xs-2.1".to_string(),
        };
        let transport = ScriptedTransport::new(echo_model);
        let c = caller(config(vec![nvidia]), transport);
        // Dense by prompt size: 20_000 chars ≈ 5_000 tokens.
        let big = ChatRequest::new(vec![ChatMessage::text("user", "x".repeat(20_000))]);
        assert_eq!(
            c.chat(&big).unwrap().model_sent,
            "nvidia/nemotron-3-ultra-550b-a55b"
        );
        // Dense by output budget.
        let wide = req().max_tokens(8192);
        assert_eq!(
            c.chat(&wide).unwrap().model_sent,
            "nvidia/nemotron-3-ultra-550b-a55b"
        );
        // Small: tiny prompt + small budget → bolt.
        let small = req().max_tokens(100);
        assert_eq!(
            c.chat(&small).unwrap().model_sent,
            "nvidia/nemotron-3.5-bolt-e4b"
        );
        // Middle: fallback.
        let mid = req().max_tokens(1024);
        assert_eq!(c.chat(&mid).unwrap().model_sent, "poolside/laguna-xs-2.1");
    }

    // -- receipts ---------------------------------------------------

    /// Required proof (c): every attempt outcome — transport
    /// failure, HTTP failure, success — leaves exactly one
    /// receipt in the estate calls.jsonl shape.
    #[test]
    fn receipts_cover_every_attempt_in_estate_shape() {
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("a.test") {
                Err(TransportError::Network("dns exploded".to_string()))
            } else if req.url.contains("b.test") {
                Ok(status_resp(503))
            } else {
                echo_model(req)
            }
        });
        let c = caller(
            config(vec![
                lane("a", &["a-model"]),
                lane("b", &["b-model"]),
                lane("c", &["c-model"]),
            ]),
            transport,
        );
        let out = c
            .chat(&req().max_tokens(64).purpose("receipt-test"))
            .unwrap();
        assert_eq!(out.lane, "c");
        let receipts = c.sink().receipts();
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0].status, "error");
        assert_eq!(receipts[0].http, None);
        assert!(receipts[0].error.as_deref().unwrap().contains("dns exploded"));
        assert_eq!(receipts[1].status, "error");
        assert_eq!(receipts[1].http, Some(503));
        assert_eq!(receipts[2].status, "ok");
        assert_eq!(receipts[2].model_returned.as_deref(), Some("c-model"));
        assert_eq!(receipts[2].prompt_tokens, Some(10));
        assert_eq!(receipts[2].completion_tokens, Some(5));
        assert_eq!(receipts[2].total_tokens, Some(15));

        // The serialized shape carries the estate fields.
        let v = serde_json::to_value(&receipts[2]).unwrap();
        for key in [
            "call_id",
            "model",
            "model_requested",
            "model_returned",
            "status",
            "http",
            "prompt_chars",
            "max_tokens_requested",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "latency_ms",
            "ts",
            "tool",
            "lane",
            "pinned",
            "substituted",
            "attempt",
            "endpoint",
            "purpose",
        ] {
            assert!(v.get(key).is_some(), "receipt missing estate field {key}: {v}");
        }
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
        assert!(v.get("error").is_none(), "ok receipts omit error: {v}");
        let e = serde_json::to_value(&receipts[0]).unwrap();
        assert!(e["error"].as_str().unwrap().contains("dns exploded"));
    }

    // -- the async walk: the three required proofs, ported ----
    //
    // chat_async must satisfy the same contract as chat, over
    // the same scripted transport: the policy code is shared
    // (plan / prepare_attempt / record_outcome / finish), so
    // these are the sync proofs re-run against the async
    // driver to prove the sharing is real.

    /// Required proof (a), async: a failing pin is attempted
    /// ONLY on its lane, and the error names the pin.
    #[test]
    fn pin_failure_is_loud_and_attempted_alone_async() {
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("nvidia.test") {
                Err(TransportError::Network("connection refused".to_string()))
            } else {
                echo_model(req)
            }
        });
        let probe = transport.clone();
        let c = caller(nvidia_config(), transport);
        let err = block_on(c.chat_async(&req().model("nim/nvidia/nemotron-3-ultra-550b-a55b")))
            .unwrap_err();
        match &err {
            ModelCallError::PinFailed {
                lane,
                model,
                attempts,
                ..
            } => {
                assert_eq!(lane, "nvidia");
                assert_eq!(model, "nvidia/nemotron-3-ultra-550b-a55b");
                assert_eq!(attempts.len(), 1);
            }
            other => panic!("expected PinFailed, got {other}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("nvidia"), "error names the lane: {msg}");
        assert!(
            msg.contains("nvidia/nemotron-3-ultra-550b-a55b"),
            "error names the model: {msg}"
        );
        assert!(msg.contains("no substitution attempted"), "{msg}");
        let sent = probe.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].url.starts_with("https://nvidia.test/"));
        let receipts = c.sink().receipts();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, "error");
        assert!(receipts[0].pinned);
    }

    /// Required proof (b), async: unpinned failover follows
    /// caller lane order, and a different serving model is
    /// reported with substituted = true and both names present.
    #[test]
    fn unpinned_failover_follows_order_and_reports_substitution_async() {
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("a.test") {
                Ok(status_resp(503))
            } else {
                echo_model(req)
            }
        });
        let c = caller(
            config(vec![lane("a", &["a-model"]), lane("b", &["b-model"])]),
            transport,
        );
        let out = block_on(c.chat_async(&req().model("a-model"))).unwrap();
        assert_eq!(out.lane, "b");
        assert_eq!(out.model_requested.as_deref(), Some("a-model"));
        assert_eq!(out.model_sent, "b-model");
        assert_eq!(out.model_served.as_deref(), Some("b-model"));
        assert!(out.substituted);
        assert_eq!(out.attempts.len(), 2);
        assert_eq!(out.attempts[0].lane, "a");
        assert_eq!(out.attempts[1].lane, "b");
    }

    /// Required proof (c), async: every attempt outcome —
    /// transport failure, HTTP failure, success — leaves
    /// exactly one receipt in the estate calls.jsonl shape.
    #[test]
    fn receipts_cover_every_attempt_in_estate_shape_async() {
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("a.test") {
                Err(TransportError::Network("dns exploded".to_string()))
            } else if req.url.contains("b.test") {
                Ok(status_resp(503))
            } else {
                echo_model(req)
            }
        });
        let c = caller(
            config(vec![
                lane("a", &["a-model"]),
                lane("b", &["b-model"]),
                lane("c", &["c-model"]),
            ]),
            transport,
        );
        let out = block_on(c.chat_async(&req().max_tokens(64).purpose("receipt-test"))).unwrap();
        assert_eq!(out.lane, "c");
        let receipts = c.sink().receipts();
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0].status, "error");
        assert_eq!(receipts[0].http, None);
        assert!(receipts[0].error.as_deref().unwrap().contains("dns exploded"));
        assert_eq!(receipts[1].status, "error");
        assert_eq!(receipts[1].http, Some(503));
        assert_eq!(receipts[2].status, "ok");
        assert_eq!(receipts[2].model_returned.as_deref(), Some("c-model"));
        assert_eq!(receipts[2].prompt_tokens, Some(10));
        assert_eq!(receipts[2].completion_tokens, Some(5));
        assert_eq!(receipts[2].total_tokens, Some(15));

        let v = serde_json::to_value(&receipts[2]).unwrap();
        for key in [
            "call_id",
            "model",
            "model_requested",
            "model_returned",
            "status",
            "http",
            "prompt_chars",
            "max_tokens_requested",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "latency_ms",
            "ts",
            "tool",
            "lane",
            "pinned",
            "substituted",
            "attempt",
            "endpoint",
            "purpose",
        ] {
            assert!(v.get(key).is_some(), "receipt missing estate field {key}: {v}");
        }
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
        assert!(v.get("error").is_none(), "ok receipts omit error: {v}");
        let e = serde_json::to_value(&receipts[0]).unwrap();
        assert!(e["error"].as_str().unwrap().contains("dns exploded"));
    }

    #[test]
    fn failed_call_receipts_match_attempts() {
        let transport = ScriptedTransport::new(|_req| Ok(status_resp(503)));
        let c = caller(
            config(vec![lane("a", &["a-model"]), lane("b", &["b-model"])]),
            transport,
        );
        let err = c.chat(&req()).unwrap_err();
        let attempts = match err {
            ModelCallError::AllLanesFailed { attempts, .. } => attempts,
            other => panic!("expected AllLanesFailed, got {other}"),
        };
        assert_eq!(attempts.len(), 2);
        assert_eq!(c.sink().receipts().len(), attempts.len());
        assert!(c.sink().receipts().iter().all(|r| r.status == "error"));
    }

    // -- guards -----------------------------------------------------

    struct DenyLane(&'static str);

    impl CallGuard for DenyLane {
        fn admit(&self, lane: &str, _now_ms: i64) -> Result<(), GuardDenial> {
            if lane == self.0 {
                Err(GuardDenial {
                    reason: format!("lane {lane} is cooling down"),
                    retry_at_ms: Some(123),
                })
            } else {
                Ok(())
            }
        }
        fn record_outcome(&self, _lane: &str, _now_ms: i64, _success: bool) {}
    }

    #[test]
    fn guard_denial_is_an_attempt_and_the_walk_moves_on() {
        let transport = ScriptedTransport::new(echo_model);
        let probe = transport.clone();
        let c: ModelCaller<ScriptedTransport, MemoryCredentials, DenyLane, MemorySink> =
            ModelCaller::new(
                config(vec![lane("a", &["a-model"]), lane("b", &["b-model"])]),
                transport,
                MemoryCredentials::new(),
                DenyLane("a"),
                MemorySink::new(),
            )
            .unwrap();
        let out = c.chat(&req()).unwrap();
        assert_eq!(out.lane, "b");
        assert!(matches!(
            out.attempts[0].outcome,
            AttemptOutcome::GuardDenied { .. }
        ));
        // Nothing was sent to the denied lane.
        assert_eq!(probe.sent().len(), 1);
        assert!(c.sink().receipts()[0]
            .error
            .as_deref()
            .unwrap()
            .contains("guard denied"));
    }

    #[test]
    fn guard_denial_on_a_pin_is_fatal() {
        let transport = ScriptedTransport::new(echo_model);
        let c: ModelCaller<ScriptedTransport, MemoryCredentials, DenyLane, MemorySink> =
            ModelCaller::new(
                nvidia_config(),
                transport,
                MemoryCredentials::new(),
                DenyLane("nvidia"),
                MemorySink::new(),
            )
            .unwrap();
        let err = c
            .chat(&req().model("nim/nvidia/nemotron-3-ultra-550b-a55b"))
            .unwrap_err();
        match err {
            ModelCallError::PinFailed { message, .. } => {
                assert!(message.contains("guard denied"), "{message}")
            }
            other => panic!("expected PinFailed, got {other}"),
        }
    }

    // -- request/config discipline ----------------------------------

    #[test]
    fn stream_is_refused_not_buffered() {
        let transport = ScriptedTransport::new(echo_model);
        let probe = transport.clone();
        let c = caller(config(vec![lane("a", &["a-model"])]), transport);
        let mut r = req();
        r.stream = true;
        let err = c.chat(&r).unwrap_err();
        assert!(matches!(err, ModelCallError::Unsupported(_)));
        assert_eq!(probe.sent().len(), 0);
        assert_eq!(c.sink().receipts().len(), 0);
    }

    #[test]
    fn config_validation_refuses_nonsense() {
        let transport = ScriptedTransport::new(echo_model);
        // Duplicate lane names.
        let dup = config(vec![lane("a", &["m"]), lane("a", &["m2"])]);
        assert!(matches!(
            ModelCaller::new(dup, transport.clone(), MemoryCredentials::new(), NoGuard, MemorySink::new()),
            Err(ModelCallError::InvalidConfig(_))
        ));
        // Strategy naming a model outside the pool.
        let mut bad = lane("a", &["m"]);
        bad.strategy = ModelStrategy::SizeRules {
            rules: vec![],
            fallback: "ghost".to_string(),
        };
        assert!(matches!(
            ModelCaller::new(config(vec![bad]), transport.clone(), MemoryCredentials::new(), NoGuard, MemorySink::new()),
            Err(ModelCallError::InvalidConfig(_))
        ));
        // Alias to an unknown lane.
        let mut cfg = config(vec![lane("a", &["m"])]);
        cfg.aliases = vec![("x".to_string(), "nowhere".to_string())];
        assert!(matches!(
            ModelCaller::new(cfg, transport.clone(), MemoryCredentials::new(), NoGuard, MemorySink::new()),
            Err(ModelCallError::InvalidConfig(_))
        ));
        // http base without allow_http.
        let mut http_lane = lane("a", &["m"]);
        http_lane.base_url = "http://a.test/v1".to_string();
        assert!(matches!(
            ModelCaller::new(config(vec![http_lane]), transport, MemoryCredentials::new(), NoGuard, MemorySink::new()),
            Err(ModelCallError::InvalidConfig(_))
        ));
    }

    #[test]
    fn config_serde_roundtrip_and_no_defaults() {
        let cfg = nvidia_config();
        let text = serde_json::to_string(&cfg).unwrap();
        let back: RouterConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(cfg, back);
        // A lane missing a stated field does not deserialize:
        // behaviour the caller did not state cannot occur.
        let incomplete = serde_json::json!({
            "lanes": [{
                "name": "a", "base_url": "https://a.test/v1",
                "credential": null, "models": ["m"],
                "strategy": {"kind": "pool_order"},
                "timeout_ms": 1000, "model_timeouts_ms": [],
                "max_response_bytes": 1024, "allow_http": false
                // abort_lane_on_429 missing
            }],
            "aliases": [],
            "failover": {
                "failover_statuses": [], "failover_on_5xx": true,
                "failover_on_transport_error": true, "max_attempts": null
            }
        });
        assert!(serde_json::from_value::<RouterConfig>(incomplete).is_err());
    }

    // -- real transport against a local fixture ---------------------

    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    #[test]
    fn local_fixture_end_to_end_through_host_transport() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16384];
            let _ = s.read(&mut buf);
            let body = br#"{"model":"fixture-model","choices":[{"message":{"role":"assistant","content":"fixture-reply"}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(body);
        });
        let mut l = lane("fixture", &["fixture-model"]);
        l.base_url = format!("http://127.0.0.1:{port}/v1");
        l.allow_http = true;
        let c = ModelCaller::host(
            config(vec![l]),
            MemoryCredentials::new(),
            NoGuard,
            MemorySink::new(),
        )
        .unwrap();
        let out = c.chat(&req()).unwrap();
        assert_eq!(out.content, "fixture-reply");
        assert_eq!(out.model_served.as_deref(), Some("fixture-model"));
        assert!(!out.substituted);
        assert_eq!(c.sink().receipts().len(), 1);
    }
}

#[cfg(all(test, feature = "guard-bq"))]
mod bq_tests {
    use super::*;
    use ref_breaker_quota::{Breaker, BreakerConfig, CooldownPolicy, QuotaConfig, QuotaMeter, WindowSpec};
    use ref_https_transport::TransportError;

    fn ok_json(model: &str, content: &str) -> ref_https_transport::HttpsResponse {
        let body = serde_json::json!({
            "model": model,
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        });
        ref_https_transport::HttpsResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
            truncated: false,
        }
    }

    fn status_resp(status: u16) -> ref_https_transport::HttpsResponse {
        ref_https_transport::HttpsResponse {
            status,
            headers: vec![],
            body: br#"{"error":{"message":"nope"}}"#.to_vec(),
            truncated: false,
        }
    }

    #[derive(Clone)]
    struct FixedTransport {
        fail: Arc<std::sync::atomic::AtomicBool>,
    }

    impl HttpsTransport for FixedTransport {
        fn send(&self, req: &HttpsRequest) -> Result<ref_https_transport::HttpsResponse, TransportError> {
            if self.fail.load(Ordering::SeqCst) {
                Ok(status_resp(503))
            } else {
                let body: Value =
                    serde_json::from_slice(req.body.as_deref().unwrap_or(b"{}")).unwrap();
                Ok(ok_json(body["model"].as_str().unwrap_or(""), "hi"))
            }
        }
    }

    #[test]
    fn breaker_trips_and_then_denies_admission() {
        let now = now_unix_ms();
        let mut guard = BreakerQuotaGuard::new();
        guard.register_breaker(
            "a",
            Breaker::new(
                "a",
                BreakerConfig {
                    failure_threshold: 1,
                    window_ms: 60_000,
                    cooldown: CooldownPolicy::Fixed {
                        cooldown_ms: 300_000,
                    },
                    half_open_max_probes: 1,
                    half_open_successes_to_close: 1,
                },
                now,
            )
            .unwrap(),
        );
        let transport = FixedTransport {
            fail: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        let cfg = RouterConfig {
            lanes: vec![Lane {
                name: "a".to_string(),
                base_url: "https://a.test/v1".to_string(),
                credential: None,
                models: vec!["a-model".to_string()],
                strategy: ModelStrategy::PoolOrder,
                timeout_ms: 5_000,
                model_timeouts_ms: vec![],
                max_response_bytes: 1_048_576,
                allow_http: false,
                abort_lane_on_429: false,
            }],
            aliases: vec![],
            failover: FailoverPolicy {
                failover_statuses: vec![429],
                failover_on_5xx: true,
                failover_on_transport_error: true,
                max_attempts: None,
            },
        };
        let c = ModelCaller::new(
            cfg,
            transport,
            MemoryCredentials::new(),
            guard,
            MemorySink::new(),
        )
        .unwrap();
        // First call: admitted, fails with 503, outcome recorded
        // → threshold 1 trips the breaker.
        let err = c
            .chat(&ChatRequest::new(vec![ChatMessage::text("user", "hi")]))
            .unwrap_err();
        assert!(matches!(err, ModelCallError::AllLanesFailed { .. }));
        // Second call: the guard denies admission — the attempt
        // is a GuardDenied, and no request is sent.
        let err = c
            .chat(&ChatRequest::new(vec![ChatMessage::text("user", "hi")]))
            .unwrap_err();
        match err {
            ModelCallError::AllLanesFailed { attempts, .. } => {
                assert!(matches!(
                    attempts[0].outcome,
                    AttemptOutcome::GuardDenied { .. }
                ));
            }
            other => panic!("expected AllLanesFailed, got {other}"),
        }
    }

    #[test]
    fn quota_exhaustion_denies_admission() {
        let now = now_unix_ms();
        let mut guard = BreakerQuotaGuard::new();
        guard.register_quota(
            "a",
            QuotaMeter::new(
                "a",
                QuotaConfig {
                    limit: 1,
                    window: WindowSpec::Fixed {
                        window_ms: 3_600_000,
                        anchor_ms: 0,
                    },
                },
                now,
            )
            .unwrap(),
        );
        // Admit once (consumes the single unit), then denied.
        assert!(guard.admit("a", now).is_ok());
        let denial = guard.admit("a", now).unwrap_err();
        assert!(denial.reason.contains("quota"), "{}", denial.reason);
    }
}

#[cfg(all(test, feature = "organelle"))]
mod organelle_tests {
    use super::tests::*;
    use super::*;
    use organelle_host::Host;

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }

    #[test]
    fn unconfigured_surface_fails_closed() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["model.call".to_string()]);
        let out = h.call(
            &ctx,
            "ml",
            "chat",
            serde_json::json!({"messages": [{"role": "user", "content": "hi"}]}),
        );
        assert!(out.is_err());
    }

    #[test]
    fn without_capability_denied() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let e = h
            .call(
                &ctx,
                "ml",
                "chat",
                serde_json::json!({"messages": [{"role": "user", "content": "hi"}]}),
            )
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
    }

    #[test]
    fn configured_surface_reports_substitution() {
        // Lane "a" 503s, lane "b" serves a different model than
        // the caller asked for: the organelle output must carry
        // the substitution in-band.
        let transport = ScriptedTransport::new(|req| {
            if req.url.contains("a.test") {
                Ok(status_resp(503))
            } else {
                echo_model(req)
            }
        });
        let caller = ModelCaller::new(
            config(vec![lane("a", &["a-model"]), lane("b", &["b-model"])]),
            transport,
            MemoryCredentials::new(),
            NoGuard,
            MemorySink::new(),
        )
        .unwrap();
        let h = Host::new();
        h.set_egress_policy(
            organelle_host::EgressPolicy::allowlist(&["a.test", "b.test"]).unwrap(),
        );
        h.register(organelle_with_caller(Arc::new(caller))).unwrap();
        let ctx = CallContext::new("test", vec!["model.call".to_string()]);
        let out = h
            .call(
                &ctx,
                "ml",
                "chat",
                serde_json::json!({
                    "messages": [{"role": "user", "content": "hi"}],
                    "model": "a-model"
                }),
            )
            .unwrap()
            .output;
        assert_eq!(out["reply"], "hello");
        assert_eq!(out["lane"], "b");
        assert_eq!(out["model_requested"], "a-model");
        assert_eq!(out["model_served"], "b-model");
        assert_eq!(out["substituted"], true);
        assert_eq!(out["stub"], false);
    }

    // -- streaming -------------------------------------------------

    /// A scripted streaming head: a status plus the chunk
    /// sequence the "provider" yields (an `Err` entry is a
    /// mid-stream death at that point).
    #[derive(Clone)]
    pub(crate) struct StreamScript {
        status: u16,
        chunks: Vec<Result<Vec<u8>, TransportError>>,
    }

    #[derive(Clone)]
    pub(crate) struct ScriptedStreamTransport {
        requests: Arc<std::sync::Mutex<Vec<HttpsRequest>>>,
        handler:
            Arc<dyn Fn(&HttpsRequest) -> Result<StreamScript, TransportError> + Send + Sync>,
    }

    impl ScriptedStreamTransport {
        pub(crate) fn new(
            handler: impl Fn(&HttpsRequest) -> Result<StreamScript, TransportError>
                + Send
                + Sync
                + 'static,
        ) -> Self {
            ScriptedStreamTransport {
                requests: Arc::new(std::sync::Mutex::new(vec![])),
                handler: Arc::new(handler),
            }
        }

        pub(crate) fn sent(&self) -> Vec<HttpsRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl StreamTransport for ScriptedStreamTransport {
        fn send_stream(&self, req: &HttpsRequest) -> Result<SyncStreamResponse, TransportError> {
            self.requests.lock().unwrap().push(req.clone());
            let script = (self.handler)(req)?;
            Ok(SyncStreamResponse {
                status: script.status,
                headers: vec![(
                    "content-type".to_string(),
                    "text/event-stream".to_string(),
                )],
                chunks: Box::new(script.chunks.into_iter()),
            })
        }
    }

    struct VecChunkStream {
        items: std::collections::VecDeque<Result<Vec<u8>, TransportError>>,
    }

    impl futures_core::Stream for VecChunkStream {
        type Item = Result<Vec<u8>, TransportError>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.items.pop_front())
        }
    }

    /// The same script through the async seam: the async proofs
    /// drive `chat_stream_async` over the identical handler.
    impl AsyncStreamTransport for ScriptedStreamTransport {
        fn send_stream_async<'a>(
            &'a self,
            req: &'a HttpsRequest,
        ) -> TransportFuture<'a, Result<StreamResponse, TransportError>> {
            Box::pin(async move {
                let resp = self.send_stream(req)?;
                let items: Vec<Result<Vec<u8>, TransportError>> = resp.chunks.collect();
                Ok(StreamResponse {
                    status: resp.status,
                    headers: resp.headers,
                    chunks: Box::pin(VecChunkStream {
                        items: items.into(),
                    }),
                })
            })
        }
    }

    pub(crate) fn sse_event(model: &str, content: &str) -> Vec<u8> {
        format!(
            "data: {{\"id\":\"chatcmpl-t\",\"object\":\"chat.completion.chunk\",\"model\":\"{model}\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{content}\"}},\"finish_reason\":null}}]}}\n\n"
        )
        .into_bytes()
    }

    pub(crate) fn stream_req() -> ChatRequest {
        let mut r = req();
        r.stream = true;
        r
    }

    pub(crate) type TestStreamCaller =
        ModelCaller<ScriptedStreamTransport, MemoryCredentials, NoGuard, MemorySink>;

    pub(crate) fn stream_caller(
        config: RouterConfig,
        transport: ScriptedStreamTransport,
    ) -> TestStreamCaller {
        ModelCaller::new(
            config,
            transport,
            MemoryCredentials::new(),
            NoGuard,
            MemorySink::new(),
        )
        .unwrap()
    }

    async fn collect_chunks(
        mut chunks: ChunkStream,
    ) -> Vec<Result<Vec<u8>, TransportError>> {
        let mut out = vec![];
        while let Some(item) = next_chunk(&mut chunks).await {
            out.push(item);
        }
        out
    }

    #[test]
    fn stream_success_sync_model_from_split_chunks() {
        // The model string is split across two chunks mid-event:
        // the peek must reassemble before it can state the model,
        // and the consumer must receive the bytes untouched.
        let ev = sse_event("served-model", "hi");
        let cut = 40;
        let (c1, c2) = (ev[..cut].to_vec(), ev[cut..].to_vec());
        let done = b"data: [DONE]\n\n".to_vec();
        let script_chunks = vec![Ok(c1), Ok(c2), Ok(done.clone())];
        let transport = ScriptedStreamTransport::new(move |_| {
            Ok(StreamScript {
                status: 200,
                chunks: script_chunks.clone(),
            })
        });
        let c = stream_caller(config(vec![lane("groq", &["llama-x"])]), transport.clone());
        let mut r = stream_req();
        r.model = Some("other-model".to_string());
        let resp = c.chat_stream(&r).unwrap();
        assert_eq!(resp.meta.lane, "groq");
        assert_eq!(resp.meta.model_sent, "llama-x");
        assert_eq!(resp.meta.model_served.as_deref(), Some("served-model"));
        // Asked "other-model", served "served-model": substitution
        // is stated, from the stream's own data.
        assert!(resp.meta.substituted);
        assert_eq!(resp.meta.http_status, 200);
        let items: Vec<_> = resp.chunks.collect();
        let bytes: Vec<u8> = items
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .concat();
        assert_eq!(bytes, [ev, done].concat());
        // The wire request carried stream: true.
        let sent = transport.sent();
        assert_eq!(sent.len(), 1);
        let body: Value = serde_json::from_slice(sent[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["stream"], Value::Bool(true));
        assert_eq!(body["model"], "llama-x");
        // One receipt, ok, carrying the served model.
        let receipts = c.sink().receipts();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, "ok");
        assert_eq!(receipts[0].model_returned.as_deref(), Some("served-model"));
        assert!(receipts[0].substituted);
    }

    #[test]
    fn stream_success_async_mirror() {
        let ev = sse_event("served-model", "hi");
        let done = b"data: [DONE]\n\n".to_vec();
        let script_chunks = vec![Ok(ev.clone()), Ok(done.clone())];
        let transport = ScriptedStreamTransport::new(move |_| {
            Ok(StreamScript {
                status: 200,
                chunks: script_chunks.clone(),
            })
        });
        let c = stream_caller(config(vec![lane("groq", &["llama-x"])]), transport);
        let resp = block_on(c.chat_stream_async(&stream_req())).unwrap();
        assert_eq!(resp.meta.model_served.as_deref(), Some("served-model"));
        assert!(!resp.meta.substituted);
        let items = block_on(collect_chunks(resp.chunks));
        let bytes: Vec<u8> = items
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .concat();
        assert_eq!(bytes, [ev, done].concat());
        assert_eq!(c.sink().receipts().len(), 1);
    }

    #[test]
    fn stream_model_unknown_when_the_stream_states_none() {
        let ev = b"data: {\"id\":\"x\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
        let transport = ScriptedStreamTransport::new(move |_| {
            Ok(StreamScript {
                status: 200,
                chunks: vec![Ok(ev.clone())],
            })
        });
        let c = stream_caller(config(vec![lane("groq", &["llama-x"])]), transport);
        let resp = c.chat_stream(&stream_req()).unwrap();
        // Unknown stays unknown: no model is invented from the
        // request, and substitution is not claimed.
        assert_eq!(resp.meta.model_served, None);
        assert!(!resp.meta.substituted);
        let receipts = c.sink().receipts();
        assert_eq!(receipts[0].model_returned, None);
    }

    #[test]
    fn stream_pin_mid_stream_error_never_hops_lanes() {
        let ev = sse_event("m1", "hi");
        let transport = ScriptedStreamTransport::new(move |_| {
            Ok(StreamScript {
                status: 200,
                chunks: vec![
                    Ok(ev.clone()),
                    Err(TransportError::Network("upstream died".to_string())),
                ],
            })
        });
        let c = stream_caller(
            config(vec![lane("a", &["m1"]), lane("b", &["m2"])]),
            transport.clone(),
        );
        let mut r = stream_req();
        r.model = Some("a/m1".to_string());
        let resp = c.chat_stream(&r).unwrap();
        assert_eq!(resp.meta.lane, "a");
        assert!(resp.meta.pin.is_some());
        // Exactly one send: the dead stream is the pin's outcome,
        // surfaced as the chunk error — never a hop to lane b.
        assert_eq!(transport.sent().len(), 1);
        let items: Vec<_> = resp.chunks.collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
        assert_eq!(resp.meta.attempts.len(), 1);
        assert_eq!(resp.meta.attempts[0].outcome, AttemptOutcome::Success);
    }

    #[test]
    fn stream_failover_on_503_then_streams() {
        let ev = sse_event("m2", "from b");
        let transport = ScriptedStreamTransport::new(move |req| {
            if req.url.contains("a.test") {
                Ok(StreamScript {
                    status: 503,
                    chunks: vec![Ok(br#"{"error":{"message":"down"}}"#.to_vec())],
                })
            } else {
                Ok(StreamScript {
                    status: 200,
                    chunks: vec![Ok(ev.clone())],
                })
            }
        });
        let c = stream_caller(
            config(vec![lane("a", &["m1"]), lane("b", &["m2"])]),
            transport.clone(),
        );
        let resp = c.chat_stream(&stream_req()).unwrap();
        assert_eq!(resp.meta.lane, "b");
        assert_eq!(transport.sent().len(), 2);
        assert_eq!(resp.meta.attempts.len(), 2);
        assert_eq!(
            resp.meta.attempts[0].outcome,
            AttemptOutcome::HttpStatus { status: 503 }
        );
        assert_eq!(resp.meta.attempts[1].outcome, AttemptOutcome::Success);
        let receipts = c.sink().receipts();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].status, "error");
        assert_eq!(receipts[1].status, "ok");
    }

    #[test]
    fn stream_async_failover_mirror() {
        let ev = sse_event("m2", "from b");
        let transport = ScriptedStreamTransport::new(move |req| {
            if req.url.contains("a.test") {
                Ok(StreamScript {
                    status: 503,
                    chunks: vec![Ok(br#"{"error":{"message":"down"}}"#.to_vec())],
                })
            } else {
                Ok(StreamScript {
                    status: 200,
                    chunks: vec![Ok(ev.clone())],
                })
            }
        });
        let c = stream_caller(
            config(vec![lane("a", &["m1"]), lane("b", &["m2"])]),
            transport,
        );
        let resp = block_on(c.chat_stream_async(&stream_req())).unwrap();
        assert_eq!(resp.meta.lane, "b");
        assert_eq!(resp.meta.attempts.len(), 2);
    }

    #[test]
    fn stream_terminal_400_returns_the_provider_error() {
        let transport = ScriptedStreamTransport::new(|_| {
            Ok(StreamScript {
                status: 400,
                chunks: vec![Ok(br#"{"error":{"message":"bad stream request"}}"#.to_vec())],
            })
        });
        let c = stream_caller(config(vec![lane("groq", &["llama-x"])]), transport);
        let err = c.chat_stream(&stream_req()).unwrap_err();
        match err {
            ModelCallError::ProviderError { status, body, .. } => {
                assert_eq!(status, 400);
                assert!(body.contains("bad stream request"), "drained body: {body}");
            }
            other => panic!("expected ProviderError, got {other}"),
        }
    }

    #[test]
    fn stream_peek_error_before_first_chunk() {
        let transport = ScriptedStreamTransport::new(|_| {
            Ok(StreamScript {
                status: 200,
                chunks: vec![Err(TransportError::Network("died at once".to_string()))],
            })
        });
        let c = stream_caller(config(vec![lane("groq", &["llama-x"])]), transport);
        let resp = c.chat_stream(&stream_req()).unwrap();
        // The head landed (a success on the books, as the JS
        // records it); the body death rides the chunk sequence.
        assert_eq!(resp.meta.model_served, None);
        let items: Vec<_> = resp.chunks.collect();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_err());
        assert_eq!(c.sink().receipts()[0].status, "ok");
    }

    #[test]
    fn stream_drivers_and_whole_body_drivers_refuse_each_others_shapes() {
        let transport = ScriptedStreamTransport::new(|_| {
            Ok(StreamScript {
                status: 200,
                chunks: vec![],
            })
        });
        let c = stream_caller(config(vec![lane("groq", &["llama-x"])]), transport);
        // The streaming driver refuses a whole-body request.
        let err = c.chat_stream(&req()).unwrap_err();
        assert!(matches!(err, ModelCallError::Unsupported(_)), "{err}");
        // And the whole-body driver still refuses stream: true
        // (chat over a stream-only transport never gets to send:
        // the refusal is in the shared plan).
        let whole = ScriptedTransport::new(echo_model);
        let c2 = caller(config(vec![lane("groq", &["llama-x"])]), whole);
        let err = c2.chat(&stream_req()).unwrap_err();
        assert!(matches!(err, ModelCallError::Unsupported(_)), "{err}");
    }
}
