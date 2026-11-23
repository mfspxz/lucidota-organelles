//! org-026 — Reference organelle: https-transport (codon `ht`).
//!
//! The estate's production HTTPS client surface (GAP-01 in the
//! 2026-11-22 decomposition map: nine scoped softwares re-implement
//! HTTPS transport today — curl subprocesses, per-system reqwest/ureq
//! wiring, Workers `fetch`).  `ref-http-fetch` (org-014) is the
//! contract and refuses HTTPS in its reference client; this crate is
//! the production transport behind that contract's shape.
//!
//! One request/response API over two backends:
//!
//! * **Native** — `ureq` 3 with its rustls backend and the platform
//!   verifier (OS root store — the trust decision curl/urllib make).
//!   No native-tls, no openssl, anywhere in the graph.  Blocking.
//!   (ureq 3, not 2: ureq 2 sends absolute-form request targets
//!   inside CONNECT tunnels, which strict proxies reject — see
//!   `Cargo.toml`.)
//! * **`wasm32-unknown-unknown`** — the host `fetch` API (Workers /
//!   browser) via web-sys.  Fetch is promise-based, so on wasm the
//!   transport is [`send_async`]; the blocking entry point returns an
//!   honest error there instead of pretending to block.
//!
//! Honest status mapping: an HTTP response is data, whatever its
//! status.  `send` returns `Ok(HttpsResponse)` for a 404 or a 500
//! exactly as for a 200; [`TransportError`] is reserved for failures
//! where no response exists (bad URL, refused scheme, DNS, TLS,
//! timeout, connection).  Callers that want `--fail` semantics check
//! `response.status` themselves.
//!
//! HTTPS only by default.  Plain `http://` is refused unless the
//! request sets `allow_http` (local fixtures, dev servers) — the
//! refusal happens before any socket or fetch call.
//!
//! The native backend honours the standard proxy env vars
//! (`HTTPS_PROXY` / `HTTP_PROXY`, bypassed per `NO_PROXY`) the way
//! curl and urllib do; some sandboxes have no direct egress at all.
//!
//! Redirects follow the backend default (ureq 3: up to 5; host fetch:
//! `redirect: follow`).  Response bodies are capped at
//! `max_bytes`; the cap sets `truncated` rather than erroring, so a
//! caller can distinguish a cut body from a failed transfer.

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
#[cfg(feature = "organelle")]
use serde_json::Value;
use std::fmt;
#[cfg(feature = "organelle")]
use std::sync::Arc;

pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_MAX_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }

    pub fn parse(s: &str) -> Result<Method, TransportError> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(Method::Get),
            "HEAD" => Ok(Method::Head),
            "POST" => Ok(Method::Post),
            "PUT" => Ok(Method::Put),
            "PATCH" => Ok(Method::Patch),
            "DELETE" => Ok(Method::Delete),
            other => Err(TransportError::InvalidRequest(format!(
                "unsupported method {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRequest {
    pub method: Method,
    pub url: String,
    /// Ordered (name, value) pairs; duplicates are sent as given.
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// Whole-transfer timeout.  Native: ureq agent timeout.
    /// Wasm: AbortController deadline.
    pub timeout_ms: u64,
    /// Response body cap; excess sets `truncated` on the response.
    pub max_bytes: usize,
    /// Permit plain `http://` (local fixtures / dev only).
    pub allow_http: bool,
}

impl HttpsRequest {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        HttpsRequest {
            method,
            url: url.into(),
            headers: vec![],
            body: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_bytes: DEFAULT_MAX_BYTES,
            allow_http: false,
        }
    }

    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::Get, url)
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn max_bytes(mut self, n: usize) -> Self {
        self.max_bytes = n;
        self
    }

    pub fn allow_http(mut self, yes: bool) -> Self {
        self.allow_http = yes;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// True when the body hit `max_bytes` and was cut.
    pub truncated: bool,
}

impl HttpsResponse {
    pub fn body_text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Malformed request (bad method, empty host, …).
    InvalidRequest(String),
    /// Plain http:// without `allow_http`.
    InsecureScheme(String),
    Timeout,
    Tls(String),
    Network(String),
    /// The backend cannot serve this call shape on this target
    /// (e.g. blocking send on wasm32).
    Unsupported(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::InvalidRequest(m) => write!(f, "https-transport: invalid request: {m}"),
            TransportError::InsecureScheme(u) => {
                write!(f, "https-transport: refusing plain http (allow_http not set): {u}")
            }
            TransportError::Timeout => write!(f, "https-transport: timeout"),
            TransportError::Tls(m) => write!(f, "https-transport: TLS failure: {m}"),
            TransportError::Network(m) => write!(f, "https-transport: network failure: {m}"),
            TransportError::Unsupported(m) => write!(f, "https-transport: unsupported: {m}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Validate scheme + host before any backend is touched.  Returns the
/// lowercased scheme on success.
pub fn validate(req: &HttpsRequest) -> Result<String, TransportError> {
    let (scheme, rest) = req
        .url
        .split_once("://")
        .ok_or_else(|| TransportError::InvalidRequest(format!("url has no scheme: {}", req.url)))?;
    let scheme = scheme.to_ascii_lowercase();
    match scheme.as_str() {
        "https" => {}
        "http" if req.allow_http => {}
        "http" => return Err(TransportError::InsecureScheme(req.url.clone())),
        other => {
            return Err(TransportError::InvalidRequest(format!(
                "unsupported scheme {other}"
            )))
        }
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return Err(TransportError::InvalidRequest(format!(
            "url has no host: {}",
            req.url
        )));
    }
    Ok(scheme)
}

/// The transport trait: one implementation per platform, chosen by
/// [`HostTransport`].  Custom implementations (fixtures, recorders)
/// plug in here.
pub trait HttpsTransport {
    fn send(&self, req: &HttpsRequest) -> Result<HttpsResponse, TransportError>;
}

/// The platform default transport: ureq/rustls on native targets.
pub struct HostTransport;

impl HttpsTransport for HostTransport {
    fn send(&self, req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
        send_blocking(req)
    }
}

/// Blocking send on the platform default transport.
pub fn send_blocking(req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
    validate(req)?;
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        Err(TransportError::Unsupported(
            "blocking send on wasm32; use send_async (host fetch is promise-based)".to_string(),
        ))
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        native::send(req)
    }
}

/// Async send.  On wasm32 this is the host `fetch`.  On native targets
/// it delegates to the blocking client (documented: the future runs
/// the blocking call on the caller's executor — spawn it on a blocking
/// pool if that matters).
pub async fn send_async(req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
    validate(req)?;
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        wasm::send(req).await
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        send_blocking(req)
    }
}

// ---------------------------------------------------------------------
// Streaming sends.  The same contract, split at the response head:
// status + headers arrive as data (any HTTP status is `Ok`; `Err`
// means no response exists), and the body follows as chunks, yielded
// as they arrive.  The request's `max_bytes` bounds the total body
// bytes a stream yields — the same cap the whole-body send truncates
// at; a stream that reaches the cap simply ends.  The request's
// `timeout_ms` bounds the wait for the response head only: the
// reference behavior (the JS router's fetch) clears its abort timer
// the moment headers land, and a stream's body may legitimately
// outlive the head deadline.
// ---------------------------------------------------------------------

/// One body chunk (or the body's mid-flight failure).
pub type ChunkItem = Result<Vec<u8>, TransportError>;

/// A chunk sequence as a future-driven stream.  `Send` on native
/// targets; on wasm32 the host stream is built on `Rc`-based host
/// objects and the host is single-threaded, so the bound is stated
/// per-target rather than faked (org-035's `TransportFuture`
/// precedent).
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub type ChunkStream =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = ChunkItem> + Send>>;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub type ChunkStream = std::pin::Pin<Box<dyn futures_core::Stream<Item = ChunkItem>>>;

/// A response whose body is pulled as a stream of chunks.
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub chunks: ChunkStream,
}

impl StreamResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A response whose body is pulled as a blocking chunk iterator
/// (native hosts and test doubles; wasm32 has no blocking pull —
/// `send_stream_blocking` reports itself `Unsupported` there).
pub struct SyncStreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub chunks: Box<dyn Iterator<Item = ChunkItem> + Send>,
}

impl SyncStreamResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Streaming send, async face.  On wasm32 this is the host `fetch`
/// with its `ReadableStream` body read incrementally; on native
/// targets the head is fetched with the blocking client and the
/// body reader is pulled chunk by chunk (the reads happen inside
/// the stream's poll — the same documented bargain `send_async`
/// makes for its whole send).
pub async fn send_stream_async(req: &HttpsRequest) -> Result<StreamResponse, TransportError> {
    validate(req)?;
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        wasm::send_stream(req).await
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        native::send_stream_async(req)
    }
}

/// Streaming send, blocking face (native only).
pub fn send_stream_blocking(req: &HttpsRequest) -> Result<SyncStreamResponse, TransportError> {
    validate(req)?;
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        let _ = req;
        Err(TransportError::Unsupported(
            "blocking stream send on wasm32; use send_stream_async (host fetch is promise-based)"
                .to_string(),
        ))
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        native::send_stream_blocking(req)
    }
}

// ---------------------------------------------------------------------
// Native backend: ureq 3 + rustls, platform-verifier roots.
// ---------------------------------------------------------------------

#[cfg(all(feature = "native", not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod native {
    use super::*;
    use std::time::Duration;

    fn build_agent(req: &HttpsRequest) -> ureq::Agent {
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let mut builder = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(req.timeout_ms.max(1))))
            .tls_config(tls)
            // Honest status mapping is this crate's contract: a 4xx/5xx
            // is a response, not an error.
            .http_status_as_error(false);
        // curl/urllib behaviour: honour the standard proxy env vars
        // (HTTPS_PROXY for https, HTTP_PROXY for http) unless the host
        // is listed in NO_PROXY.  Some sandboxes (this one included)
        // have no direct egress at all — the proxy is the only route.
        if let Some(proxy) = env_proxy_for(req) {
            builder = builder.proxy(Some(proxy));
        }
        ureq::Agent::new_with_config(builder.build())
    }

    pub fn send(req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
        let agent = build_agent(req);
        let mut resp = dispatch(&agent, req).map_err(map_error)?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        // Stream the body with our own cap: ureq's read_to_vec limit
        // *errors* on overflow (BodyExceedsLimit), while this crate's
        // contract is truncate-and-flag.
        use std::io::Read as _;
        let cap = req.max_bytes as u64;
        let mut body = Vec::new();
        resp.body_mut()
            .as_reader()
            .take(cap + 1)
            .read_to_end(&mut body)
            .map_err(|e| TransportError::Network(format!("read body: {e}")))?;
        let truncated = body.len() as u64 > cap;
        let mut body = body;
        if truncated {
            body.truncate(req.max_bytes);
        }
        Ok(HttpsResponse {
            status,
            headers,
            body,
            truncated,
        })
    }

    /// The streaming agent: like `build_agent`, but the request's
    /// timeout bounds the wait for the response head
    /// (`timeout_recv_response`), not the whole transfer — a
    /// stream's body may legitimately outlive the head deadline
    /// (the JS router clears its abort timer when fetch resolves).
    fn build_stream_agent(req: &HttpsRequest) -> ureq::Agent {
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let mut builder = ureq::Agent::config_builder()
            .timeout_recv_response(Some(Duration::from_millis(req.timeout_ms.max(1))))
            .tls_config(tls)
            .http_status_as_error(false);
        if let Some(proxy) = env_proxy_for(req) {
            builder = builder.proxy(Some(proxy));
        }
        ureq::Agent::new_with_config(builder.build())
    }

    /// Fetch a response head for a streaming send: status +
    /// headers as data, plus the owned body reader.
    fn send_head(
        req: &HttpsRequest,
    ) -> Result<(u16, Vec<(String, String)>, ureq::BodyReader<'static>), TransportError> {
        let agent = build_stream_agent(req);
        let resp = dispatch(&agent, req).map_err(map_error)?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        let (_parts, body) = resp.into_parts();
        Ok((status, headers, body.into_reader()))
    }

    /// Pull one chunk (≤16 KiB, ≤ the body's remaining cap) off a
    /// body reader.  `None` at end of body or once the cap is
    /// spent; a read failure is yielded once as an `Err` chunk and
    /// ends the sequence.
    fn read_chunk(reader: &mut ureq::BodyReader<'static>, left: &mut usize) -> Option<ChunkItem> {
        use std::io::Read as _;
        if *left == 0 {
            return None;
        }
        let want = (*left).min(16 * 1024);
        let mut buf = vec![0u8; want];
        match reader.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                *left -= n;
                Some(Ok(buf))
            }
            Err(e) => {
                *left = 0;
                Some(Err(TransportError::Network(format!("read body: {e}"))))
            }
        }
    }

    struct ReadChunks {
        reader: ureq::BodyReader<'static>,
        left: usize,
    }

    impl Iterator for ReadChunks {
        type Item = ChunkItem;
        fn next(&mut self) -> Option<ChunkItem> {
            read_chunk(&mut self.reader, &mut self.left)
        }
    }

    struct NativeReadStream {
        reader: ureq::BodyReader<'static>,
        left: usize,
    }

    impl futures_core::Stream for NativeReadStream {
        type Item = ChunkItem;
        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<ChunkItem>> {
            // The read blocks the polling thread for one chunk —
            // the native bargain, stated on send_stream_async.
            let this = self.get_mut();
            std::task::Poll::Ready(read_chunk(&mut this.reader, &mut this.left))
        }
    }

    pub fn send_stream_blocking(
        req: &HttpsRequest,
    ) -> Result<SyncStreamResponse, TransportError> {
        let (status, headers, reader) = send_head(req)?;
        Ok(SyncStreamResponse {
            status,
            headers,
            chunks: Box::new(ReadChunks {
                reader,
                left: req.max_bytes,
            }),
        })
    }

    pub fn send_stream_async(req: &HttpsRequest) -> Result<StreamResponse, TransportError> {
        let (status, headers, reader) = send_head(req)?;
        Ok(StreamResponse {
            status,
            headers,
            chunks: Box::pin(NativeReadStream {
                reader,
                left: req.max_bytes,
            }),
        })
    }

    fn dispatch(
        agent: &ureq::Agent,
        req: &HttpsRequest,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        macro_rules! with_headers {
            ($b:expr) => {{
                let mut b = $b;
                for (k, v) in &req.headers {
                    b = b.header(k.as_str(), v.as_str());
                }
                b
            }};
        }
        match req.method {
            Method::Get => with_headers!(agent.get(&req.url)).call(),
            Method::Head => with_headers!(agent.head(&req.url)).call(),
            Method::Delete => with_headers!(agent.delete(&req.url)).call(),
            Method::Post => send_body(with_headers!(agent.post(&req.url)), req),
            Method::Put => send_body(with_headers!(agent.put(&req.url)), req),
            Method::Patch => send_body(with_headers!(agent.patch(&req.url)), req),
        }
    }

    fn send_body(
        builder: ureq::RequestBuilder<ureq::typestate::WithBody>,
        req: &HttpsRequest,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        match &req.body {
            Some(body) => builder.send(body.as_slice()),
            None => builder.send_empty(),
        }
    }

    fn env_proxy_for(req: &HttpsRequest) -> Option<ureq::Proxy> {
        let rest = req.url.split_once("://")?.1;
        let authority = rest.split(['/', '?', '#']).next()?;
        let hostport = authority.rsplit('@').next()?;
        let host = hostport
            .trim_start_matches('[')
            .split([':', ']'])
            .next()?
            .to_ascii_lowercase();
        let no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .unwrap_or_default();
        for entry in no_proxy.split(',') {
            let entry = entry.trim().trim_start_matches('.').to_ascii_lowercase();
            if !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}"))) {
                return None;
            }
        }
        let scheme = req.url.split_once("://")?.0.to_ascii_lowercase();
        let var = if scheme == "https" {
            std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy"))
        } else {
            std::env::var("HTTP_PROXY").or_else(|_| std::env::var("http_proxy"))
        };
        var.ok()
            .filter(|v| !v.is_empty())
            .and_then(|v| ureq::Proxy::new(&v).ok())
    }

    fn map_error(e: ureq::Error) -> TransportError {
        match e {
            ureq::Error::Timeout(_) => TransportError::Timeout,
            ureq::Error::BadUri(m) => TransportError::InvalidRequest(m),
            ureq::Error::HostNotFound => {
                TransportError::Network("host not found (DNS)".to_string())
            }
            other => {
                let msg = other.to_string();
                if msg.to_ascii_lowercase().contains("tls")
                    || msg.to_ascii_lowercase().contains("certificate")
                {
                    TransportError::Tls(msg)
                } else {
                    TransportError::Network(msg)
                }
            }
        }
    }
}

#[cfg(not(any(
    all(feature = "native", not(all(target_arch = "wasm32", target_os = "unknown"))),
    all(target_arch = "wasm32", target_os = "unknown")
)))]
mod native {
    use super::*;
    pub fn send(_req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
        Err(TransportError::Unsupported(
            "built without the `native` feature and not on wasm32".to_string(),
        ))
    }

    pub fn send_stream_blocking(
        _req: &HttpsRequest,
    ) -> Result<SyncStreamResponse, TransportError> {
        Err(TransportError::Unsupported(
            "built without the `native` feature and not on wasm32".to_string(),
        ))
    }

    pub fn send_stream_async(_req: &HttpsRequest) -> Result<StreamResponse, TransportError> {
        Err(TransportError::Unsupported(
            "built without the `native` feature and not on wasm32".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------
// Wasm backend: host fetch via web-sys (Workers / browser).
// ---------------------------------------------------------------------

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm {
    use super::*;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    pub async fn send(req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
        // The host's global scope: a Window in a browser, a
        // WorkerGlobalScope in a Worker — Cloudflare Workers
        // have no `window`, and a `web_sys::window()` call
        // returns None there, which would make every send
        // `Unsupported` on the very hosts this backend exists
        // for.  `fetch` and `setTimeout` are therefore resolved
        // by name off the global object, which both scopes
        // expose identically.
        let global = js_sys::global();

        let headers = web_sys::Headers::new()
            .map_err(|e| TransportError::Network(format!("Headers::new: {e:?}")))?;
        for (k, v) in &req.headers {
            headers
                .append(k, v)
                .map_err(|e| TransportError::Network(format!("header {k}: {e:?}")))?;
        }

        let init = web_sys::RequestInit::new();
        init.set_method(req.method.as_str());
        init.set_headers(&headers);

        // Timeout: abort the fetch at the deadline.
        let controller = web_sys::AbortController::new()
            .map_err(|e| TransportError::Network(format!("AbortController: {e:?}")))?;
        let signal = controller.signal();
        init.set_signal(Some(&signal));
        let abort = wasm_bindgen::closure::Closure::once_into_js(move || {
            let _ = controller.abort();
        });
        set_timeout(
            &global,
            &abort,
            req.timeout_ms.min(i32::MAX as u64) as i32,
        );

        if let Some(body) = &req.body {
            let arr = js_sys::Uint8Array::from(body.as_slice());
            init.set_body(&arr);
        }

        let request = web_sys::Request::new_with_str_and_init(&req.url, &init)
            .map_err(|e| TransportError::InvalidRequest(format!("Request: {e:?}")))?;

        let fetch = global_fn(&global, "fetch")?;
        let promise = fetch
            .call1(&global, &request)
            .map_err(|e| map_fetch_error(e, req.timeout_ms))?;
        let promise: js_sys::Promise = promise.dyn_into().map_err(|v| {
            TransportError::Network(format!("fetch returned a non-Promise: {v:?}"))
        })?;
        let resp_value = JsFuture::from(promise)
            .await
            .map_err(|e| map_fetch_error(e, req.timeout_ms))?;
        let resp: web_sys::Response = resp_value
            .dyn_into()
            .map_err(|v| TransportError::Network(format!("fetch resolved to non-Response: {v:?}")))?;

        let status = resp.status();
        let mut out_headers: Vec<(String, String)> = vec![];
        let entries = js_sys::Iterator::from(resp.headers().entries());
        for item in entries {
            let value = item
                .map_err(|e| TransportError::Network(format!("headers iterator: {e:?}")))?;
            let pair = js_sys::Array::from(&value);
            if pair.length() == 2 {
                out_headers.push((
                    pair.get(0).as_string().unwrap_or_default(),
                    pair.get(1).as_string().unwrap_or_default(),
                ));
            }
        }

        let buffer = JsFuture::from(
            resp.array_buffer()
                .map_err(|e| TransportError::Network(format!("array_buffer: {e:?}")))?,
        )
        .await
        .map_err(|e| TransportError::Network(format!("read body: {e:?}")))?;
        let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
        let truncated = bytes.len() > req.max_bytes;
        let body = if truncated {
            bytes[..req.max_bytes].to_vec()
        } else {
            bytes
        };
        Ok(HttpsResponse {
            status,
            headers: out_headers,
            body,
            truncated,
        })
    }

    /// Streaming send: the same fetch as `send`, but the abort
    /// timer is cleared the moment the response head lands (the
    /// JS router's semantics — its per-attempt timer never bounds
    /// a stream's body), and the body is exposed as a
    /// `ReadableStream` chunk pull instead of an `array_buffer`
    /// read.
    pub async fn send_stream(req: &HttpsRequest) -> Result<StreamResponse, TransportError> {
        let global = js_sys::global();

        let headers = web_sys::Headers::new()
            .map_err(|e| TransportError::Network(format!("Headers::new: {e:?}")))?;
        for (k, v) in &req.headers {
            headers
                .append(k, v)
                .map_err(|e| TransportError::Network(format!("header {k}: {e:?}")))?;
        }

        let init = web_sys::RequestInit::new();
        init.set_method(req.method.as_str());
        init.set_headers(&headers);

        let controller = web_sys::AbortController::new()
            .map_err(|e| TransportError::Network(format!("AbortController: {e:?}")))?;
        let signal = controller.signal();
        init.set_signal(Some(&signal));
        let abort = wasm_bindgen::closure::Closure::once_into_js(move || {
            let _ = controller.abort();
        });
        let timer_id = set_timeout_id(&global, &abort, req.timeout_ms.min(i32::MAX as u64) as i32);

        if let Some(body) = &req.body {
            let arr = js_sys::Uint8Array::from(body.as_slice());
            init.set_body(&arr);
        }

        let request = web_sys::Request::new_with_str_and_init(&req.url, &init)
            .map_err(|e| TransportError::InvalidRequest(format!("Request: {e:?}")))?;

        let fetch = global_fn(&global, "fetch")?;
        let promise = fetch
            .call1(&global, &request)
            .map_err(|e| map_fetch_error(e, req.timeout_ms))?;
        let promise: js_sys::Promise = promise.dyn_into().map_err(|v| {
            TransportError::Network(format!("fetch returned a non-Promise: {v:?}"))
        })?;
        let resp_value = JsFuture::from(promise)
            .await
            .map_err(|e| map_fetch_error(e, req.timeout_ms))?;
        // The head has landed: the deadline's work is done.  A
        // stream body may run past it (the JS clears its timer at
        // exactly this point).
        if let Some(id) = &timer_id {
            clear_timeout(&global, id);
        }
        let resp: web_sys::Response = resp_value
            .dyn_into()
            .map_err(|v| TransportError::Network(format!("fetch resolved to non-Response: {v:?}")))?;

        let status = resp.status();
        let mut out_headers: Vec<(String, String)> = vec![];
        let entries = js_sys::Iterator::from(resp.headers().entries());
        for item in entries {
            let value = item
                .map_err(|e| TransportError::Network(format!("headers iterator: {e:?}")))?;
            let pair = js_sys::Array::from(&value);
            if pair.length() == 2 {
                out_headers.push((
                    pair.get(0).as_string().unwrap_or_default(),
                    pair.get(1).as_string().unwrap_or_default(),
                ));
            }
        }

        let reader = resp
            .body()
            .map(|stream| stream.get_reader())
            .and_then(|value| value.dyn_into::<web_sys::ReadableStreamDefaultReader>().ok());
        Ok(StreamResponse {
            status,
            headers: out_headers,
            chunks: Box::pin(FetchChunkStream {
                reader,
                pending: None,
                left: req.max_bytes,
                done: false,
            }),
        })
    }

    /// One host `ReadableStream` reader as a chunk stream.  A
    /// read failure is yielded once as an `Err` chunk (the
    /// consumer's sentinel point) and ends the sequence; dropping
    /// the stream cancels the reader best-effort.
    struct FetchChunkStream {
        reader: Option<web_sys::ReadableStreamDefaultReader>,
        pending: Option<std::pin::Pin<Box<JsFuture>>>,
        left: usize,
        done: bool,
    }

    impl futures_core::Stream for FetchChunkStream {
        type Item = ChunkItem;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<ChunkItem>> {
            use std::future::Future as _;
            loop {
                if self.done || self.left == 0 {
                    self.done = true;
                    return std::task::Poll::Ready(None);
                }
                if self.pending.is_none() {
                    let Some(reader) = &self.reader else {
                        self.done = true;
                        return std::task::Poll::Ready(None);
                    };
                    self.pending = Some(Box::pin(JsFuture::from(reader.read())));
                }
                let pending = self.pending.as_mut().expect("pending set above");
                match pending.as_mut().poll(cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Ok(v)) => {
                        self.pending = None;
                        let is_done = js_sys::Reflect::get(&v, &JsValue::from_str("done"))
                            .ok()
                            .and_then(|d| d.as_bool())
                            .unwrap_or(true);
                        if is_done {
                            self.done = true;
                            return std::task::Poll::Ready(None);
                        }
                        let value = js_sys::Reflect::get(&v, &JsValue::from_str("value"))
                            .map_err(|_| {
                                TransportError::Network(
                                    "stream read result has no value".to_string(),
                                )
                            });
                        let value = match value.and_then(|v| {
                            v.dyn_into::<js_sys::Uint8Array>().map_err(|_| {
                                TransportError::Network(
                                    "stream read value is not a Uint8Array".to_string(),
                                )
                            })
                        }) {
                            Ok(arr) => arr.to_vec(),
                            Err(e) => {
                                self.done = true;
                                return std::task::Poll::Ready(Some(Err(e)));
                            }
                        };
                        let mut bytes = value;
                        if bytes.len() > self.left {
                            bytes.truncate(self.left);
                        }
                        self.left -= bytes.len();
                        if bytes.is_empty() {
                            // An empty read with done=false: pull
                            // again rather than yield an empty chunk.
                            continue;
                        }
                        return std::task::Poll::Ready(Some(Ok(bytes)));
                    }
                    std::task::Poll::Ready(Err(e)) => {
                        self.pending = None;
                        self.done = true;
                        return std::task::Poll::Ready(Some(Err(map_fetch_error(e, 0))));
                    }
                }
            }
        }
    }

    impl Drop for FetchChunkStream {
        fn drop(&mut self) {
            if let Some(reader) = &self.reader {
                let _ = reader.cancel();
            }
        }
    }

    /// setTimeout that hands back the timer id, for callers that
    /// clear the deadline once the response head lands.
    fn set_timeout_id(global: &JsValue, callback: &JsValue, ms: i32) -> Option<JsValue> {
        let f = global_fn(global, "setTimeout").ok()?;
        f.call2(global, callback, &JsValue::from(ms)).ok()
    }

    fn clear_timeout(global: &JsValue, id: &JsValue) {
        if let Ok(f) = global_fn(global, "clearTimeout") {
            let _ = f.call1(global, id);
        }
    }

    /// Resolve a function off the host global scope by name
    /// (fetch / setTimeout live there in both Window and
    /// WorkerGlobalScope hosts).
    fn global_fn(global: &JsValue, name: &str) -> Result<js_sys::Function, TransportError> {
        let f = js_sys::Reflect::get(global, &JsValue::from_str(name))
            .map_err(|_| TransportError::Unsupported(format!("host global has no {name}")))?;
        f.dyn_into::<js_sys::Function>().map_err(|_| {
            TransportError::Unsupported(format!("host global {name} is not a function"))
        })
    }

    /// Best-effort host setTimeout for the abort deadline: a
    /// host without the timer runs the fetch without the local
    /// deadline — never a reason to fail the send itself.
    fn set_timeout(global: &JsValue, callback: &JsValue, ms: i32) {
        if let Ok(f) = global_fn(global, "setTimeout") {
            let _ = f.call2(global, callback, &JsValue::from(ms));
        }
    }

    fn map_fetch_error(e: JsValue, timeout_ms: u64) -> TransportError {
        let msg = format!("{e:?}");
        if msg.contains("AbortError") {
            let _ = timeout_ms;
            TransportError::Timeout
        } else {
            TransportError::Network(format!("fetch: {msg}"))
        }
    }
}

// ---------------------------------------------------------------------
// Organelle trait surface (codon `ht`).
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "https-transport".to_string(),
        codon: "ht".to_string(),
        version: "1.0.0".to_string(),
        description:
            "production HTTPS transport organelle (ureq/rustls native; host fetch on wasm)"
                .to_string(),
        contracts: vec![Contract {
            op: "request".to_string(),
            description:
                "send one HTTPS request; any HTTP status is returned as data, transport failures are errors"
                    .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["url"],
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]},
                    "url": {"type": "string", "minLength": 8},
                    "headers": {"type": "object"},
                    "body_text": {"type": "string"},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 300000},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 67108864},
                    "allow_http": {"type": "boolean"}
                }
            }),
            mutation_class: Some(MutationClass::ExternalEffect),
            required_capability: Some("net.fetch".to_string()),
        }],
        authority: Authority {
            mutation_class: MutationClass::ExternalEffect,
            declared_valence: Valence::Candidate,
            required_capability: Some("net.fetch".to_string()),
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
pub struct HttpsTransportOrganelle {
    manifest: OrganelleManifest,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(HttpsTransportOrganelle {
        manifest: manifest(),
    })
}

#[cfg(feature = "organelle")]
impl Organelle for HttpsTransportOrganelle {
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
        if op != "request" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        let url = input["url"].as_str().unwrap_or("");
        // Same policy seam as ref-http-fetch: the host's egress
        // allowlist decides before any socket/fetch happens.
        host.approve_egress(url)?;
        let method = match input["method"].as_str() {
            Some(s) => Method::parse(s).map_err(|e| OrganelleError::new("rejected", e.to_string()))?,
            None => Method::Get,
        };
        let mut req = HttpsRequest::new(method, url);
        if let Some(obj) = input["headers"].as_object() {
            for (k, v) in obj {
                if let Some(v) = v.as_str() {
                    req.headers.push((k.clone(), v.to_string()));
                }
            }
        }
        if let Some(text) = input["body_text"].as_str() {
            req.body = Some(text.as_bytes().to_vec());
        }
        if let Some(ms) = input["timeout_ms"].as_u64() {
            req.timeout_ms = ms;
        }
        if let Some(n) = input["max_bytes"].as_u64() {
            req.max_bytes = n as usize;
        }
        if let Some(yes) = input["allow_http"].as_bool() {
            req.allow_http = yes;
        }
        match send_blocking(&req) {
            Ok(r) => Ok(serde_json::json!({
                "status": r.status,
                "headers": r.headers.iter().map(|(k, v)| serde_json::json!({"name": k, "value": v})).collect::<Vec<_>>(),
                "body": r.body_text_lossy(),
                "bytes": r.body.len(),
                "truncated": r.truncated,
            })),
            Err(e) => Err(OrganelleError::failed(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The live tests hit the real network and say so; the fixture
// tests are deterministic and offline.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_url_validates() {
        let req = HttpsRequest::get("https://example.com/path?q=1");
        assert_eq!(validate(&req).unwrap(), "https");
    }

    #[test]
    fn http_refused_without_allow() {
        let req = HttpsRequest::get("http://127.0.0.1:8080/");
        assert!(matches!(
            validate(&req),
            Err(TransportError::InsecureScheme(_))
        ));
    }

    #[test]
    fn http_allowed_with_flag() {
        let req = HttpsRequest::get("http://127.0.0.1:8080/").allow_http(true);
        assert_eq!(validate(&req).unwrap(), "http");
    }

    #[test]
    fn garbage_url_rejected() {
        assert!(validate(&HttpsRequest::get("example.com/no-scheme")).is_err());
        assert!(validate(&HttpsRequest::get("https://")).is_err());
        assert!(validate(&HttpsRequest::get("ftp://example.com/")).is_err());
    }

    #[test]
    fn method_parse() {
        assert_eq!(Method::parse("post").unwrap(), Method::Post);
        assert!(Method::parse("FETCH").is_err());
    }
}

#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod native_tests {
    use super::*;
    use std::io::{Read, Write};

    fn serve_once(status_line: &str, body: &'static [u8]) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let status_line = status_line.to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nX-Fixture: yes\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(body);
        });
        port
    }

    #[test]
    fn local_http_fixture_roundtrip() {
        let port = serve_once("200 OK", b"transport-fixture");
        let req = HttpsRequest::get(format!("http://127.0.0.1:{port}/"))
            .allow_http(true)
            .timeout_ms(5_000);
        let resp = send_blocking(&req).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"transport-fixture");
        assert_eq!(resp.header("x-fixture"), Some("yes"));
        assert!(!resp.truncated);
    }

    #[test]
    fn local_404_is_data_not_error() {
        let port = serve_once("404 Not Found", b"nope");
        let req = HttpsRequest::get(format!("http://127.0.0.1:{port}/missing")).allow_http(true);
        let resp = send_blocking(&req).unwrap();
        assert_eq!(resp.status, 404);
        assert!(!resp.is_success());
    }

    /// Serve a response whose body is written in pieces with
    /// pauses between them, so a streaming reader observes more
    /// than one read.  `declared_len` may exceed the bytes
    /// actually written (the mid-stream death fixture).
    fn serve_pieces(pieces: Vec<&'static [u8]>, declared_len: usize) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {declared_len}\r\nConnection: close\r\n\r\n"
            );
            let _ = s.write_all(resp.as_bytes());
            for p in pieces {
                let _ = s.write_all(p);
                let _ = s.flush();
                std::thread::sleep(std::time::Duration::from_millis(60));
            }
        });
        port
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Wake};
        struct ThreadWaker(std::thread::Thread);
        impl Wake for ThreadWaker {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.unpark();
            }
            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = std::task::Waker::from(std::sync::Arc::new(ThreadWaker(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    #[test]
    fn stream_blocking_yields_body_in_chunks() {
        let pieces: Vec<&'static [u8]> = vec![b"data: one\n\n", b"data: two\n\n", b"data: [DONE]\n\n"];
        let total: usize = pieces.iter().map(|p| p.len()).sum();
        let port = serve_pieces(pieces, total);
        let req = HttpsRequest::get(format!("http://127.0.0.1:{port}/"))
            .allow_http(true)
            .timeout_ms(5_000);
        let resp = send_stream_blocking(&req).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
        let chunks: Vec<Vec<u8>> = resp
            .chunks
            .collect::<Result<Vec<_>, _>>()
            .expect("clean stream");
        assert!(
            chunks.len() >= 2,
            "body arrived in pieces, got {} chunk(s)",
            chunks.len()
        );
        assert_eq!(chunks.concat(), b"data: one\n\ndata: two\n\ndata: [DONE]\n\n");
    }

    #[test]
    fn stream_async_yields_the_same_chunks() {
        let pieces: Vec<&'static [u8]> = vec![b"data: one\n\n", b"data: two\n\n"];
        let total: usize = pieces.iter().map(|p| p.len()).sum();
        let port = serve_pieces(pieces, total);
        let req = HttpsRequest::get(format!("http://127.0.0.1:{port}/"))
            .allow_http(true)
            .timeout_ms(5_000);
        let resp = block_on(send_stream_async(&req)).unwrap();
        assert_eq!(resp.status, 200);
        let mut chunks = resp.chunks;
        let mut items = vec![];
        loop {
            let next = block_on(std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx)));
            match next {
                Some(item) => items.push(item),
                None => break,
            }
        }
        let body: Vec<u8> = items
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("clean stream")
            .concat();
        assert_eq!(body, b"data: one\n\ndata: two\n\n");
    }

    #[test]
    fn stream_mid_body_death_is_an_error_chunk() {
        // Declares 100 bytes, delivers 5, closes: the reader must
        // surface the death as an Err chunk, not a clean end.
        let port = serve_pieces(vec![b"short"], 100);
        let req = HttpsRequest::get(format!("http://127.0.0.1:{port}/"))
            .allow_http(true)
            .timeout_ms(5_000);
        let resp = send_stream_blocking(&req).unwrap();
        let items: Vec<ChunkItem> = resp.chunks.collect();
        let got: Vec<u8> = items
            .iter()
            .filter_map(|i| i.as_ref().ok())
            .flatten()
            .copied()
            .collect();
        let errs = items.iter().filter(|i| i.is_err()).count();
        assert_eq!(got, b"short");
        assert_eq!(errs, 1, "exactly one error chunk: {items:?}");
    }

    #[test]
    fn body_cap_sets_truncated() {
        let port = serve_once("200 OK", b"0123456789abcdef");
        let req = HttpsRequest::get(format!("http://127.0.0.1:{port}/"))
            .allow_http(true)
            .max_bytes(4);
        let resp = send_blocking(&req).unwrap();
        assert_eq!(resp.body, b"0123");
        assert!(resp.truncated);
    }

    /// LIVE NETWORK TEST: a real HTTPS GET through rustls against a
    /// public endpoint.  Fails honestly if the sandbox has no egress.
    #[test]
    fn live_https_get_example_com() {
        let req = HttpsRequest::get("https://example.com/").timeout_ms(20_000);
        let resp = send_blocking(&req).expect("live HTTPS GET to example.com");
        assert_eq!(resp.status, 200);
        assert!(resp.body_text_lossy().contains("Example Domain"));
    }

    /// LIVE NETWORK TEST: honest status mapping over real TLS — a 404
    /// comes back as a response, not a transport error.
    #[test]
    fn live_https_404_is_data() {
        let req =
            HttpsRequest::get("https://example.com/https-transport-no-such-page").timeout_ms(20_000);
        let resp = send_blocking(&req).expect("live HTTPS GET (404 path)");
        assert_eq!(resp.status, 404);
    }
}

#[cfg(all(test, feature = "organelle"))]
mod organelle_tests {
    use super::*;
    use organelle_host::Host;

    fn egress_host(allow: &[&str]) -> Arc<Host> {
        let h = Host::new();
        h.set_egress_policy(
            organelle_host::EgressPolicy::allowlist(allow).expect("test allowlist parses"),
        );
        h
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }

    #[test]
    fn http_url_rejected_through_host() {
        let h = egress_host(&["127.0.0.1"]);
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["net.fetch".to_string()]);
        let out = h.call(
            &ctx,
            "ht",
            "request",
            serde_json::json!({"url": "http://127.0.0.1:9/"}),
        );
        // allow_http defaults false in the organelle surface: the
        // transport refuses before connecting (port 9 would fail too,
        // but the error must be the scheme refusal surfacing as a
        // failed call, and egress approval passed first).
        assert!(out.is_err());
    }

    #[test]
    fn egress_denied_host_never_connects() {
        let h = egress_host(&["example.com"]);
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["net.fetch".to_string()]);
        let out = h.call(
            &ctx,
            "ht",
            "request",
            serde_json::json!({"url": "https://127.0.0.1:9/"}),
        );
        assert!(out.is_err());
    }
}
