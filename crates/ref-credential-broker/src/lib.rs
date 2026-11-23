//! org-028 — Reference organelle: credential-broker (codon `cb`).
//!
//! Scoped secret-material broker (GAP-03 in the 2026-11-22
//! decomposition map: six scoped softwares — FAC, WRK, EXC, RTR,
//! MCP, TEN — hand-roll credential handling today: provider keys
//! read from process env in worker layers, a bespoke token
//! custodian inside `wreck-ports`, EXC's one-off authd surrogate
//! client, raw provider keys in the ai-router's worker env, a
//! vending-machine token contract with no implementation, and
//! per-worker shared-secret compares across tentacle-corp).
//!
//! The rule this crate exists to enforce: **secret values never
//! cross the API boundary.**  Callers name a credential by
//! reference ([`CredentialRef`] — a name plus a scope, never a
//! value) and ask the broker to act:
//!
//! * [`Broker::execute_http`] — the broker resolves the reference,
//!   attaches the credential to the request per its [`Placement`],
//!   and performs the request over an injected
//!   [`HttpsTransport`].  The caller gets the response, never the
//!   value.
//! * [`Broker::grant`] / [`Broker::redeem_http`] — the broker mints
//!   a scoped, short-lived capability handle (allowed hosts, TTL,
//!   optional use count).  A handle is an opaque id, not a secret;
//!   redeeming it performs the request under the grant's scope.
//!   [`Broker::revoke_grant`] kills a handle early.
//! * [`Broker::verify_presentation`] — inbound check (the TEN
//!   shared-secret shape): the caller presents a value it received;
//!   the broker answers match / no-match against the stored
//!   credential.  The stored value is never returned.
//!
//! Every brokered operation — success or failure — appends a
//! [`BrokerReceipt`]: who (caller), what ref (name + scope), what
//! operation (method + host, grant, verify, …), what outcome, and
//! when.  Receipts carry a sha256 receipt id over their canonical
//! fields.  They never carry the value, and neither does any other
//! output of this crate: [`SecretValue`] has no `Display` and a
//! redacted `Debug`, backends redact their `Debug`, and
//! [`BrokerError`] variants are built from names, hosts and static
//! text only.  The test suite greps every output shape for the
//! fixture secret to prove it.
//!
//! Placements are header-only by construction.  There is no
//! query-param or URL-path placement variant: values in URLs land
//! in logs, so the enum refuses the shape (the same refusal EXC's
//! `creds.rs` makes against the authd placements).
//!
//! Backends ([`CredentialBackend`]): [`MemoryBackend`] (tests and
//! host-provisioned processes) and [`FileBackend`] (one file per
//! credential).  A backend is constructed with everything it may
//! read — `FileBackend` receives its (reference → path) entries at
//! construction; this crate hardcodes no paths, reads nothing at
//! import, and never reads the environment.  The estate's authd
//! surrogate flow (EXC `creds.rs`) is a future third backend behind
//! this same trait; the placement vocabulary already matches it.

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use serde_json::Value;
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use ref_https_transport::{HostTransport, HttpsRequest, HttpsResponse, HttpsTransport, TransportError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------
// References and placements — the only credential-shaped things a
// caller ever holds, and neither contains a value.
// ---------------------------------------------------------------------

/// A credential reference: a name plus a scope (e.g. name `nvidia`,
/// scope `provider-api`).  This is an identifier, not a secret —
/// safe to log, store in manifests, and pass between organelles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CredentialRef {
    pub name: String,
    pub scope: String,
}

impl CredentialRef {
    pub fn new(name: impl Into<String>, scope: impl Into<String>) -> Result<Self, BrokerError> {
        let name = name.into();
        let scope = scope.into();
        for (field, v) in [("name", &name), ("scope", &scope)] {
            if v.is_empty() || v.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(BrokerError::InvalidRequest(format!(
                    "credential {field} must be non-empty and free of whitespace/control characters"
                )));
            }
        }
        Ok(CredentialRef { name, scope })
    }

    /// Reference with the conventional `default` scope.
    pub fn unscoped(name: impl Into<String>) -> Result<Self, BrokerError> {
        Self::new(name, "default")
    }
}

impl fmt::Display for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cred:{}@{}", self.name, self.scope)
    }
}

/// How a resolved credential attaches to an HTTP request.  Header
/// placements only — see the crate docs for why no URL placement
/// variant exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// `Authorization: Bearer <value>`
    BearerHeader,
    /// `<name>: <value>` (e.g. `x-api-key`)
    CustomHeader(String),
}

impl Placement {
    /// The header name this placement writes.
    pub fn header_name(&self) -> &str {
        match self {
            Placement::BearerHeader => "Authorization",
            Placement::CustomHeader(name) => name.as_str(),
        }
    }

    fn attach(&self, req: &mut HttpsRequest, value: &SecretValue) {
        // Brokered auth wins: any caller-supplied copy of the same
        // header is replaced, never duplicated alongside.
        let name = self.header_name().to_string();
        req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
        let v = match self {
            Placement::BearerHeader => format!("Bearer {}", value.expose()),
            Placement::CustomHeader(_) => value.expose().to_string(),
        };
        req.headers.push((name, v));
    }
}

// ---------------------------------------------------------------------
// The secret itself.  Crate-internal: constructed by backends,
// consumed by Placement::attach, exposed nowhere else.
// ---------------------------------------------------------------------

/// A resolved secret value.  Deliberately has no `Display`, a
/// redacted `Debug`, no `Clone` of convenience, and a `Drop` that
/// zeroes its buffer (best-effort — the allocator may have copied
/// it before, which is why the real discipline is never letting it
/// leave the crate at all).
pub struct SecretValue(String);

impl SecretValue {
    pub(crate) fn new(value: String) -> Self {
        SecretValue(value)
    }

    /// The one door to the value, `pub(crate)`: backends build it,
    /// `Placement::attach` spends it.  Nothing outside this crate
    /// can call this.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(<redacted>)")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        // Zero the buffer before it is freed.
        let bytes = unsafe { self.0.as_mut_vec() };
        for b in bytes.iter_mut() {
            *b = 0;
        }
        self.0.clear();
    }
}

/// A credential after resolution: the value plus how it attaches.
/// Manual `Debug` — redacted by construction.
pub struct ResolvedCredential {
    value: SecretValue,
    placement: Placement,
}

impl ResolvedCredential {
    pub fn new(value: SecretValue, placement: Placement) -> Self {
        ResolvedCredential { value, placement }
    }

    pub fn placement(&self) -> &Placement {
        &self.placement
    }
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("value", &"<redacted>")
            .field("placement", &self.placement)
            .finish()
    }
}

// ---------------------------------------------------------------------
// Errors.  No variant ever carries a secret value: variants are
// built from refs, hosts, and static/backend text, and backend
// implementors are bound by the same rule (see CredentialBackend).
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// The reference is not known to the backend.  Fail-closed:
    /// nothing was sent anywhere.
    UnknownRef(CredentialRef),
    /// The backend failed (I/O, upstream).  The string is the
    /// backend's own description — backends must never embed a
    /// secret value in it.
    Backend(String),
    /// No HTTP response exists (from the transport layer).
    Transport(TransportError),
    /// The grant handle id is not known (never minted, or revoked).
    UnknownHandle,
    /// The grant handle is past its expiry.
    GrantExpired,
    /// The grant handle has no uses left.
    GrantExhausted,
    /// The request's host is outside the grant's scope.
    ScopeDenied(String),
    /// Client-side refusal before any action (bad ref, bad TTL, …).
    InvalidRequest(String),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrokerError::UnknownRef(r) => {
                write!(f, "credential-broker: unknown credential ref {r} (fail-closed)")
            }
            BrokerError::Backend(m) => write!(f, "credential-broker: backend failure: {m}"),
            BrokerError::Transport(e) => write!(f, "credential-broker: transport: {e}"),
            BrokerError::UnknownHandle => write!(f, "credential-broker: unknown grant handle"),
            BrokerError::GrantExpired => write!(f, "credential-broker: grant expired"),
            BrokerError::GrantExhausted => write!(f, "credential-broker: grant uses exhausted"),
            BrokerError::ScopeDenied(h) => {
                write!(f, "credential-broker: host {h} outside grant scope")
            }
            BrokerError::InvalidRequest(m) => {
                write!(f, "credential-broker: invalid request: {m}")
            }
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<TransportError> for BrokerError {
    fn from(e: TransportError) -> Self {
        BrokerError::Transport(e)
    }
}

// ---------------------------------------------------------------------
// Receipts — the audit shape.  Who, what ref, what operation, what
// outcome, when.  Never the value.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrokerReceipt {
    /// sha256 hex over the canonical receipt fields (plus a
    /// per-broker sequence, so identical operations at the same
    /// millisecond still get distinct ids).
    pub receipt_id: String,
    /// Who asked: the caller identity supplied to the broker call
    /// (the organelle surface passes the host `CallContext.caller`).
    pub caller: String,
    /// Credential name / scope — identifiers, never values.  For a
    /// redeem against an unknown handle these are `<unknown-handle>`.
    pub credential_name: String,
    pub credential_scope: String,
    /// `http_request` | `grant` | `redeem` | `revoke` | `verify`.
    pub operation: String,
    /// HTTP method for request operations, empty otherwise.
    pub method: String,
    /// Request host for request operations, empty otherwise.
    pub host: String,
    /// `ok:<status>` for completed requests, `ok` for grant/revoke,
    /// `match` / `no_match` for verify, `error:<kind>` for failures.
    pub outcome: String,
    pub at_unix_ms: u64,
}

fn receipt_id(
    seq: u64,
    caller: &str,
    name: &str,
    scope: &str,
    operation: &str,
    method: &str,
    host: &str,
    outcome: &str,
    at_unix_ms: u64,
) -> String {
    let preimage = format!(
        "cb-receipt/v1|{seq}|{caller}|{name}|{scope}|{operation}|{method}|{host}|{outcome}|{at_unix_ms}"
    );
    hex::encode(Sha256::digest(preimage.as_bytes()))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Host part of a URL for receipts and scope checks: lowercased,
/// userinfo and port stripped.  Empty when the URL has no authority.
fn url_host(url: &str) -> String {
    let rest = match url.split_once("://") {
        Some((_, r)) => r,
        None => return String::new(),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    hostport
        .trim_start_matches('[')
        .split([':', ']'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

// ---------------------------------------------------------------------
// Backends.  A backend resolves a reference to a credential.  It is
// constructed with everything it may read; it must never embed a
// secret value in an error or a Debug string.
// ---------------------------------------------------------------------

pub trait CredentialBackend: Send + Sync {
    fn resolve(&self, reference: &CredentialRef) -> Result<ResolvedCredential, BrokerError>;
    /// References this backend can resolve (identifiers only).
    fn known_refs(&self) -> Vec<CredentialRef>;
}

/// The fail-closed default: knows nothing, resolves nothing.
pub struct NoBackend;

impl CredentialBackend for NoBackend {
    fn resolve(&self, reference: &CredentialRef) -> Result<ResolvedCredential, BrokerError> {
        Err(BrokerError::UnknownRef(reference.clone()))
    }
    fn known_refs(&self) -> Vec<CredentialRef> {
        vec![]
    }
}

/// In-memory backend: the provisioning side (host process, test)
/// inserts values; the broker side only ever resolves them.
/// `Debug` lists references and placements — never values.
pub struct MemoryBackend {
    entries: Mutex<HashMap<CredentialRef, (String, Placement)>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        MemoryBackend {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(
        &self,
        reference: CredentialRef,
        value: impl Into<String>,
        placement: Placement,
    ) {
        self.entries
            .lock()
            .expect("memory backend lock")
            .insert(reference, (value.into(), placement));
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MemoryBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().expect("memory backend lock");
        let mut refs: Vec<String> = entries
            .iter()
            .map(|(r, (_, p))| format!("{r} via {}", p.header_name()))
            .collect();
        refs.sort();
        f.debug_struct("MemoryBackend")
            .field("credentials", &refs)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl CredentialBackend for MemoryBackend {
    fn resolve(&self, reference: &CredentialRef) -> Result<ResolvedCredential, BrokerError> {
        let entries = self.entries.lock().expect("memory backend lock");
        match entries.get(reference) {
            Some((value, placement)) => Ok(ResolvedCredential::new(
                SecretValue::new(value.clone()),
                placement.clone(),
            )),
            None => Err(BrokerError::UnknownRef(reference.clone())),
        }
    }

    fn known_refs(&self) -> Vec<CredentialRef> {
        let entries = self.entries.lock().expect("memory backend lock");
        let mut refs: Vec<CredentialRef> = entries.keys().cloned().collect();
        refs.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
        refs
    }
}

/// One file per credential.  Constructed with the full
/// (reference → path, placement) list — the paths are injected by
/// the constructing process (host config, connector harness); this
/// crate hardcodes none and reads a file only when its reference is
/// resolved.  File content is the value, with one trailing newline
/// (or CRLF) trimmed — the shape `wrangler secret put` files and
/// `~/workspace/keys/*` files already have.
pub struct FileBackend {
    entries: Vec<(CredentialRef, std::path::PathBuf, Placement)>,
}

impl FileBackend {
    pub fn new(entries: Vec<(CredentialRef, std::path::PathBuf, Placement)>) -> Self {
        FileBackend { entries }
    }
}

impl fmt::Debug for FileBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Names and placements only — not even the paths: a secret
        // file's location is the constructing process's business.
        let refs: Vec<String> = self
            .entries
            .iter()
            .map(|(r, _, p)| format!("{r} via {}", p.header_name()))
            .collect();
        f.debug_struct("FileBackend")
            .field("credentials", &refs)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl CredentialBackend for FileBackend {
    fn resolve(&self, reference: &CredentialRef) -> Result<ResolvedCredential, BrokerError> {
        let (_, path, placement) = self
            .entries
            .iter()
            .find(|(r, _, _)| r == reference)
            .ok_or_else(|| BrokerError::UnknownRef(reference.clone()))?;
        let raw = std::fs::read_to_string(path).map_err(|e| {
            BrokerError::Backend(format!("read credential file for {reference}: {e}"))
        })?;
        let value = raw
            .strip_suffix("\r\n")
            .or_else(|| raw.strip_suffix('\n'))
            .unwrap_or(&raw)
            .to_string();
        if value.is_empty() {
            return Err(BrokerError::Backend(format!(
                "credential file for {reference} is empty"
            )));
        }
        Ok(ResolvedCredential::new(
            SecretValue::new(value),
            placement.clone(),
        ))
    }

    fn known_refs(&self) -> Vec<CredentialRef> {
        self.entries.iter().map(|(r, _, _)| r.clone()).collect()
    }
}

// ---------------------------------------------------------------------
// Grants — scoped, short-lived capability handles.  A handle id is
// an opaque sha256 over broker-instance nonce material; it is not a
// secret and grants no information about the credential behind it.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantHandle {
    pub id: String,
    pub credential_name: String,
    pub credential_scope: String,
    /// Hosts the grant may be redeemed against (exact host match,
    /// case-insensitive; the entry `"*"` means any host — mint it
    /// deliberately, it is scope in name only).
    pub scope_hosts: Vec<String>,
    pub expires_at_unix_ms: u64,
    /// Uses left at mint time (`None` = unlimited within the TTL).
    pub max_uses: Option<u32>,
}

struct GrantState {
    reference: CredentialRef,
    scope_hosts: Vec<String>,
    expires_at_unix_ms: u64,
    uses_left: Option<u32>,
}

// ---------------------------------------------------------------------
// The broker.
// ---------------------------------------------------------------------

pub struct Broker<B: CredentialBackend, T: HttpsTransport> {
    backend: B,
    transport: T,
    receipts: Mutex<Vec<BrokerReceipt>>,
    grants: Mutex<HashMap<String, GrantState>>,
    seq: AtomicU64,
    nonce: [u8; 16],
}

impl<B: CredentialBackend, T: HttpsTransport> Broker<B, T> {
    pub fn new(backend: B, transport: T) -> Self {
        Broker {
            backend,
            transport,
            receipts: Mutex::new(vec![]),
            grants: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(1),
            nonce: instance_nonce(),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// All receipts this broker has emitted, oldest first.
    pub fn receipts(&self) -> Vec<BrokerReceipt> {
        self.receipts.lock().expect("receipt lock").clone()
    }

    fn record(
        &self,
        caller: &str,
        name: &str,
        scope: &str,
        operation: &str,
        method: &str,
        host: &str,
        outcome: &str,
    ) -> BrokerReceipt {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let at = now_unix_ms();
        let receipt = BrokerReceipt {
            receipt_id: receipt_id(seq, caller, name, scope, operation, method, host, outcome, at),
            caller: caller.to_string(),
            credential_name: name.to_string(),
            credential_scope: scope.to_string(),
            operation: operation.to_string(),
            method: method.to_string(),
            host: host.to_string(),
            outcome: outcome.to_string(),
            at_unix_ms: at,
        };
        self.receipts
            .lock()
            .expect("receipt lock")
            .push(receipt.clone());
        receipt
    }

    /// Perform an HTTP request authenticated by `reference`.  The
    /// credential is resolved, attached per its placement, and
    /// spent inside the transport call — the caller receives the
    /// response and the receipt, never the value.
    pub fn execute_http(
        &self,
        caller: &str,
        reference: &CredentialRef,
        req: HttpsRequest,
    ) -> Result<(HttpsResponse, BrokerReceipt), BrokerError> {
        self.execute_inner(caller, reference, req, "http_request")
    }

    fn execute_inner(
        &self,
        caller: &str,
        reference: &CredentialRef,
        mut req: HttpsRequest,
        operation: &str,
    ) -> Result<(HttpsResponse, BrokerReceipt), BrokerError> {
        let method = req.method.as_str().to_string();
        let host = url_host(&req.url);
        let fail = |e: BrokerError, kind: &str| {
            self.record(
                caller,
                &reference.name,
                &reference.scope,
                operation,
                &method,
                &host,
                &format!("error:{kind}"),
            );
            e
        };
        let resolved = self
            .backend
            .resolve(reference)
            .map_err(|e| fail(e, "resolve"))?;
        resolved.placement.attach(&mut req, &resolved.value);
        // The resolved value's job is done once the header is on the
        // request; drop it (zeroing) before the network call so it
        // lives no longer than it must.
        drop(resolved);
        match self.transport.send(&req) {
            Ok(resp) => {
                let outcome = format!("ok:{}", resp.status);
                let receipt = self.record(
                    caller,
                    &reference.name,
                    &reference.scope,
                    operation,
                    &method,
                    &host,
                    &outcome,
                );
                Ok((resp, receipt))
            }
            Err(e) => Err(fail(BrokerError::Transport(e), "transport")),
        }
    }

    /// Mint a scoped, short-lived capability handle for
    /// `reference`.  The reference must resolve *now* — the broker
    /// never mints handles for credentials it does not hold
    /// (fail-closed at mint time, not at redeem time).
    pub fn grant(
        &self,
        caller: &str,
        reference: &CredentialRef,
        scope_hosts: Vec<String>,
        ttl_ms: u64,
        max_uses: Option<u32>,
    ) -> Result<(GrantHandle, BrokerReceipt), BrokerError> {
        let fail = |e: BrokerError| {
            self.record(
                caller,
                &reference.name,
                &reference.scope,
                "grant",
                "",
                "",
                "error:grant",
            );
            e
        };
        if ttl_ms == 0 {
            return Err(fail(BrokerError::InvalidRequest(
                "grant ttl_ms must be positive".to_string(),
            )));
        }
        if scope_hosts.is_empty() {
            return Err(fail(BrokerError::InvalidRequest(
                "grant needs at least one scope host".to_string(),
            )));
        }
        if max_uses == Some(0) {
            return Err(fail(BrokerError::InvalidRequest(
                "grant max_uses must be positive when set".to_string(),
            )));
        }
        // Fail-closed existence check; the resolved value is
        // dropped unused — minting must not spend or expose it.
        let _resolved = self.backend.resolve(reference).map_err(fail)?;
        drop(_resolved);

        let expires_at = now_unix_ms().saturating_add(ttl_ms);
        // Consume a sequence value so two handles minted in the
        // same millisecond still differ (receipt ids do the same).
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let id = {
            let preimage = format!(
                "cb-grant/v1|{}|{}|{}|{}",
                hex::encode(self.nonce),
                seq,
                reference,
                expires_at
            );
            format!("grant_{}", hex::encode(Sha256::digest(preimage.as_bytes())))
        };
        let scope_hosts: Vec<String> = scope_hosts
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        self.grants.lock().expect("grant lock").insert(
            id.clone(),
            GrantState {
                reference: reference.clone(),
                scope_hosts: scope_hosts.clone(),
                expires_at_unix_ms: expires_at,
                uses_left: max_uses,
            },
        );
        let receipt = self.record(
            caller,
            &reference.name,
            &reference.scope,
            "grant",
            "",
            "",
            "ok",
        );
        Ok((
            GrantHandle {
                id,
                credential_name: reference.name.clone(),
                credential_scope: reference.scope.clone(),
                scope_hosts,
                expires_at_unix_ms: expires_at,
                max_uses,
            },
            receipt,
        ))
    }

    /// Perform an HTTP request under a grant handle.  Checks, in
    /// order: handle known, not expired, uses left, host in scope —
    /// then executes exactly like [`Broker::execute_http`] against
    /// the grant's credential.
    pub fn redeem_http(
        &self,
        caller: &str,
        handle_id: &str,
        req: HttpsRequest,
    ) -> Result<(HttpsResponse, BrokerReceipt), BrokerError> {
        let method = req.method.as_str().to_string();
        let host = url_host(&req.url);
        let reference = {
            let mut grants = self.grants.lock().expect("grant lock");
            let state = match grants.get_mut(handle_id) {
                Some(s) => s,
                None => {
                    drop(grants);
                    self.record(
                        caller,
                        "<unknown-handle>",
                        "<unknown-handle>",
                        "redeem",
                        &method,
                        &host,
                        "error:unknown_handle",
                    );
                    return Err(BrokerError::UnknownHandle);
                }
            };
            let deny = |kind: &str, e: BrokerError, state: &GrantState| {
                self.record(
                    caller,
                    &state.reference.name,
                    &state.reference.scope,
                    "redeem",
                    &method,
                    &host,
                    &format!("error:{kind}"),
                );
                e
            };
            if now_unix_ms() > state.expires_at_unix_ms {
                let e = deny("expired", BrokerError::GrantExpired, state);
                return Err(e);
            }
            if state.uses_left == Some(0) {
                let e = deny("exhausted", BrokerError::GrantExhausted, state);
                return Err(e);
            }
            if !state.scope_hosts.iter().any(|h| h == "*" || h == &host) {
                let e = deny(
                    "scope",
                    BrokerError::ScopeDenied(host.clone()),
                    state,
                );
                return Err(e);
            }
            if let Some(left) = state.uses_left {
                state.uses_left = Some(left - 1);
            }
            state.reference.clone()
        };
        self.execute_inner(caller, &reference, req, "redeem")
    }

    /// Kill a grant handle before its expiry.  Revoking an unknown
    /// handle is `UnknownHandle` — the caller should learn its
    /// handle bookkeeping is wrong.
    pub fn revoke_grant(
        &self,
        caller: &str,
        handle_id: &str,
    ) -> Result<BrokerReceipt, BrokerError> {
        let removed = self.grants.lock().expect("grant lock").remove(handle_id);
        match removed {
            Some(state) => Ok(self.record(
                caller,
                &state.reference.name,
                &state.reference.scope,
                "revoke",
                "",
                "",
                "ok",
            )),
            None => {
                self.record(
                    caller,
                    "<unknown-handle>",
                    "<unknown-handle>",
                    "revoke",
                    "",
                    "",
                    "error:unknown_handle",
                );
                Err(BrokerError::UnknownHandle)
            }
        }
    }

    /// Inbound presentation check: does `presented` equal the
    /// stored credential for `reference`?  Answers a bool and a
    /// receipt — the stored value never leaves the backend.  The
    /// comparison is constant-time over the longer input.
    pub fn verify_presentation(
        &self,
        caller: &str,
        reference: &CredentialRef,
        presented: &[u8],
    ) -> Result<(bool, BrokerReceipt), BrokerError> {
        let resolved = self.backend.resolve(reference).map_err(|e| {
            self.record(
                caller,
                &reference.name,
                &reference.scope,
                "verify",
                "",
                "",
                "error:resolve",
            );
            e
        })?;
        let stored = resolved.value.expose().as_bytes();
        let mut diff: usize = stored.len() ^ presented.len();
        let n = stored.len().max(presented.len());
        for i in 0..n {
            let a = stored.get(i).copied().unwrap_or(0);
            let b = presented.get(i).copied().unwrap_or(0);
            diff |= (a ^ b) as usize;
        }
        let matched = diff == 0;
        let receipt = self.record(
            caller,
            &reference.name,
            &reference.scope,
            "verify",
            "",
            "",
            if matched { "match" } else { "no_match" },
        );
        Ok((matched, receipt))
    }
}

impl<B: CredentialBackend, T: HttpsTransport> fmt::Debug for Broker<B, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // References and counts only — a broker's Debug must be as
        // safe to log as its receipts are.
        f.debug_struct("Broker")
            .field("known_refs", &self.backend.known_refs())
            .field("receipts", &self.receipts.lock().expect("receipt lock").len())
            .field("grants", &self.grants.lock().expect("grant lock").len())
            .field("values", &"<redacted>")
            .finish()
    }
}

/// The broker on the platform default transport (ureq/rustls
/// native; on wasm32 `HostTransport::send` is the transport's
/// honest `Unsupported` — wasm consumers inject a fetch transport).
pub type HostBroker<B> = Broker<B, HostTransport>;

impl<B: CredentialBackend> Broker<B, HostTransport> {
    pub fn with_host_transport(backend: B) -> Self {
        Broker::new(backend, HostTransport)
    }
}

/// Per-instance nonce for grant ids.  Unix: `/dev/urandom`.
/// Elsewhere: time/counter material — grant ids need opacity
/// against guessing, and on such targets this is best-effort;
/// the TTL + scope + use-count checks do not depend on it.
fn instance_nonce() -> [u8; 16] {
    #[cfg(all(unix, not(all(target_arch = "wasm32", target_os = "unknown"))))]
    {
        use std::io::Read;
        let mut buf = [0u8; 16];
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            if file.read_exact(&mut buf).is_ok() {
                return buf;
            }
        }
    }
    let mut buf = [0u8; 16];
    let seed = format!(
        "cb-nonce|{}|{}",
        now_unix_ms(),
        std::process::id()
    );
    let digest = Sha256::digest(seed.as_bytes());
    buf.copy_from_slice(&digest[..16]);
    buf
}

// ---------------------------------------------------------------------
// Organelle trait surface (codon `cb`).  The broker is injected —
// `organelle()` alone is the fail-closed shell (NoBackend), hosts
// use `organelle_with_broker` with the broker they provisioned.
// ---------------------------------------------------------------------

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    let ref_schema = serde_json::json!({
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "scope": {"type": "string", "minLength": 1}
        }
    });
    let request_props = |mut base: serde_json::Map<String, Value>| {
        base.insert("method".into(), serde_json::json!({"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]}));
        base.insert("url".into(), serde_json::json!({"type": "string", "minLength": 8}));
        base.insert("headers".into(), serde_json::json!({"type": "object"}));
        base.insert("body_text".into(), serde_json::json!({"type": "string"}));
        base.insert("timeout_ms".into(), serde_json::json!({"type": "integer", "minimum": 1, "maximum": 300000}));
        base.insert("max_bytes".into(), serde_json::json!({"type": "integer", "minimum": 1, "maximum": 67108864}));
        base.insert("allow_http".into(), serde_json::json!({"type": "boolean"}));
        serde_json::Value::Object(base)
    };
    let mut execute_props = serde_json::Map::new();
    execute_props.insert("ref".into(), ref_schema.clone());
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "credential-broker".to_string(),
        codon: "cb".to_string(),
        version: "1.0.0".to_string(),
        description:
            "scoped credential broker: performs authenticated requests, mints scoped short-lived grant handles, verifies presentations — secret values never cross the API"
                .to_string(),
        contracts: vec![
            Contract {
                op: "execute".to_string(),
                description:
                    "perform one HTTP request authenticated by the named credential ref; returns status/body and the broker receipt, never the value"
                        .to_string(),
                input_schema: request_props(execute_props),
                mutation_class: Some(MutationClass::ExternalEffect),
                required_capability: Some("cred.broker".to_string()),
            },
            Contract {
                op: "grant".to_string(),
                description:
                    "mint a scoped short-lived capability handle for a credential ref (scope_hosts + ttl_secs, optional max_uses)"
                        .to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["ref", "scope_hosts", "ttl_secs"],
                    "properties": {
                        "ref": ref_schema.clone(),
                        "scope_hosts": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "ttl_secs": {"type": "integer", "minimum": 1, "maximum": 86400},
                        "max_uses": {"type": "integer", "minimum": 1}
                    }
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cred.grant".to_string()),
            },
            Contract {
                op: "redeem".to_string(),
                description:
                    "perform one HTTP request under a grant handle (handle scope/expiry/uses enforced)"
                        .to_string(),
                input_schema: request_props({
                    let mut m = serde_json::Map::new();
                    m.insert("handle".into(), serde_json::json!({"type": "string", "minLength": 8}));
                    m
                }),
                mutation_class: Some(MutationClass::ExternalEffect),
                required_capability: Some("cred.broker".to_string()),
            },
            Contract {
                op: "revoke".to_string(),
                description: "kill a grant handle before its expiry".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["handle"],
                    "properties": {
                        "handle": {"type": "string", "minLength": 8}
                    }
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cred.grant".to_string()),
            },
            Contract {
                op: "verify".to_string(),
                description:
                    "check a presented value against the stored credential for a ref; answers match/no_match, never returns the stored value"
                        .to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["ref", "presented"],
                    "properties": {
                        "ref": ref_schema,
                        "presented": {"type": "string"}
                    }
                }),
                mutation_class: Some(MutationClass::ReadOnly),
                required_capability: Some("cred.verify".to_string()),
            },
            Contract {
                op: "receipts".to_string(),
                description:
                    "recent broker receipts (caller, ref, operation, outcome, time — never values)"
                        .to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000}
                    }
                }),
                mutation_class: None,
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ExternalEffect,
            declared_valence: Valence::Candidate,
            required_capability: Some("cred.broker".to_string()),
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
pub struct CredentialBrokerOrganelle<B: CredentialBackend, T: HttpsTransport> {
    manifest: OrganelleManifest,
    broker: std::sync::Arc<Broker<B, T>>,
}

#[cfg(feature = "organelle")]
pub fn organelle_with_broker<
    B: CredentialBackend + 'static,
    T: HttpsTransport + Send + Sync + 'static,
>(
    broker: std::sync::Arc<Broker<B, T>>,
) -> std::sync::Arc<dyn Organelle> {
    std::sync::Arc::new(CredentialBrokerOrganelle {
        manifest: manifest(),
        broker,
    })
}

/// The fail-closed shell: a broker with `NoBackend`.  Every
/// credential operation fails with `unknown credential ref` until a
/// host injects a provisioned broker via `organelle_with_broker`.
#[cfg(feature = "organelle")]
pub fn organelle() -> std::sync::Arc<dyn Organelle> {
    organelle_with_broker(std::sync::Arc::new(Broker::with_host_transport(NoBackend)))
}

#[cfg(feature = "organelle")]
fn parse_ref(input: &Value) -> Result<CredentialRef, OrganelleError> {
    let name = input["ref"]["name"].as_str().unwrap_or("");
    let scope = input["ref"]["scope"].as_str().unwrap_or("default");
    CredentialRef::new(name, scope)
        .map_err(|e| OrganelleError::new("rejected", e.to_string()))
}

#[cfg(feature = "organelle")]
fn parse_request(input: &Value) -> Result<HttpsRequest, OrganelleError> {
    use ref_https_transport::Method;
    let url = input["url"].as_str().unwrap_or("");
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
    Ok(req)
}

#[cfg(feature = "organelle")]
fn response_json(resp: &HttpsResponse, receipt: &BrokerReceipt) -> Value {
    serde_json::json!({
        "status": resp.status,
        "headers": resp.headers.iter().map(|(k, v)| serde_json::json!({"name": k, "value": v})).collect::<Vec<_>>(),
        "body": resp.body_text_lossy(),
        "bytes": resp.body.len(),
        "truncated": resp.truncated,
        "receipt": serde_json::to_value(receipt).unwrap_or(Value::Null),
    })
}

#[cfg(feature = "organelle")]
impl<B: CredentialBackend, T: HttpsTransport + Send + Sync> Organelle
    for CredentialBrokerOrganelle<B, T>
{
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        ctx: &CallContext,
        host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        let caller = ctx.caller.as_str();
        let fail = |e: BrokerError| OrganelleError::failed(e.to_string());
        match op {
            "execute" => {
                let reference = parse_ref(&input)?;
                let req = parse_request(&input)?;
                // Same policy seam as ref-https-transport: the
                // host's egress allowlist decides before the broker
                // resolves or sends anything.
                host.approve_egress(&req.url)?;
                let (resp, receipt) = self
                    .broker
                    .execute_http(caller, &reference, req)
                    .map_err(fail)?;
                Ok(response_json(&resp, &receipt))
            }
            "grant" => {
                let reference = parse_ref(&input)?;
                let scope_hosts: Vec<String> = input["scope_hosts"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let ttl_secs = input["ttl_secs"].as_u64().unwrap_or(0);
                let max_uses = input["max_uses"].as_u64().map(|n| n as u32);
                let (handle, receipt) = self
                    .broker
                    .grant(caller, &reference, scope_hosts, ttl_secs.saturating_mul(1000), max_uses)
                    .map_err(fail)?;
                Ok(serde_json::json!({
                    "handle": serde_json::to_value(&handle).unwrap_or(Value::Null),
                    "receipt": serde_json::to_value(&receipt).unwrap_or(Value::Null),
                }))
            }
            "redeem" => {
                let handle = input["handle"].as_str().unwrap_or("");
                let req = parse_request(&input)?;
                host.approve_egress(&req.url)?;
                let (resp, receipt) = self
                    .broker
                    .redeem_http(caller, handle, req)
                    .map_err(fail)?;
                Ok(response_json(&resp, &receipt))
            }
            "revoke" => {
                let handle = input["handle"].as_str().unwrap_or("");
                let receipt = self.broker.revoke_grant(caller, handle).map_err(fail)?;
                Ok(serde_json::json!({
                    "revoked": true,
                    "receipt": serde_json::to_value(&receipt).unwrap_or(Value::Null),
                }))
            }
            "verify" => {
                let reference = parse_ref(&input)?;
                let presented = input["presented"].as_str().unwrap_or("");
                let (matched, receipt) = self
                    .broker
                    .verify_presentation(caller, &reference, presented.as_bytes())
                    .map_err(fail)?;
                Ok(serde_json::json!({
                    "match": matched,
                    "receipt": serde_json::to_value(&receipt).unwrap_or(Value::Null),
                }))
            }
            "receipts" => {
                let limit = input["limit"].as_u64().unwrap_or(100) as usize;
                let all = self.broker.receipts();
                let start = all.len().saturating_sub(limit);
                Ok(serde_json::json!({
                    "receipts": serde_json::to_value(&all[start..]).unwrap_or(Value::Null),
                    "total": all.len(),
                }))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------
// Tests.  The fixture secret is deliberately loud: if it ever shows
// up in an output, the grep test cannot miss it.
// ---------------------------------------------------------------------

#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Arc;

    const SECRET: &str = "sk-TEST-SECRET-9f8e7d6c-DO-NOT-LEAK";

    fn test_ref() -> CredentialRef {
        CredentialRef::new("fixture-provider", "provider-api").unwrap()
    }

    fn memory_broker<T: HttpsTransport>(transport: T) -> Broker<MemoryBackend, T> {
        let backend = MemoryBackend::new();
        backend.insert(test_ref(), SECRET, Placement::BearerHeader);
        Broker::new(backend, transport)
    }

    /// A transport that records every request and answers a canned
    /// 200 — the deterministic half of the end-to-end proof.
    pub(crate) struct RecordingTransport {
        sent: Mutex<Vec<HttpsRequest>>,
    }

    impl RecordingTransport {
        pub(crate) fn new() -> Self {
            RecordingTransport {
                sent: Mutex::new(vec![]),
            }
        }
        pub(crate) fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
        pub(crate) fn last(&self) -> HttpsRequest {
            self.sent.lock().unwrap().last().unwrap().clone()
        }
    }

    impl HttpsTransport for RecordingTransport {
        fn send(&self, req: &HttpsRequest) -> Result<HttpsResponse, TransportError> {
            self.sent.lock().unwrap().push(req.clone());
            Ok(HttpsResponse {
                status: 200,
                headers: vec![("x-fixture".to_string(), "yes".to_string())],
                body: b"recorded-ok".to_vec(),
                truncated: false,
            })
        }
    }

    /// A real HTTP fixture on a real socket: captures the raw
    /// request bytes so the auth header is proven on the wire, not
    /// just in a struct.
    fn serve_once_capturing() -> (u16, Arc<Mutex<String>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(String::new()));
        let cap = captured.clone();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            *cap.lock().unwrap() = String::from_utf8_lossy(&buf).into_owned();
            let body = b"fixture-ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(body);
        });
        (port, captured)
    }

    // (a) Auth carried end-to-end against a local fixture.
    // Needs the `native` feature: HostTransport's ureq backend is
    // behind it (without it the transport honestly answers
    // Unsupported, and the RecordingTransport tests carry the core).
    #[cfg(feature = "native")]
    #[test]
    fn brokered_request_carries_auth_end_to_end() {
        let (port, captured) = serve_once_capturing();
        let broker = memory_broker(HostTransport);
        let req = HttpsRequest::get(format!("http://127.0.0.1:{port}/v1/thing"))
            .allow_http(true)
            .timeout_ms(5_000);
        let (resp, receipt) = broker
            .execute_http("test-caller", &test_ref(), req)
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"fixture-ok");
        // On the wire: the fixture saw the bearer credential.
        // (Header-name case is the transport's choice — ureq sends
        // it lowercase — so match on the credential value itself.)
        let raw = captured.lock().unwrap().clone();
        assert!(
            raw.contains(&format!("Bearer {SECRET}")),
            "fixture request did not carry the credential:\n{raw}"
        );
        // The receipt describes the operation — and only that.
        assert_eq!(receipt.caller, "test-caller");
        assert_eq!(receipt.credential_name, "fixture-provider");
        assert_eq!(receipt.credential_scope, "provider-api");
        assert_eq!(receipt.operation, "http_request");
        assert_eq!(receipt.method, "GET");
        assert_eq!(receipt.host, "127.0.0.1");
        assert_eq!(receipt.outcome, "ok:200");
        assert_eq!(receipt.receipt_id.len(), 64);
    }

    #[test]
    fn custom_header_placement_attaches() {
        let transport = RecordingTransport::new();
        let backend = MemoryBackend::new();
        backend.insert(
            test_ref(),
            SECRET,
            Placement::CustomHeader("x-api-key".to_string()),
        );
        let broker = Broker::new(backend, transport);
        let req = HttpsRequest::get("https://api.example.test/v1").header("x-api-key", "caller-junk");
        broker.execute_http("c", &test_ref(), req).unwrap();
        let sent = broker.transport_last();
        assert_eq!(sent.header_count("x-api-key"), 1);
        assert_eq!(sent.header_value("x-api-key"), Some(SECRET));
        assert_eq!(sent.header_count("Authorization"), 0);
    }

    // (b) The grep test: the secret appears NOWHERE in any output,
    // error, or Debug string this crate produces — across success,
    // failure, grant, redeem, verify, and diagnostics paths.
    #[test]
    fn secret_appears_nowhere_in_outputs() {
        let transport = RecordingTransport::new();
        let broker = memory_broker(transport);
        let mut outputs: Vec<String> = vec![];

        // Success path.
        let (resp, receipt) = broker
            .execute_http(
                "grep-caller",
                &test_ref(),
                HttpsRequest::get("https://api.example.test/ok"),
            )
            .unwrap();
        outputs.push(format!("{resp:?}"));
        outputs.push(format!("{receipt:?}"));
        outputs.push(serde_json::to_string(&receipt).unwrap());

        // Unknown ref error.
        let unknown = CredentialRef::new("nope", "default").unwrap();
        let err = broker
            .execute_http("grep-caller", &unknown, HttpsRequest::get("https://api.example.test/"))
            .unwrap_err();
        outputs.push(format!("{err}"));
        outputs.push(format!("{err:?}"));

        // Grant + redeem + scope denial + revoke + unknown handle.
        let (handle, greceipt) = broker
            .grant(
                "grep-caller",
                &test_ref(),
                vec!["api.example.test".to_string()],
                60_000,
                Some(2),
            )
            .unwrap();
        outputs.push(format!("{handle:?}"));
        outputs.push(serde_json::to_string(&handle).unwrap());
        outputs.push(format!("{greceipt:?}"));
        let err = broker
            .redeem_http(
                "grep-caller",
                &handle.id,
                HttpsRequest::get("https://other.example.test/"),
            )
            .unwrap_err();
        outputs.push(format!("{err}"));
        let (_, rreceipt) = broker
            .redeem_http(
                "grep-caller",
                &handle.id,
                HttpsRequest::get("https://api.example.test/in-scope"),
            )
            .unwrap();
        outputs.push(format!("{rreceipt:?}"));
        outputs.push(format!(
            "{:?}",
            broker.revoke_grant("grep-caller", &handle.id).unwrap()
        ));
        let err = broker
            .redeem_http(
                "grep-caller",
                &handle.id,
                HttpsRequest::get("https://api.example.test/"),
            )
            .unwrap_err();
        outputs.push(format!("{err}"));

        // Verify: match and no-match.
        let (matched, vreceipt) = broker
            .verify_presentation("grep-caller", &test_ref(), SECRET.as_bytes())
            .unwrap();
        assert!(matched);
        outputs.push(format!("{vreceipt:?}"));
        let (matched, _) = broker
            .verify_presentation("grep-caller", &test_ref(), b"wrong-value")
            .unwrap();
        assert!(!matched);

        // Diagnostics: broker + backend Debug, full receipt log.
        outputs.push(format!("{:?}", broker));
        outputs.push(format!("{:?}", broker.backend()));
        outputs.push(serde_json::to_string(&broker.receipts()).unwrap());

        for (i, out) in outputs.iter().enumerate() {
            assert!(
                !out.contains(SECRET),
                "output #{i} leaked the secret: {out}"
            );
        }
        // Sanity: the value really did flow to the transport — the
        // absence above is the broker's discipline, not a dead path.
        let sent = broker.transport_last();
        let bearer = format!("Bearer {SECRET}");
        assert_eq!(sent.header_value("Authorization"), Some(bearer.as_str()));
    }

    // (c) Unknown refs fail closed: error, no send, receipt kept.
    #[test]
    fn unknown_ref_fails_closed() {
        let transport = RecordingTransport::new();
        let broker = Broker::new(MemoryBackend::new(), transport);
        let unknown = CredentialRef::new("ghost", "default").unwrap();
        let err = broker
            .execute_http("c", &unknown, HttpsRequest::get("https://api.example.test/"))
            .unwrap_err();
        assert_eq!(err, BrokerError::UnknownRef(unknown.clone()));
        // Nothing was sent anywhere.
        assert_eq!(broker.transport_count(), 0);
        // The attempt is still on the receipt log.
        let receipts = broker.receipts();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, "error:resolve");
        assert_eq!(receipts[0].credential_name, "ghost");
        // Grant also fails closed at mint time.
        let err = broker
            .grant("c", &unknown, vec!["api.example.test".to_string()], 1_000, None)
            .unwrap_err();
        assert_eq!(err, BrokerError::UnknownRef(unknown));
        // Verify fails closed too.
        assert!(matches!(
            broker.verify_presentation("c", &CredentialRef::new("ghost", "default").unwrap(), b"x"),
            Err(BrokerError::UnknownRef(_))
        ));
    }

    #[test]
    fn grant_lifecycle_scope_expiry_uses() {
        let transport = RecordingTransport::new();
        let broker = memory_broker(transport);

        // Uses: exactly one redemption.
        let (handle, _) = broker
            .grant("c", &test_ref(), vec!["api.example.test".to_string()], 60_000, Some(1))
            .unwrap();
        broker
            .redeem_http("c", &handle.id, HttpsRequest::get("https://api.example.test/a"))
            .unwrap();
        let err = broker
            .redeem_http("c", &handle.id, HttpsRequest::get("https://api.example.test/b"))
            .unwrap_err();
        assert_eq!(err, BrokerError::GrantExhausted);

        // Expiry: a 1 ms TTL is dead on arrival in practice.
        let (short, _) = broker
            .grant("c", &test_ref(), vec!["api.example.test".to_string()], 1, None)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let err = broker
            .redeem_http("c", &short.id, HttpsRequest::get("https://api.example.test/"))
            .unwrap_err();
        assert_eq!(err, BrokerError::GrantExpired);

        // Unknown handle.
        let err = broker
            .redeem_http("c", "grant_deadbeef", HttpsRequest::get("https://api.example.test/"))
            .unwrap_err();
        assert_eq!(err, BrokerError::UnknownHandle);

        // Bad grant shapes refused at mint time.
        assert!(matches!(
            broker.grant("c", &test_ref(), vec![], 1_000, None),
            Err(BrokerError::InvalidRequest(_))
        ));
        assert!(matches!(
            broker.grant("c", &test_ref(), vec!["h".to_string()], 0, None),
            Err(BrokerError::InvalidRequest(_))
        ));
    }

    #[test]
    fn file_backend_resolves_injected_path() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cb-test-cred-{}.txt", std::process::id()));
        std::fs::write(&path, format!("{SECRET}\n")).unwrap();
        let backend = FileBackend::new(vec![(test_ref(), path.clone(), Placement::BearerHeader)]);
        // The backend's own Debug must not carry the value either.
        assert!(!format!("{backend:?}").contains(SECRET));
        let transport = RecordingTransport::new();
        let broker = Broker::new(backend, transport);
        broker
            .execute_http("c", &test_ref(), HttpsRequest::get("https://api.example.test/"))
            .unwrap();
        let sent = broker.transport_last();
        // Trailing newline trimmed by the backend.
        let bearer = format!("Bearer {SECRET}");
        assert_eq!(sent.header_value("Authorization"), Some(bearer.as_str()));
        let _ = std::fs::remove_file(&path);
        // After removal the backend fails closed with a Backend
        // error that names the ref — and still not the value.
        let err = broker
            .execute_http("c", &test_ref(), HttpsRequest::get("https://api.example.test/"))
            .unwrap_err();
        assert!(matches!(err, BrokerError::Backend(_)));
        assert!(!format!("{err}").contains(SECRET));
    }

    #[test]
    fn ref_validation_rejects_garbage() {
        assert!(CredentialRef::new("", "default").is_err());
        assert!(CredentialRef::new("has space", "default").is_err());
        assert!(CredentialRef::new("ok", "").is_err());
        assert!(CredentialRef::unscoped("fine").is_ok());
    }

    // Small helpers so the tests above read cleanly.
    impl<B: CredentialBackend> Broker<B, RecordingTransport> {
        fn transport_count(&self) -> usize {
            self.transport.count()
        }
        fn transport_last(&self) -> HttpsRequest {
            self.transport.last()
        }
    }
}

// Test-only conveniences on the transport's request shape.
#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
trait HeaderProbe {
    fn header_count(&self, name: &str) -> usize;
    fn header_value(&self, name: &str) -> Option<&str>;
}

#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
impl HeaderProbe for HttpsRequest {
    fn header_count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }
    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(all(test, feature = "organelle", not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod organelle_tests {
    use super::tests::RecordingTransport;
    use super::*;
    use organelle_host::Host;
    use std::sync::Arc;

    const SECRET: &str = "sk-TEST-SECRET-9f8e7d6c-DO-NOT-LEAK";

    fn brokered_host() -> (Arc<Host>, Arc<Broker<MemoryBackend, RecordingTransport>>) {
        let backend = MemoryBackend::new();
        let r = CredentialRef::new("fixture-provider", "provider-api").unwrap();
        backend.insert(r, SECRET, Placement::BearerHeader);
        let broker = Arc::new(Broker::new(backend, RecordingTransport::new()));
        let h = Host::new();
        h.set_egress_policy(
            organelle_host::EgressPolicy::allowlist(&["api.example.test"]).expect("allowlist"),
        );
        h.register(organelle_with_broker(broker.clone())).unwrap();
        (h, broker)
    }

    fn ctx() -> CallContext {
        CallContext::new(
            "organelle-test",
            vec![
                "cred.broker".to_string(),
                "cred.grant".to_string(),
                "cred.verify".to_string(),
            ],
        )
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }

    #[test]
    fn execute_and_receipts_through_host() {
        let (h, broker) = brokered_host();
        let out = h
            .call(
                &ctx(),
                "cb",
                "execute",
                serde_json::json!({
                    "ref": {"name": "fixture-provider", "scope": "provider-api"},
                    "url": "https://api.example.test/v1/thing"
                }),
            )
            .unwrap()
            .output;
        assert_eq!(out["status"], serde_json::json!(200));
        assert_eq!(out["receipt"]["caller"], serde_json::json!("organelle-test"));
        assert_eq!(out["receipt"]["outcome"], serde_json::json!("ok:200"));
        // The transport really received the credential.
        assert_eq!(broker.receipts().len(), 1);

        let out = h
            .call(&ctx(), "cb", "receipts", serde_json::json!({"limit": 10}))
            .unwrap()
            .output;
        assert_eq!(out["total"], serde_json::json!(1));
        assert!(!out.to_string().contains(SECRET));
    }

    #[test]
    fn grant_redeem_revoke_through_host() {
        let (h, _broker) = brokered_host();
        let out = h
            .call(
                &ctx(),
                "cb",
                "grant",
                serde_json::json!({
                    "ref": {"name": "fixture-provider", "scope": "provider-api"},
                    "scope_hosts": ["api.example.test"],
                    "ttl_secs": 60,
                    "max_uses": 1
                }),
            )
            .unwrap()
            .output;
        let handle = out["handle"]["id"].as_str().unwrap().to_string();
        assert!(handle.starts_with("grant_"));
        let out = h
            .call(
                &ctx(),
                "cb",
                "redeem",
                serde_json::json!({
                    "handle": handle,
                    "url": "https://api.example.test/v1/thing"
                }),
            )
            .unwrap()
            .output;
        assert_eq!(out["status"], serde_json::json!(200));
        let out = h
            .call(
                &ctx(),
                "cb",
                "revoke",
                serde_json::json!({"handle": handle}),
            )
            .unwrap()
            .output;
        assert_eq!(out["revoked"], serde_json::json!(true));
    }

    #[test]
    fn unknown_ref_through_host_fails() {
        let (h, _broker) = brokered_host();
        let out = h.call(
            &ctx(),
            "cb",
            "execute",
            serde_json::json!({
                "ref": {"name": "ghost"},
                "url": "https://api.example.test/"
            }),
        );
        assert!(out.is_err());
    }

    #[test]
    fn unprovisioned_organelle_fails_closed() {
        let h = Host::new();
        h.set_egress_policy(
            organelle_host::EgressPolicy::allowlist(&["api.example.test"]).expect("allowlist"),
        );
        h.register(organelle()).unwrap();
        let out = h.call(
            &ctx(),
            "cb",
            "execute",
            serde_json::json!({
                "ref": {"name": "anything"},
                "url": "https://api.example.test/"
            }),
        );
        assert!(out.is_err());
    }
}
