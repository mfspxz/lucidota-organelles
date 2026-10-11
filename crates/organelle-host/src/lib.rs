//! org-002 — parkwreck-organelle-host rebuild.
//!
//! The host is the membrane: it loads manifests, routes calls to organelles
//! (the proteins), and enforces fail-closed semantics on every path.
//!
//! Also implements, as host behaviors with their own test suites:
//! - org-008 fail-closed behavior suite (see `tests/fail_closed.rs`)
//! - org-009 profile activation (+ rollback, receipted)
//! - org-010 content-addressed, hash-chained receipts (offline verifiable)
//! - org-011 authority boundary enforcement (organelle -> organelle calls)
//! - org-012 hot-swap organelle versions (pin / latest / split, rollback)
//! - lifecycle: suspend / checkpoint / kill with receipted checkpoints.
//!
//! Design rules:
//! - Every `call` emits exactly one receipt, including denials and rejections.
//!   There is no silent pass. Lifecycle actions are receipted too: suspend
//!   emits a Suspend receipt plus a Checkpoint receipt carrying the sha256 of
//!   the checkpoint bytes; kill is suspend-first and emits a Kill receipt as
//!   the organelle's final receipt. There is no silent kill.
//! - The dispatch lock is never held across `handle()` — or across the
//!   lifecycle hooks `suspend()` / `kill()`: an organelle calling back into
//!   the host cannot deadlock it.
//! - `Host` is `Send + Sync` behind interior mutability so all four transport
//!   surfaces can share one `Arc<Host>`.

use organelle_manifest::{
    canonical_json, hash_value, sha256_hex, utc_now_iso, validate_input_against_schema,
    validate_manifest_json, ManifestError, OrganelleManifest, Transport, Valence,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

mod authority;
pub use authority::{GrantError, GrantErrorKind, VerifiedGrant};

// ---------------------------------------------------------------------------
// Organelle trait (the protein side of the membrane)
// ---------------------------------------------------------------------------

/// Error returned by an organelle's `handle`.
#[derive(Debug, Clone)]
pub struct OrganelleError {
    pub code: &'static str,
    pub message: String,
}

impl OrganelleError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        OrganelleError { code, message: message.into() }
    }
    pub fn failed(message: impl Into<String>) -> Self {
        Self::new("failed", message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }
    pub fn denied(message: impl Into<String>) -> Self {
        Self::new("denied", message)
    }
}

impl std::fmt::Display for OrganelleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Who is calling, and with what authority.
#[derive(Debug, Clone)]
pub struct CallContext {
    pub caller: String,
    pub capabilities: Vec<String>,
    pub trace_id: String,
}

impl CallContext {
    pub fn new(caller: impl Into<String>, capabilities: Vec<String>) -> Self {
        static CTR: AtomicU64 = AtomicU64::new(1);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        CallContext {
            caller: caller.into(),
            capabilities,
            trace_id: format!("t{n:016x}"),
        }
    }

    pub fn has(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }
}

/// What an organelle may ask of the host. Deliberately narrow: the only
/// outward call is to another organelle, and it is authority-checked
/// (org-011). This is the membrane's outbound channel.
///
/// `caller_trace` is the trace id of the invocation that is currently
/// executing the caller: the host re-resolves the caller's *routed*
/// implementation version from it (P1: the same routing policy that
/// executed the caller, so the boundary check consults the caller's real
/// version, not blindly the latest).
pub trait HostRef: Send + Sync {
    fn call_organelle(
        &self,
        caller_codon: &str,
        caller_trace: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError>;
}

/// The organelle contract, mirroring `ToolOrganelle::handle`.
///
/// Lifecycle hooks are optional: both have default impls, so existing
/// organelles keep compiling untouched. Stateful organelles override
/// `suspend()` to serialize their state into the checkpoint bytes; the
/// default is an ephemeral (empty) checkpoint.
pub trait Organelle: Send + Sync {
    fn manifest(&self) -> OrganelleManifest;
    fn handle(
        &self,
        ctx: &CallContext,
        host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError>;

    /// Quiesce and capture state. The host records the checkpoint bytes'
    /// hash on a Checkpoint receipt. Default: ephemeral, nothing to save.
    fn suspend(&self) -> Checkpoint {
        Checkpoint {
            codon: self.manifest().codon,
            ts: utc_now_iso(),
            bytes: Vec::new(),
            ephemeral: true,
        }
    }

    /// Release resources after suspend. Called by `Host::kill` between
    /// the suspend/checkpoint receipts and the final Kill receipt.
    /// Default: no-op.
    fn kill(&self) {}
}

/// Serializable checkpoint captured by `Organelle::suspend`. `ephemeral`
/// checkpoints carry no bytes; stateful organelles fill `bytes` with their
/// serialized state (the host receipt holds the sha256 of `bytes`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub codon: String,
    pub ts: String,
    pub bytes: Vec<u8>,
    pub ephemeral: bool,
}

// ---------------------------------------------------------------------------
// Invocation binding (P1: identity + version + authority, bound once)
// ---------------------------------------------------------------------------

/// The (caller identity, organelle id, implementation version, granted
/// capabilities, arrival transport) tuple bound to one invocation.
///
/// Established exactly once per invocation — at resolution time, before
/// any authorization decision and before execution — and immutable
/// afterwards: it is moved by value through the authorize -> execute ->
/// receipt phases, never re-derived. The authorization decision and the
/// execution below both consume THIS binding, so a version skew (authorize
/// one implementation, execute another) is structurally impossible.
/// Any failure to establish the binding is a fail-closed denial.
#[derive(Debug, Clone)]
pub struct InvocationBinding {
    pub caller: String,
    pub codon: String,
    pub op: String,
    /// Implementation version, resolved exactly once from the routing
    /// policy. Both the capability check and `handle()` use this version's
    /// manifest and implementation.
    pub version: String,
    /// The capabilities this invocation is authorized with: from the
    /// verified grant (external surfaces), the caller's own context
    /// (native surface), or the calling organelle's manifest (membrane).
    pub granted_capabilities: Vec<String>,
    /// Transport the invocation arrived over. `None` = internal membrane
    /// action (organelle->organelle, lifecycle, control-plane), which is
    /// not a surface arrival and skips transport restriction.
    pub transport: Option<Transport>,
}

impl InvocationBinding {
    /// Binding for control-plane / lifecycle receipts: not an organelle
    /// invocation, so no capabilities and no arrival transport.
    fn synthetic(caller: &str, codon: &str, op: &str, version: &str) -> Self {
        InvocationBinding {
            caller: caller.to_string(),
            codon: codon.to_string(),
            op: op.to_string(),
            version: version.to_string(),
            granted_capabilities: Vec::new(),
            transport: None,
        }
    }
}

/// One codon resolution, captured once per invocation: the manifest, the
/// implementation, and the binding. The lock is never held across
/// `handle()`; the `Arc` keeps the exact resolved implementation alive
/// for execution even if the registry changes underneath.
struct ResolvedCall {
    binding: InvocationBinding,
    manifest: OrganelleManifest,
    organelle: Arc<dyn Organelle>,
}

// ---------------------------------------------------------------------------
// Receipts (org-010)
// ---------------------------------------------------------------------------

/// Terminal verdict of one call. `Ok` only when the organelle ran and
/// returned output; everything else is an explicit, receipted refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallVerdict {
    Ok,
    Denied,
    Rejected,
    Failed,
}

/// Kind of receipt. Invocations dominate; control-plane actions are receipted
/// too so the chain is a complete audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Invocation,
    ProfileActivate,
    ProfileRollback,
    RouteChange,
    RouteRollback,
    Registration,
    Suspend,
    Checkpoint,
    Kill,
}

/// One content-addressed, hash-chained receipt per host action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// sha256 hex over the canonical JSON of every other field.
    pub id: String,
    pub ts: String,
    pub seq: u64,
    pub kind: ReceiptKind,
    pub codon: String,
    pub op: String,
    pub manifest_version: String,
    pub caller: String,
    /// Granted capabilities bound to this invocation, established
    /// pre-execution from the invocation binding (P1). Covered by the
    /// receipt id hash; empty for control-plane receipts.
    pub granted_capabilities: Vec<String>,
    /// Transport the invocation arrived over (P1). `None` for internal
    /// membrane actions (organelle->organelle calls, lifecycle,
    /// control-plane). Covered by the receipt id hash.
    pub transport: Option<Transport>,
    pub input_hash: String,
    /// sha256 of canonical output, or `denied:<reason>` / `rejected:<reason>`
    /// / `failed:<code>` for non-Ok verdicts (still content-addressed).
    pub output_hash: String,
    pub verdict: CallVerdict,
    pub valence: Valence,
    /// Previous receipt id, or "GENESIS".
    pub prev: String,
    pub note: Option<String>,
}

impl Receipt {
    fn body_json(&self) -> Value {
        serde_json::json!({
            "ts": self.ts, "seq": self.seq, "kind": self.kind,
            "codon": self.codon, "op": self.op,
            "manifest_version": self.manifest_version,
            "caller": self.caller,
            "granted_capabilities": self.granted_capabilities,
            "transport": self.transport,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash, "verdict": self.verdict,
            "valence": self.valence, "prev": self.prev,
            "note": self.note,
        })
    }

    fn compute_id(&self) -> String {
        sha256_hex(canonical_json(&self.body_json()).as_bytes())
    }
}

/// A cross-boundary denial that is logged separately for audit (org-011).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryDenial {
    pub ts: String,
    pub caller_codon: String,
    pub target_codon: String,
    pub op: String,
    pub reason: String,
    pub receipt_id: String,
}

// ---------------------------------------------------------------------------
// Call errors (fail-closed results)
// ---------------------------------------------------------------------------

/// What the caller gets when the host refuses or the organelle fails.
/// Always carries the receipt id — refusal without a receipt is a bug.
#[derive(Debug, Clone)]
pub struct CallError {
    pub verdict: CallVerdict,
    pub reason: String,
    pub receipt_id: String,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {} (receipt {})", self.verdict, self.reason, self.receipt_id)
    }
}

impl std::error::Error for CallError {}

// ---------------------------------------------------------------------------
// Routing (org-012 hot-swap)
// ---------------------------------------------------------------------------

/// How traffic to one codon is split across registered versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutePolicy {
    /// All traffic to this implementation version.
    Pinned(String),
    /// All traffic to the highest semver registered.
    Latest,
    /// `v2_percent`% of traces to the latest version, rest to the previous.
    /// Deterministic per trace_id.
    Split { v2_percent: u8 },
}

fn semver_key(v: &str) -> (u64, u64, u64) {
    let mut it = v.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

struct VersionedEntry {
    manifest: OrganelleManifest,
    organelle: Arc<dyn Organelle>,
}

struct HostInner {
    organelles: HashMap<String, Vec<VersionedEntry>>,
    routes: HashMap<String, RoutePolicy>,
    route_history: HashMap<String, Vec<RoutePolicy>>,
    profiles: HashMap<String, Vec<String>>,
    active_profile: Option<String>,
    profile_history: Vec<Option<String>>,
    receipts: Vec<Receipt>,
    boundary_denials: Vec<BoundaryDenial>,
    receipt_seq: u64,
    /// Sole issuer/verifier of capability grants (P0: unforgeable authority).
    authority: authority::GrantAuthority,
}

/// parkwreck-organelle-host. Share via `Arc<Host>`; all methods take `&self`.
pub struct Host {
    inner: RwLock<HostInner>,
}

impl Host {
    fn with_authority(authority: authority::GrantAuthority) -> Arc<Self> {
        Arc::new(Host {
            inner: RwLock::new(HostInner {
                organelles: HashMap::new(),
                routes: HashMap::new(),
                route_history: HashMap::new(),
                profiles: HashMap::new(),
                active_profile: None,
                profile_history: Vec::new(),
                receipts: Vec::new(),
                boundary_denials: Vec::new(),
                receipt_seq: 0,
                authority,
            }),
        })
    }

    pub fn new() -> Arc<Self> {
        Self::with_authority(authority::GrantAuthority::new())
    }

    /// Build a host with an operator-provided grant key. Grants minted under
    /// a stable key verify across restarts; the operator owns the key's
    /// secrecy, distribution, and rotation (secret-freeze: this host never
    /// logs or exposes it).
    pub fn with_grant_key(key: [u8; 32]) -> Arc<Self> {
        Self::with_authority(authority::GrantAuthority::with_key(key))
    }

    // -- receipts --------------------------------------------------------

    fn emit_receipt(&self, mut r: Receipt) -> String {
        let mut inner = self.inner.write().unwrap();
        inner.receipt_seq += 1;
        r.seq = inner.receipt_seq;
        r.prev = inner
            .receipts
            .last()
            .map(|p| p.id.clone())
            .unwrap_or_else(|| "GENESIS".to_string());
        r.id = r.compute_id();
        let id = r.id.clone();
        inner.receipts.push(r);
        id
    }

    /// Build a receipt shell from the invocation binding established
    /// pre-execution (P1): the receipt carries the bound tuple, it never
    /// re-derives identity, version, or capabilities.
    fn receipt_shell(
        kind: ReceiptKind,
        binding: &InvocationBinding,
        input: &Value,
        output_hash: String,
        verdict: CallVerdict,
        valence: Valence,
        note: Option<String>,
    ) -> Receipt {
        Receipt {
            id: String::new(),
            ts: utc_now_iso(),
            seq: 0,
            kind,
            codon: binding.codon.clone(),
            op: binding.op.clone(),
            manifest_version: binding.version.clone(),
            caller: binding.caller.clone(),
            granted_capabilities: binding.granted_capabilities.clone(),
            transport: binding.transport,
            input_hash: hash_value(input),
            output_hash,
            verdict,
            valence,
            prev: String::new(),
            note,
        }
    }

    /// All receipts, oldest first.
    pub fn receipts(&self) -> Vec<Receipt> {
        self.inner.read().unwrap().receipts.clone()
    }

    /// Verify the receipt chain offline: every id recomputes, every `prev`
    /// links, seq is strictly increasing. Returns number of receipts verified.
    pub fn verify_chain(&self) -> Result<usize, String> {
        let inner = self.inner.read().unwrap();
        let mut prev = "GENESIS".to_string();
        for (i, r) in inner.receipts.iter().enumerate() {
            if r.compute_id() != r.id {
                return Err(format!("receipt {i} (seq {}): id does not recompute", r.seq));
            }
            if r.prev != prev {
                return Err(format!("receipt {i} (seq {}): chain break", r.seq));
            }
            if i > 0 && r.seq <= inner.receipts[i - 1].seq {
                return Err(format!("receipt {i}: seq not increasing"));
            }
            prev = r.id.clone();
        }
        Ok(inner.receipts.len())
    }

    pub fn boundary_denials(&self) -> Vec<BoundaryDenial> {
        self.inner.read().unwrap().boundary_denials.clone()
    }

    // -- registration ----------------------------------------------------

    /// Register an organelle. Its manifest is re-validated from JSON
    /// (fail-closed: a bad manifest never enters the registry). Same
    /// codon + new version = versioned entry (org-012). Same codon +
    /// same version, or codon owned by a different name = error.
    pub fn register(&self, organelle: Arc<dyn Organelle>) -> Result<(), Vec<ManifestError>> {
        let manifest_value = serde_json::to_value(&organelle.manifest()).map_err(|e| {
            vec![ManifestError {
                field: "$".to_string(),
                message: format!("manifest not serializable: {e}"),
            }]
        })?;
        let manifest = validate_manifest_json(&manifest_value)?;
        let codon = manifest.codon.clone();
        let version = manifest.version.clone();
        let name = manifest.name.clone();

        {
            let mut inner = self.inner.write().unwrap();
            let entry = VersionedEntry {
                manifest: manifest.clone(),
                organelle,
            };
            match inner.organelles.get_mut(&codon) {
                Some(versions) => {
                    if versions.iter().any(|v| v.manifest.name != name) {
                        return Err(vec![ManifestError {
                            field: "codon".to_string(),
                            message: format!(
                                "codon {codon} already owned by {}",
                                versions[0].manifest.name
                            ),
                        }]);
                    }
                    if versions.iter().any(|v| v.manifest.version == version) {
                        return Err(vec![ManifestError {
                            field: "version".to_string(),
                            message: format!("{codon} version {version} already registered"),
                        }]);
                    }
                    versions.push(entry);
                    versions.sort_by_key(|v| semver_key(&v.manifest.version));
                }
                None => {
                    inner.organelles.insert(codon.clone(), vec![entry]);
                    inner.routes.insert(codon.clone(), RoutePolicy::Latest);
                }
            }
        }

        let binding = InvocationBinding::synthetic("host", &codon, "register", &version);
        let r = Self::receipt_shell(
            ReceiptKind::Registration,
            &binding,
            &manifest_value,
            hash_value(&manifest_value),
            CallVerdict::Ok,
            Valence::Proven,
            Some(format!("registered {name} {version}")),
        );
        self.emit_receipt(r);
        Ok(())
    }

    /// Active routed manifest per codon (what the surfaces advertise).
    pub fn list_manifests(&self) -> Vec<OrganelleManifest> {
        let inner = self.inner.read().unwrap();
        let mut out: Vec<OrganelleManifest> = inner
            .organelles
            .keys()
            .filter_map(|codon| self.resolve_locked(&inner, codon, "t0000000000000000").ok())
            .map(|(_, e)| e.manifest.clone())
            .collect();
        out.sort_by(|a, b| a.codon.cmp(&b.codon));
        out
    }

    fn resolve_locked<'a>(
        &self,
        inner: &'a HostInner,
        codon: &str,
        trace_id: &str,
    ) -> Result<(usize, &'a VersionedEntry), String> {
        let versions = inner
            .organelles
            .get(codon)
            .ok_or_else(|| format!("unknown organelle codon \"{codon}\""))?;
        let policy = inner.routes.get(codon).cloned().unwrap_or(RoutePolicy::Latest);
        let idx = match policy {
            RoutePolicy::Latest => versions.len() - 1,
            RoutePolicy::Pinned(v) => versions
                .iter()
                .position(|e| e.manifest.version == v)
                .ok_or_else(|| format!("pinned version {v} not registered for {codon}"))?,
            RoutePolicy::Split { v2_percent } => {
                if versions.len() < 2 || v2_percent == 0 {
                    0
                } else if v2_percent >= 100 {
                    versions.len() - 1
                } else {
                    let h = sha256_hex(format!("{codon}:{trace_id}").as_bytes());
                    let bucket = u8::from_str_radix(&h[..2], 16).unwrap_or(0) % 100;
                    if bucket < v2_percent {
                        versions.len() - 1
                    } else {
                        versions.len() - 2
                    }
                }
            }
        };
        Ok((idx, &versions[idx]))
    }

    // -- suspend / checkpoint / kill (lifecycle) ---------------------------

    /// Resolve a codon to its routed organelle (no lock held on return).
    fn resolve_for_lifecycle(&self, codon: &str) -> Result<(Arc<dyn Organelle>, String), String> {
        let inner = self.inner.read().unwrap();
        match self.resolve_locked(&inner, codon, "t0000000000000000") {
            Ok((_, e)) => Ok((e.organelle.clone(), e.manifest.version.clone())),
            Err(reason) => Err(reason),
        }
    }

    /// Emit a fail-closed lifecycle refusal receipt and return the error
    /// string (carries the receipt id, like `CallError`).
    fn lifecycle_denied(&self, kind: ReceiptKind, codon: &str, op: &str, reason: String) -> String {
        let binding = InvocationBinding::synthetic("host", codon, op, "-");
        let rid = self.emit_receipt(Self::receipt_shell(
            kind,
            &binding,
            &serde_json::json!({"codon": codon}),
            format!("denied:{reason}"),
            CallVerdict::Denied,
            Valence::Candidate,
            Some(reason.clone()),
        ));
        format!("{reason} (receipt {rid})")
    }

    /// Suspend an organelle: quiesce it, capture its checkpoint, and receipt
    /// both. Emits a `Suspend` receipt followed by a `Checkpoint` receipt
    /// whose `output_hash` is the sha256 of the checkpoint bytes — so the
    /// chain commits to the exact captured state. Returns the checkpoint.
    ///
    /// The organelle's `suspend()` hook runs outside the dispatch lock.
    /// Unknown codon is fail-closed: error + denial receipt, no checkpoint.
    pub fn suspend(&self, codon: &str) -> Result<Checkpoint, String> {
        let (organelle, version) = match self.resolve_for_lifecycle(codon) {
            Ok(v) => v,
            Err(reason) => {
                return Err(self.lifecycle_denied(ReceiptKind::Suspend, codon, "suspend", reason))
            }
        };
        let checkpoint = organelle.suspend();
        let checkpoint_hash = sha256_hex(&checkpoint.bytes);
        self.emit_receipt(Self::receipt_shell(
            ReceiptKind::Suspend,
            &InvocationBinding::synthetic("host", codon, "suspend", &version),
            &serde_json::json!({"codon": codon}),
            checkpoint_hash.clone(),
            CallVerdict::Ok,
            Valence::Proven,
            Some(format!(
                "suspended {codon} (ephemeral: {})",
                checkpoint.ephemeral
            )),
        ));
        self.emit_receipt(Self::receipt_shell(
            ReceiptKind::Checkpoint,
            &InvocationBinding::synthetic("host", codon, "checkpoint", &version),
            &serde_json::json!({"codon": codon}),
            checkpoint_hash,
            CallVerdict::Ok,
            Valence::Proven,
            Some(format!(
                "checkpoint for {codon}: {} bytes, ephemeral: {}",
                checkpoint.bytes.len(),
                checkpoint.ephemeral
            )),
        ));
        Ok(checkpoint)
    }

    /// Kill an organelle. Suspend-first: the checkpoint is captured before
    /// anything is torn down, then the organelle's `kill()` hook runs, then
    /// a `Kill` receipt is emitted as that organelle's final receipt. There
    /// is no silent kill. Unknown codon fails cleanly with a denial receipt.
    pub fn kill(&self, codon: &str) -> Result<(), String> {
        let (organelle, version) = match self.resolve_for_lifecycle(codon) {
            Ok(v) => v,
            Err(reason) => {
                return Err(self.lifecycle_denied(ReceiptKind::Kill, codon, "kill", reason))
            }
        };
        // Suspend-first: never silent-kill. Propagate the suspend error.
        let checkpoint = self.suspend(codon)?;
        organelle.kill();
        self.emit_receipt(Self::receipt_shell(
            ReceiptKind::Kill,
            &InvocationBinding::synthetic("host", codon, "kill", &version),
            &serde_json::json!({"codon": codon}),
            sha256_hex(&checkpoint.bytes),
            CallVerdict::Ok,
            Valence::Proven,
            Some(format!("killed {codon}; final checkpoint {} bytes", checkpoint.bytes.len())),
        ));
        Ok(())
    }

    // -- the call path (fail-closed) --------------------------------------

    /// Invoke an organelle. Every path — ok, denied, rejected, failed —
    /// emits exactly one receipt. There is no silent pass.
    /// (org-003: this `&self` method IS the native in-process surface.)
    ///
    /// P1: the arrival transport is `Native` — the surface is bound by the
    /// entry point, never by caller-supplied data.
    pub fn call(
        &self,
        ctx: &CallContext,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, CallError> {
        self.call_with_gate2(ctx, codon, op, input, Some(Transport::Native))
    }

    /// Internal dispatch: resolve the codon exactly once, establish the
    /// [`InvocationBinding`] (P1), authorize against that same resolution,
    /// and execute the resolved implementation. `arrival` is the transport
    /// the invocation arrived over (`None` = internal membrane call).
    pub(crate) fn call_with_gate2(
        &self,
        ctx: &CallContext,
        codon: &str,
        op: &str,
        input: Value,
        arrival: Option<Transport>,
    ) -> Result<Value, CallError> {
        // Phase 0+1, under one read lock: profile gate, single resolution,
        // binding established, authorization against the SAME resolution.
        // The lock is dropped before any handler runs.
        let resolved: Result<ResolvedCall, (CallVerdict, String)> = {
            let inner = self.inner.read().unwrap();
            let gate: Gate2 = if let Some(active) = &inner.active_profile {
                let ok = inner
                    .profiles
                    .get(active)
                    .is_some_and(|cs| cs.contains(&codon.to_string()));
                if !ok {
                    Gate2::Stop {
                        reason: format!("codon \"{codon}\" not in active profile \"{active}\""),
                    }
                } else {
                    match self.resolve_locked(&inner, codon, &ctx.trace_id) {
                        Ok((_, e)) => self.authorize(&e.manifest, &e.organelle, ctx, op, &input, arrival),
                        Err(reason) => Gate2::Stop { reason },
                    }
                }
            } else {
                match self.resolve_locked(&inner, codon, &ctx.trace_id) {
                    Ok((_, e)) => self.authorize(&e.manifest, &e.organelle, ctx, op, &input, arrival),
                    Err(reason) => Gate2::Stop { reason },
                }
            };
            match gate {
                Gate2::Go { manifest, organelle, version } => Ok(ResolvedCall {
                    binding: InvocationBinding {
                        caller: ctx.caller.clone(),
                        codon: codon.to_string(),
                        op: op.to_string(),
                        version,
                        granted_capabilities: ctx.capabilities.clone(),
                        transport: arrival,
                    },
                    manifest,
                    organelle,
                }),
                Gate2::Stop { reason } => Err((CallVerdict::Denied, reason)),
                Gate2::StopRejected { reason } => Err((CallVerdict::Rejected, reason)),
            }
        };

        // The receipt is built from the pre-execution binding. For refusals
        // the binding was never established: synthesize a denial binding
        // carrying the arrival transport so the record still names where
        // the attempt came from.
        let binding = match &resolved {
            Ok(rc) => rc.binding.clone(),
            Err(_) => InvocationBinding {
                caller: ctx.caller.clone(),
                codon: codon.to_string(),
                op: op.to_string(),
                version: "-".to_string(),
                granted_capabilities: ctx.capabilities.clone(),
                transport: arrival,
            },
        };

        match resolved {
            Err((v, reason)) => {
                let tag = match v {
                    CallVerdict::Denied => "denied",
                    CallVerdict::Rejected => "rejected",
                    _ => "stopped",
                };
                let receipt_id = self.emit_receipt(Self::receipt_shell(
                    ReceiptKind::Invocation,
                    &binding,
                    &input,
                    format!("{tag}:{reason}"),
                    v,
                    Valence::Candidate,
                    Some(reason.clone()),
                ));
                Err(CallError { verdict: v, reason, receipt_id })
            }
            Ok(rc) => self.invoke_resolved(ctx, rc, input),
        }
    }

    /// Execute an already-resolved, already-authorized invocation (phase 2).
    /// Consumes the exact [`ResolvedCall`] the binding and the
    /// authorization decision were built from — nothing re-resolves here,
    /// so authorization and execution can never consult different
    /// implementation versions. The lock is never held across `handle()`.
    fn invoke_resolved(
        &self,
        ctx: &CallContext,
        rc: ResolvedCall,
        input: Value,
    ) -> Result<Value, CallError> {
        let binding = rc.binding.clone();
        let (verdict, output_hash, valence, note, result): (
            CallVerdict,
            String,
            Valence,
            Option<String>,
            Result<Value, CallError>,
        ) = match rc.organelle.handle(ctx, self, &binding.op, input.clone()) {
            Ok(output) => (
                CallVerdict::Ok,
                hash_value(&output),
                rc.manifest.authority.declared_valence,
                None,
                Ok(output),
            ),
            Err(e) => (
                CallVerdict::Failed,
                format!("failed:{}", e.code),
                Valence::Disproven,
                Some(e.to_string()),
                Err(CallError {
                    verdict: CallVerdict::Failed,
                    reason: e.to_string(),
                    receipt_id: String::new(),
                }),
            ),
        };
        let receipt_id = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::Invocation,
            &binding,
            &input,
            output_hash,
            verdict,
            valence,
            note,
        ));
        match result {
            Ok(output) => Ok(output),
            Err(mut e) => {
                e.receipt_id = receipt_id;
                Err(e)
            }
        }
    }

    // -- capability grants (P0: unforgeable authority) -----------------------
    //
    // The native `call` above takes a `CallContext` directly: it is the
    // in-process surface, where the caller is code linked into this process.
    // Every EXTERNAL surface (unix socket, MCP stdio, REST) must enter here
    // instead. Capabilities are derived ONLY from a host-issued,
    // HMAC-authenticated grant; caller-supplied capability claims are never
    // read. Fail-closed: any grant problem is a Denied verdict with a
    // receipt, never a default-allow.

    /// Issue a multi-use capability grant for `caller`, valid `ttl_secs`
    /// seconds. This is the control plane: whoever operates the host process
    /// mints grants for its callers out-of-band.
    pub fn issue_grant(&self, caller: &str, capabilities: Vec<String>, ttl_secs: u64) -> String {
        self.inner
            .read()
            .unwrap()
            .authority
            .issue(caller, capabilities, ttl_secs)
    }

    /// Issue a single-use capability grant: honored once, replays denied.
    pub fn issue_single_use_grant(
        &self,
        caller: &str,
        capabilities: Vec<String>,
        ttl_secs: u64,
    ) -> String {
        self.inner
            .read()
            .unwrap()
            .authority
            .issue_single_use(caller, capabilities, ttl_secs)
    }

    /// Verify a grant token (public so surfaces can pre-check; the call path
    /// below is the enforced entry point).
    pub fn verify_grant(&self, token: &str) -> Result<VerifiedGrant, GrantError> {
        self.inner.write().unwrap().authority.verify(token)
    }

    /// External-surface entry point. Authenticates the grant, binds the
    /// optional claimed caller identity to the grant's subject, builds the
    /// `CallContext` from the grant alone, and dispatches. The denial /
    /// rejection / failure distinction of `call` is preserved; grant
    /// failures are Denied (never Rejected — the request was well-formed,
    /// the authority was not).
    ///
    /// P1: `transport` names the surface this invocation arrived over
    /// (bound by the surface, never by caller-supplied data). It becomes
    /// part of the invocation binding and the organelle's declared
    /// transports are enforced against it: arrival over a non-declared
    /// transport is a fail-closed denial.
    pub fn call_with_grant(
        &self,
        grant: &str,
        caller_claim: Option<&str>,
        transport: Transport,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, CallError> {
        let caller_label = caller_claim.unwrap_or("unauthenticated");
        let verified = match self.verify_grant(grant) {
            Ok(v) => v,
            Err(e) => {
                return Err(self.grant_denied(
                    caller_label,
                    codon,
                    op,
                    &input,
                    Some(transport),
                    e.to_string(),
                ))
            }
        };
        if let Some(claim) = caller_claim {
            if claim != verified.caller {
                return Err(self.grant_denied(
                    caller_label,
                    codon,
                    op,
                    &input,
                    Some(transport),
                    format!(
                        "caller claim \"{claim}\" does not match grant subject"
                    ),
                ));
            }
        }
        // Capabilities come ONLY from the trusted grant. Whatever the
        // caller claimed on the wire is not even read.
        let ctx = CallContext::new(verified.caller, verified.capabilities);
        self.call_with_gate2(&ctx, codon, op, input, Some(transport))
    }

    /// Emit a fail-closed denial receipt for a grant failure and return the
    /// `CallError` carrying its id (mirrors the Phase1::Stop arm: refusal
    /// without a receipt is a bug). The arrival transport is recorded even
    /// though no binding was established.
    fn grant_denied(
        &self,
        caller: &str,
        codon: &str,
        op: &str,
        input: &Value,
        transport: Option<Transport>,
        reason: String,
    ) -> CallError {
        let binding = InvocationBinding {
            caller: caller.to_string(),
            codon: codon.to_string(),
            op: op.to_string(),
            version: "-".to_string(),
            granted_capabilities: Vec::new(),
            transport,
        };
        let receipt_id = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::Invocation,
            &binding,
            input,
            format!("denied:{reason}"),
            CallVerdict::Denied,
            Valence::Candidate,
            Some(reason.clone()),
        ));
        CallError {
            verdict: CallVerdict::Denied,
            reason,
            receipt_id,
        }
    }

    /// Authorize op + transport + capability + input schema against the
    /// single resolved manifest. Pure w.r.t. &self. The manifest is the
    /// SAME resolution the execution will consume (P1): authorization
    /// never consults a different implementation version than execution.
    fn authorize(
        &self,
        manifest: &OrganelleManifest,
        organelle: &Arc<dyn Organelle>,
        ctx: &CallContext,
        op: &str,
        input: &Value,
        arrival: Option<Transport>,
    ) -> Gate2 {
        let m = manifest;
        let contract = match m.contract(op) {
            Some(c) => c,
            None => {
                return Gate2::Stop {
                    reason: format!("unknown op \"{op}\" for codon \"{}\"", m.codon),
                }
            }
        };
        // P1: declared transport restrictions are enforced at the host.
        // Arrival over a non-declared transport is a Denied verdict, never
        // a default-allow. `arrival == None` is an internal membrane call
        // (organelle->organelle), not a surface arrival: transport
        // restriction does not apply there; granted capabilities do.
        // Note: a manifest with no declared transports can never be
        // registered (fail-closed at manifest validation), so there is no
        // "unrestricted" case — every registered organelle declares >= 1.
        if let Some(t) = arrival {
            if !m.transports.contains(&t) {
                let declared: Vec<&str> =
                    m.transports.iter().map(|x| x.as_str()).collect();
                return Gate2::Stop {
                    reason: format!(
                        "transport \"{}\" not declared for {}@{} (declared: {})",
                        t.as_str(),
                        m.codon,
                        m.version,
                        declared.join(","),
                    ),
                };
            }
        }
        let (mc, cap) = m.authority_for(op);
        let _ = mc;
        if let Some(need) = cap {
            if !ctx.has(need) {
                return Gate2::Stop {
                    reason: format!(
                        "missing capability \"{need}\" for {}.{op}",
                        m.codon
                    ),
                };
            }
        }
        if let Err(violations) = validate_input_against_schema(&contract.input_schema, input) {
            return Gate2::StopRejected {
                reason: format!("input rejected: {}", violations.join("; ")),
            };
        }
        Gate2::Go {
            manifest: m.clone(),
            organelle: organelle.clone(),
            version: m.version.clone(),
        }
    }

    // -- organelle -> organelle (org-011 authority boundary) ---------------

    /// Called by organelles via `HostRef`. The calling organelle's
    /// *granted* capabilities are checked against the callee's required
    /// capability; excess is denied and logged (fail-closed).
    ///
    /// P1: both ends are resolved exactly once, under one lock, through
    /// the same routing policy the surface calls use. The boundary check
    /// and the execution consume the SAME callee resolution — the old
    /// code authorized against `vs.last()` (always the latest registered
    /// version) but executed the routed version, so a pinned/old version
    /// could be authorized under a newer version's policy. The caller's
    /// routed version is re-derived from the outer invocation's
    /// `caller_trace` so split-routed callers keep the version that is
    /// actually executing.
    pub fn call_as_organelle(
        &self,
        caller_codon: &str,
        caller_trace: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        let (caller_manifest, callee): (OrganelleManifest, ResolvedCall) = {
            let inner = self.inner.read().unwrap();
            let caller_manifest = match self.resolve_locked(&inner, caller_codon, caller_trace) {
                Ok((_, e)) => e.manifest.clone(),
                Err(reason) => {
                    return Err(OrganelleError::denied(format!(
                        "boundary: unknown caller codon \"{caller_codon}\": {reason}"
                    )))
                }
            };
            let (_, callee_entry) = match self.resolve_locked(&inner, codon, caller_trace) {
                Ok(v) => v,
                Err(reason) => {
                    return Err(OrganelleError::denied(format!(
                        "boundary: unknown callee codon \"{codon}\": {reason}"
                    )))
                }
            };
            // The binding is established HERE, once, before the boundary
            // check: caller identity, callee id, resolved implementation
            // version, and the caller's granted capabilities.
            let callee = ResolvedCall {
                binding: InvocationBinding {
                    caller: format!("organelle:{caller_codon}"),
                    codon: codon.to_string(),
                    op: op.to_string(),
                    version: callee_entry.manifest.version.clone(),
                    granted_capabilities: caller_manifest
                        .authority
                        .granted_capabilities
                        .clone(),
                    // Membrane-internal: not a surface arrival, so no
                    // transport restriction applies (granted caps govern).
                    transport: None,
                },
                manifest: callee_entry.manifest.clone(),
                organelle: callee_entry.organelle.clone(),
            };
            (caller_manifest, callee)
        };
        // Lock dropped before any handler runs: no registry lock is held
        // across the boundary check's receipt or the callee's handle().

        // Boundary authorization against the SAME resolved callee manifest
        // the execution will use — not the latest, not a second lookup.
        let (_, need) = callee.manifest.authority_for(op);
        if let Some(need) = need {
            if !callee
                .binding
                .granted_capabilities
                .iter()
                .any(|c| c == need)
            {
                let reason = format!(
                    "organelle \"{caller_codon}\" ({}@{}) lacks granted capability \"{need}\" for {}@{}",
                    caller_manifest.name,
                    caller_manifest.version,
                    callee.binding.codon,
                    callee.binding.version,
                );
                // Log the denial AND receipt it (no silent pass). The
                // receipt carries the established binding: caller identity,
                // callee id, resolved version, granted caps.
                let binding = &callee.binding;
                let rid = self.emit_receipt(Self::receipt_shell(
                    ReceiptKind::Invocation,
                    binding,
                    &input,
                    format!("denied:{reason}"),
                    CallVerdict::Denied,
                    Valence::Candidate,
                    Some(reason.clone()),
                ));
                self.inner.write().unwrap().boundary_denials.push(BoundaryDenial {
                    ts: utc_now_iso(),
                    caller_codon: caller_codon.to_string(),
                    target_codon: codon.to_string(),
                    op: op.to_string(),
                    reason: reason.clone(),
                    receipt_id: rid,
                });
                return Err(OrganelleError::denied(reason));
            }
        }
        // Execute the EXACT resolved entry: no re-resolution, so the
        // version the boundary authorized is the version that runs.
        // Phase-1 gates (profile, op exists, input schema) run against
        // the same resolved manifest; arrival=None because this is a
        // membrane-internal call, not a surface arrival.
        let ctx = CallContext::new(
            format!("organelle:{caller_codon}"),
            callee.binding.granted_capabilities.clone(),
        );
        let gate: Gate2 = {
            let inner = self.inner.read().unwrap();
            if let Some(active) = &inner.active_profile {
                let ok = inner
                    .profiles
                    .get(active)
                    .is_some_and(|cs| cs.contains(&codon.to_string()));
                if !ok {
                    Gate2::Stop {
                        reason: format!("codon \"{codon}\" not in active profile \"{active}\""),
                    }
                } else {
                    self.authorize(&callee.manifest, &callee.organelle, &ctx, op, &input, None)
                }
            } else {
                self.authorize(&callee.manifest, &callee.organelle, &ctx, op, &input, None)
            }
        };
        match gate {
            Gate2::Go { .. } => self
                .invoke_resolved(&ctx, callee, input)
                .map_err(|e| OrganelleError::new("denied", e.reason)),
            Gate2::Stop { reason } => {
                let rid = self.emit_receipt(Self::receipt_shell(
                    ReceiptKind::Invocation,
                    &callee.binding,
                    &input,
                    format!("denied:{reason}"),
                    CallVerdict::Denied,
                    Valence::Candidate,
                    Some(reason.clone()),
                ));
                Err(OrganelleError::denied(format!("{reason} (receipt {rid})")))
            }
            Gate2::StopRejected { reason } => {
                let rid = self.emit_receipt(Self::receipt_shell(
                    ReceiptKind::Invocation,
                    &callee.binding,
                    &input,
                    format!("rejected:{reason}"),
                    CallVerdict::Rejected,
                    Valence::Candidate,
                    Some(reason.clone()),
                ));
                Err(OrganelleError::new(
                    "rejected",
                    format!("{reason} (receipt {rid})"),
                ))
            }
        }
    }

    // -- profiles (org-009) -------------------------------------------------

    /// Define a named organelle set. Codons must all be registered.
    pub fn create_profile(&self, name: &str, codons: Vec<String>) -> Result<(), String> {
        {
            let inner = self.inner.read().unwrap();
            for c in &codons {
                if !inner.organelles.contains_key(c) {
                    return Err(format!("profile \"{name}\": unknown codon \"{c}\""));
                }
            }
        }
        self.inner
            .write()
            .unwrap()
            .profiles
            .insert(name.to_string(), codons);
        Ok(())
    }

    /// Activate a profile; every later call is gated on membership.
    /// Receipted; previous profile is pushed for rollback.
    pub fn activate_profile(&self, name: &str) -> Result<String, String> {
        let codons = {
            let inner = self.inner.read().unwrap();
            inner
                .profiles
                .get(name)
                .cloned()
                .ok_or_else(|| format!("unknown profile \"{name}\""))?
        };
        let prev = {
            let mut inner = self.inner.write().unwrap();
            let prev = inner.active_profile.clone();
            inner.profile_history.push(prev.clone());
            inner.active_profile = Some(name.to_string());
            prev
        };
        let binding = InvocationBinding::synthetic("host", "-", "profile.activate", "-");
        let rid = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::ProfileActivate,
            &binding,
            &serde_json::json!({"profile": name, "codons": codons}),
            hash_value(&serde_json::json!(codons)),
            CallVerdict::Ok,
            Valence::Proven,
            Some(format!("activated profile \"{name}\" (was {prev:?})")),
        ));
        Ok(rid)
    }

    /// Roll back to the previously active profile. Receipted.
    pub fn rollback_profile(&self) -> Result<String, String> {
        let prev = {
            let mut inner = self.inner.write().unwrap();
            inner
                .profile_history
                .pop()
                .ok_or_else(|| "no profile history to roll back".to_string())?
        };
        {
            let mut inner = self.inner.write().unwrap();
            inner.active_profile = prev.clone();
        }
        let binding = InvocationBinding::synthetic("host", "-", "profile.rollback", "-");
        let rid = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::ProfileRollback,
            &binding,
            &serde_json::json!({"restored": prev}),
            "rolled-back".to_string(),
            CallVerdict::Ok,
            Valence::Proven,
            Some(format!("restored profile {prev:?}")),
        ));
        Ok(rid)
    }

    pub fn active_profile(&self) -> Option<String> {
        self.inner.read().unwrap().active_profile.clone()
    }

    // -- hot-swap routes (org-012) ------------------------------------------

    /// Set the routing policy for a codon. Receipted; history kept.
    pub fn set_route(&self, codon: &str, policy: RoutePolicy) -> Result<String, String> {
        let prev = {
            let mut inner = self.inner.write().unwrap();
            if !inner.organelles.contains_key(codon) {
                return Err(format!("unknown codon \"{codon}\""));
            }
            if let RoutePolicy::Pinned(v) = &policy {
                let ok = inner.organelles[codon]
                    .iter()
                    .any(|e| &e.manifest.version == v);
                if !ok {
                    return Err(format!("version {v} not registered for {codon}"));
                }
            }
            if let RoutePolicy::Split { v2_percent } = &policy {
                if *v2_percent > 100 {
                    return Err("v2_percent must be <= 100".to_string());
                }
                if inner.organelles[codon].len() < 2 {
                    return Err("split routing needs >= 2 versions".to_string());
                }
            }
            let prev = inner.routes.get(codon).cloned().unwrap_or(RoutePolicy::Latest);
            inner
                .route_history
                .entry(codon.to_string())
                .or_default()
                .push(prev.clone());
            inner.routes.insert(codon.to_string(), policy.clone());
            prev
        };
        let binding = InvocationBinding::synthetic("host", codon, "route.set", "-");
        let rid = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::RouteChange,
            &binding,
            &serde_json::json!({"policy": format!("{policy:?}")}),
            hash_value(&serde_json::json!(format!("{policy:?}"))),
            CallVerdict::Ok,
            Valence::Proven,
            Some(format!("route for {codon}: {prev:?} -> {policy:?}")),
        ));
        Ok(rid)
    }

    /// Roll back the last route change for a codon. Receipted.
    pub fn rollback_route(&self, codon: &str) -> Result<String, String> {
        let prev = {
            let mut inner = self.inner.write().unwrap();
            inner
                .route_history
                .get_mut(codon)
                .and_then(|h| h.pop())
                .ok_or_else(|| format!("no route history for {codon}"))?
        };
        {
            let mut inner = self.inner.write().unwrap();
            inner.routes.insert(codon.to_string(), prev.clone());
        }
        let binding = InvocationBinding::synthetic("host", codon, "route.rollback", "-");
        let rid = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::RouteRollback,
            &binding,
            &serde_json::json!({"restored": format!("{prev:?}")}),
            "rolled-back".to_string(),
            CallVerdict::Ok,
            Valence::Proven,
            Some(format!("route for {codon} restored to {prev:?}")),
        ));
        Ok(rid)
    }
}

// Internal gate type: distinguishes Denied from Rejected (schema failure).
enum Gate2 {
    Go {
        manifest: OrganelleManifest,
        organelle: Arc<dyn Organelle>,
        version: String,
    },
    Stop {
        reason: String,
    },
    StopRejected {
        reason: String,
    },
}

impl HostRef for Host {
    fn call_organelle(
        &self,
        caller_codon: &str,
        caller_trace: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        self.call_as_organelle(caller_codon, caller_trace, codon, op, input)
    }
}

// ---------------------------------------------------------------------------
// Unit tests — org-002 (20+), plus coverage for 009/010/011/012 behaviors.
// org-008's dedicated suite lives in tests/fail_closed.rs.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_manifest::{
        Authority, Contract, MutationClass, ReceiptPolicy, Transport, MANIFEST_SCHEMA_VERSION,
        RECEIPT_ALGORITHM,
    };

    fn test_manifest(codon: &str, version: &str, granted: Vec<String>) -> OrganelleManifest {
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: format!("test-{codon}"),
            codon: codon.to_string(),
            version: version.to_string(),
            description: "test organelle".to_string(),
            contracts: vec![
                Contract {
                    op: "echo".to_string(),
                    description: "echo input back".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                    mutation_class: None,
                    required_capability: None,
                },
                Contract {
                    op: "sealed".to_string(),
                    description: "gated op".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                    mutation_class: Some(MutationClass::Write),
                    required_capability: Some("te.write".to_string()),
                },
                Contract {
                    op: "boom".to_string(),
                    description: "always fails".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                    mutation_class: None,
                    required_capability: None,
                },
            ],
            authority: Authority {
                mutation_class: MutationClass::ReadOnly,
                declared_valence: Valence::Candidate,
                required_capability: None,
                granted_capabilities: granted,
            },
            transports: vec![Transport::Native],
            receipt_policy: ReceiptPolicy {
                content_addressed: true,
                algorithm: RECEIPT_ALGORITHM.to_string(),
                chain: true,
            },
        }
    }

    struct Echo {
        manifest: OrganelleManifest,
        tag: String,
    }

    impl Organelle for Echo {
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
            match op {
                "echo" => Ok(serde_json::json!({"tag": self.tag, "input": input})),
                "sealed" => Ok(serde_json::json!({"sealed": true})),
                "boom" => Err(OrganelleError::failed("deliberate failure")),
                _ => Err(OrganelleError::not_found(format!("no such op {op}"))),
            }
        }
    }

    /// Organelle that calls another organelle through the host (org-011).
    /// P1: threads the outer invocation's trace id so the host resolves
    /// the caller's routed version (not blindly the latest).
    struct Caller {
        manifest: OrganelleManifest,
        target_codon: String,
        target_op: String,
    }

    impl Organelle for Caller {
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
            assert_eq!(op, "relay");
            // P1: thread the outer invocation's trace id so the host
            // re-resolves the caller's routed version, not blindly latest.
            host.call_organelle(
                &self.manifest.codon,
                &ctx.trace_id,
                &self.target_codon,
                &self.target_op,
                input,
            )
        }
    }

    fn caller(codon: &str, granted: Vec<String>, target_codon: &str, target_op: &str) -> Caller {
        Caller {
            manifest: caller_manifest(codon, granted),
            target_codon: target_codon.to_string(),
            target_op: target_op.to_string(),
        }
    }

    fn caller_manifest(codon: &str, granted: Vec<String>) -> OrganelleManifest {
        let mut m = test_manifest(codon, "1.0.0", granted);
        m.name = format!("test-{codon}");
        m.contracts = vec![Contract {
            op: "relay".to_string(),
            description: "relay to te.sealed".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            mutation_class: None,
            required_capability: None,
        }];
        m
    }

    fn echo_host() -> Arc<Host> {
        let h = Host::new();
        h.register(Arc::new(Echo { manifest: test_manifest("te", "1.0.0", vec![]), tag: "v1".into() }))
            .unwrap();
        h
    }

    fn ctx() -> CallContext {
        CallContext::new("test", vec![])
    }

    fn ctx_with(caps: &[&str]) -> CallContext {
        CallContext::new("test", caps.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn register_valid_ok() {
        let h = echo_host();
        assert_eq!(h.list_manifests().len(), 1);
        assert_eq!(h.list_manifests()[0].codon, "te");
    }

    #[test]
    fn register_invalid_manifest_rejected() {
        // Write authority, no capability anywhere -> fail-closed at registration.
        let h = Host::new();
        let mut m = test_manifest("xx", "1.0.0", vec![]);
        m.authority.mutation_class = MutationClass::Write;
        m.authority.required_capability = None;
        for c in &mut m.contracts {
            c.mutation_class = Some(MutationClass::Write);
            c.required_capability = None;
        }
        let e = Echo { manifest: m, tag: "x".into() };
        assert!(h.register(Arc::new(e)).is_err());
        assert_eq!(h.list_manifests().len(), 0);
    }

    #[test]
    fn register_duplicate_version_rejected() {
        let h = echo_host();
        let dup = Echo { manifest: test_manifest("te", "1.0.0", vec![]), tag: "dup".into() };
        assert!(h.register(Arc::new(dup)).is_err());
    }

    #[test]
    fn register_codon_collision_rejected() {
        let h = echo_host();
        let mut m = test_manifest("te", "1.0.0", vec![]);
        m.name = "different-name".to_string();
        let e = Echo { manifest: m, tag: "x".into() };
        assert!(h.register(Arc::new(e)).is_err());
    }

    #[test]
    fn call_ok_emits_receipt() {
        let h = echo_host();
        let out = h.call(&ctx(), "te", "echo", serde_json::json!({"a": 1})).unwrap();
        assert_eq!(out["tag"], serde_json::json!("v1"));
        let rs = h.receipts();
        assert_eq!(rs.len(), 2); // registration + invocation
        let r = rs.last().unwrap();
        assert_eq!(r.verdict, CallVerdict::Ok);
        assert_eq!(r.codon, "te");
        assert_eq!(r.output_hash, hash_value(&out));
        assert!(!r.id.is_empty());
    }

    #[test]
    fn call_unknown_codon_denied_and_receipted() {
        let h = echo_host();
        let e = h.call(&ctx(), "zz", "echo", serde_json::json!({})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(!e.receipt_id.is_empty());
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.id, e.receipt_id);
        assert_eq!(r.verdict, CallVerdict::Denied);
        assert!(r.output_hash.starts_with("denied:"));
    }

    #[test]
    fn call_unknown_op_denied_and_receipted() {
        let h = echo_host();
        let e = h.call(&ctx(), "te", "nope", serde_json::json!({})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("unknown op"));
        assert!(!e.receipt_id.is_empty());
    }

    #[test]
    fn call_missing_capability_denied_and_receipted() {
        let h = echo_host();
        let e = h.call(&ctx(), "te", "sealed", serde_json::json!({})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("te.write"));
        // With the capability it passes.
        let out = h.call(&ctx_with(&["te.write"]), "te", "sealed", serde_json::json!({})).unwrap();
        assert_eq!(out["sealed"], serde_json::json!(true));
    }

    // -- P0: call_with_grant — authority only from trusted grants --------

    fn grant_ctx_caps(h: &Host, caller: &str, caps: &[&str]) -> String {
        h.issue_grant(caller, caps.iter().map(|s| s.to_string()).collect(), 300)
    }

    #[test]
    fn grant_call_derives_caps_from_grant_only() {
        let h = echo_host();
        // Grant confers te.write -> gated op passes.
        let g = grant_ctx_caps(&h, "ext", &["te.write"]);
        let out = h
            .call_with_grant(&g, Some("ext"), Transport::Native, "te", "sealed", serde_json::json!({}))
            .unwrap();
        assert_eq!(out["sealed"], serde_json::json!(true));
        // Grant without the capability -> denied by the host's authorize().
        let g2 = grant_ctx_caps(&h, "ext", &[]);
        let e = h
            .call_with_grant(&g2, Some("ext"), Transport::Native, "te", "sealed", serde_json::json!({}))
            .unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("te.write"));
        assert!(!e.receipt_id.is_empty());
    }

    #[test]
    fn grant_call_tampered_denied_and_receipted() {
        let h = echo_host();
        let g = grant_ctx_caps(&h, "ext", &["te.write"]);
        let (payload_hex, tag) = g.split_once('.').unwrap();
        let mut chars: Vec<char> = payload_hex.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        let forged = format!("{}.{}", chars.into_iter().collect::<String>(), tag);
        let e = h
            .call_with_grant(&forged, Some("ext"), Transport::Native, "te", "echo", serde_json::json!({}))
            .unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("signature"));
        assert!(!e.receipt_id.is_empty());
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.id, e.receipt_id);
        assert_eq!(r.verdict, CallVerdict::Denied);
    }

    #[test]
    fn grant_call_wrong_caller_denied() {
        let h = echo_host();
        let g = grant_ctx_caps(&h, "alice", &["te.write"]);
        let e = h
            .call_with_grant(&g, Some("mallory"), Transport::Native, "te", "sealed", serde_json::json!({}))
            .unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("does not match grant subject"));
    }

    #[test]
    fn grant_call_missing_grant_denied_never_allowed() {
        let h = echo_host();
        for grant in ["", "garbage", "a.b"] {
            let e = h
                .call_with_grant(grant, Some("ext"), Transport::Native, "te", "echo", serde_json::json!({}))
                .unwrap_err();
            assert_eq!(e.verdict, CallVerdict::Denied, "grant {grant:?}");
        }
    }

    #[test]
    fn grant_call_single_use_replay_denied() {
        let h = echo_host();
        let g = h.issue_single_use_grant("ext", vec!["te.write".to_string()], 300);
        assert!(h
            .call_with_grant(&g, Some("ext"), Transport::Native, "te", "sealed", serde_json::json!({}))
            .is_ok());
        let e = h
            .call_with_grant(&g, Some("ext"), Transport::Native, "te", "sealed", serde_json::json!({}))
            .unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("replay"));
    }

    #[test]
    fn grant_expired_denied() {
        let h = echo_host();
        let g = h.issue_grant("ext", vec!["te.write".to_string()], 0);
        let e = h
            .call_with_grant(&g, Some("ext"), Transport::Native, "te", "sealed", serde_json::json!({}))
            .unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("expired"));
    }

    #[test]
    fn call_bad_input_rejected_not_denied() {
        let h = Host::new();
        let mut m = test_manifest("sj", "1.0.0", vec![]);
        m.contracts[0].input_schema =
            serde_json::json!({"type": "object", "required": ["key"], "properties": {"key": {"type": "string"}}});
        h.register(Arc::new(Echo { manifest: m, tag: "s".into() })).unwrap();
        let e = h.call(&ctx(), "sj", "echo", serde_json::json!({"wrong": 1})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Rejected);
        assert!(e.reason.contains("rejected"));
        let r = h.receipts().last().unwrap().clone();
        assert!(r.output_hash.starts_with("rejected:"));
    }

    #[test]
    fn call_organelle_failure_failed_and_receipted() {
        let h = echo_host();
        let e = h.call(&ctx(), "te", "boom", serde_json::json!({})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Failed);
        assert!(e.reason.contains("deliberate failure"));
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.valence, Valence::Disproven);
        assert!(r.output_hash.starts_with("failed:"));
    }

    #[test]
    fn no_silent_pass_every_call_receipted() {
        let h = echo_host();
        let before = h.receipts().len();
        let _ = h.call(&ctx(), "te", "echo", serde_json::json!({}));
        let _ = h.call(&ctx(), "zz", "echo", serde_json::json!({}));
        let _ = h.call(&ctx(), "te", "nope", serde_json::json!({}));
        let _ = h.call(&ctx(), "te", "sealed", serde_json::json!({}));
        let _ = h.call(&ctx(), "te", "boom", serde_json::json!({}));
        assert_eq!(h.receipts().len(), before + 5);
    }

    #[test]
    fn receipt_chain_verifies() {
        let h = echo_host();
        let _ = h.call(&ctx(), "te", "echo", serde_json::json!({}));
        let _ = h.call(&ctx(), "zz", "echo", serde_json::json!({}));
        assert!(h.verify_chain().unwrap() >= 3);
    }

    #[test]
    fn receipt_ids_are_content_addresses() {
        let h = echo_host();
        let _ = h.call(&ctx(), "te", "echo", serde_json::json!({"a": 1})).unwrap();
        let r = h.receipts().last().unwrap().clone();
        // Recompute: same body -> same id.
        let again = r.compute_id();
        assert_eq!(again, r.id);
    }

    #[test]
    fn profile_gates_calls() {
        let h = echo_host();
        h.register(Arc::new(Echo { manifest: test_manifest("aa", "1.0.0", vec![]), tag: "a".into() }))
            .unwrap();
        h.create_profile("small", vec!["te".to_string()]).unwrap();
        h.activate_profile("small").unwrap();
        assert_eq!(h.active_profile().as_deref(), Some("small"));
        assert!(h.call(&ctx(), "te", "echo", serde_json::json!({})).is_ok());
        let e = h.call(&ctx(), "aa", "echo", serde_json::json!({})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("profile"));
    }

    #[test]
    fn profile_rollback_restores() {
        let h = echo_host();
        h.register(Arc::new(Echo { manifest: test_manifest("aa", "1.0.0", vec![]), tag: "a".into() }))
            .unwrap();
        h.create_profile("small", vec!["te".to_string()]).unwrap();
        h.activate_profile("small").unwrap();
        assert!(h.call(&ctx(), "aa", "echo", serde_json::json!({})).is_err());
        h.rollback_profile().unwrap();
        assert_eq!(h.active_profile(), None);
        assert!(h.call(&ctx(), "aa", "echo", serde_json::json!({})).is_ok());
        // Control-plane actions are receipted too.
        assert!(h.receipts().iter().any(|r| r.kind == ReceiptKind::ProfileActivate));
        assert!(h.receipts().iter().any(|r| r.kind == ReceiptKind::ProfileRollback));
    }

    #[test]
    fn profile_errors() {
        let h = echo_host();
        assert!(h.create_profile("bad", vec!["zz".to_string()]).is_err());
        assert!(h.activate_profile("nope").is_err());
        assert!(h.rollback_profile().is_err());
    }

    #[test]
    fn two_versions_coexist_and_latest_wins() {
        let h = echo_host();
        h.register(Arc::new(Echo { manifest: test_manifest("te", "2.0.0", vec![]), tag: "v2".into() }))
            .unwrap();
        let out = h.call(&ctx(), "te", "echo", serde_json::json!({})).unwrap();
        assert_eq!(out["tag"], serde_json::json!("v2"));
    }

    #[test]
    fn route_pinned_selects_version() {
        let h = echo_host();
        h.register(Arc::new(Echo { manifest: test_manifest("te", "2.0.0", vec![]), tag: "v2".into() }))
            .unwrap();
        h.set_route("te", RoutePolicy::Pinned("1.0.0".to_string())).unwrap();
        let out = h.call(&ctx(), "te", "echo", serde_json::json!({})).unwrap();
        assert_eq!(out["tag"], serde_json::json!("v1"));
    }

    #[test]
    fn route_split_is_deterministic() {
        let h = echo_host();
        h.register(Arc::new(Echo { manifest: test_manifest("te", "2.0.0", vec![]), tag: "v2".into() }))
            .unwrap();
        h.set_route("te", RoutePolicy::Split { v2_percent: 0 }).unwrap();
        for _ in 0..5 {
            let out = h.call(&ctx(), "te", "echo", serde_json::json!({})).unwrap();
            assert_eq!(out["tag"], serde_json::json!("v1"));
        }
        h.set_route("te", RoutePolicy::Split { v2_percent: 100 }).unwrap();
        for _ in 0..5 {
            let out = h.call(&ctx(), "te", "echo", serde_json::json!({})).unwrap();
            assert_eq!(out["tag"], serde_json::json!("v2"));
        }
        assert!(h.set_route("te", RoutePolicy::Split { v2_percent: 101 }).is_err());
    }

    #[test]
    fn route_rollback_restores_previous() {
        let h = echo_host();
        h.register(Arc::new(Echo { manifest: test_manifest("te", "2.0.0", vec![]), tag: "v2".into() }))
            .unwrap();
        h.set_route("te", RoutePolicy::Pinned("1.0.0".to_string())).unwrap();
        let t0 = std::time::Instant::now();
        h.rollback_route("te").unwrap();
        let dt = t0.elapsed();
        assert!(dt.as_secs() < 60, "rollback must be < 60s");
        let out = h.call(&ctx(), "te", "echo", serde_json::json!({})).unwrap();
        assert_eq!(out["tag"], serde_json::json!("v2")); // back to Latest
        assert!(h.receipts().iter().any(|r| r.kind == ReceiptKind::RouteRollback));
    }

    #[test]
    fn set_route_errors() {
        let h = echo_host();
        assert!(h.set_route("zz", RoutePolicy::Latest).is_err());
        assert!(h.set_route("te", RoutePolicy::Pinned("9.9.9".to_string())).is_err());
        assert!(h.rollback_route("te").is_err());
    }

    #[test]
    fn organelle_to_organelle_granted_ok() {
        let h = echo_host();
        h.register(Arc::new(caller("ca", vec!["te.write".to_string()], "te", "sealed")))
            .unwrap();
        let out = h
            .call(&ctx_with(&[]), "ca", "relay", serde_json::json!({}))
            .unwrap();
        assert_eq!(out["sealed"], serde_json::json!(true));
        assert!(h.boundary_denials().is_empty());
    }

    #[test]
    fn organelle_to_organelle_denied_and_logged() {
        let h = echo_host();
        h.register(Arc::new(caller("cb", vec![], "te", "sealed"))).unwrap();
        let e = h.call(&ctx(), "cb", "relay", serde_json::json!({})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Failed); // relay itself failed: boundary denial inside
        assert!(e.reason.contains("lacks granted capability"));
        let denials = h.boundary_denials();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].caller_codon, "cb");
        assert_eq!(denials[0].target_codon, "te");
        assert!(!denials[0].receipt_id.is_empty());
    }

    #[test]
    fn list_manifests_returns_routed_version() {
        let h = echo_host();
        h.register(Arc::new(Echo { manifest: test_manifest("te", "2.0.0", vec![]), tag: "v2".into() }))
            .unwrap();
        let ms = h.list_manifests();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].version, "2.0.0");
        h.set_route("te", RoutePolicy::Pinned("1.0.0".to_string())).unwrap();
        assert_eq!(h.list_manifests()[0].version, "1.0.0");
    }

    #[test]
    fn host_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Host>();
        let h = echo_host();
        let h2 = h.clone();
        let t = std::thread::spawn(move || {
            h2.call(&ctx(), "te", "echo", serde_json::json!({})).unwrap()
        });
        t.join().unwrap();
        assert!(h.verify_chain().is_ok());
    }

    // -- lifecycle: suspend / checkpoint / kill ---------------------------

    /// Stateful organelle with overridden lifecycle hooks.
    struct Counter {
        manifest: OrganelleManifest,
        count: std::sync::atomic::AtomicU64,
        killed: std::sync::atomic::AtomicBool,
    }

    impl Organelle for Counter {
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
            match op {
                "inc" => {
                    let n = self
                        .count
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        + 1;
                    Ok(serde_json::json!({"count": n, "input": input}))
                }
                _ => Err(OrganelleError::not_found(format!("no such op {op}"))),
            }
        }
        fn suspend(&self) -> Checkpoint {
            let n = self.count.load(std::sync::atomic::Ordering::SeqCst);
            Checkpoint {
                codon: self.manifest().codon,
                ts: utc_now_iso(),
                bytes: serde_json::to_vec(&serde_json::json!({"count": n})).unwrap(),
                ephemeral: false,
            }
        }
        fn kill(&self) {
            self.killed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn counter_host() -> (Arc<Host>, Arc<Counter>) {
        let h = Host::new();
        let mut m = test_manifest("ct", "1.0.0", vec![]);
        m.contracts.push(Contract {
            op: "inc".to_string(),
            description: "increment counter".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            mutation_class: None,
            required_capability: None,
        });
        let c = Arc::new(Counter {
            manifest: m,
            count: std::sync::atomic::AtomicU64::new(0),
            killed: std::sync::atomic::AtomicBool::new(false),
        });
        h.register(c.clone()).unwrap();
        (h, c)
    }

    #[test]
    fn suspend_captures_checkpoint_and_receipts_it() {
        let (h, _) = counter_host();
        // Mutate state so the checkpoint is non-trivial.
        for _ in 0..3 {
            h.call(&ctx(), "ct", "inc", serde_json::json!({})).unwrap();
        }
        let before = h.receipts().len();
        let cp = h.suspend("ct").unwrap();
        // Checkpoint bytes round-trip: state survives serialization.
        assert!(!cp.ephemeral);
        let body: Value = serde_json::from_slice(&cp.bytes).unwrap();
        assert_eq!(body["count"], serde_json::json!(3));
        assert_eq!(cp.codon, "ct");
        // Exactly 2 receipts: Suspend then Checkpoint.
        let new = &h.receipts()[before..];
        assert_eq!(new.len(), 2);
        assert_eq!(new[0].kind, ReceiptKind::Suspend);
        assert_eq!(new[0].verdict, CallVerdict::Ok);
        assert_eq!(new[1].kind, ReceiptKind::Checkpoint);
        // Checkpoint receipt commits to the exact checkpoint bytes.
        assert_eq!(new[1].output_hash, sha256_hex(&cp.bytes));
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn kill_is_suspend_first_with_final_kill_receipt() {
        let (h, c) = counter_host();
        let _ = h.call(&ctx(), "ct", "inc", serde_json::json!({})).unwrap();
        let before = h.receipts().len();
        h.kill("ct").unwrap();
        // The organelle's kill hook ran (not a silent host-side teardown).
        assert!(c.killed.load(std::sync::atomic::Ordering::SeqCst));
        // 3 receipts: Suspend, Checkpoint (from the suspend-first), Kill last.
        let new = &h.receipts()[before..];
        assert_eq!(new.len(), 3);
        assert_eq!(new[0].kind, ReceiptKind::Suspend);
        assert_eq!(new[1].kind, ReceiptKind::Checkpoint);
        assert_eq!(new[2].kind, ReceiptKind::Kill);
        assert_eq!(new[2].verdict, CallVerdict::Ok);
        assert_eq!(new[2].codon, "ct");
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn kill_unknown_codon_errors_cleanly_with_receipt() {
        let h = echo_host();
        let before = h.receipts().len();
        let e = h.kill("zz").unwrap_err();
        assert!(e.contains("unknown organelle codon"), "got: {e}");
        assert!(e.contains("receipt"), "error must carry the receipt id: {e}");
        // Fail-closed: exactly one denial receipt, chain still green.
        let new = &h.receipts()[before..];
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].kind, ReceiptKind::Kill);
        assert_eq!(new[0].verdict, CallVerdict::Denied);
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn suspend_unknown_codon_errors_cleanly_with_receipt() {
        let h = echo_host();
        let before = h.receipts().len();
        let e = h.suspend("zz").unwrap_err();
        assert!(e.contains("unknown organelle codon"), "got: {e}");
        assert!(e.contains("receipt"), "error must carry the receipt id: {e}");
        let new = &h.receipts()[before..];
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].kind, ReceiptKind::Suspend);
        assert_eq!(new[0].verdict, CallVerdict::Denied);
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn default_lifecycle_hooks_are_ephemeral_and_noop() {
        // Echo overrides neither hook: existing organelles compile untouched
        // and suspend as ephemeral.
        let h = echo_host();
        let before = h.receipts().len();
        let cp = h.suspend("te").unwrap();
        assert!(cp.ephemeral);
        assert!(cp.bytes.is_empty());
        h.kill("te").unwrap(); // default kill(): no-op, still receipted
        let new = &h.receipts()[before..];
        assert_eq!(new.len(), 2 + 3); // suspend(2) + kill(3)
        assert_eq!(new[4].kind, ReceiptKind::Kill);
        assert!(h.verify_chain().is_ok());
    }

    // -- P1: bind identity, version, authority to each invocation --------

    /// Manifest helper for the version-skew tests: the "sealed" op
    /// requires `sealed_cap` (`None` = read-only, no cap required).
    fn skew_manifest(codon: &str, version: &str, sealed_cap: Option<&str>) -> OrganelleManifest {
        let mut m = test_manifest(codon, version, vec![]);
        for c in &mut m.contracts {
            if c.op == "sealed" {
                c.required_capability = sealed_cap.map(|s| s.to_string());
                if sealed_cap.is_none() {
                    // Write with no capability is fail-closed at
                    // registration; drop to the inherited ReadOnly.
                    c.mutation_class = None;
                }
            }
        }
        m
    }

    fn skew_host() -> Arc<Host> {
        let h = Host::new();
        // v1 (will be pinned/routed): sealed requires "te.v1cap".
        h.register(Arc::new(Echo {
            manifest: skew_manifest("sk", "1.0.0", Some("te.v1cap")),
            tag: "v1".into(),
        }))
        .unwrap();
        // v2 (latest): sealed requires nothing.
        h.register(Arc::new(Echo {
            manifest: skew_manifest("sk", "2.0.0", None),
            tag: "v2".into(),
        }))
        .unwrap();
        h.set_route("sk", RoutePolicy::Pinned("1.0.0".to_string()))
            .unwrap();
        h
    }

    #[test]
    fn version_skew_boundary_and_execution_use_same_version() {
        // The attack: authorize one implementation, execute another. The
        // old code authorized organelle->organelle calls against
        // `vs.last()` (always the latest, here v2 with no capability
        // requirement) but executed the routed version (v1, which requires
        // "te.v1cap") — the boundary passed while execution ran under a
        // stricter policy. Post-fix both consult the single resolved v1.
        let h = skew_host();
        h.register(Arc::new(caller("ca", vec![], "sk", "sealed")))
            .unwrap();
        let e = h.call(&ctx(), "ca", "relay", serde_json::json!({})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Failed); // relay failed: boundary denial inside
        assert!(e.reason.contains("lacks granted capability"), "got: {}", e.reason);
        // The boundary denied against the ROUTED version's policy and
        // logged it (pre-fix: no boundary denial — it passed on v2).
        let denials = h.boundary_denials();
        assert_eq!(denials.len(), 1);
        assert!(denials[0].reason.contains("te.v1cap"), "got: {}", denials[0].reason);
        assert!(denials[0].reason.contains("1.0.0"), "got: {}", denials[0].reason);
        // The denial receipt carries the established binding: the resolved
        // version is 1.0.0 (not "-"), caller identity is bound, and the
        // membrane-internal call records no surface transport.
        let r = h
            .receipts()
            .iter()
            .find(|r| r.id == denials[0].receipt_id)
            .unwrap()
            .clone();
        assert_eq!(r.manifest_version, "1.0.0");
        assert_eq!(r.caller, "organelle:ca");
        assert_eq!(r.codon, "sk");
        assert!(r.granted_capabilities.is_empty());
        assert_eq!(r.transport, None);
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn version_skew_authorize_and_execute_agree_on_routed_version() {
        // Positive control: with the v1 capability granted, the boundary
        // authorizes on v1's policy AND v1 executes — one version, one
        // binding, end to end.
        let h = skew_host();
        h.register(Arc::new(caller("cb", vec!["te.v1cap".to_string()], "sk", "sealed")))
            .unwrap();
        let out = h.call(&ctx(), "cb", "relay", serde_json::json!({})).unwrap();
        assert_eq!(out["sealed"], serde_json::json!(true));
        assert!(h.boundary_denials().is_empty());
        let r = h
            .receipts()
            .iter()
            .find(|r| r.kind == ReceiptKind::Invocation && r.codon == "sk")
            .unwrap()
            .clone();
        assert_eq!(r.verdict, CallVerdict::Ok);
        assert_eq!(r.manifest_version, "1.0.0");
        assert_eq!(r.caller, "organelle:cb");
        assert_eq!(r.granted_capabilities, vec!["te.v1cap".to_string()]);
        assert_eq!(r.transport, None); // membrane-internal, not a surface arrival
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn version_bound_once_authorize_and_execute_agree() {
        // Surface path: pinned route — the authorized version IS the
        // executed version, and the receipt says so.
        let h = echo_host();
        h.register(Arc::new(Echo { manifest: test_manifest("te", "2.0.0", vec![]), tag: "v2".into() }))
            .unwrap();
        h.set_route("te", RoutePolicy::Pinned("1.0.0".to_string())).unwrap();
        let out = h.call(&ctx(), "te", "echo", serde_json::json!({})).unwrap();
        assert_eq!(out["tag"], serde_json::json!("v1")); // executed v1
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.manifest_version, "1.0.0"); // authorized v1
        assert_eq!(r.transport, Some(Transport::Native));
        assert_eq!(r.caller, "test");
        assert!(r.granted_capabilities.is_empty());
    }

    fn rest_only_manifest(codon: &str, version: &str) -> OrganelleManifest {
        let mut m = test_manifest(codon, version, vec![]);
        m.transports = vec![Transport::Rest];
        m
    }

    #[test]
    fn transport_restriction_native_denied_when_not_declared() {
        let h = Host::new();
        h.register(Arc::new(Echo {
            manifest: rest_only_manifest("ro", "1.0.0"),
            tag: "r".into(),
        }))
        .unwrap();
        let e = h.call(&ctx(), "ro", "echo", serde_json::json!({})).unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("not declared"), "got: {}", e.reason);
        assert!(e.reason.contains("native"), "got: {}", e.reason);
        // The refusal is receipted with the arrival transport recorded.
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.verdict, CallVerdict::Denied);
        assert_eq!(r.transport, Some(Transport::Native));
        assert_eq!(r.manifest_version, "-"); // refused before a binding was established
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn transport_restriction_declared_surface_ok() {
        let h = Host::new();
        h.register(Arc::new(Echo {
            manifest: rest_only_manifest("ro", "1.0.0"),
            tag: "r".into(),
        }))
        .unwrap();
        let g = h.issue_grant("ext", vec![], 300);
        let out = h
            .call_with_grant(&g, Some("ext"), Transport::Rest, "ro", "echo", serde_json::json!({"a": 1}))
            .unwrap();
        assert_eq!(out["tag"], serde_json::json!("r"));
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.verdict, CallVerdict::Ok);
        assert_eq!(r.transport, Some(Transport::Rest));
        assert_eq!(r.manifest_version, "1.0.0");
        assert_eq!(r.caller, "ext");
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn transport_restriction_wrong_external_surface_denied() {
        let h = Host::new();
        h.register(Arc::new(Echo {
            manifest: rest_only_manifest("ro", "1.0.0"),
            tag: "r".into(),
        }))
        .unwrap();
        let g = h.issue_grant("ext", vec![], 300);
        let e = h
            .call_with_grant(&g, Some("ext"), Transport::Mcp, "ro", "echo", serde_json::json!({}))
            .unwrap_err();
        assert_eq!(e.verdict, CallVerdict::Denied);
        assert!(e.reason.contains("not declared"), "got: {}", e.reason);
        assert!(e.reason.contains("mcp"), "got: {}", e.reason);
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.transport, Some(Transport::Mcp));
        assert!(!e.receipt_id.is_empty());
    }

    #[test]
    fn manifest_without_transports_rejected_at_registration() {
        // Decision (also documented in authorize()): there is no
        // "unrestricted" manifest. Empty `transports` is fail-closed at
        // registration, so enforcement never faces an ambiguous case.
        let h = Host::new();
        let mut m = test_manifest("nt", "1.0.0", vec![]);
        m.transports = vec![];
        let errs = h
            .register(Arc::new(Echo { manifest: m, tag: "x".into() }))
            .unwrap_err();
        assert!(errs.iter().any(|x| x.field == "transports"), "got: {errs:?}");
        assert_eq!(h.list_manifests().len(), 0);
    }

    #[test]
    fn invocation_binding_carried_on_receipt() {
        // The receipt carries the full bound tuple: caller identity,
        // organelle id, resolved version, granted capabilities, transport.
        let h = echo_host();
        let g = h.issue_grant("ext", vec!["te.write".to_string()], 300);
        let out = h
            .call_with_grant(&g, Some("ext"), Transport::Native, "te", "sealed", serde_json::json!({}))
            .unwrap();
        assert_eq!(out["sealed"], serde_json::json!(true));
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.caller, "ext");
        assert_eq!(r.codon, "te");
        assert_eq!(r.op, "sealed");
        assert_eq!(r.manifest_version, "1.0.0");
        assert_eq!(r.granted_capabilities, vec!["te.write".to_string()]);
        assert_eq!(r.transport, Some(Transport::Native));
        // The receipt id commits to the binding fields.
        assert_eq!(r.compute_id(), r.id);
        assert!(h.verify_chain().is_ok());
    }

    #[test]
    fn receipt_binding_immutable_and_tamper_evident() {
        // The binding is established pre-execution and immutable after:
        // fetched receipts are clones, and any tampering with the bound
        // fields breaks the content address (verify_chain would fail).
        let h = echo_host();
        let g = h.issue_grant("ext", vec!["te.write".to_string()], 300);
        h.call_with_grant(&g, Some("ext"), Transport::Native, "te", "sealed", serde_json::json!({}))
            .unwrap();
        let stored = h.receipts().last().unwrap().clone();
        // A hostile mutation of a fetched copy is evident: the id no
        // longer recomputes over the tampered body.
        let mut forged = stored.clone();
        forged.granted_capabilities = vec!["admin.*".to_string()];
        forged.manifest_version = "9.9.9".to_string();
        assert_ne!(forged.compute_id(), forged.id);
        // The stored record is untouched and the chain stays green.
        let again = h.receipts().last().unwrap().clone();
        assert_eq!(again.granted_capabilities, vec!["te.write".to_string()]);
        assert_eq!(again.manifest_version, "1.0.0");
        assert_eq!(again.transport, Some(Transport::Native));
        assert!(h.verify_chain().is_ok());
    }
}
