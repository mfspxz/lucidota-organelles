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
    validate_manifest_json, ManifestError, OrganelleManifest, Valence,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

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
pub trait HostRef: Send + Sync {
    fn call_organelle(
        &self,
        caller_codon: &str,
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
            "caller": self.caller, "input_hash": self.input_hash,
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
}

/// parkwreck-organelle-host. Share via `Arc<Host>`; all methods take `&self`.
pub struct Host {
    inner: RwLock<HostInner>,
}

impl Host {
    pub fn new() -> Arc<Self> {
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
            }),
        })
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

    fn receipt_shell(
        kind: ReceiptKind,
        codon: &str,
        op: &str,
        version: &str,
        caller: &str,
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
            codon: codon.to_string(),
            op: op.to_string(),
            manifest_version: version.to_string(),
            caller: caller.to_string(),
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

        let r = Self::receipt_shell(
            ReceiptKind::Registration,
            &codon,
            "register",
            &version,
            "host",
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
        let rid = self.emit_receipt(Self::receipt_shell(
            kind,
            codon,
            op,
            "-",
            "host",
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
            codon,
            "suspend",
            &version,
            "host",
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
            codon,
            "checkpoint",
            &version,
            "host",
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
            codon,
            "kill",
            &version,
            "host",
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
    pub fn call(
        &self,
        ctx: &CallContext,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, CallError> {
        self.call_with_gate2(ctx, codon, op, input)
    }

    /// Authorize op + capability + input schema. Pure w.r.t. &self.
    fn authorize(
        &self,
        entry: &VersionedEntry,
        ctx: &CallContext,
        op: &str,
        input: &Value,
    ) -> Gate2 {
        let m = &entry.manifest;
        let contract = match m.contract(op) {
            Some(c) => c,
            None => {
                return Gate2::Stop {
                    reason: format!("unknown op \"{op}\" for codon \"{}\"", m.codon),
                }
            }
        };
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
            organelle: entry.organelle.clone(),
            version: m.version.clone(),
        }
    }

    // -- organelle -> organelle (org-011 authority boundary) ---------------

    /// Called by organelles via `HostRef`. The calling organelle's
    /// *granted* capabilities are checked against the callee's required
    /// capability; excess is denied and logged (fail-closed).
    pub fn call_as_organelle(
        &self,
        caller_codon: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        let (granted, callee_need): (Vec<String>, Option<String>) = {
            let inner = self.inner.read().unwrap();
            let caller_manifest = inner
                .organelles
                .get(caller_codon)
                .and_then(|vs| vs.last())
                .map(|e| e.manifest.clone());
            let callee_manifest = inner
                .organelles
                .get(codon)
                .and_then(|vs| vs.last())
                .map(|e| e.manifest.clone());
            match (caller_manifest, callee_manifest) {
                (Some(cm), Some(tm)) => {
                    let (_, need) = tm.authority_for(op);
                    (cm.authority.granted_capabilities.clone(), need.map(|s| s.to_string()))
                }
                _ => {
                    return Err(OrganelleError::denied(format!(
                        "boundary: unknown codon in organelle->organelle call ({caller_codon} -> {codon})"
                    )))
                }
            }
        };
        if let Some(need) = callee_need {
            if !granted.iter().any(|c| c == &need) {
                let reason = format!(
                    "organelle \"{caller_codon}\" lacks granted capability \"{need}\" for {codon}.{op}"
                );
                // Log the denial AND receipt it (no silent pass).
                let ctx = CallContext::new(format!("organelle:{caller_codon}"), granted);
                let rid = self.emit_receipt(Self::receipt_shell(
                    ReceiptKind::Invocation,
                    codon,
                    op,
                    "-",
                    &ctx.caller,
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
        let ctx = CallContext::new(format!("organelle:{caller_codon}"), granted);
        self.call(&ctx, codon, op, input)
            .map_err(|e| OrganelleError::new("denied", e.reason))
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
        let rid = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::ProfileActivate,
            "-",
            "profile.activate",
            "-",
            "host",
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
        let rid = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::ProfileRollback,
            "-",
            "profile.rollback",
            "-",
            "host",
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
        let rid = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::RouteChange,
            codon,
            "route.set",
            "-",
            "host",
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
        let rid = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::RouteRollback,
            codon,
            "route.rollback",
            "-",
            "host",
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

impl Host {
    // Re-map Gate2 into the phase-1 Gate used by call(). Kept separate so
    // the denied-vs-rejected distinction survives to the receipt.
    fn gate2_to_phase1(&self, g: Gate2) -> Phase1 {
        match g {
            Gate2::Go { manifest, organelle, version } => Phase1::Go { manifest, organelle, version },
            Gate2::Stop { reason } => Phase1::Stop { reason, verdict: CallVerdict::Denied },
            Gate2::StopRejected { reason } => Phase1::Stop { reason, verdict: CallVerdict::Rejected },
        }
    }
}

enum Phase1 {
    Go {
        manifest: OrganelleManifest,
        organelle: Arc<dyn Organelle>,
        version: String,
    },
    Stop {
        reason: String,
        verdict: CallVerdict,
    },
}

impl HostRef for Host {
    fn call_organelle(
        &self,
        caller_codon: &str,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        self.call_as_organelle(caller_codon, codon, op, input)
    }
}

// NOTE: `call` above uses an inline `Gate` enum; the authorize() helper
// returns Gate2. To keep the two in agreement without duplicating logic,
// call() delegates the whole phase-1 through a small adapter. The adapter
// is exercised by tests; the match arms are exhaustive so a new Gate2
// variant is a compile error here, not a silent pass.
impl Host {
    pub(crate) fn call_with_gate2(
        &self,
        ctx: &CallContext,
        codon: &str,
        op: &str,
        input: Value,
    ) -> Result<Value, CallError> {
        let phase1: Phase1 = {
            let inner = self.inner.read().unwrap();
            let g: Gate2 = if let Some(active) = &inner.active_profile {
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
                        Ok((_, e)) => self.authorize(e, ctx, op, &input),
                        Err(reason) => Gate2::Stop { reason },
                    }
                }
            } else {
                match self.resolve_locked(&inner, codon, &ctx.trace_id) {
                    Ok((_, e)) => self.authorize(e, ctx, op, &input),
                    Err(reason) => Gate2::Stop { reason },
                }
            };
            self.gate2_to_phase1(g)
        };

        let (verdict, output_hash, valence, note, result): (
            CallVerdict,
            String,
            Valence,
            Option<String>,
            Result<(Value, String), CallError>,
        ) = match phase1 {
            Phase1::Stop { reason, verdict } => {
                let tag = match verdict {
                    CallVerdict::Denied => "denied",
                    CallVerdict::Rejected => "rejected",
                    _ => "stopped",
                };
                (
                    verdict,
                    format!("{tag}:{reason}"),
                    Valence::Candidate,
                    Some(reason.clone()),
                    Err(CallError { verdict, reason, receipt_id: String::new() }),
                )
            }
            Phase1::Go { manifest, organelle, version } => {
                match organelle.handle(ctx, self, op, input.clone()) {
                    Ok(output) => (
                        CallVerdict::Ok,
                        hash_value(&output),
                        manifest.authority.declared_valence,
                        None,
                        Ok((output, version)),
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
                }
            }
        };

        let version = match &result {
            Ok((_, v)) => v.clone(),
            Err(_) => "-".to_string(),
        };
        let receipt_id = self.emit_receipt(Self::receipt_shell(
            ReceiptKind::Invocation,
            codon,
            op,
            &version,
            &ctx.caller,
            &input,
            output_hash,
            verdict,
            valence,
            note,
        ));
        match result {
            Ok((output, _)) => Ok(output),
            Err(mut e) => {
                e.receipt_id = receipt_id;
                Err(e)
            }
        }
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
    struct Caller {
        manifest: OrganelleManifest,
    }

    impl Organelle for Caller {
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
            assert_eq!(op, "relay");
            host.call_organelle(&self.manifest.codon, "te", "sealed", input)
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
        h.register(Arc::new(Caller { manifest: caller_manifest("ca", vec!["te.write".to_string()]) }))
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
        h.register(Arc::new(Caller { manifest: caller_manifest("cb", vec![]) })).unwrap();
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
}
