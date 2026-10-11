//! Claim reconciler organelle (codon `cr`).
//!
//! Deterministic claim/defeat reconciliation per rigor doctrine (R-1: one
//! book for claims and defeats; R-9: frozen ledger schemas with
//! SUPERSEDED-BY-BYPASS). Behavior:
//!
//! - `open-store`: binds ONE canonical absolute store path to an unforgeable
//!   256-bit grant token issued by the organelle (never caller-supplied).
//!   The path is approved through the host membrane
//!   (`HostRef::approve_write_path`): it must live under an operator
//!   allowlisted write root (default deny), and `..` / symlink escapes are
//!   rejected. The grant also binds the issuing caller and a TTL.
//! - `close-store`: revokes a grant token.
//! - `ingest-claim`: records a fix claim with a permanent ID (`FC-<n>`).
//!   Default scope is `INSTANCE_ONLY`; the organelle refuses to record any
//!   other scope at ingest — class closure goes through the gate.
//! - `ingest-defect`: records a defect. If it defeats an existing claim
//!   (reproduces the claimed-fixed behavior, with defeating-probe evidence)
//!   the claim is marked `SUPERSEDED_BY_BYPASS`: the original receipt is
//!   preserved untouched, a new event is appended with `supersedes_seq` and
//!   a link to the defeating probe. There is no delete op and no overwrite.
//! - `claim-status`: current status per claim (`INSTANCE_ONLY` /
//!   `CLASS_CLOSED` / `SUPERSEDED_BY_BYPASS`) with full history.
//! - `request-class-closure`: gated class closure. Requires all four of
//!   original_reproducer, adversarial_variants, prior_bypass_corpus,
//!   independent_review, plus independence rules. Refusals are errors, and
//!   the refusal itself is appended to the event store (audit, not a claim).
//!   The organelle has no authority to certify its own correctness.
//! - `verify`: recomputes the hash chain over the event store, then applies
//!   the provenance checks.
//!
//! ## R3-V4 repair (grant-bound store handles + evidence provenance)
//!
//! Every mutating op (`ingest-claim`, `ingest-defect`,
//! `request-class-closure`) takes `grant_token` instead of a raw
//! `store_path`. Caller-supplied paths on the write path are gone: the
//! organelle writes only to the canonical path bound at `open-store` time,
//! inside the grant-bound write root (the canonical parent directory of the
//! store file). Unknown, expired, or caller-mismatched tokens are denied.
//!
//! Provenance: every mutation records `recorded_by` (the issuing grant's
//! id); class closures record `attested_by`. Defeating probes must name a
//! real `artifact_path` inside the grant-bound root whose sha256 matches
//! `payload_hash` — invented probes are refused at ingest and failed by
//! `verify` if they ever appear in the book.
//!
//! Self-attestation refusal: the grant that recorded a claim may not attest
//! its class closure. The gate refuses it; `verify` fails any
//! `class-closure-granted` whose `attested_by` equals the claim's
//! `recorded_by`.
//!
//! Grants are process-lifetime: `suspend()` clears the registry, so tokens
//! issued before a suspend/resume boundary are rejected after it. The
//! default (ephemeral) checkpoint stays honest.
//!
//! The event store is an append-only JSONL file with a sha256 chain over
//! `prev_hash + seq + canonical(entry)`.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    canonical_json, sha256_hex, utc_now_iso, Authority, Contract, MutationClass,
    OrganelleManifest, ReceiptPolicy, Transport, Valence, MANIFEST_SCHEMA_VERSION,
    RECEIPT_ALGORITHM,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Build a JSON-Schema object validator from (field, json-type, required) rows.
/// The host validates every call input against the contract schema, so the
/// declared types must match what the op actually reads.
fn obj_schema(fields: &[(&str, &str, bool)]) -> Value {
    let mut props = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, ty, req) in fields {
        props.insert(name.to_string(), json!({"type": ty}));
        if *req {
            required.push((*name).to_string());
        }
    }
    json!({
        "type": "object",
        "required": required,
        "properties": props,
        "additionalProperties": true,
    })
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "claim-reconciler".to_string(),
        codon: "cr".to_string(),
        version: "1.1.0".to_string(),
        description: "claim-defeat reconciliation: grant-bound store handles, permanent claim IDs, instance-only default scope, gated class closure with self-attestation refusal, hash-resolvable defeating probes, bypass-linked supersede preserving the original receipt, append-only hash-chained event store".to_string(),
        contracts: vec![
            Contract {
                op: "open-store".to_string(),
                description: "bind a store path (host-approved under an operator write root) to an unforgeable grant token; mutating ops take the token, never a raw path".to_string(),
                input_schema: obj_schema(&[("store_path","string",true),("ttl_seconds","integer",false)]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("claims.write".to_string()),
            },
            Contract {
                op: "close-store".to_string(),
                description: "revoke a store grant token; the token is rejected afterwards".to_string(),
                input_schema: obj_schema(&[("grant_token","string",true)]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("claims.write".to_string()),
            },
            Contract {
                op: "ingest-claim".to_string(),
                description: "record a fix claim; permanent ID FC-<n> assigned when absent; scope locked to INSTANCE_ONLY; provenance recorded_by the issuing grant".to_string(),
                input_schema: obj_schema(&[("grant_token","string",true),("claim_id","string",false),("fix_evidence","array",true),("proof_script_path","string",true),("commit","string",true),("description","string",false),("scope","string",false)]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("claims.write".to_string()),
            },
            Contract {
                op: "ingest-defect".to_string(),
                description: "record a defect; when it reproduces a claimed-fixed behavior, append a SUPERSEDED_BY_BYPASS linkage preserving the original receipt. The defeating probe must name a real artifact inside the grant-bound root whose sha256 matches payload_hash".to_string(),
                input_schema: obj_schema(&[("grant_token","string",true),("defect_id","string",true),("defeats_claim_id","string",false),("defeating_probe","object",false),("reproduces_fixed_behavior","boolean",false),("links","array",false)]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("claims.write".to_string()),
            },
            Contract {
                op: "claim-status".to_string(),
                description: "current status of a claim (INSTANCE_ONLY / CLASS_CLOSED / SUPERSEDED_BY_BYPASS) with full event history".to_string(),
                input_schema: obj_schema(&[("store_path","string",true),("claim_id","string",true),("evidence","object",false)]),
                mutation_class: Some(MutationClass::ReadOnly),
                required_capability: None,
            },
            Contract {
                op: "request-class-closure".to_string(),
                description: "request class closure for a claim; granted only with all four evidence pieces, independent review that is not a reproducer replay, and an attesting grant different from the recording grant (self-attestation refused)".to_string(),
                input_schema: obj_schema(&[("grant_token","string",true),("claim_id","string",true),("evidence","object",false)]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("claims.class_close".to_string()),
            },
            Contract {
                op: "verify".to_string(),
                description: "recompute the event-store hash chain and provenance checks (probe artifacts resolvable + hash-matching; no self-attested closures); reports ok or the first breaking seq".to_string(),
                input_schema: obj_schema(&[("store_path","string",true)]),
                mutation_class: Some(MutationClass::ReadOnly),
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::Write,
            declared_valence: Valence::Candidate,
            required_capability: Some("claims.write".to_string()),
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

// ---------------------------------------------------------------------------
// Grant-bound store handles (R3-V4 repair)
// ---------------------------------------------------------------------------

/// Default grant TTL: one hour. Clamped to [60s, 24h] on open.
const DEFAULT_GRANT_TTL_SECS: u64 = 3600;
const MIN_GRANT_TTL_SECS: u64 = 60;
const MAX_GRANT_TTL_SECS: u64 = 86400;

/// A live store grant: ONE canonical store path bound to ONE unguessable
/// token, issued to ONE caller, valid until `expires_at`. Every mutating op
/// resolves its `grant_token` through the registry — raw caller-supplied
/// paths never reach the filesystem on the write path.
#[derive(Debug, Clone)]
struct StoreGrant {
    token: String,
    grant_id: String,
    store_path: PathBuf,
    /// Grant-bound write root: canonical parent directory of the store.
    /// Defeating-probe artifacts must resolve inside it.
    root: PathBuf,
    issued_to: String,
    expires_at: u64,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mint a 256-bit unguessable token. Fail-closed: if the OS gives us no
/// entropy, no grant is issued.
fn mint_token() -> Result<String, OrganelleError> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| {
            OrganelleError::failed(format!(
                "entropy unavailable, refusing to mint grant token: {e}"
            ))
        })?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Check a defeating-probe artifact against the grant-bound root:
/// canonicalize (must exist), reject escapes, require the file's sha256 to
/// equal `payload_hash`. Returns the canonical artifact path for the book.
fn resolve_probe_artifact(
    root: &Path,
    artifact_path: &str,
    payload_hash: &str,
) -> Result<String, OrganelleError> {
    let raw = artifact_path.trim();
    if raw.is_empty() {
        return Err(OrganelleError::denied(
            "defeating_probe.artifact_path must not be empty",
        ));
    }
    let p = Path::new(raw);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    };
    let canon = joined.canonicalize().map_err(|e| {
        OrganelleError::denied(format!("defeating probe artifact unresolvable: {e}"))
    })?;
    if !canon.starts_with(root) {
        return Err(OrganelleError::denied(
            "defeating probe artifact escapes the grant-bound write root",
        ));
    }
    if !canon.is_file() {
        return Err(OrganelleError::denied(
            "defeating probe artifact is not a file",
        ));
    }
    let bytes = std::fs::read(&canon).map_err(|e| {
        OrganelleError::denied(format!("defeating probe artifact unreadable: {e}"))
    })?;
    if sha256_hex(&bytes) != payload_hash {
        return Err(OrganelleError::denied(
            "defeating probe artifact hash does not match payload_hash: invented probes are not evidence",
        ));
    }
    Ok(canon.to_string_lossy().into_owned())
}

/// Read-only variant used by `verify`: same checks, failure as a string so
/// the caller can report `ok:false` instead of erroring the call.
fn check_probe_artifact(root: &Path, artifact_path: &str, payload_hash: &str) -> Result<(), String> {
    let canon = Path::new(artifact_path).canonicalize().map_err(|e| {
        format!("defeating probe artifact unresolvable ({artifact_path}): {e}")
    })?;
    if !canon.starts_with(root) {
        return Err(format!(
            "defeating probe artifact escapes the grant-bound root: {artifact_path}"
        ));
    }
    let bytes = std::fs::read(&canon)
        .map_err(|e| format!("defeating probe artifact unreadable: {e}"))?;
    if sha256_hex(&bytes) != payload_hash {
        return Err(
            "defeating probe artifact hash does not match payload_hash: invented probes are not evidence"
                .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Event store
// ---------------------------------------------------------------------------

/// Genesis prev-hash for seq 0.
const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Status values. Trinary discipline: a claim is exactly one of these.
pub const STATUS_INSTANCE_ONLY: &str = "INSTANCE_ONLY";
pub const STATUS_CLASS_CLOSED: &str = "CLASS_CLOSED";
pub const STATUS_SUPERSEDED_BY_BYPASS: &str = "SUPERSEDED_BY_BYPASS";

/// Event kinds written to the store.
pub const KIND_CLAIM_INGESTED: &str = "claim-ingested";
pub const KIND_DEFECT_INGESTED: &str = "defect-ingested";
pub const KIND_CLAIM_SUPERSEDED: &str = "claim-superseded";
pub const KIND_CLASS_CLOSURE_GRANTED: &str = "class-closure-granted";
pub const KIND_CLASS_CLOSURE_REFUSED: &str = "class-closure-refused";

/// One stored line: the hash chain commits to prev + seq + canonical entry.
#[derive(Debug, Clone)]
struct StoredEntry {
    seq: u64,
    prev_hash: String,
    entry: Value,
    entry_hash: String,
}

/// Read-path guard only. The write path no longer accepts caller-supplied
/// paths at all (grant-bound handles); this stays as defense-in-depth for
/// the read-only ops (`claim-status`, `verify`) that still take store_path.
fn check_store_path(path: &Path) -> Result<(), OrganelleError> {
    use std::path::Component;
    if path.as_os_str().is_empty() {
        return Err(OrganelleError::denied("store_path must not be empty"));
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(OrganelleError::denied("store_path must not contain .."));
    }
    Ok(())
}

fn entry_hash(prev_hash: &str, seq: u64, entry: &Value) -> String {
    let mut preimage = String::with_capacity(64 + 20 + 256);
    preimage.push_str(prev_hash);
    preimage.push_str(&seq.to_string());
    preimage.push_str(&canonical_json(entry));
    sha256_hex(preimage.as_bytes())
}

fn read_store(path: &Path) -> Result<Vec<StoredEntry>, OrganelleError> {
    check_store_path(path)?;
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(OrganelleError::failed(format!("read store: {e}"))),
    };
    let text = String::from_utf8(bytes)
        .map_err(|e| OrganelleError::failed(format!("store is not UTF-8: {e}")))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .map_err(|e| OrganelleError::failed(format!("store line {i} not JSON: {e}")))?;
        out.push(StoredEntry {
            seq: v["seq"].as_u64().unwrap_or(u64::MAX),
            prev_hash: v["prev_hash"].as_str().unwrap_or("").to_string(),
            entry: v["entry"].clone(),
            entry_hash: v["entry_hash"].as_str().unwrap_or("").to_string(),
        });
    }
    Ok(out)
}

/// Append one event payload. Returns the sealed stored line.
/// `path` must be a grant-bound canonical path — never raw caller input.
fn append_entry(path: &Path, entry: Value) -> Result<StoredEntry, OrganelleError> {
    let existing = read_store(path)?;
    let seq = existing.len() as u64;
    let prev_hash = existing
        .last()
        .map(|e| e.entry_hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    let hash = entry_hash(&prev_hash, seq, &entry);
    let stored = StoredEntry {
        seq,
        prev_hash: prev_hash.clone(),
        entry: entry.clone(),
        entry_hash: hash.clone(),
    };
    let line = canonical_json(&json!({
        "seq": seq,
        "prev_hash": prev_hash,
        "entry": entry,
        "entry_hash": hash,
    })) + "\n";
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(line.as_bytes())
        })
        .map_err(|e| OrganelleError::failed(format!("append to store: {e}")))?;
    Ok(stored)
}

fn verify_store(path: &str) -> Result<Value, OrganelleError> {
    let store_path = Path::new(path);
    let entries = read_store(store_path)?;
    let mut prev = GENESIS_HASH.to_string();
    for (i, e) in entries.iter().enumerate() {
        let expected_seq = i as u64;
        if e.seq != expected_seq {
            return Ok(json!({"ok": false, "break_at_seq": e.seq,
                "reason": format!("seq gap: expected {expected_seq}, found {}", e.seq)}));
        }
        if e.prev_hash != prev {
            return Ok(json!({"ok": false, "break_at_seq": e.seq,
                "reason": "prev_hash does not match previous entry_hash"}));
        }
        let recomputed = entry_hash(&e.prev_hash, e.seq, &e.entry);
        if recomputed != e.entry_hash {
            return Ok(json!({"ok": false, "break_at_seq": e.seq,
                "reason": "entry_hash mismatch: stored bytes do not match sealed entry"}));
        }
        prev = e.entry_hash.clone();
    }
    if entries.is_empty() {
        return Ok(json!({"ok": true, "entries": 0, "head_hash": prev}));
    }

    // --- R3-V4 provenance checks --------------------------------------
    // claim_id -> recording grant id (absent for pre-grant legacy entries).
    let mut recorded_by: HashMap<&str, &str> = HashMap::new();
    for e in &entries {
        if e.entry["kind"].as_str() == Some(KIND_CLAIM_INGESTED) {
            if let (Some(cid), Some(rb)) = (
                e.entry["claim_id"].as_str(),
                e.entry["recorded_by"].as_str(),
            ) {
                recorded_by.insert(cid, rb);
            }
        }
    }
    // Grant-bound root for probe resolution: canonical parent directory of
    // the store file. Matches the root bound at open-store time.
    let canon_store = store_path.canonicalize().map_err(|e| {
        OrganelleError::failed(format!("verify: cannot canonicalize store path: {e}"))
    })?;
    let root = canon_store.parent().ok_or_else(|| {
        OrganelleError::failed("verify: store path has no parent directory")
    })?;

    for e in &entries {
        let kind = e.entry["kind"].as_str().unwrap_or("");
        // Every SUPERSEDED_BY_BYPASS must resolve to a stored,
        // hash-matching probe artifact. No invented probes.
        if kind == KIND_CLAIM_SUPERSEDED {
            let probe = &e.entry["defeating_probe"];
            // No legacy exemption (round-6 lane-6): a supersede entry
            // without a resolvable, hash-matching artifact_path is
            // indistinguishable from a direct-filesystem forgery — the
            // event chain is keyless, so anyone with write access to the
            // book can seal it. Fail closed.
            match probe["artifact_path"].as_str() {
                Some(art) => {
                    let ph = probe["payload_hash"].as_str().unwrap_or("");
                    if let Err(reason) = check_probe_artifact(root, art, ph) {
                        return Ok(json!({"ok": false, "break_at_seq": e.seq,
                            "reason": reason}));
                    }
                }
                None => {
                    return Ok(json!({"ok": false, "break_at_seq": e.seq,
                        "reason": "defeating probe has no artifact_path: supersede is unverifiable (no legacy exemption)"}));
                }
            }
        }
        // No self-attested class closure: the attesting grant must differ
        // from the grant that recorded the claim.
        if kind == KIND_CLASS_CLOSURE_GRANTED {
            if let (Some(cid), Some(ab)) = (
                e.entry["claim_id"].as_str(),
                e.entry["attested_by"].as_str(),
            ) {
                if let Some(rb) = recorded_by.get(cid) {
                    if *rb == ab {
                        return Ok(json!({"ok": false, "break_at_seq": e.seq,
                            "reason": format!("self-attested class closure for {cid}: recording grant {rb} attested its own closure")}));
                    }
                }
            }
        }
    }

    Ok(json!({"ok": true, "entries": entries.len(), "head_hash": prev}))
}

// ---------------------------------------------------------------------------
// Claim helpers
// ---------------------------------------------------------------------------

fn valid_claim_id(id: &str) -> bool {
    id.len() > 3
        && id.starts_with("FC-")
        && id[3..].chars().all(|c| c.is_ascii_digit())
        && !id[3..].is_empty()
}

/// The seq of the original claim-ingested event for `claim_id`, if any.
fn claim_ingested_seq(entries: &[StoredEntry], claim_id: &str) -> Option<u64> {
    entries.iter().find_map(|e| {
        if e.entry["kind"] == KIND_CLAIM_INGESTED && e.entry["claim_id"] == claim_id {
            Some(e.seq)
        } else {
            None
        }
    })
}

fn claim_ingested_entry(entries: &[StoredEntry], claim_id: &str) -> Option<Value> {
    entries.iter().find_map(|e| {
        if e.entry["kind"] == KIND_CLAIM_INGESTED && e.entry["claim_id"] == claim_id {
            Some(e.entry.clone())
        } else {
            None
        }
    })
}

fn events_for_claim<'a>(entries: &'a [StoredEntry], claim_id: &'a str) -> Vec<&'a StoredEntry> {
    entries
        .iter()
        .filter(|e| {
            let k = e.entry["kind"].as_str().unwrap_or("");
            let cid = e.entry["claim_id"].as_str().unwrap_or("");
            (k == KIND_CLAIM_INGESTED
                || k == KIND_DEFECT_INGESTED
                || k == KIND_CLAIM_SUPERSEDED
                || k == KIND_CLASS_CLOSURE_GRANTED
                || k == KIND_CLASS_CLOSURE_REFUSED)
                && (cid == claim_id
                    || (k == KIND_DEFECT_INGESTED
                        && e.entry["defeats_claim_id"].as_str().unwrap_or("") == claim_id))
        })
        .collect()
}

fn claim_count(entries: &[StoredEntry]) -> u64 {
    entries
        .iter()
        .filter(|e| e.entry["kind"] == KIND_CLAIM_INGESTED)
        .count() as u64
}

fn non_empty_str(v: &Value, key: &str) -> Option<String> {
    v[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Organelle
// ---------------------------------------------------------------------------

pub struct ClaimReconciler {
    manifest: OrganelleManifest,
    grants: Mutex<HashMap<String, StoreGrant>>,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(ClaimReconciler {
        manifest: manifest(),
        grants: Mutex::new(HashMap::new()),
    })
}

impl ClaimReconciler {
    fn prune_expired_locked(grants: &mut HashMap<String, StoreGrant>, now: u64) {
        grants.retain(|_, g| g.expires_at > now);
    }

    /// Resolve a caller-supplied grant token to its bound store. Denies
    /// unknown tokens, expired tokens, and tokens presented by a caller
    /// other than the one that opened the store (cross-caller token replay
    /// is not a delegation mechanism).
    fn resolve_grant(
        &self,
        ctx: &CallContext,
        input: &Value,
    ) -> Result<StoreGrant, OrganelleError> {
        let token = non_empty_str(input, "grant_token").ok_or_else(|| {
            OrganelleError::denied("grant_token required: open the store with open-store first")
        })?;
        let mut grants = self.grants.lock().unwrap();
        let now = now_unix();
        Self::prune_expired_locked(&mut grants, now);
        let g = grants
            .get(&token)
            .ok_or_else(|| OrganelleError::denied("unknown or expired grant_token"))?
            .clone();
        if g.expires_at <= now {
            grants.remove(&token);
            return Err(OrganelleError::denied("grant_token expired"));
        }
        if g.issued_to != ctx.caller {
            return Err(OrganelleError::denied(
                "grant_token was not issued to this caller",
            ));
        }
        Ok(g)
    }

    fn op_open_store(
        &self,
        ctx: &CallContext,
        host: &dyn HostRef,
        input: &Value,
    ) -> Result<Value, OrganelleError> {
        let raw = non_empty_str(input, "store_path")
            .ok_or_else(|| OrganelleError::denied("store_path required"))?;
        // Membrane approval: canonicalizes, enforces the operator's write
        // roots (default deny when none are configured), rejects `..` and
        // symlink escapes. The grant binds the APPROVED path — raw caller
        // input is never consulted again after this point.
        let approved = host.approve_write_path(&raw)?;
        let root = approved
            .parent()
            .ok_or_else(|| OrganelleError::denied("store path has no parent directory"))?
            .to_path_buf();
        let ttl = input["ttl_seconds"]
            .as_u64()
            .unwrap_or(DEFAULT_GRANT_TTL_SECS)
            .clamp(MIN_GRANT_TTL_SECS, MAX_GRANT_TTL_SECS);
        let token = mint_token()?;
        let grant_id = format!("g-{}", &token[..12]);
        let now = now_unix();
        let expires_at = now + ttl;
        {
            let mut grants = self.grants.lock().unwrap();
            Self::prune_expired_locked(&mut grants, now);
            grants.insert(
                token.clone(),
                StoreGrant {
                    token: token.clone(),
                    grant_id: grant_id.clone(),
                    store_path: approved.clone(),
                    root: root.clone(),
                    issued_to: ctx.caller.clone(),
                    expires_at,
                },
            );
        }
        Ok(json!({
            "ok": true,
            "grant_token": token,
            "grant_id": grant_id,
            "store_path": approved.to_string_lossy(),
            "write_root": root.to_string_lossy(),
            "issued_to": ctx.caller,
            "expires_at": expires_at,
        }))
    }

    fn op_close_store(
        &self,
        ctx: &CallContext,
        input: &Value,
    ) -> Result<Value, OrganelleError> {
        let g = self.resolve_grant(ctx, input)?;
        self.grants.lock().unwrap().remove(&g.token);
        Ok(json!({"ok": true, "revoked": g.grant_id}))
    }

    fn op_ingest_claim(&self, ctx: &CallContext, input: &Value) -> Result<Value, OrganelleError> {
        let grant = self.resolve_grant(ctx, input)?;
        let entries = read_store(&grant.store_path)?;

        let fix_evidence = input["fix_evidence"]
            .as_array()
            .ok_or_else(|| OrganelleError::denied("fix_evidence must be a non-empty array"))?;
        if fix_evidence.is_empty()
            || fix_evidence
                .iter()
                .any(|r| r.as_str().map(str::trim).unwrap_or("").is_empty())
        {
            return Err(OrganelleError::denied(
                "fix_evidence must be a non-empty array of non-empty refs",
            ));
        }
        let proof_script_path = non_empty_str(input, "proof_script_path")
            .ok_or_else(|| OrganelleError::denied("proof_script_path required"))?;
        let commit = non_empty_str(input, "commit")
            .ok_or_else(|| OrganelleError::denied("commit required"))?;

        // Scope is locked at ingest: INSTANCE_ONLY. Class closure is only
        // ever granted through request-class-closure.
        let scope = input["scope"].as_str().unwrap_or(STATUS_INSTANCE_ONLY);
        if scope != STATUS_INSTANCE_ONLY {
            return Err(OrganelleError::denied(
                "scope must be INSTANCE_ONLY at ingest; class closure goes through request-class-closure",
            ));
        }

        let claim_id = match non_empty_str(input, "claim_id") {
            Some(id) => {
                if !valid_claim_id(&id) {
                    return Err(OrganelleError::denied(
                        "claim_id must match FC-<n> (permanent ID format)",
                    ));
                }
                if claim_ingested_seq(&entries, &id).is_some() {
                    return Err(OrganelleError::denied(format!(
                        "claim_id {id} already exists; IDs are permanent and never reused"
                    )));
                }
                id
            }
            None => format!("FC-{}", claim_count(&entries) + 1),
        };

        let entry = json!({
            "kind": KIND_CLAIM_INGESTED,
            "claim_id": claim_id,
            "scope": STATUS_INSTANCE_ONLY,
            "fix_evidence": fix_evidence,
            "proof_script_path": proof_script_path,
            "commit": commit,
            "description": input["description"].as_str().unwrap_or(""),
            "recorded_by": grant.grant_id,
            "ts": utc_now_iso(),
            "actor": ctx.caller,
        });
        let stored = append_entry(&grant.store_path, entry)?;
        Ok(json!({
            "ok": true,
            "claim_id": claim_id,
            "scope": STATUS_INSTANCE_ONLY,
            "seq": stored.seq,
            "entry_hash": stored.entry_hash,
        }))
    }

    fn op_ingest_defect(&self, ctx: &CallContext, input: &Value) -> Result<Value, OrganelleError> {
        let grant = self.resolve_grant(ctx, input)?;
        let defect_id = non_empty_str(input, "defect_id")
            .ok_or_else(|| OrganelleError::denied("defect_id required"))?;
        let entries = read_store(&grant.store_path)?;

        if entries.iter().any(|e| {
            e.entry["kind"] == KIND_DEFECT_INGESTED && e.entry["defect_id"] == defect_id
        }) {
            return Err(OrganelleError::denied(format!(
                "defect_id {defect_id} already recorded; defect records are permanent"
            )));
        }

        let defeats = non_empty_str(input, "defeats_claim_id");

        if let Some(ref claim_id) = defeats {
            // Supersede path: fail-closed unless the defeat is fully linked.
            let orig_seq = claim_ingested_seq(&entries, claim_id).ok_or_else(|| {
                OrganelleError::not_found(format!("unknown claim {claim_id}; cannot supersede"))
            })?;
            let probe = &input["defeating_probe"];
            if !probe.is_object() {
                return Err(OrganelleError::denied(
                    "supersede requires defeating_probe evidence {evidence_ref, payload_hash, artifact_path}",
                ));
            }
            let evidence_ref = non_empty_str(probe, "evidence_ref").ok_or_else(|| {
                OrganelleError::denied("supersede requires defeating_probe.evidence_ref")
            })?;
            let payload_hash = non_empty_str(probe, "payload_hash").ok_or_else(|| {
                OrganelleError::denied("supersede requires defeating_probe.payload_hash")
            })?;
            // R3-V4: the probe must be a real stored artifact inside the
            // grant-bound root, hash-matching payload_hash. Invented
            // probes are refused here and failed by verify() if hand-fed.
            let artifact_path_raw = non_empty_str(probe, "artifact_path").ok_or_else(|| {
                OrganelleError::denied(
                    "supersede requires defeating_probe.artifact_path: the probe must be a stored artifact inside the grant-bound write root",
                )
            })?;
            let artifact_path =
                resolve_probe_artifact(&grant.root, &artifact_path_raw, &payload_hash)?;
            if input["reproduces_fixed_behavior"] != json!(true) {
                return Err(OrganelleError::denied(
                    "supersede requires reproduces_fixed_behavior=true: the defect must reproduce the claimed-fixed behavior",
                ));
            }
            let defect_entry = json!({
                "kind": KIND_DEFECT_INGESTED,
                "defect_id": defect_id,
                "defeats_claim_id": claim_id,
                "defeating_probe": {"evidence_ref": evidence_ref, "payload_hash": payload_hash,
                    "artifact_path": artifact_path,
                    "output": probe["output"].as_str().unwrap_or("")},
                "reproduces_fixed_behavior": true,
                "links": input["links"].clone(),
                "recorded_by": grant.grant_id,
                "ts": utc_now_iso(),
                "actor": ctx.caller,
            });
            let d = append_entry(&grant.store_path, defect_entry)?;
            // The original claim receipt is preserved; a NEW event carries
            // the supersede linkage. Nothing is overwritten.
            let sup_entry = json!({
                "kind": KIND_CLAIM_SUPERSEDED,
                "claim_id": claim_id,
                "supersedes_seq": orig_seq,
                "defect_id": defect_id,
                "defect_seq": d.seq,
                "defeating_probe": {"evidence_ref": evidence_ref, "payload_hash": payload_hash,
                    "artifact_path": artifact_path},
                "recorded_by": grant.grant_id,
                "ts": utc_now_iso(),
                "actor": ctx.caller,
            });
            let s = append_entry(&grant.store_path, sup_entry)?;
            return Ok(json!({
                "ok": true,
                "defect_id": defect_id,
                "defect_seq": d.seq,
                "superseded": claim_id,
                "supersede_seq": s.seq,
                "supersedes_seq": orig_seq,
            }));
        }

        let entry = json!({
            "kind": KIND_DEFECT_INGESTED,
            "defect_id": defect_id,
            "defeats_claim_id": Value::Null,
            "defeating_probe": input["defeating_probe"].clone(),
            "reproduces_fixed_behavior": false,
            "links": input["links"].clone(),
            "recorded_by": grant.grant_id,
            "ts": utc_now_iso(),
            "actor": ctx.caller,
        });
        let stored = append_entry(&grant.store_path, entry)?;
        Ok(json!({
            "ok": true,
            "defect_id": defect_id,
            "seq": stored.seq,
            "superseded": Value::Null,
        }))
    }

    fn op_claim_status(&self, input: &Value) -> Result<Value, OrganelleError> {
        let path = non_empty_str(input, "store_path")
            .ok_or_else(|| OrganelleError::denied("store_path required"))?;
        let claim_id = non_empty_str(input, "claim_id")
            .ok_or_else(|| OrganelleError::denied("claim_id required"))?;
        let entries = read_store(Path::new(&path))?;
        let original = claim_ingested_entry(&entries, &claim_id).ok_or_else(|| {
            OrganelleError::not_found(format!("unknown claim {claim_id}"))
        })?;

        let mut status = STATUS_INSTANCE_ONLY.to_string();
        let mut terminal_seq: Option<u64> = None;
        let mut superseded_by: Value = Value::Null;
        let mut class_closure: Value = Value::Null;
        let mut refusals = 0u64;
        let mut history = Vec::new();

        for e in events_for_claim(&entries, &claim_id) {
            let kind = e.entry["kind"].as_str().unwrap_or("");
            history.push(json!({
                "seq": e.seq,
                "kind": kind,
                "ts": e.entry["ts"],
                "entry_hash": e.entry_hash,
            }));
            match kind {
                KIND_CLAIM_SUPERSEDED => {
                    if terminal_seq.map_or(true, |t| e.seq > t) {
                        status = STATUS_SUPERSEDED_BY_BYPASS.to_string();
                        terminal_seq = Some(e.seq);
                        superseded_by = json!({
                            "defect_id": e.entry["defect_id"],
                            "defect_seq": e.entry["defect_seq"],
                            "supersede_seq": e.seq,
                            "supersedes_seq": e.entry["supersedes_seq"],
                            "defeating_probe": e.entry["defeating_probe"],
                        });
                    }
                }
                KIND_CLASS_CLOSURE_GRANTED => {
                    if terminal_seq.map_or(true, |t| e.seq > t) {
                        status = STATUS_CLASS_CLOSED.to_string();
                        terminal_seq = Some(e.seq);
                        class_closure = json!({
                            "seq": e.seq,
                            "evidence": e.entry["evidence"],
                            "attested_by": e.entry["attested_by"],
                        });
                    }
                }
                KIND_CLASS_CLOSURE_REFUSED => {
                    refusals += 1;
                }
                _ => {}
            }
        }

        Ok(json!({
            "claim_id": claim_id,
            "status": status,
            "scope": original["scope"],
            "original_claim": original,
            "superseded_by": superseded_by,
            "class_closure": class_closure,
            "refusals": refusals,
            "history": history,
        }))
    }

    /// Gate the class-closure evidence bundle. Returns refusal reasons;
    /// empty means the gate passes.
    fn closure_reasons(
        entries: &[StoredEntry],
        claim_id: &str,
        evidence: &Value,
        attesting_grant_id: &str,
    ) -> Vec<String> {
        let mut reasons: Vec<String> = Vec::new();

        let original = match claim_ingested_entry(entries, claim_id) {
            Some(o) => o,
            None => {
                reasons.push(format!("unknown claim {claim_id}"));
                return reasons;
            }
        };
        let writer = original["actor"].as_str().unwrap_or("").to_string();

        // R3-V4: the grant that recorded the claim may not attest its
        // closure. Self-attestation is refused, not merely discouraged.
        // (Pre-grant legacy entries carry no recorded_by and are exempt
        // here; verify() applies the same exemption.)
        if let Some(recorded_by) = original["recorded_by"].as_str() {
            if !recorded_by.is_empty() && recorded_by == attesting_grant_id {
                reasons.push(format!(
                    "self-attestation refused: claim {claim_id} was recorded by grant {recorded_by}, which may not attest its own closure; open a fresh grant for the closure ceremony"
                ));
            }
        }

        // The claim must be in a closable state.
        let mut terminal: Option<(&str, u64)> = None;
        for e in events_for_claim(entries, claim_id) {
            let kind = e.entry["kind"].as_str().unwrap_or("");
            if kind == KIND_CLAIM_SUPERSEDED || kind == KIND_CLASS_CLOSURE_GRANTED {
                if terminal.map_or(true, |(_, t)| e.seq > t) {
                    terminal = Some((kind, e.seq));
                }
            }
        }
        if let Some((kind, _)) = terminal {
            if kind == KIND_CLAIM_SUPERSEDED {
                reasons.push(format!(
                    "claim {claim_id} is SUPERSEDED_BY_BYPASS; a defeated claim cannot be class-closed"
                ));
            } else {
                reasons.push(format!("claim {claim_id} is already CLASS_CLOSED"));
            }
            return reasons;
        }

        // 1. original_reproducer
        let rep = &evidence["original_reproducer"];
        let rep_agent = non_empty_str(rep, "agent");
        let rep_payload = non_empty_str(rep, "payload_hash");
        let rep_ref = non_empty_str(rep, "evidence_ref");
        if rep_agent.is_none() || rep_payload.is_none() || rep_ref.is_none() {
            reasons.push(
                "original_reproducer requires non-empty {evidence_ref, payload_hash, agent}"
                    .to_string(),
            );
        }
        let (rep_agent, rep_payload) = match (rep_agent, rep_payload) {
            (Some(a), Some(p)) => (a, p),
            _ => return reasons,
        };

        // 2. adversarial_variants: at least one, each distinct from reproducer.
        match evidence["adversarial_variants"].as_array() {
            Some(vars) if !vars.is_empty() => {
                for (i, v) in vars.iter().enumerate() {
                    let href = non_empty_str(v, "evidence_ref");
                    let hp = non_empty_str(v, "payload_hash");
                    match (href, hp) {
                        (Some(_), Some(p)) => {
                            if p == rep_payload {
                                reasons.push(format!(
                                    "adversarial_variants[{i}] payload_hash equals the reproducer payload: not an adversarial variant"
                                ));
                            }
                        }
                        _ => reasons.push(format!(
                            "adversarial_variants[{i}] requires non-empty {{evidence_ref, payload_hash}}"
                        )),
                    }
                }
            }
            _ => reasons.push(
                "adversarial_variants requires a non-empty array of payloads distinct from the reproducer"
                    .to_string(),
            ),
        }

        // 3. prior_bypass_corpus
        if non_empty_str(&evidence["prior_bypass_corpus"], "corpus_ref").is_none() {
            reasons.push("prior_bypass_corpus.corpus_ref required".to_string());
        }

        // 4. independent_review: independence + mode-specific obligations.
        let rev = &evidence["independent_review"];
        let rev_agent = non_empty_str(rev, "agent");
        let rev_payload = non_empty_str(rev, "payload_hash");
        if rev_agent.is_none() || rev_payload.is_none() {
            reasons.push(
                "independent_review requires non-empty {agent, payload_hash, mode}".to_string(),
            );
            return reasons;
        }
        let (rev_agent, rev_payload) = (rev_agent.unwrap(), rev_payload.unwrap());
        if rev_agent == rep_agent {
            reasons.push(format!(
                "independent review submitted by the same agent as the reproducer ({rev_agent}): replay rejected"
            ));
        }
        if rev_payload == rep_payload {
            reasons.push(
                "independent review payload is identical to the reproducer payload: replay rejected"
                    .to_string(),
            );
        }
        match rev["mode"].as_str() {
            Some("semantic") => {
                let s = &rev["independent_sampling"];
                if non_empty_str(s, "expected").is_none()
                    || non_empty_str(s, "observed").is_none()
                {
                    reasons.push(
                        "semantic review requires independent_review.independent_sampling {expected, observed}"
                            .to_string(),
                    );
                }
            }
            Some("provenance") => {
                match non_empty_str(rev, "external_verifier") {
                    Some(v) if v != writer && v != rev_agent => {}
                    Some(v) => reasons.push(format!(
                        "provenance review external_verifier ({v}) must be outside the writer's control (writer: {writer})"
                    )),
                    None => reasons.push(
                        "provenance review requires independent_review.external_verifier outside the writer's control"
                            .to_string(),
                    ),
                }
            }
            Some("structural") => {}
            _ => reasons.push(
                "independent_review.mode required: one of semantic | provenance | structural"
                    .to_string(),
            ),
        }

        reasons
    }

    fn op_request_class_closure(
        &self,
        ctx: &CallContext,
        input: &Value,
    ) -> Result<Value, OrganelleError> {
        let grant = self.resolve_grant(ctx, input)?;
        let claim_id = non_empty_str(input, "claim_id")
            .ok_or_else(|| OrganelleError::denied("claim_id required"))?;
        let entries = read_store(&grant.store_path)?;
        if claim_ingested_seq(&entries, &claim_id).is_none() {
            return Err(OrganelleError::not_found(format!("unknown claim {claim_id}")));
        }

        let reasons = Self::closure_reasons(&entries, &claim_id, &input["evidence"], &grant.grant_id);
        if !reasons.is_empty() {
            // Refusal is an error to the caller AND an audit event in the
            // store: it is not a claim, and the organelle certifies nothing.
            let refusal = json!({
                "kind": KIND_CLASS_CLOSURE_REFUSED,
                "claim_id": claim_id,
                "reasons": reasons,
                "recorded_by": grant.grant_id,
                "ts": utc_now_iso(),
                "actor": ctx.caller,
            });
            let stored = append_entry(&grant.store_path, refusal)?;
            return Err(OrganelleError::denied(format!(
                "class closure refused for {claim_id}: {} (refusal recorded at seq {})",
                reasons.join("; "),
                stored.seq
            )));
        }

        let grant_entry = json!({
            "kind": KIND_CLASS_CLOSURE_GRANTED,
            "claim_id": claim_id,
            "evidence": input["evidence"],
            "attested_by": grant.grant_id,
            "ts": utc_now_iso(),
            "actor": ctx.caller,
        });
        let stored = append_entry(&grant.store_path, grant_entry)?;
        Ok(json!({
            "ok": true,
            "claim_id": claim_id,
            "status": STATUS_CLASS_CLOSED,
            "seq": stored.seq,
            "entry_hash": stored.entry_hash,
        }))
    }
}

impl Organelle for ClaimReconciler {
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
        match op {
            "open-store" => self.op_open_store(ctx, host, &input),
            "close-store" => self.op_close_store(ctx, &input),
            "ingest-claim" => self.op_ingest_claim(ctx, &input),
            "ingest-defect" => self.op_ingest_defect(ctx, &input),
            "claim-status" => self.op_claim_status(&input),
            "request-class-closure" => self.op_request_class_closure(ctx, &input),
            "verify" => verify_store(
                non_empty_str(&input, "store_path")
                    .ok_or_else(|| OrganelleError::denied("store_path required"))?
                    .as_str(),
            ),
            // No delete op exists, by doctrine. Unknown ops are not found.
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }

    /// Grants are process-lifetime: a suspend/resume boundary invalidates
    /// every issued token. The checkpoint stays ephemeral and honest.
    fn suspend(&self) -> organelle_host::Checkpoint {
        self.grants.lock().unwrap().clear();
        organelle_host::Checkpoint {
            codon: self.manifest().codon,
            ts: utc_now_iso(),
            bytes: Vec::new(),
            ephemeral: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (logic-level; the adversarial suite lives in tests/adversarial.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn tmp_store(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "claim-reconciler-test-{tag}-{}.jsonl",
            std::process::id()
        ));
        let s = p.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&s);
        s
    }

    fn host_with_caps(caps: &[&str]) -> (Arc<Host>, CallContext) {
        let h = Host::new();
        h.register(organelle()).unwrap();
        // The organelle approves store paths through the host membrane:
        // tests allowlist the temp dir.
        h.set_write_roots(vec![std::env::temp_dir()]).unwrap();
        let ctx = CallContext::new(
            "unit-test",
            caps.iter().map(|c| c.to_string()).collect(),
        );
        (h, ctx)
    }

    /// Open a store through the grant flow; returns the issued grant token.
    fn open_store(h: &Arc<Host>, ctx: &CallContext, store: &str) -> String {
        h.call(
            ctx,
            "cr",
            "open-store",
            json!({"store_path": store}),
        )
        .unwrap()
        .output["grant_token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Open a store; returns (grant_token, grant_id).
    fn open_store_full(h: &Arc<Host>, ctx: &CallContext, store: &str) -> (String, String) {
        let out = h
            .call(ctx, "cr", "open-store", json!({"store_path": store}))
            .unwrap()
            .output;
        (
            out["grant_token"].as_str().unwrap().to_string(),
            out["grant_id"].as_str().unwrap().to_string(),
        )
    }

    fn claim_input(token: &str) -> Value {
        json!({
            "grant_token": token,
            "fix_evidence": ["evidence/ref-1"],
            "proof_script_path": "proofs/p1.py",
            "commit": "abc123",
        })
    }

    /// Write a real probe artifact under the grant root; returns (path, sha256).
    fn probe_artifact(tag: &str, bytes: &[u8]) -> (String, String) {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "claim-reconciler-probe-{tag}-{}.bin",
            std::process::id()
        ));
        std::fs::write(&p, bytes).unwrap();
        let s = p.to_string_lossy().into_owned();
        (s, sha256_hex(bytes))
    }

    fn good_evidence() -> Value {
        json!({
            "original_reproducer": {
                "evidence_ref": "probes/repro-1",
                "payload_hash": "aa11",
                "agent": "redteam-a",
            },
            "adversarial_variants": [
                {"evidence_ref": "probes/var-1", "payload_hash": "bb22", "agent": "redteam-a"},
            ],
            "prior_bypass_corpus": {"corpus_ref": "corpus/bypasses-v3", "samples": 41},
            "independent_review": {
                "agent": "reviewer-x",
                "payload_hash": "dd44",
                "mode": "structural",
            },
        })
    }

    #[test]
    fn manifest_contracts_have_no_delete_op() {
        let m = manifest();
        assert!(m.contract("open-store").is_some());
        assert!(m.contract("close-store").is_some());
        assert!(m.contract("ingest-claim").is_some());
        assert!(m.contract("ingest-defect").is_some());
        assert!(m.contract("claim-status").is_some());
        assert!(m.contract("request-class-closure").is_some());
        assert!(m.contract("verify").is_some());
        assert!(m.contract("delete").is_none());
        // Mutating ops bind grant_token, never a raw store_path.
        for op in ["open-store", "ingest-claim", "ingest-defect", "request-class-closure"] {
            let c = m.contract(op).unwrap();
            if op == "open-store" {
                assert!(c.input_schema["required"].as_array().unwrap().contains(&json!("store_path")));
            } else {
                assert!(
                    c.input_schema["required"].as_array().unwrap().contains(&json!("grant_token")),
                    "op {op} must require grant_token"
                );
            }
        }
        // All Write/ExternalEffect ops declare a capability (substrate rule).
        for c in &m.contracts {
            let (mc, need) = m.authority_for(&c.op);
            if matches!(mc, MutationClass::Write | MutationClass::ExternalEffect) {
                assert!(need.is_some(), "op {} lacks required_capability", c.op);
            }
        }
    }

    #[test]
    fn ingest_assigns_permanent_fc_ids() {
        let store = tmp_store("ids");
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let (token, grant_id) = open_store_full(&h, &ctx, &store);
        let r1 = h.call(&ctx, "cr", "ingest-claim", claim_input(&token)).unwrap();
        assert_eq!(r1.output["claim_id"], json!("FC-1"));
        let r2 = h.call(&ctx, "cr", "ingest-claim", claim_input(&token)).unwrap();
        assert_eq!(r2.output["claim_id"], json!("FC-2"));
        assert_eq!(r2.output["scope"], json!("INSTANCE_ONLY"));
        // Default scope is instance-only even when a scope field is omitted.
        let st = h
            .call(
                &ctx,
                "cr",
                "claim-status",
                json!({"store_path": store, "claim_id": "FC-1"}),
            )
            .unwrap();
        assert_eq!(st.output["status"], json!("INSTANCE_ONLY"));
        // Provenance: the claim records which grant recorded it.
        assert_eq!(st.output["original_claim"]["recorded_by"], json!(grant_id));
    }

    #[test]
    fn ingest_refuses_non_instance_scope_and_duplicates() {
        let store = tmp_store("scope");
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let token = open_store(&h, &ctx, &store);
        let mut bad = claim_input(&token);
        bad["scope"] = json!("CLASS_CLOSED");
        assert!(h.call(&ctx, "cr", "ingest-claim", bad).is_err());
        let mut dup = claim_input(&token);
        dup["claim_id"] = json!("FC-7");
        h.call(&ctx, "cr", "ingest-claim", dup.clone()).unwrap();
        assert!(h.call(&ctx, "cr", "ingest-claim", dup).is_err());
        let mut malformed = claim_input(&token);
        malformed["claim_id"] = json!("not-a-permanent-id");
        assert!(h.call(&ctx, "cr", "ingest-claim", malformed).is_err());
    }

    #[test]
    fn verify_clean_chain_and_empty_store() {
        let store = tmp_store("verify");
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let v0 = h
            .call(&ctx, "cr", "verify", json!({"store_path": store}))
            .unwrap();
        assert_eq!(v0.output["ok"], json!(true));
        assert_eq!(v0.output["entries"], json!(0));
        let token = open_store(&h, &ctx, &store);
        h.call(&ctx, "cr", "ingest-claim", claim_input(&token)).unwrap();
        let v1 = h
            .call(&ctx, "cr", "verify", json!({"store_path": store}))
            .unwrap();
        assert_eq!(v1.output["ok"], json!(true));
        assert_eq!(v1.output["entries"], json!(1));
        assert_eq!(v1.output["head_hash"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn store_path_traversal_refused_at_open() {
        let (h, ctx) = host_with_caps(&["claims.write", "claims.class_close"]);
        // `..` never survives the membrane's path approval.
        let bad = json!({"store_path": "/tmp/../etc/evil.jsonl"});
        assert!(h.call(&ctx, "cr", "open-store", bad).is_err());
    }

    #[test]
    fn open_store_rejects_outside_write_roots_and_default_deny() {
        // Outside the allowlisted root.
        let (h, ctx) = host_with_caps(&["claims.write"]);
        assert!(h
            .call(&ctx, "cr", "open-store", json!({"store_path": "/etc/cr-evil.jsonl"}))
            .is_err());
        // No roots configured at all: default deny.
        let h2 = Host::new();
        h2.register(organelle()).unwrap();
        let ctx2 = CallContext::new("unit-test", vec!["claims.write".to_string()]);
        let store = tmp_store("deny");
        assert!(h2
            .call(&ctx2, "cr", "open-store", json!({"store_path": store}))
            .is_err());
    }

    #[test]
    fn unknown_or_missing_grant_token_rejected() {
        let store = tmp_store("tok");
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let _token = open_store(&h, &ctx, &store);
        // Forged token: 256-bit-shaped but never issued.
        let mut forged = claim_input(&"ab".repeat(32));
        assert!(h.call(&ctx, "cr", "ingest-claim", forged.clone()).is_err());
        // Missing token entirely.
        forged.as_object_mut().unwrap().remove("grant_token");
        forged["store_path"] = json!(store);
        assert!(h.call(&ctx, "cr", "ingest-claim", forged).is_err());
    }

    #[test]
    fn grant_bound_to_issuing_caller() {
        let store = tmp_store("caller");
        let (h, ctx_a) = host_with_caps(&["claims.write"]);
        let token = open_store(&h, &ctx_a, &store);
        // Same host, same capabilities, different caller: the token is not
        // a delegation mechanism.
        let ctx_b = CallContext::new("someone-else", vec!["claims.write".to_string()]);
        assert!(h.call(&ctx_b, "cr", "ingest-claim", claim_input(&token)).is_err());
        assert!(h
            .call(&ctx_b, "cr", "close-store", json!({"grant_token": token}))
            .is_err());
        // The issuing caller works fine.
        assert!(h.call(&ctx_a, "cr", "ingest-claim", claim_input(&token)).is_ok());
    }

    #[test]
    fn supersede_requires_real_hash_matching_probe_artifact() {
        let store = tmp_store("probe");
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let token = open_store(&h, &ctx, &store);
        h.call(&ctx, "cr", "ingest-claim", claim_input(&token)).unwrap();

        // Invented hash: artifact exists but does not match payload_hash.
        let (apath, _real) = probe_artifact("mismatch", b"real-bytes");
        let invented = h.call(
            &ctx,
            "cr",
            "ingest-defect",
            json!({
                "grant_token": token,
                "defect_id": "D-invented",
                "defeats_claim_id": "FC-1",
                "defeating_probe": {"evidence_ref": "probes/x", "payload_hash": "forged-hash", "artifact_path": apath},
                "reproduces_fixed_behavior": true,
            }),
        );
        assert!(invented.is_err());

        // Missing artifact file.
        let missing = h.call(
            &ctx,
            "cr",
            "ingest-defect",
            json!({
                "grant_token": token,
                "defect_id": "D-missing",
                "defeats_claim_id": "FC-1",
                "defeating_probe": {"evidence_ref": "probes/x", "payload_hash": "aa", "artifact_path": "/tmp/claim-reconciler-no-such-probe.bin"},
                "reproduces_fixed_behavior": true,
            }),
        );
        assert!(missing.is_err());

        // Escape: a real file outside the grant-bound root.
        let outside = h.call(
            &ctx,
            "cr",
            "ingest-defect",
            json!({
                "grant_token": token,
                "defect_id": "D-escape",
                "defeats_claim_id": "FC-1",
                "defeating_probe": {"evidence_ref": "probes/x", "payload_hash": "aa", "artifact_path": "/etc/hosts"},
                "reproduces_fixed_behavior": true,
            }),
        );
        assert!(outside.is_err());

        // Real artifact, matching hash: supersede lands.
        let (apath2, ph2) = probe_artifact("real", b"defeating-probe-bytes");
        let ok = h
            .call(
                &ctx,
                "cr",
                "ingest-defect",
                json!({
                    "grant_token": token,
                    "defect_id": "D-real",
                    "defeats_claim_id": "FC-1",
                    "defeating_probe": {"evidence_ref": "probes/real", "payload_hash": ph2, "artifact_path": apath2},
                    "reproduces_fixed_behavior": true,
                }),
            )
            .unwrap();
        assert_eq!(ok.output["superseded"], json!("FC-1"));
        let v = h
            .call(&ctx, "cr", "verify", json!({"store_path": store}))
            .unwrap();
        assert_eq!(v.output["ok"], json!(true));
    }

    #[test]
    fn verify_fails_when_probe_artifact_removed_or_tampered() {
        for (tag, mutate) in [
            ("gone", "remove"),
            ("tampered", "rewrite"),
        ] {
            let store = tmp_store(&format!("pv-{tag}"));
            let (h, ctx) = host_with_caps(&["claims.write"]);
            let token = open_store(&h, &ctx, &store);
            h.call(&ctx, "cr", "ingest-claim", claim_input(&token)).unwrap();
            let (apath, ph) = probe_artifact(&format!("pv-{tag}"), b"probe-evidence");
            h.call(
                &ctx,
                "cr",
                "ingest-defect",
                json!({
                    "grant_token": token,
                    "defect_id": "D-1",
                    "defeats_claim_id": "FC-1",
                    "defeating_probe": {"evidence_ref": "probes/p", "payload_hash": ph, "artifact_path": apath},
                    "reproduces_fixed_behavior": true,
                }),
            )
            .unwrap();
            match mutate {
                "remove" => std::fs::remove_file(&apath).unwrap(),
                _ => std::fs::write(&apath, b"something-else-entirely").unwrap(),
            }
            let v = h
                .call(&ctx, "cr", "verify", json!({"store_path": store}))
                .unwrap();
            assert_eq!(v.output["ok"], json!(false), "tag={tag}");
            assert!(
                v.output["reason"].as_str().unwrap().contains("probe artifact"),
                "tag={tag} reason: {}",
                v.output["reason"]
            );
        }
    }

    #[test]
    fn self_attestation_refused_then_granted_with_fresh_grant() {
        let store = tmp_store("selfatt");
        let (h, ctx) = host_with_caps(&["claims.write", "claims.class_close"]);
        let token_a = open_store(&h, &ctx, &store);
        h.call(&ctx, "cr", "ingest-claim", claim_input(&token_a)).unwrap();

        // Same grant records and attests: refused.
        let err = h
            .call(
                &ctx,
                "cr",
                "request-class-closure",
                json!({"grant_token": token_a, "claim_id": "FC-1", "evidence": good_evidence()}),
            )
            .unwrap_err();
        assert!(err.reason.contains("self-attestation"), "reason: {}", err.reason);

        // A fresh grant attests: the closure ceremony is a distinct
        // authorization event.
        let token_b = open_store(&h, &ctx, &store);
        assert_ne!(token_a, token_b);
        let out = h
            .call(
                &ctx,
                "cr",
                "request-class-closure",
                json!({"grant_token": token_b, "claim_id": "FC-1", "evidence": good_evidence()}),
            )
            .unwrap();
        assert_eq!(out.output["status"], json!("CLASS_CLOSED"));
        let v = h
            .call(&ctx, "cr", "verify", json!({"store_path": store}))
            .unwrap();
        assert_eq!(v.output["ok"], json!(true));
    }

    /// Hand-seal a book the API can no longer produce: a class closure
    /// attested by the same grant that recorded the claim. verify must fail.
    fn seal_lines(entries: &[Value]) -> String {
        let mut prev = GENESIS_HASH.to_string();
        let mut out = String::new();
        for (seq, entry) in entries.iter().enumerate() {
            let seq = seq as u64;
            let hash = entry_hash(&prev, seq, entry);
            out.push_str(&canonical_json(&json!({
                "seq": seq, "prev_hash": prev, "entry": entry, "entry_hash": hash,
            })));
            out.push('\n');
            prev = hash;
        }
        out
    }

    #[test]
    fn verify_rejects_hand_forged_self_attested_closure() {
        let store = tmp_store("forgedclose");
        let claim = json!({
            "kind": KIND_CLAIM_INGESTED, "claim_id": "FC-1", "scope": STATUS_INSTANCE_ONLY,
            "fix_evidence": ["e/1"], "proof_script_path": "p.py", "commit": "c",
            "recorded_by": "g-attacker01", "ts": utc_now_iso(), "actor": "mallory",
        });
        // Self-attested: attested_by == recorded_by.
        let bad_close = json!({
            "kind": KIND_CLASS_CLOSURE_GRANTED, "claim_id": "FC-1",
            "evidence": {}, "attested_by": "g-attacker01",
            "ts": utc_now_iso(), "actor": "mallory",
        });
        std::fs::write(&store, seal_lines(&[claim.clone(), bad_close])).unwrap();
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let v = h
            .call(&ctx, "cr", "verify", json!({"store_path": store}))
            .unwrap();
        assert_eq!(v.output["ok"], json!(false));
        assert!(
            v.output["reason"].as_str().unwrap().contains("self-attested"),
            "reason: {}",
            v.output["reason"]
        );

        // Control: a distinct attesting grant verifies clean.
        let good_close = json!({
            "kind": KIND_CLASS_CLOSURE_GRANTED, "claim_id": "FC-1",
            "evidence": {}, "attested_by": "g-ceremony99",
            "ts": utc_now_iso(), "actor": "mallory",
        });
        std::fs::write(&store, seal_lines(&[claim, good_close])).unwrap();
        let v2 = h
            .call(&ctx, "cr", "verify", json!({"store_path": store}))
            .unwrap();
        assert_eq!(v2.output["ok"], json!(true));
    }

    #[test]
    fn close_store_revokes_token() {
        let store = tmp_store("revoke");
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let token = open_store(&h, &ctx, &store);
        let r = h
            .call(&ctx, "cr", "close-store", json!({"grant_token": token}))
            .unwrap();
        assert_eq!(r.output["ok"], json!(true));
        assert!(h.call(&ctx, "cr", "ingest-claim", claim_input(&token)).is_err());
        // Double close is also rejected (unknown token now).
        assert!(h
            .call(&ctx, "cr", "close-store", json!({"grant_token": token}))
            .is_err());
    }

    #[test]
    fn open_store_reports_binding_and_expiry() {
        let store = tmp_store("bind");
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let out = h
            .call(
                &ctx,
                "cr",
                "open-store",
                json!({"store_path": store, "ttl_seconds": 120}),
            )
            .unwrap()
            .output;
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["grant_token"].as_str().unwrap().len(), 64);
        assert!(out["grant_id"].as_str().unwrap().starts_with("g-"));
        assert_eq!(out["issued_to"], json!("unit-test"));
        let exp = out["expires_at"].as_u64().unwrap();
        let now = now_unix();
        assert!(exp >= now + 100 && exp <= now + 140, "expires_at={exp} now={now}");
        // Tokens are unguessable and unique per open.
        let t2 = open_store(&h, &ctx, &store);
        assert_ne!(out["grant_token"].as_str().unwrap(), t2);
    }
}
