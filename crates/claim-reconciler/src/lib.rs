//! Claim reconciler organelle (codon `cr`).
//!
//! Deterministic claim/defeat reconciliation per rigor doctrine (R-1: one
//! book for claims and defeats; R-9: frozen ledger schemas with
//! SUPERSEDED-BY-BYPASS). Behavior:
//!
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
//! - `verify`: recomputes the hash chain over the event store.
//!
//! The event store is an append-only JSONL file with a sha256 chain over
//! `prev_hash + seq + canonical(entry)`. The organelle keeps no in-memory
//! state, so the default (ephemeral) suspend checkpoint is honest.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    canonical_json, sha256_hex, utc_now_iso, Authority, Contract, MutationClass,
    OrganelleManifest, ReceiptPolicy, Transport, Valence, MANIFEST_SCHEMA_VERSION,
    RECEIPT_ALGORITHM,
};
use serde_json::{json, Value};
use std::sync::Arc;

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
        version: "1.0.0".to_string(),
        description: "claim-defeat reconciliation: permanent claim IDs, instance-only default scope, gated class closure, bypass-linked supersede preserving the original receipt, append-only hash-chained event store".to_string(),
        contracts: vec![
            Contract {
                op: "ingest-claim".to_string(),
                description: "record a fix claim; permanent ID FC-<n> assigned when absent; scope locked to INSTANCE_ONLY".to_string(),
                input_schema: obj_schema(&[("store_path","string",true),("claim_id","string",false),("fix_evidence","array",true),("proof_script_path","string",true),("commit","string",true),("description","string",false),("scope","string",false)]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("claims.write".to_string()),
            },
            Contract {
                op: "ingest-defect".to_string(),
                description: "record a defect; when it reproduces a claimed-fixed behavior, append a SUPERSEDED_BY_BYPASS linkage preserving the original receipt".to_string(),
                input_schema: obj_schema(&[("store_path","string",true),("defect_id","string",true),("defeats_claim_id","string",false),("defeating_probe","object",false),("reproduces_fixed_behavior","boolean",false),("links","array",false)]),
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
                description: "request class closure for a claim; granted only with all four evidence pieces and independent review that is not a reproducer replay; refused otherwise".to_string(),
                input_schema: obj_schema(&[("store_path","string",true),("claim_id","string",true),("evidence","object",false)]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("claims.class_close".to_string()),
            },
            Contract {
                op: "verify".to_string(),
                description: "recompute the event-store hash chain; reports ok or the first breaking seq".to_string(),
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

fn check_store_path(path: &str) -> Result<(), OrganelleError> {
    if path.is_empty() {
        return Err(OrganelleError::denied("store_path must not be empty"));
    }
    if path.contains("..") {
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

fn read_store(path: &str) -> Result<Vec<StoredEntry>, OrganelleError> {
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
fn append_entry(path: &str, entry: Value) -> Result<StoredEntry, OrganelleError> {
    check_store_path(path)?;
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
    let entries = read_store(path)?;
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
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(ClaimReconciler {
        manifest: manifest(),
    })
}

impl ClaimReconciler {
    fn op_ingest_claim(&self, ctx: &CallContext, input: &Value) -> Result<Value, OrganelleError> {
        let path = non_empty_str(input, "store_path")
            .ok_or_else(|| OrganelleError::denied("store_path required"))?;
        let entries = read_store(&path)?;

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
            "ts": utc_now_iso(),
            "actor": ctx.caller,
        });
        let stored = append_entry(&path, entry)?;
        Ok(json!({
            "ok": true,
            "claim_id": claim_id,
            "scope": STATUS_INSTANCE_ONLY,
            "seq": stored.seq,
            "entry_hash": stored.entry_hash,
        }))
    }

    fn op_ingest_defect(&self, ctx: &CallContext, input: &Value) -> Result<Value, OrganelleError> {
        let path = non_empty_str(input, "store_path")
            .ok_or_else(|| OrganelleError::denied("store_path required"))?;
        let defect_id = non_empty_str(input, "defect_id")
            .ok_or_else(|| OrganelleError::denied("defect_id required"))?;
        let entries = read_store(&path)?;

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
                    "supersede requires defeating_probe evidence {evidence_ref, payload_hash}",
                ));
            }
            let evidence_ref = non_empty_str(probe, "evidence_ref").ok_or_else(|| {
                OrganelleError::denied("supersede requires defeating_probe.evidence_ref")
            })?;
            let payload_hash = non_empty_str(probe, "payload_hash").ok_or_else(|| {
                OrganelleError::denied("supersede requires defeating_probe.payload_hash")
            })?;
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
                    "output": probe["output"].as_str().unwrap_or("")},
                "reproduces_fixed_behavior": true,
                "links": input["links"].clone(),
                "ts": utc_now_iso(),
                "actor": ctx.caller,
            });
            let d = append_entry(&path, defect_entry)?;
            // The original claim receipt is preserved; a NEW event carries
            // the supersede linkage. Nothing is overwritten.
            let sup_entry = json!({
                "kind": KIND_CLAIM_SUPERSEDED,
                "claim_id": claim_id,
                "supersedes_seq": orig_seq,
                "defect_id": defect_id,
                "defect_seq": d.seq,
                "defeating_probe": {"evidence_ref": evidence_ref, "payload_hash": payload_hash},
                "ts": utc_now_iso(),
                "actor": ctx.caller,
            });
            let s = append_entry(&path, sup_entry)?;
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
            "ts": utc_now_iso(),
            "actor": ctx.caller,
        });
        let stored = append_entry(&path, entry)?;
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
        let entries = read_store(&path)?;
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
        let path = non_empty_str(input, "store_path")
            .ok_or_else(|| OrganelleError::denied("store_path required"))?;
        let claim_id = non_empty_str(input, "claim_id")
            .ok_or_else(|| OrganelleError::denied("claim_id required"))?;
        let entries = read_store(&path)?;
        if claim_ingested_seq(&entries, &claim_id).is_none() {
            return Err(OrganelleError::not_found(format!("unknown claim {claim_id}")));
        }

        let reasons = Self::closure_reasons(&entries, &claim_id, &input["evidence"]);
        if !reasons.is_empty() {
            // Refusal is an error to the caller AND an audit event in the
            // store: it is not a claim, and the organelle certifies nothing.
            let refusal = json!({
                "kind": KIND_CLASS_CLOSURE_REFUSED,
                "claim_id": claim_id,
                "reasons": reasons,
                "ts": utc_now_iso(),
                "actor": ctx.caller,
            });
            let stored = append_entry(&path, refusal)?;
            return Err(OrganelleError::denied(format!(
                "class closure refused for {claim_id}: {} (refusal recorded at seq {})",
                reasons.join("; "),
                stored.seq
            )));
        }

        let grant = json!({
            "kind": KIND_CLASS_CLOSURE_GRANTED,
            "claim_id": claim_id,
            "evidence": input["evidence"],
            "ts": utc_now_iso(),
            "actor": ctx.caller,
        });
        let stored = append_entry(&path, grant)?;
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
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
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
        let ctx = CallContext::new(
            "unit-test",
            caps.iter().map(|c| c.to_string()).collect(),
        );
        (h, ctx)
    }

    fn claim_input(store: &str) -> Value {
        json!({
            "store_path": store,
            "fix_evidence": ["evidence/ref-1"],
            "proof_script_path": "proofs/p1.py",
            "commit": "abc123",
        })
    }

    #[test]
    fn manifest_contracts_have_no_delete_op() {
        let m = manifest();
        assert!(m.contract("ingest-claim").is_some());
        assert!(m.contract("ingest-defect").is_some());
        assert!(m.contract("claim-status").is_some());
        assert!(m.contract("request-class-closure").is_some());
        assert!(m.contract("verify").is_some());
        assert!(m.contract("delete").is_none());
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
        let r1 = h.call(&ctx, "cr", "ingest-claim", claim_input(&store)).unwrap();
        assert_eq!(r1.output["claim_id"], json!("FC-1"));
        let r2 = h.call(&ctx, "cr", "ingest-claim", claim_input(&store)).unwrap();
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
    }

    #[test]
    fn ingest_refuses_non_instance_scope_and_duplicates() {
        let store = tmp_store("scope");
        let (h, ctx) = host_with_caps(&["claims.write"]);
        let mut bad = claim_input(&store);
        bad["scope"] = json!("CLASS_CLOSED");
        assert!(h.call(&ctx, "cr", "ingest-claim", bad).is_err());
        let mut dup = claim_input(&store);
        dup["claim_id"] = json!("FC-7");
        h.call(&ctx, "cr", "ingest-claim", dup.clone()).unwrap();
        assert!(h.call(&ctx, "cr", "ingest-claim", dup).is_err());
        let mut malformed = claim_input(&store);
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
        h.call(&ctx, "cr", "ingest-claim", claim_input(&store)).unwrap();
        let v1 = h
            .call(&ctx, "cr", "verify", json!({"store_path": store}))
            .unwrap();
        assert_eq!(v1.output["ok"], json!(true));
        assert_eq!(v1.output["entries"], json!(1));
        assert_eq!(v1.output["head_hash"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn store_path_traversal_refused() {
        let (h, ctx) = host_with_caps(&["claims.write", "claims.class_close"]);
        let bad = json!({"store_path": "/tmp/../etc/evil.jsonl"});
        assert!(h.call(&ctx, "cr", "verify", bad.clone()).is_err());
        let mut c = claim_input("/tmp/../evil.jsonl");
        c["store_path"] = json!("/tmp/../evil.jsonl");
        assert!(h.call(&ctx, "cr", "ingest-claim", c).is_err());
    }
}
