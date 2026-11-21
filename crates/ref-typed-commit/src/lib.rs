//! org-026 (GO-50 Phase 1, family F5) — reference TYPED organelle:
//! attested commit (codon `tc`).
//!
//! Commits an arbitrary JSON value under a caller-chosen key into an
//! append-only, content-addressed, parent-linked in-memory log, and
//! attests the commit with the host invocation receipt. This is the
//! second typed organelle on the fabric (after `th`); its existence
//! converts F4 §10's CLAIMED second-organelle projection generality
//! into a proven one.
//!
//! # Attested-commit design (no spec existed on record — this is it)
//!
//! * **What it commits:** one JSON value under one string key. A commit
//!   record is `{key, value_hash, parent, seq}` where `value_hash` is
//!   the SHA-256 of the canonical JSON of the value and `parent` is the
//!   previous head commit id (or `""` for the genesis commit; an
//!   explicit parent may be supplied and must already exist).
//!   `commit_id` is the SHA-256 of the canonical JSON of
//!   `{key, value_hash, parent}` — content identity, not positional
//!   identity: `seq` is deliberately NOT hashed, so committing the
//!   same (key, value, parent) twice is idempotent (same id, same
//!   record, git-object semantics).
//! * **What attestation it produces:** twofold. (1) The host invocation
//!   receipt for the `commit` call — content-addressed, hash-chained,
//!   durable (the host's fsync'd receipt log), carrying the typed
//!   outcome (truth + provenance as separate fields); the dispatcher
//!   returns its receipt id and anyone can re-verify it via
//!   `Host::receipt_by_id` + `verify_chain`. (2) The commit record
//!   itself is content-addressed and parent-linked, so `verify`
//!   recomputes the id from the stored record and checks the parent
//!   linkage — a tampered record fails verification. Truth is Proven
//!   on that basis; provenance is input-bound (`computed_locally` for
//!   commit/verify, `retrieved` for get).
//! * **How it composes with the host receipt path:** it uses the
//!   standard F3 path — the erased adapter records truth + provenance
//!   via `record_typed_outcome`, the host attaches `typed_outcome` to
//!   the receipt, the dispatcher reads it back. No second receipt, no
//!   second envelope. The attestation is a HOST receipt, not a
//!   `lucidota-receipt/1` envelope (EB-1.2 / GAP F3-G2 still open —
//!   stated, not fudged).
//! * **Commit target:** the host receipt log (durable attestation) +
//!   the organelle's own in-memory store (the committed bytes). No
//!   filesystem writes anywhere; `fs_write` stays excluded. The
//!   in-memory store is the same durability posture as `ref-kv-store`
//!   (values are lost on restart; the receipt log durably attests
//!   input/output hashes, not values) — recorded as GAP F5-G3. A
//!   nested membrane call into `kv.put` was considered and rejected:
//!   it would require the caller to hold `kv.write` in the live grant
//!   domain (grant-domain confinement) and would couple this
//!   organelle's availability to `kv`'s registration, for no gain —
//!   the host receipt log is already the safe store the brief names
//!   first.
//!
//! GO declarations (all in the GO-50 lock): TOOL (it is a tool),
//! PROCESS (committing is a process), EVIDENCE (a commit is evidence
//! of content), ANCHOR (a commit anchors content in the log — seat
//! 29's job description). DO/CO: empty — no DO-25/CO-25 locks exist,
//! so no bindings are declared (see BLOCKERs F3-B1/F3-B2).
//!
//! `commit` is Write and requires the `tc.commit` capability
//! (per-contract authority override, the `kv-store` pattern); `get`
//! and `verify` are ReadOnly. The organelle-level default stays
//! ReadOnly.

use organelle_host::HostRef;
use organelle_manifest::{
    hash_value, utc_now_iso, Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy,
    Transport, Valence, MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use organelle_typed::{
    ClaimTruth, EnvironmentCapsule, OntologyDeclarations, OrganelleManifestV1, PayloadProvenance,
    ProvenanceSource, TypedContract, TypedError, TypedOrganelle, TypedOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

pub const CODON: &str = "tc";
pub const VERSION: &str = "1.0.0";
pub const COMMIT_CAPABILITY: &str = "tc.commit";

/// SHA-256 of the canonical JSON of a committed value.
pub fn value_hash_for(value: &Value) -> String {
    hash_value(value)
}

/// The commit id for a record: SHA-256 of the canonical JSON of
/// `{key, value_hash, parent}`. Pure function — the equivalence
/// harness uses it as the test oracle for `Exact` commit scenarios.
/// `seq` is deliberately excluded (see the module docs).
pub fn commit_id_for(key: &str, value_hash: &str, parent: &str) -> String {
    hash_value(&serde_json::json!({
        "key": key,
        "parent": parent,
        "value_hash": value_hash,
    }))
}

/// Typed input. One input type per organelle (trait shape): per-op
/// fields are optional here and required per-op in `handle_typed`
/// (`commit` needs `key` + `value`, `parent` optional; `get`/`verify`
/// need `commit_id`). The host's input-schema validation already
/// enforces the per-op required fields before typed decode runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<String>,
}

/// Typed output: one variant per op, untagged so each serializes as a
/// plain object matching its typed contract's `output_schema`.
/// Variant order matters for untagged deserialization: `Verify` before
/// `Get`, so a verify output (which also carries `found` +
/// `commit_id`) does not deserialize as a `Get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CommitOutput {
    Commit {
        commit_id: String,
        key: String,
        value_hash: String,
        parent: String,
        seq: u64,
    },
    Verify {
        found: bool,
        commit_id: String,
        hash_matches: bool,
        parent_known: bool,
    },
    Get {
        found: bool,
        commit_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
    },
}

/// One stored commit record. `seq` is positional metadata (insertion
/// order, 1-based) and is NOT part of the hashed identity.
#[derive(Debug, Clone)]
struct CommitRecord {
    key: String,
    value: Value,
    value_hash: String,
    parent: String,
    seq: u64,
}

#[derive(Debug, Default)]
struct Store {
    by_id: HashMap<String, CommitRecord>,
    head: String,
    next_seq: u64,
}

impl Store {
    fn new() -> Self {
        Store {
            by_id: HashMap::new(),
            head: String::new(),
            next_seq: 1,
        }
    }
}

fn base_manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "typed-commit".to_string(),
        codon: CODON.to_string(),
        version: VERSION.to_string(),
        description: "reference typed attested-commit organelle (commit/get/verify, typed fabric)"
            .to_string(),
        contracts: vec![
            Contract {
                op: "commit".to_string(),
                description:
                    "commit a JSON value under a key; returns its content-addressed commit id"
                        .to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["key", "value"],
                    "properties": {
                        "key": {"type": "string"},
                        "parent": {"type": "string"}
                    }
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some(COMMIT_CAPABILITY.to_string()),
            },
            Contract {
                op: "get".to_string(),
                description: "retrieve a commit record by commit id".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["commit_id"],
                    "properties": {"commit_id": {"type": "string"}}
                }),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "verify".to_string(),
                description: "recompute a commit's content hash and check its parent linkage"
                    .to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["commit_id"],
                    "properties": {"commit_id": {"type": "string"}}
                }),
                mutation_class: None,
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
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

/// The V1 manifest, built in code. A checked-in JSON copy lives at
/// `manifests/typed-commit.v1.json`; the drift test below asserts the
/// two agree exactly.
pub fn manifest_v1() -> OrganelleManifestV1 {
    OrganelleManifestV1::from_base(
        base_manifest(),
        OntologyDeclarations {
            go: vec![
                "TOOL".to_string(),
                "PROCESS".to_string(),
                "EVIDENCE".to_string(),
                "ANCHOR".to_string(),
            ],
            domain: vec![],
            client: vec![],
        },
        vec![
            TypedContract {
                op: "commit".to_string(),
                input_type: "CommitInput".to_string(),
                output_type: "CommitOutput::Commit".to_string(),
                output_schema: serde_json::json!({
                    "type": "object",
                    "required": ["commit_id", "key", "value_hash", "parent", "seq"],
                    "properties": {
                        "commit_id": {"type": "string"},
                        "key": {"type": "string"},
                        "value_hash": {"type": "string"},
                        "parent": {"type": "string"},
                        "seq": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            TypedContract {
                op: "get".to_string(),
                input_type: "CommitInput".to_string(),
                output_type: "CommitOutput::Get".to_string(),
                output_schema: serde_json::json!({
                    "type": "object",
                    "required": ["found", "commit_id"],
                    "properties": {
                        "found": {"type": "boolean"},
                        "commit_id": {"type": "string"},
                        "key": {"type": "string"}
                    }
                }),
            },
            TypedContract {
                op: "verify".to_string(),
                input_type: "CommitInput".to_string(),
                output_type: "CommitOutput::Verify".to_string(),
                output_schema: serde_json::json!({
                    "type": "object",
                    "required": ["found", "commit_id", "hash_matches", "parent_known"],
                    "properties": {
                        "found": {"type": "boolean"},
                        "commit_id": {"type": "string"},
                        "hash_matches": {"type": "boolean"},
                        "parent_known": {"type": "boolean"}
                    }
                }),
            },
        ],
    )
}

pub struct TypedCommit {
    manifest: OrganelleManifestV1,
    store: Mutex<Store>,
}

impl TypedCommit {
    pub fn new() -> Self {
        TypedCommit {
            manifest: manifest_v1(),
            store: Mutex::new(Store::new()),
        }
    }
}

impl Default for TypedCommit {
    fn default() -> Self {
        Self::new()
    }
}

fn input_value(input: &CommitInput) -> Result<Value, TypedError> {
    serde_json::to_value(input)
        .map_err(|e| TypedError::internal(format!("cannot serialize typed input: {e}")))
}

impl TypedOrganelle for TypedCommit {
    type Input = CommitInput;
    type Output = CommitOutput;

    fn manifest_v1(&self) -> OrganelleManifestV1 {
        self.manifest.clone()
    }

    fn handle_typed(
        &self,
        _capsule: &EnvironmentCapsule,
        _host: &dyn HostRef,
        op: &str,
        input: CommitInput,
    ) -> Result<TypedOutcome<CommitOutput>, TypedError> {
        // Truth: every claim this organelle makes is grounded in a
        // recomputable SHA-256 over canonical JSON — the commit id IS
        // the hash of the record, and the host receipt chain attests
        // the invocation. Provenance: the output bytes are computed
        // locally from this invocation's input (commit/verify) or
        // retrieved from the store the input names (get). Separate
        // fields, separate facts.
        let input_json = input_value(&input)?;
        let provenance_computed =
            PayloadProvenance::computed_locally(&input_json, format!("{CODON}@{VERSION}"));
        let provenance_retrieved = PayloadProvenance {
            source: ProvenanceSource::Retrieved,
            input_hash: hash_value(&input_json),
            produced_by: format!("{CODON}@{VERSION}"),
            produced_at: utc_now_iso(),
        };
        match op {
            "commit" => {
                let key = input
                    .key
                    .ok_or_else(|| TypedError::validation("commit requires key"))?;
                let value = input
                    .value
                    .ok_or_else(|| TypedError::validation("commit requires value"))?;
                let value_hash = value_hash_for(&value);
                let mut store = self.store.lock().unwrap();
                let parent = match input.parent {
                    Some(p) => {
                        if !p.is_empty() && !store.by_id.contains_key(&p) {
                            return Err(TypedError::validation(format!(
                                "unknown parent commit {p}"
                            )));
                        }
                        p
                    }
                    None => store.head.clone(),
                };
                let commit_id = commit_id_for(&key, &value_hash, &parent);
                // Idempotent by content: the same (key, value, parent)
                // is the same commit — return the existing record, do
                // not mint a second seq.
                if let Some(existing) = store.by_id.get(&commit_id) {
                    let record = existing.clone();
                    return Ok(TypedOutcome {
                        output: CommitOutput::Commit {
                            commit_id,
                            key: record.key,
                            value_hash: record.value_hash,
                            parent: record.parent,
                            seq: record.seq,
                        },
                        truth: ClaimTruth::proven(
                            "commit id is the SHA-256 of the canonical commit record; the host receipt chain attests this invocation",
                        ),
                        provenance: provenance_computed,
                    });
                }
                let seq = store.next_seq;
                store.next_seq += 1;
                store.head = commit_id.clone();
                store.by_id.insert(
                    commit_id.clone(),
                    CommitRecord {
                        key: key.clone(),
                        value,
                        value_hash: value_hash.clone(),
                        parent: parent.clone(),
                        seq,
                    },
                );
                Ok(TypedOutcome {
                    output: CommitOutput::Commit {
                        commit_id,
                        key,
                        value_hash,
                        parent,
                        seq,
                    },
                    truth: ClaimTruth::proven(
                        "commit id is the SHA-256 of the canonical commit record; the host receipt chain attests this invocation",
                    ),
                    provenance: provenance_computed,
                })
            }
            "get" => {
                let commit_id = input
                    .commit_id
                    .ok_or_else(|| TypedError::validation("get requires commit_id"))?;
                let store = self.store.lock().unwrap();
                match store.by_id.get(&commit_id) {
                    Some(record) => Ok(TypedOutcome {
                        output: CommitOutput::Get {
                            found: true,
                            commit_id,
                            key: Some(record.key.clone()),
                            value: Some(record.value.clone()),
                        },
                        truth: ClaimTruth::proven(
                            "retrieved record is content-addressed; the commit id is the hash of its canonical record",
                        ),
                        provenance: provenance_retrieved,
                    }),
                    None => Ok(TypedOutcome {
                        output: CommitOutput::Get {
                            found: false,
                            commit_id,
                            key: None,
                            value: None,
                        },
                        truth: ClaimTruth::proven(
                            "no record exists under this commit id in this store",
                        ),
                        provenance: provenance_retrieved,
                    }),
                }
            }
            "verify" => {
                let commit_id = input
                    .commit_id
                    .ok_or_else(|| TypedError::validation("verify requires commit_id"))?;
                let store = self.store.lock().unwrap();
                match store.by_id.get(&commit_id) {
                    Some(record) => {
                        // Recompute the id from the stored record: a
                        // tampered record fails this check.
                        let recomputed =
                            commit_id_for(&record.key, &record.value_hash, &record.parent);
                        let hash_matches = recomputed == commit_id;
                        let parent_known =
                            record.parent.is_empty() || store.by_id.contains_key(&record.parent);
                        Ok(TypedOutcome {
                            output: CommitOutput::Verify {
                                found: true,
                                commit_id,
                                hash_matches,
                                parent_known,
                            },
                            truth: ClaimTruth::proven(
                                "verification recomputes the content hash from the stored record and checks parent linkage",
                            ),
                            provenance: provenance_computed,
                        })
                    }
                    None => Ok(TypedOutcome {
                        output: CommitOutput::Verify {
                            found: false,
                            commit_id,
                            hash_matches: false,
                            parent_known: false,
                        },
                        truth: ClaimTruth::proven(
                            "no record exists under this commit id in this store",
                        ),
                        provenance: provenance_computed,
                    }),
                }
            }
            _ => Err(TypedError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use organelle_typed::{
        validate_manifest_v1, InvocationEnvelope, LockRegistry, TruthStatus, TypedDispatcher,
    };

    fn dispatcher() -> TypedDispatcher {
        let host = Host::new();
        let d = TypedDispatcher::new(host, LockRegistry::with_go50());
        d.register_typed(TypedCommit::new())
            .expect("typed-commit must register");
        d
    }

    fn commit_envelope(key: &str, value: Value) -> InvocationEnvelope {
        let mut env = InvocationEnvelope::native(
            "test",
            "tc",
            "commit",
            serde_json::json!({"key": key, "value": value}),
        );
        env.capabilities = vec![COMMIT_CAPABILITY.to_string()];
        env
    }

    #[test]
    fn manifest_v1_validates_against_locks() {
        let locks = LockRegistry::with_go50();
        assert!(validate_manifest_v1(&manifest_v1(), &locks).is_ok());
    }

    #[test]
    fn checked_in_manifest_matches_code() {
        // Drift guard: manifests/typed-commit.v1.json must agree exactly
        // with the code-built manifest (canonical JSON comparison).
        let text = include_str!("../manifests/typed-commit.v1.json");
        let from_file: Value = serde_json::from_str(text).expect("checked-in JSON parses");
        let from_code = serde_json::to_value(&manifest_v1()).unwrap();
        assert_eq!(
            organelle_manifest::canonical_json(&from_file),
            organelle_manifest::canonical_json(&from_code),
            "checked-in manifest drifted from code — regenerate it from manifest_v1()"
        );
        let locks = LockRegistry::with_go50();
        assert!(
            organelle_typed::validate_manifest_v1_json(&from_file, &locks).is_ok(),
            "checked-in manifest must validate against the locks"
        );
    }

    #[test]
    fn commit_known_vector() {
        let d = dispatcher();
        let ok = d
            .dispatch(commit_envelope("greeting", serde_json::json!("hello")))
            .expect("commit dispatch must succeed");
        // Independently constructed record: the id must be the hash of
        // {key, value_hash, parent} with value_hash the hash of "hello".
        let value_hash = hash_value(&serde_json::json!("hello"));
        let want_id = hash_value(&serde_json::json!({
            "key": "greeting", "parent": "", "value_hash": value_hash,
        }));
        assert_eq!(ok.output["commit_id"], serde_json::json!(want_id));
        assert_eq!(ok.output["key"], serde_json::json!("greeting"));
        assert_eq!(ok.output["value_hash"], serde_json::json!(value_hash));
        assert_eq!(ok.output["parent"], serde_json::json!(""));
        assert_eq!(ok.output["seq"], serde_json::json!(1));
        assert_eq!(ok.truth.status, TruthStatus::Proven);
        assert_eq!(ok.provenance.produced_by, "tc@1.0.0");
        assert_eq!(ok.provenance.source, ProvenanceSource::ComputedLocally);
        // The attestation: the receipt exists, carries the typed
        // outcome, and the chain verifies.
        let receipt = d.host().receipt_by_id(&ok.receipt_id).unwrap();
        assert!(receipt.typed_outcome.is_some());
        assert!(d.host().verify_chain().is_ok());
    }

    #[test]
    fn commit_idempotent_and_parent_linked() {
        let d = dispatcher();
        let first = d
            .dispatch(commit_envelope("a", serde_json::json!(1)))
            .unwrap();
        // Idempotency is by the full triple (key, value, parent): the
        // same triple — here with the genesis parent named explicitly
        // — is the same commit, same id, same seq.
        let mut repeat = commit_envelope("a", serde_json::json!(1));
        repeat.input["parent"] = serde_json::json!("");
        let again = d.dispatch(repeat).unwrap();
        assert_eq!(first.output["commit_id"], again.output["commit_id"]);
        assert_eq!(again.output["seq"], serde_json::json!(1));
        // A bare repeat (no parent named) is a NEW commit: the default
        // parent is the moving head, so the triple differs. That is
        // the documented semantics, not a bug — like committing the
        // same tree twice in git with different parents.
        let bare = d
            .dispatch(commit_envelope("a", serde_json::json!(1)))
            .unwrap();
        assert_ne!(bare.output["commit_id"], first.output["commit_id"]);
        assert_eq!(bare.output["parent"], first.output["commit_id"]);
        assert_eq!(bare.output["seq"], serde_json::json!(2));
        // A second, distinct commit parents onto the head (the bare
        // repeat above).
        let second = d
            .dispatch(commit_envelope("b", serde_json::json!(2)))
            .unwrap();
        assert_eq!(second.output["seq"], serde_json::json!(3));
        assert_eq!(second.output["parent"], bare.output["commit_id"]);
        // An explicit parent is honored.
        let mut env = commit_envelope("c", serde_json::json!(3));
        env.input["parent"] = first.output["commit_id"].clone();
        let third = d.dispatch(env).unwrap();
        assert_eq!(third.output["parent"], first.output["commit_id"]);
        assert_eq!(third.output["seq"], serde_json::json!(4));
    }

    #[test]
    fn unknown_parent_rejected() {
        let d = dispatcher();
        let mut env = commit_envelope("x", serde_json::json!(0));
        env.input["parent"] = serde_json::json!("deadbeef");
        let err = d.dispatch(env).unwrap_err();
        assert!(
            matches!(
                err,
                organelle_typed::TypedDispatchError::Host(ref e)
                    if e.verdict == organelle_host::CallVerdict::Failed
            ),
            "{err:?}"
        );
    }

    #[test]
    fn get_and_verify_roundtrip() {
        let d = dispatcher();
        let committed = d
            .dispatch(commit_envelope("greeting", serde_json::json!("hello")))
            .unwrap();
        let id = committed.output["commit_id"].as_str().unwrap().to_string();
        let got = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "tc",
                "get",
                serde_json::json!({"commit_id": id}),
            ))
            .unwrap();
        assert_eq!(got.output["found"], serde_json::json!(true));
        assert_eq!(got.output["key"], serde_json::json!("greeting"));
        assert_eq!(got.output["value"], serde_json::json!("hello"));
        assert_eq!(got.provenance.source, ProvenanceSource::Retrieved);
        let verified = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "tc",
                "verify",
                serde_json::json!({"commit_id": id}),
            ))
            .unwrap();
        assert_eq!(verified.output["found"], serde_json::json!(true));
        assert_eq!(verified.output["hash_matches"], serde_json::json!(true));
        assert_eq!(verified.output["parent_known"], serde_json::json!(true));
        // Unknown ids: honest not-found, not an error.
        let unknown = "00".repeat(32);
        let missing = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "tc",
                "verify",
                serde_json::json!({"commit_id": unknown}),
            ))
            .unwrap();
        assert_eq!(missing.output["found"], serde_json::json!(false));
        assert_eq!(missing.output["hash_matches"], serde_json::json!(false));
        let gone = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "tc",
                "get",
                serde_json::json!({"commit_id": unknown}),
            ))
            .unwrap();
        assert_eq!(gone.output["found"], serde_json::json!(false));
        assert!(gone.output.get("value").is_none());
    }

    #[test]
    fn commit_without_capability_denied() {
        let d = dispatcher();
        let err = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "tc",
                "commit",
                serde_json::json!({"key": "a", "value": 1}),
            ))
            .unwrap_err();
        assert!(
            matches!(
                err,
                organelle_typed::TypedDispatchError::Host(ref e)
                    if e.verdict == organelle_host::CallVerdict::Denied
            ),
            "{err:?}"
        );
        // The denial left nothing in the store: a get for the would-be
        // commit id finds nothing (proves the denial happened before
        // any mutation).
        let value_hash = value_hash_for(&serde_json::json!(1));
        let would_be = commit_id_for("a", &value_hash, "");
        let got = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "tc",
                "get",
                serde_json::json!({"commit_id": would_be}),
            ))
            .unwrap();
        assert_eq!(got.output["found"], serde_json::json!(false));
    }

    #[test]
    fn malformed_input_rejected() {
        let d = dispatcher();
        let mut env =
            InvocationEnvelope::native("test", "tc", "commit", serde_json::json!({"key": "a"}));
        env.capabilities = vec![COMMIT_CAPABILITY.to_string()];
        let err = d.dispatch(env).unwrap_err();
        assert!(
            matches!(
                err,
                organelle_typed::TypedDispatchError::Host(ref e)
                    if e.verdict == organelle_host::CallVerdict::Rejected
            ),
            "{err:?}"
        );
    }

    #[test]
    fn receipt_carries_separate_truth_and_provenance() {
        let d = dispatcher();
        let ok = d
            .dispatch(commit_envelope("greeting", serde_json::json!("hello")))
            .unwrap();
        let receipt = d.host().receipt_by_id(&ok.receipt_id).unwrap();
        let typed = receipt
            .typed_outcome
            .as_ref()
            .expect("typed outcome on receipt");
        assert_eq!(typed["truth"]["status"], serde_json::json!("proven"));
        assert!(typed["truth"]["basis"]
            .as_str()
            .unwrap()
            .contains("SHA-256"));
        assert_eq!(
            typed["provenance"]["source"],
            serde_json::json!("computed_locally")
        );
        assert_eq!(
            typed["provenance"]["input_hash"].as_str().unwrap().len(),
            64
        );
        assert_eq!(receipt.valence, Valence::Proven);
        assert!(d.host().verify_chain().is_ok());
    }

    #[test]
    fn projection_source_lists_typed_commit() {
        let d = dispatcher();
        let ms = d.typed_manifests();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].base.codon, "tc");
        assert_eq!(ms[0].typed_contracts.len(), 3);
        assert_eq!(
            ms[0].ontology.go,
            vec!["TOOL", "PROCESS", "EVIDENCE", "ANCHOR"]
        );
        assert!(ms[0].ontology.domain.is_empty());
        assert!(ms[0].ontology.client.is_empty());
    }

    #[test]
    fn discovery_finds_checked_in_manifest() {
        let d = TypedDispatcher::new(Host::new(), LockRegistry::with_go50());
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/manifests");
        let codons = d
            .load_manifests_dir(std::path::Path::new(dir))
            .expect("checked-in manifest must discover + validate");
        assert_eq!(codons, vec!["tc".to_string()]);
    }

    // -- F6: hostile review ----------------------------------------------

    /// F6 (prove-sound): a commit cannot parent itself. The id of
    /// the genesis commit for this triple is computable, but naming
    /// it as the parent fails — the parent must pre-exist, and a
    /// commit's id is derived from its parent, so a cycle would
    /// require the parent to exist before the child that defines it.
    #[test]
    fn f6_commit_cannot_parent_itself() {
        let d = dispatcher();
        let value_hash = hash_value(&serde_json::json!("hello"));
        let genesis_id = hash_value(&serde_json::json!({
            "key": "self", "parent": "", "value_hash": value_hash,
        }));
        let mut env = commit_envelope("self", serde_json::json!("hello"));
        env.input["parent"] = serde_json::json!(genesis_id);
        let err = d.dispatch(env).unwrap_err();
        assert!(
            matches!(
                err,
                organelle_typed::TypedDispatchError::Host(ref e)
                    if e.verdict == organelle_host::CallVerdict::Failed
            ),
            "{err:?}"
        );
    }
}
