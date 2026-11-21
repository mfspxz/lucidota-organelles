//! org-025 (GO-50 Phase 1, family F3) — reference TYPED organelle:
//! typed-hash (codon `th`).
//!
//! Mirrors `ref-hash-seal` (`hs`) over the typed fabric: the same
//! SHA-256 function, but with typed input/output, GO/DO/CO declarations
//! validated against the ontology locks, and claim truth + payload
//! provenance as separate typed fields on every outcome.
//!
//! This is the acceptance-test subject for the next family
//! (projections): it is registered through the universal dispatcher
//! ([`organelle_typed::TypedDispatcher::register_typed`]), and its V1
//! manifest is the projection source's first entry.
//!
//! GO declarations (all in the GO-50 lock): TOOL (it is a tool),
//! PROCESS (hashing is a process), EVIDENCE (a digest is evidence of
//! content), IDENTITY (a content digest is identity-through-content —
//! seat 14's job description). DO/CO: empty — no DO-25/CO-25 locks
//! exist, so no bindings are declared (see BLOCKERs F3-B1/F3-B2).

use organelle_host::HostRef;
use organelle_manifest::{
    hash_value, sha256_hex, Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy,
    Transport, Valence, MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use organelle_typed::{
    ClaimTruth, EnvironmentCapsule, OntologyDeclarations, OrganelleManifestV1, PayloadProvenance,
    TypedContract, TypedError, TypedOrganelle, TypedOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CODON: &str = "th";
pub const VERSION: &str = "1.0.0";

/// Typed input. One input type per organelle (trait shape): per-op
/// fields are optional here and required per-op in `handle_typed`
/// (`sha256` needs `text`; `verify` needs `text` + `expected_hex`).
/// The host's input-schema validation already enforces the per-op
/// required fields before typed decode runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashInput {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_hex: Option<String>,
}

/// Typed output: one variant per op, untagged so each serializes as a
/// plain object matching its typed contract's `output_schema`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HashOutput {
    Sha256 {
        algorithm: String,
        hex: String,
        input_bytes: u64,
    },
    Verify {
        matches: bool,
        hex: String,
    },
}

fn base_manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "typed-hash".to_string(),
        codon: CODON.to_string(),
        version: VERSION.to_string(),
        description: "reference typed hash organelle (sha256, typed fabric)".to_string(),
        contracts: vec![
            Contract {
                op: "sha256".to_string(),
                description: "SHA-256 hex digest of text".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["text"],
                    "properties": {"text": {"type": "string"}}
                }),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "verify".to_string(),
                description: "verify text against an expected hex digest".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["text", "expected_hex"],
                    "properties": {
                        "text": {"type": "string"},
                        "expected_hex": {"type": "string"}
                    }
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
/// `manifests/typed-hash.v1.json`; the drift test below asserts the
/// two agree exactly.
pub fn manifest_v1() -> OrganelleManifestV1 {
    OrganelleManifestV1::from_base(
        base_manifest(),
        OntologyDeclarations {
            go: vec![
                "TOOL".to_string(),
                "PROCESS".to_string(),
                "EVIDENCE".to_string(),
                "IDENTITY".to_string(),
            ],
            domain: vec![],
            client: vec![],
        },
        vec![
            TypedContract {
                op: "sha256".to_string(),
                input_type: "HashInput".to_string(),
                output_type: "HashOutput::Sha256".to_string(),
                output_schema: serde_json::json!({
                    "type": "object",
                    "required": ["algorithm", "hex", "input_bytes"],
                    "properties": {
                        "algorithm": {"type": "string"},
                        "hex": {"type": "string"},
                        "input_bytes": {"type": "integer", "minimum": 0}
                    }
                }),
            },
            TypedContract {
                op: "verify".to_string(),
                input_type: "HashInput".to_string(),
                output_type: "HashOutput::Verify".to_string(),
                output_schema: serde_json::json!({
                    "type": "object",
                    "required": ["matches", "hex"],
                    "properties": {
                        "matches": {"type": "boolean"},
                        "hex": {"type": "string"}
                    }
                }),
            },
        ],
    )
}

pub struct TypedHash {
    manifest: OrganelleManifestV1,
}

impl TypedHash {
    pub fn new() -> Self {
        TypedHash {
            manifest: manifest_v1(),
        }
    }
}

impl Default for TypedHash {
    fn default() -> Self {
        Self::new()
    }
}

impl TypedOrganelle for TypedHash {
    type Input = HashInput;
    type Output = HashOutput;

    fn manifest_v1(&self) -> OrganelleManifestV1 {
        self.manifest.clone()
    }

    fn handle_typed(
        &self,
        _capsule: &EnvironmentCapsule,
        _host: &dyn HostRef,
        op: &str,
        input: HashInput,
    ) -> Result<TypedOutcome<HashOutput>, TypedError> {
        // Truth: a SHA-256 digest is a deterministic function of the
        // input bytes — recomputation reproduces it, so the claim the
        // output asserts is Proven on that basis. Provenance: computed
        // locally from this invocation's input (hash-bound). Separate
        // fields, separate facts.
        let truth = ClaimTruth::proven(
            "SHA-256 is a deterministic function of the input bytes; recomputation reproduces the digest",
        );
        let input_value = serde_json::to_value(&input)
            .map_err(|e| TypedError::internal(format!("cannot serialize typed input: {e}")))?;
        let provenance =
            PayloadProvenance::computed_locally(&input_value, format!("{CODON}@{VERSION}"));
        match op {
            "sha256" => {
                let hex = sha256_hex(input.text.as_bytes());
                Ok(TypedOutcome {
                    output: HashOutput::Sha256 {
                        algorithm: "sha256".to_string(),
                        hex,
                        input_bytes: input.text.len() as u64,
                    },
                    truth,
                    provenance,
                })
            }
            "verify" => {
                let expected = input
                    .expected_hex
                    .ok_or_else(|| TypedError::validation("verify requires expected_hex"))?;
                let hex = sha256_hex(input.text.as_bytes());
                Ok(TypedOutcome {
                    output: HashOutput::Verify {
                        matches: hex == expected,
                        hex,
                    },
                    truth,
                    provenance,
                })
            }
            _ => Err(TypedError::not_found(format!("unknown op {op}"))),
        }
    }
}

/// Cross-check helper used by tests: hash a JSON value the way
/// `ref-hash-seal` does (sha256 over canonical JSON), proving the two
/// organelles agree on the same digest function for JSON inputs.
pub fn seal_value(v: &Value) -> String {
    hash_value(v)
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
        d.register_typed(TypedHash::new())
            .expect("typed-hash must register");
        d
    }

    #[test]
    fn manifest_v1_validates_against_locks() {
        let locks = LockRegistry::with_go50();
        assert!(validate_manifest_v1(&manifest_v1(), &locks).is_ok());
    }

    #[test]
    fn checked_in_manifest_matches_code() {
        // Drift guard: manifests/typed-hash.v1.json must agree exactly
        // with the code-built manifest (canonical JSON comparison).
        let text = include_str!("../manifests/typed-hash.v1.json");
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
    fn sha256_known_vector() {
        let d = dispatcher();
        let ok = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "th",
                "sha256",
                serde_json::json!({"text": "abc"}),
            ))
            .expect("sha256 dispatch must succeed");
        assert_eq!(
            ok.output["hex"],
            serde_json::json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(ok.output["algorithm"], serde_json::json!("sha256"));
        assert_eq!(ok.output["input_bytes"], serde_json::json!(3));
        assert_eq!(ok.truth.status, TruthStatus::Proven);
        assert_eq!(ok.provenance.produced_by, "th@1.0.0");
    }

    #[test]
    fn verify_match_and_mismatch() {
        let d = dispatcher();
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let ok = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "th",
                "verify",
                serde_json::json!({"text": "abc", "expected_hex": digest}),
            ))
            .unwrap();
        assert_eq!(ok.output["matches"], serde_json::json!(true));
        let no = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "th",
                "verify",
                serde_json::json!({"text": "abd", "expected_hex": digest}),
            ))
            .unwrap();
        assert_eq!(no.output["matches"], serde_json::json!(false));
        // A mismatch is a Proven false, not a failure: the verdict is
        // about the digest comparison, and the comparison itself is
        // deterministic. Truth stays Proven either way.
        assert_eq!(no.truth.status, TruthStatus::Proven);
    }

    #[test]
    fn receipt_carries_separate_truth_and_provenance() {
        let d = dispatcher();
        let ok = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "th",
                "sha256",
                serde_json::json!({"text": "abc"}),
            ))
            .unwrap();
        let receipt = d.host().receipt_by_id(&ok.receipt_id).unwrap();
        let typed = receipt
            .typed_outcome
            .as_ref()
            .expect("typed outcome on receipt");
        // Two separate fields, not one collapsed valence.
        assert_eq!(typed["truth"]["status"], serde_json::json!("proven"));
        assert!(typed["truth"]["basis"]
            .as_str()
            .unwrap()
            .contains("deterministic"));
        assert_eq!(
            typed["provenance"]["source"],
            serde_json::json!("computed_locally")
        );
        assert_eq!(
            typed["provenance"]["input_hash"].as_str().unwrap().len(),
            64
        );
        // The host's own Valence field is untouched by the typed layer:
        // it still carries the organelle's DECLARED valence (Proven for
        // this organelle), a different fact from the per-output truth.
        assert_eq!(receipt.valence, Valence::Proven);
        assert!(d.host().verify_chain().is_ok());
    }

    #[test]
    fn malformed_input_rejected() {
        let d = dispatcher();
        let err = d
            .dispatch(InvocationEnvelope::native(
                "test",
                "th",
                "verify",
                serde_json::json!({"text": "abc"}),
            ))
            .unwrap_err();
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
    fn agrees_with_hash_seal_on_json() {
        // Same digest function as ref-hash-seal for JSON values.
        let v = serde_json::json!({"b": 2, "a": 1});
        let h = Host::new();
        h.register(ref_hash_seal::organelle()).unwrap();
        let ctx = organelle_host::CallContext::new("test", vec![]);
        let sealed = h
            .call(&ctx, "hs", "seal", serde_json::json!({"data": v}))
            .unwrap()
            .output;
        assert_eq!(sealed["sha256"].as_str().unwrap(), seal_value(&v));
    }

    #[test]
    fn projection_source_lists_typed_hash() {
        let d = dispatcher();
        let ms = d.typed_manifests();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].base.codon, "th");
        assert_eq!(ms[0].typed_contracts.len(), 2);
        assert_eq!(
            ms[0].ontology.go,
            vec!["TOOL", "PROCESS", "EVIDENCE", "IDENTITY"]
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
        assert_eq!(codons, vec!["th".to_string()]);
    }
}
