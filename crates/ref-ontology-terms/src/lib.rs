//! Reference organelle: ontology-terms (codon `ot`).
//!
//! The GO-50 shared vocabulary of the PALANTOUR federation, harvested
//! BY COPY from the go-ontology treatment app
//! (`~/workspace/full-send/projects/go-ontology/app/src/lib.rs`,
//! byte-identical, kept as `ontology.rs`): the 50 core terms (RECEIPT,
//! LEDGER, CAS, ORACLE, …), each with a definition, one of 8
//! `TermType`s, a parent hierarchy and a default ternary valence —
//! plus [`TernaryValence`], the canonical -1/0/+1 type the family's
//! scattered valence enums converge on (pt-oracle's gate already does
//! `pub use go_ontology::TernaryValence as Valence;`).
//!
//! Pure API: [`InMemoryOntology::bootstrap_core`] for the GO-50 set,
//! [`InMemoryOntology::load_from_json`] for a caller-supplied set,
//! and the [`OntologyStore`] trait (`resolve`, `by_type`, `children`,
//! `is_a`, `all_terms`).
//!
//! Everything below the re-exports is organelle glue (manifest +
//! trait surface), written for this crate; it is not harvested code.

mod ontology;

pub use ontology::{
    InMemoryOntology, OntologyStore, OntologyTerm, TermType, TernaryValence,
};

// ---------------------------------------------------------------------------
// Organelle trait surface (glue)
// ---------------------------------------------------------------------------

#[cfg(feature = "organelle")]
mod organelle_impl {
    use super::{InMemoryOntology, OntologyStore};
    use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
    use organelle_manifest::{
        Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
        MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
    };
    use serde_json::Value;
    use std::sync::Arc;

    fn contract(op: &str, description: &str, required: &[&str]) -> Contract {
        let props: serde_json::Map<String, Value> = required
            .iter()
            .map(|k| (k.to_string(), serde_json::json!({"type": "string"})))
            .collect();
        Contract {
            op: op.to_string(),
            description: description.to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": required,
                "properties": props
            }),
            mutation_class: None,
            required_capability: None,
        }
    }

    fn manifest() -> OrganelleManifest {
        OrganelleManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
            name: "ontology-terms".to_string(),
            codon: "ot".to_string(),
            version: "1.0.0".to_string(),
            description: "GO-50 ontology term store + canonical TernaryValence".to_string(),
            contracts: vec![
                contract("resolve", "resolve one GO-50 term by name", &["term"]),
                contract("is_a", "transitive is-a check in the term hierarchy", &["child", "parent"]),
                contract("count", "number of terms in the bootstrapped GO-50 store", &[]),
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

    pub struct OntologyTerms {
        manifest: OrganelleManifest,
        store: InMemoryOntology,
    }

    pub fn organelle() -> Arc<dyn Organelle> {
        Arc::new(OntologyTerms {
            manifest: manifest(),
            store: InMemoryOntology::bootstrap_core(),
        })
    }

    impl Organelle for OntologyTerms {
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
            let s = |k: &str| input[k].as_str().unwrap_or("").to_string();
            match op {
                "resolve" => match self.store.resolve(&s("term")) {
                    Some(term) => Ok(serde_json::to_value(term)
                        .map_err(|e| OrganelleError::failed(e.to_string()))?),
                    None => Ok(Value::Null),
                },
                "is_a" => Ok(serde_json::json!({
                    "is_a": self.store.is_a(&s("child"), &s("parent"))
                })),
                "count" => Ok(serde_json::json!({
                    "terms": self.store.all_terms().len()
                })),
                _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
            }
        }
    }
}

#[cfg(feature = "organelle")]
pub use organelle_impl::organelle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_loads_50_terms() {
        let store = InMemoryOntology::bootstrap_core();
        assert_eq!(store.all_terms().len(), 50);
    }

    #[test]
    fn tripartoken_is_a_term_not_code() {
        // The ontology records the concept in the vocabulary; the
        // three-lane tokenization itself is doc/data only.
        let store = InMemoryOntology::bootstrap_core();
        let t = store.resolve("TRIPARTOKEN").expect("term exists");
        assert!(t.definition.contains("three-lane tokenization system"));
    }
}
