//! org-016 — Reference organelle: json-validate (codon `jv`).
//!
//! Validates an arbitrary JSON value against a caller-supplied schema using
//! the manifest crate's subset validator. ReadOnly, Proven (deterministic).

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::Arc;

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "json-validate".to_string(),
        codon: "jv".to_string(),
        version: "1.0.0".to_string(),
        description: "reference JSON-schema validation organelle".to_string(),
        contracts: vec![Contract {
            op: "validate".to_string(),
            description: "validate value against schema".to_string(),
            input_schema: serde_json::json!({
                "type": "object", "required": ["value", "schema"],
                "properties": {"schema": {"type": "object"}}
            }),
            mutation_class: None,
            required_capability: None,
        }],
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

pub struct JsonValidate {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(JsonValidate { manifest: manifest() })
}

impl Organelle for JsonValidate {
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
        if op != "validate" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        let schema = &input["schema"];
        // The caller-supplied schema must itself be structurally sound.
        let mut schema_errs = Vec::new();
        organelle_manifest::validate_manifest_json(&serde_json::json!({
            "schema_version": "1", "name": "probe", "codon": "pb", "version": "1.0.0",
            "description": "probe",
            "contracts": [{"op": "x", "description": "x", "input_schema": schema}],
            "authority": {"mutation_class": "read_only", "declared_valence": "candidate"},
            "transports": ["native"],
            "receipt_policy": {"content_addressed": true, "algorithm": "sha256", "chain": true}
        }))
        .err()
        .map(|errs| {
            schema_errs = errs
                .into_iter()
                .filter(|e| e.field.contains("input_schema"))
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        });
        if !schema_errs.is_empty() {
            return Ok(serde_json::json!({"valid": false, "errors": schema_errs}));
        }
        match organelle_manifest::validate_input_against_schema(schema, &input["value"]) {
            Ok(()) => Ok(serde_json::json!({"valid": true, "errors": []})),
            Err(errs) => Ok(serde_json::json!({"valid": false, "errors": errs})),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn validate(value: Value, schema: Value) -> Value {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        h.call(&ctx, "jv", "validate", serde_json::json!({"value": value, "schema": schema}))
            .unwrap()
            .output
    }

    #[test]
    fn valid_and_invalid() {
        let schema = serde_json::json!({"type": "object", "required": ["a"]});
        let ok = validate(serde_json::json!({"a": 1}), schema.clone());
        assert_eq!(ok["valid"], serde_json::json!(true));
        let bad = validate(serde_json::json!({"b": 1}), schema);
        assert_eq!(bad["valid"], serde_json::json!(false));
        assert!(bad["errors"].as_array().unwrap().len() >= 1);
    }

    #[test]
    fn malformed_schema_reported_not_panicking() {
        let out = validate(
            serde_json::json!({}),
            serde_json::json!({"type": "nonsense"}),
        );
        assert_eq!(out["valid"], serde_json::json!(false));
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
