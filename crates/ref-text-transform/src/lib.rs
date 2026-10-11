//! org-015 — Reference organelle: text-transform (codon `tt`).
//!
//! Pure, deterministic string transforms. Declared valence: Proven — every
//! output is exactly recomputable from the input.

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
        name: "text-transform".to_string(),
        codon: "tt".to_string(),
        version: "1.0.0".to_string(),
        description: "reference pure text-transform organelle".to_string(),
        contracts: vec![Contract {
            op: "transform".to_string(),
            description: "apply a named transform to text".to_string(),
            input_schema: serde_json::json!({
                "type": "object", "required": ["text", "mode"],
                "properties": {
                    "text": {"type": "string"},
                    "mode": {"enum": ["upper","lower","reverse","slug","words","lines","trim"]}
                }
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

pub struct TextTransform {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(TextTransform { manifest: manifest() })
}

fn slug(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

impl Organelle for TextTransform {
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
        if op != "transform" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        let text = input["text"].as_str().unwrap_or("");
        let mode = input["mode"].as_str().unwrap_or("");
        let result = match mode {
            "upper" => Value::String(text.to_uppercase()),
            "lower" => Value::String(text.to_lowercase()),
            "reverse" => Value::String(text.chars().rev().collect()),
            "slug" => Value::String(slug(text)),
            "trim" => Value::String(text.trim().to_string()),
            "words" => Value::from(text.split_whitespace().count() as u64),
            "lines" => Value::from(text.lines().count() as u64),
            _ => return Err(OrganelleError::failed(format!("unknown mode {mode}"))),
        };
        Ok(serde_json::json!({"mode": mode, "result": result}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn call(mode: &str, text: &str) -> Value {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        h.call(&ctx, "tt", "transform", serde_json::json!({"text": text, "mode": mode}))
            .unwrap()
            .output
    }

    #[test]
    fn modes() {
        assert_eq!(call("upper", "hi")["result"], serde_json::json!("HI"));
        assert_eq!(call("lower", "HI")["result"], serde_json::json!("hi"));
        assert_eq!(call("reverse", "abc")["result"], serde_json::json!("cba"));
        assert_eq!(call("slug", "Hello,  World!")["result"], serde_json::json!("hello-world"));
        assert_eq!(call("trim", "  x  ")["result"], serde_json::json!("x"));
        assert_eq!(call("words", "a b  c")["result"], serde_json::json!(3));
        assert_eq!(call("lines", "a\nb\nc")["result"], serde_json::json!(3));
    }

    #[test]
    fn bad_mode_rejected_by_schema() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let e = h
            .call(&ctx, "tt", "transform", serde_json::json!({"text": "x", "mode": "nope"}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Rejected);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
