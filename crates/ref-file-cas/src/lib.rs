//! org-024 — Reference organelle: file-cas (codon `fc`).
//!
//! Content-addressed file store: `put` stores bytes under their sha256 id,
//! `get` retrieves by id. `put` is Write (`cas.write`); `get` is ReadOnly.
//! Ids containing `..` or `/` are refused.

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
        name: "file-cas".to_string(),
        codon: "fc".to_string(),
        version: "1.0.0".to_string(),
        description: "reference content-addressed file store".to_string(),
        contracts: vec![
            Contract {
                op: "put".to_string(),
                description: "store text content under its sha256 id".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["content"],
                    "properties": {"content": {"type": "string"}}
                }),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("cas.write".to_string()),
            },
            Contract {
                op: "get".to_string(),
                description: "retrieve content by id".to_string(),
                input_schema: serde_json::json!({
                    "type": "object", "required": ["id"],
                    "properties": {"id": {"type": "string", "minLength": 64, "maxLength": 64}}
                }),
                mutation_class: None,
                required_capability: None,
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: Valence::Candidate,
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

pub struct FileCas {
    manifest: OrganelleManifest,
    dir: String,
}

pub fn organelle() -> Arc<dyn Organelle> {
    organelle_with_dir(default_dir())
}

pub fn organelle_with_dir(dir: String) -> Arc<dyn Organelle> {
    Arc::new(FileCas { manifest: manifest(), dir })
}

pub fn default_dir() -> String {
    std::env::var("FILE_CAS_DIR").unwrap_or_else(|_| {
        let mut p = std::env::temp_dir();
        p.push("organelle-file-cas");
        p.to_string_lossy().into_owned()
    })
}

fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

impl Organelle for FileCas {
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
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| OrganelleError::failed(format!("cas dir: {e}")))?;
        match op {
            "put" => {
                let content = input["content"].as_str().unwrap_or("");
                let id = organelle_manifest::sha256_hex(content.as_bytes());
                let path = format!("{}/{id}", self.dir);
                std::fs::write(&path, content)
                    .map_err(|e| OrganelleError::failed(format!("write: {e}")))?;
                Ok(serde_json::json!({"id": id, "bytes": content.len()}))
            }
            "get" => {
                let id = input["id"].as_str().unwrap_or("");
                if !valid_id(id) {
                    return Err(OrganelleError::denied("malformed content id"));
                }
                let path = format!("{}/{id}", self.dir);
                match std::fs::read_to_string(&path) {
                    Ok(content) => Ok(serde_json::json!({"found": true, "id": id, "content": content})),
                    Err(_) => Ok(serde_json::json!({"found": false, "id": id})),
                }
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn tmp_dir(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("organelle-fc-test-{tag}-{}", std::process::id()));
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tmp_dir("ok");
        let _ = std::fs::remove_dir_all(&dir);
        let h = Host::new();
        h.register(organelle_with_dir(dir.clone())).unwrap();
        let ctx = CallContext::new("test", vec!["cas.write".to_string()]);
        let put = h.call(&ctx, "fc", "put", serde_json::json!({"content": "hello cas"})).unwrap();
        let id = put["id"].as_str().unwrap().to_string();
        assert_eq!(id.len(), 64);
        // Same content -> same id (content addressing).
        let put2 = h.call(&ctx, "fc", "put", serde_json::json!({"content": "hello cas"})).unwrap();
        assert_eq!(put2["id"], serde_json::json!(id));
        // get works without the write capability.
        let reader = CallContext::new("reader", vec![]);
        let got = h.call(&reader, "fc", "get", serde_json::json!({"id": id})).unwrap();
        assert_eq!(got["found"], serde_json::json!(true));
        assert_eq!(got["content"], serde_json::json!("hello cas"));
        let missing = h
            .call(&reader, "fc", "get", serde_json::json!({"id": "0".repeat(64)}))
            .unwrap();
        assert_eq!(missing["found"], serde_json::json!(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_id_denied() {
        let dir = tmp_dir("bad");
        let h = Host::new();
        h.register(organelle_with_dir(dir)).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let e = h.call(&ctx, "fc", "get", serde_json::json!({"id": "../evil"})).unwrap_err();
        // schema rejects (length) before handle; either way it must not read.
        assert!(matches!(
            e.verdict,
            organelle_host::CallVerdict::Rejected | organelle_host::CallVerdict::Failed | organelle_host::CallVerdict::Denied
        ));
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
