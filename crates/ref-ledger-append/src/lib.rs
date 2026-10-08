//! org-020 — Reference organelle: ledger-append (codon `la`).
//!
//! Appends a canonical-JSON line to a JSONL ledger file. Write, requires
//! `ledger.write`. Paths containing `..` are refused (fail-closed on
//! traversal, even though the capability gate is the primary control).

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
        name: "ledger-append".to_string(),
        codon: "la".to_string(),
        version: "1.0.0".to_string(),
        description: "reference JSONL ledger-append organelle".to_string(),
        contracts: vec![Contract {
            op: "append".to_string(),
            description: "append entry as one canonical JSON line".to_string(),
            input_schema: serde_json::json!({
                "type": "object", "required": ["entry", "ledger_path"],
                "properties": {"ledger_path": {"type": "string", "minLength": 1}}
            }),
            mutation_class: Some(MutationClass::Write),
            required_capability: Some("ledger.write".to_string()),
        }],
        authority: Authority {
            mutation_class: MutationClass::Write,
            declared_valence: Valence::Candidate,
            required_capability: Some("ledger.write".to_string()),
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

pub struct LedgerAppend {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(LedgerAppend { manifest: manifest() })
}

impl Organelle for LedgerAppend {
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
        if op != "append" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        let path = input["ledger_path"].as_str().unwrap_or("");
        if path.contains("..") {
            return Err(OrganelleError::denied("ledger_path must not contain .."));
        }
        let line = organelle_manifest::canonical_json(&input["entry"]) + "\n";
        let entry_hash = organelle_manifest::sha256_hex(line.as_bytes());
        let existed = std::path::Path::new(path).exists();
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(line.as_bytes())
            })
            .map_err(|e| OrganelleError::failed(format!("append failed: {e}")))?;
        Ok(serde_json::json!({
            "ok": true,
            "path": path,
            "bytes_written": line.len(),
            "entry_hash": entry_hash,
            "created": !existed,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn tmp_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("organelle-la-test-{tag}-{}.jsonl", std::process::id()));
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn append_roundtrip() {
        let path = tmp_path("ok");
        let _ = std::fs::remove_file(&path);
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["ledger.write".to_string()]);
        let entry = serde_json::json!({"b": 2, "a": 1});
        let out = h
            .call(&ctx, "la", "append", serde_json::json!({"entry": entry, "ledger_path": path}))
            .unwrap();
        assert_eq!(out["ok"], serde_json::json!(true));
        assert_eq!(out["created"], serde_json::json!(true));
        assert_eq!(out["entry_hash"].as_str().unwrap().len(), 64);
        // Canonical line on disk: keys sorted.
        let disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(disk, "{\"a\":1,\"b\":2}\n");
        // Second append: created=false.
        let out2 = h
            .call(&ctx, "la", "append", serde_json::json!({"entry": {"x": 1}, "ledger_path": path}))
            .unwrap();
        assert_eq!(out2["created"], serde_json::json!(false));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn traversal_refused() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["ledger.write".to_string()]);
        let e = h
            .call(&ctx, "la", "append",
                serde_json::json!({"entry": {}, "ledger_path": "/tmp/../evil.jsonl"}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
    }

    #[test]
    fn without_capability_denied() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let e = h
            .call(&ctx, "la", "append",
                serde_json::json!({"entry": {}, "ledger_path": tmp_path("denied")}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
