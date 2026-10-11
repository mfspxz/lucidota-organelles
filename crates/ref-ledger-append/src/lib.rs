//! org-020 — Reference organelle: ledger-append (codon `la`).
//!
//! Appends a canonical-JSON line to a JSONL ledger file. Write, requires
//! `ledger.write`. The write path is approved by the host against its
//! declared write roots (P1 lane 3): no roots configured = deny, `..`
//! traversal and symlink escapes denied, and the organelle writes to the
//! canonical path the host returns (never re-derived from raw input).

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
        host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        if op != "append" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        let path = input["ledger_path"].as_str().unwrap_or("");
        // P1 lane 3: the host's approved write roots are the policy. The
        // returned canonical path is the one written — never re-derived.
        let approved = host.approve_write_path(path)?;
        let line = organelle_manifest::canonical_json(&input["entry"]) + "\n";
        let entry_hash = organelle_manifest::sha256_hex(line.as_bytes());
        let existed = approved.exists();
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&approved)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(line.as_bytes())
            })
            .map_err(|e| OrganelleError::failed(format!("append failed: {e}")))?;
        Ok(serde_json::json!({
            "ok": true,
            "path": approved.to_string_lossy(),
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

    /// Host with write roots covering the process temp dir (P1 lane 3).
    fn rooted_host() -> std::sync::Arc<Host> {
        let h = Host::new();
        h.set_write_roots(vec![std::env::temp_dir()])
            .expect("temp dir must canonicalize");
        h
    }

    #[test]
    fn append_roundtrip() {
        let path = tmp_path("ok");
        let _ = std::fs::remove_file(&path);
        let h = rooted_host();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["ledger.write".to_string()]);
        let entry = serde_json::json!({"b": 2, "a": 1});
        let out = h
            .call(&ctx, "la", "append", serde_json::json!({"entry": entry, "ledger_path": path}))
            .unwrap();
        assert_eq!(out.output["ok"], serde_json::json!(true));
        assert_eq!(out.output["created"], serde_json::json!(true));
        assert_eq!(out.output["entry_hash"].as_str().unwrap().len(), 64);
        // Canonical line on disk: keys sorted.
        let disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(disk, "{\"a\":1,\"b\":2}\n");
        // Second append: created=false.
        let out2 = h
            .call(&ctx, "la", "append", serde_json::json!({"entry": {"x": 1}, "ledger_path": path}))
            .unwrap();
        assert_eq!(out2.output["created"], serde_json::json!(false));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn traversal_refused() {
        let h = rooted_host();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["ledger.write".to_string()]);
        let e = h
            .call(&ctx, "la", "append",
                serde_json::json!({"entry": {}, "ledger_path": "/tmp/../evil.jsonl"}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
        assert!(e.reason.contains(".."), "{}", e.reason);
    }

    #[test]
    fn write_outside_roots_denied_and_receipted() {
        // Roots cover a scratch dir; the ledger path points elsewhere.
        let mut root = std::env::temp_dir();
        root.push(format!("organelle-la-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let h = Host::new();
        h.set_write_roots(vec![root.clone()]).unwrap();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["ledger.write".to_string()]);
        let outside = tmp_path("outside");
        let e = h
            .call(&ctx, "la", "append",
                serde_json::json!({"entry": {"x": 1}, "ledger_path": outside}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
        assert!(e.reason.contains("denied"), "{}", e.reason);
        assert!(!e.receipt_id.is_empty());
        // Fail-closed: nothing was written.
        assert!(!std::path::Path::new(&outside).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_roots_default_deny() {
        // A host with no write roots configured denies every write.
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["ledger.write".to_string()]);
        let path = tmp_path("noroot");
        let e = h
            .call(&ctx, "la", "append",
                serde_json::json!({"entry": {"x": 1}, "ledger_path": path}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
        assert!(e.reason.contains("default deny"), "{}", e.reason);
        assert!(!std::path::Path::new(&path).exists());
    }

    #[test]
    fn symlink_escape_denied() {
        // root/link -> outside: writing through the symlink must be denied
        // even though the lexical path sits under the root.
        let mut root = std::env::temp_dir();
        root.push(format!("organelle-la-symroot-{}", std::process::id()));
        let mut outside = std::env::temp_dir();
        outside.push(format!("organelle-la-symout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let h = Host::new();
        h.set_write_roots(vec![root.clone()]).unwrap();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["ledger.write".to_string()]);
        let via_link = root.join("link").join("evil.jsonl");
        let e = h
            .call(&ctx, "la", "append",
                serde_json::json!({"entry": {"x": 1},
                    "ledger_path": via_link.to_string_lossy()}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
        assert!(e.reason.contains("denied"), "{}", e.reason);
        assert!(!via_link.exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
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
