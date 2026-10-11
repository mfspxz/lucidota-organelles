//! org-021 — Reference organelle: notify (codon `nt`).
//!
//! Queues a notification into a local outbox directory (one JSON file per
//! notification, content-addressed filename). ExternalEffect, requires
//! `notify.send`. Honest contract: the output says `queued`, never `sent` —
//! delivery is a separate system this reference build does not claim.

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
        name: "notify".to_string(),
        codon: "nt".to_string(),
        version: "1.0.0".to_string(),
        description: "reference notification-outbox organelle".to_string(),
        contracts: vec![Contract {
            op: "send".to_string(),
            description: "queue a notification into the local outbox".to_string(),
            input_schema: serde_json::json!({
                "type": "object", "required": ["channel", "title", "body"],
                "properties": {
                    "channel": {"type": "string", "minLength": 1},
                    "title": {"type": "string", "minLength": 1},
                    "body": {"type": "string"}
                }
            }),
            mutation_class: Some(MutationClass::ExternalEffect),
            required_capability: Some("notify.send".to_string()),
        }],
        authority: Authority {
            mutation_class: MutationClass::ExternalEffect,
            declared_valence: Valence::Candidate,
            required_capability: Some("notify.send".to_string()),
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

pub struct Notify {
    manifest: OrganelleManifest,
    outbox: String,
}

pub fn organelle() -> Arc<dyn Organelle> {
    organelle_with_outbox(default_outbox())
}

/// Outbox override (tests / harness point all transports at one dir).
pub fn organelle_with_outbox(outbox: String) -> Arc<dyn Organelle> {
    Arc::new(Notify { manifest: manifest(), outbox })
}

pub fn default_outbox() -> String {
    std::env::var("NOTIFY_OUTBOX").unwrap_or_else(|_| {
        let mut p = std::env::temp_dir();
        p.push("organelle-notify-outbox");
        p.to_string_lossy().into_owned()
    })
}

impl Organelle for Notify {
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
        if op != "send" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        // P1 lane 3: the outbox dir must sit under an approved write root.
        // The filename is a content hash, so joining it onto the approved
        // dir cannot escape.
        let outbox = host.approve_write_path(&self.outbox)?;
        std::fs::create_dir_all(&outbox)
            .map_err(|e| OrganelleError::failed(format!("outbox: {e}")))?;
        let envelope = serde_json::json!({
            "channel": input["channel"],
            "title": input["title"],
            "body": input["body"],
            "queued_at": organelle_manifest::utc_now_iso(),
        });
        let id = organelle_manifest::hash_value(&envelope);
        let path = outbox.join(format!("{id}.json"));
        std::fs::write(&path, organelle_manifest::canonical_json(&envelope))
            .map_err(|e| OrganelleError::failed(format!("write: {e}")))?;
        Ok(serde_json::json!({
            "queued": true,
            "id": id,
            "outbox_path": path.to_string_lossy(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn tmp_outbox(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("organelle-nt-test-{tag}-{}", std::process::id()));
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
    fn queues_to_outbox() {
        let outbox = tmp_outbox("ok");
        let _ = std::fs::remove_dir_all(&outbox);
        let h = rooted_host();
        h.register(organelle_with_outbox(outbox.clone())).unwrap();
        let ctx = CallContext::new("test", vec!["notify.send".to_string()]);
        let out = h
            .call(&ctx, "nt", "send",
                serde_json::json!({"channel": "test", "title": "T", "body": "B"}))
            .unwrap()
            .output;
        assert_eq!(out["queued"], serde_json::json!(true));
        assert!(out["outbox_path"].as_str().unwrap().starts_with(&outbox));
        assert!(std::path::Path::new(out["outbox_path"].as_str().unwrap()).exists());
        let _ = std::fs::remove_dir_all(&outbox);
    }

    #[test]
    fn outbox_outside_write_roots_denied() {
        // Outbox dir outside the approved roots: send fails closed and
        // queues nothing.
        let mut root = std::env::temp_dir();
        root.push(format!("organelle-nt-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let h = Host::new();
        h.set_write_roots(vec![root.clone()]).unwrap();
        let evil_outbox = tmp_outbox("outside");
        h.register(organelle_with_outbox(evil_outbox.clone())).unwrap();
        let ctx = CallContext::new("test", vec!["notify.send".to_string()]);
        let e = h
            .call(&ctx, "nt", "send",
                serde_json::json!({"channel": "c", "title": "t", "body": "b"}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
        assert!(e.reason.contains("denied"), "{}", e.reason);
        assert!(!std::path::Path::new(&evil_outbox).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn without_capability_denied() {
        let h = rooted_host();
        h.register(organelle_with_outbox(tmp_outbox("denied"))).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let e = h
            .call(&ctx, "nt", "send",
                serde_json::json!({"channel": "c", "title": "t", "body": "b"}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
