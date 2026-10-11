//! org-014 — Reference organelle: http-fetch (codon `hf`).
//!
//! Fetches an http:// URL (https honestly refused by the reference client).
//! ExternalEffect, requires `net.fetch`. Body capped; truncation flagged.

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
        name: "http-fetch".to_string(),
        codon: "hf".to_string(),
        version: "1.0.0".to_string(),
        description: "reference HTTP fetch organelle".to_string(),
        contracts: vec![Contract {
            op: "fetch".to_string(),
            description: "GET an http:// URL".to_string(),
            input_schema: serde_json::json!({
                "type": "object", "required": ["url"],
                "properties": {
                    "url": {"type": "string", "minLength": 8},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 30000},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 10000000}
                }
            }),
            mutation_class: Some(MutationClass::ExternalEffect),
            required_capability: Some("net.fetch".to_string()),
        }],
        authority: Authority {
            mutation_class: MutationClass::ExternalEffect,
            declared_valence: Valence::Candidate,
            required_capability: Some("net.fetch".to_string()),
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

pub struct HttpFetch {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(HttpFetch { manifest: manifest() })
}

impl Organelle for HttpFetch {
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
        if op != "fetch" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        let url = input["url"].as_str().unwrap_or("");
        let timeout_ms = input["timeout_ms"].as_u64().unwrap_or(5000);
        let max_bytes = input["max_bytes"].as_u64().unwrap_or(262_144) as usize;
        match ref_common::http_get(url, timeout_ms, max_bytes) {
            Ok(r) => Ok(serde_json::json!({
                "status": r.status,
                "headers": r.headers.iter().map(|(k, v)| serde_json::json!({"name": k, "value": v})).collect::<Vec<_>>(),
                "body": String::from_utf8_lossy(&r.body).into_owned(),
                "bytes": r.body.len(),
                "truncated": r.truncated,
            })),
            Err(e) => Err(OrganelleError::failed(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use std::io::{Read, Write};

    fn serve_once(body: &'static [u8]) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(body);
        });
        port
    }

    fn fetch(url: &str) -> Result<Value, organelle_host::CallError> {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["net.fetch".to_string()]);
        h.call(&ctx, "hf", "fetch", serde_json::json!({"url": url}))
            .map(|ok| ok.output)
    }

    #[test]
    fn fetch_local_page() {
        let port = serve_once(b"<html><body>deterministic-fixture</body></html>");
        let out = fetch(&format!("http://127.0.0.1:{port}/")).unwrap();
        assert_eq!(out["status"], serde_json::json!(200));
        assert!(out["body"].as_str().unwrap().contains("deterministic-fixture"));
        assert_eq!(out["truncated"], serde_json::json!(false));
    }

    #[test]
    fn https_refused_honestly() {
        let e = fetch("https://example.com/").unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Failed);
        assert!(e.reason.contains("http://"), "{}", e.reason);
    }

    #[test]
    fn without_capability_denied() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let e = h
            .call(&ctx, "hf", "fetch", serde_json::json!({"url": "http://127.0.0.1:1/"}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
