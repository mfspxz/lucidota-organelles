//! org-022 — Reference organelle: scrape-extract (codon `se`).
//!
//! Fetches an http:// page and extracts title, visible text, and links.
//! ExternalEffect, requires `net.fetch`.

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
        name: "scrape-extract".to_string(),
        codon: "se".to_string(),
        version: "1.0.0".to_string(),
        description: "reference scrape-and-extract organelle".to_string(),
        contracts: vec![Contract {
            op: "extract".to_string(),
            description: "fetch page, extract title/text/links".to_string(),
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

pub struct ScrapeExtract {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(ScrapeExtract { manifest: manifest() })
}

impl Organelle for ScrapeExtract {
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
        if op != "extract" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        let url = input["url"].as_str().unwrap_or("");
        let timeout_ms = input["timeout_ms"].as_u64().unwrap_or(5000);
        let max_bytes = input["max_bytes"].as_u64().unwrap_or(1_048_576) as usize;
        let r = ref_common::http_get(url, timeout_ms, max_bytes)
            .map_err(|e| OrganelleError::failed(e.to_string()))?;
        let html = String::from_utf8_lossy(&r.body);
        let ex = ref_common::extract_text(&html);
        Ok(serde_json::json!({
            "url": url,
            "status": r.status,
            "title": ex.title,
            "text": ex.text,
            "links": ex.links,
            "bytes": r.body.len(),
            "truncated": r.truncated,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use std::io::{Read, Write};

    const PAGE: &[u8] = b"<html><head><title>Fixture</title></head><body><p>Hello <a href=\"/x\">there</a></p><script>bad()</script></body></html>";

    fn serve_once() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                PAGE.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(PAGE);
        });
        port
    }

    #[test]
    fn extract_local_page() {
        let port = serve_once();
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["net.fetch".to_string()]);
        let out = h
            .call(&ctx, "se", "extract", serde_json::json!({"url": format!("http://127.0.0.1:{port}/")}))
            .unwrap();
        assert_eq!(out["title"], serde_json::json!("Fixture"));
        assert!(out["text"].as_str().unwrap().contains("Hello"), "{}", out["text"]);
        assert!(!out["text"].as_str().unwrap().contains("bad()"));
        assert_eq!(out["links"], serde_json::json!(["/x"]));
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
