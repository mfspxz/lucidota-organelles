//! org-023 — Reference organelle: model-call (codon `mc`).
//!
//! Calls an OpenAI-compatible chat endpoint when `MODEL_API_URL` is set;
//! otherwise runs an honest deterministic stub (`stub: true` in the output,
//! Candidate valence, and the reply is an echo — never presented as model
//! output). ExternalEffect, requires `model.call`.

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
        name: "model-call".to_string(),
        codon: "mc".to_string(),
        version: "1.0.0".to_string(),
        description: "reference model-call organelle (stub unless MODEL_API_URL set)".to_string(),
        contracts: vec![Contract {
            op: "chat".to_string(),
            description: "chat completion".to_string(),
            input_schema: serde_json::json!({
                "type": "object", "required": ["messages"],
                "properties": {
                    "messages": {
                        "type": "array", "minItems": 1,
                        "items": {
                            "type": "object", "required": ["role", "content"],
                            "properties": {
                                "role": {"enum": ["system","user","assistant"]},
                                "content": {"type": "string"}
                            }
                        }
                    },
                    "model": {"type": "string"}
                }
            }),
            mutation_class: Some(MutationClass::ExternalEffect),
            required_capability: Some("model.call".to_string()),
        }],
        authority: Authority {
            mutation_class: MutationClass::ExternalEffect,
            declared_valence: Valence::Candidate,
            required_capability: Some("model.call".to_string()),
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

pub struct ModelCall {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(ModelCall { manifest: manifest() })
}

fn stub_reply(messages: &Value) -> String {
    let last_user = messages
        .as_array()
        .map(|arr| {
            arr.iter()
                .rev()
                .find(|m| m["role"] == "user")
                .and_then(|m| m["content"].as_str())
                .unwrap_or("")
        })
        .unwrap_or("");
    format!("stub-echo: {last_user}")
}

impl Organelle for ModelCall {
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
        if op != "chat" {
            return Err(OrganelleError::not_found(format!("unknown op {op}")));
        }
        let messages = &input["messages"];
        let model = input["model"].as_str().unwrap_or("stub").to_string();

        match std::env::var("MODEL_API_URL") {
            Ok(base) if !base.trim().is_empty() => {
                let url = format!("{}/chat/completions", base.trim_end_matches('/'));
                let body = serde_json::json!({"model": model, "messages": messages});
                match ref_common::http_post_json(&url, &body, 30_000, 1_048_576) {
                    Ok((status, v)) => {
                        if !(200..300).contains(&status) {
                            return Err(OrganelleError::failed(format!(
                                "provider http {status}"
                            )));
                        }
                        let reply = v["choices"][0]["message"]["content"]
                            .as_str()
                            .unwrap_or("")
                            .to_string();
                        Ok(serde_json::json!({
                            "reply": reply, "model": model,
                            "provider": base, "stub": false,
                        }))
                    }
                    Err(e) => Err(OrganelleError::failed(e.to_string())),
                }
            }
            _ => Ok(serde_json::json!({
                "reply": stub_reply(messages),
                "model": model,
                "provider": "stub",
                "stub": true,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    fn chat(messages: Value) -> Value {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["model.call".to_string()]);
        // Ensure stub mode regardless of ambient env.
        std::env::remove_var("MODEL_API_URL");
        h.call(&ctx, "mc", "chat", serde_json::json!({"messages": messages})).unwrap()
    }

    #[test]
    fn stub_is_honest_and_deterministic() {
        let out = chat(serde_json::json!([
            {"role": "user", "content": "hello there"}
        ]));
        assert_eq!(out["stub"], serde_json::json!(true));
        assert_eq!(out["reply"], serde_json::json!("stub-echo: hello there"));
        assert_eq!(out["provider"], serde_json::json!("stub"));
        // Deterministic: same input, same output.
        let out2 = chat(serde_json::json!([
            {"role": "user", "content": "hello there"}
        ]));
        assert_eq!(out, out2);
    }

    #[test]
    fn live_provider_path_against_local_stub_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let body = br#"{"choices":[{"message":{"content":"live-reply"}}]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(body);
        });
        std::env::set_var("MODEL_API_URL", format!("http://127.0.0.1:{port}"));
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec!["model.call".to_string()]);
        let out = h
            .call(&ctx, "mc", "chat",
                serde_json::json!({"messages": [{"role": "user", "content": "hi"}], "model": "t"}))
            .unwrap();
        std::env::remove_var("MODEL_API_URL");
        assert_eq!(out["stub"], serde_json::json!(false));
        assert_eq!(out["reply"], serde_json::json!("live-reply"));
    }

    #[test]
    fn without_capability_denied() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let e = h
            .call(&ctx, "mc", "chat",
                serde_json::json!({"messages": [{"role": "user", "content": "hi"}]}))
            .unwrap_err();
        assert_eq!(e.verdict, organelle_host::CallVerdict::Denied);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
