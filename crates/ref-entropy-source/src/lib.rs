//! org-025 — Reference organelle: entropy-source (codon `es`).
//!
//! Host entropy for Workers and native hosts.
//!
//! This crate has two deliberately separate jobs:
//!
//! 1. Its `fill` operation calls the host CSPRNG directly.  On
//!    `wasm32-unknown-unknown` that is the Workers/WebCrypto host binding
//!    `globalThis.crypto.getRandomValues`, requested in chunks no larger
//!    than WebCrypto's 65,536-byte per-call limit.  On Unix it reads
//!    `/dev/urandom`.
//! 2. Its Cargo features activate the matching upstream `getrandom`
//!    backend in a consumer's dependency graph.  Cargo feature
//!    unification is the mechanism: selecting `getrandom-0_2`,
//!    `getrandom-0_3`, or `getrandom-0_4` makes this crate depend on that
//!    getrandom line with `js` (0.2) or `wasm_js` (0.3/0.4) enabled for
//!    `wasm32-unknown-unknown`, so existing transitive users compile.
//!
//! getrandom 0.3 has one extra requirement that no library crate can set
//! for a consumer: the final build must pass
//! `--cfg getrandom_backend="wasm_js"`.  See `APPLICATION.md` for the
//! exact `.cargo/config.toml` stanza.  Declared valence is Candidate:
//! the bytes are only as trustworthy as the host CSPRNG, which this
//! organelle cannot attest from inside the sandbox.

#[cfg(feature = "organelle")]
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
#[cfg(feature = "organelle")]
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
#[cfg(feature = "organelle")]
use serde_json::Value;
use std::fmt;
use std::sync::Arc;

pub const MAX_FILL_BYTES: usize = 65_536;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
const WEB_CRYPTO_MAX_PER_CALL: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyError(pub String);

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "entropy-source: {}", self.0)
    }
}

impl std::error::Error for EntropyError {}

#[cfg(feature = "organelle")]
fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "entropy-source".to_string(),
        codon: "es".to_string(),
        version: "1.0.0".to_string(),
        description: "reference host-entropy organelle (WebCrypto on WASM; /dev/urandom on Unix)"
            .to_string(),
        contracts: vec![Contract {
            op: "fill".to_string(),
            description: "fill a caller-sized buffer from the host CSPRNG; returns hex".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["len"],
                "properties": {
                    "len": {"type": "integer", "minimum": 0, "maximum": MAX_FILL_BYTES}
                }
            }),
            mutation_class: None,
            required_capability: None,
        }],
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

#[cfg(feature = "organelle")]
pub struct EntropySource {
    manifest: OrganelleManifest,
}

#[cfg(feature = "organelle")]
pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(EntropySource {
        manifest: manifest(),
    })
}

/// Name of the host source used by this build, for receipts/diagnostics.
pub fn source_name() -> &'static str {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        "crypto.getRandomValues"
    }
    #[cfg(all(unix, not(all(target_arch = "wasm32", target_os = "unknown"))))]
    {
        "/dev/urandom"
    }
    #[cfg(not(any(
        all(target_arch = "wasm32", target_os = "unknown"),
        unix
    )))]
    {
        "unsupported"
    }
}

/// Fill `dest` completely from the host CSPRNG, or return an error.
pub fn fill_bytes(dest: &mut [u8]) -> Result<(), EntropyError> {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        return fill_wasm(dest);
    }
    #[cfg(all(unix, not(all(target_arch = "wasm32", target_os = "unknown"))))]
    {
        return fill_unix(dest);
    }
    #[allow(unreachable_code)]
    Err(EntropyError(format!(
        "no entropy backend for this target (buffer length {})",
        dest.len()
    )))
}

#[cfg(all(unix, not(all(target_arch = "wasm32", target_os = "unknown"))))]
fn fill_unix(dest: &mut [u8]) -> Result<(), EntropyError> {
    use std::io::Read;
    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|e| EntropyError(format!("open /dev/urandom: {e}")))?;
    file.read_exact(dest)
        .map_err(|e| EntropyError(format!("read /dev/urandom: {e}")))
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn fill_wasm(dest: &mut [u8]) -> Result<(), EntropyError> {
    use wasm_bindgen::JsCast;

    let global = js_sys::global();
    let crypto_value = js_sys::Reflect::get(&global, &wasm_bindgen::JsValue::from_str("crypto"))
        .map_err(|e| EntropyError(format!("read globalThis.crypto: {e:?}")))?;
    let crypto: web_sys::Crypto = crypto_value
        .dyn_into()
        .map_err(|v| EntropyError(format!("globalThis.crypto has unexpected type: {v:?}")))?;

    // WebCrypto rejects views longer than 65,536 bytes.  wasm-bindgen's
    // mutable-slice binding lets the host fill each permitted chunk in
    // place, with no intermediate typed-array copy.
    for chunk in dest.chunks_mut(WEB_CRYPTO_MAX_PER_CALL) {
        crypto
            .get_random_values_with_u8_array(chunk)
            .map_err(|e| EntropyError(format!("crypto.getRandomValues: {e:?}")))?;
    }
    Ok(())
}

#[cfg(feature = "organelle")]
impl Organelle for EntropySource {
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
        match op {
            "fill" => {
                let len = input["len"]
                    .as_u64()
                    .ok_or_else(|| OrganelleError::new("rejected", "len must be an integer"))?;
                if len as usize > MAX_FILL_BYTES {
                    return Err(OrganelleError::new("rejected", format!(
                        "len {len} exceeds max {MAX_FILL_BYTES}"
                    )));
                }
                let mut bytes = vec![0u8; len as usize];
                fill_bytes(&mut bytes).map_err(|e| OrganelleError::failed(e.to_string()))?;
                Ok(serde_json::json!({
                    "bytes_hex": hex::encode(bytes),
                    "len": len,
                    "source": source_name(),
                }))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_bytes_direct() {
        let mut bytes = [0u8; 64];
        fill_bytes(&mut bytes).unwrap();
        assert!(bytes.iter().any(|b| *b != 0));
    }
}

#[cfg(all(test, feature = "organelle"))]
mod organelle_tests {
    use super::*;
    use organelle_host::Host;

    #[test]
    fn fill_shape() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let out = h
            .call(&ctx, "es", "fill", serde_json::json!({"len": 32}))
            .unwrap()
            .output;
        assert_eq!(out["len"], serde_json::json!(32));
        assert_eq!(out["bytes_hex"].as_str().unwrap().len(), 64);
        assert_eq!(out["source"], serde_json::json!(source_name()));
    }

    #[test]
    fn fill_rejects_oversize() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let err = h
            .call(
                &ctx,
                "es",
                "fill",
                serde_json::json!({"len": MAX_FILL_BYTES + 1}),
            )
            .unwrap_err();
        assert_eq!(err.verdict, organelle_host::CallVerdict::Rejected);
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
