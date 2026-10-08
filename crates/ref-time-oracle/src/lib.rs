//! org-018 — Reference organelle: time-oracle (codon `to`).
//!
//! System-clock time. Declared valence: Candidate — the clock is
//! unverified; callers must not treat it as attested time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "time-oracle".to_string(),
        codon: "to".to_string(),
        version: "1.0.0".to_string(),
        description: "reference system-clock time organelle".to_string(),
        contracts: vec![
            Contract {
                op: "now".to_string(),
                description: "current UTC time".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                mutation_class: None,
                required_capability: None,
            },
            Contract {
                op: "tick".to_string(),
                description: "monotonic nanoseconds since organelle start".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
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

pub struct TimeOracle {
    manifest: OrganelleManifest,
    start: Instant,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(TimeOracle { manifest: manifest(), start: Instant::now() })
}

impl Organelle for TimeOracle {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        _input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "now" => Ok(serde_json::json!({
                "utc_iso": organelle_manifest::utc_now_iso(),
                "unix_secs": organelle_manifest::unix_now(),
            })),
            "tick" => Ok(serde_json::json!({
                "monotonic_nanos": self.start.elapsed().as_nanos() as u64,
            })),
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;

    #[test]
    fn now_shape() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let out = h.call(&ctx, "to", "now", serde_json::json!({})).unwrap();
        assert!(out["utc_iso"].as_str().unwrap().ends_with('Z'));
        assert!(out["unix_secs"].as_u64().unwrap() > 1_700_000_000);
    }

    #[test]
    fn tick_monotonic() {
        let h = Host::new();
        h.register(organelle()).unwrap();
        let ctx = CallContext::new("test", vec![]);
        let a = h.call(&ctx, "to", "tick", serde_json::json!({})).unwrap();
        let b = h.call(&ctx, "to", "tick", serde_json::json!({})).unwrap();
        assert!(b["monotonic_nanos"].as_u64().unwrap() >= a["monotonic_nanos"].as_u64().unwrap());
    }

    #[test]
    fn manifest_validates() {
        let m = serde_json::to_value(&manifest()).unwrap();
        assert!(organelle_manifest::validate_manifest_json(&m).is_ok());
    }
}
