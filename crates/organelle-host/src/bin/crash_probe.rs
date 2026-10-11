//! P2 crash probe: a sacrificial host process for crash-recovery tests.
//!
//! Usage: `crash_probe <logdir> <mode>`
//!   mode `normal`         — one invocation, print `OK <receipt_id>`, exit 0.
//!   mode `crash-in-handle`— one invocation (`OK <receipt_id>` printed and
//!                           flushed), then a second invocation whose handler
//!                           calls `process::exit(42)` MID-HANDLE, before any
//!                           receipt is emitted. The caller of the crashed
//!                           invocation never receives a receipt id.
//!
//! The parent test asserts the exit code, then re-opens the host on the
//! same log dir and proves recovery: the first invocation's receipt is
//! durable, the crashed invocation left no phantom receipt.

use organelle_host::{CallContext, Host, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

struct Probe {
    manifest: OrganelleManifest,
}

impl Organelle for Probe {
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
        if input.get("crash") == Some(&Value::Bool(true)) {
            // Simulate a hard crash mid-invocation: no receipt emitted,
            // no result returned, no unwind.
            let _ = std::io::stderr().write_all(b"probe: crashing mid-handle\n");
            let _ = std::io::stderr().flush();
            std::process::exit(42);
        }
        match op {
            "echo" => Ok(serde_json::json!({"echo": input})),
            _ => Err(OrganelleError::not_found(format!("no such op {op}"))),
        }
    }
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "crash-probe".to_string(),
        codon: "cp".to_string(),
        version: "1.0.0".to_string(),
        description: "P2 crash probe organelle".to_string(),
        contracts: vec![Contract {
            op: "echo".to_string(),
            description: "echo".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            mutation_class: None,
            required_capability: None,
        }],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: Valence::Candidate,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: vec![Transport::Native],
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: crash_probe <logdir> <normal|crash-in-handle>");
        std::process::exit(2);
    }
    let logdir = PathBuf::from(&args[1]);
    let mode = args[2].as_str();

    let h = Host::new();
    h.set_write_roots(vec![logdir.clone()])
        .expect("set_write_roots");
    let log_path = logdir.join("receipts.log");
    h.enable_receipt_log(log_path.to_str().expect("utf8"))
        .expect("enable_receipt_log");
    h.register(Arc::new(Probe { manifest: manifest() }))
        .expect("register");

    let ctx = CallContext::new("probe", vec![]);
    let ok = h
        .call(&ctx, "cp", "echo", serde_json::json!({"n": 1}))
        .expect("first call");
    println!("OK {}", ok.receipt_id);
    std::io::stdout().flush().expect("flush");

    match mode {
        "normal" => std::process::exit(0),
        "crash-in-handle" => {
            // This never returns: the handler exits the process mid-handle.
            let _ = h.call(&ctx, "cp", "echo", serde_json::json!({"crash": true}));
            eprintln!("probe: BUG — survived the crash call");
            std::process::exit(3);
        }
        _ => {
            eprintln!("unknown mode {mode}");
            std::process::exit(2);
        }
    }
}
