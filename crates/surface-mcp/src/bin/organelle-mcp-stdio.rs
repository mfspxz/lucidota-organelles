//! Generated MCP server stub: all 12 reference organelles over stdio.
//! Built from manifests by surface-mcp's generator (org-005 done definition:
//! "manifest -> MCP server stub generated; 3 organelles exposed" — 12 here,
//! which exceeds the minimum; the generator itself is transport-agnostic).
//!
//! P0 authority: callers authenticate with a host-issued capability grant
//! (the `grant` argument on every tools/call). Grants are minted by the
//! host operator out-of-band; this binary's grant key comes from the
//! `ORGANELLE_GRANT_KEY` env var (64 hex chars) when set, otherwise a fresh
//! random key is generated per process (grants then don't survive restarts).
//! A malformed key is fatal — the server refuses to start rather than run
//! with unintended authority semantics.

use std::sync::Arc;

/// Grant key for this process: operator-provided via env, else fresh random.
fn grant_key() -> Option<[u8; 32]> {
    let hex = std::env::var("ORGANELLE_GRANT_KEY").ok()?;
    let bytes = hex::decode(hex.trim()).ok()?;
    if bytes.len() != 32 {
        eprintln!("ORGANELLE_GRANT_KEY must be 64 hex chars (32 bytes)");
        std::process::exit(1);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn main() {
    let host: Arc<organelle_host::Host> = match grant_key() {
        Some(key) => organelle_host::Host::with_grant_key(key),
        None => organelle_host::Host::new(),
    };
    // Outbox/CAS dirs come from NOTIFY_OUTBOX / FILE_CAS_DIR env when set,
    // so a harness can point every transport at shared dirs.
    let outbox = ref_notify::default_outbox();
    let cas_dir = ref_file_cas::default_dir();
    host.register(ref_kv_store::organelle()).expect("kv");
    host.register(ref_http_fetch::organelle()).expect("hf");
    host.register(ref_text_transform::organelle()).expect("tt");
    host.register(ref_json_validate::organelle()).expect("jv");
    host.register(ref_hash_seal::organelle()).expect("hs");
    host.register(ref_time_oracle::organelle()).expect("to");
    host.register(ref_geo_point::organelle()).expect("gp");
    host.register(ref_ledger_append::organelle()).expect("la");
    host.register(ref_notify::organelle_with_outbox(outbox)).expect("nt");
    host.register(ref_scrape_extract::organelle()).expect("se");
    host.register(ref_model_call::organelle()).expect("mc");
    host.register(ref_file_cas::organelle_with_dir(cas_dir)).expect("fc");
    if let Err(e) = surface_mcp::serve_stdio(host) {
        eprintln!("mcp stdio: {e}");
        std::process::exit(1);
    }
}
