//! LIVE SMOKE — one bounded end-to-end pass against the real
//! Mem0 platform: add one probe memory under a dedicated smoke
//! scope, poll search until extraction lands it, delete it, and
//! verify the delete.  The real import scope (`user_id = "zack"`)
//! is never touched.
//!
//! Env-gated: without `MEM0_LIVE=1` and `MEM0_KEY` the test
//! passes trivially (the offline suite must stay offline and
//! keyless).  Run it with:
//!
//! ```text
//! MEM0_LIVE=1 MEM0_KEY=<key> cargo test -p ref-mem0-client \
//!     --test live_mem0 -- --nocapture
//! ```
//!
//! Optional env: `MEM0_API_BASE` (default `https://api.mem0.ai`),
//! `MEM0_API_VERSION` (`v1` default — the proven shapes; `v3`
//! exercises the doc-derived shapes).  The key is read from the
//! environment only; it is never printed and never stored.

#![cfg(not(target_arch = "wasm32"))]

use ref_mem0_client::*;
use std::time::{Duration, Instant};

const SMOKE_USER: &str = "lucidota-smoke";
const PROBE_TEXT: &str =
    "The ref-mem0-client organelle (org-039) ran its live smoke test on 2026-11-23.";

#[test]
fn live_mem0_add_search_delete_round_trip() {
    if std::env::var("MEM0_LIVE").as_deref() != Ok("1") {
        eprintln!("skipping live Mem0 smoke (set MEM0_LIVE=1 and MEM0_KEY to run)");
        return;
    }
    let key = std::env::var("MEM0_KEY").expect("MEM0_KEY must be set for the live smoke");
    let base = std::env::var("MEM0_API_BASE")
        .unwrap_or_else(|_| "https://api.mem0.ai".to_string());
    let version = match std::env::var("MEM0_API_VERSION").as_deref() {
        Ok("v3") => ApiVersion::V3,
        _ => ApiVersion::V1,
    };
    let config = Mem0Config::new(base, version, 120_000, 4_194_304);
    let sink = MemorySink::new();
    let client = Mem0Client::host(config, Mem0ApiKey::new(key), sink);

    // Step 1 — add the probe.  The honest expectation is a
    // PENDING event receipt, not a memory.
    let outcome = client
        .add(
            &AddRequest::new(
                vec![Message::user(PROBE_TEXT)],
                Scope::user(SMOKE_USER),
            )
            .metadata(serde_json::json!({"source": "ref-mem0-client live smoke"})),
        )
        .expect("live add succeeds");
    println!(
        "step 1 add: {} event(s), statuses {:?}, event_ids {:?}",
        outcome.events.len(),
        outcome.events.iter().map(|e| e.status.as_str()).collect::<Vec<_>>(),
        outcome.event_ids()
    );
    assert!(!outcome.events.is_empty(), "add returned no event records");

    // Step 2 — poll search until extraction lands the probe (or
    // the stated timeout: 300 s, one search every 10 s).
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut found: Option<MemoryRecord> = None;
    while Instant::now() < deadline {
        let results = client
            .search(&SearchRequest::new(
                "ref-mem0-client organelle live smoke",
                Scope::user(SMOKE_USER),
            ))
            .expect("live search succeeds");
        if let Some(record) = results
            .into_iter()
            .find(|r| r.memory.contains("org-039") || r.memory.contains("ref-mem0-client"))
        {
            found = Some(record);
            break;
        }
        std::thread::sleep(Duration::from_secs(10));
    }
    let record = found.expect("probe memory did not appear in search within 300 s");
    println!(
        "step 2 search: probe landed as memory id {} (score {:?})",
        record.id, record.score
    );

    // Step 3 — delete it.
    let deleted = client.delete(&record.id).expect("live delete succeeds");
    println!("step 3 delete: message {:?}", deleted.message);

    // Step 4 — verify the delete: get must stop succeeding
    // (404 → Mem0Error::Http) within 60 s.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut verified = false;
    while Instant::now() < deadline {
        match client.get(&record.id) {
            Err(Mem0Error::Http { status: 404, .. }) => {
                verified = true;
                break;
            }
            Err(e) => println!("step 4 verify: get returned {e} (still verifying)"),
            Ok(_) => std::thread::sleep(Duration::from_secs(5)),
        }
    }
    assert!(verified, "deleted memory still fetched OK after 60 s");
    println!("step 4 verify: get returns 404 — delete confirmed");

    // Every call left exactly one receipt, in the estate shape.
    let receipts = client.sink().receipts();
    assert!(receipts.len() >= 4, "expected receipts for add/search/delete/get");
    for r in &receipts {
        assert_eq!(r.tool, "ref-mem0-client");
        assert_eq!(r.version, version.as_str());
    }
    println!(
        "receipts: {} recorded, statuses {:?}",
        receipts.len(),
        receipts.iter().map(|r| r.status.as_str()).collect::<Vec<_>>()
    );
}
