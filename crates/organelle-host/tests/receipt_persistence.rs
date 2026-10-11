//! P2 — receipt persistence, crash recovery, concurrent writes, anchors.
//!
//! Proves, against real files and a real crashed subprocess:
//! - receipts survive a host restart (durable append-only log, fsync'd);
//! - a returned receipt id is always durable (fsync before return);
//! - a torn trailing record (crash mid-append) is truncated openly on
//!   recovery; a fully-written corrupt record fails closed;
//! - a crash mid-invocation (no receipt emitted, caller got nothing)
//!   leaves no phantom receipt and loses nothing acknowledged;
//! - N threads x M invocations: no loss, no duplicates, chain verifies;
//! - anchors pin (seq, head_id); rewinds/rewrites at-or-before the anchor
//!   are detected; the honest bound is documented in docs/VERIFIER.md.

use organelle_host::{
    CallContext, Host, HostRef, Organelle, OrganelleError, ReceiptAnchor, RecoveryOutcome,
};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct Echo {
    manifest: OrganelleManifest,
}

impl Organelle for Echo {
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
            "echo" => Ok(serde_json::json!({"echo": input})),
            _ => Err(OrganelleError::not_found(format!("no such op {op}"))),
        }
    }
}

fn manifest(codon: &str) -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: format!("persist-{codon}"),
        codon: codon.to_string(),
        version: "1.0.0".to_string(),
        description: "persistence probe".to_string(),
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

static CTR: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "org-persist-{}-{}-{}",
        std::process::id(),
        CTR.fetch_add(1, Ordering::SeqCst),
        tag
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn cleanup(p: &PathBuf) {
    let _ = std::fs::remove_dir_all(p);
}

/// Host with the write root blessed and the receipt log attached at
/// `<dir>/receipts.log`. Returns the host and the log path.
fn persistent_host(dir: &PathBuf) -> (Arc<Host>, PathBuf) {
    let h = Host::new();
    h.set_write_roots(vec![dir.clone()]).unwrap();
    let log = dir.join("receipts.log");
    h.enable_receipt_log(log.to_str().unwrap()).unwrap();
    (h, log)
}

fn ctx() -> CallContext {
    CallContext::new("ptest", vec![])
}

#[test]
fn persistence_survives_restart() {
    let dir = tmpdir("restart");
    let log_s;
    let mut ids = Vec::new();
    {
        let (h, log) = persistent_host(&dir);
        log_s = log;
        h.register(Arc::new(Echo { manifest: manifest("pe") })).unwrap();
        for i in 0..10 {
            let ok = h.call(&ctx(), "pe", "echo", serde_json::json!({"i": i})).unwrap();
            ids.push(ok.receipt_id);
        }
        assert_eq!(h.receipts().len(), 11); // registration + 10
        assert!(h.verify_chain().is_ok());
    } // host dropped: the "restart"
    {
        let h = Host::new();
        h.set_write_roots(vec![dir.clone()]).unwrap();
        let outcome = h
            .enable_receipt_log(log_s.to_str().unwrap())
            .expect("recovery must succeed");
        assert_eq!(outcome, RecoveryOutcome::Loaded { count: 11 });
        assert!(h.verify_chain().is_ok());
        let reloaded: HashSet<String> = h.receipts().iter().map(|r| r.id.clone()).collect();
        assert_eq!(reloaded.len(), 11);
        for id in &ids {
            assert!(reloaded.contains(id), "lost receipt {id}");
        }
        // seq is contiguous and monotonic after reload.
        let seqs: Vec<u64> = h.receipts().iter().map(|r| r.seq).collect();
        assert_eq!(seqs, (1..=11).collect::<Vec<_>>());
        // Recovery restores receipts, not the organelle registry: the
        // operator re-registers organelles on restart (itself receipted),
        // and the chain continues linked to the reloaded head.
        h.register(Arc::new(Echo { manifest: manifest("pe") })).unwrap();
        let head_before = h.receipts().last().unwrap().id.clone();
        let ok = h.call(&ctx(), "pe", "echo", serde_json::json!({"i": 99})).unwrap();
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.seq, 13); // 11 reloaded + registration + this call
        assert_eq!(r.prev, head_before);
        assert_eq!(r.id, ok.receipt_id);
        assert!(h.verify_chain().is_ok());
    }
    cleanup(&dir);
}

#[test]
fn returned_id_is_durable_before_return() {
    // The record must be in the file (fsync'd) by the time `call`
    // returns — verified with a fresh, uncooperative file handle, not
    // through the host.
    let dir = tmpdir("durable");
    let (h, log) = persistent_host(&dir);
    h.register(Arc::new(Echo { manifest: manifest("pd") })).unwrap();
    let ok = h
        .call(&ctx(), "pd", "echo", serde_json::json!({"k": "v"}))
        .unwrap();
    let raw = std::fs::read(&log).unwrap();
    assert!(
        raw.windows(ok.receipt_id.len())
            .any(|w| w == ok.receipt_id.as_bytes()),
        "returned receipt id not found in the log file"
    );
    cleanup(&dir);
}

#[test]
fn concurrent_writes_no_loss_no_dupes() {
    let dir = tmpdir("concurrent");
    let log_s;
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    const THREADS: usize = 8;
    const PER_THREAD: usize = 25;
    {
        let (h, log) = persistent_host(&dir);
        log_s = log;
        h.register(Arc::new(Echo { manifest: manifest("pc") })).unwrap();
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let h2 = h.clone();
            let seen2 = seen.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    let c = CallContext::new(format!("t{t}"), vec![]);
                    let ok = h2
                        .call(&c, "pc", "echo", serde_json::json!({"t": t, "i": i}))
                        .expect("concurrent call");
                    seen2.lock().unwrap().push(ok.receipt_id);
                }
            }));
        }
        for th in handles {
            th.join().expect("thread");
        }
        assert!(h.verify_chain().is_ok());
    }
    let seen_ids = seen.lock().unwrap().clone();
    assert_eq!(seen_ids.len(), THREADS * PER_THREAD);
    // Restart and prove: every returned id present, no duplicates, chain green.
    {
        let h = Host::new();
        h.set_write_roots(vec![dir.clone()]).unwrap();
        let outcome = h.enable_receipt_log(log_s.to_str().unwrap()).unwrap();
        let total = 1 + THREADS * PER_THREAD; // registration + invocations
        assert_eq!(outcome, RecoveryOutcome::Loaded { count: total });
        let reloaded: Vec<String> = h.receipts().iter().map(|r| r.id.clone()).collect();
        assert_eq!(reloaded.len(), total);
        let uniq: HashSet<&str> = reloaded.iter().map(|s| s.as_str()).collect();
        assert_eq!(uniq.len(), total, "duplicate receipt ids");
        for id in &seen_ids {
            assert!(uniq.contains(id.as_str()), "lost receipt {id}");
        }
        assert!(h.verify_chain().is_ok());
        let seqs: Vec<u64> = h.receipts().iter().map(|r| r.seq).collect();
        assert_eq!(seqs, (1..=total as u64).collect::<Vec<_>>());
    }
    cleanup(&dir);
}

#[test]
fn torn_tail_truncated_on_recovery() {
    // Crash mid-append: the last record is torn. Recovery must truncate
    // the torn tail openly (Repaired) and keep the valid prefix.
    let dir = tmpdir("torn");
    let log_s;
    {
        let (h, log) = persistent_host(&dir);
        log_s = log.clone();
        h.register(Arc::new(Echo { manifest: manifest("pt") })).unwrap();
        for i in 0..3 {
            h.call(&ctx(), "pt", "echo", serde_json::json!({"i": i})).unwrap();
        }
        assert_eq!(h.receipts().len(), 4);
    }
    // Parse the 4 record boundaries from the healthy file, then tear the
    // last record by cutting 7 bytes off the end (mid-body).
    let raw = std::fs::read(&log_s).unwrap();
    let len = raw.len() as u64;
    let mut bounds = vec![0u64];
    let mut off = 0usize;
    for _ in 0..4 {
        assert_eq!(&raw[off..off + 4], b"ORL1", "magic");
        let l = u64::from_le_bytes(raw[off + 4..off + 12].try_into().unwrap()) as usize;
        off += 12 + l;
        bounds.push(off as u64);
    }
    assert_eq!(off as u64, len, "file holds exactly 4 records");
    let f = std::fs::OpenOptions::new().write(true).open(&log_s).unwrap();
    f.set_len(len - 7).unwrap();
    drop(f);
    {
        let h = Host::new();
        h.set_write_roots(vec![dir.clone()]).unwrap();
        let outcome = h.enable_receipt_log(log_s.to_str().unwrap()).unwrap();
        match outcome {
            RecoveryOutcome::Repaired { count, dropped_tail_bytes } => {
                assert_eq!(count, 3);
                // The torn partial record ran from bounds[3] to len-7.
                assert_eq!(dropped_tail_bytes, (len - 7) - bounds[3]);
            }
            other => panic!("expected Repaired, got {other:?}"),
        }
        assert!(h.verify_chain().is_ok());
        assert_eq!(h.receipts().len(), 3);
        // The file itself was truncated to the last good record boundary.
        assert_eq!(std::fs::metadata(&log_s).unwrap().len(), bounds[3]);
        // Chain continues cleanly from the repaired head (re-register the
        // organelle first: recovery restores receipts, not the registry).
        h.register(Arc::new(Echo { manifest: manifest("pt") })).unwrap();
        let head_before = h.receipts().last().unwrap().id.clone();
        let ok = h.call(&ctx(), "pt", "echo", serde_json::json!({"i": 9})).unwrap();
        let r = h.receipts().last().unwrap().clone();
        assert_eq!(r.seq, 5); // 3 repaired + registration + this call
        assert_eq!(r.prev, head_before);
        assert_eq!(r.id, ok.receipt_id);
        assert!(h.verify_chain().is_ok());
    }
    cleanup(&dir);
}

#[test]
fn corrupt_record_fails_closed() {
    // A fully-written record whose bytes were tampered with is
    // corruption, not a crash artifact: recovery must refuse the log.
    let dir = tmpdir("corrupt");
    let log_s;
    {
        let (h, log) = persistent_host(&dir);
        log_s = log.clone();
        h.register(Arc::new(Echo { manifest: manifest("px") })).unwrap();
        h.call(&ctx(), "px", "echo", serde_json::json!({"i": 1})).unwrap();
        h.call(&ctx(), "px", "echo", serde_json::json!({"i": 2})).unwrap();
        assert!(h.verify_chain().is_ok());
    }
    // Flip one byte inside the SECOND record's JSON body.
    let mut raw = std::fs::read(&log_s).unwrap();
    let len1 = u64::from_le_bytes(raw[4..12].try_into().unwrap()) as usize;
    let rec2_body = 12 + len1 + 12; // magic+len of rec1, then rec2 body start
    assert!(raw[rec2_body] == b'{');
    raw[rec2_body + 10] ^= 0xFF;
    std::fs::write(&log_s, &raw).unwrap();
    {
        let h = Host::new();
        h.set_write_roots(vec![dir.clone()]).unwrap();
        let err = h.enable_receipt_log(log_s.to_str().unwrap()).unwrap_err();
        assert!(
            err.contains("refusing to load"),
            "fail-closed message expected, got: {err}"
        );
        // The log was NOT attached: this host serves nothing from it.
        assert!(h.receipt_log_path().is_none());
        assert!(h.receipts().is_empty());
    }
    cleanup(&dir);
}

#[test]
fn anchor_export_verify_and_rewind_detection() {
    let dir = tmpdir("anchor");
    let (h, _log) = persistent_host(&dir);
    h.register(Arc::new(Echo { manifest: manifest("pa") })).unwrap();
    for i in 0..3 {
        h.call(&ctx(), "pa", "echo", serde_json::json!({"i": i})).unwrap();
    }
    // Anchor at seq 4 (registration + 3 invocations).
    let anchor = h.export_anchor().unwrap();
    assert_eq!(anchor.seq, 4);
    assert_eq!(anchor.count, 4);
    assert_eq!(anchor.head_id, h.receipts().last().unwrap().id);
    // Written out under the approved root, reloadable by an external verifier.
    let anchor_file = dir.join("anchors").join("a1.json");
    let anchor_path = h.write_anchor(anchor_file.to_str().unwrap()).unwrap();
    assert!(anchor_path.exists(), "anchor file must exist");
    // The returned path is the canonical absolute path under the root.
    assert!(anchor_path.is_absolute());
    let loaded = ReceiptAnchor::load(&anchor_path).unwrap();
    // Same pinned (seq, head_id); ts is stamped per export, so it differs.
    assert_eq!(loaded.format, anchor.format);
    assert_eq!(loaded.seq, anchor.seq);
    assert_eq!(loaded.head_id, anchor.head_id);
    assert_eq!(loaded.count, anchor.count);
    // The chain grows past the anchor; the anchor still verifies.
    for i in 3..5 {
        h.call(&ctx(), "pa", "echo", serde_json::json!({"i": i})).unwrap();
    }
    assert!(h.verify_against_anchor(&anchor).is_ok());
    assert!(h.verify_against_anchor(&loaded).is_ok());
    // A tampered anchor does not verify.
    let mut forged = anchor.clone();
    forged.head_id = "00".repeat(32);
    assert!(h.verify_against_anchor(&forged).is_err());
    // Rewind simulation: a host that only ever saw the first 2 receipts
    // cannot satisfy the anchor (tail deletion below the anchor detected).
    let dir2 = tmpdir("anchor-rewind");
    let h2 = Host::new();
    h2.set_write_roots(vec![dir2.clone()]).unwrap();
    let log2 = dir2.join("receipts.log");
    h2.enable_receipt_log(log2.to_str().unwrap()).unwrap();
    h2.register(Arc::new(Echo { manifest: manifest("pa") })).unwrap();
    h2.call(&ctx(), "pa", "echo", serde_json::json!({"i": 0})).unwrap();
    let err = h2.verify_against_anchor(&anchor).unwrap_err();
    assert!(err.contains("not present"), "got: {err}");
    cleanup(&dir);
    cleanup(&dir2);
}

#[test]
fn crash_mid_invocation_no_phantom_receipt() {
    // A real process crash (exit(42)) mid-handle: the crashed invocation
    // emitted no receipt and its caller received no id. Recovery must show
    // the acknowledged invocation durable and no phantom for the crashed one.
    let dir = tmpdir("crash");
    let probe = env!("CARGO_BIN_EXE_crash_probe");
    let out = std::process::Command::new(probe)
        .arg(dir.to_str().unwrap())
        .arg("crash-in-handle")
        .output()
        .expect("spawn crash_probe");
    assert_eq!(out.status.code(), Some(42), "probe must die mid-handle");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let acked_id = stdout
        .strip_prefix("OK ")
        .expect("probe prints the acknowledged receipt id")
        .trim()
        .to_string();
    assert!(!acked_id.is_empty());
    // "Restart": a fresh host recovers the same log.
    let h = Host::new();
    h.set_write_roots(vec![dir.clone()]).unwrap();
    let outcome = h
        .enable_receipt_log(dir.join("receipts.log").to_str().unwrap())
        .expect("recovery after crash");
    assert_eq!(outcome, RecoveryOutcome::Loaded { count: 2 });
    assert!(h.verify_chain().is_ok());
    let ids: Vec<String> = h.receipts().iter().map(|r| r.id.clone()).collect();
    assert_eq!(ids.len(), 2); // registration + the ONE acknowledged invocation
    assert!(ids.contains(&acked_id), "acknowledged receipt must be durable");
    // No phantom: the crashed invocation is absent — exactly 2 receipts.
    assert_eq!(h.receipts()[1].codon, "cp");
    assert_eq!(h.receipts()[1].verdict, organelle_host::CallVerdict::Ok);
    cleanup(&dir);
}

#[test]
fn enable_requires_approved_write_root() {
    let dir = tmpdir("roots");
    // No roots configured: default deny.
    let h = Host::new();
    let err = h
        .enable_receipt_log(dir.join("receipts.log").to_str().unwrap())
        .unwrap_err();
    assert!(err.contains("no approved write roots"), "got: {err}");
    // Path escaping the approved root: denied.
    h.set_write_roots(vec![dir.clone()]).unwrap();
    let err = h.enable_receipt_log("/tmp/org-persist-outside.log").unwrap_err();
    assert!(err.contains("denied") || err.contains("outside"), "got: {err}");
    // `..` in the path: denied.
    let sneaky = dir.join("..").join("org-persist-outside2.log");
    let err = h.enable_receipt_log(sneaky.to_str().unwrap()).unwrap_err();
    assert!(err.contains(".."), "got: {err}");
    // Nothing attached after the denials.
    assert!(h.receipt_log_path().is_none());
    // Double-enable: fail closed.
    h.enable_receipt_log(dir.join("receipts.log").to_str().unwrap()).unwrap();
    let err = h
        .enable_receipt_log(dir.join("other.log").to_str().unwrap())
        .unwrap_err();
    assert!(err.contains("already enabled"), "got: {err}");
    cleanup(&dir);
}

#[test]
fn enable_on_mismatched_log_fails_closed() {
    // Two different in-memory chains, one log file: attaching the second
    // host must fail rather than merge.
    let dir = tmpdir("mismatch");
    let log = dir.join("receipts.log");
    let a = Host::new();
    a.set_write_roots(vec![dir.clone()]).unwrap();
    a.enable_receipt_log(log.to_str().unwrap()).unwrap();
    a.register(Arc::new(Echo { manifest: manifest("ma") })).unwrap();
    a.call(&ctx(), "ma", "echo", serde_json::json!({})).unwrap();
    drop(a);
    let b = Host::new();
    b.set_write_roots(vec![dir.clone()]).unwrap();
    b.register(Arc::new(Echo { manifest: manifest("mb") })).unwrap(); // different chain
    let err = b.enable_receipt_log(log.to_str().unwrap()).unwrap_err();
    assert!(err.contains("does not match"), "got: {err}");
    assert!(b.receipt_log_path().is_none());
    cleanup(&dir);
}

#[test]
#[should_panic(expected = "refusing to serve")]
fn log_write_failure_poisons_host() {
    // Break the log's fd (swap in write-only /dev/full: every write fails
    // with ENOSPC, even for root). The next emission must die loudly —
    // poisoning the dispatch lock — rather than hand out a receipt id
    // that is not durable.
    let dir = tmpdir("poison");
    let (h, _log) = persistent_host(&dir);
    h.register(Arc::new(Echo { manifest: manifest("pf") })).unwrap();
    h.__test_break_receipt_log();
    // This emission's append fails -> panic("... refusing to serve ...").
    let _ = h.call(&ctx(), "pf", "echo", serde_json::json!({}));
    // (unreached; cleanup best-effort)
    cleanup(&dir);
}
