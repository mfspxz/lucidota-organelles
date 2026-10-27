//! P2 — durable receipt log with crash recovery and external anchors.
//!
//! Pre-P2 the receipt chain was a `Vec<Receipt>` behind an `RwLock`:
//! process-integrity only, gone on restart (see AUDIT-APPLICATION.md R-2).
//! This module appends every emitted receipt to a length-prefixed,
//! fsync'd log file under an operator-approved write root, and rebuilds
//! the in-memory chain from that log on startup.
//!
//! Record format (all multi-byte integers little-endian):
//!   magic[4] = "ORL1" | body_len: u64 | body[body_len] (JSON `Receipt`)
//!
//! Crash semantics:
//! - `fsync` happens BEFORE the receipt id is returned to the caller, so
//!   a returned id is always durable against process crash (machine-crash
//!   safety is modulo the OS/storage stack honoring fsync — see
//!   docs/VERIFIER.md).
//! - A torn trailing record (crash mid-append) is detected on recovery
//!   and truncated: the log keeps its longest valid prefix. This is a
//!   crash artifact, repaired openly, never silently.
//! - A fully-written record that fails to parse or fails integrity
//!   (id mismatch, broken prev link, non-monotonic seq) is CORRUPTION,
//!   not a crash artifact: recovery fails closed and the host refuses to
//!   attach the log.
//!
//! No hand-rolled crypto: record integrity rides on the receipt's own
//! content-addressed id (sha256, computed in `Receipt::compute_id`).

use crate::Receipt;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Magic prefix of every log record. Versioned so a future format change
/// fails loudly instead of misparsing.
pub const LOG_MAGIC: &[u8; 4] = b"ORL1";
const LOG_FORMAT_VERSION: u8 = 1;

/// Sanity cap on one record: anything larger is corruption, not a receipt.
const MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;

/// What recovery found in the log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// Log file was empty (or newly created). In-memory receipts, if any,
    /// are adopted into the fresh log.
    Fresh,
    /// `count` receipts loaded; the chain verified clean.
    Loaded { count: usize },
    /// A torn trailing record (crash artifact) was truncated; `count`
    /// valid receipts loaded. `dropped_tail_bytes` is how much trailing
    /// garbage was cut.
    Repaired {
        count: usize,
        dropped_tail_bytes: u64,
    },
}

/// The receipts recovered from the log plus what recovery did.
#[derive(Debug)]
pub struct Recovery {
    pub receipts: Vec<Receipt>,
    pub outcome: RecoveryOutcome,
}

/// An out-of-band checkpoint over the receipt chain: the (seq, head id)
/// pair at export time. Publish/store it somewhere the host operator does
/// NOT control (append-only store, separate machine, printed page — the
/// anchor is only as trustworthy as its store's independence from the
/// host). `verify_against_anchor` checks the live chain still contains
/// this exact pair, which detects rewinds/rewrites of everything at or
/// before the anchor. It does NOT detect tail truncation after the
/// anchor, forks sharing the prefix, or anything about later receipts —
/// see docs/VERIFIER.md for the brutally honest bound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptAnchor {
    /// Format version of the anchor itself.
    pub format: u8,
    /// Head sequence number at export time.
    pub seq: u64,
    /// Content-addressed id of the head receipt at export time.
    pub head_id: String,
    /// Number of receipts in the chain at export time.
    pub count: usize,
    /// Export timestamp (UTC ISO-8601, operator clock — trusted, not proven).
    pub ts: String,
}

impl ReceiptAnchor {
    /// Read an anchor back from a JSON file written by `write_anchor`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("anchor read {}: {e}", path.display()))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| format!("anchor parse {}: {e}", path.display()))
    }
}

/// The open, append-only receipt log. Appends are length-prefixed single
/// `write_all` calls followed by `sync_all`; recovery truncates torn tails.
pub struct ReceiptLog {
    file: File,
    /// Canonical absolute path of the log file (resolved under an approved
    /// write root by the caller).
    pub path: PathBuf,
}

impl ReceiptLog {
    /// Open (creating) the log at `path`, run recovery, and leave the file
    /// positioned at the end for appends.
    pub fn open(path: &Path) -> Result<(Self, Recovery), String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(|e| format!("receipt log open {}: {e}", path.display()))?;
        let recovery = scan_and_repair(&file, path)?;
        let mut log = ReceiptLog {
            file,
            path: path.to_path_buf(),
        };
        log.file
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("receipt log seek {}: {e}", path.display()))?;
        let _ = LOG_FORMAT_VERSION; // referenced so the version constant stays load-bearing
        Ok((log, recovery))
    }

    /// Test hook: swap the log's file handle for a write-only handle to
    /// /dev/full, so the next append fails with ENOSPC. Lets tests prove
    /// the host fails closed (poisons itself) instead of serving receipts
    /// that are not durable. Not for production use.
    #[doc(hidden)]
    pub fn __test_break(&mut self) {
        if let Ok(broken) = OpenOptions::new().write(true).open("/dev/full") {
            self.file = broken;
        }
    }

    /// Append one receipt and fsync before returning. Callers must treat
    /// the receipt id as durable only after this returns `Ok`.
    pub fn append(&mut self, r: &Receipt) -> Result<(), String> {
        let body =
            serde_json::to_vec(r).map_err(|e| format!("receipt log serialize: {e}"))?;
        let mut buf = Vec::with_capacity(12 + body.len());
        buf.extend_from_slice(LOG_MAGIC);
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend_from_slice(&body);
        self.file
            .write_all(&buf)
            .map_err(|e| format!("receipt log write {}: {e}", self.path.display()))?;
        self.file
            .sync_all()
            .map_err(|e| format!("receipt log fsync {}: {e}", self.path.display()))?;
        Ok(())
    }
}

/// Host-side view of the dispatch effect-state file (see
/// `fabric-dispatch::idem::DurableEffectLog` for the writer and the full
/// protocol docs).
///
/// WHY THIS EXISTS, AND WHY IT IS NOT A SECOND SOURCE OF TRUTH: the
/// receipt chain (ORL1, above) is the sole receipt truth, but a receipt
/// only exists AFTER an effect completes. The gap between "effect
/// attempted" and "receipt durable" is exactly where duplicate external
/// sends are born. This file is the sole EFFECT-STATE truth for a
/// deployment: one file, written by the dispatcher and readable here,
/// correlated to receipts by idempotency key. Both sides replay the
/// SAME file with the SAME record schema (`op`/`key`/`reserved_ms`/
/// `receipt.result_digest`/`provider_id`); extra fields (effect kind,
/// task id, attempt) are ignored on read. There are not two effect
/// stores — there is one file with two crate-side views of it.
///
/// States mirror the dispatch side: UNKNOWN (reserved, outcome unknown —
/// reconcile, never blindly re-execute) and PROVEN (confirmed with a
/// digest; a conflicting digest is refused).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEffectState {
    Unknown { reserved_ms: u64 },
    Proven {
        result_digest: String,
        provider_id: Option<String>,
    },
}

/// One effect-state record as written to the file. Only the fields this
/// side needs are modeled; everything else is ignored on read.
#[derive(Debug, Deserialize)]
struct EffectFileRecord {
    op: String,
    key: String,
    #[serde(default)]
    reserved_ms: u64,
    #[serde(default)]
    receipt: Option<EffectFileReceipt>,
    #[serde(default)]
    provider_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EffectFileReceipt {
    result_digest: String,
}

/// File-backed effect-state log: append-only JSONL, fsync'd before a
/// transition is reported done. Torn-final-line repair mirrors
/// [`ReceiptLog`]: a crash mid-append truncates, a complete-but-bad
/// record fails closed.
pub struct EffectStateLog {
    file: File,
    pub path: PathBuf,
    states: std::collections::HashMap<String, HostEffectState>,
}

impl EffectStateLog {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(|e| format!("effect log open {}: {e}", path.display()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("effect log read {}: {e}", path.display()))?;
        let mut states = std::collections::HashMap::new();
        let mut offset = 0usize;
        let mut good_end = 0usize;
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            let line_start = offset;
            offset += line.len();
            let text = match std::str::from_utf8(line) {
                Ok(t) => t.trim_end_matches(['\n', '\r']),
                Err(_) => break, // torn non-UTF8 tail: truncate below
            };
            if text.is_empty() {
                good_end = offset;
                continue;
            }
            let rec: EffectFileRecord = match serde_json::from_str(text) {
                Ok(r) => r,
                Err(_) => {
                    let torn_tail = offset >= bytes.len() && !line.ends_with(b"\n");
                    if torn_tail {
                        break;
                    }
                    return Err(format!(
                        "effect log {}: unparseable record at byte {line_start}: \
                         corruption — refusing to load",
                        path.display()
                    ));
                }
            };
            match rec.op.as_str() {
                "reserve" => match states.get(&rec.key) {
                    Some(HostEffectState::Proven { .. }) => {
                        return Err(format!(
                            "effect log {}: reserve replay for already-proven key {}",
                            path.display(),
                            rec.key
                        ));
                    }
                    _ => {
                        states.entry(rec.key).or_insert(HostEffectState::Unknown {
                            reserved_ms: rec.reserved_ms,
                        });
                    }
                },
                "confirm" => {
                    let receipt = rec.receipt.ok_or_else(|| {
                        format!(
                            "effect log {}: confirm record without receipt for key {}",
                            path.display(),
                            rec.key
                        )
                    })?;
                    match states.get(&rec.key) {
                        None => {
                            return Err(format!(
                                "effect log {}: confirm replay for never-reserved key {}",
                                path.display(),
                                rec.key
                            ));
                        }
                        Some(HostEffectState::Proven { result_digest, .. })
                            if *result_digest != receipt.result_digest =>
                        {
                            return Err(format!(
                                "effect log {}: conflicting confirm for key {}",
                                path.display(),
                                rec.key
                            ));
                        }
                        Some(HostEffectState::Proven { .. }) => {}
                        Some(HostEffectState::Unknown { .. }) => {
                            states.insert(
                                rec.key.clone(),
                                HostEffectState::Proven {
                                    result_digest: receipt.result_digest,
                                    provider_id: rec.provider_id,
                                },
                            );
                        }
                    }
                }
                other => {
                    return Err(format!(
                        "effect log {}: unknown record op {other:?} at byte {line_start}",
                        path.display()
                    ));
                }
            }
            good_end = offset;
        }
        if good_end < bytes.len() {
            file.set_len(good_end as u64)
                .map_err(|e| format!("effect log truncate {}: {e}", path.display()))?;
            file.sync_all()
                .map_err(|e| format!("effect log fsync after truncate {}: {e}", path.display()))?;
        }
        file.seek(SeekFrom::End(0))
            .map_err(|e| format!("effect log seek {}: {e}", path.display()))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            states,
        })
    }

    fn append_record(&mut self, line: &str) -> Result<(), String> {
        self.file
            .write_all(line.as_bytes())
            .map_err(|e| format!("effect log write {}: {e}", self.path.display()))?;
        self.file
            .sync_all()
            .map_err(|e| format!("effect log fsync {}: {e}", self.path.display()))?;
        Ok(())
    }

    /// Reserve intent durably before an outbound effect. Re-reserving an
    /// UNKNOWN key is a no-op returning its existing state; reserving a
    /// PROVEN key returns the proven state (do not re-execute). If the
    /// fsync'd append fails, NO reservation is recorded in memory: the
    /// caller must not send, because a crash would leave no UNKNOWN
    /// marker to reconcile against.
    pub fn reserve(
        &mut self,
        key: &str,
        reserved_ms: u64,
    ) -> Result<HostEffectState, String> {
        match self.states.get(key) {
            Some(s) => Ok(s.clone()),
            None => {
                let line = serde_json::json!({
                    "op": "reserve", "key": key, "reserved_ms": reserved_ms,
                })
                .to_string()
                    + "\n";
                self.append_record(&line)?;
                let s = HostEffectState::Unknown { reserved_ms };
                self.states.insert(key.to_string(), s.clone());
                Ok(s)
            }
        }
    }

    /// Confirm (reconcile) an UNKNOWN effect with the provider's digest.
    /// Refuses unreserved keys and conflicting digests. Same digest over
    /// a PROVEN key is an idempotent no-op.
    pub fn confirm(
        &mut self,
        key: &str,
        result_digest: &str,
        provider_id: Option<&str>,
    ) -> Result<HostEffectState, String> {
        match self.states.get(key) {
            None => Err(format!(
                "cannot confirm effect {key} that was never reserved"
            )),
            Some(HostEffectState::Proven {
                result_digest: prev,
                ..
            }) if prev != result_digest => Err(format!(
                "conflicting confirm for key {key}: first digest wins"
            )),
            Some(HostEffectState::Proven { .. }) => {
                Ok(self.states.get(key).unwrap().clone())
            }
            Some(HostEffectState::Unknown { .. }) => {
                let line = serde_json::json!({
                    "op": "confirm", "key": key,
                    "receipt": { "result_digest": result_digest },
                    "provider_id": provider_id,
                })
                .to_string()
                    + "\n";
                self.append_record(&line)?;
                let s = HostEffectState::Proven {
                    result_digest: result_digest.to_string(),
                    provider_id: provider_id.map(|p| p.to_string()),
                };
                self.states.insert(key.to_string(), s.clone());
                Ok(s)
            }
        }
    }

    pub fn state(&self, key: &str) -> Option<&HostEffectState> {
        self.states.get(key)
    }
}

/// Scan the log, validate every record, truncate a torn tail. Returns the
/// recovered receipts in file order. Any fully-written record that fails
/// to parse or fails integrity checks is an `Err` (fail-closed): it is
/// corruption, not a crash artifact.
fn scan_and_repair(file: &File, path: &Path) -> Result<Recovery, String> {
    let mut f = file;
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut pos: u64 = 0;
    let mut expected_prev = "GENESIS".to_string();
    let mut expected_seq_min: u64 = 0; // seq must be strictly increasing

    loop {
        let record_start = pos;
        // -- magic --
        let mut magic = [0u8; 4];
        match read_exact_tracked(&mut f, &mut magic, &mut pos) {
            Ok(()) => {}
            Err(Tracked::Eof { partial }) => {
                if partial > 0 {
                    // Torn magic: crash mid-append. Truncate to the last
                    // good record boundary.
                    let before = file_len(file, path)?;
                    truncate_to(file, path, record_start)?;
                    let dropped = before - record_start;
                    return Ok(Recovery {
                        outcome: RecoveryOutcome::Repaired {
                            count: receipts.len(),
                            dropped_tail_bytes: dropped,
                        },
                        receipts,
                    });
                }
                break; // clean EOF on a record boundary
            }
            Err(Tracked::Io(e)) => {
                return Err(format!("receipt log read {}: {e}", path.display()))
            }
        }
        if &magic != LOG_MAGIC {
            return Err(format!(
                "receipt log {}: bad record magic at offset {record_start} \
                 (expected ORL1): corruption — refusing to load",
                path.display()
            ));
        }
        // -- length --
        let mut lenb = [0u8; 8];
        match read_exact_tracked(&mut f, &mut lenb, &mut pos) {
            Ok(()) => {}
            Err(Tracked::Eof { .. }) => {
                let before = file_len(file, path)?;
                truncate_to(file, path, record_start)?;
                let dropped = before - record_start;
                return Ok(Recovery {
                    outcome: RecoveryOutcome::Repaired {
                        count: receipts.len(),
                        dropped_tail_bytes: dropped,
                    },
                    receipts,
                });
            }
            Err(Tracked::Io(e)) => {
                return Err(format!("receipt log read {}: {e}", path.display()))
            }
        }
        let len = u64::from_le_bytes(lenb);
        if len == 0 || len > MAX_RECORD_BYTES {
            return Err(format!(
                "receipt log {}: impossible record length {len} at offset {record_start}: \
                 corruption — refusing to load",
                path.display()
            ));
        }
        // -- body --
        let mut body = vec![0u8; len as usize];
        match read_exact_tracked(&mut f, &mut body, &mut pos) {
            Ok(()) => {}
            Err(Tracked::Eof { .. }) => {
                // Torn body: the classic crash-mid-append. Truncate.
                let before = file_len(file, path)?;
                truncate_to(file, path, record_start)?;
                let dropped = before - record_start;
                return Ok(Recovery {
                    outcome: RecoveryOutcome::Repaired {
                        count: receipts.len(),
                        dropped_tail_bytes: dropped,
                    },
                    receipts,
                });
            }
            Err(Tracked::Io(e)) => {
                return Err(format!("receipt log read {}: {e}", path.display()))
            }
        }
        // A complete record that does not parse is corruption, not a crash
        // artifact: fail closed.
        let r: Receipt = serde_json::from_slice(&body).map_err(|e| {
            format!(
                "receipt log {}: complete record at offset {record_start} does not parse \
                 ({e}): corruption — refusing to load",
                path.display()
            )
        })?;
        if r.compute_id() != r.id {
            return Err(format!(
                "receipt log {}: record at offset {record_start} (seq {}) fails id \
                 recomputation: corruption — refusing to load",
                path.display(),
                r.seq
            ));
        }
        if r.prev != expected_prev {
            return Err(format!(
                "receipt log {}: chain break at offset {record_start} (seq {}): \
                 corruption — refusing to load",
                path.display(),
                r.seq
            ));
        }
        if r.seq <= expected_seq_min {
            return Err(format!(
                "receipt log {}: non-monotonic seq {} at offset {record_start}: \
                 corruption — refusing to load",
                path.display(),
                r.seq
            ));
        }
        expected_prev = r.id.clone();
        expected_seq_min = r.seq;
        receipts.push(r);
    }

    let outcome = if receipts.is_empty() {
        RecoveryOutcome::Fresh
    } else {
        RecoveryOutcome::Loaded {
            count: receipts.len(),
        }
    };
    Ok(Recovery { receipts, outcome })
}

enum Tracked {
    /// Hit EOF; `partial` bytes were read before it.
    Eof { partial: usize },
    Io(std::io::Error),
}

/// `read_exact`, but distinguishes "clean EOF before any byte" (Ok with
/// partial=0 is impossible — read_exact either fills or errors) from I/O
/// errors, and tracks the file position.
fn read_exact_tracked(f: &mut &File, buf: &mut [u8], pos: &mut u64) -> Result<(), Tracked> {
    let mut read = 0;
    while read < buf.len() {
        match f.read(&mut buf[read..]) {
            Ok(0) => return Err(Tracked::Eof { partial: read }),
            Ok(n) => {
                read += n;
                *pos += n as u64;
            }
            Err(e) => return Err(Tracked::Io(e)),
        }
    }
    Ok(())
}

fn truncate_to(file: &File, path: &Path, len: u64) -> Result<(), String> {
    file.set_len(len)
        .map_err(|e| format!("receipt log truncate {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("receipt log fsync after truncate {}: {e}", path.display()))?;
    Ok(())
}

fn file_len(file: &File, path: &Path) -> Result<u64, String> {
    file.metadata()
        .map(|m| m.len())
        .map_err(|e| format!("receipt log stat {}: {e}", path.display()))
}

#[cfg(test)]
mod effect_state_tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lucidota-host-effects-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{tag}.jsonl"))
    }

    #[test]
    fn crash_recovery_reconciles_instead_of_repeating() {
        let path = tmp_path("crash");
        let _ = std::fs::remove_file(&path);
        {
            let mut log = EffectStateLog::open(&path).unwrap();
            // Reserve durably before the (simulated) send; then crash:
            // drop without confirm.
            assert_eq!(
                log.reserve("ext:send-123", 1000).unwrap(),
                HostEffectState::Unknown { reserved_ms: 1000 }
            );
        }
        let mut log = EffectStateLog::open(&path).unwrap();
        // After restart: UNKNOWN, not absent (absent would invite a
        // blind re-send) and not proven.
        assert_eq!(
            log.state("ext:send-123"),
            Some(&HostEffectState::Unknown { reserved_ms: 1000 })
        );
        // Reconcile with the provider's digest instead of re-sending.
        let proven = log
            .confirm("ext:send-123", "sha256:provider-receipt", Some("provider:msg-123"))
            .unwrap();
        assert_eq!(
            proven,
            HostEffectState::Proven {
                result_digest: "sha256:provider-receipt".to_string(),
                provider_id: Some("provider:msg-123".to_string()),
            }
        );
        // Blind retry with a different digest is refused.
        assert!(log
            .confirm("ext:send-123", "sha256:second-send", None)
            .is_err());
        // Confirming a never-reserved key is refused.
        assert!(log.confirm("never-reserved", "sha256:x", None).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reads_dispatch_schema_records() {
        // The dispatch writer's records carry extra fields (effect kind,
        // task id, attempt, full receipt object); the host reader must
        // replay them from the SAME file without choking on extras.
        let path = tmp_path("dispatch-schema");
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            "{\"op\":\"reserve\",\"key\":\"ext:1\",\"effect\":\"EXTERNAL_POST\",\"task_id\":\"T001\",\"attempt\":1,\"reserved_ms\":42}\n\
             {\"op\":\"confirm\",\"key\":\"ext:1\",\"receipt\":{\"key\":\"ext:1\",\"effect\":\"EXTERNAL_POST\",\"task_id\":\"T001\",\"attempt\":1,\"performed_ms\":43,\"result_digest\":\"sha256:abc\"},\"provider_id\":\"provider:1\"}\n",
        )
        .unwrap();
        let log = EffectStateLog::open(&path).unwrap();
        assert_eq!(
            log.state("ext:1"),
            Some(&HostEffectState::Proven {
                result_digest: "sha256:abc".to_string(),
                provider_id: Some("provider:1".to_string()),
            })
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn torn_tail_truncated_on_reopen() {
        let path = tmp_path("torn");
        let _ = std::fs::remove_file(&path);
        {
            let mut log = EffectStateLog::open(&path).unwrap();
            log.reserve("torn:1", 7).unwrap();
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"op\":\"reserve\",\"key\":\"tor").unwrap();
            f.sync_all().unwrap();
        }
        let log = EffectStateLog::open(&path).unwrap();
        assert_eq!(
            log.state("torn:1"),
            Some(&HostEffectState::Unknown { reserved_ms: 7 })
        );
        let _ = std::fs::remove_file(&path);
    }
}
