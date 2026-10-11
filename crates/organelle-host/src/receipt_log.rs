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
