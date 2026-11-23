//! The SQLite storage backend (feature `sqlite`, native only):
//! one `items` table in one database file (or `:memory:`).
//!
//! Atomicity: [`Store::cas`] is a single conditional
//! `UPDATE ... WHERE id = ? AND version = ?` and the write counts
//! only when exactly one row changed — atomic at the database
//! level, so two processes (or two queue instances) sharing one
//! file still get single-winner claims.  Inserts assign `seq`
//! from `MAX(seq) + 1` inside the same statement, keeping FIFO
//! order total across writers.

use crate::{Item, ItemState, QueueError, Store};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS items (
    id              TEXT PRIMARY KEY,
    idem_key        TEXT UNIQUE,
    payload         TEXT NOT NULL,
    state           TEXT NOT NULL,
    attempts        INTEGER NOT NULL,
    version         INTEGER NOT NULL,
    seq             INTEGER NOT NULL,
    enqueued_at_ms  INTEGER NOT NULL,
    available_at_ms INTEGER NOT NULL,
    lease_id        TEXT,
    claimant        TEXT,
    claimed_at_ms   INTEGER,
    expires_at_ms   INTEGER,
    result          TEXT,
    last_error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_items_seq ON items(seq);
CREATE INDEX IF NOT EXISTS idx_items_lease ON items(lease_id);
";

const COLUMNS: &str = "id, idem_key, payload, state, attempts, version, seq, \
    enqueued_at_ms, available_at_ms, lease_id, claimant, claimed_at_ms, \
    expires_at_ms, result, last_error";

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Open (creating if needed) a database file and ensure the
    /// schema exists.
    pub fn open(path: &std::path::Path) -> Result<Self, QueueError> {
        let conn = Connection::open(path)
            .map_err(|e| QueueError::Store(format!("open {}: {e}", path.display())))?;
        Self::init(conn)
    }

    /// An in-memory database — the same code paths as the file
    /// backend, without durability.
    pub fn in_memory() -> Result<Self, QueueError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| QueueError::Store(format!("open in-memory: {e}")))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, QueueError> {
        conn.execute_batch(SCHEMA)
            .map_err(|e| QueueError::Store(format!("schema: {e}")))?;
        Ok(Self { conn })
    }
}

fn state_to_str(state: ItemState) -> String {
    serde_json::to_value(state)
        .expect("state serializes")
        .as_str()
        .expect("state is a string")
        .to_string()
}

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<Item> {
    let payload_s: String = row.get(2)?;
    let state_s: String = row.get(3)?;
    let result_s: Option<String> = row.get(13)?;
    let lease = match (row.get::<_, Option<String>>(9)?, row.get::<_, Option<String>>(10)?) {
        (Some(lease_id), Some(claimant)) => Some(crate::Lease {
            lease_id,
            claimant,
            claimed_at_ms: row.get::<_, Option<i64>>(11)?.unwrap_or(0),
            expires_at_ms: row.get::<_, Option<i64>>(12)?.unwrap_or(0),
        }),
        _ => None,
    };
    Ok(Item {
        id: row.get(0)?,
        idempotency_key: row.get(1)?,
        payload: serde_json::from_str(&payload_s).unwrap_or(Value::Null),
        state: serde_json::from_value(Value::String(state_s)).unwrap_or(ItemState::Queued),
        attempts: row.get::<_, i64>(4)? as u32,
        version: row.get::<_, i64>(5)? as u64,
        seq: row.get::<_, i64>(6)? as u64,
        enqueued_at_ms: row.get(7)?,
        available_at_ms: row.get(8)?,
        lease,
        result: result_s.map(|s| serde_json::from_str(&s).unwrap_or(Value::Null)),
        last_error: row.get(14)?,
    })
}

fn json_text(value: &Value) -> String {
    serde_json::to_string(value).expect("payload values are always serializable")
}

impl Store for SqliteStore {
    fn insert(&mut self, item: Item) -> Result<Item, QueueError> {
        let seq: i64 = self
            .conn
            .query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM items", [], |r| {
                r.get(0)
            })
            .map_err(|e| QueueError::Store(format!("seq: {e}")))?;
        let mut stored = item.clone();
        stored.seq = seq as u64;
        let lease = stored.lease.clone();
        self.conn
            .execute(
                &format!("INSERT INTO items ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"),
                params![
                    stored.id,
                    stored.idempotency_key,
                    json_text(&stored.payload),
                    state_to_str(stored.state),
                    i64::from(stored.attempts),
                    stored.version as i64,
                    seq,
                    stored.enqueued_at_ms,
                    stored.available_at_ms,
                    lease.as_ref().map(|l| l.lease_id.clone()),
                    lease.as_ref().map(|l| l.claimant.clone()),
                    lease.as_ref().map(|l| l.claimed_at_ms),
                    lease.as_ref().map(|l| l.expires_at_ms),
                    stored.result.as_ref().map(json_text),
                    stored.last_error,
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(ref ffi, _)
                    if ffi.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    QueueError::DuplicateId(stored.id.clone())
                }
                other => QueueError::Store(format!("insert: {other}")),
            })?;
        Ok(stored)
    }

    fn get(&mut self, id: &str) -> Result<Option<Item>, QueueError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM items WHERE id = ?1"),
                params![id],
                row_to_item,
            )
            .optional()
            .map_err(|e| QueueError::Store(format!("get: {e}")))
    }

    fn get_by_idempotency_key(&mut self, key: &str) -> Result<Option<Item>, QueueError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM items WHERE idem_key = ?1"),
                params![key],
                row_to_item,
            )
            .optional()
            .map_err(|e| QueueError::Store(format!("get_by_idempotency_key: {e}")))
    }

    fn list(&mut self) -> Result<Vec<Item>, QueueError> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {COLUMNS} FROM items ORDER BY seq ASC"))
            .map_err(|e| QueueError::Store(format!("list prepare: {e}")))?;
        let rows = stmt
            .query_map([], row_to_item)
            .map_err(|e| QueueError::Store(format!("list: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| QueueError::Store(format!("list row: {e}")))?);
        }
        Ok(out)
    }

    fn cas(&mut self, expected_version: u64, item: Item) -> Result<bool, QueueError> {
        if item.version != expected_version + 1 {
            return Ok(false);
        }
        let lease = item.lease.clone();
        let changed = self
            .conn
            .execute(
                "UPDATE items SET idem_key = ?2, payload = ?3, state = ?4, attempts = ?5, \
                 version = ?6, seq = ?7, enqueued_at_ms = ?8, available_at_ms = ?9, \
                 lease_id = ?10, claimant = ?11, claimed_at_ms = ?12, expires_at_ms = ?13, \
                 result = ?14, last_error = ?15 \
                 WHERE id = ?1 AND version = ?16",
                params![
                    item.id,
                    item.idempotency_key,
                    json_text(&item.payload),
                    state_to_str(item.state),
                    i64::from(item.attempts),
                    item.version as i64,
                    item.seq as i64,
                    item.enqueued_at_ms,
                    item.available_at_ms,
                    lease.as_ref().map(|l| l.lease_id.clone()),
                    lease.as_ref().map(|l| l.claimant.clone()),
                    lease.as_ref().map(|l| l.claimed_at_ms),
                    lease.as_ref().map(|l| l.expires_at_ms),
                    item.result.as_ref().map(json_text),
                    item.last_error,
                    expected_version as i64,
                ],
            )
            .map_err(|e| QueueError::Store(format!("cas: {e}")))?;
        Ok(changed == 1)
    }

    fn remove(&mut self, id: &str) -> Result<bool, QueueError> {
        let changed = self
            .conn
            .execute("DELETE FROM items WHERE id = ?1", params![id])
            .map_err(|e| QueueError::Store(format!("remove: {e}")))?;
        Ok(changed == 1)
    }
}
