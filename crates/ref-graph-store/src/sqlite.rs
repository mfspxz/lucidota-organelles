//! The SQLite storage backend (feature `sqlite`, native only):
//! `assertions` and `nodes` tables in one database file (or
//! `:memory:`).
//!
//! Terms and states are stored as their canonical JSON strings,
//! so a row round-trips to exactly the assertion that was
//! asserted — the backend adds no representation of its own.
//! Query logic lives in the core over the full, id-sorted
//! assertion set, so this backend's answers are byte-identical
//! to the in-memory backend's (proven by test).

use crate::{Assertion, GraphError, NodeDecl, Store};
use rusqlite::{params, Connection, OptionalExtension};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS assertions (
    id            TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    predicate     TEXT NOT NULL,
    object        TEXT NOT NULL,
    state         TEXT NOT NULL,
    provenance    TEXT NOT NULL,
    valid_from_ms INTEGER,
    valid_to_ms   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_assertions_predicate ON assertions(predicate);
CREATE INDEX IF NOT EXISTS idx_assertions_provenance ON assertions(provenance);
CREATE TABLE IF NOT EXISTS nodes (
    id     TEXT PRIMARY KEY,
    class  TEXT NOT NULL,
    traits TEXT NOT NULL
);
";

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Open (creating if needed) a database file and ensure the
    /// schema exists.
    pub fn open(path: &std::path::Path) -> Result<Self, GraphError> {
        let conn = Connection::open(path)
            .map_err(|e| GraphError::Store(format!("open {}: {e}", path.display())))?;
        Self::init(conn)
    }

    /// An in-memory database — the same code paths as the file
    /// backend, without durability.
    pub fn in_memory() -> Result<Self, GraphError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| GraphError::Store(format!("open in-memory: {e}")))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, GraphError> {
        conn.execute_batch(SCHEMA)
            .map_err(|e| GraphError::Store(format!("schema: {e}")))?;
        Ok(Self { conn })
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<String, GraphError> {
    serde_json::to_string(v).map_err(|e| GraphError::Store(format!("serialize: {e}")))
}

fn row_to_assertion(row: &rusqlite::Row<'_>) -> rusqlite::Result<Assertion> {
    let subject_s: String = row.get(1)?;
    let object_s: String = row.get(3)?;
    let state_s: String = row.get(4)?;
    Ok(Assertion {
        id: row.get(0)?,
        subject: serde_json::from_str(&subject_s)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        predicate: row.get(2)?,
        object: serde_json::from_str(&object_s)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        state: serde_json::from_str(&format!("\"{state_s}\""))
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        provenance: row.get(5)?,
        valid_from_ms: row.get(6)?,
        valid_to_ms: row.get(7)?,
    })
}

const ASSERTION_COLUMNS: &str =
    "id, subject, predicate, object, state, provenance, valid_from_ms, valid_to_ms";

impl Store for SqliteStore {
    fn put_assertion(&mut self, assertion: Assertion) -> Result<Assertion, GraphError> {
        if let Some(existing) = self.get_assertion(&assertion.id)? {
            return Ok(existing);
        }
        let state = serde_json::to_value(assertion.state)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        self.conn
            .execute(
                &format!("INSERT INTO assertions ({ASSERTION_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
                params![
                    assertion.id,
                    to_json(&assertion.subject)?,
                    assertion.predicate,
                    to_json(&assertion.object)?,
                    state,
                    assertion.provenance,
                    assertion.valid_from_ms,
                    assertion.valid_to_ms,
                ],
            )
            .map_err(|e| GraphError::Store(format!("insert assertion: {e}")))?;
        Ok(assertion)
    }

    fn get_assertion(&mut self, id: &str) -> Result<Option<Assertion>, GraphError> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {ASSERTION_COLUMNS} FROM assertions WHERE id = ?1"
            ))
            .map_err(|e| GraphError::Store(format!("prepare: {e}")))?;
        let a = stmt
            .query_row(params![id], row_to_assertion)
            .optional()
            .map_err(|e| GraphError::Store(format!("get assertion: {e}")))?;
        Ok(a)
    }

    fn assertions(&mut self) -> Result<Vec<Assertion>, GraphError> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {ASSERTION_COLUMNS} FROM assertions ORDER BY id"
            ))
            .map_err(|e| GraphError::Store(format!("prepare: {e}")))?;
        let rows = stmt
            .query_map([], row_to_assertion)
            .map_err(|e| GraphError::Store(format!("list assertions: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| GraphError::Store(format!("row: {e}")))?);
        }
        Ok(out)
    }

    fn put_node(&mut self, node: NodeDecl) -> Result<NodeDecl, GraphError> {
        self.conn
            .execute(
                "INSERT INTO nodes (id, class, traits) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET class = excluded.class, traits = excluded.traits",
                params![node.id, node.class, to_json(&node.traits)?],
            )
            .map_err(|e| GraphError::Store(format!("insert node: {e}")))?;
        Ok(node)
    }

    fn get_node(&mut self, id: &str) -> Result<Option<NodeDecl>, GraphError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, class, traits FROM nodes WHERE id = ?1")
            .map_err(|e| GraphError::Store(format!("prepare: {e}")))?;
        let node = stmt
            .query_row(params![id], |row| {
                let traits_s: String = row.get(2)?;
                Ok(NodeDecl {
                    id: row.get(0)?,
                    class: row.get(1)?,
                    traits: serde_json::from_str(&traits_s).map_err(|e| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                    })?,
                })
            })
            .optional()
            .map_err(|e| GraphError::Store(format!("get node: {e}")))?;
        Ok(node)
    }

    fn nodes(&mut self) -> Result<Vec<NodeDecl>, GraphError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, class, traits FROM nodes ORDER BY id")
            .map_err(|e| GraphError::Store(format!("prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                let traits_s: String = row.get(2)?;
                Ok(NodeDecl {
                    id: row.get(0)?,
                    class: row.get(1)?,
                    traits: serde_json::from_str(&traits_s).map_err(|e| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                    })?,
                })
            })
            .map_err(|e| GraphError::Store(format!("list nodes: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| GraphError::Store(format!("row: {e}")))?);
        }
        Ok(out)
    }
}
