//! The SQLite storage backend (feature `sqlite`, native only):
//! one `registrations` table in one database file (or
//! `:memory:`).
//!
//! `insert_if_absent` is `INSERT OR IGNORE` keyed on the seal
//! primary key — the same statement shape the Exchange's
//! durable `seal_registry` table is written with — so the
//! first-vs-replay decision at the store layer is the
//! database's, not a check-then-insert the caller can race
//! across connections. All verdict logic lives in the core
//! over this trait, so this backend's answers are
//! byte-identical to the in-memory backend's (proven by test).

use crate::{Registration, RegistryError, Store};
use rusqlite::{params, Connection, OptionalExtension};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS registrations (
    seal          TEXT PRIMARY KEY,
    first_seen_ms INTEGER NOT NULL,
    presentations INTEGER NOT NULL
);
";

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Open (creating if needed) a database file and ensure
    /// the schema exists.
    pub fn open(path: &std::path::Path) -> Result<Self, RegistryError> {
        let conn = Connection::open(path)
            .map_err(|e| RegistryError::Store(format!("open {}: {e}", path.display())))?;
        Self::init(conn)
    }

    /// An in-memory database — the same code paths as the file
    /// backend, without durability.
    pub fn in_memory() -> Result<Self, RegistryError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| RegistryError::Store(format!("open in-memory: {e}")))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, RegistryError> {
        conn.execute_batch(SCHEMA)
            .map_err(|e| RegistryError::Store(format!("schema: {e}")))?;
        Ok(Self { conn })
    }
}

fn row_to_registration(row: &rusqlite::Row<'_>) -> rusqlite::Result<Registration> {
    let presentations: i64 = row.get(2)?;
    Ok(Registration {
        seal: row.get(0)?,
        first_seen_ms: row.get(1)?,
        presentations: presentations as u64,
    })
}

const COLUMNS: &str = "seal, first_seen_ms, presentations";

impl Store for SqliteStore {
    fn get(&mut self, seal: &str) -> Result<Option<Registration>, RegistryError> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM registrations WHERE seal = ?1"
            ))
            .map_err(|e| RegistryError::Store(format!("prepare: {e}")))?;
        let record = stmt
            .query_row(params![seal], row_to_registration)
            .optional()
            .map_err(|e| RegistryError::Store(format!("get: {e}")))?;
        Ok(record)
    }

    fn insert_if_absent(&mut self, record: &Registration) -> Result<bool, RegistryError> {
        let changed = self
            .conn
            .execute(
                &format!(
                    "INSERT OR IGNORE INTO registrations ({COLUMNS}) VALUES (?1, ?2, ?3)"
                ),
                params![record.seal, record.first_seen_ms, record.presentations as i64],
            )
            .map_err(|e| RegistryError::Store(format!("insert: {e}")))?;
        Ok(changed == 1)
    }

    fn update(&mut self, record: &Registration) -> Result<(), RegistryError> {
        self.conn
            .execute(
                "UPDATE registrations SET first_seen_ms = ?2, presentations = ?3 WHERE seal = ?1",
                params![record.seal, record.first_seen_ms, record.presentations as i64],
            )
            .map_err(|e| RegistryError::Store(format!("update: {e}")))?;
        Ok(())
    }

    fn remove(&mut self, seal: &str) -> Result<Option<Registration>, RegistryError> {
        let existing = self.get(seal)?;
        if existing.is_some() {
            self.conn
                .execute(
                    "DELETE FROM registrations WHERE seal = ?1",
                    params![seal],
                )
                .map_err(|e| RegistryError::Store(format!("delete: {e}")))?;
        }
        Ok(existing)
    }

    fn all(&mut self) -> Result<Vec<Registration>, RegistryError> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM registrations ORDER BY seal"
            ))
            .map_err(|e| RegistryError::Store(format!("prepare: {e}")))?;
        let rows = stmt
            .query_map([], row_to_registration)
            .map_err(|e| RegistryError::Store(format!("list: {e}")))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| RegistryError::Store(format!("row: {e}")))?);
        }
        Ok(out)
    }

    fn count(&mut self) -> Result<u64, RegistryError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM registrations", [], |row| row.get(0))
            .map_err(|e| RegistryError::Store(format!("count: {e}")))?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use crate::{seal_of, Registry, Retention};

    fn seal(tag: &str) -> String {
        seal_of(tag.as_bytes())
    }

    // Cross-backend determinism: the same scripted sequence
    // over the SQLite backend produces byte-identical output
    // to the in-memory backend.
    #[test]
    fn sqlite_backend_matches_memory_backend() {
        use crate::MemoryStore;
        let script: Vec<(String, i64)> = vec![
            (seal("one"), 0),
            (seal("two"), 10),
            (seal("one"), 20),
            (seal("three"), 30),
            (seal("two"), 40),
        ];
        // Registry<S> is generic over the backend; the same
        // script is run per backend and the serialized outputs
        // compared.
        let run_mem = {
            let mut r = Registry::new(
                MemoryStore::new(),
                Retention::new(Some(100), Some(3)).unwrap(),
            );
            script
                .iter()
                .map(|(s, t)| serde_json::to_string(&r.present(s, *t).unwrap()).unwrap())
                .collect::<Vec<_>>()
        };
        let mut sql = Registry::new(
            super::SqliteStore::in_memory().unwrap(),
            Retention::new(Some(100), Some(3)).unwrap(),
        );
        let run_sql: Vec<String> = script
            .iter()
            .map(|(s, t)| serde_json::to_string(&sql.present(s, *t).unwrap()).unwrap())
            .collect();
        assert_eq!(run_mem, run_sql);
    }

    // Durability + the capacity arm over a shared file: a
    // store populated under unbounded retention, reopened
    // under a capacity of 2, sweeps exactly the oldest two —
    // and the surviving registrations kept their original
    // first-seen instants across the reopen.
    #[test]
    fn sqlite_shared_file_capacity_sweep() {
        let path = std::env::temp_dir().join(format!(
            "ref-replay-registry-test-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let seals: Vec<String> = (0..4).map(|i| seal(&format!("file-{i}"))).collect();
        {
            let mut r = Registry::new(
                super::SqliteStore::open(&path).unwrap(),
                Retention::unbounded(),
            );
            for (i, s) in seals.iter().enumerate() {
                assert!(r.present(s, (i as i64) * 10).unwrap().is_first());
            }
            assert!(r.present(&seals[0], 999).unwrap().is_replay());
        }
        {
            let mut r = Registry::new(
                super::SqliteStore::open(&path).unwrap(),
                Retention::new(None, Some(2)).unwrap(),
            );
            // State survived the reopen, replay counts included.
            let held = r.check(&seals[0]).unwrap().unwrap();
            assert_eq!(held.first_seen_ms, 0);
            assert_eq!(held.presentations, 2);
            let evicted = r.sweep(1_000).unwrap();
            let evicted_seals: Vec<&str> =
                evicted.iter().map(|x| x.seal.as_str()).collect();
            assert_eq!(
                evicted_seals,
                vec![seals[0].as_str(), seals[1].as_str()],
                "oldest two evicted, in (first_seen, seal) order"
            );
            assert_eq!(r.stats().unwrap().count, 2);
        }
        let _ = std::fs::remove_file(&path);
    }
}
