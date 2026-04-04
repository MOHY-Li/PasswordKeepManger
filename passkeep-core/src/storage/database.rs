//! Database operations

use crate::models::VaultMetadata;
use crate::storage::error::PassKeepError;
use crate::storage::lock_state::LockState;
use rusqlite::{Connection, Result as SqliteResult};
use std::path::Path;

// 嵌入 schema.sql
const SCHEMA_SQL: &str = include_str!("schema.sql");

/// The main database interface
pub struct Database {
    pub conn: Connection,
}

impl Database {
    /// Create a new database
    pub fn create(path: &Path) -> Result<Self, PassKeepError> {
        let conn = Connection::open(path)?;

        // Enable WAL mode (query_row because PRAGMA returns values)
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute("PRAGMA foreign_keys=ON", [])?;

        // Execute schema
        conn.execute_batch(SCHEMA_SQL)?;

        // Set busy timeout after schema (PRAGMA busy_timeout returns a value)
        let _: i64 = conn.query_row("PRAGMA busy_timeout=5000", [], |row| row.get(0))?;

        // Initialize schema migration version using prepare to handle return value properly
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        {
            let mut stmt = conn.prepare(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, ?1)",
            )?;
            stmt.execute([now])?;
        } // Drop stmt before moving conn

        // Apply v2 migration
        crate::storage::migrations::apply_v2_migration(&conn)?;

        Ok(Self { conn })
    }

    /// Open an existing database
    pub fn open(path: &Path) -> Result<Self, PassKeepError> {
        let conn = Connection::open(path)?;
        conn.execute("PRAGMA foreign_keys=ON", [])?;

        // Apply any pending migrations
        crate::storage::migrations::apply_v2_migration(&conn)?;

        Ok(Self { conn })
    }

    /// Read vault metadata
    pub fn get_vault_metadata(&self) -> SqliteResult<VaultMetadata> {
        self.conn.query_row(
            "SELECT version, kdf_salt, kdf_mem_cost, kdf_time_cost, kdf_parallelism, created_at, updated_at FROM vault_metadata WHERE id = 1",
            [],
            |row| {
                let salt_bytes: Vec<u8> = row.get(1)?;
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&salt_bytes[..salt_bytes.len().min(32)]);

                Ok(VaultMetadata {
                    version: row.get(0)?,
                    kdf_params: crate::crypto::KdfParams {
                        salt,
                        mem_cost_kib: row.get(2)?,
                        time_cost: row.get(3)?,
                        parallelism: row.get(4)?,
                    },
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                    entry_count: 0, // TODO: Count from entries table
                })
            },
        )
    }

    /// Check if the database is locked
    pub fn is_locked(&self) -> Result<bool, PassKeepError> {
        // Try to execute a simple query to check if database is accessible
        match self
            .conn
            .query_row("SELECT 1", [], |_: &rusqlite::Row| Ok(()))
        {
            Ok(_) => Ok(false),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::DatabaseBusy =>
            {
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Get the current lock state from the database
    pub fn get_lock_state(&self) -> Result<LockState, PassKeepError> {
        self.conn
            .query_row(
                "SELECT failed_attempts, lock_until, last_attempt_at FROM vault_metadata WHERE id = 1",
                [],
                |row| {
                    Ok(LockState {
                        failed_attempts: row.get(0)?,
                        lock_until: row.get(1)?,
                        // Use current time if last_attempt_at is NULL
                        last_attempt_at: match row.get::<_, Option<i64>>(2)? {
                            Some(t) => t,
                            None => {
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs() as i64
                            }
                        },
                    })
                },
            )
            .map_err(|_| PassKeepError::DatabaseCorrupted)
    }

    /// Save the lock state to the database
    pub fn save_lock_state(&self, state: &LockState) -> Result<(), PassKeepError> {
        self.conn
            .execute(
                "UPDATE vault_metadata SET failed_attempts = ?1, lock_until = ?2, last_attempt_at = ?3 WHERE id = 1",
                (state.failed_attempts, state.lock_until, state.last_attempt_at),
            )
            .map_err(|_| PassKeepError::LockStateUpdateFailed)?;
        Ok(())
    }

    /// Get KDF parameters from vault metadata
    pub fn get_kdf_params(&self) -> Result<crate::crypto::KdfParams, PassKeepError> {
        self.conn
            .query_row(
                "SELECT kdf_salt, kdf_mem_cost, kdf_time_cost, kdf_parallelism FROM vault_metadata WHERE id = 1",
                [],
                |row| {
                    let salt_bytes: Vec<u8> = row.get(0)?;
                    let mut salt = [0u8; 32];
                    salt.copy_from_slice(&salt_bytes[..salt_bytes.len().min(32)]);

                    Ok(crate::crypto::KdfParams {
                        salt,
                        mem_cost_kib: row.get(1)?,
                        time_cost: row.get(2)?,
                        parallelism: row.get(3)?,
                    })
                },
            )
            .map_err(|_| PassKeepError::DatabaseCorrupted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_create_database() {
        let temp = NamedTempFile::new().unwrap();
        let db = Database::create(temp.path()).unwrap();

        // Verify tables exist
        let table_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(table_count, 5); // vault_metadata, entries, folders, master_key_check, schema_migrations
    }

    #[test]
    fn test_database_is_not_locked_after_init() {
        let temp = NamedTempFile::new().unwrap();
        let db = Database::create(temp.path()).unwrap();

        // Database should not be locked after initialization
        assert!(!db.is_locked().unwrap());
    }

    #[test]
    fn test_open_existing_database() {
        let temp = NamedTempFile::new().unwrap();

        // Create database first
        Database::create(temp.path()).unwrap();

        // Open existing database
        let db = Database::open(temp.path()).unwrap();

        // Verify tables exist in opened database
        let table_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(table_count, 5);
    }

    #[test]
    fn test_indexes_created() {
        let temp = NamedTempFile::new().unwrap();
        let db = Database::create(temp.path()).unwrap();

        // Verify indexes exist
        let index_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(index_count, 5); // idx_entries_title, idx_entries_username, idx_entries_tags, idx_entries_folder, idx_folders_parent
    }

    #[test]
    fn test_triggers_created() {
        let temp = NamedTempFile::new().unwrap();
        let db = Database::create(temp.path()).unwrap();

        // Verify triggers exist
        let trigger_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(trigger_count, 4); // set_entries_timestamps, update_entries_timestamp, set_folders_timestamps, update_folders_timestamp
    }

    #[test]
    fn test_schema_migration_version() {
        let temp = NamedTempFile::new().unwrap();
        let db = Database::create(temp.path()).unwrap();

        // Verify schema version is set
        let version: i64 = db
            .conn
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(version, 1);
    }
}
