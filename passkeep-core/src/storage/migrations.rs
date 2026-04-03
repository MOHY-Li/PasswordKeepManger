//! Database schema migrations

use crate::storage::error::PassKeepError;
use rusqlite::Connection;

// 嵌入 schema_v2.sql
const V2_SCHEMA_SQL: &str = include_str!("schema_v2.sql");

/// Apply v2 migration to add nonce columns and lock state fields
pub fn apply_v2_migration(conn: &Connection) -> Result<(), PassKeepError> {
    // 检查是否已应用 v2 迁移
    let version: i64 = conn
        .query_row(
            "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or(1);

    if version >= 2 {
        return Ok(());
    }

    // 应用迁移
    conn.execute_batch(V2_SCHEMA_SQL)
        .map_err(|_e| PassKeepError::DatabaseCorrupted)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use tempfile::NamedTempFile;

    // Helper to set up a v1 database for migration testing
    fn setup_v1_database(conn: &Connection) {
        // Create v1 schema (without v2 columns)
        conn.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    kdf_salt BLOB NOT NULL,
    kdf_mem_cost INTEGER NOT NULL,
    kdf_time_cost INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    username TEXT NOT NULL,
    password_encrypted BLOB NOT NULL,
    url_preview TEXT NOT NULL,
    url_encrypted BLOB,
    notes_encrypted BLOB,
    nonce BLOB NOT NULL UNIQUE,
    folder_id TEXT,
    tags TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT,
    parent_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS master_key_check (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value_encrypted BLOB NOT NULL,
    nonce BLOB NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

-- Insert initial migration version
INSERT INTO schema_migrations (version, applied_at) VALUES (1, 1000000);
"#,
        )
        .unwrap();
    }

    #[test]
    fn test_apply_v2_migration_adds_nonce_columns() {
        let temp = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp.path()).unwrap();

        // Set up v1 database
        setup_v1_database(&conn);

        // Apply v2 migration
        apply_v2_migration(&conn).unwrap();

        // Verify new nonce columns exist in entries table
        let columns: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('entries') ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert!(columns.contains(&"password_nonce".to_string()));
        assert!(columns.contains(&"url_nonce".to_string()));
        assert!(columns.contains(&"notes_nonce".to_string()));
    }

    #[test]
    fn test_apply_v2_migration_adds_lock_state_columns() {
        let temp = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp.path()).unwrap();

        // Set up v1 database
        setup_v1_database(&conn);

        // Apply v2 migration
        apply_v2_migration(&conn).unwrap();

        // Verify lock state columns exist in vault_metadata table
        let columns: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('vault_metadata') ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert!(columns.contains(&"failed_attempts".to_string()));
        assert!(columns.contains(&"lock_until".to_string()));
        assert!(columns.contains(&"last_attempt_at".to_string()));
    }

    #[test]
    fn test_apply_v2_migration_sets_default_values() {
        let temp = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp.path()).unwrap();

        // Set up v1 database
        setup_v1_database(&conn);

        // Insert a test entry before migration
        conn.execute(
            "INSERT INTO entries (id, title, username, password_encrypted, url_preview, nonce, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, 1)",
            params!["test-id", "Test Entry", "user", b"encrypted", b"https://example.com", b"nonce123456789012"],
        ).unwrap();

        // Apply v2 migration
        apply_v2_migration(&conn).unwrap();

        // Verify default values for new columns
        let (password_nonce, url_nonce, notes_nonce): (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT password_nonce, url_nonce, notes_nonce FROM entries WHERE id = ?",
                params!["test-id"],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?
                    ))
                },
            )
            .unwrap();

        assert_eq!(password_nonce, vec![0u8; 12]); // Default value
        assert!(url_nonce.is_none()); // Optional, no default
        assert!(notes_nonce.is_none()); // Optional, no default
    }

    #[test]
    fn test_apply_v2_migration_sets_lock_state_defaults() {
        let temp = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp.path()).unwrap();

        // Set up v1 database
        setup_v1_database(&conn);

        // Insert vault metadata
        conn.execute(
            "INSERT INTO vault_metadata (id, version, kdf_salt, kdf_mem_cost, kdf_time_cost, kdf_parallelism, created_at, updated_at) VALUES (1, 1, X'0000000000000000000000000000000000000000000000000000000000000000', 64000, 3, 4, 1000000, 1000000)",
            [],
        ).unwrap();

        // Apply v2 migration
        apply_v2_migration(&conn).unwrap();

        // Verify default lock state values
        let (failed_attempts, lock_until, last_attempt_at): (i64, Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT failed_attempts, lock_until, last_attempt_at FROM vault_metadata WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(failed_attempts, 0); // Default value
        assert!(lock_until.is_none()); // Optional, no default
        assert!(last_attempt_at.is_none()); // Optional, no default
    }

    #[test]
    fn test_apply_v2_migration_is_idempotent() {
        let temp = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp.path()).unwrap();

        // Set up v1 database
        setup_v1_database(&conn);

        // Apply v2 migration twice
        apply_v2_migration(&conn).unwrap();
        apply_v2_migration(&conn).unwrap(); // Should not fail

        // Verify schema version is 2
        let version: i64 = conn
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(version, 2);
    }

    #[test]
    fn test_apply_v2_migration_updates_schema_version() {
        let temp = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp.path()).unwrap();

        // Set up v1 database
        setup_v1_database(&conn);

        // Apply v2 migration
        apply_v2_migration(&conn).unwrap();

        // Verify schema version 2 is recorded
        let version: i64 = conn
            .query_row(
                "SELECT version FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(version, 2);

        // Verify applied_at is a valid timestamp
        let applied_at: i64 = conn
            .query_row(
                "SELECT applied_at FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(applied_at > 1000000); // Should be recent
    }

    #[test]
    fn test_apply_v2_migration_skips_if_already_applied() {
        let temp = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp.path()).unwrap();

        // Set up v1 database with v2 already applied
        setup_v1_database(&conn);
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (2, 2000000)",
            [],
        ).unwrap();

        // Apply v2 migration - should skip without error
        apply_v2_migration(&conn).unwrap();

        // Verify only one v2 migration record exists
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 1);
    }
}
