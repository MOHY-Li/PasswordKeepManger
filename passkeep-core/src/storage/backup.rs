//! Backup management for vault databases

use crate::storage::error::PassKeepError;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Maximum number of backups to retain
const MAX_BACKUPS: usize = 5;

/// Manager for creating and cleaning up vault backups
pub struct BackupManager {
    vault_path: PathBuf,
    backup_dir: PathBuf,
}

impl BackupManager {
    /// Create a new BackupManager
    ///
    /// Creates the backup directory if it doesn't exist.
    pub fn new(vault_path: &Path) -> Result<Self, PassKeepError> {
        let backup_dir = vault_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("backups");

        fs::create_dir_all(&backup_dir).map_err(|_| PassKeepError::BackupFailed)?;

        Ok(Self {
            vault_path: vault_path.to_path_buf(),
            backup_dir,
        })
    }

    /// Create a backup of the vault database
    ///
    /// Uses VACUUM INTO to create a clean, compact backup.
    /// Automatically cleans up old backups, keeping only the 5 most recent.
    pub fn create_backup(&self) -> Result<PathBuf, PassKeepError> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let backup_name = format!("vault_{}.db", timestamp);
        let backup_path = self.backup_dir.join(&backup_name);

        // Remove existing backup if it exists (in case of duplicate timestamps)
        if backup_path.exists() {
            fs::remove_file(&backup_path).map_err(|_| PassKeepError::BackupFailed)?;
        }

        // Use VACUUM INTO to create a clean backup
        let conn = Connection::open(&self.vault_path).map_err(|_| PassKeepError::BackupFailed)?;

        // Note: VACUUM INTO doesn't support parameter binding for filename.
        // The backup_path is internally generated, not from user input, so this is safe.
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        conn.execute(&format!("VACUUM INTO '{}'", backup_path.display()), [])
            .map_err(|_| PassKeepError::BackupFailed)?;

        // Clean up old backups (keep max 5)
        self.cleanup_old_backups()?;

        Ok(backup_path)
    }

    /// List all backup files in the backup directory
    pub fn list_backups(&self) -> Result<Vec<PathBuf>, PassKeepError> {
        let mut backups = Vec::new();

        if !self.backup_dir.exists() {
            return Ok(backups);
        }

        for entry in fs::read_dir(&self.backup_dir).map_err(|_| PassKeepError::BackupFailed)? {
            let entry = entry.map_err(|_| PassKeepError::BackupFailed)?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("db") {
                backups.push(path);
            }
        }

        // Sort by filename (which contains timestamp)
        backups.sort();

        Ok(backups)
    }

    /// Clean up old backups, keeping only the most recent backups
    fn cleanup_old_backups(&self) -> Result<(), PassKeepError> {
        let mut backups = self.list_backups()?;
        backups.sort();
        backups.reverse();

        // Remove backups beyond the MAX_BACKUPS most recent
        for old_backup in backups.into_iter().skip(MAX_BACKUPS) {
            fs::remove_file(&old_backup).map_err(|_| PassKeepError::BackupFailed)?;
        }

        Ok(())
    }

    /// Get the backup directory path
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::fs::File;
    use tempfile::TempDir;

    /// Helper to create a test database in a temp directory
    fn create_test_vault(dir: &Path, name: &str) -> PathBuf {
        let vault_path = dir.join(name);
        let conn = Connection::open(&vault_path).unwrap();
        conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)", [])
            .unwrap();
        conn.execute("INSERT INTO test (id, value) VALUES (1, 'test')", [])
            .unwrap();
        vault_path
    }

    #[test]
    fn test_create_backup_manager() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault.db");
        File::create(&vault_path).unwrap();

        let manager = BackupManager::new(&vault_path);

        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert_eq!(manager.vault_path, vault_path);
        assert!(manager.backup_dir().ends_with("backups"));
    }

    #[test]
    fn test_create_backup_manager_creates_backup_dir() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault.db");
        File::create(&vault_path).unwrap();

        let manager = BackupManager::new(&vault_path).unwrap();

        assert!(manager.backup_dir().exists());
    }

    #[test]
    fn test_create_backup_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(temp_dir.path(), "vault.db");

        let manager = BackupManager::new(&vault_path).unwrap();
        let backup_path = manager.create_backup().unwrap();

        assert!(backup_path.exists());
        assert!(backup_path.to_string_lossy().contains("vault_"));
        assert!(backup_path.to_string_lossy().ends_with(".db"));
    }

    #[test]
    fn test_list_backups_empty() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault.db");
        File::create(&vault_path).unwrap();

        let manager = BackupManager::new(&vault_path).unwrap();

        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 0);
    }

    #[test]
    fn test_list_backups_after_creation() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(temp_dir.path(), "vault.db");

        let manager = BackupManager::new(&vault_path).unwrap();
        manager.create_backup().unwrap();
        manager.create_backup().unwrap();

        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 2);
    }

    #[test]
    fn test_cleanup_old_backups() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(temp_dir.path(), "vault.db");

        let manager = BackupManager::new(&vault_path).unwrap();

        // Create 7 backups
        for _ in 0..7 {
            manager.create_backup().unwrap();
        }

        // Should only have 5 (most recent)
        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 5);
    }

    #[test]
    fn test_backup_content_valid() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(temp_dir.path(), "vault.db");

        let manager = BackupManager::new(&vault_path).unwrap();
        let backup_path = manager.create_backup().unwrap();

        // Verify backup contains the same data
        let backup_conn = Connection::open(&backup_path).unwrap();
        let value: String = backup_conn
            .query_row("SELECT value FROM test WHERE id = 1", [], |row| row.get(0))
            .unwrap();

        assert_eq!(value, "test");
    }

    #[test]
    fn test_create_backup_manager_without_parent() {
        // Test with a path that has no parent directory
        let path = Path::new("vault.db");
        let manager = BackupManager::new(path);

        assert!(manager.is_ok());
        let manager = manager.unwrap();
        // Should default to "./backups"
        assert!(manager.backup_dir().ends_with("backups"));
    }

    #[test]
    fn test_vacuum_into_creates_clean_backup() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(temp_dir.path(), "vault.db");

        let manager = BackupManager::new(&vault_path).unwrap();
        let backup_path = manager.create_backup().unwrap();

        // Verify backup is a valid SQLite database
        let backup_conn = Connection::open(&backup_path).unwrap();

        // Check that the table exists
        let table_exists: i64 = backup_conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(table_exists, 1);
    }

    #[test]
    fn test_keeps_most_recent_backups() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = create_test_vault(temp_dir.path(), "vault.db");

        let manager = BackupManager::new(&vault_path).unwrap();

        // Create more than 5 backups
        let mut backup_paths = Vec::new();
        for _ in 0..7 {
            let path = manager.create_backup().unwrap();
            backup_paths.push(path);
        }

        // Only 5 should remain
        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 5);

        // The oldest 2 should be deleted
        assert!(!backup_paths[0].exists());
        assert!(!backup_paths[1].exists());

        // The newest 5 should exist
        for path in &backup_paths[2..] {
            assert!(path.exists());
        }
    }
}
