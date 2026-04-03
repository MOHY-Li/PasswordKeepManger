//! Error types for passkeep-core

use thiserror::Error;

/// PassKeep 核心错误类型
#[derive(Debug, Error)]
pub enum PassKeepError {
    #[error("Incorrect master password")]
    WrongPassword,

    #[error("Key file not found: {0}")]
    KeyFileNotFound(String),

    #[error("Invalid key file format")]
    KeyFileInvalid,

    #[error("Key file is corrupted")]
    KeyFileCorrupted,

    #[error("Unsupported key file version: {0}")]
    KeyFileVersionMismatch(u32),

    #[error("Vault is locked. Try again in {0} seconds")]
    VaultLocked(i64),

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Failed to generate unique nonce")]
    NonceGenerationFailed,

    #[error("Database is locked")]
    DatabaseLocked,

    #[error("Database is corrupted")]
    DatabaseCorrupted,

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Backup failed")]
    BackupFailed,

    #[error("Invalid export file format")]
    InvalidExportFormat,

    #[error("Export file version mismatch")]
    ExportVersionMismatch,

    #[error("Import cancelled")]
    ImportCancelled,

    #[error("Source vault password required")]
    SourcePasswordRequired,

    #[error("Source key file required")]
    SourceKeyFileRequired,

    #[error("Failed to update lock state file")]
    LockStateUpdateFailed,

    #[error("Unauthorized access")]
    UnauthorizedAccess,

    #[error("Disk full")]
    DiskFull,

    #[error("Invalid KDF parameters")]
    InvalidKdfParams,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PassKeepError::WrongPassword;
        assert_eq!(err.to_string(), "Incorrect master password");
    }

    #[test]
    fn test_error_with_context() {
        let err = PassKeepError::EntryNotFound("test-id".to_string());
        assert!(err.to_string().contains("test-id"));
    }

    #[test]
    fn test_key_file_not_found() {
        let err = PassKeepError::KeyFileNotFound("/path/to/keyfile".to_string());
        assert!(err.to_string().contains("/path/to/keyfile"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_vault_locked() {
        let err = PassKeepError::VaultLocked(30);
        assert_eq!(err.to_string(), "Vault is locked. Try again in 30 seconds");
    }

    #[test]
    fn test_key_version_mismatch() {
        let err = PassKeepError::KeyFileVersionMismatch(5);
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = PassKeepError::from(io_err);
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_error_from_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let err = PassKeepError::from(json_err);
        assert!(err.to_string().contains("JSON error"));
    }
}
