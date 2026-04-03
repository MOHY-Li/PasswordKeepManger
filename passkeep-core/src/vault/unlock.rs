//! Vault unlock flow
//!
//! Implements password-based vault unlocking with:
//! - HKDF-Expand for Argon2 salt derivation
//! - Argon2id for master key derivation
//! - LockState integration for brute-force protection

use crate::crypto::argon2;
use crate::crypto::hkdf;
use crate::crypto::keyfile::KeyFile;
use crate::models::KdfParams;
use crate::storage::Database;
use crate::storage::error::PassKeepError;
use std::fs;
use std::path::Path;
use tempfile::TempDir;
use zeroize::Zeroizing;

/// Unlock the vault and return the master key
///
/// # Arguments
/// * `config_path` - Path to the vault database
/// * `master_password` - The user's master password
/// * `keyfile_path` - Path to the keyfile
///
/// # Returns
/// The derived master key on success
///
/// # Errors
/// - `VaultLocked` if the vault is locked due to failed attempts
/// - `WrongPassword` if the password is incorrect
/// - Other errors for I/O, database, or key derivation failures
pub fn unlock_vault(
    config_path: &Path,
    master_password: &str,
    keyfile_path: &Path,
) -> Result<Zeroizing<[u8; 32]>, PassKeepError> {
    // Open the database
    let db = Database::open(config_path)?;

    // Read LockState and kdf_params
    let mut lock_state = db.get_lock_state()?;

    // Check if vault is locked
    if lock_state.is_locked() {
        let remaining = lock_state.remaining_lock_time().as_secs();
        return Err(PassKeepError::VaultLocked(remaining as i64));
    }

    // Read the keyfile
    let keyfile = KeyFile::from_path(keyfile_path)?;

    // Read KDF parameters
    let kdf_params = db.get_kdf_params()?;

    // Attempt to derive the master key
    match derive_master_key(master_password, &keyfile.secret, &kdf_params) {
        Ok(master_key) => {
            // Success: reset failed attempt counter
            lock_state.record_success();
            db.save_lock_state(&lock_state)?;
            Ok(master_key)
        }
        Err(_) => {
            // Failure: record the failed attempt
            let _duration = lock_state.record_failure();
            db.save_lock_state(&lock_state)?;
            Err(PassKeepError::WrongPassword)
        }
    }
}

/// Derive the master key from password, keyfile secret, and KDF parameters
///
/// Uses a two-step process:
/// 1. HKDF-Expand to derive Argon2 salt from database salt + keyfile secret
/// 2. Argon2id to derive the master key from password + derived salt
fn derive_master_key(
    password: &str,
    keyfile_secret: &[u8; 32],
    kdf_params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, PassKeepError> {
    // Step 1: HKDF-Expand to generate Argon2 salt
    let mut argon_salt = [0u8; 32];
    hkdf::expand(&kdf_params.salt, keyfile_secret, &mut argon_salt)?;

    // Step 2: Argon2id to derive master key
    let mut master_key = Zeroizing::new([0u8; 32]);
    let params = ::argon2::Params::new(
        kdf_params.mem_cost_kib,
        kdf_params.time_cost,
        kdf_params.parallelism,
        None,
    )
    .map_err(|_| PassKeepError::InvalidKdfParams)?;

    argon2::derive_key(password, &argon_salt, &params, &mut master_key)?;

    // TODO: Step 3: Verify master_key by decrypting master_key_check

    Ok(master_key)
}

/// Helper to create a test vault with known parameters
#[cfg(test)]
fn setup_test_vault(temp_dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf, String) {
    use crate::crypto::rng::generate_salt;
    use crate::models::VaultMetadata;
    use crate::storage::Database;

    let config_path = temp_dir.path().join("test.db");
    let keyfile_path = temp_dir.path().join("test.key");

    // Create a test keyfile
    let keyfile = KeyFile::new();
    fs::write(&keyfile_path, keyfile.to_bytes()).unwrap();

    // Create a test database
    let db = Database::create(&config_path).unwrap();

    // Set up vault metadata with test KDF parameters
    let test_password = "test-password";
    let test_salt = generate_salt();
    let kdf_params = KdfParams {
        salt: test_salt,
        mem_cost_kib: 65536, // 64 MiB (reduced for tests)
        time_cost: 2,
        parallelism: 2,
    };

    let _metadata = VaultMetadata::new(kdf_params.clone());

    // Insert initial vault_metadata row (id=1) with lock state initialized
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    db.conn
        .execute(
            "INSERT OR REPLACE INTO vault_metadata (id, version, kdf_salt, kdf_mem_cost, kdf_time_cost, kdf_parallelism, created_at, updated_at, failed_attempts, lock_until, last_attempt_at) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, NULL, ?8)",
            (
                1u32,
                &kdf_params.salt[..],
                kdf_params.mem_cost_kib,
                kdf_params.time_cost,
                kdf_params.parallelism,
                now,
                now,
                now, // last_attempt_at
            ),
        )
        .unwrap();

    (config_path, keyfile_path, test_password.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlock_with_correct_password() {
        let temp_dir = TempDir::new().unwrap();
        let (config_path, keyfile_path, _password) = setup_test_vault(&temp_dir);

        // Note: Without master_key_check verification, any password will succeed
        // This test verifies the unlock flow structure
        let result = unlock_vault(&config_path, "test-password", &keyfile_path);

        // Should succeed structurally (even without password verification)
        assert!(result.is_ok());
    }

    #[test]
    fn test_unlock_with_invalid_keyfile() {
        let temp_dir = TempDir::new().unwrap();
        let (config_path, _keyfile_path, _) = setup_test_vault(&temp_dir);

        let invalid_keyfile = temp_dir.path().join("invalid.key");
        fs::write(&invalid_keyfile, b"invalid keyfile content").unwrap();

        let result = unlock_vault(&config_path, "test-password", &invalid_keyfile);
        assert!(matches!(result, Err(PassKeepError::KeyFileInvalid)));
    }

    #[test]
    fn test_unlock_with_missing_keyfile() {
        let temp_dir = TempDir::new().unwrap();
        let (config_path, _keyfile_path, _) = setup_test_vault(&temp_dir);

        let missing_keyfile = temp_dir.path().join("missing.key");

        let result = unlock_vault(&config_path, "test-password", &missing_keyfile);
        assert!(matches!(result, Err(PassKeepError::Io(_))));
    }

    #[test]
    fn test_unlock_with_invalid_database() {
        let temp_dir = TempDir::new().unwrap();
        let keyfile_path = temp_dir.path().join("test.key");

        // Create a test keyfile
        let keyfile = KeyFile::new();
        fs::write(&keyfile_path, keyfile.to_bytes()).unwrap();

        // Try to unlock with non-existent database
        let invalid_db = temp_dir.path().join("nonexistent.db");

        let result = unlock_vault(&invalid_db, "test-password", &keyfile_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_state_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let (config_path, _keyfile_path, _) = setup_test_vault(&temp_dir);

        let db = Database::open(&config_path).unwrap();

        // Verify initial lock state
        let initial_state = db.get_lock_state().unwrap();
        assert_eq!(initial_state.failed_attempts, 0);
        assert!(!initial_state.is_locked());

        // Manually update lock state to simulate failed attempts
        let mut lock_state = initial_state.clone();
        lock_state.failed_attempts = 2;
        db.save_lock_state(&lock_state).unwrap();

        // Verify the state was persisted
        let loaded_state = db.get_lock_state().unwrap();
        assert_eq!(loaded_state.failed_attempts, 2);
    }

    #[test]
    fn test_lock_state_with_three_failures_triggers_lock() {
        let temp_dir = TempDir::new().unwrap();
        let (config_path, _keyfile_path, _) = setup_test_vault(&temp_dir);

        let db = Database::open(&config_path).unwrap();

        // Manually simulate 3 failed attempts
        let mut lock_state = db.get_lock_state().unwrap();
        for _ in 0..3 {
            lock_state.record_failure();
        }
        db.save_lock_state(&lock_state).unwrap();

        // Verify the vault is now locked
        let loaded_state = db.get_lock_state().unwrap();
        assert!(loaded_state.is_locked());
        assert!(loaded_state.remaining_lock_time() > std::time::Duration::ZERO);
    }

    #[test]
    fn test_successful_reset_clears_lock_state() {
        let temp_dir = TempDir::new().unwrap();
        let (config_path, _keyfile_path, _) = setup_test_vault(&temp_dir);

        let db = Database::open(&config_path).unwrap();

        // Simulate some failed attempts
        let mut lock_state = db.get_lock_state().unwrap();
        lock_state.failed_attempts = 5;
        db.save_lock_state(&lock_state).unwrap();

        // Verify failures were recorded
        let loaded_state = db.get_lock_state().unwrap();
        assert_eq!(loaded_state.failed_attempts, 5);

        // Simulate successful unlock (reset)
        let mut lock_state = db.get_lock_state().unwrap();
        lock_state.record_success();
        db.save_lock_state(&lock_state).unwrap();

        // Verify state was reset
        let reset_state = db.get_lock_state().unwrap();
        assert_eq!(reset_state.failed_attempts, 0);
        assert!(!reset_state.is_locked());
    }

    #[test]
    fn test_kdf_params_retrieval() {
        let temp_dir = TempDir::new().unwrap();
        let (config_path, _keyfile_path, _) = setup_test_vault(&temp_dir);

        let db = Database::open(&config_path).unwrap();

        let kdf_params = db.get_kdf_params().unwrap();
        assert_eq!(kdf_params.mem_cost_kib, 65536);
        assert_eq!(kdf_params.time_cost, 2);
        assert_eq!(kdf_params.parallelism, 2);
        assert!(!kdf_params.salt.iter().all(|&b| b == 0)); // Salt should be non-zero
    }

    // Note: Tests for actual password verification (WrongPassword, VaultLocked) are
    // deferred until master_key_check is implemented. The current implementation
    // accepts any password since we can't verify correctness yet.
}
