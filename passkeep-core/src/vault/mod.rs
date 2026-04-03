//! Vault session management
//!
//! This module provides VaultManager and VaultHandle system for managing vault sessions.

use crate::crypto::MasterKey;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

pub mod unlock;

/// Opaque handle type for vault sessions
pub type VaultHandle = u64;

/// Global vault manager (thread-safe)
pub struct VaultManager {
    next_handle: AtomicU64,
    vaults: RwLock<HashMap<VaultHandle, Arc<Mutex<VaultSession>>>>,
}

impl VaultManager {
    pub fn new() -> Self {
        Self {
            next_handle: AtomicU64::new(1),
            vaults: RwLock::new(HashMap::new()),
        }
    }

    /// Internal: generate next handle
    fn next_handle(&self) -> VaultHandle {
        self.next_handle.fetch_add(1, Ordering::SeqCst)
    }

    pub fn has_sessions(&self) -> bool {
        self.vaults.read().unwrap().len() > 0
    }
}

/// Vault database wrapper
#[derive(Clone)]
pub struct VaultDb {
    pub conn: Arc<Mutex<rusqlite::Connection>>,
}

impl VaultDb {
    pub fn new(conn: Arc<Mutex<rusqlite::Connection>>) -> Self {
        // Enable WAL mode (log warning but don't interrupt on failure)
        let conn_guard = conn.lock().unwrap();
        if let Err(e) = conn_guard.execute("PRAGMA journal_mode=WAL", []) {
            eprintln!("Warning: Failed to enable WAL mode: {}", e);
        }
        drop(conn_guard);
        Self { conn }
    }
}

/// Single vault session
///
/// This struct implements zeroization on drop to securely clear the master key
/// from memory when the session is closed.
pub struct VaultSession {
    master_key: MasterKey,
    db: VaultDb,
    config_path: PathBuf,
    keyfile_path: PathBuf,
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        // Securely zero the master key on drop
        self.master_key.zeroize();
    }
}

impl VaultSession {
    pub fn new(
        master_key: MasterKey,
        db: VaultDb,
        config_path: PathBuf,
        keyfile_path: PathBuf,
    ) -> Self {
        Self {
            master_key,
            db,
            config_path,
            keyfile_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_manager_creates_unique_handles() {
        let manager = VaultManager::new();
        let handle1 = manager.next_handle();
        let handle2 = manager.next_handle();
        assert_ne!(handle1, handle2);
    }

    #[test]
    fn test_vault_manager_no_sessions_initially() {
        let manager = VaultManager::new();
        assert!(!manager.has_sessions());
    }
}
