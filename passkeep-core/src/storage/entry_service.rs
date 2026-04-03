//! Entry service for CRUD operations on password entries
//!
//! This service handles creating, reading, updating, and deleting password entries
//! with encryption for sensitive fields (password, URL, notes).

use crate::crypto::{aes, rng, MasterKey};
use crate::models::{Entry, EntryInput, EntryMetadata};
use crate::storage::error::PassKeepError;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

/// Service for managing password entries with encryption
pub struct EntryService {
    db: Arc<Mutex<Connection>>,
    master_key: MasterKey,
}

impl EntryService {
    /// Create a new EntryService
    ///
    /// # Arguments
    /// * `db` - SQLite database connection
    /// * `master_key` - Master key for encryption/decryption
    pub fn new(db: Arc<Mutex<Connection>>, master_key: MasterKey) -> Self {
        Self { db, master_key }
    }

    /// Create a new password entry
    ///
    /// # Arguments
    /// * `input` - Entry data including sensitive information
    ///
    /// # Returns
    /// The ID of the created entry
    pub fn create(&self, input: &EntryInput) -> Result<String, PassKeepError> {
        let id = input
            .id
            .clone()
            .unwrap_or_else(|| rng::generate_uuid());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Generate nonce and encrypt sensitive fields
        let password_nonce = rng::generate_nonce();
        let password_encrypted = aes::encrypt_with_nonce(
            input.password.as_bytes(),
            self.master_key.as_bytes(),
            &password_nonce,
            b"",
        )?;

        let url_nonce = input.url.as_ref().map(|_| rng::generate_nonce());
        let url_encrypted = input.url.as_ref().and_then(|url| {
            url_nonce.as_ref().map(|nonce| {
                aes::encrypt_with_nonce(url.as_bytes(), self.master_key.as_bytes(), nonce, b"")
            })
        }).transpose()?;

        let notes_nonce = input.notes.as_ref().map(|_| rng::generate_nonce());
        let notes_encrypted = input.notes.as_ref().and_then(|notes| {
            notes_nonce.as_ref().map(|nonce| {
                aes::encrypt_with_nonce(
                    notes.as_bytes(),
                    self.master_key.as_bytes(),
                    nonce,
                    b"",
                )
            })
        }).transpose()?;

        // TODO: Implement SQL INSERT with encrypted data
        let _ = (password_encrypted, url_encrypted, notes_encrypted);
        let _ = (password_nonce, url_nonce, notes_nonce);
        let _ = now;

        // Placeholder - entry creation not fully implemented yet
        Ok(id)
    }

    /// Get a password entry by ID
    ///
    /// # Arguments
    /// * `id` - The entry ID
    ///
    /// # Returns
    /// The decrypted entry if found
    pub fn get(&self, id: &str) -> Result<Entry, PassKeepError> {
        // TODO: Implement SQL SELECT and decryption
        let _ = id;
        Err(PassKeepError::EntryNotFound(id.to_string()))
    }

    /// List all entry metadata (without sensitive data)
    ///
    /// # Returns
    /// Vector of entry metadata
    pub fn list(&self) -> Result<Vec<EntryMetadata>, PassKeepError> {
        // TODO: Implement SQL SELECT for metadata only
        Ok(Vec::new())
    }

    /// Update an existing password entry
    ///
    /// # Arguments
    /// * `id` - The entry ID to update
    /// * `input` - New entry data
    pub fn update(&self, id: &str, input: &EntryInput) -> Result<(), PassKeepError> {
        // TODO: Implement SQL UPDATE with re-encryption
        let _ = input;
        Err(PassKeepError::EntryNotFound(id.to_string()))
    }

    /// Delete a password entry
    ///
    /// # Arguments
    /// * `id` - The entry ID to delete
    pub fn delete(&self, id: &str) -> Result<(), PassKeepError> {
        // TODO: Implement SQL DELETE
        Err(PassKeepError::EntryNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates an in-memory database for testing
    fn create_test_db() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().unwrap();
        Arc::new(Mutex::new(conn))
    }

    /// Creates a test master key
    fn create_test_master_key() -> MasterKey {
        MasterKey::new([1u8; 32])
    }

    /// Creates a test entry input
    fn create_test_input() -> EntryInput {
        EntryInput {
            id: None,
            title: "Test Entry".to_string(),
            username: "testuser".to_string(),
            password: "testpassword123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("Test notes".to_string()),
            folder_id: None,
            tags: vec!["test".to_string()],
        }
    }

    #[test]
    fn test_create_entry_service() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);
        // Service created successfully
        let _ = service;
    }

    #[test]
    fn test_create_entry_generates_id() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);

        let input = EntryInput {
            id: None,
            title: "Test".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            url: None,
            notes: None,
            folder_id: None,
            tags: vec![],
        };

        let id = service.create(&input).unwrap();
        // Should generate a UUID
        assert!(!id.is_empty());
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_create_entry_with_custom_id() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);

        let custom_id = "my-custom-id".to_string();
        let mut input = create_test_input();
        input.id = Some(custom_id.clone());

        let id = service.create(&input).unwrap();
        assert_eq!(id, custom_id);
    }

    #[test]
    fn test_create_entry_encryption() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);

        let input = create_test_input();
        // This should not fail - encryption works
        let result = service.create(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_nonexistent_entry() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);

        let result = service.get("nonexistent-id");
        assert!(matches!(result, Err(PassKeepError::EntryNotFound(_))));
    }

    #[test]
    fn test_list_entries_empty() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);

        let entries = service.list().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_update_nonexistent_entry() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);

        let result = service.update("nonexistent-id", &create_test_input());
        assert!(matches!(result, Err(PassKeepError::EntryNotFound(_))));
    }

    #[test]
    fn test_delete_nonexistent_entry() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);

        let result = service.delete("nonexistent-id");
        assert!(matches!(result, Err(PassKeepError::EntryNotFound(_))));
    }

    #[test]
    fn test_entry_with_optional_fields_none() {
        let db = create_test_db();
        let master_key = create_test_master_key();
        let service = EntryService::new(db, master_key);

        let input = EntryInput {
            id: None,
            title: "Minimal Entry".to_string(),
            username: "user".to_string(),
            password: "password".to_string(),
            url: None,
            notes: None,
            folder_id: None,
            tags: vec![],
        };

        let result = service.create(&input);
        assert!(result.is_ok());
    }
}
