//! JSON import functionality
//!
//! Imports vault data from JSON export format with support for:
//! - Integrity verification via BLAKE3 hash
//! - Master key verification
//! - Conflict resolution strategies (Skip, Overwrite, Rename, Abort)
//! - Decryption of encrypted fields

use crate::crypto::aes;
use crate::crypto::MasterKey;
use crate::import_export::format::{
    ExportDocument, ExportedEntry, ExportedFolder, VERIFICATION_VALUE,
};
use crate::import_export::json_exporter::verify_integrity_hash;
use crate::models::Entry;
use crate::storage::error::PassKeepError;
use base64::prelude::*;
use std::collections::HashSet;

/// Import conflict resolution strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictStrategy {
    /// Skip conflicting entries, keep existing data
    Skip,
    /// Overwrite existing entries with imported data
    Overwrite,
    /// Generate new UUID for imported entries (recommended, default)
    #[default]
    Rename,
    /// Abort entire import on any conflict
    Abort,
}

/// Import options
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Strategy for handling conflicting entry IDs
    pub conflict_strategy: ConflictStrategy,
    /// Whether to verify the integrity hash before import
    pub verify_integrity: bool,
    /// Whether to verify the master key before import
    pub verify_master_key: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            conflict_strategy: ConflictStrategy::default(),
            verify_integrity: true,
            verify_master_key: true,
        }
    }
}

/// Result of an import operation
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// Number of entries imported
    pub entries_imported: usize,
    /// Number of entries skipped (due to conflicts or other reasons)
    pub entries_skipped: usize,
    /// Number of folders imported
    pub folders_imported: usize,
    /// IDs of entries that were skipped
    pub skipped_entry_ids: Vec<String>,
    /// Mapping of original IDs to new IDs (for Rename strategy)
    pub id_mapping: Vec<(String, String)>,
}

/// Import vault entries from JSON format
///
/// # Arguments
/// * `json_data` - JSON string of exported data
/// * `existing_entry_ids` - Set of existing entry IDs to check for conflicts
/// * `master_key` - Master key for decryption
/// * `options` - Import options
///
/// # Returns
/// Import result with statistics and decrypted entries ready for insertion
pub fn import_vault(
    json_data: &str,
    existing_entry_ids: &HashSet<String>,
    master_key: &MasterKey,
    options: &ImportOptions,
) -> Result<(ImportResult, Vec<Entry>, Vec<ExportedFolder>), PassKeepError> {
    // Parse JSON
    let document: ExportDocument = serde_json::from_str(json_data)?;

    // Verify format
    if document.metadata.format != "passkeep-export" {
        return Err(PassKeepError::InvalidExportFormat);
    }

    // Verify integrity hash if requested
    if options.verify_integrity {
        verify_integrity_hash(&document)?;
    }

    // Verify master key if requested
    if options.verify_master_key {
        verify_master_key_integrity(&document, master_key)?;
    }

    let mut result = ImportResult {
        entries_imported: 0,
        entries_skipped: 0,
        folders_imported: document.folders.len(),
        skipped_entry_ids: Vec::new(),
        id_mapping: Vec::new(),
    };

    let mut imported_entries = Vec::new();

    // Process entries based on conflict strategy
    for exported_entry in document.entries {
        match import_entry(
            &exported_entry,
            existing_entry_ids,
            master_key,
            options.conflict_strategy,
        )? {
            ImportEntryResult::Imported(entry) => {
                result.entries_imported += 1;
                imported_entries.push(entry);
            }
            ImportEntryResult::ImportedWithNewId(original_id, entry) => {
                result.entries_imported += 1;
                result.id_mapping.push((original_id, entry.id.clone()));
                imported_entries.push(entry);
            }
            ImportEntryResult::Skipped(id) => {
                result.entries_skipped += 1;
                result.skipped_entry_ids.push(id);
            }
            ImportEntryResult::Conflict(_id) => {
                return Err(PassKeepError::ImportCancelled);
            }
        }
    }

    Ok((result, imported_entries, document.folders))
}

/// Result of importing a single entry
enum ImportEntryResult {
    Imported(Entry),
    ImportedWithNewId(String, Entry),
    Skipped(String),
    Conflict(String),
}

/// Import a single entry with conflict resolution
fn import_entry(
    exported_entry: &ExportedEntry,
    existing_entry_ids: &HashSet<String>,
    master_key: &MasterKey,
    strategy: ConflictStrategy,
) -> Result<ImportEntryResult, PassKeepError> {
    let original_id = exported_entry.id.clone();

    // Check for conflict
    let has_conflict = existing_entry_ids.contains(&exported_entry.id);

    if has_conflict {
        match strategy {
            ConflictStrategy::Skip => {
                return Ok(ImportEntryResult::Skipped(original_id));
            }
            ConflictStrategy::Overwrite => {
                // Continue with import using original ID
            }
            ConflictStrategy::Rename => {
                // Generate new UUID and continue
            }
            ConflictStrategy::Abort => {
                return Ok(ImportEntryResult::Conflict(original_id));
            }
        }
    }

    // Decrypt fields
    let password = decrypt_field(
        &exported_entry.password_encrypted,
        &exported_entry.password_nonce,
        master_key,
    )?;

    let url = match (&exported_entry.url_encrypted, &exported_entry.url_nonce) {
        (Some(encrypted_url), Some(nonce_b64)) => {
            Some(decrypt_field(encrypted_url, nonce_b64, master_key)?)
        }
        _ => None,
    };

    let notes = match (&exported_entry.notes_encrypted, &exported_entry.notes_nonce) {
        (Some(encrypted_notes), Some(nonce_b64)) => {
            Some(decrypt_field(encrypted_notes, nonce_b64, master_key)?)
        }
        _ => None,
    };

    // Build entry
    let entry = Entry {
        id: if has_conflict && strategy == ConflictStrategy::Rename {
            crate::crypto::generate_uuid()
        } else {
            exported_entry.id.clone()
        },
        title: exported_entry.title.clone(),
        username: exported_entry.username.clone(),
        password,
        url,
        notes,
        folder_id: exported_entry.folder_id.clone(),
        tags: exported_entry.tags.clone(),
        created_at: exported_entry.created_at,
        updated_at: exported_entry.updated_at,
    };

    if has_conflict && strategy == ConflictStrategy::Rename {
        Ok(ImportEntryResult::ImportedWithNewId(original_id, entry))
    } else {
        Ok(ImportEntryResult::Imported(entry))
    }
}

/// Decrypt a single field
fn decrypt_field(
    encrypted_b64: &str,
    nonce_b64: &str,
    master_key: &MasterKey,
) -> Result<String, PassKeepError> {
    let encrypted = BASE64_STANDARD
        .decode(encrypted_b64)
        .map_err(|_| PassKeepError::DecryptionFailed)?;
    let nonce_bytes = BASE64_STANDARD
        .decode(nonce_b64)
        .map_err(|_| PassKeepError::DecryptionFailed)?;

    if nonce_bytes.len() != 12 {
        return Err(PassKeepError::InvalidNonce);
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let decrypted = aes::decrypt_with_nonce(&encrypted, master_key.as_bytes(), &nonce, b"")?;

    String::from_utf8(decrypted).map_err(|_| PassKeepError::DecryptionFailed)
}

/// Verify the master key by decrypting the verification value
fn verify_master_key_integrity(
    document: &ExportDocument,
    master_key: &MasterKey,
) -> Result<(), PassKeepError> {
    let encrypted = BASE64_STANDARD
        .decode(&document.metadata.verification_value_encrypted)
        .map_err(|_| PassKeepError::DecryptionFailed)?;

    let nonce_bytes = BASE64_STANDARD
        .decode(&document.metadata.verification_nonce)
        .map_err(|_| PassKeepError::DecryptionFailed)?;

    if nonce_bytes.len() != 12 {
        return Err(PassKeepError::InvalidNonce);
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let decrypted = aes::decrypt_with_nonce(&encrypted, master_key.as_bytes(), &nonce, b"")?;

    let verification_str =
        String::from_utf8(decrypted).map_err(|_| PassKeepError::DecryptionFailed)?;

    if verification_str == VERIFICATION_VALUE {
        Ok(())
    } else {
        Err(PassKeepError::WrongPassword)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::import_export::json_exporter::{export_vault, ExportOptions};

    fn create_test_entry(id: &str) -> Entry {
        Entry {
            id: id.to_string(),
            title: "Test Entry".to_string(),
            username: "testuser".to_string(),
            password: "password123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("Secret notes".to_string()),
            folder_id: None,
            tags: vec!["test".to_string()],
            created_at: 1712188800,
            updated_at: 1712188800,
        }
    }

    fn create_test_export(master_key: &MasterKey) -> String {
        let entries = vec![
            create_test_entry("entry-1"),
            create_test_entry("entry-2"),
            create_test_entry("entry-3"),
        ];
        let folders = vec![ExportedFolder {
            id: "folder-1".to_string(),
            name: "Personal".to_string(),
            parent_id: None,
            created_at: 1712188800,
            updated_at: 1712188800,
        }];
        let kdf_params = KdfParams::default_params();
        let options = ExportOptions::default();

        export_vault(&entries, &folders, &kdf_params, master_key, &options).unwrap()
    }

    #[test]
    fn test_import_vault_basic() {
        let master_key = MasterKey::new([1u8; 32]);
        let export_json = create_test_export(&master_key);

        let existing_ids = HashSet::new();
        let options = ImportOptions::default();

        let (result, entries, folders) =
            import_vault(&export_json, &existing_ids, &master_key, &options).unwrap();

        assert_eq!(result.entries_imported, 3);
        assert_eq!(result.entries_skipped, 0);
        assert_eq!(result.folders_imported, 1);
        assert_eq!(entries.len(), 3);
        assert_eq!(folders.len(), 1);
        assert_eq!(entries[0].password, "password123");
        assert_eq!(entries[0].url.as_ref().unwrap(), "https://example.com");
        assert_eq!(entries[0].notes.as_ref().unwrap(), "Secret notes");
    }

    #[test]
    fn test_import_with_wrong_master_key_fails() {
        let export_key = MasterKey::new([1u8; 32]);
        let import_key = MasterKey::new([2u8; 32]);
        let export_json = create_test_export(&export_key);

        let existing_ids = HashSet::new();
        let options = ImportOptions {
            verify_master_key: true,
            ..Default::default()
        };

        let result = import_vault(&export_json, &existing_ids, &import_key, &options);
        match &result {
            Ok(_) => panic!("Expected error but got success"),
            Err(e) => {
                // We expect WrongPassword from master key verification,
                // but the test entry decryption might also fail with DecryptionFailed
                // Both are acceptable outcomes for wrong master key
                assert!(
                    matches!(
                        e,
                        PassKeepError::WrongPassword | PassKeepError::DecryptionFailed
                    ),
                    "Expected WrongPassword or DecryptionFailed, got: {:?}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_import_skip_master_key_verification() {
        let export_key = MasterKey::new([1u8; 32]);
        let import_key = MasterKey::new([2u8; 32]);
        let export_json = create_test_export(&export_key);

        let existing_ids = HashSet::new();
        let options = ImportOptions {
            verify_master_key: false,
            ..Default::default()
        };

        // Should fail at decryption step instead of master key verification
        let result = import_vault(&export_json, &existing_ids, &import_key, &options);
        assert!(matches!(result, Err(PassKeepError::DecryptionFailed)));
    }

    #[test]
    fn test_conflict_strategy_skip() {
        let master_key = MasterKey::new([1u8; 32]);
        let export_json = create_test_export(&master_key);

        let mut existing_ids = HashSet::new();
        existing_ids.insert("entry-1".to_string());
        existing_ids.insert("entry-3".to_string());

        let options = ImportOptions {
            conflict_strategy: ConflictStrategy::Skip,
            ..Default::default()
        };

        let (result, entries, _) =
            import_vault(&export_json, &existing_ids, &master_key, &options).unwrap();

        assert_eq!(result.entries_imported, 1); // Only entry-2
        assert_eq!(result.entries_skipped, 2); // entry-1 and entry-3
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "entry-2");
        assert!(result.skipped_entry_ids.contains(&"entry-1".to_string()));
        assert!(result.skipped_entry_ids.contains(&"entry-3".to_string()));
    }

    #[test]
    fn test_conflict_strategy_overwrite() {
        let master_key = MasterKey::new([1u8; 32]);
        let export_json = create_test_export(&master_key);

        let mut existing_ids = HashSet::new();
        existing_ids.insert("entry-1".to_string());

        let options = ImportOptions {
            conflict_strategy: ConflictStrategy::Overwrite,
            ..Default::default()
        };

        let (result, entries, _) =
            import_vault(&export_json, &existing_ids, &master_key, &options).unwrap();

        assert_eq!(result.entries_imported, 3); // All entries imported
        assert_eq!(result.entries_skipped, 0);
        assert_eq!(entries.len(), 3);
        // entry-1 should have original ID (not renamed)
        assert!(entries.iter().any(|e| e.id == "entry-1"));
    }

    #[test]
    fn test_conflict_strategy_rename() {
        let master_key = MasterKey::new([1u8; 32]);
        let export_json = create_test_export(&master_key);

        let mut existing_ids = HashSet::new();
        existing_ids.insert("entry-1".to_string());
        existing_ids.insert("entry-2".to_string());

        let options = ImportOptions {
            conflict_strategy: ConflictStrategy::Rename,
            ..Default::default()
        };

        let (result, entries, _) =
            import_vault(&export_json, &existing_ids, &master_key, &options).unwrap();

        assert_eq!(result.entries_imported, 3);
        assert_eq!(result.entries_skipped, 0);
        assert_eq!(entries.len(), 3);
        assert_eq!(result.id_mapping.len(), 2);

        // Check that conflicting entries got new IDs
        let entry_ids: Vec<_> = entries.iter().map(|e| e.id.as_str()).collect();
        assert!(!entry_ids.contains(&"entry-1"));
        assert!(!entry_ids.contains(&"entry-2"));
        assert!(entry_ids.contains(&"entry-3")); // No conflict, kept original

        // Check ID mapping
        let original_ids: Vec<_> = result
            .id_mapping
            .iter()
            .map(|(orig, _)| orig.as_str())
            .collect();
        assert!(original_ids.contains(&"entry-1"));
        assert!(original_ids.contains(&"entry-2"));
    }

    #[test]
    fn test_conflict_strategy_abort() {
        let master_key = MasterKey::new([1u8; 32]);
        let export_json = create_test_export(&master_key);

        let mut existing_ids = HashSet::new();
        existing_ids.insert("entry-2".to_string());

        let options = ImportOptions {
            conflict_strategy: ConflictStrategy::Abort,
            ..Default::default()
        };

        let result = import_vault(&export_json, &existing_ids, &master_key, &options);
        assert!(matches!(result, Err(PassKeepError::ImportCancelled)));
    }

    #[test]
    fn test_conflict_strategy_abort_no_conflict() {
        let master_key = MasterKey::new([1u8; 32]);
        let export_json = create_test_export(&master_key);

        let existing_ids = HashSet::new(); // No conflicts

        let options = ImportOptions {
            conflict_strategy: ConflictStrategy::Abort,
            ..Default::default()
        };

        let (result, entries, _) =
            import_vault(&export_json, &existing_ids, &master_key, &options).unwrap();

        assert_eq!(result.entries_imported, 3);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_import_invalid_json_fails() {
        let master_key = MasterKey::new([1u8; 32]);
        let invalid_json = "not valid json";

        let existing_ids = HashSet::new();
        let options = ImportOptions::default();

        let result = import_vault(invalid_json, &existing_ids, &master_key, &options);
        assert!(matches!(result, Err(PassKeepError::Json(_))));
    }

    #[test]
    fn test_import_invalid_format_fails() {
        let master_key = MasterKey::new([1u8; 32]);
        let invalid_format = r#"{
            "metadata": {
                "format": "wrong-format",
                "version": 1,
                "exported_at": 1712188800,
                "kdf_params": {
                    "salt": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                    "mem_cost_kib": 65536,
                    "time_cost": 3,
                    "parallelism": 4
                },
                "verification_value_encrypted": "test",
                "verification_nonce": "test",
                "integrity_hash": "test"
            },
            "entries": [],
            "folders": []
        }"#;

        let existing_ids = HashSet::new();
        let options = ImportOptions {
            verify_integrity: false,
            verify_master_key: false,
            ..Default::default()
        };

        let result = import_vault(invalid_format, &existing_ids, &master_key, &options);
        assert!(matches!(result, Err(PassKeepError::InvalidExportFormat)));
    }

    #[test]
    fn test_import_with_tampered_integrity_hash_fails() {
        let master_key = MasterKey::new([1u8; 32]);
        let mut json = create_test_export(&master_key);

        // Tamper with the JSON (change a title)
        // This will invalidate the integrity hash
        json = json.replace("Test Entry", "Tampered Entry");

        let existing_ids = HashSet::new();
        let options = ImportOptions {
            verify_integrity: true,
            ..Default::default()
        };

        let result = import_vault(&json, &existing_ids, &master_key, &options);
        assert!(matches!(result, Err(PassKeepError::InvalidExportFormat)));
    }

    #[test]
    fn test_import_skip_integrity_verification() {
        let master_key = MasterKey::new([1u8; 32]);
        let mut json = create_test_export(&master_key);

        // Tamper with the JSON
        json = json.replace("Test Entry", "Tampered Entry");

        let existing_ids = HashSet::new();
        let options = ImportOptions {
            verify_integrity: false,
            ..Default::default()
        };

        // Should succeed when integrity verification is disabled
        let (result, entries, _) =
            import_vault(&json, &existing_ids, &master_key, &options).unwrap();

        assert_eq!(result.entries_imported, 3);
        // The tampered title should be imported
        assert!(entries.iter().all(|e| e.title == "Tampered Entry"));
    }

    #[test]
    fn test_import_entry_with_optional_fields() {
        let master_key = MasterKey::new([1u8; 32]);

        // Create export with minimal entry
        let minimal_entry = Entry {
            id: "minimal-id".to_string(),
            title: "Minimal Entry".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            url: None,
            notes: None,
            folder_id: None,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };

        let entries = vec![minimal_entry];
        let folders = vec![];
        let kdf_params = KdfParams::default_params();
        let options = ExportOptions::default();

        let json = export_vault(&entries, &folders, &kdf_params, &master_key, &options).unwrap();

        let existing_ids = HashSet::new();
        let import_options = ImportOptions::default();

        let (result, imported_entries, _) =
            import_vault(&json, &existing_ids, &master_key, &import_options).unwrap();

        assert_eq!(result.entries_imported, 1);
        assert_eq!(imported_entries.len(), 1);
        assert_eq!(imported_entries[0].id, "minimal-id");
        assert!(imported_entries[0].url.is_none());
        assert!(imported_entries[0].notes.is_none());
        assert!(imported_entries[0].tags.is_empty());
    }

    #[test]
    fn test_conflict_strategy_default_is_rename() {
        let strategy = ConflictStrategy::default();
        assert_eq!(strategy, ConflictStrategy::Rename);
    }

    #[test]
    fn test_import_options_default() {
        let options = ImportOptions::default();
        assert_eq!(options.conflict_strategy, ConflictStrategy::Rename);
        assert!(options.verify_integrity);
        assert!(options.verify_master_key);
    }

    #[test]
    fn test_decrypt_invalid_base64_fails() {
        let master_key = MasterKey::new([1u8; 32]);

        let result = decrypt_field("invalid-base64!!!", "invalid", &master_key);
        assert!(matches!(result, Err(PassKeepError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_invalid_nonce_length_fails() {
        let master_key = MasterKey::new([1u8; 32]);

        // Valid base64 but wrong length (5 bytes instead of 12)
        let short_nonce = BASE64_STANDARD.encode([0u8; 5]);

        let result = decrypt_field(
            &BASE64_STANDARD.encode([0u8; 32]),
            &short_nonce,
            &master_key,
        );
        assert!(matches!(result, Err(PassKeepError::InvalidNonce)));
    }
}
