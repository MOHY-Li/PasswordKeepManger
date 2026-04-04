//! JSON export functionality
//!
//! Exports vault data to JSON format with encrypted sensitive fields
//! and BLAKE3 integrity hash verification.

use crate::crypto::aes;
use crate::crypto::rng;
use crate::crypto::MasterKey;
use crate::import_export::format::{
    ExportDocument, ExportMetadata, ExportedEntry, ExportedFolder, EXPORT_FORMAT, EXPORT_VERSION,
    MAX_URL_PREVIEW_LENGTH, VERIFICATION_VALUE,
};
use crate::models::Entry;
use crate::storage::error::PassKeepError;
use base64::prelude::*;

/// Export options
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Whether to encrypt the entire JSON file
    pub encrypt_full_file: bool,
}

/// Export vault entries to JSON format
///
/// # Arguments
/// * `entries` - Entries to export
/// * `folders` - Folders to export
/// * `kdf_params` - KDF parameters from source vault
/// * `master_key` - Master key for encryption
/// * `options` - Export options
///
/// # Returns
/// JSON string of exported data
pub fn export_vault(
    entries: &[Entry],
    folders: &[ExportedFolder],
    kdf_params: &crate::crypto::KdfParams,
    master_key: &MasterKey,
    options: &ExportOptions,
) -> Result<String, PassKeepError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create verification value (encrypt "PASSKEEP-VERIFICATION")
    let verification_nonce = rng::generate_nonce();
    let verification_encrypted = aes::encrypt_with_nonce(
        VERIFICATION_VALUE.as_bytes(),
        master_key.as_bytes(),
        &verification_nonce,
        b"",
    )?;

    let verification_value_encrypted = BASE64_STANDARD.encode(verification_encrypted);
    let verification_nonce_b64 = BASE64_STANDARD.encode(verification_nonce);

    // Export entries with encrypted sensitive fields
    let mut exported_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        exported_entries.push(export_entry(entry, master_key)?);
    }

    // Calculate integrity hash (BLAKE3 of entries + folders JSON)
    let integrity_hash = calculate_integrity_hash(&exported_entries, folders)?;

    let metadata = ExportMetadata {
        format: EXPORT_FORMAT.to_string(),
        version: EXPORT_VERSION,
        exported_at: now,
        kdf_params: kdf_params.clone(),
        verification_value_encrypted,
        verification_nonce: verification_nonce_b64,
        integrity_hash: BASE64_STANDARD.encode(integrity_hash),
    };

    let document = ExportDocument {
        metadata,
        entries: exported_entries,
        folders: folders.to_vec(),
    };

    let json = serde_json::to_string_pretty(&document)?;

    if options.encrypt_full_file {
        // Note: Full file encryption is planned for a future phase.
        // Returning EncryptionFailed to maintain error type consistency.
        // When implemented, this will encrypt the entire JSON output.
        return Err(PassKeepError::EncryptionFailed);
    }

    Ok(json)
}

/// Export a single entry with encrypted sensitive fields
fn export_entry(entry: &Entry, master_key: &MasterKey) -> Result<ExportedEntry, PassKeepError> {
    // Encrypt password
    let password_nonce = rng::generate_nonce();
    let password_encrypted = aes::encrypt_with_nonce(
        entry.password.as_bytes(),
        master_key.as_bytes(),
        &password_nonce,
        b"",
    )?;

    // Encrypt URL if present
    let (url_encrypted, url_nonce) = if let Some(ref url) = entry.url {
        let nonce = rng::generate_nonce();
        let encrypted =
            aes::encrypt_with_nonce(url.as_bytes(), master_key.as_bytes(), &nonce, b"")?;
        (Some(BASE64_STANDARD.encode(encrypted)), Some(nonce))
    } else {
        (None, None)
    };

    // Encrypt notes if present
    let (notes_encrypted, notes_nonce) = if let Some(ref notes) = entry.notes {
        let nonce = rng::generate_nonce();
        let encrypted =
            aes::encrypt_with_nonce(notes.as_bytes(), master_key.as_bytes(), &nonce, b"")?;
        (Some(BASE64_STANDARD.encode(encrypted)), Some(nonce))
    } else {
        (None, None)
    };

    Ok(ExportedEntry {
        id: entry.id.clone(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        password_encrypted: BASE64_STANDARD.encode(password_encrypted),
        url_preview: entry
            .url
            .as_ref()
            .map(|u| u.chars().take(MAX_URL_PREVIEW_LENGTH).collect())
            .unwrap_or_default(),
        url_encrypted,
        notes_encrypted,
        password_nonce: BASE64_STANDARD.encode(password_nonce),
        url_nonce: url_nonce.map(|n| BASE64_STANDARD.encode(n)),
        notes_nonce: notes_nonce.map(|n| BASE64_STANDARD.encode(n)),
        folder_id: entry.folder_id.clone(),
        tags: entry.tags.clone(),
        created_at: entry.created_at,
        updated_at: entry.updated_at,
    })
}

/// Calculate BLAKE3 integrity hash of entries and folders
fn calculate_integrity_hash(
    entries: &[ExportedEntry],
    folders: &[ExportedFolder],
) -> Result<[u8; 32], PassKeepError> {
    // Serialize entries and folders separately for hashing
    let entries_json = serde_json::to_vec(entries).map_err(|_| PassKeepError::EncryptionFailed)?;
    let folders_json = serde_json::to_vec(folders).map_err(|_| PassKeepError::EncryptionFailed)?;

    // Use hash_chunks to compute hash of both arrays
    Ok(crate::crypto::hash_chunks(&[&entries_json, &folders_json]))
}

/// Verify the integrity hash of an export document
///
/// # Arguments
/// * `document` - The export document to verify
///
/// # Returns
/// Ok(()) if hash is valid, Err otherwise
pub fn verify_integrity_hash(document: &ExportDocument) -> Result<(), PassKeepError> {
    let expected_hash = BASE64_STANDARD
        .decode(&document.metadata.integrity_hash)
        .map_err(|_| PassKeepError::InvalidExportFormat)?;

    let calculated_hash = calculate_integrity_hash(&document.entries, &document.folders)?;

    if expected_hash.as_slice() == calculated_hash {
        Ok(())
    } else {
        Err(PassKeepError::InvalidExportFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entry(id: &str) -> Entry {
        Entry {
            id: id.to_string(),
            title: "Test Entry".to_string(),
            username: "testuser".to_string(),
            password: "password123".to_string(),
            url: Some(
                "https://example.com/very/long/url/that/has/more/than/fifty/characters".to_string(),
            ),
            notes: Some("Secret notes".to_string()),
            folder_id: None,
            tags: vec!["test".to_string()],
            created_at: 1712188800,
            updated_at: 1712188800,
        }
    }

    #[test]
    fn test_export_entry_encryption() {
        let master_key = MasterKey::new([1u8; 32]);
        let entry = create_test_entry("test-id");

        let exported = export_entry(&entry, &master_key).unwrap();

        assert_eq!(exported.id, "test-id");
        assert_eq!(exported.title, "Test Entry");
        assert_eq!(exported.username, "testuser");
        assert!(!exported.password_encrypted.is_empty());
        assert!(!exported.password_nonce.is_empty());
        assert_eq!(exported.url_preview.len(), MAX_URL_PREVIEW_LENGTH); // URL truncated to MAX_URL_PREVIEW_LENGTH chars
        assert!(exported.url_encrypted.is_some());
        assert!(exported.url_nonce.is_some());
        assert!(exported.notes_encrypted.is_some());
        assert!(exported.notes_nonce.is_some());
    }

    #[test]
    fn test_export_entry_minimal() {
        let master_key = MasterKey::new([1u8; 32]);
        let entry = Entry {
            id: "minimal-id".to_string(),
            title: "Minimal".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            url: None,
            notes: None,
            folder_id: None,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };

        let exported = export_entry(&entry, &master_key).unwrap();

        assert_eq!(exported.url_preview, "");
        assert!(exported.url_encrypted.is_none());
        assert!(exported.url_nonce.is_none());
        assert!(exported.notes_encrypted.is_none());
        assert!(exported.notes_nonce.is_none());
    }

    #[test]
    fn test_export_vault_basic() {
        let master_key = MasterKey::new([1u8; 32]);
        let entries = vec![create_test_entry("entry-1"), create_test_entry("entry-2")];
        let folders = vec![];
        let kdf_params = crate::crypto::KdfParams::default_params();
        let options = ExportOptions::default();

        let json = export_vault(&entries, &folders, &kdf_params, &master_key, &options).unwrap();

        assert!(json.contains("passkeep-export"));
        assert!(json.contains("integrity_hash"));
        assert!(json.contains("verification_value_encrypted"));

        // Verify it's valid JSON
        let _doc: ExportDocument = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_export_vault_with_folders() {
        let master_key = MasterKey::new([1u8; 32]);
        let entries = vec![];
        let folders = vec![
            ExportedFolder {
                id: "folder-1".to_string(),
                name: "Personal".to_string(),
                parent_id: None,
                created_at: 1712188800,
                updated_at: 1712188800,
            },
            ExportedFolder {
                id: "folder-2".to_string(),
                name: "Work".to_string(),
                parent_id: Some("folder-1".to_string()),
                created_at: 1712188801,
                updated_at: 1712188801,
            },
        ];
        let kdf_params = crate::crypto::KdfParams::default_params();
        let options = ExportOptions::default();

        let json = export_vault(&entries, &folders, &kdf_params, &master_key, &options).unwrap();

        let doc: ExportDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc.folders.len(), 2);
        assert_eq!(doc.folders[0].name, "Personal");
        assert_eq!(doc.folders[1].name, "Work");
    }

    #[test]
    fn test_integrity_hash_verification() {
        let master_key = MasterKey::new([1u8; 32]);
        let entries = vec![create_test_entry("entry-1")];
        let folders = vec![];
        let kdf_params = crate::crypto::KdfParams::default_params();
        let options = ExportOptions::default();

        let json = export_vault(&entries, &folders, &kdf_params, &master_key, &options).unwrap();
        let doc: ExportDocument = serde_json::from_str(&json).unwrap();

        // Verification should succeed
        assert!(verify_integrity_hash(&doc).is_ok());

        // Tamper with entries
        let mut tampered_doc = doc.clone();
        tampered_doc.entries[0].title = "Tampered".to_string();

        // Verification should fail
        assert!(verify_integrity_hash(&tampered_doc).is_err());
    }

    #[test]
    fn test_integrity_hash_includes_folders() {
        let master_key = MasterKey::new([1u8; 32]);
        let entries = vec![];
        let folders = vec![ExportedFolder {
            id: "folder-1".to_string(),
            name: "Test".to_string(),
            parent_id: None,
            created_at: 0,
            updated_at: 0,
        }];
        let kdf_params = crate::crypto::KdfParams::default_params();
        let options = ExportOptions::default();

        let json = export_vault(&entries, &folders, &kdf_params, &master_key, &options).unwrap();
        let doc: ExportDocument = serde_json::from_str(&json).unwrap();

        // Tamper with folders
        let mut tampered_doc = doc.clone();
        tampered_doc.folders[0].name = "Tampered".to_string();

        // Verification should fail
        assert!(verify_integrity_hash(&tampered_doc).is_err());
    }

    #[test]
    fn test_export_includes_verification_value() {
        let master_key = MasterKey::new([1u8; 32]);
        let entries = vec![];
        let folders = vec![];
        let kdf_params = crate::crypto::KdfParams::default_params();
        let options = ExportOptions::default();

        let json = export_vault(&entries, &folders, &kdf_params, &master_key, &options).unwrap();
        let doc: ExportDocument = serde_json::from_str(&json).unwrap();

        assert!(!doc.metadata.verification_value_encrypted.is_empty());
        assert!(!doc.metadata.verification_nonce.is_empty());
    }

    #[test]
    fn test_url_preview_truncation() {
        let master_key = MasterKey::new([1u8; 32]);
        let long_url = "https://example.com/very/long/url/that/has/more/than/fifty/characters/here";
        let entry = Entry {
            id: "test".to_string(),
            title: "Test".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            url: Some(long_url.to_string()),
            notes: None,
            folder_id: None,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };

        let exported = export_entry(&entry, &master_key).unwrap();
        assert_eq!(exported.url_preview.len(), MAX_URL_PREVIEW_LENGTH);
        assert_eq!(&exported.url_preview, &long_url[..MAX_URL_PREVIEW_LENGTH]);
    }
}
