//! Export data structures
//!
//! Defines the format for vault export JSON.

use crate::crypto::KdfParams;
use serde::{Deserialize, Serialize};

/// Export format identifier
pub const EXPORT_FORMAT: &str = "passkeep-export";

/// Current export version
pub const EXPORT_VERSION: u32 = 1;

/// Verification value to encrypt (validates master key on import)
pub const VERIFICATION_VALUE: &str = "PASSKEEP-VERIFICATION";

/// Export metadata
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExportMetadata {
    /// Format identifier
    pub format: String,
    /// Format version
    pub version: u32,
    /// Export timestamp (Unix seconds)
    pub exported_at: i64,
    /// KDF parameters from source vault
    pub kdf_params: KdfParams,
    /// Encrypted verification value (base64)
    pub verification_value_encrypted: String,
    /// Nonce for verification value (base64)
    pub verification_nonce: String,
    /// BLAKE3 integrity hash of entries + folders (base64)
    pub integrity_hash: String,
}

/// Exported password entry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExportedEntry {
    /// Entry ID (UUID)
    pub id: String,
    /// Title (plaintext when encrypt_full_file=false)
    pub title: String,
    /// Username (plaintext when encrypt_full_file=false)
    pub username: String,
    /// Encrypted password (base64)
    #[serde(rename = "password_encrypted")]
    pub password_encrypted: String,
    /// URL preview (first 50 chars, plaintext)
    pub url_preview: String,
    /// Encrypted URL (base64, optional)
    #[serde(rename = "url_encrypted", skip_serializing_if = "Option::is_none")]
    pub url_encrypted: Option<String>,
    /// Encrypted notes (base64, optional)
    #[serde(rename = "notes_encrypted", skip_serializing_if = "Option::is_none")]
    pub notes_encrypted: Option<String>,
    /// Nonce for password encryption (base64)
    #[serde(rename = "password_nonce")]
    pub password_nonce: String,
    /// Nonce for URL encryption (base64, optional)
    #[serde(rename = "url_nonce", skip_serializing_if = "Option::is_none")]
    pub url_nonce: Option<String>,
    /// Nonce for notes encryption (base64, optional)
    #[serde(rename = "notes_nonce", skip_serializing_if = "Option::is_none")]
    pub notes_nonce: Option<String>,
    /// Parent folder ID (optional)
    pub folder_id: Option<String>,
    /// Tags
    pub tags: Vec<String>,
    /// Creation timestamp
    pub created_at: i64,
    /// Update timestamp
    pub updated_at: i64,
}

/// Exported folder
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExportedFolder {
    /// Folder ID (UUID)
    pub id: String,
    /// Folder name
    pub name: String,
    /// Parent folder ID (optional)
    pub parent_id: Option<String>,
    /// Creation timestamp
    pub created_at: i64,
    /// Update timestamp
    pub updated_at: i64,
}

/// Complete export document
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExportDocument {
    /// Export metadata
    pub metadata: ExportMetadata,
    /// Password entries
    pub entries: Vec<ExportedEntry>,
    /// Folders
    pub folders: Vec<ExportedFolder>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_constants() {
        assert_eq!(EXPORT_FORMAT, "passkeep-export");
        assert_eq!(EXPORT_VERSION, 1);
        assert_eq!(VERIFICATION_VALUE, "PASSKEEP-VERIFICATION");
    }

    #[test]
    fn test_export_document_serialization() {
        let doc = ExportDocument {
            metadata: ExportMetadata {
                format: EXPORT_FORMAT.to_string(),
                version: EXPORT_VERSION,
                exported_at: 1712188800,
                kdf_params: KdfParams::default_params(),
                verification_value_encrypted: "encrypted".to_string(),
                verification_nonce: "nonce".to_string(),
                integrity_hash: "hash".to_string(),
            },
            entries: vec![],
            folders: vec![],
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("passkeep-export"));
        assert!(json.contains("integrity_hash"));
    }

    #[test]
    fn test_exported_entry_minimal() {
        let entry = ExportedEntry {
            id: "uuid".to_string(),
            title: "Test".to_string(),
            username: "user".to_string(),
            password_encrypted: "enc".to_string(),
            url_preview: "".to_string(),
            url_encrypted: None,
            notes_encrypted: None,
            password_nonce: "nonce".to_string(),
            url_nonce: None,
            notes_nonce: None,
            folder_id: None,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };

        let json = serde_json::to_string(&entry).unwrap();
        // None fields should be skipped
        assert!(!json.contains("url_encrypted"));
        assert!(!json.contains("notes_encrypted"));
        assert!(!json.contains("url_nonce"));
        assert!(!json.contains("notes_nonce"));
    }
}
