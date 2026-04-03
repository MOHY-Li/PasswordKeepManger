//! Keyfile handling with BLAKE3 checksum verification
//!
//! Keyfiles provide an additional authentication factor beyond the master password.
//! Each keyfile contains:
//! - A 32-byte randomly generated secret
//! - BLAKE3 checksum for integrity verification
//! - Version field for future compatibility

use crate::storage::error::PassKeepError;
use blake3::Hasher;
use std::fs;
use std::path::Path;
use subtle::ConstantTimeEq;

/// Keyfile magic bytes for format identification
pub const KEYFILE_MAGIC: &[u8; 4] = b"PKEY";

/// Current keyfile format version
pub const KEYFILE_VERSION: u32 = 1;

/// Total keyfile size in bytes (magic + version + secret + checksum)
pub const KEYFILE_SIZE: usize = 4 + 4 + 32 + 32; // 72 bytes

/// Keyfile structure containing a cryptographic secret
///
/// The keyfile provides a second factor of authentication. The secret
/// is combined with the master password during key derivation.
#[derive(Debug, Clone)]
pub struct KeyFile {
    /// Format version
    pub version: u32,
    /// 32-byte cryptographic secret
    pub secret: [u8; 32],
    /// BLAKE3 checksum of (secret || version)
    pub checksum: [u8; 32],
}

impl Default for KeyFile {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyFile {
    /// Creates a new keyfile with a randomly generated secret
    ///
    /// # Panics
    /// Panics if the system's random number generator fails.
    pub fn new() -> Self {
        use getrandom::getrandom;

        let mut secret = [0u8; 32];
        getrandom(&mut secret).expect("Failed to generate secret");

        let mut hasher = Hasher::new();
        hasher.update(&secret);
        hasher.update(&KEYFILE_VERSION.to_le_bytes());
        let checksum = hasher.finalize();

        Self {
            version: KEYFILE_VERSION,
            secret,
            checksum: *checksum.as_bytes(),
        }
    }

    /// Serializes the keyfile to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(KEYFILE_SIZE);
        bytes.extend_from_slice(KEYFILE_MAGIC);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.secret);
        bytes.extend_from_slice(&self.checksum);
        bytes
    }

    /// Loads and validates a keyfile from the given path
    ///
    /// # Errors
    /// - `KeyFileInvalid` if the file format is invalid
    /// - `KeyFileVersionMismatch` if the version is unsupported
    /// - `KeyFileCorrupted` if the checksum doesn't match
    /// - `Io` for file system errors
    pub fn from_path(path: &Path) -> Result<Self, PassKeepError> {
        let data = fs::read(path)?;

        if data.len() != KEYFILE_SIZE {
            return Err(PassKeepError::KeyFileInvalid);
        }

        if &data[0..4] != KEYFILE_MAGIC {
            return Err(PassKeepError::KeyFileInvalid);
        }

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != KEYFILE_VERSION {
            return Err(PassKeepError::KeyFileVersionMismatch(version));
        }

        let secret: [u8; 32] = data[8..40].try_into().unwrap();
        let stored_checksum: [u8; 32] = data[40..72].try_into().unwrap();

        // Verify checksum using constant-time comparison to prevent timing attacks
        let mut hasher = Hasher::new();
        hasher.update(&secret);
        hasher.update(&version.to_le_bytes());
        let computed_checksum = hasher.finalize();

        if !bool::from(computed_checksum.as_bytes().ct_eq(&stored_checksum)) {
            return Err(PassKeepError::KeyFileCorrupted);
        }

        Ok(Self {
            version,
            secret,
            checksum: stored_checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_valid_keyfile() {
        let mut temp = NamedTempFile::new().unwrap();
        let keyfile = KeyFile::new();

        temp.write_all(&keyfile.to_bytes()).unwrap();

        let result = KeyFile::from_path(temp.path());
        assert!(result.is_ok());

        let loaded = result.unwrap();
        assert_eq!(loaded.version, KEYFILE_VERSION);
        assert_eq!(loaded.secret, keyfile.secret);
        assert_eq!(loaded.checksum, keyfile.checksum);
    }

    #[test]
    fn test_validate_invalid_magic() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"XXXX").unwrap();

        let result = KeyFile::from_path(temp.path());
        assert!(matches!(result, Err(PassKeepError::KeyFileInvalid)));
    }

    #[test]
    fn test_validate_corrupted_checksum() {
        let mut temp = NamedTempFile::new().unwrap();
        let keyfile = KeyFile::new();

        // Corrupt the checksum by modifying it before serialization
        let mut bytes = keyfile.to_bytes();
        bytes[70] ^= 0xFF; // Modify last byte of checksum

        temp.write_all(&bytes).unwrap();

        let result = KeyFile::from_path(temp.path());
        assert!(matches!(result, Err(PassKeepError::KeyFileCorrupted)));
    }

    #[test]
    fn test_validate_wrong_size() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"PKEY").unwrap(); // Too short

        let result = KeyFile::from_path(temp.path());
        assert!(matches!(result, Err(PassKeepError::KeyFileInvalid)));
    }

    #[test]
    fn test_validate_version_mismatch() {
        let mut temp = NamedTempFile::new().unwrap();

        // Create a keyfile bytes with wrong version
        let mut bytes = Vec::with_capacity(KEYFILE_SIZE);
        bytes.extend_from_slice(KEYFILE_MAGIC);
        bytes.extend_from_slice(&9999u32.to_le_bytes()); // Wrong version
        bytes.extend_from_slice(&[0u8; 32]); // dummy secret
        bytes.extend_from_slice(&[0u8; 32]); // dummy checksum

        temp.write_all(&bytes).unwrap();

        let result = KeyFile::from_path(temp.path());
        assert!(matches!(
            result,
            Err(PassKeepError::KeyFileVersionMismatch(9999))
        ));
    }

    #[test]
    fn test_keyfile_secret_is_unique() {
        let keyfile1 = KeyFile::new();
        let keyfile2 = KeyFile::new();

        // Two generated secrets should be different (extremely unlikely to be equal)
        assert_ne!(keyfile1.secret, keyfile2.secret);
    }

    #[test]
    fn test_keyfile_to_bytes_roundtrip() {
        let keyfile = KeyFile::new();
        let bytes = keyfile.to_bytes();

        assert_eq!(bytes.len(), KEYFILE_SIZE);
        assert_eq!(&bytes[0..4], KEYFILE_MAGIC);
    }

    #[test]
    fn test_corrupted_secret_detected() {
        let mut temp = NamedTempFile::new().unwrap();
        let keyfile = KeyFile::new();

        // Corrupt the secret
        let mut bytes = keyfile.to_bytes();
        bytes[10] ^= 0xFF; // Modify a byte in the secret

        temp.write_all(&bytes).unwrap();

        let result = KeyFile::from_path(temp.path());
        // Checksum validation should fail
        assert!(matches!(result, Err(PassKeepError::KeyFileCorrupted)));
    }
}
