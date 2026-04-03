//! Cryptographic random number generation utilities
//!
//! Provides functions for generating nonces, UUIDs, and salts for cryptographic operations.

use getrandom::getrandom;

/// Generates a cryptographic nonce (12 bytes) for AES-GCM encryption.
///
/// # Returns
/// A 12-byte array containing cryptographically secure random data.
///
/// # Panics
/// Panics if the underlying RNG fails.
///
/// # Examples
/// ```ignore
/// let nonce = generate_nonce();
/// assert_eq!(nonce.len(), 12);
/// ```
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    getrandom(&mut nonce).expect("RNG failed");
    nonce
}

/// Generates a UUID v4 string.
///
/// # Returns
/// A string containing a randomly generated UUID.
///
/// # Examples
/// ```ignore
/// let id = generate_uuid();
/// assert!(uuid::Uuid::parse_str(&id).is_ok());
/// ```
pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generates a random salt (32 bytes) for key derivation functions.
///
/// # Returns
/// A 32-byte array containing cryptographically secure random data.
///
/// # Panics
/// Panics if the underlying RNG fails.
///
/// # Examples
/// ```ignore
/// let salt = generate_salt();
/// assert_eq!(salt.len(), 32);
/// ```
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    getrandom(&mut salt).expect("RNG failed");
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce_is_unique() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn test_generate_uuid() {
        let id1 = generate_uuid();
        let id2 = generate_uuid();

        assert_ne!(id1, id2);
        assert!(uuid::Uuid::parse_str(&id1).is_ok());
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), 32);
    }
}
