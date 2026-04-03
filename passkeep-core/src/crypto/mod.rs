//! Cryptographic operations for encryption and key derivation

pub mod aes;
pub mod argon2;
pub mod encryption;
pub mod hkdf;
pub mod kdf;
pub mod keyfile;
pub mod master_key;
pub mod rng;

// Re-exports
pub use argon2::derive_key;
pub use hkdf::{expand, expand_with_info};
pub use kdf::KdfParams;
pub use keyfile::{KeyFile, KEYFILE_SIZE, KEYFILE_VERSION};
pub use master_key::MasterKey;
pub use rng::{generate_nonce, generate_salt, generate_uuid};
