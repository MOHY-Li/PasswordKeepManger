//! Master key management

use serde::{Deserialize, Serialize};

/// The master key used for encryption/decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKey {
    pub key: Vec<u8>,
}
