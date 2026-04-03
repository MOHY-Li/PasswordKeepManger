//! Master key management
//!
//! TODO: This file belongs to future crypto implementation tasks.
//! It is included here as scaffolding/preview of upcoming work.

use serde::{Deserialize, Serialize};

/// The master key used for encryption/decryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKey {
    pub key: Vec<u8>,
}
