//! Vault metadata model

use serde::{Deserialize, Serialize};

/// Metadata about the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub version: u32,
    pub kdf_iterations: u32,
    pub kdf_memory: u32,
    pub kdf_parallelism: u32,
    pub created_at: i64,
    pub updated_at: i64,
}
