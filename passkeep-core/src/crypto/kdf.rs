//! Key derivation function parameters

use serde::{Deserialize, Serialize};

/// Parameters for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub memory: u32,
    pub parallelism: u32,
    pub salt: Vec<u8>,
}
