//! Key derivation function parameters
//!
//! TODO: This file belongs to future crypto implementation tasks (Task 5/6).
//! It is included here as scaffolding/preview of upcoming work.

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
