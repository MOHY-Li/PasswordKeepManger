//! Error types for passkeep-core

use thiserror::Error;

/// Main error type for passkeep-core
#[derive(Error, Debug)]
pub enum PassKeepError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
