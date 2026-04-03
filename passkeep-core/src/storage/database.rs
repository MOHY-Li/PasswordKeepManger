//! Database operations
//!
//! TODO: This file belongs to future storage implementation tasks.
//! It is included here as scaffolding/preview of upcoming work.

use crate::storage::error::PassKeepError;

/// The main database interface
pub struct Database {
    pub path: String,
}

impl Database {
    pub fn new(path: String) -> Result<Self, PassKeepError> {
        Ok(Database { path })
    }

    pub fn initialize(&self) -> Result<(), PassKeepError> {
        Ok(())
    }
}
