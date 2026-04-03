//! Database operations

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
