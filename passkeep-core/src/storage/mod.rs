//! Database storage layer

pub mod database;
pub mod error;

// Re-exports
pub use database::Database;
pub use error::PassKeepError;
