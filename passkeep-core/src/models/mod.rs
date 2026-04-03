//! Data models for password entries and vault metadata

pub mod entry;
pub mod vault;

// Re-exports
pub use entry::{Entry, EntryInput, EntryMetadata};
pub use vault::VaultMetadata;
