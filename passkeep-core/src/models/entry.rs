//! Password entry model
//!
//! TODO: This file belongs to Task 3 (Data Models Definition).
//! It is included here as scaffolding/preview of upcoming work.

use serde::{Deserialize, Serialize};

/// A password entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Input for creating or updating an entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryInput {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
}

/// Metadata for an entry (without sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
