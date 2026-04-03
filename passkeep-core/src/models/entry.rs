//! Password entry model
//!
//! TODO: This file belongs to Task 3 (Data Models Definition).
//! It is included here as scaffolding/preview of upcoming work.

use serde::{Serialize, Deserialize};

/// 条目输入（包含明文敏感数据）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntryInput {
    pub id: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
}

/// 条目元数据（不含敏感信息）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntryMetadata {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url_preview: String,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 完整条目（包含解密后的敏感数据）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Entry {
    pub fn generate_url_preview(url: &Option<String>) -> String {
        url.as_ref()
            .map(|u| u.chars().take(50).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_url_preview() {
        assert_eq!(Entry::generate_url_preview(&None), "");
        assert_eq!(Entry::generate_url_preview(&Some("https://example.com".to_string())), "https://example.com");
        assert_eq!(Entry::generate_url_preview(&Some("a".repeat(100))), "a".repeat(50));
    }
}
