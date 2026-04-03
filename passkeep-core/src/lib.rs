//! PassKeep Core - 密码管理器核心库
//!
//! 提供加密、存储和 FFI 接口

pub mod models;
pub mod crypto;
pub mod storage;
pub mod import_export;

// 重新导出常用类型
pub use models::{Entry, EntryInput, EntryMetadata, VaultMetadata};
pub use crypto::{MasterKey, KdfParams};
pub use storage::Database;
pub use storage::error::PassKeepError;

/// 库版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
