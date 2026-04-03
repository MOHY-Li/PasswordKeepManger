//! PassKeep Core - 密码管理器核心库
//!
//! 提供加密、存储和 FFI 接口

pub mod crypto;
pub mod ffi;
pub mod import_export;
pub mod models;
pub mod storage;

// 重新导出常用类型
pub use crypto::{KdfParams, MasterKey};
pub use models::{Entry, EntryInput, EntryMetadata, VaultMetadata};
pub use storage::error::PassKeepError;
pub use storage::Database;

/// 库版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
