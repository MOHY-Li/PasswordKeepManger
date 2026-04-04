//! FFI (Foreign Function Interface) module
//!
//! This module provides C-compatible interfaces for external language bindings.
//! It will be used to create bindings for:
//! - Python (via PyO3)
//! - JavaScript/WASM (via wasm-bindgen)
//! - Mobile platforms (via JNI/Kotlin Native)
//!
//! # Modules
//!
//! ## simple
//! A simple C FFI interface for Flutter integration.
//! Each function returns an error code (`i32`), where 0 = success, non-zero = error type.
//! The last error message is stored in thread-local storage and can be retrieved
//! via `passkeep_get_last_error()`.

pub mod simple;

// Re-export commonly used FFI types
pub use simple::{ErrorCode, PasskeepEntry, VaultHandleC};
