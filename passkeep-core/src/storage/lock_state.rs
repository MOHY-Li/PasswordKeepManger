//! Lock state management
//!
//! TODO: This file belongs to a future task.
//! It is included here as scaffolding.

#[derive(Debug, Clone)]
pub struct LockState {
    pub locked_until: Option<i64>,
}

impl LockState {
    pub fn new() -> Self {
        Self { locked_until: None }
    }
}

impl Default for LockState {
    fn default() -> Self {
        Self::new()
    }
}
