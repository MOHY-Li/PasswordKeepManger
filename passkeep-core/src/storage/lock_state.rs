//! Lock state management
//!
//! Implements exponential backoff lockout protection against brute force attacks.
//! Lock duration: 30s × 2^(failed_attempts - 3), capped at 512s (30 × 2^10).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 暴力破解防护状态（存储在数据库中）
#[derive(Debug, Clone)]
pub struct LockState {
    pub failed_attempts: u32,
    pub lock_until: Option<i64>,
    pub last_attempt_at: i64,
}

impl LockState {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            failed_attempts: 0,
            lock_until: None,
            last_attempt_at: now,
        }
    }

    /// 计算锁定时长（秒）- 指数退避
    /// Formula: 30 × 2^(failed_attempts - 3), capped at 512 seconds
    pub fn calculate_lock_duration(&self) -> i64 {
        if self.failed_attempts < 3 {
            return 0;
        }
        let base = 30i64;
        // Calculate 30 * 2^(failed_attempts - 3), capped at 512
        let exponent = (self.failed_attempts - 3).min(9) as u32; // Cap exponent so 30 * 2^9 = 30 * 512 = 15360, still capped
        (base * (1 << exponent)).min(512)
    }

    /// 记录一次失败尝试，返回新的锁定时长
    pub fn record_failure(&mut self) -> Duration {
        self.failed_attempts += 1;
        let duration = self.calculate_lock_duration();

        self.last_attempt_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if duration > 0 {
            self.lock_until = Some(self.last_attempt_at + duration);
        }

        Duration::from_secs(duration as u64)
    }

    /// 记录成功，重置失败计数
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.lock_until = None;
    }

    /// 检查是否被锁定
    pub fn is_locked(&self) -> bool {
        if let Some(until) = self.lock_until {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            now < until
        } else {
            false
        }
    }

    /// 获取剩余锁定时间
    pub fn remaining_lock_time(&self) -> Duration {
        if let Some(until) = self.lock_until {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if until > now {
                return Duration::from_secs((until - now) as u64);
            }
        }
        Duration::ZERO
    }
}

impl Default for LockState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_time_calculation() {
        let mut state = LockState::new();
        state.failed_attempts = 3;
        assert_eq!(state.calculate_lock_duration(), 30);

        state.failed_attempts = 4;
        assert_eq!(state.calculate_lock_duration(), 60);
    }

    #[test]
    fn test_lock_time_under_3() {
        let mut state = LockState::new();
        state.failed_attempts = 2;
        assert_eq!(state.calculate_lock_duration(), 0);

        state.failed_attempts = 0;
        assert_eq!(state.calculate_lock_duration(), 0);
    }

    #[test]
    fn test_lock_time_max() {
        let mut state = LockState::new();
        state.failed_attempts = 20; // 超过封顶值
        assert_eq!(state.calculate_lock_duration(), 512); // 30 * 2^10
    }

    #[test]
    fn test_lock_time_exponential_growth() {
        let mut state = LockState::new();

        // 3 attempts: 30s
        state.failed_attempts = 3;
        assert_eq!(state.calculate_lock_duration(), 30);

        // 4 attempts: 60s
        state.failed_attempts = 4;
        assert_eq!(state.calculate_lock_duration(), 60);

        // 5 attempts: 120s
        state.failed_attempts = 5;
        assert_eq!(state.calculate_lock_duration(), 120);

        // 6 attempts: 240s
        state.failed_attempts = 6;
        assert_eq!(state.calculate_lock_duration(), 240);

        // 13 attempts: should hit max of 512s
        state.failed_attempts = 13;
        assert_eq!(state.calculate_lock_duration(), 512);
    }

    #[test]
    fn test_record_success() {
        let mut state = LockState::new();
        state.failed_attempts = 5;
        state.record_success();
        assert_eq!(state.failed_attempts, 0);
        assert!(state.lock_until.is_none());
    }

    #[test]
    fn test_record_failure_increments_attempts() {
        let mut state = LockState::new();

        // First failure
        let duration = state.record_failure();
        assert_eq!(state.failed_attempts, 1);
        assert_eq!(duration.as_secs(), 0); // No lock under 3 attempts
        assert!(state.lock_until.is_none());

        // Second failure
        let duration = state.record_failure();
        assert_eq!(state.failed_attempts, 2);
        assert_eq!(duration.as_secs(), 0);

        // Third failure - should trigger lock
        let duration = state.record_failure();
        assert_eq!(state.failed_attempts, 3);
        assert_eq!(duration.as_secs(), 30);
        assert!(state.lock_until.is_some());
    }

    #[test]
    fn test_is_locked() {
        let mut state = LockState::new();

        // Not locked initially
        assert!(!state.is_locked());

        // After 2 failures - not locked
        state.failed_attempts = 2;
        assert!(!state.is_locked());

        // After 3 failures - should be locked
        state.record_failure();
        assert!(state.is_locked());

        // After success - not locked
        state.record_success();
        assert!(!state.is_locked());
    }

    #[test]
    fn test_remaining_lock_time() {
        let mut state = LockState::new();

        // No lock - zero duration
        assert_eq!(state.remaining_lock_time(), Duration::ZERO);

        // After 1-2 failures - still no lock
        state.record_failure();
        state.record_failure();
        assert_eq!(state.remaining_lock_time(), Duration::ZERO);

        // After 3 failures - should have lock time
        state.record_failure();
        assert!(state.remaining_lock_time() > Duration::ZERO);

        // After success - zero duration
        state.record_success();
        assert_eq!(state.remaining_lock_time(), Duration::ZERO);
    }

    #[test]
    fn test_new_creates_valid_state() {
        let state = LockState::new();
        assert_eq!(state.failed_attempts, 0);
        assert!(state.lock_until.is_none());
        assert!(state.last_attempt_at > 0);
    }

    #[test]
    fn test_default_trait() {
        let state = LockState::default();
        assert_eq!(state.failed_attempts, 0);
        assert!(state.lock_until.is_none());
    }
}
