//! Key derivation function parameters

use serde::{Deserialize, Serialize};

/// Key derivation parameters (Argon2id)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Salt for key derivation (32 bytes)
    pub salt: [u8; 32],
    /// Memory cost in KiB
    pub mem_cost_kib: u32,
    /// Time cost (number of iterations)
    pub time_cost: u32,
    /// Parallelism (number of threads)
    pub parallelism: u32,
}

impl KdfParams {
    /// Create default KDF parameters
    pub fn default_params() -> Self {
        Self {
            salt: [0u8; 32],
            mem_cost_kib: 262144, // 256 MiB
            time_cost: 3,
            parallelism: 4,
        }
    }

    /// Create new KDF parameters with a random salt
    pub fn new(salt: [u8; 32]) -> Self {
        Self {
            salt,
            ..Self::default_params()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_params_default() {
        let params = KdfParams::default_params();
        assert_eq!(params.mem_cost_kib, 262144);
        assert_eq!(params.time_cost, 3);
        assert_eq!(params.parallelism, 4);
    }

    #[test]
    fn test_kdf_params_new() {
        let salt = [42u8; 32];
        let params = KdfParams::new(salt);
        assert_eq!(params.salt, salt);
        assert_eq!(params.mem_cost_kib, 262144);
    }

    #[test]
    fn test_kdf_params_serialization() {
        let params = KdfParams {
            salt: [1u8; 32],
            mem_cost_kib: 65536,
            time_cost: 2,
            parallelism: 2,
        };

        let json = serde_json::to_string(&params).unwrap();
        let de: KdfParams = serde_json::from_str(&json).unwrap();

        assert_eq!(de.salt, params.salt);
        assert_eq!(de.mem_cost_kib, params.mem_cost_kib);
    }

    #[test]
    fn test_kdf_params_equality() {
        let params1 = KdfParams {
            salt: [1u8; 32],
            mem_cost_kib: 65536,
            time_cost: 2,
            parallelism: 2,
        };

        let params2 = KdfParams {
            salt: [1u8; 32],
            mem_cost_kib: 65536,
            time_cost: 2,
            parallelism: 2,
        };

        assert_eq!(params1, params2);
    }

    #[test]
    fn test_kdf_params_inequality() {
        let params1 = KdfParams {
            salt: [1u8; 32],
            ..KdfParams::default_params()
        };

        let params2 = KdfParams {
            salt: [2u8; 32],
            ..KdfParams::default_params()
        };

        assert_ne!(params1, params2);
    }
}
