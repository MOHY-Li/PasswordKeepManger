//! Vault metadata model
//!
//! TODO: This file belongs to Task 3 (Data Models Definition).
//! It is included here as scaffolding/preview of upcoming work.

use serde::{Deserialize, Serialize};

/// 主密钥派生参数
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub salt: [u8; 32],
    pub mem_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

/// 保险库元数据
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultMetadata {
    pub version: u32,
    pub kdf_params: KdfParams,
    pub created_at: i64,
    pub updated_at: i64,
    pub entry_count: u32,
}

impl VaultMetadata {
    pub fn new(kdf_params: KdfParams) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            version: 1,
            kdf_params,
            created_at: now,
            updated_at: now,
            entry_count: 0,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_params_serialization() {
        let params = KdfParams {
            salt: [0u8; 32],
            mem_cost_kib: 262144,
            time_cost: 3,
            parallelism: 4,
        };

        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("262144"));

        let de: KdfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(de.mem_cost_kib, 262144);
    }
}
