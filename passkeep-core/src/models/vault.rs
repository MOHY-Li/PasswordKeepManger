//! Vault metadata model

use serde::{Deserialize, Serialize};

/// 保险库元数据
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultMetadata {
    pub version: u32,
    pub kdf_params: crate::crypto::KdfParams,
    pub created_at: i64,
    pub updated_at: i64,
    pub entry_count: u32,
}

impl VaultMetadata {
    pub fn new(kdf_params: crate::crypto::KdfParams) -> Self {
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
    use crate::crypto::KdfParams;

    #[test]
    fn test_vault_metadata_new() {
        let kdf_params = KdfParams::new([0u8; 32]);
        let metadata = VaultMetadata::new(kdf_params);
        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.entry_count, 0);
    }

    #[test]
    fn test_vault_metadata_touch() {
        let kdf_params = KdfParams::new([0u8; 32]);
        let mut metadata = VaultMetadata::new(kdf_params);
        let old_updated_at = metadata.updated_at;
        metadata.touch();
        assert!(metadata.updated_at >= old_updated_at);
    }
}
