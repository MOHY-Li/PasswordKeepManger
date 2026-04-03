//! HKDF key derivation for combining master password and keyfile into Argon2 salt

use crate::storage::error::PassKeepError;
use hkdf::Hkdf;
use sha2::Sha256;

/// 使用 HKDF-Expand 派生 Argon2 salt
///
/// # Arguments
/// * `salt` - HKDF salt（来自数据库）
/// * `ikm` - 输入密钥材料（来自密钥文件）
/// * `output` - 输出缓冲区
pub fn expand(
    salt: &[u8; 32],
    ikm: &[u8; 32],
    output: &mut [u8; 32],
) -> Result<(), PassKeepError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    hkdf.expand(b"passkeep-argon2-salt", output)
        .map_err(|_| PassKeepError::KeyDerivationFailed)?;
    Ok(())
}

/// 带上下文的 HKDF-Expand
///
/// # Arguments
/// * `salt` - HKDF salt（来自数据库）
/// * `ikm` - 输入密钥材料（来自密钥文件）
/// * `info` - 上下文信息
/// * `output` - 输出缓冲区
pub fn expand_with_info(
    salt: &[u8; 32],
    ikm: &[u8; 32],
    info: &[&[u8]],
    output: &mut [u8; 32],
) -> Result<(), PassKeepError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    hkdf.expand_multi_info(info, output)
        .map_err(|_| PassKeepError::KeyDerivationFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_expand_same_input_same_output() {
        let salt = [0u8; 32];
        let ikm = [1u8; 32];

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        expand(&salt, &ikm, &mut out1).unwrap();
        expand(&salt, &ikm, &mut out2).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_hkdf_expand_different_info() {
        let salt = [0u8; 32];
        let ikm = [1u8; 32];

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        expand_with_info(&salt, &ikm, &[b"info-a"], &mut out1).unwrap();
        expand_with_info(&salt, &ikm, &[b"info-b"], &mut out2).unwrap();

        assert_ne!(out1, out2);
    }

    #[test]
    fn test_hkdf_expand_different_salt_produces_different_output() {
        let ikm = [1u8; 32];
        let salt1 = [0u8; 32];
        let salt2 = [1u8; 32];

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        expand(&salt1, &ikm, &mut out1).unwrap();
        expand(&salt2, &ikm, &mut out2).unwrap();

        assert_ne!(out1, out2);
    }

    #[test]
    fn test_hkdf_expand_different_ikm_produces_different_output() {
        let salt = [0u8; 32];
        let ikm1 = [0u8; 32];
        let ikm2 = [1u8; 32];

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        expand(&salt, &ikm1, &mut out1).unwrap();
        expand(&salt, &ikm2, &mut out2).unwrap();

        assert_ne!(out1, out2);
    }
}
