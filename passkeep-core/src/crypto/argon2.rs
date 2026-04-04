//! Argon2id key derivation for master key from password

use crate::storage::error::PassKeepError;
use zeroize::Zeroizing;

/// 使用 Argon2id 从主密码派生主密钥
///
/// # Arguments
/// * `password` - 主密码
/// * `salt` - 派生用的盐值（由 HKDF 生成）
/// * `params` - Argon2 参数
/// * `output` - 输出缓冲区
pub fn derive_key(
    password: &str,
    salt: &[u8; 32],
    params: &argon2::Params,
    output: &mut Zeroizing<[u8; 32]>,
) -> Result<(), PassKeepError> {
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );

    argon
        .hash_password_into(password.as_bytes(), salt, &mut **output)
        .map_err(|_| PassKeepError::KeyDerivationFailed)?;

    Ok(())
}

/// 使用默认参数派生密钥（用于测试）
#[cfg(test)]
pub fn derive_key_with_defaults(
    password: &str,
    salt: &[u8; 32],
    output: &mut Zeroizing<[u8; 32]>,
) -> Result<(), PassKeepError> {
    let params = argon2::Params::new(65536, 2, 2, None).unwrap();
    derive_key(password, salt, &params, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_same_input() {
        let password = "test-password";
        let salt = [0u8; 32];
        let params = argon2::Params::new(65536, 2, 2, None).unwrap();

        let mut key1 = Zeroizing::new([0u8; 32]);
        let mut key2 = Zeroizing::new([0u8; 32]);

        derive_key(password, &salt, &params, &mut key1).unwrap();
        derive_key(password, &salt, &params, &mut key2).unwrap();

        assert_eq!(*key1, *key2);
    }

    #[test]
    fn test_derive_key_different_input() {
        let salt = [0u8; 32];
        let params = argon2::Params::new(65536, 2, 2, None).unwrap();

        let mut key1 = Zeroizing::new([0u8; 32]);
        let mut key2 = Zeroizing::new([0u8; 32]);

        derive_key("password1", &salt, &params, &mut key1).unwrap();
        derive_key("password2", &salt, &params, &mut key2).unwrap();

        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_derive_key_different_salt() {
        let password = "test-password";
        let salt1 = [0u8; 32];
        let salt2 = [1u8; 32];
        let params = argon2::Params::new(65536, 2, 2, None).unwrap();

        let mut key1 = Zeroizing::new([0u8; 32]);
        let mut key2 = Zeroizing::new([0u8; 32]);

        derive_key(password, &salt1, &params, &mut key1).unwrap();
        derive_key(password, &salt2, &params, &mut key2).unwrap();

        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_derive_key_with_defaults() {
        let password = "test-password";
        let salt = [0u8; 32];

        let mut key1 = Zeroizing::new([0u8; 32]);
        let mut key2 = Zeroizing::new([0u8; 32]);

        derive_key_with_defaults(password, &salt, &mut key1).unwrap();
        derive_key_with_defaults(password, &salt, &mut key2).unwrap();

        assert_eq!(*key1, *key2);
    }

    #[test]
    fn test_derive_key_different_params() {
        let password = "test-password";
        let salt = [0u8; 32];
        let params1 = argon2::Params::new(65536, 2, 2, None).unwrap();
        let params2 = argon2::Params::new(32768, 2, 2, None).unwrap();

        let mut key1 = Zeroizing::new([0u8; 32]);
        let mut key2 = Zeroizing::new([0u8; 32]);

        derive_key(password, &salt, &params1, &mut key1).unwrap();
        derive_key(password, &salt, &params2, &mut key2).unwrap();

        assert_ne!(*key1, *key2);
    }
}
