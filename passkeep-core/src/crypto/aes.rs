//! AES-256-GCM authenticated encryption
//!
//! Provides nonce-based encryption with authentication for password entries.

use crate::storage::error::PassKeepError;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use zeroize::Zeroizing;

/// AES-256-GCM 加密
///
/// # Arguments
/// * `plaintext` - 明文数据
/// * `key` - 32 字节密钥
/// * `aad` - 附加认证数据
///
/// # Returns
/// (密文, nonce) - 注意：aes-gcm 库返回的密文已包含 tag，这里返回 nonce 用于解密
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; 32],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), PassKeepError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // aes-gcm 的 encrypt 方法需要 Payload 结构，包含 msg 和 aad
    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| PassKeepError::EncryptionFailed)?;

    // 将 nonce 转换为数组返回
    let nonce_array = nonce.into();

    Ok((ciphertext, nonce_array))
}

/// AES-256-GCM 解密
pub fn decrypt(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    key: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>, PassKeepError> {
    let cipher = Aes256Gcm::new(key.into());

    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce.into(), payload)
        .map_err(|_| PassKeepError::DecryptionFailed)?;

    Ok(plaintext)
}

/// 使用指定 nonce 加密（用于实际存储）
pub fn encrypt_with_nonce(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, PassKeepError> {
    let cipher = Aes256Gcm::new(key.into());

    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce.into(), payload)
        .map_err(|_| PassKeepError::EncryptionFailed)?;

    Ok(ciphertext)
}

/// 使用指定 nonce 解密
pub fn decrypt_with_nonce(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, PassKeepError> {
    let cipher = Aes256Gcm::new(key.into());
    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce.into(), payload)
        .map_err(|_| PassKeepError::DecryptionFailed)?;

    Ok(plaintext)
}

/// 主密钥类型（内存安全）
pub type MasterKey = Zeroizing<[u8; 32]>;

/// 从切片创建主密钥
pub fn master_key_from_slice(slice: &[u8]) -> Option<MasterKey> {
    if slice.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(slice);
    Some(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"secret message";
        let key = [1u8; 32];
        let aad = b"additional authenticated data";

        let (ciphertext, nonce) = encrypt(plaintext, &key, aad).unwrap();
        let decrypted = decrypt(&ciphertext, &nonce, &key, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let plaintext = b"secret message";
        let key = [1u8; 32];
        let aad = b"additional authenticated data";

        let (ciphertext, _nonce) = encrypt(plaintext, &key, aad).unwrap();
        let wrong_nonce = [0u8; 12];

        let result = decrypt(&ciphertext, &wrong_nonce, &key, aad);
        assert!(matches!(result, Err(PassKeepError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_decrypt_with_nonce() {
        let plaintext = b"secret message";
        let key = [2u8; 32];
        let nonce = [3u8; 12];
        let aad = b"additional authenticated data";

        let ciphertext = encrypt_with_nonce(plaintext, &key, &nonce, aad).unwrap();
        let decrypted = decrypt_with_nonce(&ciphertext, &key, &nonce, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_nonce_wrong_key_fails() {
        let plaintext = b"secret message";
        let key = [2u8; 32];
        let wrong_key = [3u8; 32];
        let nonce = [3u8; 12];
        let aad = b"additional authenticated data";

        let ciphertext = encrypt_with_nonce(plaintext, &key, &nonce, aad).unwrap();
        let result = decrypt_with_nonce(&ciphertext, &wrong_key, &nonce, aad);

        assert!(matches!(result, Err(PassKeepError::DecryptionFailed)));
    }

    #[test]
    fn test_master_key_from_slice() {
        let slice = [1u8; 32];
        let key = master_key_from_slice(&slice);
        assert!(key.is_some());
        assert_eq!(key.unwrap().as_ref(), &slice);
    }

    #[test]
    fn test_master_key_from_slice_wrong_length() {
        let slice = [1u8; 16]; // Wrong length
        let key = master_key_from_slice(&slice);
        assert!(key.is_none());
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let plaintext = b"secret message";
        let key = [5u8; 32];
        let aad = b"correct aad";

        let (ciphertext, nonce) = encrypt(plaintext, &key, aad).unwrap();
        let wrong_aad = b"wrong aad";

        let result = decrypt(&ciphertext, &nonce, &key, wrong_aad);
        assert!(matches!(result, Err(PassKeepError::DecryptionFailed)));
    }

    #[test]
    fn test_empty_plaintext() {
        let plaintext = b"";
        let key = [6u8; 32];
        let aad = b"test";

        let (ciphertext, nonce) = encrypt(plaintext, &key, aad).unwrap();
        let decrypted = decrypt(&ciphertext, &nonce, &key, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let plaintext = vec![7u8; 10000];
        let key = [8u8; 32];
        let aad = b"large data test";

        let (ciphertext, nonce) = encrypt(&plaintext, &key, aad).unwrap();
        let decrypted = decrypt(&ciphertext, &nonce, &key, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
