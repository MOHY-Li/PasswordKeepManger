//! BLAKE3 hash functionality
//!
//! Provides BLAKE3 hashing for integrity verification.

/// Compute BLAKE3 hash of data
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// 32-byte hash
pub fn hash(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

/// Compute BLAKE3 hash of multiple data chunks
///
/// # Arguments
/// * `chunks` - Iterator over data chunks to hash
///
/// # Returns
/// 32-byte hash
pub fn hash_chunks(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    let hash = hasher.finalize();
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"hello world";
        let hash_result = hash(data);
        assert_eq!(hash_result.len(), 32);
    }

    #[test]
    fn test_hash_is_deterministic() {
        let data = b"test data";
        let hash1 = hash(data);
        let hash2 = hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let hash1 = hash(b"test1");
        let hash2 = hash(b"test2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_chunks() {
        let chunk1 = b"hello";
        let chunk2 = b" ";
        let chunk3 = b"world";
        let hash_chunks_result = hash_chunks(&[chunk1, chunk2, chunk3]);
        let hash_single = hash(b"hello world");
        assert_eq!(hash_chunks_result, hash_single);
    }

    #[test]
    fn test_hash_empty() {
        let hash_result = hash(b"");
        assert_eq!(hash_result.len(), 32);
    }

    #[test]
    fn test_hash_large_data() {
        let data = vec![42u8; 10000];
        let hash_result = hash(&data);
        assert_eq!(hash_result.len(), 32);
    }
}
