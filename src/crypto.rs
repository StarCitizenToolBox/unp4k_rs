//! Cryptographic functions for P4K file decryption and encryption
//!
//! Star Citizen uses AES-128-CBC encryption for some entries in the P4K archive.
//! The encryption key is the same public key used by CryEngine-based games.

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use crate::error::{Error, Result};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

/// The standard encryption key used by Star Citizen / CryEngine
/// This is the same key referenced in the C# unp4k project
pub const P4K_KEY: [u8; 16] = [
    0x5E, 0x7A, 0x20, 0x02, 0x30, 0x2E, 0xEB, 0x1A,
    0x3B, 0xB6, 0x17, 0xC3, 0x0F, 0xDE, 0x1E, 0x47,
];

/// Decrypt data using AES-128-CBC with the P4K key
///
/// # Arguments
/// * `data` - The encrypted data (must be a multiple of 16 bytes)
///
/// # Returns
/// Decrypted data with PKCS7 padding removed
pub fn decrypt_aes_cbc(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // AES block size is 16 bytes
    if !data.len().is_multiple_of(16) {
        return Err(Error::Decryption(format!(
            "Data length {} is not a multiple of 16",
            data.len()
        )));
    }

    // IV is all zeros for P4K decryption
    let iv = [0u8; 16];

    let cipher = Aes128CbcDec::new(&P4K_KEY.into(), &iv.into());

    let mut buffer = data.to_vec();
    
    let decrypted = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|e| Error::Decryption(format!("AES decryption failed: {:?}", e)))?;

    // Remove trailing null bytes (padding)
    let mut result = decrypted.to_vec();
    while result.last() == Some(&0) {
        result.pop();
    }

    Ok(result)
}

/// Encrypt data using AES-128-CBC with the P4K key
///
/// # Arguments
/// * `data` - The data to encrypt
///
/// # Returns
/// Encrypted data padded to 16-byte boundary
pub fn encrypt_aes_cbc(data: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::block_padding::ZeroPadding;
    
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // IV is all zeros for P4K encryption
    let iv = [0u8; 16];

    let cipher = Aes128CbcEnc::new(&P4K_KEY.into(), &iv.into());

    // Pad to 16-byte boundary with zero padding (matching P4K format)
    let padded_len = data.len().div_ceil(16) * 16;
    let mut buffer = vec![0u8; padded_len];
    buffer[..data.len()].copy_from_slice(data);

    let encrypted = cipher
        .encrypt_padded_mut::<ZeroPadding>(&mut buffer, padded_len)
        .map_err(|e| Error::Decryption(format!("AES encryption failed: {:?}", e)))?;

    Ok(encrypted.to_vec())
}

/// Check if data appears to be encrypted
/// Encrypted data in P4K files typically starts with non-printable characters
pub fn is_likely_encrypted(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    // Check for common unencrypted file signatures
    // PK (ZIP), CryXml signatures, XML declaration, etc.
    let signatures: &[&[u8]] = &[
        b"PK",
        b"CryXml",
        b"CryXmlB",
        b"CRY3SDK",
        b"<?xml",
        b"<",
    ];
    
    !signatures.iter().any(|sig| data.starts_with(sig))
}

/// Check if data is a ZSTD compressed stream
pub fn is_zstd_stream(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    // ZSTD magic number: 0xFD2FB528
    data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_length() {
        assert_eq!(P4K_KEY.len(), 16);
    }

    #[test]
    fn test_is_zstd_stream() {
        let zstd_header = [0x28, 0xB5, 0x2F, 0xFD, 0x00];
        assert!(is_zstd_stream(&zstd_header));
        
        let not_zstd = [0x50, 0x4B, 0x03, 0x04]; // PK signature
        assert!(!is_zstd_stream(&not_zstd));
    }
}
