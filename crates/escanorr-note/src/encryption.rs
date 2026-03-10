//! ChaCha20-Poly1305 AEAD encryption for note delivery.
//!
//! Notes are encrypted with an ECDH shared secret so that only the
//! intended recipient can decrypt them.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;

/// Encryption error.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
}

/// Encrypt a plaintext note using a shared secret.
///
/// The shared secret is typically the x-coordinate of an ECDH shared point.
/// A random 12-byte nonce is prepended to the ciphertext.
pub fn encrypt_note(shared_secret: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let key = derive_encryption_key(shared_secret);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| EncryptionError::Encrypt(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::Encrypt(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a ciphertext note using a shared secret.
///
/// Expects the nonce prepended (first 12 bytes).
pub fn decrypt_note(shared_secret: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if ciphertext.len() < 12 {
        return Err(EncryptionError::Decrypt("ciphertext too short".into()));
    }

    let key = derive_encryption_key(shared_secret);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| EncryptionError::Decrypt(e.to_string()))?;

    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let plaintext = cipher
        .decrypt(nonce, &ciphertext[12..])
        .map_err(|e| EncryptionError::Decrypt(e.to_string()))?;

    Ok(plaintext)
}

/// Derive a 32-byte encryption key from a shared secret using HKDF-SHA256.
fn derive_encryption_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"escanorr-note-encryption"), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"chacha20poly1305", &mut key)
        .expect("HKDF expand should not fail for 32-byte output");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secret = [0x42u8; 32];
        let plaintext = b"this is a private note";
        let ciphertext = encrypt_note(&secret, plaintext).unwrap();
        let recovered = decrypt_note(&secret, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let secret = [0x42u8; 32];
        let wrong_secret = [0x43u8; 32];
        let plaintext = b"secret data";
        let ciphertext = encrypt_note(&secret, plaintext).unwrap();
        assert!(decrypt_note(&wrong_secret, &ciphertext).is_err());
    }

    #[test]
    fn ciphertext_differs_each_time() {
        let secret = [0x42u8; 32];
        let plaintext = b"same plaintext";
        let ct1 = encrypt_note(&secret, plaintext).unwrap();
        let ct2 = encrypt_note(&secret, plaintext).unwrap();
        assert_ne!(ct1, ct2, "nonce randomization should produce different ciphertexts");
    }

    #[test]
    fn empty_plaintext() {
        let secret = [0x42u8; 32];
        let ciphertext = encrypt_note(&secret, b"").unwrap();
        let recovered = decrypt_note(&secret, &ciphertext).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let secret = [0x42u8; 32];
        assert!(decrypt_note(&secret, &[0u8; 5]).is_err());
    }
}
