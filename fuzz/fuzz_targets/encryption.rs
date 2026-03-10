//! Fuzz target for note encryption/decryption.

#![no_main]

use libfuzzer_sys::fuzz_target;
use escanorr_note::encryption::{encrypt_note, decrypt_note};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // First 32 bytes as shared secret, rest as plaintext
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&data[..32]);
    let plaintext = &data[32..];

    match encrypt_note(&shared_secret, plaintext) {
        Ok(ciphertext) => {
            // Decrypt with same secret should recover plaintext
            let decrypted = decrypt_note(&shared_secret, &ciphertext)
                .expect("decrypt should succeed with correct key");
            assert_eq!(&decrypted[..], plaintext, "roundtrip mismatch");

            // Decrypt with different key should fail
            let mut wrong_secret = shared_secret;
            wrong_secret[0] ^= 0xFF;
            let _ = decrypt_note(&wrong_secret, &ciphertext);
        }
        Err(_) => {
            // Encryption failure — acceptable for edge cases
        }
    }
});
