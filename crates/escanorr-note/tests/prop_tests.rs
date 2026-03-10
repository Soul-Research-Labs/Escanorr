//! Property-based tests for escanorr-note encryption module.

use proptest::prelude::*;

use escanorr_note::encryption::{encrypt_note, decrypt_note};

proptest! {
    #[test]
    fn encrypt_decrypt_roundtrip(
        secret in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let ct = encrypt_note(&secret, &plaintext).unwrap();
        let pt = decrypt_note(&secret, &ct).unwrap();
        prop_assert_eq!(plaintext, pt);
    }

    #[test]
    fn wrong_key_fails(
        secret_a in any::<[u8; 32]>(),
        secret_b in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..512)
    ) {
        prop_assume!(secret_a != secret_b);
        let ct = encrypt_note(&secret_a, &plaintext).unwrap();
        let result = decrypt_note(&secret_b, &ct);
        prop_assert!(result.is_err());
    }

    #[test]
    fn ciphertext_has_overhead(
        secret in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..1024)
    ) {
        let ct = encrypt_note(&secret, &plaintext).unwrap();
        // 12-byte nonce + 16-byte Poly1305 tag
        prop_assert_eq!(ct.len(), plaintext.len() + 12 + 16);
    }

    #[test]
    fn different_nonces_produce_different_ciphertext(
        secret in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 16..256)
    ) {
        let ct1 = encrypt_note(&secret, &plaintext).unwrap();
        let ct2 = encrypt_note(&secret, &plaintext).unwrap();
        // Nonces are random, so ciphertexts should differ
        prop_assert_ne!(ct1, ct2);
    }
}
