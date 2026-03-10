//! Integration test for note encryption and stealth address roundtrip.

use escanorr_note::{
    encryption::{decrypt_note, encrypt_note},
    stealth::{stealth_receive, stealth_send, StealthMeta},
    Note, SpendingKey,
};
use ff::Field;
use group::Group;
use pasta_curves::pallas;
use rand::rngs::OsRng;

/// Encrypt and decrypt raw bytes using shared secret.
#[test]
fn note_encrypt_decrypt_roundtrip() {
    let shared_secret = [0xABu8; 32];
    let plaintext = b"hello privacy world";

    let ciphertext = encrypt_note(&shared_secret, plaintext).expect("encrypt should succeed");
    let decrypted = decrypt_note(&shared_secret, &ciphertext).expect("decrypt should succeed");

    assert_eq!(&decrypted[..], plaintext);
}

/// Decryption with wrong key fails.
#[test]
fn note_decrypt_wrong_key_fails() {
    let correct_secret = [0xABu8; 32];
    let wrong_secret = [0xCDu8; 32];
    let plaintext = b"secret data";

    let ciphertext = encrypt_note(&correct_secret, plaintext).expect("encrypt");
    let result = decrypt_note(&wrong_secret, &ciphertext);
    assert!(result.is_err(), "decryption with wrong key should fail");
}

/// Stealth address send/receive roundtrip.
#[test]
fn stealth_address_roundtrip() {
    let spend_sk = pallas::Scalar::random(OsRng);
    let view_sk = pallas::Scalar::random(OsRng);

    let spend_pk = pallas::Point::generator() * spend_sk;
    let view_pk = pallas::Point::generator() * view_sk;

    let meta = StealthMeta { spend_pk, view_pk };
    let stealth_addr = stealth_send(&meta);

    // Receiver scans using their secret keys
    let result = stealth_receive(spend_sk, view_sk, stealth_addr.ephemeral_pk, stealth_addr.owner);
    assert!(result.is_some(), "receiver should detect the stealth note");
}

/// Different sends produce different stealth addresses.
#[test]
fn stealth_addresses_are_unique() {
    let spend_sk = pallas::Scalar::random(OsRng);
    let view_sk = pallas::Scalar::random(OsRng);

    let spend_pk = pallas::Point::generator() * spend_sk;
    let view_pk = pallas::Point::generator() * view_sk;

    let meta = StealthMeta { spend_pk, view_pk };

    let addr1 = stealth_send(&meta);
    let addr2 = stealth_send(&meta);

    // Each send uses a random ephemeral key → different one-time addresses
    assert_ne!(addr1.owner, addr2.owner);
}

/// Note commitment is deterministic given the same inputs.
#[test]
fn note_commitment_deterministic() {
    let sk = SpendingKey::random();
    let fvk = sk.to_full_viewing_key();
    let owner = fvk.viewing_key.to_owner();
    let blinding = pallas::Base::from(42u64);

    let note1 = Note::with_blinding(owner, 1000, 0, blinding);
    let note2 = Note::with_blinding(owner, 1000, 0, blinding);

    assert_eq!(note1.commitment().0, note2.commitment().0);
}

/// Different values produce different commitments.
#[test]
fn note_commitment_changes_with_value() {
    let sk = SpendingKey::random();
    let fvk = sk.to_full_viewing_key();
    let owner = fvk.viewing_key.to_owner();

    let note1 = Note::new(owner, 1000, 0);
    let note2 = Note::new(owner, 2000, 0);

    assert_ne!(note1.commitment().0, note2.commitment().0);
}
