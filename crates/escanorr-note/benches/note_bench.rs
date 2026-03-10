//! Benchmarks for note encryption/decryption and key derivation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use escanorr_note::{
    encryption::{encrypt_note, decrypt_note},
    Note, SpendingKey,
};

fn bench_spending_key_random(c: &mut Criterion) {
    c.bench_function("spending_key_random", |b| {
        b.iter(|| SpendingKey::random())
    });
}

fn bench_full_viewing_key(c: &mut Criterion) {
    let sk = SpendingKey::random();

    c.bench_function("spending_key_to_fvk", |b| {
        b.iter(|| black_box(&sk).to_full_viewing_key())
    });
}

fn bench_note_commitment(c: &mut Criterion) {
    let sk = SpendingKey::random();
    let fvk = sk.to_full_viewing_key();
    let owner = fvk.viewing_key.to_owner();
    let note = Note::new(owner, 1000, 0);

    c.bench_function("note_commitment", |b| {
        b.iter(|| black_box(&note).commitment())
    });
}

fn bench_encrypt_note(c: &mut Criterion) {
    let shared_secret = [0xABu8; 32];
    let plaintext = vec![0u8; 128]; // 128-byte note payload

    c.bench_function("encrypt_note_128b", |b| {
        b.iter(|| encrypt_note(black_box(&shared_secret), black_box(&plaintext)).unwrap())
    });
}

fn bench_decrypt_note(c: &mut Criterion) {
    let shared_secret = [0xABu8; 32];
    let plaintext = vec![0u8; 128];
    let ciphertext = encrypt_note(&shared_secret, &plaintext).unwrap();

    c.bench_function("decrypt_note_128b", |b| {
        b.iter(|| decrypt_note(black_box(&shared_secret), black_box(&ciphertext)).unwrap())
    });
}

fn bench_nullifier(c: &mut Criterion) {
    let sk = SpendingKey::random();
    let fvk = sk.to_full_viewing_key();
    let owner = fvk.viewing_key.to_owner();
    let note = Note::new(owner, 1000, 0);
    let cm = note.commitment().0;

    c.bench_function("nullifier_from_fvk", |b| {
        b.iter(|| fvk.nullifier(black_box(cm)))
    });
}

criterion_group!(
    benches,
    bench_spending_key_random,
    bench_full_viewing_key,
    bench_note_commitment,
    bench_encrypt_note,
    bench_decrypt_note,
    bench_nullifier,
);
criterion_main!(benches);
