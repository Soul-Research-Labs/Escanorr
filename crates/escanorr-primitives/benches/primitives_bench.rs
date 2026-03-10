//! Benchmarks for Poseidon hash, nullifier computation, and proof envelope operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use escanorr_primitives::{
    compute_nullifier_v1, compute_nullifier_v2, DomainSeparator, ProofEnvelope,
    poseidon::{poseidon_hash, poseidon_hash_with_domain},
};
use pasta_curves::pallas;

fn bench_poseidon_hash(c: &mut Criterion) {
    let left = pallas::Base::from(123456u64);
    let right = pallas::Base::from(789012u64);

    c.bench_function("poseidon_hash", |b| {
        b.iter(|| poseidon_hash(black_box(left), black_box(right)))
    });
}

fn bench_poseidon_hash_with_domain(c: &mut Criterion) {
    let left = pallas::Base::from(123456u64);
    let right = pallas::Base::from(789012u64);
    let domain = b"escanorr.nullifier";

    c.bench_function("poseidon_hash_with_domain", |b| {
        b.iter(|| poseidon_hash_with_domain(black_box(domain), black_box(left), black_box(right)))
    });
}

fn bench_nullifier_v1(c: &mut Criterion) {
    let sk = pallas::Base::from(42u64);
    let cm = pallas::Base::from(999u64);

    c.bench_function("compute_nullifier_v1", |b| {
        b.iter(|| compute_nullifier_v1(black_box(sk), black_box(cm)))
    });
}

fn bench_nullifier_v2(c: &mut Criterion) {
    let sk = pallas::Base::from(42u64);
    let cm = pallas::Base::from(999u64);
    let domain = DomainSeparator::new(1, 1);

    c.bench_function("compute_nullifier_v2", |b| {
        b.iter(|| compute_nullifier_v2(black_box(sk), black_box(cm), black_box(&domain)))
    });
}

fn bench_envelope_seal(c: &mut Criterion) {
    let payload = vec![0xABu8; 1024]; // 1 KB proof payload

    c.bench_function("envelope_seal_1kb", |b| {
        b.iter(|| ProofEnvelope::seal(black_box(&payload)).unwrap())
    });
}

fn bench_envelope_open(c: &mut Criterion) {
    let payload = vec![0xABu8; 1024];
    let envelope = ProofEnvelope::seal(&payload).unwrap();

    c.bench_function("envelope_open_1kb", |b| {
        b.iter(|| envelope.open().unwrap())
    });
}

fn bench_envelope_seal_large(c: &mut Criterion) {
    let payload = vec![0xCDu8; 16384]; // 16 KB proof payload

    c.bench_function("envelope_seal_16kb", |b| {
        b.iter(|| ProofEnvelope::seal(black_box(&payload)).unwrap())
    });
}

criterion_group!(
    benches,
    bench_poseidon_hash,
    bench_poseidon_hash_with_domain,
    bench_nullifier_v1,
    bench_nullifier_v2,
    bench_envelope_seal,
    bench_envelope_open,
    bench_envelope_seal_large,
);
criterion_main!(benches);
