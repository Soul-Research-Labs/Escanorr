//! Benchmarks for incremental Merkle tree operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use escanorr_tree::IncrementalMerkleTree;
use pasta_curves::pallas;

fn bench_merkle_insert(c: &mut Criterion) {
    c.bench_function("merkle_insert_single", |b| {
        let mut tree = IncrementalMerkleTree::new();
        let leaf = pallas::Base::from(42u64);
        b.iter(|| {
            tree.insert(black_box(leaf));
        })
    });
}

fn bench_merkle_root(c: &mut Criterion) {
    let mut tree = IncrementalMerkleTree::new();
    for i in 0..100u64 {
        tree.insert(pallas::Base::from(i + 1));
    }

    c.bench_function("merkle_root_100_leaves", |b| {
        b.iter(|| tree.root())
    });
}

fn bench_merkle_auth_path(c: &mut Criterion) {
    let mut tree = IncrementalMerkleTree::new();
    for i in 0..100u64 {
        tree.insert(pallas::Base::from(i + 1));
    }

    c.bench_function("merkle_auth_path_100_leaves", |b| {
        b.iter(|| tree.auth_path(black_box(50)))
    });
}

fn bench_merkle_bulk_insert(c: &mut Criterion) {
    c.bench_function("merkle_insert_1000", |b| {
        b.iter(|| {
            let mut tree = IncrementalMerkleTree::new();
            for i in 0..1000u64 {
                tree.insert(pallas::Base::from(i + 1));
            }
            black_box(tree.root());
        })
    });
}

criterion_group!(
    benches,
    bench_merkle_insert,
    bench_merkle_root,
    bench_merkle_auth_path,
    bench_merkle_bulk_insert,
);
criterion_main!(benches);
