//! Fuzz target for incremental Merkle tree operations.

#![no_main]

use libfuzzer_sys::fuzz_target;
use escanorr_tree::IncrementalMerkleTree;
use ff::PrimeField;
use pasta_curves::pallas;

fuzz_target!(|data: &[u8]| {
    let mut tree = IncrementalMerkleTree::new();

    // Insert up to 64 leaves from fuzzer data (each leaf = 32 bytes)
    let num_leaves = data.len() / 32;
    let num_leaves = num_leaves.min(64);

    for i in 0..num_leaves {
        let mut leaf_bytes = [0u8; 32];
        leaf_bytes.copy_from_slice(&data[i * 32..(i + 1) * 32]);

        if let Some(leaf) = Option::from(pallas::Base::from_repr(leaf_bytes)) {
            let idx = tree.insert(leaf);
            assert_eq!(idx, i as u64);

            // Auth path should exist for every inserted leaf
            let path = tree.auth_path(idx);
            assert!(path.is_some(), "auth_path should succeed for valid index");
        }
    }

    // Root should be deterministic for same insertions
    let _root = tree.root();
});
