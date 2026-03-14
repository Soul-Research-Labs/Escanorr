//! Fuzz target for incremental Merkle tree operations.

#![no_main]

use libfuzzer_sys::fuzz_target;
use escanorr_tree::IncrementalMerkleTree;
use ff::PrimeField;
use pasta_curves::pallas;

fuzz_target!(|data: &[u8]| {
    let mut tree = IncrementalMerkleTree::new();
    let mut inserted_leaves = Vec::new();

    // Insert up to 64 leaves from fuzzer data (each leaf = 32 bytes)
    let num_leaves = data.len() / 32;
    let num_leaves = num_leaves.min(64);

    for i in 0..num_leaves {
        let mut leaf_bytes = [0u8; 32];
        leaf_bytes.copy_from_slice(&data[i * 32..(i + 1) * 32]);

        if let Some(leaf) = Option::from(pallas::Base::from_repr(leaf_bytes)) {
            let idx = tree.insert(leaf);
            assert_eq!(idx, i as u64);
            inserted_leaves.push(leaf);

            // Auth path should exist for every inserted leaf
            let path = tree.auth_path(idx);
            assert!(path.is_some(), "auth_path should succeed for valid index");
        }
    }

    // Root consistency invariant: every inserted leaf's auth path must
    // verify against the current root.
    let root = tree.root();
    for (i, leaf) in inserted_leaves.iter().enumerate() {
        let (siblings, path_indices) = tree
            .auth_path(i as u64)
            .expect("auth_path must exist for inserted leaf");
        assert!(
            IncrementalMerkleTree::verify_proof(root, *leaf, &siblings, &path_indices),
            "proof for leaf {} must verify against current root",
            i,
        );
    }

    // Out-of-bounds index should return None
    if !inserted_leaves.is_empty() {
        assert!(tree.auth_path(inserted_leaves.len() as u64).is_none());
    }
});
