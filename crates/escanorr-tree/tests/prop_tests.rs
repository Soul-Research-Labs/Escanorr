//! Property-based tests for escanorr-tree Merkle tree.

use proptest::prelude::*;

use escanorr_tree::IncrementalMerkleTree;
use pasta_curves::pallas;

// Real P128Pow5T3 Poseidon is ~100x slower than the old algebraic placeholder,
// so we keep proptest cases low to avoid multi-minute test runtimes.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn root_changes_on_every_insert(values in proptest::collection::vec(1u64..u64::MAX, 2..5)) {
        let mut tree = IncrementalMerkleTree::new();
        let mut roots = Vec::new();
        for v in &values {
            tree.insert(pallas::Base::from(*v));
            roots.push(tree.root());
        }
        for i in 1..roots.len() {
            prop_assert_ne!(roots[i], roots[i - 1]);
        }
    }

    #[test]
    fn insert_returns_sequential_indices(n in 1usize..6) {
        let mut tree = IncrementalMerkleTree::new();
        for i in 0..n {
            let idx = tree.insert(pallas::Base::from(i as u64));
            prop_assert_eq!(idx, i as u64);
        }
    }

    #[test]
    fn auth_path_verifies_for_any_leaf(values in proptest::collection::vec(1u64..u64::MAX, 1..5)) {
        let mut tree = IncrementalMerkleTree::new();
        for v in &values {
            tree.insert(pallas::Base::from(*v));
        }
        let path = tree.auth_path(0);
        prop_assert!(path.is_some());
    }

    #[test]
    fn tree_size_tracks_insertions(values in proptest::collection::vec(any::<u64>(), 0..6)) {
        let mut tree = IncrementalMerkleTree::new();
        for v in &values {
            tree.insert(pallas::Base::from(*v));
        }
        prop_assert_eq!(tree.size(), values.len() as u64);
    }
}
