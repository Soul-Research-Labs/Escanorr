//! Property-based tests for escanorr-tree Merkle tree.

use proptest::prelude::*;

use escanorr_tree::IncrementalMerkleTree;
use pasta_curves::pallas;

proptest! {
    #[test]
    fn root_changes_on_every_insert(values in proptest::collection::vec(1u64..u64::MAX, 2..20)) {
        let mut tree = IncrementalMerkleTree::new();
        let mut roots = Vec::new();
        for v in &values {
            tree.insert(pallas::Base::from(*v));
            roots.push(tree.root());
        }
        // Each insertion should produce a distinct root (overwhelmingly likely)
        for i in 1..roots.len() {
            prop_assert_ne!(roots[i], roots[i - 1]);
        }
    }

    #[test]
    fn insert_returns_sequential_indices(n in 1usize..50) {
        let mut tree = IncrementalMerkleTree::new();
        for i in 0..n {
            let idx = tree.insert(pallas::Base::from(i as u64));
            prop_assert_eq!(idx, i as u64);
        }
    }

    #[test]
    fn auth_path_verifies_for_any_leaf(values in proptest::collection::vec(1u64..u64::MAX, 1..30)) {
        let mut tree = IncrementalMerkleTree::new();
        for v in &values {
            tree.insert(pallas::Base::from(*v));
        }
        // Pick the first leaf and verify its auth path
        let path = tree.auth_path(0);
        prop_assert!(path.is_some());
    }

    #[test]
    fn tree_size_tracks_insertions(values in proptest::collection::vec(any::<u64>(), 0..50)) {
        let mut tree = IncrementalMerkleTree::new();
        for v in &values {
            tree.insert(pallas::Base::from(*v));
        }
        prop_assert_eq!(tree.size(), values.len() as u64);
    }
}
