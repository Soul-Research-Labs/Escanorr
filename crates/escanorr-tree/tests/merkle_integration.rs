//! Integration test for the Merkle tree.

use escanorr_tree::IncrementalMerkleTree;
use pasta_curves::pallas;

/// Insert leaves into the tree and verify structure.
#[test]
fn merkle_insert_and_verify() {
    let mut tree = IncrementalMerkleTree::new();

    // Insert 10 leaves
    let mut indices = Vec::new();
    for i in 0..10u64 {
        let leaf = pallas::Base::from(i * 100 + 1);
        let idx = tree.insert(leaf);
        indices.push(idx);
    }

    assert_eq!(tree.size(), 10);

    // Verify each leaf's Merkle auth path exists
    let _root = tree.root();
    for &idx in &indices {
        let path = tree.auth_path(idx).expect("path should exist");
        assert!(!path.0.is_empty(), "auth path should not be empty");
    }
}

/// Root changes with each insertion.
#[test]
fn root_changes_on_insert() {
    let mut tree = IncrementalMerkleTree::new();
    let root0 = tree.root();

    let leaf = pallas::Base::from(42u64);
    tree.insert(leaf);
    let root1 = tree.root();

    assert_ne!(root0, root1);

    tree.insert(pallas::Base::from(43u64));
    let root2 = tree.root();

    assert_ne!(root1, root2);
}

/// Empty tree has a deterministic initial root.
#[test]
fn empty_tree_root_is_deterministic() {
    let t1 = IncrementalMerkleTree::new();
    let t2 = IncrementalMerkleTree::new();
    assert_eq!(t1.root(), t2.root());
}

/// Tree can hold many leaves.
#[test]
fn bulk_insert() {
    let mut tree = IncrementalMerkleTree::new();
    for i in 0..100u64 {
        tree.insert(pallas::Base::from(i + 1));
    }
    assert_eq!(tree.size(), 100);
}
