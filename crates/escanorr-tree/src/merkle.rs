//! Incremental Merkle tree with Poseidon hashing.
//!
//! This is an append-only tree that efficiently maintains the root hash
//! as new leaves are inserted. Authentication paths can be computed for
//! any inserted leaf.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use escanorr_primitives::poseidon::{poseidon_hash_with_domain, DOMAIN_MERKLE};

use crate::TREE_DEPTH;

/// Precomputed empty subtree hashes for each level.
/// `EMPTY_ROOTS[i]` is the root of a completely empty subtree of depth `i`.
fn empty_roots() -> Vec<pallas::Base> {
    let mut roots = vec![pallas::Base::zero(); TREE_DEPTH + 1];
    roots[0] = pallas::Base::zero(); // empty leaf
    for i in 1..=TREE_DEPTH {
        roots[i] = poseidon_hash_with_domain(DOMAIN_MERKLE, roots[i - 1], roots[i - 1]);
    }
    roots
}

/// Append-only incremental Merkle tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncrementalMerkleTree {
    /// Number of leaves inserted so far.
    size: u64,
    /// Filled subtree hashes along the left frontier.
    /// `filled[i]` holds the hash of the completed subtree at level `i`.
    #[serde(with = "vec_field_serde")]
    filled: Vec<Option<pallas::Base>>,
    /// Current Merkle root.
    #[serde(with = "field_serde")]
    root: pallas::Base,
    /// All leaf values (for path computation). In production, use a database.
    #[serde(with = "vec_field_serde_flat")]
    leaves: Vec<pallas::Base>,
}

impl IncrementalMerkleTree {
    /// Create an empty Merkle tree.
    pub fn new() -> Self {
        let empty = empty_roots();
        Self {
            size: 0,
            filled: vec![None; TREE_DEPTH],
            root: empty[TREE_DEPTH],
            leaves: Vec::new(),
        }
    }

    /// Insert a leaf and update the root. Returns the leaf index.
    pub fn insert(&mut self, leaf: pallas::Base) -> u64 {
        let index = self.size;
        self.leaves.push(leaf);
        self.size += 1;
        self.recompute_root();
        index
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> pallas::Base {
        self.root
    }

    /// Get the number of leaves.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Compute an authentication path (Merkle proof) for a leaf at the given index.
    ///
    /// Returns `(siblings, path_indices)` where `path_indices[i]` is 0 if the
    /// node is a left child, 1 if right.
    pub fn auth_path(&self, index: u64) -> Option<(Vec<pallas::Base>, Vec<u8>)> {
        if index >= self.size {
            return None;
        }

        let empty = empty_roots();
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut path_indices = Vec::with_capacity(TREE_DEPTH);
        let mut idx = index as usize;

        // Build level hashes layer by layer
        let mut current_level: Vec<pallas::Base> = self.leaves.clone();

        for level in 0..TREE_DEPTH {
            let is_right = idx & 1;
            path_indices.push(is_right as u8);

            let sibling_idx = idx ^ 1;
            let sibling = if sibling_idx < current_level.len() {
                current_level[sibling_idx]
            } else {
                empty[level]
            };
            siblings.push(sibling);

            // Compute next level
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < current_level.len() {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    empty[level]
                };
                next_level.push(poseidon_hash_with_domain(DOMAIN_MERKLE, left, right));
                i += 2;
            }
            if next_level.is_empty() {
                next_level.push(empty[level + 1]);
            }

            current_level = next_level;
            idx >>= 1;
        }

        Some((siblings, path_indices))
    }

    /// Verify a Merkle proof.
    pub fn verify_proof(
        root: pallas::Base,
        leaf: pallas::Base,
        siblings: &[pallas::Base],
        path_indices: &[u8],
    ) -> bool {
        if siblings.len() != TREE_DEPTH || path_indices.len() != TREE_DEPTH {
            return false;
        }

        let mut current = leaf;
        for i in 0..TREE_DEPTH {
            let (left, right) = if path_indices[i] == 0 {
                (current, siblings[i])
            } else {
                (siblings[i], current)
            };
            current = poseidon_hash_with_domain(DOMAIN_MERKLE, left, right);
        }

        current == root
    }

    /// Recompute the root from all leaves.
    fn recompute_root(&mut self) {
        let empty = empty_roots();
        let mut current_level = self.leaves.clone();

        for level in 0..TREE_DEPTH {
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < current_level.len() {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    empty[level]
                };
                next_level.push(poseidon_hash_with_domain(DOMAIN_MERKLE, left, right));
                i += 2;
            }
            if next_level.is_empty() {
                next_level.push(empty[level + 1]);
            }
            current_level = next_level;
        }

        self.root = current_level[0];
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// Serde helpers
mod field_serde {
    use ff::PrimeField;
    use pasta_curves::pallas;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(field: &pallas::Base, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(field.to_repr()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<pallas::Base, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        pallas::Base::from_repr(arr).into_option().ok_or_else(|| serde::de::Error::custom("invalid field"))
    }
}

mod vec_field_serde {
    use ff::PrimeField;
    use pasta_curves::pallas;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(vec: &[Option<pallas::Base>], serializer: S) -> Result<S::Ok, S::Error> {
        let hex_vec: Vec<Option<String>> = vec.iter().map(|opt| opt.map(|f| hex::encode(f.to_repr()))).collect();
        hex_vec.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Option<pallas::Base>>, D::Error> {
        let hex_vec: Vec<Option<String>> = Vec::deserialize(deserializer)?;
        hex_vec.into_iter().map(|opt| {
            opt.map(|s| {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                pallas::Base::from_repr(arr).into_option().ok_or_else(|| serde::de::Error::custom("invalid"))
            }).transpose()
        }).collect()
    }
}

mod vec_field_serde_flat {
    use ff::PrimeField;
    use pasta_curves::pallas;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(vec: &[pallas::Base], serializer: S) -> Result<S::Ok, S::Error> {
        let hex_vec: Vec<String> = vec.iter().map(|f| hex::encode(f.to_repr())).collect();
        hex_vec.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<pallas::Base>, D::Error> {
        let hex_vec: Vec<String> = Vec::deserialize(deserializer)?;
        hex_vec.into_iter().map(|s| {
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            pallas::Base::from_repr(arr).into_option().ok_or_else(|| serde::de::Error::custom("invalid"))
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_has_deterministic_root() {
        let t1 = IncrementalMerkleTree::new();
        let t2 = IncrementalMerkleTree::new();
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = IncrementalMerkleTree::new();
        let root_before = tree.root();
        tree.insert(pallas::Base::from(42u64));
        assert_ne!(tree.root(), root_before);
    }

    #[test]
    fn insert_returns_sequential_indices() {
        let mut tree = IncrementalMerkleTree::new();
        assert_eq!(tree.insert(pallas::Base::from(1u64)), 0);
        assert_eq!(tree.insert(pallas::Base::from(2u64)), 1);
        assert_eq!(tree.insert(pallas::Base::from(3u64)), 2);
    }

    #[test]
    fn size_tracks_insertions() {
        let mut tree = IncrementalMerkleTree::new();
        assert_eq!(tree.size(), 0);
        tree.insert(pallas::Base::from(1u64));
        assert_eq!(tree.size(), 1);
        tree.insert(pallas::Base::from(2u64));
        assert_eq!(tree.size(), 2);
    }

    #[test]
    fn auth_path_verifies() {
        let mut tree = IncrementalMerkleTree::new();
        let leaf = pallas::Base::from(42u64);
        let idx = tree.insert(leaf);

        let (siblings, path_indices) = tree.auth_path(idx).unwrap();
        assert!(IncrementalMerkleTree::verify_proof(
            tree.root(),
            leaf,
            &siblings,
            &path_indices
        ));
    }

    #[test]
    fn auth_path_multiple_leaves() {
        let mut tree = IncrementalMerkleTree::new();
        let leaves: Vec<pallas::Base> = (0..8)
            .map(|i| {
                let leaf = pallas::Base::from(i as u64 + 100);
                tree.insert(leaf);
                leaf
            })
            .collect();

        // Verify each leaf's path
        for (i, leaf) in leaves.iter().enumerate() {
            let (siblings, path_indices) = tree.auth_path(i as u64).unwrap();
            assert!(
                IncrementalMerkleTree::verify_proof(tree.root(), *leaf, &siblings, &path_indices),
                "proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn wrong_leaf_fails_verification() {
        let mut tree = IncrementalMerkleTree::new();
        let leaf = pallas::Base::from(42u64);
        let idx = tree.insert(leaf);

        let (siblings, path_indices) = tree.auth_path(idx).unwrap();
        let wrong_leaf = pallas::Base::from(999u64);
        assert!(!IncrementalMerkleTree::verify_proof(
            tree.root(),
            wrong_leaf,
            &siblings,
            &path_indices
        ));
    }

    #[test]
    fn auth_path_out_of_bounds() {
        let tree = IncrementalMerkleTree::new();
        assert!(tree.auth_path(0).is_none());
    }

    #[test]
    fn deterministic_roots() {
        let mut t1 = IncrementalMerkleTree::new();
        let mut t2 = IncrementalMerkleTree::new();

        t1.insert(pallas::Base::from(1u64));
        t1.insert(pallas::Base::from(2u64));

        t2.insert(pallas::Base::from(1u64));
        t2.insert(pallas::Base::from(2u64));

        assert_eq!(t1.root(), t2.root());
    }
}
