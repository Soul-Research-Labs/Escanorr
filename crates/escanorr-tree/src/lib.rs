//! ESCANORR Tree — append-only incremental Merkle tree (depth 32, Poseidon hash).
//!
//! Stores note commitments in a binary Merkle tree using Poseidon hashing.
//! Supports ~4 billion leaves (2^32). The tree is append-only: leaves
//! cannot be removed or modified once inserted.

pub mod merkle;

pub use merkle::IncrementalMerkleTree;

/// Default tree depth.
pub const TREE_DEPTH: usize = 32;
