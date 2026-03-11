// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @title Incremental Merkle Tree with Poseidon hashing (BN254)
/// @notice Gas-efficient append-only Merkle tree for note commitments.
/// @dev Uses the standard Poseidon T3 hash (width=3, 2 inputs) over the BN254
///      scalar field.  The off-chain Halo2 circuits operate on Pallas, so roots
///      differ until recursive proof wrapping (Halo2 → Groth16) is implemented.
library IncrementalMerkleTree {
    /// @notice Maximum depth of the tree
    uint256 internal constant DEPTH = 32;

    struct Tree {
        /// @notice Number of leaves inserted
        uint256 nextIndex;
        /// @notice Current root
        bytes32 root;
        /// @notice Filled subtrees at each level (used for incremental insertion)
        bytes32[DEPTH] filledSubtrees;
        /// @notice Zero values at each tree level (precomputed)
        bytes32[DEPTH] zeros;
    }

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error MerkleTreeFull();
    error InvalidLeaf();

    // ──────────────────────────────────────────────────────────────────
    // Initialization
    // ──────────────────────────────────────────────────────────────────

    /// @notice Initialize the tree with zero values at each level
    /// @dev Must be called once before any insertions
    function init(Tree storage tree) internal {
        bytes32 currentZero = bytes32(0);
        for (uint256 i = 0; i < DEPTH; i++) {
            tree.zeros[i] = currentZero;
            tree.filledSubtrees[i] = currentZero;
            currentZero = _hash(currentZero, currentZero);
        }
        tree.root = currentZero;
    }

    // ──────────────────────────────────────────────────────────────────
    // Insertion
    // ──────────────────────────────────────────────────────────────────

    /// @notice Insert a new leaf into the tree
    /// @param tree The tree storage
    /// @param leaf The leaf commitment to insert
    /// @return index The index of the inserted leaf
    function insert(
        Tree storage tree,
        bytes32 leaf
    ) internal returns (uint256 index) {
        uint256 currentIndex = tree.nextIndex;
        if (currentIndex >= 2 ** DEPTH) revert MerkleTreeFull();
        if (leaf == bytes32(0)) revert InvalidLeaf();

        bytes32 currentHash = leaf;
        uint256 idx = currentIndex;

        for (uint256 i = 0; i < DEPTH; i++) {
            if (idx % 2 == 0) {
                // Left child: pair with the zero value at this level
                tree.filledSubtrees[i] = currentHash;
                currentHash = _hash(currentHash, tree.zeros[i]);
            } else {
                // Right child: pair with the stored left sibling
                currentHash = _hash(tree.filledSubtrees[i], currentHash);
            }
            idx /= 2;
        }

        tree.root = currentHash;
        index = currentIndex;
        tree.nextIndex = currentIndex + 1;
    }

    // ──────────────────────────────────────────────────────────────────
    // Hash function
    // ──────────────────────────────────────────────────────────────────

    /// @notice Poseidon hash of two field elements (BN254, T=3)
    function _hash(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return bytes32(PoseidonT3.hash([uint256(left), uint256(right)]));
    }

    // ──────────────────────────────────────────────────────────────────
    // View
    // ──────────────────────────────────────────────────────────────────

    /// @notice Get the current root
    function getRoot(Tree storage tree) internal view returns (bytes32) {
        return tree.root;
    }

    /// @notice Get the number of leaves inserted
    function getNextIndex(Tree storage tree) internal view returns (uint256) {
        return tree.nextIndex;
    }
}
