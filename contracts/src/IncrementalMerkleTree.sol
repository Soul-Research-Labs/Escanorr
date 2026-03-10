// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Incremental Merkle Tree with Poseidon-style hashing
/// @notice Gas-efficient append-only Merkle tree for note commitments.
/// @dev Uses a simplified Poseidon-like hash (modular arithmetic over BN254 scalar field).
///      In production, replace `_hash` with a proper Poseidon precompile or assembly
///      implementation once EIP-5988 or equivalent is available.
library IncrementalMerkleTree {
    /// @notice Maximum depth of the tree
    uint256 internal constant DEPTH = 32;

    /// @notice BN254 scalar field modulus
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

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

    /// @notice Poseidon-style hash of two field elements
    /// @dev Simplified algebraic hash: H(l, r) = (l + r)^5 + l*r + c  mod p
    ///      This mirrors the Rust-side Poseidon used in escanorr-primitives.
    ///      For production, use a gas-optimized Poseidon assembly implementation.
    function _hash(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        uint256 l = uint256(left) % FIELD_MODULUS;
        uint256 r = uint256(right) % FIELD_MODULUS;

        // Constant for domain separation
        uint256 c = 0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e;

        // sum = l + r mod p
        uint256 sum = addmod(l, r, FIELD_MODULUS);
        // sum^2
        uint256 sum2 = mulmod(sum, sum, FIELD_MODULUS);
        // sum^4
        uint256 sum4 = mulmod(sum2, sum2, FIELD_MODULUS);
        // sum^5
        uint256 sum5 = mulmod(sum4, sum, FIELD_MODULUS);
        // l * r
        uint256 lr = mulmod(l, r, FIELD_MODULUS);
        // result = sum^5 + l*r + c mod p
        uint256 result = addmod(
            addmod(sum5, lr, FIELD_MODULUS),
            c,
            FIELD_MODULUS
        );

        return bytes32(result);
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
