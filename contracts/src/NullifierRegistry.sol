// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Nullifier Registry for ESCANORR
/// @notice Tracks spent nullifiers across all bridge operations to prevent double-spending.
/// @dev Nullifiers are 32-byte hashes derived from Poseidon(domain, spending_key, commitment, [chain_id]).
///      Once a nullifier is recorded, the corresponding note cannot be spent again on any chain.
contract NullifierRegistry {
    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event NullifierSpent(
        bytes32 indexed nullifier,
        uint256 indexed chainId,
        uint256 timestamp
    );

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error NullifierAlreadySpent(bytes32 nullifier);
    error Unauthorized();
    error ZeroNullifier();

    // ──────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────

    /// @notice Mapping from nullifier hash to whether it has been spent
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Count of total nullifiers recorded
    uint256 public nullifierCount;

    /// @notice Address authorized to record nullifiers (the PrivacyPool contract)
    address public pool;

    /// @notice Contract owner (can update pool address)
    address public owner;

    // ──────────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────────

    constructor(address _pool) {
        owner = msg.sender;
        pool = _pool;
    }

    // ──────────────────────────────────────────────────────────────────
    // Modifiers
    // ──────────────────────────────────────────────────────────────────

    modifier onlyPool() {
        if (msg.sender != pool) revert Unauthorized();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ──────────────────────────────────────────────────────────────────
    // External functions
    // ──────────────────────────────────────────────────────────────────

    /// @notice Record a nullifier as spent. Reverts if already spent.
    /// @param nullifier The 32-byte nullifier hash
    /// @param chainId The origin chain ID for cross-chain tracking
    function spend(bytes32 nullifier, uint256 chainId) external onlyPool {
        if (nullifier == bytes32(0)) revert ZeroNullifier();
        if (nullifiers[nullifier]) revert NullifierAlreadySpent(nullifier);

        nullifiers[nullifier] = true;
        nullifierCount++;

        emit NullifierSpent(nullifier, chainId, block.timestamp);
    }

    /// @notice Check if a nullifier has been spent
    /// @param nullifier The 32-byte nullifier hash
    /// @return True if the nullifier is already recorded
    function isSpent(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /// @notice Batch check multiple nullifiers
    /// @param _nullifiers Array of nullifier hashes to check
    /// @return results Array of booleans — true if spent
    function batchIsSpent(
        bytes32[] calldata _nullifiers
    ) external view returns (bool[] memory results) {
        results = new bool[](_nullifiers.length);
        for (uint256 i = 0; i < _nullifiers.length; i++) {
            results[i] = nullifiers[_nullifiers[i]];
        }
    }

    /// @notice Update the authorized pool address
    /// @param _pool New pool contract address
    function setPool(address _pool) external onlyOwner {
        pool = _pool;
    }

    /// @notice Transfer ownership
    /// @param newOwner New owner address
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
