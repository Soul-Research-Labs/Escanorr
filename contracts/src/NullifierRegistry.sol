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

    event CallerAuthorized(address indexed caller);
    event CallerRevoked(address indexed caller);

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error NullifierAlreadySpent(bytes32 nullifier);
    error Unauthorized();
    error ZeroNullifier();
    error ZeroAddress();

    // ──────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────

    /// @notice Mapping from nullifier hash to whether it has been spent
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Count of total nullifiers recorded
    uint256 public nullifierCount;

    /// @notice Authorized callers (PrivacyPool, BridgeVault, etc.)
    mapping(address => bool) public authorized;

    /// @notice Legacy single-pool getter for backwards compatibility
    address public pool;

    /// @notice Contract owner (can update authorized callers)
    address public owner;

    // ──────────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────────

    constructor(address _pool) {
        owner = msg.sender;
        pool = _pool;
        authorized[_pool] = true;
    }

    // ──────────────────────────────────────────────────────────────────
    // Modifiers
    // ──────────────────────────────────────────────────────────────────

    modifier onlyAuthorized() {
        if (!authorized[msg.sender]) revert Unauthorized();
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
    function spend(bytes32 nullifier, uint256 chainId) external onlyAuthorized {
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

    /// @notice Authorize a new caller (e.g. BridgeVault, additional pool)
    /// @param caller Address to authorize
    function authorize(address caller) external onlyOwner {
        if (caller == address(0)) revert ZeroAddress();
        authorized[caller] = true;
        emit CallerAuthorized(caller);
    }

    /// @notice Revoke an authorized caller
    /// @param caller Address to revoke
    function revoke(address caller) external onlyOwner {
        authorized[caller] = false;
        emit CallerRevoked(caller);
    }

    /// @notice Update the primary pool address (backwards-compatible)
    /// @param _pool New pool contract address
    function setPool(address _pool) external onlyOwner {
        // Revoke old pool, authorize new one
        authorized[pool] = false;
        pool = _pool;
        authorized[_pool] = true;
    }

    /// @notice Transfer ownership
    /// @param newOwner New owner address
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
