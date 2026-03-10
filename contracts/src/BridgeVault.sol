// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Groth16Verifier} from "./Groth16Verifier.sol";
import {NullifierRegistry} from "./NullifierRegistry.sol";

/// @title Bridge Vault for ESCANORR
/// @notice Manages asset locking/unlocking for cross-chain bridge operations.
///         Assets are locked on the source chain and unlocked on the destination
///         chain upon presentation of a valid bridge proof.
/// @dev Bridge proofs verify: (1) the note exists in the source chain's Merkle tree,
///      (2) the nullifier is correctly derived with chain_id binding, and
///      (3) source_chain_id != destination_chain_id.
contract BridgeVault {
    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event BridgeLock(
        bytes32 indexed nullifier,
        bytes32 indexed commitmentHash,
        uint256 amount,
        uint256 sourceChainId,
        uint256 destinationChainId,
        uint256 timestamp
    );

    event BridgeUnlock(
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount,
        uint256 sourceChainId,
        uint256 timestamp
    );

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error InvalidProof();
    error InvalidAmount();
    error InvalidChainId();
    error InvalidRecipient();
    error InvalidNullifier();
    error InsufficientBalance();
    error TransferFailed();
    error VaultPaused();
    error Unauthorized();

    // ──────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────

    Groth16Verifier public immutable verifier;
    NullifierRegistry public immutable nullifierRegistry;

    /// @notice This chain's ID
    uint256 public immutable chainId;

    /// @notice Total locked per destination chain
    mapping(uint256 => uint256) public lockedPerChain;

    /// @notice Pending bridge operations (nullifier => BridgeOp)
    mapping(bytes32 => BridgeOp) public pendingOps;

    /// @notice Emergency pause
    bool public paused;

    /// @notice Contract owner
    address public owner;

    struct BridgeOp {
        bytes32 commitmentHash;
        uint256 amount;
        uint256 sourceChainId;
        uint256 destinationChainId;
        uint256 timestamp;
        bool completed;
    }

    // ──────────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────────

    constructor(address _verifier, address _nullifierRegistry) {
        verifier = Groth16Verifier(_verifier);
        nullifierRegistry = NullifierRegistry(_nullifierRegistry);
        owner = msg.sender;
        chainId = block.chainid;
    }

    // ──────────────────────────────────────────────────────────────────
    // Modifiers
    // ──────────────────────────────────────────────────────────────────

    modifier whenNotPaused() {
        if (paused) revert VaultPaused();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Lock (source chain)
    // ──────────────────────────────────────────────────────────────────

    /// @notice Lock assets for bridging to another chain
    /// @param proof The Groth16 bridge proof
    /// @param nullifier The nullifier of the note being bridged
    /// @param commitmentHash Hash of the new note commitment on the destination chain
    /// @param destinationChainId Target chain ID
    function lock(
        Groth16Verifier.Proof calldata proof,
        bytes32 nullifier,
        bytes32 commitmentHash,
        uint256 destinationChainId
    ) external payable whenNotPaused {
        if (msg.value == 0) revert InvalidAmount();
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (destinationChainId == chainId) revert InvalidChainId();

        // Verify bridge proof (public inputs: nullifier, commitment, source, dest)
        uint256[] memory publicInputs = new uint256[](4);
        publicInputs[0] = uint256(nullifier);
        publicInputs[1] = uint256(commitmentHash);
        publicInputs[2] = chainId;
        publicInputs[3] = destinationChainId;

        bool valid = verifier.verifyProof(proof, publicInputs);
        if (!valid) revert InvalidProof();

        // Record nullifier
        nullifierRegistry.spend(nullifier, chainId);

        // Track the locked operation
        pendingOps[nullifier] = BridgeOp({
            commitmentHash: commitmentHash,
            amount: msg.value,
            sourceChainId: chainId,
            destinationChainId: destinationChainId,
            timestamp: block.timestamp,
            completed: false
        });

        lockedPerChain[destinationChainId] += msg.value;

        emit BridgeLock(
            nullifier,
            commitmentHash,
            msg.value,
            chainId,
            destinationChainId,
            block.timestamp
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // Unlock (destination chain)
    // ──────────────────────────────────────────────────────────────────

    /// @notice Unlock assets that were bridged from another chain
    /// @param proof The Groth16 bridge proof
    /// @param nullifier The nullifier from the source chain lock
    /// @param recipient The address to receive unlocked funds
    /// @param amount The amount to unlock
    /// @param sourceChainId The chain where assets were locked
    function unlock(
        Groth16Verifier.Proof calldata proof,
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        uint256 sourceChainId
    ) external whenNotPaused {
        if (recipient == address(0)) revert InvalidRecipient();
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (amount == 0) revert InvalidAmount();
        if (sourceChainId == chainId) revert InvalidChainId();
        if (address(this).balance < amount) revert InsufficientBalance();

        // Verify bridge proof
        uint256[] memory publicInputs = new uint256[](4);
        publicInputs[0] = uint256(nullifier);
        publicInputs[1] = uint256(uint160(recipient));
        publicInputs[2] = sourceChainId;
        publicInputs[3] = chainId;

        bool valid = verifier.verifyProof(proof, publicInputs);
        if (!valid) revert InvalidProof();

        // Record nullifier on destination chain
        nullifierRegistry.spend(nullifier, sourceChainId);

        // Transfer funds
        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit BridgeUnlock(
            nullifier,
            recipient,
            amount,
            sourceChainId,
            block.timestamp
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // Admin
    // ──────────────────────────────────────────────────────────────────

    /// @notice Emergency pause
    function pause() external onlyOwner {
        paused = true;
    }

    /// @notice Unpause
    function unpause() external onlyOwner {
        paused = false;
    }

    /// @notice Transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    /// @notice Accept ETH for liquidity provision
    receive() external payable {}
}
