// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Groth16Verifier} from "./Groth16Verifier.sol";
import {NullifierRegistry} from "./NullifierRegistry.sol";
import {IncrementalMerkleTree} from "./IncrementalMerkleTree.sol";

/// @title Privacy Pool for ESCANORR
/// @notice Manages shielded deposits, withdrawals, and transfers on EVM chains.
///         Deposits enter the pool, transfers occur within the pool (shielded),
///         and withdrawals exit with a verified ZK proof.
/// @dev The pool maintains a Merkle root of note commitments and delegates
///      nullifier tracking to the NullifierRegistry. Proof verification is
///      handled by the Groth16Verifier (which verifies recursively wrapped
///      Halo2/IPA proofs).
contract PrivacyPool {
    using IncrementalMerkleTree for IncrementalMerkleTree.Tree;

    // ──────────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────────

    event Deposit(
        bytes32 indexed commitment,
        uint256 leafIndex,
        uint256 amount,
        uint256 timestamp
    );
    event Withdrawal(
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount,
        uint256 timestamp
    );
    event MerkleRootUpdated(bytes32 indexed newRoot, uint256 leafCount);

    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error InvalidProof();
    error InvalidAmount();
    error InvalidCommitment();
    error InvalidNullifier();
    error InvalidRecipient();
    error MerkleRootUnknown();
    error TransferFailed();
    error PoolPaused();
    error Unauthorized();

    // ──────────────────────────────────────────────────────────────────
    // Constants
    // ──────────────────────────────────────────────────────────────────

    uint256 public constant TREE_DEPTH = 32;
    uint256 public constant MAX_DEPOSIT = 100 ether;

    // ──────────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────────

    Groth16Verifier public immutable verifier;
    NullifierRegistry public immutable nullifierRegistry;

    /// @notice Current Merkle root of the note commitment tree
    bytes32 public currentRoot;

    /// @notice Historical roots — valid for withdrawals within a window
    mapping(bytes32 => bool) public knownRoots;

    /// @notice Number of leaves (commitments) inserted
    uint256 public leafCount;

    /// @notice Mapping from leaf index to commitment
    mapping(uint256 => bytes32) public commitments;

    /// @notice Total value locked in the pool
    uint256 public totalValueLocked;

    /// @notice Emergency pause flag
    bool public paused;

    /// @notice Contract owner
    address public owner;

    /// @notice Chain ID for nullifier domain separation
    uint256 public immutable chainId;

    /// @notice On-chain incremental Merkle tree for note commitments
    IncrementalMerkleTree.Tree private merkleTree;

    // ──────────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────────

    constructor(address _verifier, address _nullifierRegistry) {
        verifier = Groth16Verifier(_verifier);
        nullifierRegistry = NullifierRegistry(_nullifierRegistry);
        owner = msg.sender;
        chainId = block.chainid;

        // Initialize with empty root
        currentRoot = bytes32(0);
        knownRoots[bytes32(0)] = true;

        // Initialize the on-chain Merkle tree
        merkleTree.init();
    }

    // ──────────────────────────────────────────────────────────────────
    // Modifiers
    // ──────────────────────────────────────────────────────────────────

    modifier whenNotPaused() {
        if (paused) revert PoolPaused();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Deposit
    // ──────────────────────────────────────────────────────────────────

    /// @notice Deposit ETH into the privacy pool
    /// @param commitment The Poseidon commitment of the new note
    /// @return leafIndex The index of the inserted leaf
    function deposit(
        bytes32 commitment
    ) external payable whenNotPaused returns (uint256 leafIndex) {
        if (msg.value == 0 || msg.value > MAX_DEPOSIT) revert InvalidAmount();
        if (commitment == bytes32(0)) revert InvalidCommitment();

        leafIndex = leafCount;
        commitments[leafIndex] = commitment;
        leafCount++;

        totalValueLocked += msg.value;

        // Insert into the on-chain incremental Merkle tree
        merkleTree.insert(commitment);
        currentRoot = merkleTree.getRoot();
        knownRoots[currentRoot] = true;

        emit Deposit(commitment, leafIndex, msg.value, block.timestamp);
    }

    /// @notice Manually update the Merkle root (for emergency/migration scenarios)
    /// @dev The tree now auto-updates on deposit. This remains for operator overrides.
    /// @param newRoot The new Merkle root
    function updateMerkleRoot(bytes32 newRoot) external onlyOwner {
        currentRoot = newRoot;
        knownRoots[newRoot] = true;
        emit MerkleRootUpdated(newRoot, leafCount);
    }

    // ──────────────────────────────────────────────────────────────────
    // Withdraw
    // ──────────────────────────────────────────────────────────────────

    /// @notice Withdraw from the privacy pool with a ZK proof
    /// @param proof The Groth16 proof (recursively wrapped from Halo2)
    /// @param root The Merkle root the proof is anchored to
    /// @param nullifier The nullifier of the spent note
    /// @param recipient The address to receive the withdrawn funds
    /// @param amount The amount to withdraw
    function withdraw(
        Groth16Verifier.Proof calldata proof,
        bytes32 root,
        bytes32 nullifier,
        address recipient,
        uint256 amount
    ) external whenNotPaused {
        if (recipient == address(0)) revert InvalidRecipient();
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (amount == 0) revert InvalidAmount();
        if (!knownRoots[root]) revert MerkleRootUnknown();

        // Verify the ZK proof
        uint256[] memory publicInputs = new uint256[](4);
        publicInputs[0] = uint256(root);
        publicInputs[1] = uint256(nullifier);
        publicInputs[2] = uint256(uint160(recipient));
        publicInputs[3] = amount;

        bool valid = verifier.verifyProof(proof, publicInputs);
        if (!valid) revert InvalidProof();

        // Record the nullifier (reverts if already spent)
        nullifierRegistry.spend(nullifier, chainId);

        // Transfer funds
        totalValueLocked -= amount;
        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawal(nullifier, recipient, amount, block.timestamp);
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

    // ──────────────────────────────────────────────────────────────────
    // View
    // ──────────────────────────────────────────────────────────────────

    /// @notice Check if a root is known (valid for withdrawals)
    function isKnownRoot(bytes32 root) external view returns (bool) {
        return knownRoots[root];
    }

    /// @notice Get a commitment by leaf index
    function getCommitment(uint256 index) external view returns (bytes32) {
        return commitments[index];
    }

    receive() external payable {
        revert InvalidAmount();
    }
}
