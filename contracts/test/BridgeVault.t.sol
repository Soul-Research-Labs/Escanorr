// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {BridgeVault} from "../src/BridgeVault.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {NullifierRegistry} from "../src/NullifierRegistry.sol";

contract BridgeVaultTest is Test {
    BridgeVault public vault;
    Groth16Verifier public verifier;
    NullifierRegistry public registry;

    address public owner;
    address public user = address(0xBEEF);

    function setUp() public {
        owner = address(this);
        verifier = new Groth16Verifier();
        registry = new NullifierRegistry(address(0));

        vault = new BridgeVault(address(verifier), address(registry));

        registry.setPool(address(vault));

        vm.deal(user, 100 ether);
        // Fund vault for unlock operations
        vm.deal(address(vault), 50 ether);
    }

    // ─── Helpers ──────────────────────────────────────────────────────

    function _dummyProof() internal pure returns (Groth16Verifier.Proof memory) {
        return Groth16Verifier.Proof({
            a_x: 1,
            a_y: 2,
            b_x1: 1,
            b_x2: 1,
            b_y1: 1,
            b_y2: 1,
            c_x: 1,
            c_y: 2
        });
    }

    // ─── Initial State ───────────────────────────────────────────────

    function test_initialState() public view {
        assertEq(vault.owner(), owner);
        assertFalse(vault.paused());
        assertEq(address(vault.verifier()), address(verifier));
        assertEq(address(vault.nullifierRegistry()), address(registry));
    }

    // ─── Pause / Unpause ─────────────────────────────────────────────

    function test_pause_unpause() public {
        vault.pause();
        assertTrue(vault.paused());

        vault.unpause();
        assertFalse(vault.paused());
    }

    function test_pause_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert(BridgeVault.Unauthorized.selector);
        vault.pause();
    }

    function test_transferOwnership() public {
        vault.transferOwnership(user);
        assertEq(vault.owner(), user);
    }

    function test_receive_acceptsEth() public {
        uint256 balBefore = address(vault).balance;
        vm.prank(user);
        (bool success, ) = address(vault).call{value: 1 ether}("");
        assertTrue(success);
        assertEq(address(vault).balance, balBefore + 1 ether);
    }

    // ─── Lock: input validation ──────────────────────────────────────

    function test_lock_reverts_when_paused() public {
        vault.pause();
        vm.prank(user);
        vm.expectRevert(BridgeVault.VaultPaused.selector);
        vault.lock{value: 1 ether}(
            _dummyProof(),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            999
        );
    }

    function test_lock_reverts_zero_value() public {
        vm.prank(user);
        vm.expectRevert(BridgeVault.InvalidAmount.selector);
        vault.lock{value: 0}(
            _dummyProof(),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            999
        );
    }

    function test_lock_reverts_zero_nullifier() public {
        vm.prank(user);
        vm.expectRevert(BridgeVault.InvalidNullifier.selector);
        vault.lock{value: 1 ether}(
            _dummyProof(),
            bytes32(0),
            bytes32(uint256(2)),
            999
        );
    }

    function test_lock_reverts_same_chain() public {
        vm.prank(user);
        vm.expectRevert(BridgeVault.InvalidChainId.selector);
        vault.lock{value: 1 ether}(
            _dummyProof(),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            block.chainid
        );
    }

    function test_lock_reverts_invalid_proof() public {
        // With placeholder VK, proof verification fails
        vm.prank(user);
        vm.expectRevert();
        vault.lock{value: 1 ether}(
            _dummyProof(),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            999
        );
    }

    // ─── Unlock: input validation ────────────────────────────────────

    function test_unlock_reverts_when_paused() public {
        vault.pause();
        vm.expectRevert(BridgeVault.VaultPaused.selector);
        vault.unlock(
            _dummyProof(),
            bytes32(uint256(1)),
            user,
            1 ether,
            42
        );
    }

    function test_unlock_reverts_zero_recipient() public {
        vm.expectRevert(BridgeVault.InvalidRecipient.selector);
        vault.unlock(
            _dummyProof(),
            bytes32(uint256(1)),
            address(0),
            1 ether,
            42
        );
    }

    function test_unlock_reverts_zero_nullifier() public {
        vm.expectRevert(BridgeVault.InvalidNullifier.selector);
        vault.unlock(
            _dummyProof(),
            bytes32(0),
            user,
            1 ether,
            42
        );
    }

    function test_unlock_reverts_zero_amount() public {
        vm.expectRevert(BridgeVault.InvalidAmount.selector);
        vault.unlock(
            _dummyProof(),
            bytes32(uint256(1)),
            user,
            0,
            42
        );
    }

    function test_unlock_reverts_same_chain() public {
        vm.expectRevert(BridgeVault.InvalidChainId.selector);
        vault.unlock(
            _dummyProof(),
            bytes32(uint256(1)),
            user,
            1 ether,
            block.chainid
        );
    }

    function test_unlock_reverts_insufficient_balance() public {
        // Vault has 50 ether; requesting more should fail with InsufficientBalance
        vm.expectRevert(BridgeVault.InsufficientBalance.selector);
        vault.unlock(
            _dummyProof(),
            bytes32(uint256(1)),
            user,
            100 ether,
            42
        );
    }

    function test_unlock_reverts_invalid_proof() public {
        // With placeholder VK, proof verification fails
        vm.expectRevert();
        vault.unlock(
            _dummyProof(),
            bytes32(uint256(1)),
            user,
            1 ether,
            42
        );
    }
}
