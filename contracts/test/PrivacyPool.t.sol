// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {PrivacyPool} from "../src/PrivacyPool.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {NullifierRegistry} from "../src/NullifierRegistry.sol";

contract PrivacyPoolTest is Test {
    PrivacyPool public pool;
    Groth16Verifier public verifier;
    NullifierRegistry public registry;

    address public owner;
    address public user = address(0xBEEF);

    function setUp() public {
        owner = address(this);
        verifier = new Groth16Verifier();
        registry = new NullifierRegistry(address(0)); // will set pool later

        pool = new PrivacyPool(address(verifier), address(registry));

        // Authorize the pool to record nullifiers
        registry.setPool(address(pool));

        // Fund user
        vm.deal(user, 100 ether);
    }

    function test_initialState() public view {
        assertEq(pool.owner(), owner);
        assertEq(pool.leafCount(), 0);
        assertEq(pool.totalValueLocked(), 0);
        assertFalse(pool.paused());
        assertEq(address(pool.verifier()), address(verifier));
        assertEq(address(pool.nullifierRegistry()), address(registry));
    }

    function test_deposit() public {
        bytes32 commitment = keccak256("commitment1");

        vm.prank(user);
        uint256 leafIndex = pool.deposit{value: 1 ether}(commitment);

        assertEq(leafIndex, 0);
        assertEq(pool.leafCount(), 1);
        assertEq(pool.totalValueLocked(), 1 ether);
        assertEq(pool.getCommitment(0), commitment);
    }

    function test_deposit_emitsEvent() public {
        bytes32 commitment = keccak256("commitment1");

        vm.prank(user);
        vm.expectEmit(true, false, false, true);
        emit PrivacyPool.Deposit(commitment, 0, 1 ether, block.timestamp);
        pool.deposit{value: 1 ether}(commitment);
    }

    function test_deposit_multiple() public {
        vm.startPrank(user);

        bytes32 c1 = keccak256("c1");
        bytes32 c2 = keccak256("c2");
        bytes32 c3 = keccak256("c3");

        assertEq(pool.deposit{value: 1 ether}(c1), 0);
        assertEq(pool.deposit{value: 2 ether}(c2), 1);
        assertEq(pool.deposit{value: 3 ether}(c3), 2);

        vm.stopPrank();

        assertEq(pool.leafCount(), 3);
        assertEq(pool.totalValueLocked(), 6 ether);
    }

    function test_deposit_revert_zeroValue() public {
        bytes32 commitment = keccak256("c1");

        vm.prank(user);
        vm.expectRevert(PrivacyPool.InvalidAmount.selector);
        pool.deposit{value: 0}(commitment);
    }

    function test_deposit_revert_exceedsMax() public {
        bytes32 commitment = keccak256("c1");

        vm.deal(user, 200 ether);
        vm.prank(user);
        vm.expectRevert(PrivacyPool.InvalidAmount.selector);
        pool.deposit{value: 101 ether}(commitment);
    }

    function test_deposit_revert_zeroCommitment() public {
        vm.prank(user);
        vm.expectRevert(PrivacyPool.InvalidCommitment.selector);
        pool.deposit{value: 1 ether}(bytes32(0));
    }

    function test_deposit_revert_whenPaused() public {
        pool.pause();

        vm.prank(user);
        vm.expectRevert(PrivacyPool.PoolPaused.selector);
        pool.deposit{value: 1 ether}(keccak256("c1"));
    }

    function test_updateMerkleRoot() public {
        bytes32 newRoot = keccak256("root1");

        pool.updateMerkleRoot(newRoot);

        assertEq(pool.currentRoot(), newRoot);
        assertTrue(pool.isKnownRoot(newRoot));
    }

    function test_updateMerkleRoot_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert(PrivacyPool.Unauthorized.selector);
        pool.updateMerkleRoot(keccak256("root"));
    }

    function test_pause_unpause() public {
        pool.pause();
        assertTrue(pool.paused());

        pool.unpause();
        assertFalse(pool.paused());
    }

    function test_pause_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert(PrivacyPool.Unauthorized.selector);
        pool.pause();
    }

    function test_transferOwnership() public {
        pool.transferOwnership(user);
        assertEq(pool.owner(), user);
    }

    function test_receive_reverts() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(PrivacyPool.InvalidAmount.selector);
        (bool success, ) = address(pool).call{value: 1 ether}("");
        // The call itself succeeds from EVM perspective but the revert is caught
        // by the test framework
        success; // silence warning
    }

    function test_knownRoots_preserveHistory() public {
        bytes32 root1 = keccak256("root1");
        bytes32 root2 = keccak256("root2");

        pool.updateMerkleRoot(root1);
        pool.updateMerkleRoot(root2);

        // Both roots should remain valid
        assertTrue(pool.isKnownRoot(root1));
        assertTrue(pool.isKnownRoot(root2));
        assertEq(pool.currentRoot(), root2);
    }
}
