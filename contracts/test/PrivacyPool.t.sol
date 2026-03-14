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

    // ──────────────────────────────────────────────────────────────────
    // Edge-case & security tests
    // ──────────────────────────────────────────────────────────────────

    function test_deposit_updatesOnChainMerkleRoot() public {
        bytes32 rootBefore = pool.currentRoot();

        vm.prank(user);
        pool.deposit{value: 1 ether}(keccak256("c1"));

        bytes32 rootAfter = pool.currentRoot();
        assertTrue(rootBefore != rootAfter, "Root should change after deposit");
        assertTrue(pool.isKnownRoot(rootAfter), "New root should be known");
    }

    function test_deposit_sequentialDepositsProduceDifferentRoots() public {
        vm.startPrank(user);
        pool.deposit{value: 1 ether}(keccak256("c1"));
        bytes32 root1 = pool.currentRoot();

        pool.deposit{value: 1 ether}(keccak256("c2"));
        bytes32 root2 = pool.currentRoot();
        vm.stopPrank();

        assertTrue(
            root1 != root2,
            "Different deposits should produce different roots"
        );
        assertTrue(pool.isKnownRoot(root1));
        assertTrue(pool.isKnownRoot(root2));
    }

    function test_deposit_maxValue() public {
        vm.deal(user, 200 ether);
        vm.prank(user);
        uint256 idx = pool.deposit{value: 100 ether}(keccak256("max"));
        assertEq(idx, 0);
        assertEq(pool.totalValueLocked(), 100 ether);
    }

    function test_deposit_exactlyMaxValue() public {
        vm.deal(user, 200 ether);
        vm.prank(user);
        // 100 ether = MAX_DEPOSIT, should succeed
        pool.deposit{value: 100 ether}(keccak256("exactly-max"));
        assertEq(pool.totalValueLocked(), 100 ether);
    }

    function test_unpause_revert_unauthorized() public {
        pool.pause();
        vm.prank(user);
        vm.expectRevert(PrivacyPool.Unauthorized.selector);
        pool.unpause();
    }

    function test_transferOwnership_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert(PrivacyPool.Unauthorized.selector);
        pool.transferOwnership(user);
    }

    function test_deposit_afterUnpause() public {
        pool.pause();
        pool.unpause();

        vm.prank(user);
        uint256 idx = pool.deposit{value: 1 ether}(keccak256("after-unpause"));
        assertEq(idx, 0);
    }

    function test_multipleDeposits_treeSizeCorrect() public {
        vm.startPrank(user);
        for (uint256 i = 0; i < 10; i++) {
            pool.deposit{value: 1 ether}(keccak256(abi.encode(i)));
        }
        vm.stopPrank();

        assertEq(pool.leafCount(), 10);
        assertEq(pool.totalValueLocked(), 10 ether);
    }

    function test_getCommitment_returnsZeroForUnsetIndex() public view {
        assertEq(pool.getCommitment(999), bytes32(0));
    }

    function test_isKnownRoot_emptyRootIsKnown() public view {
        assertTrue(pool.isKnownRoot(bytes32(0)));
    }

    function test_isKnownRoot_randomRootNotKnown() public view {
        assertFalse(pool.isKnownRoot(keccak256("random-unknown-root")));
    }

    function testFuzz_deposit_anyValidAmount(uint256 amount) public {
        amount = bound(amount, 1, 100 ether);
        vm.deal(user, amount);
        vm.prank(user);
        uint256 idx = pool.deposit{value: amount}(
            keccak256(abi.encode(amount))
        );
        assertEq(idx, 0);
        assertEq(pool.totalValueLocked(), amount);
    }

    function testFuzz_deposit_rejectsOverMax(uint256 amount) public {
        amount = bound(amount, 100 ether + 1, type(uint256).max);
        vm.deal(user, amount);
        vm.prank(user);
        vm.expectRevert(PrivacyPool.InvalidAmount.selector);
        pool.deposit{value: amount}(keccak256("overmax"));
    }

    // ──────────────────────────────────────────────────────────────────
    // Withdraw: input validation
    // ──────────────────────────────────────────────────────────────────

    function _dummyProof()
        internal
        pure
        returns (Groth16Verifier.Proof memory)
    {
        return
            Groth16Verifier.Proof({
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

    function test_withdraw_reverts_when_paused() public {
        // Deposit first so pool has funds and a known root
        vm.prank(user);
        pool.deposit{value: 1 ether}(keccak256("c1"));
        bytes32 root = pool.currentRoot();

        pool.pause();

        vm.expectRevert(PrivacyPool.PoolPaused.selector);
        pool.withdraw(_dummyProof(), root, bytes32(uint256(1)), user, 1 ether);
    }

    function test_withdraw_reverts_zero_recipient() public {
        vm.prank(user);
        pool.deposit{value: 1 ether}(keccak256("c1"));
        bytes32 root = pool.currentRoot();

        vm.expectRevert(PrivacyPool.InvalidRecipient.selector);
        pool.withdraw(
            _dummyProof(),
            root,
            bytes32(uint256(1)),
            address(0),
            1 ether
        );
    }

    function test_withdraw_reverts_zero_nullifier() public {
        vm.prank(user);
        pool.deposit{value: 1 ether}(keccak256("c1"));
        bytes32 root = pool.currentRoot();

        vm.expectRevert(PrivacyPool.InvalidNullifier.selector);
        pool.withdraw(_dummyProof(), root, bytes32(0), user, 1 ether);
    }

    function test_withdraw_reverts_zero_amount() public {
        vm.prank(user);
        pool.deposit{value: 1 ether}(keccak256("c1"));
        bytes32 root = pool.currentRoot();

        vm.expectRevert(PrivacyPool.InvalidAmount.selector);
        pool.withdraw(_dummyProof(), root, bytes32(uint256(1)), user, 0);
    }

    function test_withdraw_reverts_unknown_root() public {
        vm.expectRevert(PrivacyPool.MerkleRootUnknown.selector);
        pool.withdraw(
            _dummyProof(),
            keccak256("bogus-root"),
            bytes32(uint256(1)),
            user,
            1 ether
        );
    }

    function test_withdraw_reverts_invalid_proof() public {
        // With placeholder VK, proof verification should fail
        vm.prank(user);
        pool.deposit{value: 1 ether}(keccak256("c1"));
        bytes32 root = pool.currentRoot();

        vm.expectRevert();
        pool.withdraw(_dummyProof(), root, bytes32(uint256(1)), user, 1 ether);
    }

    function test_withdraw_knownRoot_afterDeposit() public {
        vm.prank(user);
        pool.deposit{value: 1 ether}(keccak256("c1"));
        bytes32 root1 = pool.currentRoot();

        vm.prank(user);
        pool.deposit{value: 1 ether}(keccak256("c2"));

        // root1 should still be known (historical root)
        assertTrue(pool.isKnownRoot(root1));
    }
}
