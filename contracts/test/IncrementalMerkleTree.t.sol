// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {IncrementalMerkleTree} from "../src/IncrementalMerkleTree.sol";

/// @dev Wrapper contract to expose library functions for testing
contract TreeHarness {
    using IncrementalMerkleTree for IncrementalMerkleTree.Tree;

    IncrementalMerkleTree.Tree public tree;
    bool public initialized;

    function init() external {
        tree.init();
        initialized = true;
    }

    function insert(bytes32 leaf) external returns (uint256) {
        return tree.insert(leaf);
    }

    function root() external view returns (bytes32) {
        return tree.getRoot();
    }

    function nextIndex() external view returns (uint256) {
        return tree.getNextIndex();
    }
}

contract IncrementalMerkleTreeTest is Test {
    TreeHarness public harness;

    function setUp() public {
        harness = new TreeHarness();
        harness.init();
    }

    function test_initialState() public view {
        assertEq(harness.nextIndex(), 0);
        // Root should be non-zero after init (hash of zeros propagated up)
        assertTrue(harness.root() != bytes32(0));
    }

    function test_insertSingleLeaf() public {
        bytes32 leaf = keccak256("commitment1");
        uint256 index = harness.insert(leaf);
        assertEq(index, 0);
        assertEq(harness.nextIndex(), 1);
    }

    function test_insertChangesRoot() public {
        bytes32 rootBefore = harness.root();
        bytes32 leaf = keccak256("commitment1");
        harness.insert(leaf);
        bytes32 rootAfter = harness.root();
        assertTrue(rootBefore != rootAfter);
    }

    function test_insertMultipleLeaves() public {
        bytes32 leaf1 = keccak256("commitment1");
        bytes32 leaf2 = keccak256("commitment2");
        bytes32 leaf3 = keccak256("commitment3");

        assertEq(harness.insert(leaf1), 0);
        assertEq(harness.insert(leaf2), 1);
        assertEq(harness.insert(leaf3), 2);
        assertEq(harness.nextIndex(), 3);
    }

    function test_differentLeavesProduceDifferentRoots() public {
        TreeHarness h1 = new TreeHarness();
        TreeHarness h2 = new TreeHarness();
        h1.init();
        h2.init();

        h1.insert(keccak256("a"));
        h2.insert(keccak256("b"));

        assertTrue(h1.root() != h2.root());
    }

    function test_sameLeavesSameRoot() public {
        TreeHarness h1 = new TreeHarness();
        TreeHarness h2 = new TreeHarness();
        h1.init();
        h2.init();

        bytes32 leaf = keccak256("same");
        h1.insert(leaf);
        h2.insert(leaf);

        assertEq(h1.root(), h2.root());
    }

    function test_insertionOrderMatters() public {
        TreeHarness h1 = new TreeHarness();
        TreeHarness h2 = new TreeHarness();
        h1.init();
        h2.init();

        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");
        bytes32 c = keccak256("c");

        // [a, b, c] vs [c, b, a] — asymmetric across subtree boundaries
        h1.insert(a);
        h1.insert(b);
        h1.insert(c);

        h2.insert(c);
        h2.insert(b);
        h2.insert(a);

        assertTrue(h1.root() != h2.root());
    }

    function test_revert_insertZeroLeaf() public {
        vm.expectRevert(IncrementalMerkleTree.InvalidLeaf.selector);
        harness.insert(bytes32(0));
    }

    function test_rootDeterministic() public {
        bytes32 leaf = keccak256("deterministic");
        harness.insert(leaf);
        bytes32 root1 = harness.root();

        // Create a fresh tree and insert the same leaf
        TreeHarness h2 = new TreeHarness();
        h2.init();
        h2.insert(leaf);

        assertEq(root1, h2.root());
    }

    function test_batchInsertions() public {
        for (uint256 i = 0; i < 16; i++) {
            harness.insert(keccak256(abi.encode(i)));
        }
        assertEq(harness.nextIndex(), 16);
        assertTrue(harness.root() != bytes32(0));
    }

    function testFuzz_insertNonZeroLeaf(bytes32 leaf) public {
        vm.assume(leaf != bytes32(0));
        uint256 index = harness.insert(leaf);
        assertEq(index, 0);
        assertEq(harness.nextIndex(), 1);
        assertTrue(harness.root() != bytes32(0));
    }
}
