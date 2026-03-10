// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {NullifierRegistry} from "../src/NullifierRegistry.sol";

contract NullifierRegistryTest is Test {
    NullifierRegistry public registry;
    address public pool = address(0xBEEF);
    address public owner;

    function setUp() public {
        owner = address(this);
        registry = new NullifierRegistry(pool);
    }

    function test_initialState() public view {
        assertEq(registry.owner(), owner);
        assertEq(registry.pool(), pool);
        assertEq(registry.nullifierCount(), 0);
    }

    function test_spend() public {
        bytes32 nf = keccak256("nullifier1");

        vm.prank(pool);
        registry.spend(nf, 1);

        assertTrue(registry.isSpent(nf));
        assertEq(registry.nullifierCount(), 1);
    }

    function test_spend_emitsEvent() public {
        bytes32 nf = keccak256("nullifier1");

        vm.prank(pool);
        vm.expectEmit(true, true, false, true);
        emit NullifierRegistry.NullifierSpent(nf, 1, block.timestamp);
        registry.spend(nf, 1);
    }

    function test_spend_revert_unauthorized() public {
        bytes32 nf = keccak256("nullifier1");

        vm.prank(address(0xDEAD));
        vm.expectRevert(NullifierRegistry.Unauthorized.selector);
        registry.spend(nf, 1);
    }

    function test_spend_revert_alreadySpent() public {
        bytes32 nf = keccak256("nullifier1");

        vm.prank(pool);
        registry.spend(nf, 1);

        vm.prank(pool);
        vm.expectRevert(
            abi.encodeWithSelector(
                NullifierRegistry.NullifierAlreadySpent.selector,
                nf
            )
        );
        registry.spend(nf, 1);
    }

    function test_spend_revert_zeroNullifier() public {
        vm.prank(pool);
        vm.expectRevert(NullifierRegistry.ZeroNullifier.selector);
        registry.spend(bytes32(0), 1);
    }

    function test_batchIsSpent() public {
        bytes32 nf1 = keccak256("nf1");
        bytes32 nf2 = keccak256("nf2");
        bytes32 nf3 = keccak256("nf3");

        vm.startPrank(pool);
        registry.spend(nf1, 1);
        registry.spend(nf3, 1);
        vm.stopPrank();

        bytes32[] memory nfs = new bytes32[](3);
        nfs[0] = nf1;
        nfs[1] = nf2;
        nfs[2] = nf3;

        bool[] memory results = registry.batchIsSpent(nfs);
        assertTrue(results[0]);
        assertFalse(results[1]);
        assertTrue(results[2]);
    }

    function test_setPool() public {
        address newPool = address(0xCAFE);
        registry.setPool(newPool);
        assertEq(registry.pool(), newPool);
    }

    function test_setPool_revert_unauthorized() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(NullifierRegistry.Unauthorized.selector);
        registry.setPool(address(0xCAFE));
    }

    function test_transferOwnership() public {
        address newOwner = address(0xCAFE);
        registry.transferOwnership(newOwner);
        assertEq(registry.owner(), newOwner);
    }

    function test_multipleNullifiers() public {
        vm.startPrank(pool);
        for (uint256 i = 0; i < 10; i++) {
            registry.spend(keccak256(abi.encode(i)), i % 3);
        }
        vm.stopPrank();

        assertEq(registry.nullifierCount(), 10);
    }

    // ──────────────────────────────────────────────────────────────────
    // Multi-pool ACL tests
    // ──────────────────────────────────────────────────────────────────

    function test_authorize() public {
        address bridgeVault = address(0xBB);
        registry.authorize(bridgeVault);
        assertTrue(registry.authorized(bridgeVault));
    }

    function test_authorize_emitsEvent() public {
        address bridgeVault = address(0xBB);
        vm.expectEmit(true, false, false, false);
        emit NullifierRegistry.CallerAuthorized(bridgeVault);
        registry.authorize(bridgeVault);
    }

    function test_authorize_revert_unauthorized() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(NullifierRegistry.Unauthorized.selector);
        registry.authorize(address(0xBB));
    }

    function test_authorize_revert_zeroAddress() public {
        vm.expectRevert(NullifierRegistry.ZeroAddress.selector);
        registry.authorize(address(0));
    }

    function test_authorizedCallerCanSpend() public {
        address bridgeVault = address(0xBB);
        registry.authorize(bridgeVault);

        bytes32 nf = keccak256("bridge-nf");
        vm.prank(bridgeVault);
        registry.spend(nf, 1_000_001);

        assertTrue(registry.isSpent(nf));
    }

    function test_revoke() public {
        address bridgeVault = address(0xBB);
        registry.authorize(bridgeVault);
        assertTrue(registry.authorized(bridgeVault));

        registry.revoke(bridgeVault);
        assertFalse(registry.authorized(bridgeVault));
    }

    function test_revoke_emitsEvent() public {
        address bridgeVault = address(0xBB);
        registry.authorize(bridgeVault);

        vm.expectEmit(true, false, false, false);
        emit NullifierRegistry.CallerRevoked(bridgeVault);
        registry.revoke(bridgeVault);
    }

    function test_revokedCallerCannotSpend() public {
        address bridgeVault = address(0xBB);
        registry.authorize(bridgeVault);
        registry.revoke(bridgeVault);

        bytes32 nf = keccak256("revoked-nf");
        vm.prank(bridgeVault);
        vm.expectRevert(NullifierRegistry.Unauthorized.selector);
        registry.spend(nf, 1);
    }

    function test_setPool_revokesOldPool() public {
        assertTrue(registry.authorized(pool));

        address newPool = address(0xCAFE);
        registry.setPool(newPool);

        assertEq(registry.pool(), newPool);
        assertTrue(registry.authorized(newPool));
        assertFalse(registry.authorized(pool));
    }

    function test_poolIsAuthorizedByDefault() public view {
        assertTrue(registry.authorized(pool));
    }

    function test_multipleAuthorizedCallers() public {
        address vault = address(0xBB);
        address relayer = address(0xCC);
        registry.authorize(vault);
        registry.authorize(relayer);

        bytes32 nf1 = keccak256("pool-nf");
        bytes32 nf2 = keccak256("vault-nf");
        bytes32 nf3 = keccak256("relayer-nf");

        vm.prank(pool);
        registry.spend(nf1, 1);

        vm.prank(vault);
        registry.spend(nf2, 1_000_001);

        vm.prank(relayer);
        registry.spend(nf3, 1_000_137);

        assertEq(registry.nullifierCount(), 3);
        assertTrue(registry.isSpent(nf1));
        assertTrue(registry.isSpent(nf2));
        assertTrue(registry.isSpent(nf3));
    }
}
