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

    function test_initialState() public view {
        assertEq(vault.owner(), owner);
        assertFalse(vault.paused());
        assertEq(address(vault.verifier()), address(verifier));
        assertEq(address(vault.nullifierRegistry()), address(registry));
    }

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
}
