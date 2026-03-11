// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {NullifierRegistry} from "../src/NullifierRegistry.sol";
import {PrivacyPool} from "../src/PrivacyPool.sol";
import {BridgeVault} from "../src/BridgeVault.sol";

/// @notice Deploy all ESCANORR contracts
contract DeployEscanorr is Script {
    function run() public {
        vm.startBroadcast();

        // 1. Deploy verifier
        Groth16Verifier verifier = new Groth16Verifier();
        console2.log("Groth16Verifier:", address(verifier));

        // 2. Deploy nullifier registry (pool address set after)
        NullifierRegistry registry = new NullifierRegistry(address(0));
        console2.log("NullifierRegistry:", address(registry));

        // 3. Deploy privacy pool
        PrivacyPool pool = new PrivacyPool(
            address(verifier),
            address(registry)
        );
        console2.log("PrivacyPool:", address(pool));

        // 4. Deploy bridge vault
        BridgeVault vault = new BridgeVault(
            address(verifier),
            address(registry)
        );
        console2.log("BridgeVault:", address(vault));

        // 5. Authorize pool and vault to record nullifiers
        registry.setPool(address(pool));
        registry.authorize(address(pool));
        registry.authorize(address(vault));
        console2.log("NullifierRegistry: pool and vault authorized");

        vm.stopBroadcast();
    }
}
