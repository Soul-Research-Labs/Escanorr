// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

contract Groth16VerifierTest is Test {
    Groth16Verifier public verifier;

    function setUp() public {
        verifier = new Groth16Verifier();
    }

    // ── Proof structure helpers ──────────────────────────────

    function _zeroProof() internal pure returns (Groth16Verifier.Proof memory) {
        return
            Groth16Verifier.Proof({
                a_x: 1,
                a_y: 2,
                b_x1: 1,
                b_x2: 0,
                b_y1: 0,
                b_y2: 0,
                c_x: 1,
                c_y: 2
            });
    }

    // ── Input validation ────────────────────────────────────
    // NOTE: The verifier uses placeholder verification key points.
    // Valid-format proofs will pass input validation then fail at the pairing
    // check. We test that input validation rejects bad inputs *before* pairing,
    // and that well-formed inputs reach the pairing stage.

    function test_rejectsEmptyInputs_reachesPairing() public {
        Groth16Verifier.Proof memory proof = _zeroProof();
        uint256[] memory inputs = new uint256[](0);
        // 0 inputs passes validation but fails at pairing (placeholder VK)
        vm.expectRevert(Groth16Verifier.PairingFailed.selector);
        verifier.verifyProof(proof, inputs);
    }

    function test_rejectsTooManyInputs() public {
        Groth16Verifier.Proof memory proof = _zeroProof();
        uint256[] memory inputs = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) {
            inputs[i] = i + 1;
        }
        vm.expectRevert(Groth16Verifier.InvalidPublicInputs.selector);
        verifier.verifyProof(proof, inputs);
    }

    function test_rejectsInputExceedingScalarField() public {
        Groth16Verifier.Proof memory proof = _zeroProof();
        uint256[] memory inputs = new uint256[](1);
        // SCALAR_FIELD from the contract
        inputs[
            0
        ] = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        vm.expectRevert(Groth16Verifier.InvalidPublicInputs.selector);
        verifier.verifyProof(proof, inputs);
    }

    function test_maxValidInputPassesValidation() public {
        Groth16Verifier.Proof memory proof = _zeroProof();
        uint256[] memory inputs = new uint256[](1);
        // SCALAR_FIELD - 1 should pass validation, then fail at pairing
        inputs[
            0
        ] = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
        vm.expectRevert(Groth16Verifier.PairingFailed.selector);
        verifier.verifyProof(proof, inputs);
    }

    function test_rejectsProofPointOutOfBounds() public {
        uint256 primeQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        Groth16Verifier.Proof memory proof = _zeroProof();
        proof.a_x = primeQ; // out of range
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 42;
        vm.expectRevert(Groth16Verifier.InvalidProofLength.selector);
        verifier.verifyProof(proof, inputs);
    }

    function test_rejectsProofCPointOutOfBounds() public {
        uint256 primeQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        Groth16Verifier.Proof memory proof = _zeroProof();
        proof.c_y = primeQ; // out of range
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 42;
        vm.expectRevert(Groth16Verifier.InvalidProofLength.selector);
        verifier.verifyProof(proof, inputs);
    }

    function test_4InputsPassValidation() public {
        Groth16Verifier.Proof memory proof = _zeroProof();
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = 1;
        inputs[1] = 2;
        inputs[2] = 3;
        inputs[3] = 4;
        // 4 inputs passes validation, then reaches pairing (fails with placeholder VK)
        vm.expectRevert(Groth16Verifier.PairingFailed.selector);
        verifier.verifyProof(proof, inputs);
    }

    function test_verifierIsDeterministic() public {
        Groth16Verifier.Proof memory proof = _zeroProof();
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 100;
        inputs[1] = 200;
        // Both calls should revert with the same error
        vm.expectRevert(Groth16Verifier.PairingFailed.selector);
        verifier.verifyProof(proof, inputs);
        vm.expectRevert(Groth16Verifier.PairingFailed.selector);
        verifier.verifyProof(proof, inputs);
    }

    // ── Fuzz tests ──────────────────────────────────────────

    function testFuzz_rejectsOversizedInputArray(uint8 len) public {
        vm.assume(len > 4);
        Groth16Verifier.Proof memory proof = _zeroProof();
        uint256[] memory inputs = new uint256[](len);
        vm.expectRevert(Groth16Verifier.InvalidPublicInputs.selector);
        verifier.verifyProof(proof, inputs);
    }

    function testFuzz_rejectsInputBeyondField(uint256 val) public {
        uint256 scalarField = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        vm.assume(val >= scalarField);
        Groth16Verifier.Proof memory proof = _zeroProof();
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = val;
        vm.expectRevert(Groth16Verifier.InvalidPublicInputs.selector);
        verifier.verifyProof(proof, inputs);
    }
}
