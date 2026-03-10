// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Groth16 BN254 Verifier for ESCANORR
/// @notice Verifies Groth16 proofs over BN254 (alt_bn128) that attest to the
///         correctness of recursively wrapped Halo2/IPA/Pallas privacy proofs.
/// @dev Uses the EVM precompiles at addresses 6 (ecAdd), 7 (ecMul), and 8 (ecPairing).
///      The verification key is hardcoded for the ESCANORR recursive wrapping circuit.
///      In production, this would be generated from the actual circuit's trusted setup.
contract Groth16Verifier {
    // ──────────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────────

    error InvalidProofLength();
    error InvalidPublicInputs();
    error PairingFailed();
    error EcMulFailed();
    error EcAddFailed();

    // ──────────────────────────────────────────────────────────────────
    // BN254 curve order
    // ──────────────────────────────────────────────────────────────────

    uint256 internal constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ──────────────────────────────────────────────────────────────────
    // Placeholder verification key points
    // NOTE: These are placeholder values. In production, replace with
    // actual VK points from the recursive wrapping circuit's setup.
    // ──────────────────────────────────────────────────────────────────

    // G1 points (alpha, beta, gamma, delta) — placeholder identity-ish values
    uint256 internal constant VK_ALPHA_X = 1;
    uint256 internal constant VK_ALPHA_Y = 2;

    uint256 internal constant VK_BETA_X1 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant VK_BETA_X2 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant VK_BETA_Y1 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 internal constant VK_BETA_Y2 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;

    uint256 internal constant VK_GAMMA_X1 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant VK_GAMMA_X2 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant VK_GAMMA_Y1 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 internal constant VK_GAMMA_Y2 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;

    uint256 internal constant VK_DELTA_X1 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant VK_DELTA_X2 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant VK_DELTA_Y1 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 internal constant VK_DELTA_Y2 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;

    // IC (input commitment) points — for up to 4 public inputs
    uint256 internal constant VK_IC0_X = 1;
    uint256 internal constant VK_IC0_Y = 2;
    uint256 internal constant VK_IC1_X = 1;
    uint256 internal constant VK_IC1_Y = 2;
    uint256 internal constant VK_IC2_X = 1;
    uint256 internal constant VK_IC2_Y = 2;
    uint256 internal constant VK_IC3_X = 1;
    uint256 internal constant VK_IC3_Y = 2;
    uint256 internal constant VK_IC4_X = 1;
    uint256 internal constant VK_IC4_Y = 2;

    uint256 internal constant MAX_PUBLIC_INPUTS = 4;

    // ──────────────────────────────────────────────────────────────────
    // Proof structure: 8 uint256 values = A(x,y), B(x1,x2,y1,y2), C(x,y)
    // ──────────────────────────────────────────────────────────────────

    struct Proof {
        uint256 a_x;
        uint256 a_y;
        uint256 b_x1;
        uint256 b_x2;
        uint256 b_y1;
        uint256 b_y2;
        uint256 c_x;
        uint256 c_y;
    }

    /// @notice Verify a Groth16 proof with the given public inputs
    /// @param proof The Groth16 proof (A, B, C points)
    /// @param publicInputs Array of public inputs (max 4)
    /// @return True if the proof is valid
    function verifyProof(
        Proof calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        if (publicInputs.length > MAX_PUBLIC_INPUTS)
            revert InvalidPublicInputs();

        // Validate public inputs are in the scalar field
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] >= SCALAR_FIELD) revert InvalidPublicInputs();
        }

        // Validate proof points are on the curve (x, y < PRIME_Q)
        if (proof.a_x >= PRIME_Q || proof.a_y >= PRIME_Q)
            revert InvalidProofLength();
        if (proof.c_x >= PRIME_Q || proof.c_y >= PRIME_Q)
            revert InvalidProofLength();

        // Compute vk_x = IC[0] + sum(publicInputs[i] * IC[i+1])
        uint256[2] memory vk_x = [VK_IC0_X, VK_IC0_Y];

        uint256[2][5] memory ic = [
            [VK_IC0_X, VK_IC0_Y],
            [VK_IC1_X, VK_IC1_Y],
            [VK_IC2_X, VK_IC2_Y],
            [VK_IC3_X, VK_IC3_Y],
            [VK_IC4_X, VK_IC4_Y]
        ];

        for (uint256 i = 0; i < publicInputs.length; i++) {
            // ecMul: IC[i+1] * publicInputs[i]
            (uint256 mx, uint256 my) = _ecMul(
                ic[i + 1][0],
                ic[i + 1][1],
                publicInputs[i]
            );
            // ecAdd: vk_x += result
            (vk_x[0], vk_x[1]) = _ecAdd(vk_x[0], vk_x[1], mx, my);
        }

        // Pairing check:
        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        return _pairingCheck(proof, vk_x);
    }

    // ──────────────────────────────────────────────────────────────────
    // Internal precompile wrappers
    // ──────────────────────────────────────────────────────────────────

    function _ecAdd(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) internal view returns (uint256, uint256) {
        uint256[4] memory input;
        input[0] = x1;
        input[1] = y1;
        input[2] = x2;
        input[3] = y2;

        uint256[2] memory result;
        bool success;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 6, input, 128, result, 64)
        }

        if (!success) revert EcAddFailed();
        return (result[0], result[1]);
    }

    function _ecMul(
        uint256 x,
        uint256 y,
        uint256 s
    ) internal view returns (uint256, uint256) {
        uint256[3] memory input;
        input[0] = x;
        input[1] = y;
        input[2] = s;

        uint256[2] memory result;
        bool success;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 7, input, 96, result, 64)
        }

        if (!success) revert EcMulFailed();
        return (result[0], result[1]);
    }

    function _pairingCheck(
        Proof calldata proof,
        uint256[2] memory vk_x
    ) internal view returns (bool) {
        // 4 pairing pairs = 24 uint256 values
        uint256[24] memory input;

        // Pair 1: -A, B
        input[0] = proof.a_x;
        input[1] = (PRIME_Q - proof.a_y) % PRIME_Q; // negate Y for -A
        input[2] = proof.b_x2;
        input[3] = proof.b_x1;
        input[4] = proof.b_y2;
        input[5] = proof.b_y1;

        // Pair 2: alpha, beta
        input[6] = VK_ALPHA_X;
        input[7] = VK_ALPHA_Y;
        input[8] = VK_BETA_X2;
        input[9] = VK_BETA_X1;
        input[10] = VK_BETA_Y2;
        input[11] = VK_BETA_Y1;

        // Pair 3: vk_x, gamma
        input[12] = vk_x[0];
        input[13] = vk_x[1];
        input[14] = VK_GAMMA_X2;
        input[15] = VK_GAMMA_X1;
        input[16] = VK_GAMMA_Y2;
        input[17] = VK_GAMMA_Y1;

        // Pair 4: C, delta
        input[18] = proof.c_x;
        input[19] = proof.c_y;
        input[20] = VK_DELTA_X2;
        input[21] = VK_DELTA_X1;
        input[22] = VK_DELTA_Y2;
        input[23] = VK_DELTA_Y1;

        uint256[1] memory result;
        bool success;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 8, input, 768, result, 32)
        }

        if (!success) revert PairingFailed();
        return result[0] == 1;
    }
}
