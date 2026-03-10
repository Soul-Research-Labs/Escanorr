# ADR-003: Recursive Proof Wrapping for EVM Verification

## Status

Accepted

## Context

Halo2/IPA proofs over Pallas/Vesta cannot be verified directly on EVM chains. The EVM has precompiles for BN254 (alt_bn128) pairing operations but not for Pallas/Vesta IPA verification.

Options:

1. **Rewrite circuits for Groth16/BN254** — Lose Zcash alignment, require trusted setup
2. **Deploy custom IPA verifier on EVM** — Prohibitively expensive gas cost (~millions of gas)
3. **Recursive proof wrapping** — Prove "I verified a Halo2/Pallas proof" inside a Groth16/BN254 circuit

## Decision

Use recursive proof wrapping: generate a Groth16/BN254 proof that attests to the correctness of a Halo2/IPA/Pallas proof. The EVM contract verifies only the outer Groth16 proof (~200K gas).

## Rationale

- Maintains Zcash-native cryptography for the privacy layer
- EVM verification becomes a single pairing check (cheap)
- The recursion overhead is borne by the prover (off-chain), not the verifier (on-chain)
- Axiom's `snark-verifier` provides a production-grade implementation for this wrapping

## Trade-offs

- Proof generation time increases (~2x for the wrapping step)
- Adds a dependency on the BN254 curve for the outer proof
- The wrapping circuit itself needs a trusted setup (universal SRS from Hermez/Perpetual Powers of Tau)
- Zcash-family chains skip this step entirely — they verify Halo2/IPA natively

## Consequences

- The prover pipeline has two stages: native proof → wrapped proof (EVM only)
- A single IPA-verified proof works for all Zcash-family chains
- EVM chains pay gas only for Groth16 verification
- The bridge adapter determines which verification path to use based on `ChainId::is_evm()`
