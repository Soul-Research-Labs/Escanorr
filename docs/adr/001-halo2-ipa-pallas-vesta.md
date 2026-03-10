# ADR-001: Halo2 with IPA Over Pallas/Vesta

## Status

Accepted

## Context

ESCANORR needs a zero-knowledge proving system. Options considered:

1. **Groth16/BN254** — Mature, EVM-native, but requires trusted setup per circuit
2. **Plonk/BN254** — Universal SRS, EVM-native, but still needs ceremony
3. **Halo2/IPA over Pallas/Vesta** — Zcash's native proving system, no trusted setup
4. **STARKs** — No trusted setup, but large proofs and no curve alignment with Zcash

## Decision

Use Halo2 with IPA commitments over the Pallas/Vesta curve cycle (the Zcash `halo2_proofs` crate).

## Rationale

- **No trusted setup**: IPA commitments derive verification keys from public randomness — no ceremony needed
- **Zcash alignment**: Reuses the same proving system as Zcash Orchard, enabling shared circuit parameters with Zcash-family chains
- **Curve cycle**: Pallas/Vesta enable efficient recursive proof composition needed for the bridge wrapping step
- **Algebraic compatibility**: Poseidon hash is efficient in Pallas arithmetic, matching Orchard's design

## Trade-offs

- Halo2/IPA proofs are larger than Groth16 (~8 KiB vs ~128 bytes)
- Verification is slower than Groth16 on-chain
- EVM verification requires recursive wrapping (Halo2 → Groth16/BN254), adding complexity
- The `halo2_proofs` crate from Zcash is less actively maintained than PSE's fork

## Consequences

- All circuits are written against the Halo2 API with Pallas as the native scalar field
- EVM chains require a recursive wrapping step via snark-verifier
- Zcash-family chains can verify proofs natively without wrapping
- Proof envelopes are 32 KiB (fixed size with random padding) to accommodate IPA proof sizes
