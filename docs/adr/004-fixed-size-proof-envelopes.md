# ADR-004: Fixed-Size Proof Envelopes

## Status

Accepted

## Context

ZK proofs vary in size based on circuit complexity. An adversary observing proof sizes could infer transaction types (transfer vs bridge vs withdraw) or circuit parameters, leaking metadata.

## Decision

All proofs are sealed into fixed-size 32 KiB `ProofEnvelope` containers before transmission. Structure:

- 4-byte little-endian length prefix (actual proof size)
- Variable-length proof payload
- Random padding (from `OsRng`) to fill the remaining space

## Rationale

- **Side-channel resistance**: All envelopes are identical in size regardless of circuit type
- **Simplicity**: Fixed buffers simplify network protocol framing
- **32 KiB**: Accommodates Halo2 IPA proofs (typically ~8 KiB for k=13) with room for growth

## Trade-offs

- Bandwidth overhead: ~24 KiB of random padding per proof
- Larger than necessary for simple proofs
- Cannot accommodate proofs larger than 32 KiB (would need to increase ENVELOPE_SIZE)

## Consequences

- All network and storage layers handle uniform 32 KiB buffers
- The `seal()`/`open()` API encapsulates the padding logic
- Serde serialization uses hex encoding for transport
