# ADR-002: Domain-Separated Poseidon Nullifiers

## Status

Accepted

## Context

Nullifiers prevent double-spending. In a cross-chain system, nullifiers must be unique not just within a chain but across all supported chains. A note bridged from Zcash to Ethereum and back must not be double-spent on either chain.

## Decision

Use domain-separated Poseidon-based nullifiers with two versions:

- **V1**: `Poseidon(DOMAIN_NULLIFIER, spending_key, note_commitment)` — for standard single-chain notes
- **V2**: `Poseidon(DOMAIN_NULLIFIER, spending_key, note_commitment, chain_id)` — for cross-chain bridged notes

Both use constant-time comparison (`subtle::ConstantTimeEq`) to prevent timing side channels.

## Rationale

- Poseidon is algebraic and efficient inside Halo2 circuits
- Domain separation via constants (`DOMAIN_NULLIFIER = 0x02`) prevents cross-purpose collisions
- V2 nullifiers with chain_id binding prevent a bridged note from being spent on the wrong chain
- Constant-time comparison prevents timing attacks during nullifier lookups

## Consequences

- The BridgeCircuit must constrain chain_id distinctness (source ≠ destination) within the circuit
- Nullifier sets must be synchronized across chains for full double-spend prevention
- The two-version scheme maintains backward compatibility if single-chain mode is used standalone
