# Security Policy

## Disclaimer

**ESCANORR has not been audited.** This software is experimental and should not be used in production with real funds. Use at your own risk.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue.
2. Email **security@soulresearchlabs.dev** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)
3. You will receive an acknowledgement within **48 hours**.
4. We will work with you to understand the scope and coordinate disclosure.

## Scope

The following components are in scope for security reports:

- **Cryptographic primitives** (Poseidon hash, nullifier derivation, proof envelopes)
- **Encryption** (ChaCha20-Poly1305 AEAD, HKDF key derivation)
- **Key management** (spending keys, viewing keys, BIP39 derivation)
- **Zero-knowledge circuits** (Halo2 transfer, withdraw, bridge circuits)
- **Solidity contracts** (PrivacyPool, NullifierRegistry, Groth16Verifier, BridgeVault)
- **RPC server** (input validation, authentication, authorization)
- **Cross-chain bridge** (nullifier isolation, domain separation)

## Known Limitations

- The Groth16 verifier uses **placeholder verification key points** — production deployment requires generating VK from the actual recursive wrapping circuit.
- The Poseidon hash uses a simplified algebraic construction; the full P128Pow5T3 permutation is wired through the Halo2 circuit layer.
- The bridge relayer mechanism is not yet implemented — bridge messages require off-chain coordination.

## Security Practices

- **Constant-time comparison** for nullifiers (via `subtle::ConstantTimeEq`)
- **Domain-separated hashing** to prevent cross-context collisions
- **Fixed-size proof envelopes** (32 KiB) to prevent operation-type side channels
- **Random nonces** for AEAD encryption (12-byte, never reused)
- **No trusted setup** — Halo2/IPA proving system over Pallas/Vesta
