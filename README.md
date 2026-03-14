# Escanorr

**Zcash-native privacy coprocessor & cross-chain bridge**

Escanorr extends Zcash's Orchard-level privacy across chains. It combines a Halo2-based privacy coprocessor with a cross-chain bridge that wraps Zcash-native proofs for EVM verification — enabling private transfers, withdrawals, and bridging without metadata leakage.

[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

> This project is under active development and has not been audited. Do not use in production with real funds.

---

## Why Escanorr?

No production-grade Zcash ↔ EVM bridge exists. Zcash's privacy is single-chain. Escanorr extends it cross-chain:

- **Zcash-native cryptography**: Halo2 proving system over Pallas/Vesta curves — no trusted setup
- **Cross-chain privacy**: Recursive proof wrapping (Halo2/IPA → Groth16/BN254) for EVM verification
- **Zcash-family support**: Native compatibility with Horizen, Komodo, and Pirate Chain via shared circuit parameters
- **Stealth addresses**: ECDH-based one-time addresses on Pallas for unlinkable receiving
- **Poseidon hashing**: Algebraic hash function for efficient in-circuit operations

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ESCANORR Architecture                           │
│                                                                     │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────────┐  │
│  │ escanorr-cli │  │ @escanorr/sdk(TS)│  │ escanorr-sdk (Rust) │  │
│  │ REPL binary  │  │ HTTP client      │  │ High-level API      │  │
│  └──────┬───────┘  └────────┬─────────┘  └──────────┬──────────┘  │
│         │                   │                        │              │
│  ┌──────▼───────────────────▼────────────────────────▼──────────┐  │
│  │                    escanorr-rpc                               │  │
│  │  Axum HTTP server · proof envelope unwrap · batch processing │  │
│  └──────────────────────────┬───────────────────────────────────┘  │
│                              │                                      │
│  ┌───────────────────────────▼──────────────────────────────────┐  │
│  │                    escanorr-bridge                            │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐   │  │
│  │  │ ZcashAdapter│  │ EVMAdapter   │  │ ZcashForkAdapter  │   │  │
│  │  │ (lightwalletd│ │ (recursive   │  │ (Horizen/Komodo/  │   │  │
│  │  │  / zcashd)  │  │  proof wrap) │  │  Pirate Chain)    │   │  │
│  │  └─────────────┘  └──────────────┘  └───────────────────┘   │  │
│  └──────────────────────────┬───────────────────────────────────┘  │
│                              │                                      │
│  ┌──────┬───────────────────▼─────────────────────────────────┐   │
│  │ escanorr-node          │  escanorr-contracts               │   │
│  │ Prover daemon          │  PrivacyPool state machine        │   │
│  │ Note relay/store       │  Epoch/nullifier management       │   │
│  │ Batch accumulator      │  Cross-chain nullifier sync       │   │
│  └──────┬─────────────────┴───────────────────────────────────┘   │
│         │                                                          │
│  ┌──────▼──────────┐  ┌──────────────────────────────────────┐   │
│  │escanorr-prover  │  │ escanorr-verifier                    │   │
│  │Halo2 IPA prove  │  │ Halo2 IPA verify                     │   │
│  │BN254 wrap       │  │ Recursive BN254 verify               │   │
│  └──────┬──────────┘  └──────────────────────────────────────┘   │
│         │                                                         │
│  ┌──────▼─────────────────────────────────────────────────────┐  │
│  │                  escanorr-circuits                          │  │
│  │  TransferCircuit (k=17) · WithdrawCircuit · BridgeCircuit  │  │
│  └──────┬─────────────────┬──────────────────┬───────────────┘   │
│         │                 │                   │                    │
│  ┌──────▼─────┐  ┌───────▼──────┐  ┌────────▼───────────────┐   │
│  │escanorr-   │  │escanorr-tree │  │escanorr-primitives     │   │
│  │  note      │  │Merkle tree   │  │Poseidon hash           │   │
│  │Note, keys  │  │depth=32      │  │Domain nullifiers       │   │
│  │Encryption  │  │              │  │Proof envelopes         │   │
│  │Stealth addr│  │              │  │                        │   │
│  └────────────┘  └──────────────┘  └────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Crates

| Crate                   | Description                                                                                                                   |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **escanorr-primitives** | Field types (Pallas/Vesta), Poseidon hash, domain-separated nullifiers, proof envelopes                                       |
| **escanorr-note**       | UTXO note model, key hierarchy (spending/viewing/full), ChaCha20-Poly1305 encryption, stealth addresses                       |
| **escanorr-tree**       | Append-only incremental Merkle tree (depth 32, Poseidon)                                                                      |
| **escanorr-circuits**   | Halo2 ZK circuits — transfer (2-in-2-out), withdraw, bridge (chain-ID distinctness)                                           |
| **escanorr-prover**     | Proof generation with Halo2 IPA backend, sealed proof envelopes                                                               |
| **escanorr-verifier**   | Proof verification with Halo2 IPA backend                                                                                     |
| **escanorr-contracts**  | Privacy pool state machine — deposits, withdrawals, transfers, epoch/nullifier tracking                                       |
| **escanorr-node**       | Prover daemon state coordinator — transaction recording, pool management, batch accumulator, sled persistence                 |
| **escanorr-client**     | Wallet with BIP39 key derivation, note tracking, greedy coin selection, AES-256-GCM encrypted persistence                     |
| **escanorr-bridge**     | Cross-chain adapter trait with retry logic: Zcash, Horizen, Komodo, Pirate Chain, Ethereum, Polygon, Arbitrum, Optimism, Base |
| **escanorr-sdk**        | High-level orchestrator — deposit, send, withdraw, bridge with async prover                                                   |
| **escanorr-rpc**        | Axum HTTP server — 9 endpoints, per-IP rate limiting, Prometheus metrics, structured tracing                                  |
| **escanorr-cli**        | CLI binary — serve, init, import, export, info, deposit, balance, withdraw, transfer, bridge, history subcommands             |

---

## Getting Started

### Prerequisites

- **Rust 1.75+** (`rustup update stable`)
- **Git** (for Halo2 git dependencies)

### Build

```bash
git clone https://github.com/Soul-Research-Labs/escanorr.git
cd escanorr
cargo build --release
```

### Run Tests

```bash
# Run all tests (prover tests take ~3 minutes due to Halo2 proof generation)
cargo test

# Run fast tests only (skip prover)
cargo test --workspace --exclude escanorr-prover

# Run a specific crate's tests
cargo test -p escanorr-primitives
cargo test -p escanorr-circuits
```

### Start the RPC Server

```bash
cargo run --release --bin escanorr-cli -- serve --addr 127.0.0.1:3030
```

### Create a Wallet

```bash
# Creates an encrypted wallet at ~/.escanorr/wallet.enc
cargo run --release --bin escanorr-cli -- init
```

### CLI Usage

```bash
# Show wallet info (spending/viewing keys)
cargo run --release --bin escanorr-cli -- info

# Deposit into privacy pool
cargo run --release --bin escanorr-cli -- deposit --value 100

# Check balance
cargo run --release --bin escanorr-cli -- balance

# Private transfer (recipient is a 64-char hex public key)
cargo run --release --bin escanorr-cli -- transfer --recipient <hex> --value 50

# Withdraw with ZK proof
cargo run --release --bin escanorr-cli -- withdraw --value 25 --fee 1

# Cross-chain bridge
cargo run --release --bin escanorr-cli -- bridge --dest-chain-id 137

# Import wallet from mnemonic
cargo run --release --bin escanorr-cli -- import

# Export spending key for backup
cargo run --release --bin escanorr-cli -- export

# View recent transaction history
cargo run --release --bin escanorr-cli -- history --count 50
```

---

### TypeScript SDK

```bash
cd sdks/typescript
npm install
npm test
```

```typescript
import { EscanorrClient, ChainId } from "@escanorr/sdk";

const client = new EscanorrClient({
  baseUrl: "http://localhost:3030",
  retries: 3, // retry on 5xx / network errors
  retryBaseMs: 500, // exponential backoff starting at 500ms
});

const health = await client.health();
const info = await client.info();
const deposit = await client.deposit({ owner: "0x...", value: 1000 });
```

---

## Cryptographic Primitives

### Halo2 (IPA)

The Zcash Halo2 proving system with Inner Product Argument commitments over the Pallas/Vesta curve cycle. No trusted setup required.

### Pallas/Vesta Curve Cycle

- **Pallas**: Main curve for note commitments, nullifiers, and stealth addresses
- **Vesta**: Complement curve enabling efficient recursive proof composition

### Poseidon Hash

Algebraic hash function (P128Pow5T3 in circuits) with domain separation for:

- Note commitments (`DOMAIN_NOTE_COMMITMENT`)
- Nullifier derivation (`DOMAIN_NULLIFIER`)
- Merkle tree nodes (`DOMAIN_MERKLE`)

### Nullifiers

Domain-separated with constant-time comparison (V1 for standard notes, V2 for cross-chain bridged notes). Prevents double-spending across chains.

### Note Encryption

- **ECDH** key agreement on Pallas
- **HKDF-SHA256** symmetric key derivation
- **ChaCha20-Poly1305** authenticated encryption

### Proof Envelopes

Fixed-size 32 KiB containers with random padding to prevent proof-size side channels. 4-byte LE length prefix, payload, then random fill.

---

## Cross-Chain Bridge Design

ESCANORR bridges Zcash privacy to EVM chains via a two-step process:

1. **Prove** (Zcash-native): Generate a Halo2/IPA proof over Pallas/Vesta for the privacy-preserving state transition
2. **Wrap** (EVM-compatible): Recursively wrap the Halo2 proof into a Groth16/BN254 proof that EVM contracts can verify cheaply (~200K gas)

### Supported Chains

| Chain        | Type       | Adapter                                               |
| ------------ | ---------- | ----------------------------------------------------- |
| Zcash        | Native     | `ZcashAdapter` — shared circuit params, Pallas-native |
| Horizen      | Zcash fork | `ZcashForkAdapter` — parameter-compatible             |
| Komodo       | Zcash fork | `ZcashForkAdapter` — parameter-compatible             |
| Pirate Chain | Zcash fork | `ZcashForkAdapter` — parameter-compatible             |
| Ethereum     | EVM        | `EVMAdapter` — recursive proof wrapping               |
| Polygon      | EVM        | `EVMAdapter` — recursive proof wrapping               |
| Arbitrum     | EVM        | `EVMAdapter` — recursive proof wrapping               |
| Optimism     | EVM        | `EVMAdapter` — recursive proof wrapping               |
| Base         | EVM        | `EVMAdapter` — recursive proof wrapping               |

---

## Project Structure

```
escanorr/
├── Cargo.toml                 # Workspace manifest
├── crates/
│   ├── escanorr-primitives/   # Field types, Poseidon, nullifiers, envelopes
│   ├── escanorr-note/         # Note model, keys, encryption, stealth
│   ├── escanorr-tree/         # Incremental Merkle tree (depth 32)
│   ├── escanorr-circuits/     # Halo2 ZK circuits
│   ├── escanorr-prover/       # Proof generation
│   ├── escanorr-verifier/     # Proof verification
│   ├── escanorr-contracts/    # Privacy pool state machine
│   ├── escanorr-node/         # Node state coordinator
│   ├── escanorr-client/       # Wallet & coin selection
│   ├── escanorr-bridge/       # Cross-chain adapters
│   ├── escanorr-sdk/          # High-level orchestrator
│   ├── escanorr-rpc/          # Axum HTTP server
│   └── escanorr-cli/          # CLI binary
├── contracts/                  # Solidity (Foundry) — EVM verifier
├── docs/                       # Architecture decision records
├── sdks/                       # TypeScript SDK
├── tests/                      # Integration tests
├── benches/                    # Benchmarks
├── fuzz/                       # Fuzz targets
├── deploy/                     # Helm chart & Kubernetes configs
└── Dockerfile                  # Multi-stage production image
```

---

## Production Readiness Checklist

Before deploying with real funds, complete every item below:

- [ ] **Security audit** — Independent audit of all Halo2 circuits, Solidity contracts, and bridge adapter code
- [ ] **Groth16 verification key** — Replace the placeholder VK in `Groth16Verifier.sol` with keys generated from a trusted setup ceremony (see [Groth16 Setup Guide](docs/guides/groth16-setup.md))
- [ ] **Bridge relayer** — Implement and deploy the cross-chain bridge relayer (see [ADR-005](docs/adr/005-bridge-relayer-architecture.md))
- [ ] **Recursive proof wrapping** — Complete the `snark-verifier` integration in `EvmAdapter::submit()` (currently returns `EvmWrappingNotImplemented`)
- [ ] **On-chain Merkle tree depth** — Verify the depth-32 IncrementalMerkleTree gas profile meets target chain block limits
- [ ] **Key management** — Hardware-backed key storage for relayer signing keys and contract admin keys
- [x] **Rate limiting** — Per-IP sliding-window rate limiter (60 req/min) with exempt IPs, deployed on the RPC server (128 KiB body limit)
- [x] **Monitoring** — Prometheus metrics on `/metrics` (deposits, transfers, withdrawals, bridge locks, tree size, epoch, nullifier count)
- [ ] **Incident response** — Emergency pause procedures tested; owner multisig deployed
- [ ] **Fuzz testing** — Run `cargo fuzz` targets for extended duration (current CI only compile-checks)

---

## Inspired By

- [ZAseon](https://github.com/Soul-Research-Labs/ZAseon) — Cross-chain ZK privacy middleware
- [Lumora](https://github.com/Soul-Research-Labs/Lumora) — Halo2 privacy coprocessor
- [Zcash Orchard](https://github.com/zcash/orchard) — Zcash's shielded protocol
- [Penumbra](https://github.com/penumbra-zone/penumbra) — Private DEX/staking on Cosmos
- [Aztec](https://github.com/AztecProtocol/aztec-packages) — EVM privacy layer

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

---

## Documentation

- [RPC API Reference](docs/guides/api.md) — All 9 HTTP endpoints with request/response schemas
- [Deployment Guide](docs/guides/deployment.md) — Docker, Helm, and Kubernetes setup
- [Groth16 Setup Guide](docs/guides/groth16-setup.md) — Trusted setup ceremony
- [ADR-001: Halo2 IPA](docs/adr/001-halo2-ipa-pallas-vesta.md) — Proving system choice
- [ADR-002: Domain Nullifiers](docs/adr/002-domain-separated-nullifiers.md) — Cross-chain nullifier design
- [ADR-003: Recursive Wrapping](docs/adr/003-recursive-proof-wrapping.md) — EVM proof wrapping
- [ADR-004: Proof Envelopes](docs/adr/004-fixed-size-proof-envelopes.md) — Side-channel resistant format
- [ADR-005: Bridge Architecture](docs/adr/005-bridge-relayer-architecture.md) — Relayer design

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

### Development

```bash
# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --workspace --all-targets

# Run all tests
cargo test --workspace

# Run Solidity tests
cd contracts && forge test -vvv

# Build docs
cargo doc --workspace --no-deps --open
```
