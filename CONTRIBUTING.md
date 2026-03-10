# Contributing to ESCANORR

Thank you for your interest in contributing to ESCANORR.

## Getting Started

### Prerequisites

- **Rust 1.75+**: `rustup update stable`
- **Foundry** (for Solidity): `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- **Node.js 18+** (for TypeScript SDK): `nvm install 18`

### Setup

```bash
git clone https://github.com/Soul-Research-Labs/escanorr.git
cd escanorr
cargo build
```

### Running Tests

```bash
# Rust (fast — excludes slow prover tests)
cargo test --workspace --exclude escanorr-prover

# Rust (full — includes Halo2 proof generation, ~3 min)
cargo test --workspace

# Solidity
cd contracts && forge test -vvv

# TypeScript SDK
cd sdks/typescript && npm test
```

### Running Lints

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`.
2. Write your code with tests.
3. Run `cargo fmt` and `cargo clippy` before committing.
4. Open a pull request against `main`.

## Code Standards

- **No `unwrap()` in library code** — use `Result<T, E>` with typed errors.
- **Constant-time operations** for all cryptographic comparisons.
- **Domain separation** for all hash functions — never reuse domain tags.
- **Test coverage** — every public function should have unit tests.
- **No `unsafe`** unless absolutely necessary with a safety comment.

## Architecture Decisions

Significant design choices are documented in [docs/adr/](docs/adr/). If your change introduces a new architectural pattern, please write an ADR.

## Crate Structure

| Layer    | Crates                                                            |
| -------- | ----------------------------------------------------------------- |
| Core     | `escanorr-primitives`, `escanorr-note`, `escanorr-tree`           |
| Circuits | `escanorr-circuits`, `escanorr-prover`, `escanorr-verifier`       |
| State    | `escanorr-contracts`, `escanorr-node`                             |
| Client   | `escanorr-client`, `escanorr-sdk`, `escanorr-rpc`, `escanorr-cli` |
| Bridge   | `escanorr-bridge`                                                 |

Dependencies flow downward: CLI → SDK → Node/Client → Circuits → Core.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add stealth address rotation
fix: correct nullifier domain separator for Horizen
test: add property-based tests for Poseidon hash
docs: update bridge architecture ADR
```

## License

By contributing, you agree that your contributions will be licensed under the MIT OR Apache-2.0 dual license.
