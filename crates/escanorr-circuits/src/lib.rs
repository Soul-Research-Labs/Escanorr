//! ESCANORR Circuits — Halo2 ZK circuits for the privacy coprocessor.
//!
//! Circuits:
//! - **TransferCircuit**: 2-in-2-out private transfer (k=13)
//! - **WithdrawCircuit**: Transfer with a public exit value (k=13)
//! - **BridgeCircuit**: Cross-chain state transition proof
//! - **WealthProofCircuit**: Prove balance ≥ threshold (k=15)
//!
//! All circuits use Halo2 with IPA commitments over Pallas/Vesta.

pub mod transfer;
pub mod withdraw;
pub mod bridge;

pub use transfer::TransferCircuit;
pub use withdraw::WithdrawCircuit;
pub use bridge::BridgeCircuit;

/// Circuit parameter: `k` value for transfer/withdraw circuits.
pub const K_TRANSFER: u32 = 13;
/// Circuit parameter: `k` value for wealth proof circuits.
pub const K_WEALTH: u32 = 15;
