//! ESCANORR Prover — ZK proof generation with Halo2 IPA.
//!
//! Provides:
//! - `ProverParams`: keygen and parameter setup
//! - `prove_transfer`: generate a transfer proof
//! - `prove_withdraw`: generate a withdraw proof
//! - `prove_bridge`: generate a bridge proof

mod prove;

pub use prove::{ProverParams, prove_transfer, prove_withdraw, prove_bridge};
