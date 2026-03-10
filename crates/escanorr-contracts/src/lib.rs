//! ESCANORR Contracts — Privacy pool state machine.
//!
//! This crate manages the on-chain state for the privacy pool:
//! - Nullifier set (double-spend prevention)
//! - Commitment tree (note commitments)
//! - Epoch management
//! - Deposit/withdraw/transfer processing

mod pool;
mod nullifier_set;

pub use pool::{PrivacyPool, PoolError, DepositRequest, WithdrawRequest, TransferRequest};
pub use nullifier_set::NullifierSet;
