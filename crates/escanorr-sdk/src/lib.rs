//! ESCANORR SDK — high-level orchestrator for privacy pool operations.
//!
//! Provides a single `Escanorr` struct that coordinates wallet, node, and bridge
//! operations into simple deposit/send/withdraw/bridge calls.

mod orchestrator;

pub use orchestrator::{
    Escanorr, SdkError, TransferResult, WithdrawResult, BridgeResult,
};
