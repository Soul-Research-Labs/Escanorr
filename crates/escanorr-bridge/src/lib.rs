//! ESCANORR Bridge — cross-chain bridge adapters.
//!
//! Provides:
//! - `ChainAdapter` trait: common interface for chain-specific adapters
//! - `ZcashAdapter`: Zcash mainnet via lightwalletd
//! - `ZcashForkAdapter`: Zcash forks (Horizen, Komodo, Pirate Chain)
//! - `EvmAdapter`: EVM chains (pending recursive proof wrapping)
//! - `RetryAdapter`: retry wrapper with exponential backoff and timeout

mod adapter;
pub mod retry;

pub use adapter::{
    ChainAdapter, ChainId, BridgeMessage, BridgeError,
    ZcashAdapter, ZcashForkAdapter, EvmAdapter,
};
pub use retry::{RetryAdapter, RetryConfig};
