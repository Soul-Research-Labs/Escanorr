//! ESCANORR Bridge — cross-chain bridge adapters.
//!
//! Provides:
//! - `ChainAdapter` trait: common interface for chain-specific adapters
//! - `ZcashAdapter`: Zcash mainnet via lightwalletd
//! - `ZcashForkAdapter`: Zcash forks (Horizen, Komodo, Pirate Chain)
//! - `EvmAdapter`: EVM chains (pending recursive proof wrapping)

mod adapter;

pub use adapter::{ChainAdapter, ChainId, BridgeMessage, BridgeError};
