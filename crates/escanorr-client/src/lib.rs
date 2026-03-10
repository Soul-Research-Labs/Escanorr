//! ESCANORR Client — wallet key management and note tracking.
//!
//! Provides:
//! - `Wallet`: create keys, track owned notes, select coins for spending
//! - Mnemonic-based key derivation (BIP39)
//! - Encrypted wallet backup

mod wallet;

pub use wallet::{Wallet, OwnedNote, WalletError};
