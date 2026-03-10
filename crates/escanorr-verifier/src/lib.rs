//! ESCANORR Verifier — ZK proof verification with Halo2 IPA.
//!
//! Provides:
//! - `VerifierParams`: holds verification keys
//! - `verify_transfer`, `verify_withdraw`, `verify_bridge`: verify specific proof types

mod verify;

pub use verify::{VerifierParams, verify_transfer, verify_withdraw, verify_bridge};
