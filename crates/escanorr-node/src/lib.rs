//! ESCANORR Node — prover daemon and state coordinator.
//!
//! Manages the privacy pool state, processes transactions, and coordinates
//! proof generation.

mod state;

pub use state::{NodeState, NodeError, TxRecord, TxKind};
