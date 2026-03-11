//! ESCANORR Node — prover daemon and state coordinator.
//!
//! Manages the privacy pool state, processes transactions, and coordinates
//! proof generation.

mod state;
pub mod storage;

pub use state::{NodeState, NodeError, TxRecord, TxKind};
pub use storage::{NodeStorage, StorageError};
