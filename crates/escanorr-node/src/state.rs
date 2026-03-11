//! Node state management — tracks the privacy pool, pending transactions, and history.
//!
//! The raw `transfer()` / `withdraw()` methods trust the caller (e.g. SDK after
//! proof generation). For callers that need defense-in-depth, `verified_*`
//! methods accept a proof envelope + public inputs and verify before mutation.

use escanorr_contracts::{PrivacyPool, PoolError, DepositRequest, WithdrawRequest, TransferRequest};
use escanorr_primitives::{Base, ProofEnvelope};
use escanorr_verifier::{VerifierParams, verify_transfer, verify_withdraw, verify_bridge};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Errors from verified node operations.
#[derive(Debug)]
pub enum NodeError {
    Pool(PoolError),
    InvalidProof,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Pool(e) => write!(f, "pool error: {e}"),
            NodeError::InvalidProof => write!(f, "invalid proof"),
        }
    }
}

impl std::error::Error for NodeError {}

/// The kind of transaction processed by the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxKind {
    Deposit { value: u64 },
    Withdraw { exit_value: u64 },
    Transfer,
}

/// A record of a processed transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub epoch: u64,
    pub kind: TxKind,
    pub tree_size: u64,
}

/// The node's in-memory state.
#[derive(Serialize, Deserialize)]
pub struct NodeState {
    pool: PrivacyPool,
    /// Recent transaction history (bounded).
    history: VecDeque<TxRecord>,
    max_history: usize,
}

impl NodeState {
    /// Create a new node state.
    pub fn new() -> Self {
        Self {
            pool: PrivacyPool::new(),
            history: VecDeque::new(),
            max_history: 10_000,
        }
    }

    /// Access the underlying privacy pool.
    pub fn pool(&self) -> &PrivacyPool {
        &self.pool
    }

    /// Process a deposit.
    pub fn deposit(&mut self, commitment: Base, value: u64) -> Result<u64, PoolError> {
        let index = self.pool.deposit(DepositRequest { commitment, value })?;
        self.record(TxKind::Deposit { value });
        Ok(index)
    }

    /// Process a withdrawal.
    pub fn withdraw(
        &mut self,
        nullifier: Base,
        merkle_root: Base,
        exit_value: u64,
        change_commitment: Option<Base>,
    ) -> Result<(), PoolError> {
        self.pool.withdraw(WithdrawRequest {
            nullifier,
            merkle_root,
            exit_value,
            change_commitment,
        })?;
        self.record(TxKind::Withdraw { exit_value });
        Ok(())
    }

    /// Process a transfer.
    pub fn transfer(
        &mut self,
        nullifiers: Vec<Base>,
        merkle_root: Base,
        output_commitments: Vec<Base>,
    ) -> Result<(), PoolError> {
        self.pool.transfer(TransferRequest {
            nullifiers,
            merkle_root,
            output_commitments,
        })?;
        self.record(TxKind::Transfer);
        Ok(())
    }

    /// Advance epoch.
    pub fn advance_epoch(&mut self) {
        self.pool.advance_epoch();
    }

    /// Get current epoch.
    pub fn epoch(&self) -> u64 {
        self.pool.epoch
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> Base {
        self.pool.root()
    }

    /// Get transaction history.
    pub fn history(&self) -> &VecDeque<TxRecord> {
        &self.history
    }

    // ─── Verified (proof-checked) methods ───────────────────────

    /// Transfer with proof verification (defense-in-depth).
    ///
    /// `public_inputs` layout: `[root, nf_0, nf_1, out_cm_0, out_cm_1]`
    pub fn verified_transfer(
        &mut self,
        nullifiers: Vec<Base>,
        merkle_root: Base,
        output_commitments: Vec<Base>,
        envelope: &ProofEnvelope,
        verifier: &VerifierParams,
    ) -> Result<(), NodeError> {
        let mut pi = vec![merkle_root];
        pi.extend_from_slice(&nullifiers);
        pi.extend_from_slice(&output_commitments);
        verify_transfer(verifier, envelope, &[&pi])
            .map_err(|_| NodeError::InvalidProof)?;
        self.transfer(nullifiers, merkle_root, output_commitments)
            .map_err(NodeError::Pool)
    }

    /// Withdraw with proof verification (defense-in-depth).
    ///
    /// `public_inputs` layout: `[root, nullifier, change_cm, exit_value]`
    pub fn verified_withdraw(
        &mut self,
        nullifier: Base,
        merkle_root: Base,
        exit_value: u64,
        change_commitment: Option<Base>,
        envelope: &ProofEnvelope,
        verifier: &VerifierParams,
    ) -> Result<(), NodeError> {
        let chg_cm = change_commitment.unwrap_or(Base::from(0u64));
        let pi = vec![merkle_root, nullifier, chg_cm, Base::from(exit_value)];
        verify_withdraw(verifier, envelope, &[&pi])
            .map_err(|_| NodeError::InvalidProof)?;
        self.withdraw(nullifier, merkle_root, exit_value, change_commitment)
            .map_err(NodeError::Pool)
    }

    /// Bridge lock with proof verification (defense-in-depth).
    ///
    /// `public_inputs` layout: `[src_root, src_nullifier, dest_cm, src_chain_id, dest_chain_id]`
    pub fn verified_bridge_lock(
        &mut self,
        nullifier: Base,
        merkle_root: Base,
        dest_commitment: Base,
        src_chain_id: u64,
        dest_chain_id: u64,
        envelope: &ProofEnvelope,
        verifier: &VerifierParams,
    ) -> Result<(), NodeError> {
        let pi = vec![
            merkle_root,
            nullifier,
            dest_commitment,
            Base::from(src_chain_id),
            Base::from(dest_chain_id),
        ];
        verify_bridge(verifier, envelope, &[&pi])
            .map_err(|_| NodeError::InvalidProof)?;
        // Source chain: nullify the note
        self.withdraw(nullifier, merkle_root, 0, None)
            .map_err(NodeError::Pool)
    }

    fn record(&mut self, kind: TxKind) {
        let record = TxRecord {
            epoch: self.pool.epoch,
            kind,
            tree_size: self.pool.tree_size(),
        };
        self.history.push_back(record);
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    #[test]
    fn node_deposit_and_history() {
        let mut node = NodeState::new();
        let cm = pallas::Base::random(OsRng);
        let idx = node.deposit(cm, 1000).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(node.history().len(), 1);
        assert!(matches!(node.history()[0].kind, TxKind::Deposit { value: 1000 }));
    }

    #[test]
    fn node_transfer_flow() {
        let mut node = NodeState::new();
        let cm = pallas::Base::random(OsRng);
        node.deposit(cm, 1000).unwrap();

        let root = node.root();
        let nf = pallas::Base::random(OsRng);
        let out0 = pallas::Base::random(OsRng);
        let out1 = pallas::Base::random(OsRng);

        node.transfer(vec![nf], root, vec![out0, out1]).unwrap();
        assert_eq!(node.history().len(), 2);
    }
}
