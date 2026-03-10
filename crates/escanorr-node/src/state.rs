//! Node state management — tracks the privacy pool, pending transactions, and history.

use escanorr_contracts::{PrivacyPool, PoolError, DepositRequest, WithdrawRequest, TransferRequest};
use escanorr_primitives::Base;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

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
