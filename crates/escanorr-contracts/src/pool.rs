//! Privacy pool — the core state machine for managing deposits, withdrawals, and transfers.

use crate::nullifier_set::NullifierSet;
use escanorr_primitives::Base;
use escanorr_tree::IncrementalMerkleTree;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from the privacy pool.
#[derive(Debug, Error)]
pub enum PoolError {
    #[error("double spend: nullifier already exists")]
    DoubleSpend,
    #[error("invalid Merkle root")]
    InvalidRoot,
    #[error("Merkle root expired (too many epochs old)")]
    RootExpired,
    #[error("value overflow")]
    Overflow,
    #[error("tree is full")]
    TreeFull,
}

/// A request to deposit funds into the privacy pool.
#[derive(Debug, Clone)]
pub struct DepositRequest {
    /// The note commitment to insert into the Merkle tree.
    pub commitment: Base,
    /// The deposit value (verified externally, e.g., via on-chain check).
    pub value: u64,
}

/// A request to withdraw funds from the privacy pool.
#[derive(Debug, Clone)]
pub struct WithdrawRequest {
    /// Nullifier for the spent note.
    pub nullifier: Base,
    /// The claimed Merkle root at time of proof generation.
    pub merkle_root: Base,
    /// The value being withdrawn (public).
    pub exit_value: u64,
    /// Output commitment for change (if any).
    pub change_commitment: Option<Base>,
}

/// A request to perform a private transfer within the pool.
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Nullifiers for spent input notes.
    pub nullifiers: Vec<Base>,
    /// The claimed Merkle root.
    pub merkle_root: Base,
    /// Output commitments for newly created notes.
    pub output_commitments: Vec<Base>,
}

use std::collections::VecDeque;

/// Maximum number of historical roots to retain.
/// Proofs referencing a root older than this are rejected.
const MAX_ROOT_HISTORY: usize = 100;

/// The privacy pool state machine.
#[derive(Serialize, Deserialize)]
pub struct PrivacyPool {
    tree: IncrementalMerkleTree,
    nullifiers: NullifierSet,
    /// Historical Merkle roots (most-recent last). The current root
    /// is always the last entry. Roots older than MAX_ROOT_HISTORY
    /// entries are pruned and considered expired.
    #[serde(skip, default)]
    known_roots: VecDeque<Base>,
    /// Epoch counter.
    pub epoch: u64,
    /// Total deposited value (for accounting).
    pub total_deposited: u128,
    /// Total withdrawn value.
    pub total_withdrawn: u128,
}

impl PrivacyPool {
    /// Create a new empty privacy pool.
    pub fn new() -> Self {
        let tree = IncrementalMerkleTree::new();
        let initial_root = tree.root();
        let mut known_roots = VecDeque::with_capacity(MAX_ROOT_HISTORY);
        known_roots.push_back(initial_root);
        Self {
            tree,
            nullifiers: NullifierSet::new(),
            known_roots,
            epoch: 0,
            total_deposited: 0,
            total_withdrawn: 0,
        }
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> Base {
        self.tree.root()
    }

    /// Get the current tree size.
    pub fn tree_size(&self) -> u64 {
        self.tree.size()
    }

    /// Get the Merkle authentication path for a leaf at `index`.
    /// Returns `(siblings, path_indices)` or `None` if index is out of range.
    pub fn auth_path(&self, index: u64) -> Option<(Vec<Base>, Vec<u8>)> {
        self.tree.auth_path(index)
    }

    /// Process a deposit: insert commitment into the Merkle tree.
    pub fn deposit(&mut self, req: DepositRequest) -> Result<u64, PoolError> {
        let index = self.tree.insert(req.commitment);
        self.total_deposited = self
            .total_deposited
            .checked_add(req.value as u128)
            .ok_or(PoolError::Overflow)?;
        self.record_root();
        Ok(index)
    }

    /// Process a withdrawal: check nullifier, optionally insert change commitment.
    pub fn withdraw(&mut self, req: WithdrawRequest) -> Result<(), PoolError> {
        // Verify Merkle root is known (not expired)
        if !self.is_known_root(req.merkle_root) {
            return Err(PoolError::InvalidRoot);
        }

        // Check double-spend
        if !self.nullifiers.insert(req.nullifier) {
            return Err(PoolError::DoubleSpend);
        }

        // Insert change commitment if present
        if let Some(cm) = req.change_commitment {
            self.tree.insert(cm);
        }

        self.total_withdrawn = self
            .total_withdrawn
            .checked_add(req.exit_value as u128)
            .ok_or(PoolError::Overflow)?;

        self.record_root();
        Ok(())
    }

    /// Process a transfer: check nullifiers, insert output commitments.
    pub fn transfer(&mut self, req: TransferRequest) -> Result<(), PoolError> {
        // Verify Merkle root is known (not expired)
        if !self.is_known_root(req.merkle_root) {
            return Err(PoolError::InvalidRoot);
        }

        // Check double-spend for all input nullifiers
        for nf in &req.nullifiers {
            if !self.nullifiers.insert(*nf) {
                return Err(PoolError::DoubleSpend);
            }
        }

        // Insert output commitments
        for cm in &req.output_commitments {
            self.tree.insert(*cm);
        }

        self.record_root();
        Ok(())
    }

    /// Advance to the next epoch.
    pub fn advance_epoch(&mut self) {
        self.epoch += 1;
    }

    /// Get the nullifier set (for inspection/serialization).
    pub fn nullifier_set(&self) -> &NullifierSet {
        &self.nullifiers
    }

    /// Check whether `root` is in the recent history of known roots.
    /// Returns `false` for expired or unknown roots.
    pub fn is_known_root(&self, root: Base) -> bool {
        self.known_roots.iter().any(|r| *r == root)
    }

    /// Record the current Merkle root in history, pruning old entries.
    fn record_root(&mut self) {
        let root = self.tree.root();
        self.known_roots.push_back(root);
        while self.known_roots.len() > MAX_ROOT_HISTORY {
            self.known_roots.pop_front();
        }
    }
}

impl Default for PrivacyPool {
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
    fn deposit_and_root_changes() {
        let mut pool = PrivacyPool::new();
        let root_before = pool.root();

        let cm = pallas::Base::random(OsRng);
        pool.deposit(DepositRequest {
            commitment: cm,
            value: 1000,
        })
        .unwrap();

        assert_ne!(pool.root(), root_before);
        assert_eq!(pool.tree_size(), 1);
        assert_eq!(pool.total_deposited, 1000);
    }

    #[test]
    fn withdraw_checks_nullifier() {
        let mut pool = PrivacyPool::new();
        let cm = pallas::Base::random(OsRng);
        pool.deposit(DepositRequest {
            commitment: cm,
            value: 1000,
        })
        .unwrap();

        let root = pool.root();
        let nf = pallas::Base::random(OsRng);

        // First withdraw succeeds
        pool.withdraw(WithdrawRequest {
            nullifier: nf,
            merkle_root: root,
            exit_value: 500,
            change_commitment: None,
        })
        .unwrap();

        let root2 = pool.root();
        // Double spend fails
        let result = pool.withdraw(WithdrawRequest {
            nullifier: nf,
            merkle_root: root2,
            exit_value: 500,
            change_commitment: None,
        });
        assert!(matches!(result, Err(PoolError::DoubleSpend)));
    }

    #[test]
    fn transfer_inserts_outputs() {
        let mut pool = PrivacyPool::new();
        let cm = pallas::Base::random(OsRng);
        pool.deposit(DepositRequest {
            commitment: cm,
            value: 1000,
        })
        .unwrap();

        let root = pool.root();
        let nf = pallas::Base::random(OsRng);
        let out0 = pallas::Base::random(OsRng);
        let out1 = pallas::Base::random(OsRng);

        pool.transfer(TransferRequest {
            nullifiers: vec![nf],
            merkle_root: root,
            output_commitments: vec![out0, out1],
        })
        .unwrap();

        // 1 deposit + 2 transfer outputs = 3
        assert_eq!(pool.tree_size(), 3);
    }

    #[test]
    fn invalid_root_rejected() {
        let mut pool = PrivacyPool::new();
        let cm = pallas::Base::random(OsRng);
        pool.deposit(DepositRequest {
            commitment: cm,
            value: 1000,
        })
        .unwrap();

        let fake_root = pallas::Base::random(OsRng);
        let nf = pallas::Base::random(OsRng);

        let result = pool.withdraw(WithdrawRequest {
            nullifier: nf,
            merkle_root: fake_root,
            exit_value: 500,
            change_commitment: None,
        });
        assert!(matches!(result, Err(PoolError::InvalidRoot)));
    }

    #[test]
    fn recent_root_accepted_after_deposits() {
        let mut pool = PrivacyPool::new();
        let cm1 = pallas::Base::random(OsRng);
        pool.deposit(DepositRequest { commitment: cm1, value: 100 }).unwrap();
        let old_root = pool.root();

        // Make a second deposit (changes the root)
        let cm2 = pallas::Base::random(OsRng);
        pool.deposit(DepositRequest { commitment: cm2, value: 200 }).unwrap();
        assert_ne!(pool.root(), old_root);

        // The old root should still be accepted (within history window)
        let nf = pallas::Base::random(OsRng);
        pool.withdraw(WithdrawRequest {
            nullifier: nf,
            merkle_root: old_root,
            exit_value: 50,
            change_commitment: None,
        }).unwrap();
    }

    #[test]
    fn expired_root_rejected() {
        let mut pool = PrivacyPool::new();
        let cm = pallas::Base::random(OsRng);
        pool.deposit(DepositRequest { commitment: cm, value: 100 }).unwrap();
        let old_root = pool.root();

        // Do MAX_ROOT_HISTORY + 1 deposits to push old_root out of history
        for i in 0..(super::MAX_ROOT_HISTORY + 1) {
            let cm = pallas::Base::from(i as u64 + 1000);
            pool.deposit(DepositRequest { commitment: cm, value: 1 }).unwrap();
        }

        // The old root should now be expired
        let nf = pallas::Base::random(OsRng);
        let result = pool.withdraw(WithdrawRequest {
            nullifier: nf,
            merkle_root: old_root,
            exit_value: 50,
            change_commitment: None,
        });
        assert!(matches!(result, Err(PoolError::InvalidRoot)));
    }
}
