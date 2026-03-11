//! Privacy pool — the core state machine for managing deposits, withdrawals, and transfers.

use crate::nullifier_set::NullifierSet;
use escanorr_primitives::Base;
use escanorr_tree::IncrementalMerkleTree;
use thiserror::Error;

/// Errors from the privacy pool.
#[derive(Debug, Error)]
pub enum PoolError {
    #[error("double spend: nullifier already exists")]
    DoubleSpend,
    #[error("invalid Merkle root")]
    InvalidRoot,
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

/// The privacy pool state machine.
pub struct PrivacyPool {
    tree: IncrementalMerkleTree,
    nullifiers: NullifierSet,
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
        Self {
            tree: IncrementalMerkleTree::new(),
            nullifiers: NullifierSet::new(),
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
        Ok(index)
    }

    /// Process a withdrawal: check nullifier, optionally insert change commitment.
    pub fn withdraw(&mut self, req: WithdrawRequest) -> Result<(), PoolError> {
        // Verify Merkle root
        if self.tree.root() != req.merkle_root {
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

        Ok(())
    }

    /// Process a transfer: check nullifiers, insert output commitments.
    pub fn transfer(&mut self, req: TransferRequest) -> Result<(), PoolError> {
        // Verify Merkle root
        if self.tree.root() != req.merkle_root {
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
}
