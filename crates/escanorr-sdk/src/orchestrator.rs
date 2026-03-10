//! High-level orchestrator for the ESCANORR privacy coprocessor.

use escanorr_client::{Wallet, WalletError};
use escanorr_node::NodeState;
use escanorr_note::Note;
use escanorr_primitives::Base;
use ff::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use thiserror::Error;

/// SDK errors.
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("wallet error: {0}")]
    Wallet(#[from] WalletError),
    #[error("pool error: {0}")]
    Pool(#[from] escanorr_contracts::PoolError),
    #[error("no wallet loaded")]
    NoWallet,
}

/// The top-level ESCANORR orchestrator.
pub struct Escanorr {
    wallet: Wallet,
    node: NodeState,
}

impl Escanorr {
    /// Create a new ESCANORR instance with a random wallet.
    pub fn new() -> Self {
        Self {
            wallet: Wallet::random(),
            node: NodeState::new(),
        }
    }

    /// Create an instance with a specific wallet.
    pub fn with_wallet(wallet: Wallet) -> Self {
        Self {
            wallet,
            node: NodeState::new(),
        }
    }

    /// Get the wallet.
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Get a mutable reference to the wallet.
    pub fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    /// Get the node state.
    pub fn node(&self) -> &NodeState {
        &self.node
    }

    /// Deposit a value into the privacy pool.
    /// Returns the note and its tree index.
    pub fn deposit(&mut self, value: u64) -> Result<(Note, u64), SdkError> {
        let owner = self.wallet.owner().ok_or(SdkError::NoWallet)?;

        let note = Note {
            owner,
            value,
            asset_id: 0,
            blinding: pallas::Base::random(OsRng),
        };

        let cm = note.commitment();
        let index = self.node.deposit(cm.0, value)?;
        self.wallet.add_note(note.clone(), index);

        Ok((note, index))
    }

    /// Send a private transfer to a recipient.
    /// Returns the output notes.
    pub fn send(
        &mut self,
        recipient_owner: Base,
        amount: u64,
        fee: u64,
    ) -> Result<Vec<Note>, SdkError> {
        let total_needed = amount + fee;
        let (selected, total_selected) = self.wallet.select_coins(total_needed)?;

        let root = self.node.root();
        let mut nullifiers = Vec::new();
        let mut input_indices = Vec::new();

        for coin in &selected {
            let sk = self.wallet.spending_key().ok_or(SdkError::NoWallet)?;
            let fvk = sk.to_full_viewing_key();
            let nf = fvk.nullifier(coin.commitment.0);
            nullifiers.push(nf.inner());
            input_indices.push(coin.tree_index);
        }

        // Create output notes
        let recipient_note = Note {
            owner: recipient_owner,
            value: amount,
            asset_id: 0,
            blinding: pallas::Base::random(OsRng),
        };

        let change = total_selected - total_needed;
        let my_owner = self.wallet.owner().ok_or(SdkError::NoWallet)?;
        let change_note = Note {
            owner: my_owner,
            value: change,
            asset_id: 0,
            blinding: pallas::Base::random(OsRng),
        };

        let output_cms = vec![recipient_note.commitment().0, change_note.commitment().0];

        self.node.transfer(nullifiers, root, output_cms)?;

        // Mark spent
        for idx in input_indices {
            self.wallet.mark_spent(idx);
        }

        // Track change note
        let change_index = self.node.pool().tree_size() - 1;
        self.wallet.add_note(change_note.clone(), change_index);

        Ok(vec![recipient_note, change_note])
    }

    /// Get the current pool root.
    pub fn root(&self) -> Base {
        self.node.root()
    }

    /// Get the wallet's balance.
    pub fn balance(&self) -> u64 {
        self.wallet.balance()
    }
}

impl Default for Escanorr {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use escanorr_note::SpendingKey;

    #[test]
    fn full_deposit_and_send_flow() {
        let mut esc = Escanorr::new();

        // Deposit
        let (_, _) = esc.deposit(1000).unwrap();
        assert_eq!(esc.balance(), 1000);

        // Create a recipient
        let recipient_sk = SpendingKey::random();
        let recipient_owner = recipient_sk.to_full_viewing_key().viewing_key.to_owner();

        // Send
        let outputs = esc.send(recipient_owner, 400, 10).unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].value, 400); // recipient
        assert_eq!(outputs[1].value, 590); // change: 1000 - 400 - 10
        assert_eq!(esc.balance(), 590);
    }

    #[test]
    fn deposit_multiple() {
        let mut esc = Escanorr::new();
        esc.deposit(500).unwrap();
        esc.deposit(300).unwrap();
        assert_eq!(esc.balance(), 800);
    }
}
