//! Wallet — key management, note tracking, and coin selection.

use escanorr_note::{SpendingKey, FullViewingKey, Note, NoteCommitment};
use escanorr_primitives::Base;
use thiserror::Error;

/// Wallet errors.
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("insufficient funds: need {need}, have {have}")]
    InsufficientFunds { need: u64, have: u64 },
    #[error("no spending key loaded")]
    NoKey,
    #[error("mnemonic error: {0}")]
    Mnemonic(String),
}

/// A note owned by this wallet, with its position in the Merkle tree.
#[derive(Debug, Clone)]
pub struct OwnedNote {
    pub note: Note,
    pub commitment: NoteCommitment,
    pub tree_index: u64,
    pub spent: bool,
}

/// A simple in-memory wallet.
pub struct Wallet {
    spending_key: Option<SpendingKey>,
    fvk: Option<FullViewingKey>,
    notes: Vec<OwnedNote>,
}

impl Wallet {
    /// Create a new empty wallet.
    pub fn new() -> Self {
        Self {
            spending_key: None,
            fvk: None,
            notes: Vec::new(),
        }
    }

    /// Create a wallet from a random spending key.
    pub fn random() -> Self {
        let sk = SpendingKey::random();
        let fvk = sk.to_full_viewing_key();
        Self {
            spending_key: Some(sk),
            fvk: Some(fvk),
            notes: Vec::new(),
        }
    }

    /// Create a wallet from a BIP39 mnemonic phrase.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, WalletError> {
        let mnemonic = bip39::Mnemonic::parse(phrase)
            .map_err(|e| WalletError::Mnemonic(e.to_string()))?;
        let seed = mnemonic.to_seed("");
        let sk = SpendingKey::from_seed(&seed[..32]);
        let fvk = sk.to_full_viewing_key();
        Ok(Self {
            spending_key: Some(sk),
            fvk: Some(fvk),
            notes: Vec::new(),
        })
    }

    /// Get the spending key.
    pub fn spending_key(&self) -> Option<&SpendingKey> {
        self.spending_key.as_ref()
    }

    /// Get the full viewing key.
    pub fn fvk(&self) -> Option<&FullViewingKey> {
        self.fvk.as_ref()
    }

    /// Get the wallet's owner address (x-coordinate of viewing key point).
    pub fn owner(&self) -> Option<Base> {
        self.fvk.as_ref().map(|fvk| fvk.viewing_key.to_owner())
    }

    /// Track a new note as owned.
    pub fn add_note(&mut self, note: Note, tree_index: u64) {
        let commitment = note.commitment();
        self.notes.push(OwnedNote {
            note,
            commitment,
            tree_index,
            spent: false,
        });
    }

    /// Mark a note as spent by its tree index.
    pub fn mark_spent(&mut self, tree_index: u64) {
        for n in &mut self.notes {
            if n.tree_index == tree_index {
                n.spent = true;
            }
        }
    }

    /// Get total unspent balance.
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.spent)
            .map(|n| n.note.value)
            .sum()
    }

    /// Select coins to cover `target_amount`, using a greedy algorithm.
    /// Returns the selected notes and total value.
    pub fn select_coins(&self, target_amount: u64) -> Result<(Vec<&OwnedNote>, u64), WalletError> {
        let mut unspent: Vec<&OwnedNote> = self.notes.iter().filter(|n| !n.spent).collect();
        // Sort by value descending for greedy selection
        unspent.sort_by(|a, b| b.note.value.cmp(&a.note.value));

        let mut selected = Vec::new();
        let mut total = 0u64;
        for note in unspent {
            if total >= target_amount {
                break;
            }
            total += note.note.value;
            selected.push(note);
        }

        if total < target_amount {
            return Err(WalletError::InsufficientFunds {
                need: target_amount,
                have: total,
            });
        }

        Ok((selected, total))
    }

    /// Get all owned (unspent) notes.
    pub fn unspent_notes(&self) -> Vec<&OwnedNote> {
        self.notes.iter().filter(|n| !n.spent).collect()
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use escanorr_note::Note;
    use ff::Field;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    fn make_note(value: u64) -> Note {
        Note {
            owner: pallas::Base::random(OsRng),
            value,
            asset_id: 0,
            blinding: pallas::Base::random(OsRng),
        }
    }

    #[test]
    fn wallet_balance_and_coin_selection() {
        let mut wallet = Wallet::random();
        wallet.add_note(make_note(100), 0);
        wallet.add_note(make_note(200), 1);
        wallet.add_note(make_note(50), 2);

        assert_eq!(wallet.balance(), 350);

        let (selected, total) = wallet.select_coins(250).unwrap();
        assert!(total >= 250);
        assert!(!selected.is_empty());
    }

    #[test]
    fn wallet_insufficient_funds() {
        let mut wallet = Wallet::random();
        wallet.add_note(make_note(100), 0);

        let result = wallet.select_coins(200);
        assert!(matches!(result, Err(WalletError::InsufficientFunds { .. })));
    }

    #[test]
    fn wallet_mark_spent() {
        let mut wallet = Wallet::random();
        wallet.add_note(make_note(100), 0);
        wallet.add_note(make_note(200), 1);

        assert_eq!(wallet.balance(), 300);
        wallet.mark_spent(0);
        assert_eq!(wallet.balance(), 200);
    }
}
