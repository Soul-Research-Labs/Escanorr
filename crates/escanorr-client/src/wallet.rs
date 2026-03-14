//! Wallet — key management, note tracking, coin selection, and encrypted persistence.

use escanorr_note::{SpendingKey, FullViewingKey, Note, NoteCommitment};
use escanorr_primitives::Base;
use ff::PrimeField;
use rand::RngCore;
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
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("decryption failed (wrong password or corrupted file)")]
    Decryption,
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

    /// Generate a new random BIP39 mnemonic and derive a wallet from it.
    /// Returns `(wallet, mnemonic_phrase)`.
    pub fn from_new_mnemonic() -> (Self, String) {
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .expect("valid 32-byte entropy for 24-word mnemonic");
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");
        let sk = SpendingKey::from_seed(&seed[..32]);
        let fvk = sk.to_full_viewing_key();
        let wallet = Self {
            spending_key: Some(sk),
            fvk: Some(fvk),
            notes: Vec::new(),
        };
        (wallet, phrase)
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
        self.fvk.as_ref().and_then(|fvk| fvk.viewing_key.to_owner())
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

// ── Encrypted persistence ───────────────────────────────────────────────────

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use serde::{Serialize, Deserialize};
use std::path::Path;
use zeroize::Zeroize;

/// On-disk format: salt + nonce + ciphertext, all JSON-wrapped for simplicity.
#[derive(Serialize, Deserialize)]
struct EncryptedWallet {
    /// Argon2 salt (16 bytes, hex-encoded).
    salt: String,
    /// AES-GCM nonce (12 bytes, hex-encoded).
    nonce: String,
    /// AES-GCM ciphertext (hex-encoded).
    ciphertext: String,
}

/// Plaintext wallet state — what gets encrypted.
#[derive(Serialize, Deserialize)]
struct WalletData {
    /// Spending key scalar bytes (hex).
    spending_key: String,
    /// Owned notes.
    notes: Vec<OwnedNoteData>,
}

#[derive(Serialize, Deserialize)]
struct OwnedNoteData {
    note: escanorr_note::Note,
    tree_index: u64,
    spent: bool,
}

/// Derive a 32-byte AES key from a password and salt using Argon2id.
/// The caller is responsible for zeroizing the returned key after use.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], WalletError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| WalletError::Decryption)?;
    Ok(key)
}

impl Wallet {
    /// Save the wallet to an encrypted file.
    ///
    /// The spending key and all notes are serialized to JSON, then encrypted
    /// with AES-256-GCM. The encryption key is derived from `password` using
    /// Argon2id with a random salt.
    pub fn save(&self, path: &Path, password: &[u8]) -> Result<(), WalletError> {
        let sk = self.spending_key.as_ref().ok_or(WalletError::NoKey)?;

        let data = WalletData {
            spending_key: hex::encode(sk.inner().to_repr()),
            notes: self
                .notes
                .iter()
                .map(|n| OwnedNoteData {
                    note: n.note.clone(),
                    tree_index: n.tree_index,
                    spent: n.spent,
                })
                .collect(),
        };

        let plaintext = serde_json::to_vec(&data)?;

        // Generate random salt and nonce
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

        let mut key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| WalletError::Decryption)?;
        key.zeroize();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| WalletError::Decryption)?;

        let encrypted = EncryptedWallet {
            salt: hex::encode(salt),
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
        };

        let json = serde_json::to_vec_pretty(&encrypted)?;

        // Write atomically via temp file
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, path)?;

        Ok(())
    }

    /// Load a wallet from an encrypted file.
    pub fn load(path: &Path, password: &[u8]) -> Result<Self, WalletError> {
        let json = std::fs::read(path)?;
        let encrypted: EncryptedWallet = serde_json::from_slice(&json)?;

        let salt = hex::decode(&encrypted.salt).map_err(|_| WalletError::Decryption)?;
        let nonce_bytes = hex::decode(&encrypted.nonce).map_err(|_| WalletError::Decryption)?;
        let ciphertext = hex::decode(&encrypted.ciphertext).map_err(|_| WalletError::Decryption)?;

        if nonce_bytes.len() != 12 {
            return Err(WalletError::Decryption);
        }

        let mut key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| WalletError::Decryption)?;
        key.zeroize();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| WalletError::Decryption)?;

        let data: WalletData = serde_json::from_slice(&plaintext)?;

        // Reconstruct spending key from hex
        let sk_bytes = hex::decode(&data.spending_key).map_err(|_| WalletError::Decryption)?;
        let arr: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| WalletError::Decryption)?;
        let scalar = pasta_curves::pallas::Scalar::from_repr(arr);
        let sk = SpendingKey::from_scalar(
            Option::from(scalar).ok_or(WalletError::Decryption)?,
        );
        let fvk = sk.to_full_viewing_key();

        let notes = data
            .notes
            .into_iter()
            .map(|nd| {
                let commitment = nd.note.commitment();
                OwnedNote {
                    note: nd.note,
                    commitment,
                    tree_index: nd.tree_index,
                    spent: nd.spent,
                }
            })
            .collect();

        Ok(Self {
            spending_key: Some(sk),
            fvk: Some(fvk),
            notes,
        })
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

    #[test]
    fn wallet_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.enc");
        let password = b"test-password-123";

        let mut wallet = Wallet::random();
        wallet.add_note(make_note(100), 0);
        wallet.add_note(make_note(200), 1);
        wallet.mark_spent(0);

        let original_owner = wallet.owner().unwrap();
        let original_balance = wallet.balance();

        wallet.save(&path, password).unwrap();

        let loaded = Wallet::load(&path, password).unwrap();
        assert_eq!(loaded.owner().unwrap(), original_owner);
        assert_eq!(loaded.balance(), original_balance);
        assert_eq!(loaded.unspent_notes().len(), 1);
    }

    #[test]
    fn wallet_load_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.enc");

        let wallet = Wallet::random();
        wallet.save(&path, b"correct").unwrap();

        let result = Wallet::load(&path, b"wrong");
        assert!(matches!(result, Err(WalletError::Decryption)));
    }
}
