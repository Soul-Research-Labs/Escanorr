//! Note model — the fundamental unit of value in the privacy pool.
//!
//! A note represents a private UTXO: `Note { owner, value, asset_id, blinding }`.
//! The note commitment `cm = Poseidon(owner, value, asset_id, blinding)` is
//! what gets inserted into the Merkle tree on-chain.

use ff::{Field, PrimeField};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use escanorr_primitives::poseidon::{poseidon_hash, poseidon_hash_with_domain, DOMAIN_NOTE_COMMITMENT};

/// A private note (UTXO) in the shielded pool.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    /// Owner field — typically the x-coordinate of the owner's viewing key.
    #[serde(with = "field_serde")]
    pub owner: pallas::Base,
    /// Value stored in this note.
    pub value: u64,
    /// Asset identifier (0 = native token).
    pub asset_id: u64,
    /// Random blinding factor for hiding the commitment.
    #[serde(with = "field_serde")]
    pub blinding: pallas::Base,
}

impl Note {
    /// Create a new note with a random blinding factor.
    pub fn new(owner: pallas::Base, value: u64, asset_id: u64) -> Self {
        Self {
            owner,
            value,
            asset_id,
            blinding: pallas::Base::random(OsRng),
        }
    }

    /// Create a note with a specific blinding factor (for testing or reconstruction).
    pub fn with_blinding(
        owner: pallas::Base,
        value: u64,
        asset_id: u64,
        blinding: pallas::Base,
    ) -> Self {
        Self { owner, value, asset_id, blinding }
    }

    /// Compute the note commitment.
    pub fn commitment(&self) -> NoteCommitment {
        let value_field = pallas::Base::from(self.value);
        let asset_field = pallas::Base::from(self.asset_id);
        // cm = Poseidon_domain(Poseidon(owner, value), Poseidon(asset_id, blinding))
        let left = poseidon_hash(self.owner, value_field);
        let right = poseidon_hash(asset_field, self.blinding);
        let cm = poseidon_hash_with_domain(DOMAIN_NOTE_COMMITMENT, left, right);
        NoteCommitment(cm)
    }

    /// Create a zero-value dummy note (used for padding batches).
    pub fn dummy() -> Self {
        Self {
            owner: pallas::Base::zero(),
            value: 0,
            asset_id: 0,
            blinding: pallas::Base::random(OsRng),
        }
    }

    /// Check if this is a dummy (zero-value) note.
    pub fn is_dummy(&self) -> bool {
        self.value == 0
    }
}

/// A note commitment — the hash of a note's contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment(#[serde(with = "field_serde")] pub pallas::Base);

impl std::hash::Hash for NoteCommitment {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_repr().hash(state);
    }
}

impl NoteCommitment {
    /// Get the inner field element.
    pub fn inner(&self) -> pallas::Base {
        self.0
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// Serde helper for Pallas base field elements (serialized as hex strings).
mod field_serde {
    use ff::PrimeField;
    use pasta_curves::pallas;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(field: &pallas::Base, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = field.to_repr();
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<pallas::Base, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        pallas::Base::from_repr(arr)
            .into_option()
            .ok_or_else(|| serde::de::Error::custom("invalid field element"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_commitment_deterministic() {
        let owner = pallas::Base::from(42u64);
        let blinding = pallas::Base::from(99u64);
        let n1 = Note::with_blinding(owner, 100, 0, blinding);
        let n2 = Note::with_blinding(owner, 100, 0, blinding);
        assert_eq!(n1.commitment(), n2.commitment());
    }

    #[test]
    fn different_values_different_commitments() {
        let owner = pallas::Base::from(42u64);
        let blinding = pallas::Base::from(99u64);
        let n1 = Note::with_blinding(owner, 100, 0, blinding);
        let n2 = Note::with_blinding(owner, 200, 0, blinding);
        assert_ne!(n1.commitment(), n2.commitment());
    }

    #[test]
    fn different_owners_different_commitments() {
        let blinding = pallas::Base::from(99u64);
        let n1 = Note::with_blinding(pallas::Base::from(1u64), 100, 0, blinding);
        let n2 = Note::with_blinding(pallas::Base::from(2u64), 100, 0, blinding);
        assert_ne!(n1.commitment(), n2.commitment());
    }

    #[test]
    fn dummy_note_is_zero_value() {
        let dummy = Note::dummy();
        assert!(dummy.is_dummy());
        assert_eq!(dummy.value, 0);
    }

    #[test]
    fn note_serde_roundtrip() {
        let note = Note::with_blinding(
            pallas::Base::from(42u64),
            1000,
            0,
            pallas::Base::from(77u64),
        );
        let json = serde_json::to_string(&note).unwrap();
        let recovered: Note = serde_json::from_str(&json).unwrap();
        assert_eq!(note.commitment(), recovered.commitment());
    }

    #[test]
    fn commitment_bytes_non_zero() {
        let note = Note::new(pallas::Base::from(1u64), 100, 0);
        let bytes = note.commitment().to_bytes();
        assert_ne!(bytes, [0u8; 32]);
    }
}
