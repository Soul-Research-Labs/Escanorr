//! Core type aliases and error types for the Escanorr privacy coprocessor.

use pasta_curves::pallas;

/// Base field element on the Pallas curve (used for note commitments, nullifiers, etc.).
pub type Base = pallas::Base;

/// Scalar field element on the Pallas curve (used for secret keys, blinding factors).
pub type Scalar = pallas::Scalar;

/// A point on the Pallas curve (used for public keys, Pedersen commitments).
pub type Point = pallas::Point;

/// An affine point on the Pallas curve.
pub type Affine = pallas::Affine;

/// Root-level error type for the primitives crate.
#[derive(Debug, thiserror::Error)]
pub enum EscanorrError {
    #[error("invalid field element: {0}")]
    InvalidField(String),
    #[error("proof envelope error: {0}")]
    Envelope(String),
    #[error("nullifier error: {0}")]
    Nullifier(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// A 32-byte hash digest used for Merkle roots, nullifiers, and commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, EscanorrError> {
        let bytes = hex::decode(s).map_err(|e| EscanorrError::Serialization(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(EscanorrError::Serialization(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash32(arr))
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(bytes: [u8; 32]) -> Self {
        Hash32(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash32_hex_roundtrip() {
        let h = Hash32([0xab; 32]);
        let hex_str = h.to_hex();
        let recovered = Hash32::from_hex(&hex_str).unwrap();
        assert_eq!(h, recovered);
    }

    #[test]
    fn hash32_invalid_length() {
        assert!(Hash32::from_hex("abcd").is_err());
    }

    #[test]
    fn hash32_invalid_hex() {
        assert!(Hash32::from_hex("zzzz").is_err());
    }
}
