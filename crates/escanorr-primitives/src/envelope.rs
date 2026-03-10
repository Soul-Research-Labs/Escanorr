//! Fixed-size proof envelopes for metadata resistance.
//!
//! All proofs are padded to exactly [`ENVELOPE_SIZE`] bytes (32768) with
//! cryptographically random padding. This prevents an observer from
//! inferring the operation type (transfer vs. withdraw vs. bridge)
//! based on proof size.

use rand::RngCore;

use crate::types::EscanorrError;

/// Fixed envelope size in bytes.
pub const ENVELOPE_SIZE: usize = 32768;

/// A fixed-size proof envelope that hides the actual proof length.
#[derive(Clone, Debug)]
pub struct ProofEnvelope {
    /// The sealed envelope bytes (always exactly [`ENVELOPE_SIZE`]).
    data: [u8; ENVELOPE_SIZE],
}

impl ProofEnvelope {
    /// Seal a proof payload into a fixed-size envelope.
    ///
    /// The format is: `[payload_len: 4 bytes LE][payload][random padding]`.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload exceeds `ENVELOPE_SIZE - 4` bytes.
    pub fn seal(payload: &[u8]) -> Result<Self, EscanorrError> {
        let max_payload = ENVELOPE_SIZE - 4;
        if payload.len() > max_payload {
            return Err(EscanorrError::Envelope(format!(
                "payload too large: {} bytes (max {})",
                payload.len(),
                max_payload
            )));
        }

        let mut data = [0u8; ENVELOPE_SIZE];

        // Write payload length as 4-byte LE
        let len_bytes = (payload.len() as u32).to_le_bytes();
        data[..4].copy_from_slice(&len_bytes);

        // Write payload
        data[4..4 + payload.len()].copy_from_slice(payload);

        // Fill remaining bytes with random padding
        let padding_start = 4 + payload.len();
        if padding_start < ENVELOPE_SIZE {
            rand::thread_rng().fill_bytes(&mut data[padding_start..]);
        }

        Ok(ProofEnvelope { data })
    }

    /// Open an envelope and extract the original proof payload.
    pub fn open(&self) -> Result<Vec<u8>, EscanorrError> {
        if self.data.len() < 4 {
            return Err(EscanorrError::Envelope("envelope too short".into()));
        }

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&self.data[..4]);
        let len = u32::from_le_bytes(len_bytes) as usize;

        let max_payload = ENVELOPE_SIZE - 4;
        if len > max_payload {
            return Err(EscanorrError::Envelope(format!(
                "stored length {} exceeds maximum {}",
                len, max_payload
            )));
        }

        Ok(self.data[4..4 + len].to_vec())
    }

    /// Get the raw envelope bytes.
    pub fn as_bytes(&self) -> &[u8; ENVELOPE_SIZE] {
        &self.data
    }

    /// Construct from raw bytes (e.g., from network/storage).
    pub fn from_bytes(bytes: [u8; ENVELOPE_SIZE]) -> Self {
        ProofEnvelope { data: bytes }
    }
}

impl serde::Serialize for ProofEnvelope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex_str = hex::encode(self.data);
        serializer.serialize_str(&hex_str)
    }
}

impl<'de> serde::Deserialize<'de> for ProofEnvelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != ENVELOPE_SIZE {
            return Err(serde::de::Error::custom(format!(
                "expected {} bytes, got {}",
                ENVELOPE_SIZE,
                bytes.len()
            )));
        }
        let mut data = [0u8; ENVELOPE_SIZE];
        data.copy_from_slice(&bytes);
        Ok(ProofEnvelope { data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let payload = b"hello proof world";
        let envelope = ProofEnvelope::seal(payload).unwrap();
        let recovered = envelope.open().unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn envelope_fixed_size() {
        let small = ProofEnvelope::seal(b"tiny").unwrap();
        let large = ProofEnvelope::seal(&[0xab; 1500]).unwrap();
        assert_eq!(small.as_bytes().len(), ENVELOPE_SIZE);
        assert_eq!(large.as_bytes().len(), ENVELOPE_SIZE);
    }

    #[test]
    fn envelope_max_payload() {
        let max = ENVELOPE_SIZE - 4;
        let payload = vec![0u8; max];
        let envelope = ProofEnvelope::seal(&payload).unwrap();
        let recovered = envelope.open().unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn envelope_too_large() {
        let too_big = vec![0u8; ENVELOPE_SIZE]; // exceeds max by 4
        assert!(ProofEnvelope::seal(&too_big).is_err());
    }

    #[test]
    fn envelope_empty_payload() {
        let envelope = ProofEnvelope::seal(b"").unwrap();
        let recovered = envelope.open().unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn envelope_random_padding_differs() {
        let payload = b"same payload";
        let e1 = ProofEnvelope::seal(payload).unwrap();
        let e2 = ProofEnvelope::seal(payload).unwrap();
        // The payloads are identical but padding should differ (with overwhelming probability)
        assert_ne!(e1.as_bytes()[20..], e2.as_bytes()[20..]);
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let env = ProofEnvelope::seal(b"serde test").unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let recovered: ProofEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env.open().unwrap(), recovered.open().unwrap());
    }
}
