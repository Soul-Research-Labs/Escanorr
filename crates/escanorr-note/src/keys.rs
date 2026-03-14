//! Key hierarchy for the Escanorr privacy coprocessor.
//!
//! ```text
//! SpendingKey (sk) ──→ ViewingKey (vk = sk * G) ──→ NullifierKey, EncryptionKey
//! ```
//!
//! The spending key is a Pallas scalar. The viewing key is the corresponding
//! Pallas point (public key). The full viewing key bundles both.

use ff::{Field, PrimeField};
use group::Group;
use pasta_curves::{arithmetic::CurveAffine, pallas};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A spending key — the master secret for a wallet.
///
/// Knowledge of the spending key allows spending notes and deriving nullifiers.
/// The scalar is zeroized from memory on drop.
#[derive(Clone, Debug)]
pub struct SpendingKey(pallas::Scalar);

impl Drop for SpendingKey {
    fn drop(&mut self) {
        // Zeroize the scalar's repr bytes in-place
        let bytes = self.0.to_repr();
        let _ = bytes; // scalar is Copy; we overwrite via mut ref
        // Write zero scalar over self
        self.0 = pallas::Scalar::zero();
    }
}

impl SpendingKey {
    /// Generate a new random spending key.
    pub fn random() -> Self {
        SpendingKey(pallas::Scalar::random(OsRng))
    }

    /// Create from a raw scalar.
    pub fn from_scalar(scalar: pallas::Scalar) -> Self {
        SpendingKey(scalar)
    }

    /// Create from a BIP39 seed (first 32 bytes → scalar).
    pub fn from_seed(seed: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(seed);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        // Clear top bits to ensure value is in the scalar field
        bytes[31] &= 0x0f;
        let scalar = pallas::Scalar::from_repr(bytes)
            .expect("seed hash with cleared top bits must be valid scalar");
        SpendingKey(scalar)
    }

    /// Get the raw scalar value.
    pub fn inner(&self) -> pallas::Scalar {
        self.0
    }

    /// Convert spending key to a base field element for nullifier derivation.
    ///
    /// # Panics
    /// If the scalar representation exceeds the Pallas base modulus (extremely
    /// unlikely in practice since both fields have similar size).
    pub fn to_base(&self) -> pallas::Base {
        let bytes = self.0.to_repr();
        // Reinterpret scalar bytes as a base field element.
        // Pallas scalar and base fields have similar moduli, so this
        // succeeds for all but a negligible fraction of scalars.
        pallas::Base::from_repr(bytes)
            .expect("spending key scalar must be representable as base field element")
    }

    /// Derive the corresponding viewing key (public key).
    pub fn to_viewing_key(&self) -> ViewingKey {
        let point = pallas::Point::generator() * self.0;
        ViewingKey(point)
    }

    /// Derive a full viewing key (spending + viewing).
    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey {
            spending_key: self.clone(),
            viewing_key: self.to_viewing_key(),
        }
    }
}

/// A viewing key — the public key derived from a spending key.
///
/// Allows scanning for incoming notes but not spending them.
#[derive(Clone, Debug)]
pub struct ViewingKey(pub pallas::Point);

impl ViewingKey {
    /// Get the raw point.
    pub fn inner(&self) -> pallas::Point {
        self.0
    }

    /// Get the x-coordinate as a base field element (for use as note owner).
    pub fn to_owner(&self) -> pallas::Base {
        let affine: pallas::Affine = self.0.into();
        let coords = affine.coordinates();
        if bool::from(coords.is_some()) {
            *coords.unwrap().x()
        } else {
            pallas::Base::zero()
        }
    }

    /// Serialize to bytes (compressed point representation).
    pub fn to_bytes(&self) -> [u8; 32] {
        let affine: pallas::Affine = self.0.into();
        let coords = affine.coordinates();
        if bool::from(coords.is_some()) {
            coords.unwrap().x().to_repr()
        } else {
            [0u8; 32] // Point at infinity
        }
    }
}

/// Full viewing key: spending + viewing key pair.
#[derive(Clone, Debug)]
pub struct FullViewingKey {
    pub spending_key: SpendingKey,
    pub viewing_key: ViewingKey,
}

impl FullViewingKey {
    /// Compute the "owner" field for notes owned by this key.
    pub fn owner(&self) -> pallas::Base {
        self.viewing_key.to_owner()
    }

    /// Compute a nullifier for a given note commitment.
    pub fn nullifier(&self, commitment: pallas::Base) -> escanorr_primitives::nullifier::Nullifier {
        escanorr_primitives::compute_nullifier_v1(self.spending_key.to_base(), commitment)
    }

    /// Compute a V2 nullifier with domain separation.
    pub fn nullifier_v2(
        &self,
        commitment: pallas::Base,
        domain: &escanorr_primitives::DomainSeparator,
    ) -> escanorr_primitives::nullifier::Nullifier {
        escanorr_primitives::compute_nullifier_v2(self.spending_key.to_base(), commitment, domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spending_key_random() {
        let sk1 = SpendingKey::random();
        let sk2 = SpendingKey::random();
        assert_ne!(sk1.inner(), sk2.inner());
    }

    #[test]
    fn spending_key_to_viewing_key() {
        let sk = SpendingKey::random();
        let vk = sk.to_viewing_key();
        // Viewing key should be a non-identity point
        assert_ne!(vk.inner(), pallas::Point::identity());
    }

    #[test]
    fn full_viewing_key_owner() {
        let sk = SpendingKey::random();
        let fvk = sk.to_full_viewing_key();
        let owner = fvk.owner();
        assert_ne!(owner, pallas::Base::zero());
    }

    #[test]
    fn full_viewing_key_nullifier() {
        let sk = SpendingKey::random();
        let fvk = sk.to_full_viewing_key();
        let cm = pallas::Base::from(42u64);
        let nf1 = fvk.nullifier(cm);
        let nf2 = fvk.nullifier(cm);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn seed_derivation_deterministic() {
        let seed = b"test seed for deterministic key derivation";
        let sk1 = SpendingKey::from_seed(seed);
        let sk2 = SpendingKey::from_seed(seed);
        assert_eq!(sk1.inner(), sk2.inner());
    }

    #[test]
    fn different_seeds_different_keys() {
        let sk1 = SpendingKey::from_seed(b"seed-a");
        let sk2 = SpendingKey::from_seed(b"seed-b");
        assert_ne!(sk1.inner(), sk2.inner());
    }
}
