//! Domain-separated nullifier derivation.
//!
//! Nullifiers prevent double-spending. Two versions are supported:
//!
//! - **V1**: `Poseidon(spending_key, commitment)` — single-chain use.
//! - **V2**: `Poseidon(Poseidon(sk, cm), Poseidon(chain_id, app_id))` —
//!   cross-chain isolation via domain separation.

use ff::PrimeField;
use pasta_curves::pallas;
use subtle::ConstantTimeEq;

use crate::poseidon::{poseidon_hash, poseidon_hash_with_domain, DOMAIN_NULLIFIER};

/// Domain separator for cross-chain nullifier isolation (V2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DomainSeparator {
    pub chain_id: u64,
    pub app_id: u64,
}

impl DomainSeparator {
    pub fn new(chain_id: u64, app_id: u64) -> Self {
        Self { chain_id, app_id }
    }

    /// Convert the domain separator to a field element pair.
    fn to_field_elements(&self) -> (pallas::Base, pallas::Base) {
        (
            pallas::Base::from(self.chain_id),
            pallas::Base::from(self.app_id),
        )
    }
}

/// A nullifier value with constant-time comparison.
#[derive(Clone, Copy, Debug)]
pub struct Nullifier(pub pallas::Base);

impl serde::Serialize for Nullifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex_str = hex::encode(self.0.to_repr());
        serializer.serialize_str(&hex_str)
    }
}

impl<'de> serde::Deserialize<'de> for Nullifier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        let base = pallas::Base::from_repr(arr);
        Option::from(base)
            .map(Nullifier)
            .ok_or_else(|| serde::de::Error::custom("invalid field element"))
    }
}

impl Nullifier {
    pub fn inner(&self) -> pallas::Base {
        self.0
    }

    /// Convert to a 32-byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

impl ConstantTimeEq for Nullifier {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl PartialEq for Nullifier {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison to prevent timing attacks on nullifier lookups
        self.ct_eq(other).into()
    }
}

impl Eq for Nullifier {}

impl std::hash::Hash for Nullifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

/// Compute a V1 nullifier: `Poseidon(spending_key, commitment)`.
///
/// Suitable for single-chain deployments where cross-chain replay is not a concern.
pub fn compute_nullifier_v1(spending_key: pallas::Base, commitment: pallas::Base) -> Nullifier {
    let nf = poseidon_hash_with_domain(DOMAIN_NULLIFIER, spending_key, commitment);
    Nullifier(nf)
}

/// Compute a V2 nullifier with domain separation:
/// `Poseidon(Poseidon(sk, cm), Poseidon(chain_id, app_id))`.
///
/// This prevents cross-chain replay by binding the nullifier to a specific
/// chain and application. Two notes with the same `(sk, cm)` produce
/// different nullifiers on different chains.
pub fn compute_nullifier_v2(
    spending_key: pallas::Base,
    commitment: pallas::Base,
    domain: &DomainSeparator,
) -> Nullifier {
    let (chain_field, app_field) = domain.to_field_elements();
    let inner = poseidon_hash(spending_key, commitment);
    let domain_hash = poseidon_hash(chain_field, app_field);
    let nf = poseidon_hash_with_domain(DOMAIN_NULLIFIER, inner, domain_hash);
    Nullifier(nf)
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[test]
    fn nullifier_v1_deterministic() {
        let sk = pallas::Base::from(0xDEAD_u64);
        let cm = pallas::Base::from(0xBEEF_u64);
        let nf1 = compute_nullifier_v1(sk, cm);
        let nf2 = compute_nullifier_v1(sk, cm);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn nullifier_v1_different_keys() {
        let cm = pallas::Base::from(100u64);
        let nf1 = compute_nullifier_v1(pallas::Base::from(1u64), cm);
        let nf2 = compute_nullifier_v1(pallas::Base::from(2u64), cm);
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn nullifier_v2_cross_chain_isolation() {
        let sk = pallas::Base::from(42u64);
        let cm = pallas::Base::from(99u64);
        let domain_a = DomainSeparator::new(1, 1); // Chain 1
        let domain_b = DomainSeparator::new(2, 1); // Chain 2

        let nf_a = compute_nullifier_v2(sk, cm, &domain_a);
        let nf_b = compute_nullifier_v2(sk, cm, &domain_b);

        assert_ne!(nf_a, nf_b, "same note on different chains must have different nullifiers");
    }

    #[test]
    fn nullifier_v2_app_isolation() {
        let sk = pallas::Base::from(42u64);
        let cm = pallas::Base::from(99u64);
        let domain_a = DomainSeparator::new(1, 1);
        let domain_b = DomainSeparator::new(1, 2);

        let nf_a = compute_nullifier_v2(sk, cm, &domain_a);
        let nf_b = compute_nullifier_v2(sk, cm, &domain_b);

        assert_ne!(nf_a, nf_b, "same note in different apps must have different nullifiers");
    }

    #[test]
    fn nullifier_v1_v2_differ() {
        let sk = pallas::Base::from(42u64);
        let cm = pallas::Base::from(99u64);
        let nf_v1 = compute_nullifier_v1(sk, cm);
        let nf_v2 = compute_nullifier_v2(sk, cm, &DomainSeparator::new(1, 1));
        assert_ne!(nf_v1, nf_v2, "V1 and V2 nullifiers must always differ");
    }

    #[test]
    fn nullifier_constant_time_eq() {
        let sk = pallas::Base::from(42u64);
        let cm = pallas::Base::from(99u64);
        let nf1 = compute_nullifier_v1(sk, cm);
        let nf2 = compute_nullifier_v1(sk, cm);
        // Use the constant-time comparison
        assert!(bool::from(nf1.ct_eq(&nf2)));
    }

    #[test]
    fn nullifier_bytes_roundtrip() {
        let nf = compute_nullifier_v1(pallas::Base::from(1u64), pallas::Base::from(2u64));
        let bytes = nf.to_bytes();
        assert_eq!(bytes.len(), 32);
        let recovered = pallas::Base::from_repr(bytes).unwrap();
        assert_eq!(nf.inner(), recovered);
    }
}
