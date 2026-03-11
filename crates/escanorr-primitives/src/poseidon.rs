//! Poseidon hash function over the Pallas base field.
//!
//! Uses the P128Pow5T3 configuration (width=3, rate=2) matching
//! Zcash's Orchard protocol parameters. The native (off-circuit)
//! computation uses `halo2_gadgets::poseidon::primitives` so that
//! the output is **identical** to the in-circuit Poseidon gadget.

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};
use pasta_curves::pallas;

/// Domain separation tag for note commitments.
pub const DOMAIN_NOTE_COMMITMENT: &[u8] = b"escanorr:note-cm";
/// Domain separation tag for nullifier derivation.
pub const DOMAIN_NULLIFIER: &[u8] = b"escanorr:nf";
/// Domain separation tag for Merkle tree hashing.
pub const DOMAIN_MERKLE: &[u8] = b"escanorr:merkle";

/// Compute Poseidon hash of two Pallas base field elements.
///
/// Applies the real P128Pow5T3 permutation (width=3, rate=2) via
/// `halo2_gadgets::poseidon::primitives::Hash`. This matches the
/// in-circuit Poseidon gadget bit-for-bit.
pub fn poseidon_hash(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([left, right])
}

/// Compute Poseidon hash with a domain separation tag.
///
/// The domain tag is converted to a field element and mixed into the hash:
///   H_domain(l, r) = Poseidon(domain_element, Poseidon(l, r))
pub fn poseidon_hash_with_domain(
    domain: &[u8],
    left: pallas::Base,
    right: pallas::Base,
) -> pallas::Base {
    let domain_element = domain_to_field(domain);
    let inner = poseidon_hash(left, right);
    poseidon_hash(domain_element, inner)
}

/// Convert a domain separation tag (byte string) to a Pallas base field element.
fn domain_to_field(domain: &[u8]) -> pallas::Base {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(domain);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    // Clear the top two bits so the value is < 2^254 < p (Pallas modulus)
    bytes[31] &= 0x3f;
    pallas::Base::from_repr(bytes).expect("domain hash with cleared top bits must be valid field element")
}

/// Hash a single field element (used for leaf hashing in Merkle trees).
pub fn poseidon_hash_single(value: pallas::Base) -> pallas::Base {
    poseidon_hash(value, pallas::Base::zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use pasta_curves::pallas;

    #[test]
    fn poseidon_hash_deterministic() {
        let a = pallas::Base::from(42u64);
        let b = pallas::Base::from(99u64);
        let h1 = poseidon_hash(a, b);
        let h2 = poseidon_hash(a, b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon_hash_not_commutative() {
        let a = pallas::Base::from(1u64);
        let b = pallas::Base::from(2u64);
        let h1 = poseidon_hash(a, b);
        let h2 = poseidon_hash(b, a);
        // Real P128Pow5T3 Poseidon is NOT commutative — this is critical
        // for security (e.g. Merkle left vs right children must differ).
        assert_ne!(h1, h2, "Poseidon must not be commutative");
    }

    #[test]
    fn poseidon_hash_with_domain_differs() {
        let a = pallas::Base::from(10u64);
        let b = pallas::Base::from(20u64);
        let h1 = poseidon_hash_with_domain(DOMAIN_NOTE_COMMITMENT, a, b);
        let h2 = poseidon_hash_with_domain(DOMAIN_NULLIFIER, a, b);
        assert_ne!(h1, h2, "different domains must produce different hashes");
    }

    #[test]
    fn poseidon_hash_zero_inputs() {
        let z = pallas::Base::zero();
        let h = poseidon_hash(z, z);
        // Should produce a non-zero result
        assert_ne!(h, pallas::Base::zero());
    }

    #[test]
    fn domain_to_field_deterministic() {
        let f1 = domain_to_field(b"test");
        let f2 = domain_to_field(b"test");
        assert_eq!(f1, f2);
    }

    #[test]
    fn domain_to_field_different_tags() {
        let f1 = domain_to_field(b"tag-a");
        let f2 = domain_to_field(b"tag-b");
        assert_ne!(f1, f2);
    }
}
