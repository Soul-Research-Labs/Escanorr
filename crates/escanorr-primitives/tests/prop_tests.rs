//! Property-based tests for escanorr-primitives using proptest.

use proptest::prelude::*;

use escanorr_primitives::poseidon::{poseidon_hash, poseidon_hash_with_domain};
use escanorr_primitives::{
    compute_nullifier_v1, compute_nullifier_v2, DomainSeparator, ProofEnvelope,
};
use pasta_curves::pallas;

proptest! {
    // ── Poseidon hash properties ────────────────────────────

    #[test]
    fn poseidon_hash_is_deterministic(a in any::<u64>(), b in any::<u64>()) {
        let l = pallas::Base::from(a);
        let r = pallas::Base::from(b);
        prop_assert_eq!(poseidon_hash(l, r), poseidon_hash(l, r));
    }

    #[test]
    fn poseidon_different_inputs_differ(a in 1u64..u64::MAX, b in 1u64..u64::MAX) {
        prop_assume!(a != b);
        let zero = pallas::Base::from(0u64);
        let va = pallas::Base::from(a);
        let vb = pallas::Base::from(b);
        prop_assert_ne!(poseidon_hash(va, zero), poseidon_hash(vb, zero));
    }

    #[test]
    fn poseidon_domain_changes_output(a in any::<u64>(), b in any::<u64>()) {
        let l = pallas::Base::from(a);
        let r = pallas::Base::from(b);
        let h1 = poseidon_hash_with_domain(b"domain-a", l, r);
        let h2 = poseidon_hash_with_domain(b"domain-b", l, r);
        prop_assert_ne!(h1, h2);
    }

    // ── Nullifier properties ────────────────────────────────

    #[test]
    fn nullifier_v1_deterministic(sk in any::<u64>(), cm in any::<u64>()) {
        let sk = pallas::Base::from(sk);
        let cm = pallas::Base::from(cm);
        let nf1 = compute_nullifier_v1(sk, cm);
        let nf2 = compute_nullifier_v1(sk, cm);
        prop_assert_eq!(nf1, nf2);
    }

    #[test]
    fn nullifier_v1_different_keys_differ(sk1 in 1u64..u64::MAX, sk2 in 1u64..u64::MAX, cm in any::<u64>()) {
        prop_assume!(sk1 != sk2);
        let nf1 = compute_nullifier_v1(pallas::Base::from(sk1), pallas::Base::from(cm));
        let nf2 = compute_nullifier_v1(pallas::Base::from(sk2), pallas::Base::from(cm));
        prop_assert_ne!(nf1, nf2);
    }

    #[test]
    fn nullifier_v2_chain_isolation(sk in any::<u64>(), cm in any::<u64>(), chain_a in 1u64..1000, chain_b in 1u64..1000) {
        prop_assume!(chain_a != chain_b);
        let sk = pallas::Base::from(sk);
        let cm = pallas::Base::from(cm);
        let dom_a = DomainSeparator::new(chain_a, 0);
        let dom_b = DomainSeparator::new(chain_b, 0);
        let nf_a = compute_nullifier_v2(sk, cm, &dom_a);
        let nf_b = compute_nullifier_v2(sk, cm, &dom_b);
        prop_assert_ne!(nf_a, nf_b);
    }

    #[test]
    fn nullifier_v1_v2_differ(sk in any::<u64>(), cm in any::<u64>()) {
        let sk = pallas::Base::from(sk);
        let cm = pallas::Base::from(cm);
        let nf1 = compute_nullifier_v1(sk, cm);
        let dom = DomainSeparator::new(1, 0);
        let nf2 = compute_nullifier_v2(sk, cm, &dom);
        prop_assert_ne!(nf1, nf2);
    }

    // ── Envelope properties ─────────────────────────────────

    #[test]
    fn envelope_seal_open_roundtrip(payload in proptest::collection::vec(any::<u8>(), 0..32000)) {
        let envelope = ProofEnvelope::seal(&payload).unwrap();
        let recovered = envelope.open().unwrap();
        prop_assert_eq!(payload, recovered);
    }

    #[test]
    fn envelope_always_fixed_size(payload in proptest::collection::vec(any::<u8>(), 0..32000)) {
        let envelope = ProofEnvelope::seal(&payload).unwrap();
        prop_assert_eq!(envelope.as_bytes().len(), 32768);
    }

    #[test]
    fn envelope_rejects_oversized(payload in proptest::collection::vec(any::<u8>(), 32765..40000)) {
        let result = ProofEnvelope::seal(&payload);
        prop_assert!(result.is_err());
    }
}
