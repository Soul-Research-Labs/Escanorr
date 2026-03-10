//! Fuzz target for Poseidon hash — verify it doesn't panic on arbitrary inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use escanorr_primitives::poseidon::{poseidon_hash, poseidon_hash_with_domain};
use ff::PrimeField;
use pasta_curves::pallas;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    // Interpret the first 64 bytes as two field elements (mod p).
    let mut left_bytes = [0u8; 32];
    let mut right_bytes = [0u8; 32];
    left_bytes.copy_from_slice(&data[..32]);
    right_bytes.copy_from_slice(&data[32..64]);

    let left = pallas::Base::from_repr(left_bytes);
    let right = pallas::Base::from_repr(right_bytes);

    if let (Some(l), Some(r)) = (Option::from(left), Option::from(right)) {
        // Should never panic
        let _h = poseidon_hash(l, r);

        // Domain-separated hash
        let _hd = poseidon_hash_with_domain(b"fuzz-domain", l, r);
    }
});
