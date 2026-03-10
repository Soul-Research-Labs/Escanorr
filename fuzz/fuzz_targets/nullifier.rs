//! Fuzz target for nullifier computation — verify determinism and no panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use escanorr_primitives::{compute_nullifier_v1, compute_nullifier_v2, DomainSeparator};
use ff::PrimeField;
use pasta_curves::pallas;

fuzz_target!(|data: &[u8]| {
    if data.len() < 72 {
        return;
    }

    // Parse: 32 bytes for spending key, 32 bytes for commitment, 8 bytes for chain_id
    let mut sk_bytes = [0u8; 32];
    let mut cm_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&data[..32]);
    cm_bytes.copy_from_slice(&data[32..64]);

    let chain_id = u64::from_le_bytes(data[64..72].try_into().unwrap());

    let sk = Option::from(pallas::Base::from_repr(sk_bytes));
    let cm = Option::from(pallas::Base::from_repr(cm_bytes));

    if let (Some(sk), Some(cm)) = (sk, cm) {
        // V1 nullifier should be deterministic
        let nf1a = compute_nullifier_v1(sk, cm);
        let nf1b = compute_nullifier_v1(sk, cm);
        assert_eq!(nf1a.inner(), nf1b.inner(), "v1 nullifier not deterministic");

        // V2 nullifier should be deterministic
        let domain = DomainSeparator::new(chain_id, 1);
        let nf2a = compute_nullifier_v2(sk, cm, &domain);
        let nf2b = compute_nullifier_v2(sk, cm, &domain);
        assert_eq!(nf2a.inner(), nf2b.inner(), "v2 nullifier not deterministic");

        // V1 and V2 should differ (different domain separation)
        // (unless by astronomically unlikely collision)
    }
});
