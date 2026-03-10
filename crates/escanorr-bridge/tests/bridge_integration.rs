//! Integration test for cross-chain bridge data structures.

use escanorr_bridge::{BridgeMessage, ChainId};
use escanorr_primitives::{
    compute_nullifier_v2,
    DomainSeparator,
    ProofEnvelope,
};
use pasta_curves::pallas;

/// Bridge message serialization roundtrip.
#[test]
fn bridge_message_serde_roundtrip() {
    let envelope = ProofEnvelope::seal(b"test proof payload").expect("seal");
    let msg = BridgeMessage {
        src_chain: ChainId::Zcash,
        dest_chain: ChainId::Ethereum,
        src_nullifier: [0xAB; 32],
        dest_commitment: [0xCD; 32],
        envelope,
        fee: 500_000,
    };

    let json = serde_json::to_string(&msg).expect("serialize");
    let decoded: BridgeMessage = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(msg.src_chain, decoded.src_chain);
    assert_eq!(msg.dest_chain, decoded.dest_chain);
    assert_eq!(msg.src_nullifier, decoded.src_nullifier);
    assert_eq!(msg.dest_commitment, decoded.dest_commitment);
    assert_eq!(msg.fee, decoded.fee);
}

/// ChainId classification — Zcash family vs EVM.
#[test]
fn chain_id_classification() {
    assert!(ChainId::Zcash.is_zcash_family());
    assert!(ChainId::Horizen.is_zcash_family());
    assert!(ChainId::Komodo.is_zcash_family());
    assert!(ChainId::PirateChain.is_zcash_family());

    assert!(ChainId::Ethereum.is_evm());
    assert!(ChainId::Polygon.is_evm());
    assert!(ChainId::Arbitrum.is_evm());
    assert!(ChainId::Optimism.is_evm());
    assert!(ChainId::Base.is_evm());

    // Cross-check
    assert!(!ChainId::Zcash.is_evm());
    assert!(!ChainId::Ethereum.is_zcash_family());
}

/// V2 nullifiers with different chain_ids produce different values.
#[test]
fn cross_chain_nullifier_isolation() {
    let sk = pallas::Base::from(12345u64);
    let commitment = pallas::Base::from(67890u64);

    let domain_zcash = DomainSeparator::new(ChainId::Zcash.to_u64(), 1);
    let domain_eth = DomainSeparator::new(ChainId::Ethereum.to_u64(), 1);

    let nf_zcash = compute_nullifier_v2(sk, commitment, &domain_zcash);
    let nf_eth = compute_nullifier_v2(sk, commitment, &domain_eth);

    // Same key + same commitment on different chains → different nullifiers
    assert_ne!(nf_zcash.inner(), nf_eth.inner());
}

/// V2 nullifier is deterministic.
#[test]
fn cross_chain_nullifier_determinism() {
    let sk = pallas::Base::from(111u64);
    let commitment = pallas::Base::from(222u64);
    let domain = DomainSeparator::new(42, 1);

    let nf1 = compute_nullifier_v2(sk, commitment, &domain);
    let nf2 = compute_nullifier_v2(sk, commitment, &domain);

    assert_eq!(nf1.inner(), nf2.inner());
}
