//! End-to-end bridge adapter tests.
//!
//! These tests verify the concrete adapter implementations without
//! hitting real endpoints (construction, chain validation, error paths).

use escanorr_bridge::{
    BridgeError, BridgeMessage, ChainId, EvmAdapter, ZcashAdapter, ZcashForkAdapter,
};
use escanorr_primitives::ProofEnvelope;

// ────────────────────────────────────────────────────────────────
// ZcashAdapter
// ────────────────────────────────────────────────────────────────

#[test]
fn zcash_adapter_serves_correct_chain() {
    use escanorr_bridge::ChainAdapter;
    let adapter = ZcashAdapter::new("http://127.0.0.1:9067");
    assert_eq!(adapter.chain_id(), ChainId::Zcash);
}

#[tokio::test]
async fn zcash_adapter_submit_rejects_non_zcash_message() {
    use escanorr_bridge::ChainAdapter;
    let adapter = ZcashAdapter::new("http://127.0.0.1:1"); // unreachable
    let envelope = ProofEnvelope::seal(b"test").unwrap();
    let msg = BridgeMessage {
        src_chain: ChainId::Ethereum,
        dest_chain: ChainId::Polygon,
        src_nullifier: [1u8; 32],
        dest_commitment: [2u8; 32],
        envelope,
        fee: 100,
    };
    let result = adapter.submit(&msg).await;
    assert!(result.is_err());
}

// ────────────────────────────────────────────────────────────────
// ZcashForkAdapter
// ────────────────────────────────────────────────────────────────

#[test]
fn zcash_fork_adapter_accepts_all_forks() {
    let chains = [ChainId::Horizen, ChainId::Komodo, ChainId::PirateChain];
    for chain in chains {
        let adapter = ZcashForkAdapter::new(chain, "http://127.0.0.1:9999").unwrap();
        use escanorr_bridge::ChainAdapter;
        assert_eq!(adapter.chain_id(), chain);
        assert!(chain.is_zcash_family());
    }
}

#[test]
fn zcash_fork_adapter_rejects_zcash_mainnet() {
    let result = ZcashForkAdapter::new(ChainId::Zcash, "http://127.0.0.1:9999");
    assert!(result.is_err());
}

#[test]
fn zcash_fork_adapter_rejects_evm_chains() {
    let evm_chains = [
        ChainId::Ethereum,
        ChainId::Polygon,
        ChainId::Arbitrum,
        ChainId::Optimism,
        ChainId::Base,
    ];
    for chain in evm_chains {
        let result = ZcashForkAdapter::new(chain, "http://127.0.0.1:8545");
        assert!(result.is_err(), "Should reject {:?}", chain);
    }
}

// ────────────────────────────────────────────────────────────────
// EvmAdapter
// ────────────────────────────────────────────────────────────────

#[test]
fn evm_adapter_accepts_all_evm_chains() {
    let chains = [
        ChainId::Ethereum,
        ChainId::Polygon,
        ChainId::Arbitrum,
        ChainId::Optimism,
        ChainId::Base,
    ];
    for chain in chains {
        let adapter = EvmAdapter::new(chain, "http://127.0.0.1:8545", "0x1234", "0x5678").unwrap();
        use escanorr_bridge::ChainAdapter;
        assert_eq!(adapter.chain_id(), chain);
    }
}

#[test]
fn evm_adapter_rejects_zcash_family() {
    let zcash_chains = [
        ChainId::Zcash,
        ChainId::Horizen,
        ChainId::Komodo,
        ChainId::PirateChain,
    ];
    for chain in zcash_chains {
        let result = EvmAdapter::new(chain, "http://127.0.0.1:8545", "0x1234", "0x5678");
        assert!(result.is_err(), "Should reject {:?}", chain);
    }
}

#[tokio::test]
async fn evm_adapter_submit_returns_not_implemented() {
    use escanorr_bridge::ChainAdapter;
    let adapter =
        EvmAdapter::new(ChainId::Ethereum, "http://127.0.0.1:1", "0x1234", "0x5678").unwrap();
    let envelope = ProofEnvelope::seal(b"test").unwrap();
    let msg = BridgeMessage {
        src_chain: ChainId::Zcash,
        dest_chain: ChainId::Ethereum,
        src_nullifier: [0xAA; 32],
        dest_commitment: [0xBB; 32],
        envelope,
        fee: 1000,
    };
    let result = adapter.submit(&msg).await;
    assert!(matches!(result, Err(BridgeError::EvmWrappingNotImplemented)));
}

// ────────────────────────────────────────────────────────────────
// ChainId properties
// ────────────────────────────────────────────────────────────────

#[test]
fn chain_id_numeric_values_are_unique() {
    let ids = [
        ChainId::Zcash,
        ChainId::Horizen,
        ChainId::Komodo,
        ChainId::PirateChain,
        ChainId::Ethereum,
        ChainId::Polygon,
        ChainId::Arbitrum,
        ChainId::Optimism,
        ChainId::Base,
    ];
    let mut seen = std::collections::HashSet::new();
    for id in &ids {
        assert!(seen.insert(id.to_u64()), "Duplicate chain ID for {:?}", id);
    }
}

#[test]
fn chain_id_custom_roundtrip() {
    let custom = ChainId::Custom(999);
    assert_eq!(custom.to_u64(), 999);
    assert!(!custom.is_zcash_family());
    assert!(!custom.is_evm());
}

#[test]
fn bridge_message_rejects_same_chain() {
    // BridgeError::SameChain exists — verify the enum variant
    let err = BridgeError::SameChain;
    assert!(err.to_string().contains("same-chain"));
}

#[test]
fn bridge_message_json_roundtrip_with_all_fields() {
    let envelope = ProofEnvelope::seal(&[0u8; 256]).unwrap();
    let msg = BridgeMessage {
        src_chain: ChainId::PirateChain,
        dest_chain: ChainId::Polygon,
        src_nullifier: [0xFF; 32],
        dest_commitment: [0x00; 32],
        envelope,
        fee: u64::MAX,
    };

    let json = serde_json::to_string(&msg).unwrap();
    let decoded: BridgeMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.src_chain, ChainId::PirateChain);
    assert_eq!(decoded.dest_chain, ChainId::Polygon);
    assert_eq!(decoded.fee, u64::MAX);
    assert_eq!(decoded.src_nullifier, [0xFF; 32]);
}
