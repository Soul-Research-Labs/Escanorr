//! Chain adapter trait and message types for cross-chain bridge operations.

use escanorr_primitives::ProofEnvelope;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Known chain identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
    /// Zcash mainnet.
    Zcash,
    /// Horizen (ZEN) — Zcash fork with shared Sapling params.
    Horizen,
    /// Komodo (KMD) — Zcash fork with shared Sapling params.
    Komodo,
    /// Pirate Chain (ARRR) — Zcash fork, mandatory shielded.
    PirateChain,
    /// Ethereum mainnet.
    Ethereum,
    /// Polygon.
    Polygon,
    /// Arbitrum.
    Arbitrum,
    /// Optimism.
    Optimism,
    /// Base.
    Base,
    /// Custom chain by numeric ID.
    Custom(u64),
}

impl ChainId {
    /// Get the numeric chain ID for domain separation.
    pub fn to_u64(&self) -> u64 {
        match self {
            ChainId::Zcash => 1,
            ChainId::Horizen => 2,
            ChainId::Komodo => 3,
            ChainId::PirateChain => 4,
            ChainId::Ethereum => 1_000_001,
            ChainId::Polygon => 1_000_137,
            ChainId::Arbitrum => 1_042_161,
            ChainId::Optimism => 1_000_010,
            ChainId::Base => 1_008_453,
            ChainId::Custom(id) => *id,
        }
    }

    /// Whether this chain is a Zcash fork (shares Sapling circuit params).
    pub fn is_zcash_family(&self) -> bool {
        matches!(
            self,
            ChainId::Zcash | ChainId::Horizen | ChainId::Komodo | ChainId::PirateChain
        )
    }

    /// Whether this chain is EVM-compatible.
    pub fn is_evm(&self) -> bool {
        matches!(
            self,
            ChainId::Ethereum
                | ChainId::Polygon
                | ChainId::Arbitrum
                | ChainId::Optimism
                | ChainId::Base
        )
    }
}

/// A bridge message carrying a proof and metadata across chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeMessage {
    pub src_chain: ChainId,
    pub dest_chain: ChainId,
    /// The nullifier from the source chain.
    #[serde(with = "hex_field")]
    pub src_nullifier: [u8; 32],
    /// The commitment for the destination chain.
    #[serde(with = "hex_field")]
    pub dest_commitment: [u8; 32],
    /// The proof envelope.
    pub envelope: ProofEnvelope,
    /// Bridge fee (in source chain units).
    pub fee: u64,
}

/// Bridge errors.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("unsupported chain: {0:?}")]
    UnsupportedChain(ChainId),
    #[error("same-chain bridge not allowed")]
    SameChain,
    #[error("proof verification failed: {0}")]
    ProofFailed(String),
    #[error("chain communication error: {0}")]
    Transport(String),
    #[error("recursive proof wrapping not yet implemented for EVM")]
    EvmWrappingNotImplemented,
}

/// Trait for chain-specific bridge adapters.
#[async_trait::async_trait]
pub trait ChainAdapter: Send + Sync {
    /// The chain this adapter serves.
    fn chain_id(&self) -> ChainId;

    /// Submit a bridge message to the destination chain.
    async fn submit(&self, msg: &BridgeMessage) -> Result<Vec<u8>, BridgeError>;

    /// Check if a nullifier exists on-chain (for double-spend prevention).
    async fn check_nullifier(&self, nullifier: &[u8; 32]) -> Result<bool, BridgeError>;
}

/// Hex serialization for 32-byte arrays.
mod hex_field {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_id_properties() {
        assert!(ChainId::Zcash.is_zcash_family());
        assert!(ChainId::PirateChain.is_zcash_family());
        assert!(!ChainId::Ethereum.is_zcash_family());

        assert!(ChainId::Ethereum.is_evm());
        assert!(ChainId::Polygon.is_evm());
        assert!(!ChainId::Zcash.is_evm());
    }

    #[test]
    fn bridge_message_serialization() {
        let msg = BridgeMessage {
            src_chain: ChainId::Zcash,
            dest_chain: ChainId::Ethereum,
            src_nullifier: [1u8; 32],
            dest_commitment: [2u8; 32],
            envelope: ProofEnvelope::seal(&[0xde, 0xad]).unwrap(),
            fee: 100,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: BridgeMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.src_chain, ChainId::Zcash);
        assert_eq!(parsed.dest_chain, ChainId::Ethereum);
        assert_eq!(parsed.fee, 100);
    }
}
