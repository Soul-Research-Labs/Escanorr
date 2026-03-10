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

// ─────────────────────────────────────────────────────────────────────────────
// Concrete adapters
// ─────────────────────────────────────────────────────────────────────────────

/// Adapter for Zcash mainnet via lightwalletd gRPC.
pub struct ZcashAdapter {
    endpoint: String,
    client: reqwest::Client,
}

impl ZcashAdapter {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for ZcashAdapter {
    fn chain_id(&self) -> ChainId {
        ChainId::Zcash
    }

    async fn submit(&self, msg: &BridgeMessage) -> Result<Vec<u8>, BridgeError> {
        if msg.dest_chain != ChainId::Zcash && msg.src_chain != ChainId::Zcash {
            return Err(BridgeError::UnsupportedChain(msg.dest_chain));
        }
        let url = format!("{}/bridge/submit", self.endpoint);
        let resp = self
            .client
            .post(&url)
            .json(msg)
            .send()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    async fn check_nullifier(&self, nullifier: &[u8; 32]) -> Result<bool, BridgeError> {
        let url = format!("{}/nullifier/{}", self.endpoint, hex::encode(nullifier));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        Ok(body.get("spent").and_then(|v| v.as_bool()).unwrap_or(false))
    }
}

/// Adapter for Zcash forks (Horizen, Komodo, Pirate Chain) that share Sapling parameters.
pub struct ZcashForkAdapter {
    chain: ChainId,
    endpoint: String,
    client: reqwest::Client,
}

impl ZcashForkAdapter {
    pub fn new(chain: ChainId, endpoint: impl Into<String>) -> Result<Self, BridgeError> {
        if !chain.is_zcash_family() || chain == ChainId::Zcash {
            return Err(BridgeError::UnsupportedChain(chain));
        }
        Ok(Self {
            chain,
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
        })
    }
}

#[async_trait::async_trait]
impl ChainAdapter for ZcashForkAdapter {
    fn chain_id(&self) -> ChainId {
        self.chain
    }

    async fn submit(&self, msg: &BridgeMessage) -> Result<Vec<u8>, BridgeError> {
        let url = format!("{}/bridge/submit", self.endpoint);
        let resp = self
            .client
            .post(&url)
            .json(msg)
            .send()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    async fn check_nullifier(&self, nullifier: &[u8; 32]) -> Result<bool, BridgeError> {
        let url = format!("{}/nullifier/{}", self.endpoint, hex::encode(nullifier));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;
        Ok(body.get("spent").and_then(|v| v.as_bool()).unwrap_or(false))
    }
}

/// Adapter for EVM-compatible chains (Ethereum, Polygon, Arbitrum, etc.).
///
/// Interacts with the on-chain `BridgeVault` and `NullifierRegistry` contracts
/// via JSON-RPC at the configured endpoint.
pub struct EvmAdapter {
    chain: ChainId,
    rpc_url: String,
    #[allow(dead_code)] // Used once recursive proof wrapping is implemented
    bridge_vault: String,
    nullifier_registry: String,
    client: reqwest::Client,
}

impl EvmAdapter {
    pub fn new(
        chain: ChainId,
        rpc_url: impl Into<String>,
        bridge_vault: impl Into<String>,
        nullifier_registry: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        if !chain.is_evm() {
            return Err(BridgeError::UnsupportedChain(chain));
        }
        Ok(Self {
            chain,
            rpc_url: rpc_url.into(),
            bridge_vault: bridge_vault.into(),
            nullifier_registry: nullifier_registry.into(),
            client: reqwest::Client::new(),
        })
    }

    /// Build an `eth_call` JSON-RPC request body.
    fn eth_call_body(&self, to: &str, data: &str) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": to, "data": data}, "latest"],
            "id": 1
        })
    }
}

#[async_trait::async_trait]
impl ChainAdapter for EvmAdapter {
    fn chain_id(&self) -> ChainId {
        self.chain
    }

    async fn submit(&self, msg: &BridgeMessage) -> Result<Vec<u8>, BridgeError> {
        if !msg.dest_chain.is_evm() && !msg.src_chain.is_evm() {
            return Err(BridgeError::UnsupportedChain(msg.dest_chain));
        }
        // EVM bridge submission requires recursive proof wrapping (future work).
        // For now, we serialize the message and post it to a relay endpoint.
        Err(BridgeError::EvmWrappingNotImplemented)
    }

    async fn check_nullifier(&self, nullifier: &[u8; 32]) -> Result<bool, BridgeError> {
        // NullifierRegistry.isSpent(bytes32) — selector 0x9b4bae3e
        // function isSpent(bytes32 nullifier) external view returns (bool)
        let selector = "0x9b4bae3e";
        let data = format!("{}{}", selector, hex::encode(nullifier));
        let body = self.eth_call_body(&self.nullifier_registry, &data);

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::Transport(e.to_string()))?;

        let result = json
            .get("result")
            .and_then(|v| v.as_str())
            .unwrap_or("0x");

        // Non-zero result means true
        let is_spent = result.len() > 2
            && result
                .trim_start_matches("0x")
                .chars()
                .any(|c| c != '0');
        Ok(is_spent)
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

    #[test]
    fn zcash_adapter_creation() {
        let adapter = ZcashAdapter::new("http://localhost:9067");
        assert_eq!(adapter.chain_id(), ChainId::Zcash);
    }

    #[test]
    fn zcash_fork_adapter_creation() {
        let adapter = ZcashForkAdapter::new(ChainId::Horizen, "http://localhost:9068").unwrap();
        assert_eq!(adapter.chain_id(), ChainId::Horizen);

        let adapter = ZcashForkAdapter::new(ChainId::PirateChain, "http://localhost:9069").unwrap();
        assert_eq!(adapter.chain_id(), ChainId::PirateChain);
    }

    #[test]
    fn zcash_fork_adapter_rejects_mainnet() {
        let result = ZcashForkAdapter::new(ChainId::Zcash, "http://localhost:9067");
        assert!(result.is_err());
    }

    #[test]
    fn zcash_fork_adapter_rejects_evm() {
        let result = ZcashForkAdapter::new(ChainId::Ethereum, "http://localhost:8545");
        assert!(result.is_err());
    }

    #[test]
    fn evm_adapter_creation() {
        let adapter = EvmAdapter::new(
            ChainId::Ethereum,
            "http://localhost:8545",
            "0x1234567890abcdef1234567890abcdef12345678",
            "0xabcdef1234567890abcdef1234567890abcdef12",
        )
        .unwrap();
        assert_eq!(adapter.chain_id(), ChainId::Ethereum);
    }

    #[test]
    fn evm_adapter_rejects_zcash_family() {
        let result = EvmAdapter::new(
            ChainId::Zcash,
            "http://localhost:8545",
            "0x1234",
            "0x5678",
        );
        assert!(result.is_err());
    }
}
