//! Route handlers for the RPC server.

use axum::{extract::{Path, State}, http::StatusCode, Json};
use escanorr_primitives::{Base, ProofEnvelope};
use escanorr_verifier::{VerifierParams, verify_transfer, verify_withdraw, verify_bridge};
use ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use escanorr_node::NodeState;

/// Shared application state: mutable node + read-only verifier keys.
pub struct SharedState {
    pub node: RwLock<NodeState>,
    pub verifier: VerifierParams,
}

pub type AppState = Arc<SharedState>;

/// Health check response.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

/// Node info response.
#[derive(Serialize)]
pub struct InfoResponse {
    pub epoch: u64,
    pub tree_size: u64,
    pub root: String,
}

/// Deposit request body.
#[derive(Deserialize)]
pub struct DepositBody {
    pub commitment: String,
    pub value: u64,
}

/// Deposit response.
#[derive(Serialize)]
pub struct DepositResponse {
    pub index: u64,
    pub root: String,
}

/// Transfer request body.
#[derive(Deserialize)]
pub struct TransferBody {
    pub nullifiers: Vec<String>,
    pub merkle_root: String,
    pub output_commitments: Vec<String>,
    pub proof: String,
}

/// Root response.
#[derive(Serialize)]
pub struct RootResponse {
    pub root: String,
}

/// Withdraw request body.
#[derive(Deserialize)]
pub struct WithdrawBody {
    pub nullifier: String,
    pub merkle_root: String,
    pub exit_value: u64,
    pub change_commitment: Option<String>,
    pub proof: String,
}

/// Withdraw response.
#[derive(Serialize)]
pub struct WithdrawResponse {
    pub nullifier: String,
    pub exit_value: u64,
}

/// Nullifier check response.
#[derive(Serialize)]
pub struct NullifierResponse {
    pub spent: bool,
}

/// Bridge lock request body.
#[derive(Deserialize)]
pub struct BridgeLockBody {
    pub nullifier: String,
    pub merkle_root: String,
    pub dest_commitment: String,
    pub source_chain_id: u64,
    pub destination_chain_id: u64,
    #[allow(dead_code)] // Informational; value conservation enforced by the proof
    pub amount: u64,
    pub proof: String,
}

/// Bridge lock response.
#[derive(Serialize)]
pub struct BridgeLockResponse {
    pub nullifier: String,
    pub status: &'static str,
}

/// Bridge status response.
#[derive(Serialize)]
pub struct BridgeStatusResponse {
    pub nullifier: String,
    pub status: &'static str,
}

fn base_to_hex(b: &Base) -> String {
    hex::encode(b.to_repr())
}

fn hex_to_base(s: &str) -> Result<Base, StatusCode> {
    // Validate hex string length: must be exactly 64 hex chars (32 bytes)
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = hex::decode(s).map_err(|_| StatusCode::BAD_REQUEST)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Option::from(Base::from_repr(arr)).ok_or(StatusCode::BAD_REQUEST)
}

fn hex_to_envelope(s: &str) -> Result<ProofEnvelope, StatusCode> {
    let bytes = hex::decode(s).map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() != escanorr_primitives::envelope::ENVELOPE_SIZE {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut arr = [0u8; escanorr_primitives::envelope::ENVELOPE_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(ProofEnvelope::from_bytes(arr))
}

/// GET /health
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// GET /root
pub async fn get_root(State(state): State<AppState>) -> Json<RootResponse> {
    let node = state.node.read().await;
    Json(RootResponse {
        root: base_to_hex(&node.root()),
    })
}

/// GET /info
pub async fn get_info(State(state): State<AppState>) -> Json<InfoResponse> {
    let node = state.node.read().await;
    Json(InfoResponse {
        epoch: node.epoch(),
        tree_size: node.pool().tree_size(),
        root: base_to_hex(&node.root()),
    })
}

/// POST /deposit
pub async fn post_deposit(
    State(state): State<AppState>,
    Json(body): Json<DepositBody>,
) -> Result<Json<DepositResponse>, StatusCode> {
    let commitment = hex_to_base(&body.commitment)?;
    let mut node = state.node.write().await;
    let index = node
        .deposit(commitment, body.value)
        .map_err(|_| StatusCode::CONFLICT)?;
    let root = base_to_hex(&node.root());
    Ok(Json(DepositResponse { index, root }))
}

/// POST /transfer
pub async fn post_transfer(
    State(state): State<AppState>,
    Json(body): Json<TransferBody>,
) -> Result<StatusCode, StatusCode> {
    let merkle_root = hex_to_base(&body.merkle_root)?;
    let nullifiers: Result<Vec<Base>, _> = body.nullifiers.iter().map(|s| hex_to_base(s)).collect();
    let nullifiers = nullifiers?;
    let output_cms: Result<Vec<Base>, _> = body
        .output_commitments
        .iter()
        .map(|s| hex_to_base(s))
        .collect();
    let output_cms = output_cms?;
    let envelope = hex_to_envelope(&body.proof)?;

    // Public inputs: [root, nf_0, nf_1, out_cm_0, out_cm_1]
    let mut pi = vec![merkle_root];
    pi.extend_from_slice(&nullifiers);
    pi.extend_from_slice(&output_cms);
    verify_transfer(&state.verifier, &envelope, &[&pi])
        .map_err(|_| StatusCode::FORBIDDEN)?;

    let mut node = state.node.write().await;
    node.transfer(nullifiers, merkle_root, output_cms)
        .map_err(|_| StatusCode::CONFLICT)?;

    Ok(StatusCode::OK)
}

/// POST /withdraw
pub async fn post_withdraw(
    State(state): State<AppState>,
    Json(body): Json<WithdrawBody>,
) -> Result<Json<WithdrawResponse>, StatusCode> {
    let nullifier = hex_to_base(&body.nullifier)?;
    let merkle_root = hex_to_base(&body.merkle_root)?;
    let change_commitment = body
        .change_commitment
        .as_deref()
        .map(hex_to_base)
        .transpose()?;
    let envelope = hex_to_envelope(&body.proof)?;

    // Public inputs: [root, nullifier, change_cm, exit_value]
    // If no change commitment, use the zero element
    let chg_cm = change_commitment.unwrap_or(Base::from(0u64));
    let pi = vec![
        merkle_root,
        nullifier,
        chg_cm,
        Base::from(body.exit_value),
    ];
    verify_withdraw(&state.verifier, &envelope, &[&pi])
        .map_err(|_| StatusCode::FORBIDDEN)?;

    let mut node = state.node.write().await;
    node.withdraw(nullifier, merkle_root, body.exit_value, change_commitment)
        .map_err(|_| StatusCode::CONFLICT)?;

    Ok(Json(WithdrawResponse {
        nullifier: body.nullifier,
        exit_value: body.exit_value,
    }))
}

/// GET /nullifier/:nf
pub async fn get_nullifier(
    State(state): State<AppState>,
    Path(nf): Path<String>,
) -> Result<Json<NullifierResponse>, StatusCode> {
    let nullifier = hex_to_base(&nf)?;
    let node = state.node.read().await;
    let spent = node.pool().nullifier_set().contains(&nullifier);
    Ok(Json(NullifierResponse { spent }))
}

/// POST /bridge/lock
pub async fn post_bridge_lock(
    State(state): State<AppState>,
    Json(body): Json<BridgeLockBody>,
) -> Result<Json<BridgeLockResponse>, StatusCode> {
    let nullifier = hex_to_base(&body.nullifier)?;
    let merkle_root = hex_to_base(&body.merkle_root)?;
    let dest_cm = hex_to_base(&body.dest_commitment)?;
    let envelope = hex_to_envelope(&body.proof)?;

    // Public inputs: [src_root, src_nullifier, dest_cm, src_chain_id, dest_chain_id]
    let pi = vec![
        merkle_root,
        nullifier,
        dest_cm,
        Base::from(body.source_chain_id),
        Base::from(body.destination_chain_id),
    ];
    verify_bridge(&state.verifier, &envelope, &[&pi])
        .map_err(|_| StatusCode::FORBIDDEN)?;

    // Nullify the source note (withdraw with 0 exit)
    let mut node = state.node.write().await;
    node.withdraw(nullifier, merkle_root, 0, None)
        .map_err(|_| StatusCode::CONFLICT)?;

    Ok(Json(BridgeLockResponse {
        nullifier: body.nullifier,
        status: "pending",
    }))
}

/// GET /bridge/status/:nf
pub async fn get_bridge_status(
    State(state): State<AppState>,
    Path(nf): Path<String>,
) -> Result<Json<BridgeStatusResponse>, StatusCode> {
    let nullifier = hex_to_base(&nf)?;
    let node = state.node.read().await;
    let spent = node.pool().nullifier_set().contains(&nullifier);
    let status = if spent { "confirmed" } else { "pending" };
    Ok(Json(BridgeStatusResponse {
        nullifier: nf,
        status,
    }))
}
