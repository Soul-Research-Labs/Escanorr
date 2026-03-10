//! Route handlers for the RPC server.

use axum::{extract::State, http::StatusCode, Json};
use escanorr_primitives::Base;
use ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use escanorr_node::NodeState;

/// Shared application state.
pub type AppState = Arc<RwLock<NodeState>>;

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
}

/// Root response.
#[derive(Serialize)]
pub struct RootResponse {
    pub root: String,
}

fn base_to_hex(b: &Base) -> String {
    hex::encode(b.to_repr())
}

fn hex_to_base(s: &str) -> Result<Base, StatusCode> {
    let bytes = hex::decode(s).map_err(|_| StatusCode::BAD_REQUEST)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Option::from(Base::from_repr(arr)).ok_or(StatusCode::BAD_REQUEST)
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
    let node = state.read().await;
    Json(RootResponse {
        root: base_to_hex(&node.root()),
    })
}

/// GET /info
pub async fn get_info(State(state): State<AppState>) -> Json<InfoResponse> {
    let node = state.read().await;
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
    let mut node = state.write().await;
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

    let mut node = state.write().await;
    node.transfer(nullifiers, merkle_root, output_cms)
        .map_err(|_| StatusCode::CONFLICT)?;

    Ok(StatusCode::OK)
}
