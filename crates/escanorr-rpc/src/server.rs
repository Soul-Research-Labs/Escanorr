//! Axum server setup and configuration.

use crate::routes::{self, AppState};
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use escanorr_node::NodeState;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::info;

/// Maximum request body size: 64 KiB (prevents oversized payloads).
const MAX_BODY_SIZE: usize = 64 * 1024;

/// Run the ESCANORR RPC server on the given address.
pub async fn run_server(addr: SocketAddr) -> std::io::Result<()> {
    let state: AppState = Arc::new(RwLock::new(NodeState::new()));

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/root", get(routes::get_root))
        .route("/info", get(routes::get_info))
        .route("/deposit", post(routes::post_deposit))
        .route("/transfer", post(routes::post_transfer))
        .route("/withdraw", post(routes::post_withdraw))
        .route("/nullifier/{nf}", get(routes::get_nullifier))
        .route("/bridge/lock", post(routes::post_bridge_lock))
        .route("/bridge/status/{nf}", get(routes::get_bridge_status))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("ESCANORR RPC server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
