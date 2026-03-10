//! ESCANORR RPC — Axum HTTP server for the privacy coprocessor.
//!
//! Endpoints:
//! - `POST /deposit` — submit a deposit
//! - `POST /transfer` — submit a transfer
//! - `POST /withdraw` — submit a withdrawal
//! - `GET /root` — get current Merkle root
//! - `GET /info` — get node info
//! - `GET /health` — health check
//! - `GET /nullifier/:nf` — check if nullifier is spent
//! - `POST /bridge/lock` — lock assets for cross-chain bridge
//! - `GET /bridge/status/:nf` — check bridge operation status

mod server;
mod routes;

pub use server::run_server;
