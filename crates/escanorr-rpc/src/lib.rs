//! ESCANORR RPC — Axum HTTP server for the privacy coprocessor.
//!
//! Endpoints:
//! - `POST /deposit` — submit a deposit
//! - `POST /transfer` — submit a transfer
//! - `POST /withdraw` — submit a withdrawal
//! - `GET /root` — get current Merkle root
//! - `GET /info` — get node info
//! - `GET /health` — health check

mod server;
mod routes;

pub use server::run_server;
