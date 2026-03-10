//! ESCANORR Primitives — field types, Poseidon hash, Pedersen commitment,
//! domain-separated nullifiers, and fixed-size proof envelopes.
//!
//! This crate provides the foundational cryptographic building blocks used
//! throughout the Escanorr privacy coprocessor. It wraps the Pallas/Vesta
//! curve cycle from the Zcash ecosystem with domain-specific abstractions.

pub mod envelope;
pub mod nullifier;
pub mod poseidon;
pub mod types;

pub use envelope::ProofEnvelope;
pub use nullifier::{compute_nullifier_v1, compute_nullifier_v2, DomainSeparator};
pub use poseidon::poseidon_hash;
pub use types::{Base, Scalar, EscanorrError};
