//! ESCANORR Note — note model, spending/viewing keys, nullifiers,
//! stealth addresses, and ChaCha20-Poly1305 note encryption.
//!
//! This crate defines the core data structures for private notes,
//! the key hierarchy (spending key → viewing key → public key),
//! stealth address generation, and encrypted note delivery.

pub mod encryption;
pub mod keys;
pub mod note;
pub mod stealth;

pub use keys::{SpendingKey, ViewingKey, FullViewingKey};
pub use note::{Note, NoteCommitment};
pub use stealth::{StealthAddress, StealthMeta};
