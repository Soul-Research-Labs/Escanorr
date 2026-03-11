//! Sled-backed persistent storage for node state.
//!
//! Stores the entire [`NodeState`] as a bincode-serialized snapshot.
//! Writes are crash-safe via sled's log-structured merge approach.

use crate::NodeState;
use std::path::Path;

/// Persistent storage backed by sled.
pub struct NodeStorage {
    db: sled::Db,
}

/// Key under which the state snapshot is stored.
const STATE_KEY: &[u8] = b"node_state";

/// Errors from the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("serialization error: {0}")]
    Encode(#[from] bincode::Error),
}

impl NodeStorage {
    /// Open (or create) a sled database at the given directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Persist the full node state.
    pub fn save(&self, state: &NodeState) -> Result<(), StorageError> {
        let bytes = bincode::serialize(state)?;
        self.db.insert(STATE_KEY, bytes)?;
        self.db.flush()?;
        Ok(())
    }

    /// Load the node state from disk. Returns `None` if no snapshot exists.
    pub fn load(&self) -> Result<Option<NodeState>, StorageError> {
        match self.db.get(STATE_KEY)? {
            Some(bytes) => {
                let state: NodeState = bincode::deserialize(&bytes)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    #[test]
    fn round_trip_empty() {
        let dir = tempfile::tempdir().unwrap();
        let storage = NodeStorage::open(dir.path()).unwrap();

        // No state yet
        assert!(storage.load().unwrap().is_none());

        // Save empty state
        let state = NodeState::new();
        storage.save(&state).unwrap();

        let loaded = storage.load().unwrap().unwrap();
        assert_eq!(loaded.epoch(), 0);
        assert!(loaded.history().is_empty());
    }

    #[test]
    fn round_trip_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let storage = NodeStorage::open(dir.path()).unwrap();

        let mut state = NodeState::new();
        let cm = pallas::Base::random(OsRng);
        state.deposit(cm, 1000).unwrap();
        state.advance_epoch();

        let root = state.root();
        storage.save(&state).unwrap();

        let loaded = storage.load().unwrap().unwrap();
        assert_eq!(loaded.epoch(), 1);
        assert_eq!(loaded.root(), root);
        assert_eq!(loaded.history().len(), 1);
    }

    #[test]
    fn reopen_persists() {
        let dir = tempfile::tempdir().unwrap();

        {
            let storage = NodeStorage::open(dir.path()).unwrap();
            let mut state = NodeState::new();
            let cm = pallas::Base::random(OsRng);
            state.deposit(cm, 500).unwrap();
            storage.save(&state).unwrap();
        }

        // Reopen from same path
        let storage = NodeStorage::open(dir.path()).unwrap();
        let loaded = storage.load().unwrap().unwrap();
        assert_eq!(loaded.pool().tree_size(), 1);
        assert_eq!(loaded.pool().total_deposited, 500);
    }
}
