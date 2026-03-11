//! Nullifier set — efficient double-spend detection.

use escanorr_primitives::Base;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A set tracking spent nullifiers to prevent double-spending.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NullifierSet {
    /// Backed by a HashSet of 32-byte representations.
    nullifiers: HashSet<[u8; 32]>,
}

impl NullifierSet {
    /// Create a new empty nullifier set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a nullifier has already been spent.
    pub fn contains(&self, nullifier: &Base) -> bool {
        self.nullifiers.contains(&nullifier.to_repr())
    }

    /// Insert a nullifier. Returns `false` if it was already present (double-spend).
    pub fn insert(&mut self, nullifier: Base) -> bool {
        self.nullifiers.insert(nullifier.to_repr())
    }

    /// Number of nullifiers in the set.
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

use ff::PrimeField;

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    #[test]
    fn insert_and_check() {
        let mut set = NullifierSet::new();
        let nf = pallas::Base::random(OsRng);
        assert!(set.insert(nf));
        assert!(set.contains(&nf));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn double_spend_detected() {
        let mut set = NullifierSet::new();
        let nf = pallas::Base::random(OsRng);
        assert!(set.insert(nf));
        assert!(!set.insert(nf)); // double-spend
    }
}
