//! Transaction batch accumulator.
//!
//! Collects pending transactions in a queue and flushes them to the pool
//! once a size or time threshold is reached. This amortizes per-transaction
//! overhead and allows the node to process multiple operations atomically
//! within a single epoch tick.

use escanorr_primitives::Base;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// A pending transaction waiting to be flushed.
#[derive(Debug, Clone)]
pub enum PendingTx {
    Deposit {
        commitment: Base,
        value: u64,
    },
    Transfer {
        nullifiers: Vec<Base>,
        merkle_root: Base,
        output_commitments: Vec<Base>,
    },
    Withdraw {
        nullifier: Base,
        merkle_root: Base,
        exit_value: u64,
        change_commitment: Option<Base>,
    },
}

/// Configuration for the batch accumulator.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of transactions per batch.
    pub max_batch_size: usize,
    /// Maximum time to wait before flushing an incomplete batch.
    pub max_batch_delay: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 32,
            max_batch_delay: Duration::from_secs(5),
        }
    }
}

/// Accumulates pending transactions and signals when a batch is ready.
pub struct BatchAccumulator {
    config: BatchConfig,
    pending: VecDeque<PendingTx>,
    /// Timestamp of the first item in the current batch window.
    window_start: Option<Instant>,
}

impl BatchAccumulator {
    /// Create a new accumulator with the given configuration.
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config,
            pending: VecDeque::new(),
            window_start: None,
        }
    }

    /// Push a transaction into the pending queue.
    /// Returns `true` if the batch is now ready to flush.
    pub fn push(&mut self, tx: PendingTx) -> bool {
        if self.pending.is_empty() {
            self.window_start = Some(Instant::now());
        }
        self.pending.push_back(tx);
        self.is_ready()
    }

    /// Check if the batch is ready to flush (size or time threshold met).
    pub fn is_ready(&self) -> bool {
        if self.pending.len() >= self.config.max_batch_size {
            return true;
        }
        if let Some(start) = self.window_start {
            if start.elapsed() >= self.config.max_batch_delay {
                return true;
            }
        }
        false
    }

    /// Drain all pending transactions for processing. Resets the window.
    pub fn drain(&mut self) -> Vec<PendingTx> {
        self.window_start = None;
        self.pending.drain(..).collect()
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the accumulator is empty.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    #[test]
    fn flush_on_size_threshold() {
        let config = BatchConfig {
            max_batch_size: 3,
            max_batch_delay: Duration::from_secs(60),
        };
        let mut acc = BatchAccumulator::new(config);

        let tx = || PendingTx::Deposit {
            commitment: pallas::Base::random(OsRng),
            value: 100,
        };

        assert!(!acc.push(tx()));
        assert!(!acc.push(tx()));
        assert!(acc.push(tx())); // 3rd triggers ready

        let batch = acc.drain();
        assert_eq!(batch.len(), 3);
        assert!(acc.is_empty());
    }

    #[test]
    fn flush_on_time_threshold() {
        let config = BatchConfig {
            max_batch_size: 100, // won't trigger by size
            max_batch_delay: Duration::from_millis(0), // instant
        };
        let mut acc = BatchAccumulator::new(config);

        let tx = PendingTx::Deposit {
            commitment: pallas::Base::random(OsRng),
            value: 100,
        };
        acc.push(tx);
        // With 0ms delay, should be ready immediately
        assert!(acc.is_ready());
    }

    #[test]
    fn drain_resets_state() {
        let mut acc = BatchAccumulator::new(BatchConfig::default());
        let tx = PendingTx::Deposit {
            commitment: pallas::Base::random(OsRng),
            value: 50,
        };
        acc.push(tx);
        assert_eq!(acc.len(), 1);

        let batch = acc.drain();
        assert_eq!(batch.len(), 1);
        assert!(acc.is_empty());
        assert!(!acc.is_ready());
    }

    #[test]
    fn mixed_transaction_types() {
        let mut acc = BatchAccumulator::new(BatchConfig {
            max_batch_size: 3,
            max_batch_delay: Duration::from_secs(60),
        });

        acc.push(PendingTx::Deposit {
            commitment: pallas::Base::random(OsRng),
            value: 100,
        });
        acc.push(PendingTx::Transfer {
            nullifiers: vec![pallas::Base::random(OsRng)],
            merkle_root: pallas::Base::random(OsRng),
            output_commitments: vec![pallas::Base::random(OsRng)],
        });
        assert!(acc.push(PendingTx::Withdraw {
            nullifier: pallas::Base::random(OsRng),
            merkle_root: pallas::Base::random(OsRng),
            exit_value: 50,
            change_commitment: None,
        }));

        let batch = acc.drain();
        assert_eq!(batch.len(), 3);
        assert!(matches!(batch[0], PendingTx::Deposit { .. }));
        assert!(matches!(batch[1], PendingTx::Transfer { .. }));
        assert!(matches!(batch[2], PendingTx::Withdraw { .. }));
    }
}
