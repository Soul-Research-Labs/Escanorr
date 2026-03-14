//! Retry wrapper for chain adapters.
//!
//! Wraps any `ChainAdapter` to automatically retry transient failures
//! with exponential backoff and a configurable timeout.

use crate::adapter::{BridgeError, BridgeMessage, ChainAdapter, ChainId};
use std::time::Duration;
use tracing::warn;

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of attempts (including the initial one).
    pub max_attempts: u32,
    /// Initial backoff delay.
    pub initial_backoff: Duration,
    /// Maximum backoff delay.
    pub max_backoff: Duration,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(10),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Returns `true` if the error is transient and should be retried.
fn is_retryable(err: &BridgeError) -> bool {
    matches!(err, BridgeError::Transport(_))
}

/// A wrapper that adds retry and timeout behavior to any `ChainAdapter`.
pub struct RetryAdapter<A> {
    inner: A,
    config: RetryConfig,
}

impl<A> RetryAdapter<A> {
    pub fn new(inner: A, config: RetryConfig) -> Self {
        Self { inner, config }
    }
}

#[async_trait::async_trait]
impl<A: ChainAdapter> ChainAdapter for RetryAdapter<A> {
    fn chain_id(&self) -> ChainId {
        self.inner.chain_id()
    }

    async fn submit(&self, msg: &BridgeMessage) -> Result<Vec<u8>, BridgeError> {
        let mut backoff = self.config.initial_backoff;

        for attempt in 1..=self.config.max_attempts {
            let result = tokio::time::timeout(self.config.timeout, self.inner.submit(msg)).await;

            match result {
                Ok(Ok(data)) => return Ok(data),
                Ok(Err(e)) if is_retryable(&e) && attempt < self.config.max_attempts => {
                    warn!(
                        attempt,
                        max = self.config.max_attempts,
                        error = %e,
                        backoff_ms = backoff.as_millis() as u64,
                        "retrying submit"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(self.config.max_backoff);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) if attempt < self.config.max_attempts => {
                    warn!(
                        attempt,
                        max = self.config.max_attempts,
                        backoff_ms = backoff.as_millis() as u64,
                        "submit timed out, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(self.config.max_backoff);
                }
                Err(_) => {
                    return Err(BridgeError::Transport(format!(
                        "timed out after {} attempts",
                        self.config.max_attempts
                    )));
                }
            }
        }

        unreachable!()
    }

    async fn check_nullifier(&self, nullifier: &[u8; 32]) -> Result<bool, BridgeError> {
        let mut backoff = self.config.initial_backoff;

        for attempt in 1..=self.config.max_attempts {
            let result = tokio::time::timeout(
                self.config.timeout,
                self.inner.check_nullifier(nullifier),
            )
            .await;

            match result {
                Ok(Ok(val)) => return Ok(val),
                Ok(Err(e)) if is_retryable(&e) && attempt < self.config.max_attempts => {
                    warn!(
                        attempt,
                        max = self.config.max_attempts,
                        error = %e,
                        "retrying check_nullifier"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(self.config.max_backoff);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) if attempt < self.config.max_attempts => {
                    warn!(attempt, max = self.config.max_attempts, "check_nullifier timed out, retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(self.config.max_backoff);
                }
                Err(_) => {
                    return Err(BridgeError::Transport(format!(
                        "timed out after {} attempts",
                        self.config.max_attempts
                    )));
                }
            }
        }

        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A mock adapter that fails the first N calls then succeeds.
    struct FailNTimes {
        fails_remaining: Arc<AtomicU32>,
    }

    #[async_trait::async_trait]
    impl ChainAdapter for FailNTimes {
        fn chain_id(&self) -> ChainId {
            ChainId::Zcash
        }

        async fn submit(&self, _msg: &BridgeMessage) -> Result<Vec<u8>, BridgeError> {
            let remaining = self.fails_remaining.fetch_sub(1, Ordering::SeqCst);
            if remaining > 0 {
                Err(BridgeError::Transport("transient failure".into()))
            } else {
                Ok(vec![0xAB])
            }
        }

        async fn check_nullifier(&self, _nullifier: &[u8; 32]) -> Result<bool, BridgeError> {
            let remaining = self.fails_remaining.fetch_sub(1, Ordering::SeqCst);
            if remaining > 0 {
                Err(BridgeError::Transport("transient failure".into()))
            } else {
                Ok(true)
            }
        }
    }

    #[tokio::test]
    async fn retries_on_transport_error() {
        let inner = FailNTimes {
            fails_remaining: Arc::new(AtomicU32::new(2)), // fail twice, succeed third
        };
        let adapter = RetryAdapter::new(
            inner,
            RetryConfig {
                max_attempts: 3,
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
                timeout: Duration::from_secs(1),
            },
        );

        let nf = [1u8; 32];
        let result = adapter.check_nullifier(&nf).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn fails_after_max_attempts() {
        let inner = FailNTimes {
            fails_remaining: Arc::new(AtomicU32::new(10)), // will always fail
        };
        let adapter = RetryAdapter::new(
            inner,
            RetryConfig {
                max_attempts: 2,
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
                timeout: Duration::from_secs(1),
            },
        );

        let nf = [1u8; 32];
        let result = adapter.check_nullifier(&nf).await;
        assert!(result.is_err());
    }
}
