//! Prometheus metrics for the ESCANORR RPC server.
//!
//! Tracks key operational metrics for monitoring:
//! - Total deposits, transfers, withdrawals, bridge locks
//! - Current pool tree size, epoch, nullifier count
//! - Request latency histograms
//! - Rate limit rejections

use prometheus::{
    Encoder, IntCounter, IntGauge, Histogram, HistogramOpts, Registry, TextEncoder,
    opts,
};

/// Application-level metrics.
#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    // Counters
    pub deposits_total: IntCounter,
    pub transfers_total: IntCounter,
    pub withdrawals_total: IntCounter,
    pub bridge_locks_total: IntCounter,
    pub rate_limit_rejections: IntCounter,
    pub proof_verification_failures: IntCounter,
    // Gauges
    pub tree_size: IntGauge,
    pub epoch: IntGauge,
    pub nullifier_count: IntGauge,
    pub pool_balance: IntGauge,
    // Histograms
    pub request_duration_seconds: Histogram,
}

impl Metrics {
    /// Create a new metrics registry with all counters/gauges registered.
    pub fn new() -> Self {
        let registry = Registry::new();

        let deposits_total = IntCounter::with_opts(opts!(
            "escanorr_deposits_total",
            "Total number of deposits processed"
        ))
        .unwrap();

        let transfers_total = IntCounter::with_opts(opts!(
            "escanorr_transfers_total",
            "Total number of transfers processed"
        ))
        .unwrap();

        let withdrawals_total = IntCounter::with_opts(opts!(
            "escanorr_withdrawals_total",
            "Total number of withdrawals processed"
        ))
        .unwrap();

        let bridge_locks_total = IntCounter::with_opts(opts!(
            "escanorr_bridge_locks_total",
            "Total number of bridge lock operations"
        ))
        .unwrap();

        let rate_limit_rejections = IntCounter::with_opts(opts!(
            "escanorr_rate_limit_rejections_total",
            "Total number of rate-limited requests"
        ))
        .unwrap();

        let proof_verification_failures = IntCounter::with_opts(opts!(
            "escanorr_proof_verification_failures_total",
            "Total number of failed proof verifications"
        ))
        .unwrap();

        let tree_size = IntGauge::with_opts(opts!(
            "escanorr_tree_size",
            "Current Merkle tree leaf count"
        ))
        .unwrap();

        let epoch = IntGauge::with_opts(opts!(
            "escanorr_epoch",
            "Current pool epoch"
        ))
        .unwrap();

        let nullifier_count = IntGauge::with_opts(opts!(
            "escanorr_nullifier_count",
            "Number of spent nullifiers"
        ))
        .unwrap();

        let pool_balance = IntGauge::with_opts(opts!(
            "escanorr_pool_balance",
            "Total pool balance (sum of deposit values)"
        ))
        .unwrap();

        let request_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "escanorr_request_duration_seconds",
            "HTTP request duration in seconds",
        ))
        .unwrap();

        registry.register(Box::new(deposits_total.clone())).unwrap();
        registry.register(Box::new(transfers_total.clone())).unwrap();
        registry.register(Box::new(withdrawals_total.clone())).unwrap();
        registry.register(Box::new(bridge_locks_total.clone())).unwrap();
        registry.register(Box::new(rate_limit_rejections.clone())).unwrap();
        registry.register(Box::new(proof_verification_failures.clone())).unwrap();
        registry.register(Box::new(tree_size.clone())).unwrap();
        registry.register(Box::new(epoch.clone())).unwrap();
        registry.register(Box::new(nullifier_count.clone())).unwrap();
        registry.register(Box::new(pool_balance.clone())).unwrap();
        registry.register(Box::new(request_duration_seconds.clone())).unwrap();

        Self {
            registry,
            deposits_total,
            transfers_total,
            withdrawals_total,
            bridge_locks_total,
            rate_limit_rejections,
            proof_verification_failures,
            tree_size,
            epoch,
            nullifier_count,
            pool_balance,
            request_duration_seconds,
        }
    }

    /// Encode metrics to Prometheus text format for the /metrics endpoint.
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
