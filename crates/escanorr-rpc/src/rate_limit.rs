//! Per-IP sliding-window rate limiter as Axum middleware.
//!
//! Uses an in-memory `DashMap` to track request timestamps per IP.
//! Suitable for single-node deployments; for multi-node, use a shared
//! store (Redis) behind the same interface.

use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::{
    collections::{HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use dashmap::DashMap;
use tracing::warn;

/// Configuration for the rate limiter.
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed per window.
    pub max_requests: u32,
    /// Window duration.
    pub window: Duration,
    /// IPs exempt from rate limiting (e.g. relayers, internal services).
    pub exempt_ips: HashSet<IpAddr>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window: Duration::from_secs(60),
            exempt_ips: HashSet::new(),
        }
    }
}

/// Shared rate-limiter state.
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Map from IP address to timestamps of recent requests.
    windows: Arc<DashMap<IpAddr, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Arc::new(DashMap::new()),
        }
    }

    /// Check if a request from `ip` is allowed. Returns `true` if allowed.
    fn check(&self, ip: IpAddr) -> bool {
        if self.config.exempt_ips.contains(&ip) {
            return true;
        }
        let now = Instant::now();
        let cutoff = now - self.config.window;

        let mut entry = self.windows.entry(ip).or_insert_with(VecDeque::new);
        let window = entry.value_mut();

        // Evict expired entries
        while window.front().is_some_and(|&t| t < cutoff) {
            window.pop_front();
        }

        if window.len() >= self.config.max_requests as usize {
            return false;
        }

        window.push_back(now);
        true
    }
}

/// Axum middleware function for rate limiting.
///
/// Must be used with `axum::middleware::from_fn_with_state` and the server
/// must be started with `into_make_service_with_connect_info::<SocketAddr>()`.
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !limiter.check(addr.ip()) {
        warn!(ip = %addr.ip(), "rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(request).await)
}
