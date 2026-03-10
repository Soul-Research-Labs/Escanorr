# ── Build stage ──────────────────────────────────────────────
FROM rust:1.75-bookworm AS builder

WORKDIR /build

# Cache dependency compilation: copy manifests first
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build release binary
RUN cargo build --release --bin escanorr-cli \
    && strip /build/target/release/escanorr-cli

# ── Runtime stage ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r escanorr && useradd -r -g escanorr -s /sbin/nologin escanorr

COPY --from=builder /build/target/release/escanorr-cli /usr/local/bin/escanorr

USER escanorr

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/escanorr", "info", "--host", "http://localhost:3000"]

ENTRYPOINT ["/usr/local/bin/escanorr"]
CMD ["serve", "--host", "0.0.0.0", "--port", "3000"]
