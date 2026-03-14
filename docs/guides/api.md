# RPC API Reference

ESCANORR exposes an HTTP/JSON API via an Axum server.  
Default bind address: `127.0.0.1:3030` (configurable with `--addr`).

All field element values (commitments, nullifiers, roots) are encoded as **64-character lowercase hex strings** (32 bytes, little-endian).  
Proofs are hex-encoded 32 KiB proof envelopes (65536 hex chars).

---

## Endpoints

### `GET /health`

Returns server health status.

**Response**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

### `GET /info`

Returns current node state summary.

**Response**
```json
{
  "epoch": 5,
  "tree_size": 128,
  "root": "0a1b2c...64 hex chars"
}
```

---

### `GET /root`

Returns the current Merkle tree root.

**Response**
```json
{
  "root": "0a1b2c...64 hex chars"
}
```

---

### `POST /deposit`

Insert a note commitment into the privacy pool.

**Request**
```json
{
  "commitment": "0a1b2c...64 hex chars",
  "value": 1000
}
```

**Response** `200 OK`
```json
{
  "index": 42,
  "root": "d3e4f5...64 hex chars"
}
```

**Errors**
| Status | Reason |
|--------|--------|
| 400 | Invalid hex commitment |
| 409 | Pool state conflict |

---

### `POST /transfer`

Submit a private transfer with ZK proof verification.

**Request**
```json
{
  "nullifiers": ["aabb...64 hex", "ccdd...64 hex"],
  "merkle_root": "1122...64 hex",
  "output_commitments": ["eeff...64 hex", "0011...64 hex"],
  "proof": "...65536 hex chars (32 KiB envelope)"
}
```

**Response** `200 OK` (empty body)

**Errors**
| Status | Reason |
|--------|--------|
| 400 | Invalid hex input |
| 403 | Proof verification failed |
| 409 | Nullifier already spent or invalid root |

---

### `POST /withdraw`

Withdraw from the privacy pool with ZK proof.

**Request**
```json
{
  "nullifier": "aabb...64 hex",
  "merkle_root": "1122...64 hex",
  "exit_value": 500,
  "change_commitment": "eeff...64 hex or null",
  "proof": "...65536 hex chars"
}
```

**Response** `200 OK`
```json
{
  "nullifier": "aabb...64 hex",
  "exit_value": 500
}
```

**Errors**
| Status | Reason |
|--------|--------|
| 400 | Invalid hex input |
| 403 | Proof verification failed |
| 409 | Nullifier already spent or invalid root |

---

### `GET /nullifier/:nf`

Check whether a nullifier has been spent.

**Parameters**
- `:nf` — 64-character hex nullifier

**Response**
```json
{
  "spent": true
}
```

---

### `POST /bridge/lock`

Lock a note for cross-chain bridging with ZK proof.

**Request**
```json
{
  "nullifier": "aabb...64 hex",
  "merkle_root": "1122...64 hex",
  "dest_commitment": "eeff...64 hex",
  "source_chain_id": 1,
  "destination_chain_id": 137,
  "amount": 1000,
  "proof": "...65536 hex chars"
}
```

**Response** `200 OK`
```json
{
  "nullifier": "aabb...64 hex",
  "status": "pending"
}
```

**Errors**
| Status | Reason |
|--------|--------|
| 400 | Invalid hex input |
| 403 | Bridge proof verification failed |
| 409 | Nullifier already spent |

---

### `GET /bridge/status/:nf`

Check the status of a bridge operation by its nullifier.

**Parameters**
- `:nf` — 64-character hex nullifier

**Response**
```json
{
  "nullifier": "aabb...64 hex",
  "status": "confirmed"
}
```

Status values: `"pending"` (nullifier not yet seen) or `"confirmed"` (nullifier spent).

---

### `GET /metrics`

Prometheus-formatted metrics. Available counters and gauges:

| Metric | Type | Description |
|--------|------|-------------|
| `deposits_total` | Counter | Total deposits processed |
| `transfers_total` | Counter | Total transfers processed |
| `withdrawals_total` | Counter | Total withdrawals processed |
| `bridge_locks_total` | Counter | Total bridge locks processed |
| `proof_verification_failures` | Counter | Failed proof verifications |
| `tree_size` | Gauge | Current Merkle tree leaf count |
| `epoch` | Gauge | Current epoch number |
| `nullifier_count` | Gauge | Spent nullifiers tracked |

---

## Rate Limiting

The server enforces per-IP sliding-window rate limiting:

- **Default**: 60 requests per 60-second window
- **Body limit**: 128 KiB per request
- Exempt IPs can be configured via `RateLimitConfig::exempt_ips`
- Rate-limited requests receive `429 Too Many Requests`

## Authentication

The RPC server does not enforce authentication. In production, place it behind a reverse proxy (nginx, Envoy) with TLS termination and API key authentication.

## CORS

Cross-Origin Resource Sharing is enabled with permissive defaults via `tower-http::cors::CorsLayer::permissive()`.
