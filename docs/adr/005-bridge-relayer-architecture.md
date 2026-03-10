# ADR-005: Bridge Relayer Architecture

## Status

Proposed

## Context

ESCANORR's cross-chain bridge requires an off-chain component to relay bridge messages between chains. The bridge adapter trait (`ChainAdapter`) defines how proofs are submitted to destination chains, but the relay orchestration — message observation, ordering, fee collection, and liveness — is undefined.

Key requirements:

1. **Privacy preservation** — The relayer must not learn the mapping between source nullifiers and destination commitments beyond what is already public
2. **Liveness** — Messages must be relayed within bounded latency
3. **Finality** — The relayer must wait for source-chain finality before submitting to the destination
4. **Fee model** — Bridge fees must incentivize relayer operation without creating MEV opportunities

## Decision

Adopt a **centralized relayer with watchtower upgradeability**:

### Phase 1 — Centralized Relayer

A single operator-run service observes `BridgeLock` events on source chains and submits wrapped proofs to destination chains.

```
Source Chain              Relayer                    Destination Chain
────────────             ─────────                  ──────────────────
BridgeLock event  ──►  Observe  ──►  Wait for       POST wrapped-proof
                        queue        finality  ──►   to PrivacyPool or
                                                     BridgeVault
```

**Message lifecycle:**

1. User calls `POST /bridge/lock` on the RPC server, which emits a `BridgeLock` event (or stores in state)
2. Relayer polls for pending lock messages (via RPC `/bridge/status/:nf` or chain events)
3. Relayer verifies the proof envelope locally
4. Relayer waits for source-chain finality (Zcash: 10 confirmations, EVM: chain-specific)
5. Relayer calls `ChainAdapter::submit()` on the destination adapter
6. Relayer updates status to `Completed` or `Failed`

**Fee model:**

- Flat fee per bridge operation, paid in the source chain's native asset
- Fee is locked alongside the bridge amount in `BridgeVault`
- Relayer claims fees in a batch settlement transaction

### Phase 2 — Watchtower Network (Future)

Replace the single relayer with a permissioned set of watchtowers using threshold signatures (t-of-n) for message attestation. This removes the single point of failure without requiring a full consensus mechanism.

## Rationale

- A centralized relayer is the simplest path to a working bridge with known trust assumptions
- The `ChainAdapter` trait is already designed for this — `submit()` is async and chain-agnostic
- Watchtower upgradeability is additive — the relayer interface doesn't change, only the signing/attestation layer
- Privacy-preserving because the relayer sees only public on-chain events (nullifiers and commitments are unlinkable without the spending key)

## Trade-offs

- **Trust**: Users must trust the relayer for liveness (not safety — proofs are verified on-chain)
- **Censorship**: A centralized relayer can censor specific bridge requests
- **Availability**: Single point of failure until Phase 2
- **Fee extraction**: Relayer sets fees unilaterally until a competitive market exists

## Finality Assumptions

| Chain    | Confirmations           | Approximate Time     |
| -------- | ----------------------- | -------------------- |
| Zcash    | 10 blocks               | ~12.5 min            |
| Ethereum | 2 epochs (64 slots)     | ~13 min              |
| Polygon  | 256 blocks              | ~8.5 min             |
| Arbitrum | L1 finality             | ~13 min              |
| Optimism | L1 finality + challenge | ~13 min (optimistic) |
| Base     | L1 finality             | ~13 min              |

## Consequences

- The relayer is a new binary/service that must be deployed alongside the RPC server
- Bridge operations have latency bounded by source-chain finality + relayer processing
- Fee economics must be calibrated per-chain based on gas costs
- The `BridgeMessage.fee` field is already defined and carried through the pipeline
- Monitoring must track relayer queue depth, resubmission rate, and per-chain latency
