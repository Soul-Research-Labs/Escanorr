/**
 * Supported chain identifiers.
 */
export enum ChainId {
  Zcash = "zcash",
  Horizen = "horizen",
  Komodo = "komodo",
  PirateChain = "pirate_chain",
  Ethereum = "ethereum",
  Polygon = "polygon",
  Arbitrum = "arbitrum",
  Optimism = "optimism",
  Base = "base",
}

/**
 * Hex-encoded 32-byte hash.
 */
export type Hash32 = string;

/**
 * A note commitment in the privacy pool.
 */
export interface NoteCommitment {
  inner: Hash32;
}

/**
 * A nullifier proving a note was spent.
 */
export interface Nullifier {
  inner: Hash32;
}

/**
 * Information about the ESCANORR node.
 */
export interface NodeInfo {
  version: string;
  treeSize: number;
  merkleRoot: Hash32;
  epoch: number;
}

/**
 * Response from a deposit operation.
 */
export interface DepositResponse {
  commitment: Hash32;
  leafIndex: number;
}

/**
 * Response from a transfer operation.
 */
export interface TransferResponse {
  nullifiers: Hash32[];
  outputCommitments: Hash32[];
}

/**
 * Response from a withdrawal operation.
 */
export interface WithdrawResponse {
  nullifier: Hash32;
  exitValue: number;
}

/**
 * Bridge lock request.
 */
export interface BridgeLockRequest {
  nullifier: Hash32;
  commitmentHash: Hash32;
  sourceChainId: ChainId;
  destinationChainId: ChainId;
  amount: number;
  proof: string;
}

/**
 * Bridge lock response.
 */
export interface BridgeLockResponse {
  txHash: Hash32;
  sourceChainId: ChainId;
  destinationChainId: ChainId;
  status: "pending" | "confirmed" | "finalized";
}

/**
 * Bridge status query result.
 */
export interface BridgeStatus {
  nullifier: Hash32;
  sourceChainId: ChainId;
  destinationChainId: ChainId;
  amount: number;
  status: "pending" | "confirmed" | "finalized" | "failed";
  timestamp: number;
}

/**
 * Health check response.
 */
export interface HealthResponse {
  status: "ok" | "degraded" | "down";
  uptime: number;
}

/**
 * Deposit request payload.
 */
export interface DepositRequest {
  owner: Hash32;
  value: number;
}

/**
 * Transfer request payload.
 */
export interface TransferRequest {
  sender: Hash32;
  recipient: Hash32;
  amount: number;
  fee: number;
}
