import { HttpError, NetworkError } from "./errors.js";
import type {
  BridgeLockRequest,
  BridgeLockResponse,
  BridgeStatus,
  DepositRequest,
  DepositResponse,
  Hash32,
  HealthResponse,
  NodeInfo,
  TransferRequest,
  TransferResponse,
  WithdrawResponse,
} from "./types.js";

/**
 * Configuration for the ESCANORR client.
 */
export interface EscanorrClientConfig {
  /** Base URL of the ESCANORR RPC server (e.g. "http://localhost:3000") */
  baseUrl: string;
  /** Optional API key for authenticated endpoints */
  apiKey?: string;
  /** Request timeout in milliseconds (default: 30_000) */
  timeoutMs?: number;
  /** Number of retry attempts for transient failures (default: 3) */
  retries?: number;
  /** Initial backoff delay in ms, doubled each attempt (default: 500) */
  retryBaseMs?: number;
}

/**
 * Typed HTTP client for the ESCANORR RPC server.
 *
 * @example
 * ```ts
 * const client = new EscanorrClient({ baseUrl: "http://localhost:3000" });
 * const info = await client.info();
 * console.log(info.treeSize);
 * ```
 */
export class EscanorrClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly retryBaseMs: number;

  constructor(config: EscanorrClientConfig) {
    // Strip trailing slash
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.apiKey = config.apiKey;
    this.timeoutMs = config.timeoutMs ?? 30_000;
    this.retries = config.retries ?? 3;
    this.retryBaseMs = config.retryBaseMs ?? 500;
  }

  // ──────────────────────────────────────────────────────────
  // Core endpoints
  // ──────────────────────────────────────────────────────────

  /** Health check */
  async health(): Promise<HealthResponse> {
    return this.get<HealthResponse>("/health");
  }

  /** Node info — tree size, merkle root, epoch */
  async info(): Promise<NodeInfo> {
    return this.get<NodeInfo>("/info");
  }

  /** Deposit into the privacy pool */
  async deposit(request: DepositRequest): Promise<DepositResponse> {
    return this.post<DepositResponse>("/deposit", request);
  }

  /** Private transfer within the pool */
  async transfer(request: TransferRequest): Promise<TransferResponse> {
    return this.post<TransferResponse>("/transfer", request);
  }

  /** Withdraw from the privacy pool */
  async withdraw(
    nullifier: Hash32,
    exitValue: number,
  ): Promise<WithdrawResponse> {
    return this.post<WithdrawResponse>("/withdraw", { nullifier, exitValue });
  }

  /** Check if a nullifier has been spent */
  async isNullifierSpent(nullifier: Hash32): Promise<boolean> {
    const resp = await this.get<{ spent: boolean }>(`/nullifier/${nullifier}`);
    return resp.spent;
  }

  /** Get the current Merkle root */
  async merkleRoot(): Promise<Hash32> {
    const resp = await this.get<{ root: Hash32 }>("/merkle-root");
    return resp.root;
  }

  // ──────────────────────────────────────────────────────────
  // Bridge endpoints
  // ──────────────────────────────────────────────────────────

  /** Lock assets for cross-chain bridge */
  async bridgeLock(request: BridgeLockRequest): Promise<BridgeLockResponse> {
    return this.post<BridgeLockResponse>("/bridge/lock", request);
  }

  /** Check bridge operation status */
  async bridgeStatus(nullifier: Hash32): Promise<BridgeStatus> {
    return this.get<BridgeStatus>(`/bridge/status/${nullifier}`);
  }

  // ──────────────────────────────────────────────────────────
  // HTTP primitives
  // ──────────────────────────────────────────────────────────

  private async get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }

    let lastError: unknown;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) {
        const delay = this.retryBaseMs * 2 ** (attempt - 1);
        await new Promise((r) => setTimeout(r, delay));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const resp = await fetch(url, {
          method,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });

        const text = await resp.text();

        if (!resp.ok) {
          const err = new HttpError(resp.status, text);
          // Only retry on 5xx or 429 (rate limited)
          if (
            (resp.status >= 500 || resp.status === 429) &&
            attempt < this.retries
          ) {
            lastError = err;
            continue;
          }
          throw err;
        }

        return JSON.parse(text) as T;
      } catch (err) {
        if (err instanceof HttpError) throw err;
        lastError = err;
        // Retry on network-level errors
        if (attempt < this.retries) continue;
        throw new NetworkError(`Request to ${method} ${path} failed`, err);
      } finally {
        clearTimeout(timer);
      }
    }

    // Should not reach here, but satisfy TypeScript
    throw new NetworkError(
      `Request to ${method} ${path} failed after ${this.retries} retries`,
      lastError,
    );
  }
}
