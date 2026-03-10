/**
 * Errors from the ESCANORR SDK.
 */
export class EscanorrError extends Error {
  public readonly statusCode: number;
  public readonly body?: string;

  constructor(message: string, statusCode: number, body?: string) {
    super(message);
    this.name = "EscanorrError";
    this.statusCode = statusCode;
    this.body = body;
  }
}

/**
 * The server returned a non-2xx status.
 */
export class HttpError extends EscanorrError {
  constructor(statusCode: number, body?: string) {
    super(`HTTP ${statusCode}${body ? `: ${body}` : ""}`, statusCode, body);
    this.name = "HttpError";
  }
}

/**
 * Network-level failure (timeout, DNS, connection refused).
 */
export class NetworkError extends EscanorrError {
  public readonly cause: unknown;

  constructor(message: string, cause: unknown) {
    super(message, 0);
    this.name = "NetworkError";
    this.cause = cause;
  }
}
