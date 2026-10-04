import type { ErrorCode } from '@vibesec/shared';

export type ErrorKind = 'transient' | 'permanent' | 'budget' | 'cancelled';

const HTTP_STATUS: Partial<Record<ErrorCode, number>> = {
  VALIDATION: 400,
  AUTH_REQUIRED: 401,
  AUTH_INVALID: 403,
  NOT_FOUND: 404,
  REPO_NOT_FOUND: 404,
  REF_NOT_FOUND: 404,
  CONFLICT: 409,
  REPO_TOO_LARGE: 413,
  RATE_LIMITED: 429,
  QUEUE_FULL: 503,
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly kind: ErrorKind;
  readonly userMessage: string;
  readonly retryAfterMs: number | undefined;
  readonly details: unknown;

  constructor(
    code: ErrorCode, kind: ErrorKind, userMessage: string,
    opts: { cause?: unknown; retryAfterMs?: number; details?: unknown } = {},
  ) {
    super(userMessage, { cause: opts.cause });
    this.name = 'AppError';
    this.code = code;
    this.kind = kind;
    this.userMessage = userMessage;
    this.retryAfterMs = opts.retryAfterMs;
    this.details = opts.details;
  }

  get retryable(): boolean { return this.kind === 'transient'; }
  get httpStatus(): number { return HTTP_STATUS[this.code] ?? 500; }
}

export function toAppError(err: unknown): AppError {
  if (err instanceof AppError) return err;
  const name = err instanceof Error ? err.name : '';
  if (name === 'AbortError') return new AppError('CANCELLED', 'cancelled', 'Operation was cancelled', { cause: err });
  if (name === 'TimeoutError') return new AppError('INTERNAL', 'transient', 'Operation timed out', { cause: err });
  return new AppError('INTERNAL', 'permanent', 'Unexpected internal error', { cause: err });
}
