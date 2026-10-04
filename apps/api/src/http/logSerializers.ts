import { scrubSecrets } from '../security/scrub';

export interface SerializedError {
  type: string;
  message: string;
  stack: string;
  code?: string;
  cause?: string;
  [key: string]: unknown;
}

// Pino `serializers.err` hook: the default pino-std-serializers passes `error.message`
// and `error.stack` through verbatim, which leaks secrets (tokens, PATs) captured in
// error messages (e.g. from a failed git/http call) straight into log output. Route
// every error field through scrubSecrets before it reaches the logger.
export function serializeError(err: unknown): SerializedError {
  if (err instanceof Error) {
    const out: SerializedError = {
      type: err.name,
      message: scrubSecrets(err.message),
      stack: scrubSecrets(err.stack ?? ''),
    };
    const code = (err as NodeJS.ErrnoException).code;
    if (code) out.code = code;
    if (err.cause instanceof Error) {
      out.cause = scrubSecrets(err.cause.message);
    } else if (err.cause !== undefined) {
      out.cause = scrubSecrets(String(err.cause));
    }
    return out;
  }
  return { type: typeof err, message: scrubSecrets(String(err)), stack: '' };
}
