import Anthropic from '@anthropic-ai/sdk';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import { AppError, toAppError } from '../errors/AppError';
import type { LlmRequest, LlmTransport } from './transport';

export class AnthropicTransport implements LlmTransport {
  readonly mode = 'live' as const;

  constructor(private readonly client: Anthropic, private readonly timeoutMs: number) {}

  static create(apiKey: string, timeoutMs: number): AnthropicTransport {
    // maxRetries: 0 — withRetry in LlmClient owns retries (visible, budgeted, breaker-aware).
    return new AnthropicTransport(new Anthropic({ apiKey, maxRetries: 0, timeout: timeoutMs }), timeoutMs);
  }

  async send(req: LlmRequest, signal: AbortSignal): Promise<Anthropic.Message> {
    try {
      return await this.client.messages.create({
        model: req.model,
        max_tokens: req.maxTokens,
        system: req.system,
        messages: req.messages,
        ...(req.thinking ? { thinking: { type: 'adaptive' as const } } : {}),
        output_config: { format: zodOutputFormat(req.schema), ...(req.effort ? { effort: req.effort } : {}) },
      }, { signal, timeout: this.timeoutMs });
    } catch (err) {
      throw mapAnthropicError(err);
    }
  }
}

const CONTEXT_TOO_LARGE = /prompt is too long|too many tokens|context (window|length)|exceeds the maximum/i;

export function mapAnthropicError(err: unknown): AppError {
  if (err instanceof Anthropic.APIUserAbortError) {
    return new AppError('CANCELLED', 'cancelled', 'Operation was cancelled', { cause: err });
  }
  if (err instanceof Anthropic.APIConnectionError) {
    return new AppError('LLM_UNAVAILABLE', 'transient', 'Could not reach the Anthropic API', { cause: err });
  }
  if (err instanceof Anthropic.RateLimitError) {
    const seconds = Number(err.headers?.get('retry-after'));
    return new AppError('LLM_UNAVAILABLE', 'transient', 'Anthropic API rate limit reached', {
      cause: err, retryAfterMs: Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : undefined, details: { rateLimited: true },
    });
  }
  if (err instanceof Anthropic.InternalServerError) {
    return new AppError('LLM_UNAVAILABLE', 'transient', 'The Anthropic API is temporarily unavailable', { cause: err });
  }
  if (err instanceof Anthropic.AuthenticationError || err instanceof Anthropic.PermissionDeniedError) {
    return new AppError('LLM_UNAVAILABLE', 'permanent', 'The Anthropic API key is invalid or lacks access', { cause: err });
  }
  if (err instanceof Anthropic.BadRequestError && CONTEXT_TOO_LARGE.test(err.message)) {
    return new AppError('LLM_OUTPUT_INVALID', 'permanent', 'The request was too large for the model context', {
      cause: err, details: { contextTooLarge: true },
    });
  }
  if (err instanceof Anthropic.BadRequestError || err instanceof Anthropic.NotFoundError || err instanceof Anthropic.UnprocessableEntityError) {
    return new AppError('INTERNAL', 'permanent', 'Invalid request to the Anthropic API', { cause: err });
  }
  if (err instanceof Anthropic.APIError && typeof err.status === 'number' && err.status >= 500) {
    return new AppError('LLM_UNAVAILABLE', 'transient', 'The Anthropic API is temporarily unavailable', { cause: err });
  }
  return toAppError(err);
}
