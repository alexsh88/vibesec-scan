import type Anthropic from '@anthropic-ai/sdk';
import type { z } from 'zod';
import type { LlmCallRepo, LlmTotals } from '../db/llmCallRepo';
import type { ScanRepo } from '../db/scanRepo';
import { AppError, toAppError } from '../errors/AppError';
import { CircuitBreaker } from '../resilience/circuitBreaker';
import { RETRY_POLICIES, withRetry, type RetryDeps } from '../resilience/retry';
import type { BudgetTracker } from './budget';
import { capsOf, costUsd, DEFAULT_EFFORT, DEGRADE_ROLE, FALLBACK_ROLE, type Effort, type ModelRole, type TokenUsage } from './models';
import { buildRequestParts, estimateTokens } from './prompt';
import type { RateLimiter, Semaphore } from './rateLimiter';
import { requestHash, type LlmRequest, type LlmTransport } from './transport';

export type StructuredCall<T> = {
  scanId: string | null;
  analyzer: string;
  purpose: string;
  promptVersion: string;
  role: ModelRole;
  /** Frozen per analyzer + prompt version (cached). Never include timestamps or ids. */
  system: string;
  /** Optional per-scan context pack (cached). */
  context?: string;
  /** Volatile per-call content (wrap repository content with untrustedFile/untrustedText). */
  prompt: string;
  schema: z.ZodType<T>;
  maxTokens?: number;
  effort?: Effort;
  signal: AbortSignal;
  /** Called on every attempt; pass ctx.touch so long calls keep the scan watchdog alive. */
  onActivity?: () => void;
};

export type StructuredResult<T> = {
  output: T;
  model: string;
  usage: TokenUsage;
  costUsd: number;
  callIds: string[];
  /** Served by a lower tier after the requested one stayed unavailable — lower your confidence. */
  degraded: boolean;
  fellBackOnRefusal: boolean;
};

export type LlmClientDeps = {
  transport: LlmTransport;
  models: Record<ModelRole, string>;
  limiter: RateLimiter;
  semaphore: Semaphore;
  budget: BudgetTracker;
  calls: LlmCallRepo;
  scans: Pick<ScanRepo, 'addCost'>;
  breaker?: CircuitBreaker;
  retryDeps?: RetryDeps;
  onUsage?: (scanId: string, totals: LlmTotals) => void;
  now?: () => number;
};

type Sent = { message: Anthropic.Message; model: string; callId: string; usage: TokenUsage; costUsd: number };

const DEFAULT_MAX_TOKENS = 16_000;
const ZERO: TokenUsage = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

export class LlmClient {
  private readonly breaker: CircuitBreaker;
  private readonly now: () => number;

  constructor(private readonly deps: LlmClientDeps) {
    this.breaker = deps.breaker ?? new CircuitBreaker('Anthropic API', { failureThreshold: 5, resetMs: 30_000, unavailableCode: 'LLM_UNAVAILABLE' });
    this.now = deps.now ?? Date.now;
  }

  get mode(): LlmTransport['mode'] {
    return this.deps.transport.mode;
  }

  async structured<T>(call: StructuredCall<T>): Promise<StructuredResult<T>> {
    const c = call as StructuredCall<unknown>;
    const parts = buildRequestParts(call);
    let role = call.role;
    let degraded = false;
    let fellBackOnRefusal = false;
    const sends: Sent[] = [];

    const sendAs = async (r: ModelRole, messages: Anthropic.MessageParam[]): Promise<Sent> => {
      const sent = await this.send(c, this.request(c, r, parts.system, messages));
      sends.push(sent);
      return sent;
    };

    // 1. First send, degrading one tier down if the requested tier stays unavailable (transient only).
    let sent: Sent;
    try {
      sent = await sendAs(role, parts.messages);
    } catch (raw) {
      const err = toAppError(raw);
      const lower = DEGRADE_ROLE[role];
      if (err.kind !== 'transient' || !lower) throw err;
      role = lower;
      degraded = true;
      sent = await sendAs(role, parts.messages);
    }

    // 2. Refusal: exactly one retry on a different tier.
    if (sent.message.stop_reason === 'refusal') {
      role = FALLBACK_ROLE[role];
      fellBackOnRefusal = true;
      sent = await sendAs(role, parts.messages);
      if (sent.message.stop_reason === 'refusal') {
        throw new AppError('LLM_REFUSAL', 'permanent', 'The model declined to analyze this content');
      }
    }

    // 3. Parse + one repair turn (assistant's previous text + the validation issues).
    let parsed = this.parse(call.schema, sent.message);
    if (!parsed.ok) {
      const text = textOf(sent.message);
      const repair: Anthropic.MessageParam[] = [
        ...parts.messages,
        { role: 'assistant', content: [{ type: 'text', text: text || '(empty)' }] },
        { role: 'user', content: [{ type: 'text', text: `Your previous reply did not match the required JSON schema: ${parsed.issues}. Reply again with only the corrected JSON.` }] },
      ];
      sent = await sendAs(role, repair);
      parsed = this.parse(call.schema, sent.message);
      if (!parsed.ok) {
        throw new AppError('LLM_OUTPUT_INVALID', 'permanent', 'The model returned output that does not match the expected format', {
          details: { issues: parsed.issues },
        });
      }
    }

    return {
      output: parsed.value,
      model: sent.model,
      usage: sends.reduce((acc, s) => addUsage(acc, s.usage), ZERO),
      costUsd: sends.reduce((acc, s) => acc + s.costUsd, 0),
      callIds: sends.map((s) => s.callId),
      degraded,
      fellBackOnRefusal,
    };
  }

  private request(call: StructuredCall<unknown>, role: ModelRole, system: Anthropic.TextBlockParam[], messages: Anthropic.MessageParam[]): LlmRequest {
    const model = this.deps.models[role];
    const caps = capsOf(model);
    return {
      model, system, messages,
      maxTokens: call.maxTokens ?? DEFAULT_MAX_TOKENS,
      thinking: caps.adaptiveThinking,
      effort: caps.effort ? (call.effort ?? DEFAULT_EFFORT[role]) : undefined,
      schema: call.schema,
    };
  }

  /** One logical send: budget check → semaphore slot → breaker(retry chain). Truncation is permanent. */
  private async send(call: StructuredCall<unknown>, req: LlmRequest): Promise<Sent> {
    if (call.signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    if (call.scanId) this.deps.budget.ensureAvailable(call.scanId);
    const release = await this.deps.semaphore.acquire(call.signal);
    try {
      const estimate = estimateTokens(JSON.stringify(req.system) + JSON.stringify(req.messages));
      const inputHash = requestHash(req);
      const sent = await this.breaker.run(() => withRetry(async (attempt) => {
        await this.deps.limiter.acquire(estimate, call.signal);
        call.onActivity?.();
        const started = this.now();
        let message: Anthropic.Message;
        try {
          message = await this.deps.transport.send(req, call.signal);
        } catch (raw) {
          const err = toAppError(raw);
          if ((err.details as { rateLimited?: boolean } | undefined)?.rateLimited) this.deps.limiter.penalize();
          if (err.kind !== 'cancelled') this.record(call, req.model, inputHash, attempt, started, null, err.code);
          throw err;
        }
        return this.record(call, req.model, inputHash, attempt, started, message, null);
      }, RETRY_POLICIES.anthropic, call.signal, this.deps.retryDeps));
      call.onActivity?.();
      const stop = sent.message.stop_reason;
      if (stop === 'max_tokens' || stop === 'model_context_window_exceeded') {
        throw new AppError('LLM_OUTPUT_INVALID', 'permanent', 'The model output was truncated', { details: { truncated: true } });
      }
      return sent;
    } finally {
      release();
    }
  }

  private record(
    call: StructuredCall<unknown>, model: string, inputHash: string, attempt: number, started: number,
    message: Anthropic.Message | null, errorCode: string | null,
  ): Sent {
    const usage: TokenUsage = message ? {
      inputTokens: message.usage.input_tokens ?? 0,
      outputTokens: message.usage.output_tokens ?? 0,
      cacheReadTokens: message.usage.cache_read_input_tokens ?? 0,
      cacheWriteTokens: message.usage.cache_creation_input_tokens ?? 0,
    } : ZERO;
    const cost = costUsd(model, usage);
    const callId = this.deps.calls.insert({
      scanId: call.scanId, analyzer: call.analyzer, purpose: call.purpose, model, promptVersion: call.promptVersion, inputHash,
      ...usage, costUsd: cost, latencyMs: this.now() - started, stopReason: message?.stop_reason ?? null, attempt, errorCode,
    });
    if (call.scanId) {
      if (cost > 0) {
        // Budget first: its lazy load reads scans.cost_usd, so adding there first would double-count.
        this.deps.budget.add(call.scanId, cost);
        this.deps.scans.addCost(call.scanId, cost);
      }
      this.deps.onUsage?.(call.scanId, this.deps.calls.totals(call.scanId));
    }
    return { message: message as Anthropic.Message, model, callId, usage, costUsd: cost };
  }

  private parse<T>(schema: z.ZodType<T>, message: Anthropic.Message): { ok: true; value: T } | { ok: false; issues: string } {
    let json: unknown;
    try {
      json = JSON.parse(textOf(message));
    } catch {
      return { ok: false, issues: 'the reply was not valid JSON' };
    }
    const result = schema.safeParse(json);
    if (result.success) return { ok: true, value: result.data };
    const issues = result.error.issues.slice(0, 10).map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ');
    return { ok: false, issues };
  }
}

function textOf(message: Anthropic.Message): string {
  return message.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('').trim();
}

function addUsage(a: TokenUsage, b: TokenUsage): TokenUsage {
  return {
    inputTokens: a.inputTokens + b.inputTokens, outputTokens: a.outputTokens + b.outputTokens,
    cacheReadTokens: a.cacheReadTokens + b.cacheReadTokens, cacheWriteTokens: a.cacheWriteTokens + b.cacheWriteTokens,
  };
}
