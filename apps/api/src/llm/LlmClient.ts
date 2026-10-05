import type Anthropic from '@anthropic-ai/sdk';
import { z } from 'zod';
import type { LlmCallRepo, LlmTotals } from '../db/llmCallRepo';
import type { ScanRepo } from '../db/scanRepo';
import { AppError, toAppError } from '../errors/AppError';
import { CircuitBreaker } from '../resilience/circuitBreaker';
import { RETRY_POLICIES, withRetry, type RetryDeps } from '../resilience/retry';
import type { BudgetTracker, SettleBudget } from './budget';
import { capsOf, costUsd, DEFAULT_EFFORT, DEFAULT_MAX_TOKENS, DEGRADE_ROLE, FALLBACK_ROLE, type Effort, type ModelRole, type TokenUsage } from './models';
import { buildRequestParts, estimateTokens } from './prompt';
import type { RateLimiter, Semaphore } from './rateLimiter';
import { requestHash, type LlmRequest, type LlmToolDef, type LlmTransport } from './transport';

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

/** A client tool the model may call during `agent()`. Results go back to the model as tool_result text. */
export type AgentTool<I = any> = {
  name: string;
  description: string;
  /** Validates the model's input; its JSON schema (input side) is what the model sees. Must be an object schema. */
  input: z.ZodType<I>;
  /** Never needs to catch: a throw becomes an is_error tool_result. Output is truncated to AGENT_TOOL_RESULT_MAX_CHARS. */
  run(input: I, ctx: { signal: AbortSignal }): Promise<string> | string;
};

/** Infers `I` from the zod schema so `run`'s input is typed. */
export function defineTool<I>(tool: AgentTool<I>): AgentTool<I> {
  return tool;
}

export type AgentCall<T> = Omit<StructuredCall<T>, 'schema'> & {
  tools: AgentTool[];
  /** Name of the tool (in `tools`) whose validated inputs are collected as the result, e.g. 'report_flow'. */
  finishTool: string;
  /** Model turns (sends), default 25. */
  maxTurns?: number;
  /** Whole-loop wall clock, default 300 000 ms. An in-flight send/tool run is aborted when it elapses. */
  wallClockMs?: number;
  toolChoice?: Anthropic.ToolChoice;
};

export type AgentStopReason = 'end_turn' | 'max_turns' | 'timeout' | 'budget' | 'refusal' | 'truncated' | 'error';

export type AgentResult<T> = {
  /** Validated inputs of every finishTool call, in call order. */
  finished: T[];
  turns: number;
  stopReason: AgentStopReason;
  /** Model of the last send ('' when nothing was sent). */
  model: string;
  costUsd: number;
  usage: TokenUsage;
  callIds: string[];
  degraded: boolean;
  /** Set when stopReason is 'error' (a non-budget failure after something was already collected). */
  error?: AppError;
};

export const AGENT_TOOL_RESULT_MAX_CHARS = 20_000;
const AGENT_DEFAULT_MAX_TURNS = 25;
const AGENT_DEFAULT_WALL_CLOCK_MS = 300_000;

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
  /** Fired only for attempts with a cost > 0, coalesced to at most once per USAGE_EMIT_INTERVAL_MS per scan. */
  onUsage?: (scanId: string, totals: LlmTotals) => void;
  /** Runs fn in one DB transaction (container: `(fn) => db.transaction(fn)()`); defaults to calling fn directly. */
  atomically?: <T>(fn: () => T) => T;
  now?: () => number;
};

/** What send()/record() need from a call (shared by structured() and agent()). */
type CallMeta = Pick<StructuredCall<unknown>, 'scanId' | 'analyzer' | 'purpose' | 'promptVersion' | 'signal' | 'onActivity'>;

type Sent = { message: Anthropic.Message; model: string; callId: string; usage: TokenUsage; costUsd: number };

const USAGE_EMIT_INTERVAL_MS = 1_000;
const ZERO: TokenUsage = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

export class LlmClient {
  private readonly breaker: CircuitBreaker;
  private readonly now: () => number;
  private readonly atomically: <T>(fn: () => T) => T;
  /** Per scan: when the last cost event was emitted, and the pending trailing emit (if any). */
  private readonly lastUsageEmit = new Map<string, number>();
  private readonly pendingUsageEmit = new Map<string, NodeJS.Timeout>();

  constructor(private readonly deps: LlmClientDeps) {
    this.breaker = deps.breaker ?? new CircuitBreaker('Anthropic API', { failureThreshold: 5, resetMs: 30_000, unavailableCode: 'LLM_UNAVAILABLE' });
    this.now = deps.now ?? Date.now;
    this.atomically = deps.atomically ?? ((fn) => fn());
  }

  get mode(): LlmTransport['mode'] {
    return this.deps.transport.mode;
  }

  /** How many times the Anthropic circuit breaker has opened since startup. */
  get breakerTrips(): number {
    return this.breaker.trips;
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

  /**
   * Manual tool-use loop over our own transport, so every turn keeps rate limiting, the semaphore, budget
   * reservation, retries, the breaker, llm_calls accounting and mock/record/live modes.
   *
   * send → stop_reason tool_use: each tool_use block is validated (zod) and run; invalid input, unknown tools
   * and tool errors become is_error tool_results (never thrown). finishTool inputs are collected. The loop
   * ends when the model stops calling tools ('end_turn'), or on maxTurns / wallClockMs / budget / refusal /
   * truncation, always returning what was collected. Cancellation (call.signal) throws CANCELLED. Any other
   * failure throws when nothing was collected yet, else returns stopReason 'error'.
   *
   * Caching: system (+ tools, which precede it in the cache order) and the optional context pack carry
   * breakpoints; each turn additionally marks the last block of the transcript, so the growing
   * transcript is read from cache on the next turn (3 breakpoints max, the API allows 4).
   * A transient failure on the first turn degrades one tier (like structured()); never mid-loop, since
   * thinking blocks in the transcript are bound to the model that produced them.
   */
  async agent<T>(call: AgentCall<T>): Promise<AgentResult<T>> {
    const byName = new Map<string, AgentTool>();
    for (const tool of call.tools) {
      if (byName.has(tool.name)) throw new AppError('INTERNAL', 'permanent', `Duplicate agent tool "${tool.name}"`);
      byName.set(tool.name, tool);
    }
    if (!byName.has(call.finishTool)) throw new AppError('INTERNAL', 'permanent', `finishTool "${call.finishTool}" is not among the agent tools`);
    const toolDefs = call.tools.map(toolDefOf);
    const maxTurns = call.maxTurns ?? AGENT_DEFAULT_MAX_TURNS;
    const wallClockMs = call.wallClockMs ?? AGENT_DEFAULT_WALL_CLOCK_MS;
    const started = this.now();
    const clock = new AbortController();
    const timer = setTimeout(() => clock.abort(), wallClockMs);
    timer.unref?.();
    const signal = AbortSignal.any([call.signal, clock.signal]);
    const meta: CallMeta = { ...call, signal };
    const parts = buildRequestParts(call);
    const transcript: Anthropic.MessageParam[] = [...parts.messages];
    const finished: T[] = [];
    const sends: Sent[] = [];
    let role = call.role;
    let degraded = false;
    let turns = 0;
    let stopReason: AgentStopReason = 'end_turn';
    let error: AppError | undefined;
    const cancelled = () => new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');

    try {
      for (;;) {
        if (call.signal.aborted) throw cancelled();
        if (turns >= maxTurns) { stopReason = 'max_turns'; break; }
        if (clock.signal.aborted || this.now() - started >= wallClockMs) { stopReason = 'timeout'; break; }
        let sent: Sent;
        try {
          const req: LlmRequest = {
            ...this.request(call, role, parts.system, withCacheTail(transcript)),
            tools: toolDefs,
            ...(call.toolChoice ? { toolChoice: call.toolChoice } : {}),
          };
          sent = await this.send(meta, req);
        } catch (raw) {
          const err = toAppError(raw);
          if (call.signal.aborted) throw err.kind === 'cancelled' ? err : cancelled();
          if (err.kind === 'cancelled' && clock.signal.aborted) { stopReason = 'timeout'; break; }
          if (err.kind === 'budget') { stopReason = 'budget'; break; }
          const lower = DEGRADE_ROLE[role];
          if (turns === 0 && !degraded && err.kind === 'transient' && lower) {
            role = lower;
            degraded = true;
            continue;
          }
          if ((err.details as { truncated?: boolean } | undefined)?.truncated) { stopReason = 'truncated'; break; }
          if (finished.length === 0) throw err;
          stopReason = 'error';
          error = err;
          break;
        }
        turns++;
        sends.push(sent);
        const message = sent.message;
        if (message.stop_reason === 'refusal') { stopReason = 'refusal'; break; }
        const uses = message.content.filter((b): b is Anthropic.ToolUseBlock => b.type === 'tool_use');
        if (message.stop_reason !== 'tool_use' || uses.length === 0) { stopReason = 'end_turn'; break; }

        transcript.push({ role: 'assistant', content: message.content.flatMap(toParam) });
        const results: Anthropic.ToolResultBlockParam[] = [];
        for (const use of uses) {
          results.push(await this.runTool(use, byName, call.finishTool, finished, signal));
        }
        call.onActivity?.();
        if (call.signal.aborted) throw cancelled();
        if (clock.signal.aborted) { stopReason = 'timeout'; break; }
        transcript.push({ role: 'user', content: results });
      }
    } finally {
      clearTimeout(timer);
    }

    return {
      finished, turns, stopReason, degraded,
      model: sends.at(-1)?.model ?? '',
      usage: sends.reduce((acc, s) => addUsage(acc, s.usage), ZERO),
      costUsd: sends.reduce((acc, s) => acc + s.costUsd, 0),
      callIds: sends.map((s) => s.callId),
      ...(error ? { error } : {}),
    };
  }

  private async runTool<T>(
    use: Anthropic.ToolUseBlock, byName: Map<string, AgentTool>, finishTool: string, finished: T[], signal: AbortSignal,
  ): Promise<Anthropic.ToolResultBlockParam> {
    const result = (content: string, isError = false): Anthropic.ToolResultBlockParam => ({
      type: 'tool_result', tool_use_id: use.id, content: truncateResult(content), ...(isError ? { is_error: true } : {}),
    });
    const tool = byName.get(use.name);
    if (!tool) return result(`Unknown tool "${use.name}". Available tools: ${[...byName.keys()].join(', ')}.`, true);
    const parsed = tool.input.safeParse(use.input);
    if (!parsed.success) {
      const issues = parsed.error.issues.slice(0, 10).map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ');
      return result(`Invalid input for ${tool.name}: ${issues}`, true);
    }
    if (tool.name === finishTool) finished.push(parsed.data as T);
    try {
      return result(String(await tool.run(parsed.data, { signal })));
    } catch (err) {
      const msg = err instanceof AppError ? err.userMessage : err instanceof Error ? err.message : String(err);
      return result(`Tool ${tool.name} failed: ${msg}`, true);
    }
  }

  private request(
    call: { maxTokens?: number; effort?: Effort; schema?: z.ZodType }, role: ModelRole,
    system: Anthropic.TextBlockParam[], messages: Anthropic.MessageParam[],
  ): LlmRequest {
    const model = this.deps.models[role];
    const caps = capsOf(model);
    return {
      model, system, messages,
      maxTokens: call.maxTokens ?? DEFAULT_MAX_TOKENS[role],
      thinking: caps.adaptiveThinking,
      effort: caps.effort ? (call.effort ?? DEFAULT_EFFORT[role]) : undefined,
      ...(call.schema ? { schema: call.schema } : {}),
    };
  }

  /** One logical send: budget check → semaphore slot → breaker(retry chain, budget reservation per attempt). Truncation is permanent. */
  private async send(call: CallMeta, req: LlmRequest): Promise<Sent> {
    if (call.signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
    if (call.scanId) this.deps.budget.ensureAvailable(call.scanId);
    const release = await this.deps.semaphore.acquire(call.signal);
    try {
      const estimate = estimateTokens(JSON.stringify(req.system) + JSON.stringify(req.messages));
      const inputHash = requestHash(req);
      // Worst case for one attempt: the full input estimate plus all of max_tokens as output.
      const estimateUsd = costUsd(req.model, { inputTokens: estimate, outputTokens: req.maxTokens, cacheReadTokens: 0, cacheWriteTokens: 0 });
      const sent = await this.breaker.run(() => withRetry(async (attempt) => {
        // Reserve per attempt so concurrent in-flight calls cannot jointly overshoot the scan budget.
        // Waits (abortably) while only other in-flight reservations block; throws once committed spend can't fit.
        const settle: SettleBudget = call.scanId ? await this.deps.budget.reserve(call.scanId, estimateUsd, call.signal) : () => {};
        try {
          await this.deps.limiter.acquire(estimate, call.signal);
          call.onActivity?.();
          const started = this.now();
          let message: Anthropic.Message;
          try {
            message = await this.deps.transport.send(req, call.signal);
          } catch (raw) {
            const err = toAppError(raw);
            if ((err.details as { rateLimited?: boolean } | undefined)?.rateLimited) this.deps.limiter.penalize();
            if (err.kind !== 'cancelled') this.record(call, req.model, inputHash, attempt, started, null, err.code, settle);
            throw err;
          }
          return this.record(call, req.model, inputHash, attempt, started, message, null, settle);
        } finally {
          settle(0); // no-op once record() settled; frees the reservation on cancellation/limiter errors
        }
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
    call: CallMeta, model: string, inputHash: string, attempt: number, started: number,
    message: Anthropic.Message | null, errorCode: string | null, settle: SettleBudget,
  ): Sent {
    const usage: TokenUsage = message ? {
      inputTokens: message.usage.input_tokens ?? 0,
      outputTokens: message.usage.output_tokens ?? 0,
      cacheReadTokens: message.usage.cache_read_input_tokens ?? 0,
      cacheWriteTokens: message.usage.cache_creation_input_tokens ?? 0,
    } : ZERO;
    const cost = costUsd(model, usage);
    // Budget first: settle() frees this attempt's reservation and commits the actual cost (0 on failure).
    // It must precede scans.addCost because the budget's lazy load reads scans.cost_usd (adding there
    // first would double-count), and it runs even if the DB write below fails — conservative on purpose:
    // the money was spent at the API, so in-memory spend must never under-count it.
    settle(cost);
    // The call row and the scan's running cost commit together or not at all.
    const callId = this.atomically(() => {
      const id = this.deps.calls.insert({
        scanId: call.scanId, analyzer: call.analyzer, purpose: call.purpose, model, promptVersion: call.promptVersion, inputHash,
        ...usage, costUsd: cost, latencyMs: this.now() - started, stopReason: message?.stop_reason ?? null, attempt, errorCode,
      });
      if (call.scanId && cost > 0) this.deps.scans.addCost(call.scanId, cost);
      return id;
    });
    if (call.scanId && cost > 0) this.emitUsage(call.scanId);
    return { message: message as Anthropic.Message, model, callId, usage, costUsd: cost };
  }

  /** Leading emit, then at most one trailing emit (with the then-latest totals) per interval per scan. */
  private emitUsage(scanId: string): void {
    const onUsage = this.deps.onUsage;
    if (!onUsage || this.pendingUsageEmit.has(scanId)) return;
    const elapsed = this.now() - (this.lastUsageEmit.get(scanId) ?? -Infinity);
    const fire = (): void => {
      this.pendingUsageEmit.delete(scanId);
      this.lastUsageEmit.set(scanId, this.now());
      onUsage(scanId, this.deps.calls.totals(scanId));
    };
    if (elapsed >= USAGE_EMIT_INTERVAL_MS) {
      fire();
      return;
    }
    const timer = setTimeout(fire, USAGE_EMIT_INTERVAL_MS - elapsed);
    timer.unref?.();
    this.pendingUsageEmit.set(scanId, timer);
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

/** Response block → request param for the transcript (thinking blocks passed back verbatim, as the API requires with tools). */
function toParam(b: Anthropic.ContentBlock): Anthropic.ContentBlockParam[] {
  switch (b.type) {
    case 'text': return [{ type: 'text', text: b.text }];
    case 'thinking': return [{ type: 'thinking', thinking: b.thinking, signature: b.signature }];
    case 'redacted_thinking': return [{ type: 'redacted_thinking', data: b.data }];
    case 'tool_use': return [{ type: 'tool_use', id: b.id, name: b.name, input: b.input }];
    default: return []; // server-tool blocks: we never offer server tools
  }
}

/** Copy of the transcript whose last block carries a cache breakpoint (the stored transcript stays unmarked). */
function withCacheTail(messages: Anthropic.MessageParam[]): Anthropic.MessageParam[] {
  const last = messages.at(-1);
  if (!last || typeof last.content === 'string' || last.content.length === 0) return messages;
  const blocks = [...last.content];
  const tail = blocks[blocks.length - 1]!;
  if (tail.type === 'thinking' || tail.type === 'redacted_thinking') return messages;
  blocks[blocks.length - 1] = { ...tail, cache_control: { type: 'ephemeral' } } as Anthropic.ContentBlockParam;
  return [...messages.slice(0, -1), { ...last, content: blocks }];
}

function toolDefOf(tool: AgentTool): LlmToolDef {
  const { $schema: _ignored, ...schema } = z.toJSONSchema(tool.input, { io: 'input' }) as Record<string, unknown>;
  if (schema.type !== 'object') throw new AppError('INTERNAL', 'permanent', `Agent tool "${tool.name}" needs an object input schema`);
  return { name: tool.name, description: tool.description, input_schema: schema as Anthropic.Tool.InputSchema };
}

function truncateResult(text: string): string {
  if (text.length <= AGENT_TOOL_RESULT_MAX_CHARS) return text;
  return `${text.slice(0, AGENT_TOOL_RESULT_MAX_CHARS)}\n…[truncated ${text.length - AGENT_TOOL_RESULT_MAX_CHARS} chars]`;
}

function addUsage(a: TokenUsage, b: TokenUsage): TokenUsage {
  return {
    inputTokens: a.inputTokens + b.inputTokens, outputTokens: a.outputTokens + b.outputTokens,
    cacheReadTokens: a.cacheReadTokens + b.cacheReadTokens, cacheWriteTokens: a.cacheWriteTokens + b.cacheWriteTokens,
  };
}
