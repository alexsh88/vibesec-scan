import type Anthropic from '@anthropic-ai/sdk';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ScanOptionsSchema } from '@vibesec/shared';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { BudgetTracker } from '../src/llm/budget';
import { LlmClient, type StructuredCall } from '../src/llm/LlmClient';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import type { LlmRequest, LlmTransport } from '../src/llm/transport';
import { memoryDb } from './helpers';

const Out = z.object({ verdict: z.enum(['safe', 'vulnerable']), reason: z.string() });

type Step = { text?: string; stop?: Anthropic.Message['stop_reason']; error?: AppError };
const msg = (model: string, text: string, stop: Anthropic.Message['stop_reason'] = 'end_turn') => ({
  id: 'm', type: 'message', role: 'assistant', model, content: [{ type: 'text', text, citations: null }], stop_reason: stop,
  stop_sequence: null, usage: { input_tokens: 1_000, output_tokens: 100, cache_read_input_tokens: 500, cache_creation_input_tokens: 0 },
}) as unknown as Anthropic.Message;

function setup(steps: Step[], opts: { budgetUsd?: number; semaphore?: Semaphore; now?: () => number } = {}) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({ repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false }).id;
  const calls = new LlmCallRepo(db);
  const seen: LlmRequest[] = [];
  const transport: LlmTransport = {
    mode: 'mock',
    send: vi.fn(async (req: LlmRequest) => {
      seen.push(req);
      const step = steps.shift() ?? { text: JSON.stringify({ verdict: 'safe', reason: 'default' }) };
      if (step.error) throw step.error;
      return msg(req.model, step.text ?? '', step.stop ?? 'end_turn');
    }),
  };
  const limiter = new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 10_000_000 });
  const penalize = vi.spyOn(limiter, 'penalize');
  const onUsage = vi.fn();
  const budget = new BudgetTracker(opts.budgetUsd ?? 5, (id) => scans.getDto(id)?.costUsd ?? 0);
  const client = new LlmClient({
    transport, models: { fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' },
    limiter, semaphore: opts.semaphore ?? new Semaphore(4), budget, calls, scans, onUsage, retryDeps: { sleep: async () => {} },
    atomically: (fn) => db.transaction(fn)(), now: opts.now,
  });
  const call = (over: Partial<StructuredCall<z.infer<typeof Out>>> = {}): StructuredCall<z.infer<typeof Out>> => ({
    scanId, analyzer: 'sast', purpose: 'review-file', promptVersion: 'v1', role: 'deep',
    system: 'You review code.', prompt: 'review', schema: Out, signal: new AbortController().signal, ...over,
  });
  return { client, call, calls, scans, scanId, seen, transport, penalize, onUsage, budget, db };
}

const ok = (verdict = 'vulnerable') => ({ text: JSON.stringify({ verdict, reason: 'sql injection' }) });
const transient = () => ({ error: new AppError('LLM_UNAVAILABLE', 'transient', 'overloaded') });

describe('LlmClient.structured', () => {
  it('returns parsed output and records usage, cost and SSE totals', async () => {
    const { client, call, calls, scans, scanId, seen, onUsage } = setup([ok()]);
    const r = await client.structured(call());
    expect(r.output).toEqual({ verdict: 'vulnerable', reason: 'sql injection' });
    expect(r).toMatchObject({ model: 'claude-sonnet-5', degraded: false, fellBackOnRefusal: false });
    expect(seen[0]).toMatchObject({ model: 'claude-sonnet-5', thinking: true, effort: 'medium' });
    expect(calls.totals(scanId)).toMatchObject({ calls: 1, inputTokens: 1_000, outputTokens: 100, cacheReadTokens: 500 });
    expect(scans.getDto(scanId)!.costUsd).toBeCloseTo(r.costUsd, 9);
    expect(onUsage).toHaveBeenCalledWith(scanId, expect.objectContaining({ calls: 1 }));
  });

  it('sends neither thinking nor effort to the fast tier (Haiku)', async () => {
    const { client, call, seen } = setup([ok()]);
    await client.structured(call({ role: 'fast' }));
    expect(seen[0]).toMatchObject({ model: 'claude-haiku-4-5', thinking: false, effort: undefined });
  });

  it('repairs invalid JSON once with the validation issues', async () => {
    const { client, call, seen } = setup([{ text: '{"verdict":"maybe"}' }, ok()]);
    await expect(client.structured(call())).resolves.toMatchObject({ output: { verdict: 'vulnerable' } });
    const repairTurn = JSON.stringify(seen[1]!.messages);
    expect(repairTurn).toContain('verdict');
    expect(seen[1]!.messages.at(-2)).toMatchObject({ role: 'assistant', content: [{ type: 'text', text: '{"verdict":"maybe"}' }] });
    expect(JSON.stringify(seen[1]!.messages.at(-1))).toContain('reason');
  });

  it('gives up with LLM_OUTPUT_INVALID after a failed repair', async () => {
    const { client, call, transport } = setup([{ text: 'not json' }, { text: '{"nope":1}' }]);
    await expect(client.structured(call())).rejects.toMatchObject({ code: 'LLM_OUTPUT_INVALID' });
    expect(transport.send).toHaveBeenCalledTimes(2);
  });

  it('falls back to another tier once on refusal, then fails with LLM_REFUSAL', async () => {
    const a = setup([{ text: '', stop: 'refusal' }, ok()]);
    const r = await a.client.structured(a.call());
    expect(r).toMatchObject({ model: 'claude-opus-5', fellBackOnRefusal: true });
    const b = setup([{ text: '', stop: 'refusal' }, { text: '', stop: 'refusal' }]);
    await expect(b.client.structured(b.call())).rejects.toMatchObject({ code: 'LLM_REFUSAL', kind: 'permanent' });
    expect(b.transport.send).toHaveBeenCalledTimes(2);
  });

  it('signals truncation so callers can split their batch', async () => {
    const { client, call, transport } = setup([{ text: '{"verdict":', stop: 'max_tokens' }]);
    await expect(client.structured(call())).rejects.toMatchObject({ code: 'LLM_OUTPUT_INVALID', details: { truncated: true } });
    expect(transport.send).toHaveBeenCalledOnce();
  });

  it('retries transient failures and records each failed attempt', async () => {
    const { client, call, calls, scanId } = setup([transient(), transient(), ok()]);
    await expect(client.structured(call())).resolves.toBeDefined();
    expect(calls.totals(scanId)).toMatchObject({ calls: 3, failedCalls: 2 });
  });

  it('degrades one tier down when the model stays unavailable', async () => {
    // RETRY_POLICIES.anthropic.retries = 4 → 5 attempts on the requested tier, then success one tier down.
    const { client, call, seen } = setup([transient(), transient(), transient(), transient(), transient(), ok()]);
    await expect(client.structured(call())).resolves.toMatchObject({ model: 'claude-haiku-4-5', degraded: true });
    expect(seen.map((s) => s.model)).toEqual([...Array(5).fill('claude-sonnet-5'), 'claude-haiku-4-5']);
  });

  it('does not degrade on permanent failures', async () => {
    const { client, call, transport } = setup([{ error: new AppError('LLM_UNAVAILABLE', 'permanent', 'bad request') }]);
    await expect(client.structured(call())).rejects.toMatchObject({ kind: 'permanent' });
    expect(transport.send).toHaveBeenCalledOnce();
  });

  it('penalizes the rate limiter on rate-limit errors', async () => {
    const rateLimited = { error: new AppError('LLM_UNAVAILABLE', 'transient', 'rl', { details: { rateLimited: true } }) };
    const { client, call, penalize } = setup([rateLimited, ok()]);
    await client.structured(call());
    expect(penalize).toHaveBeenCalledOnce();
  });

  it('refuses to call the model once the scan budget is exhausted', async () => {
    const { client, call, transport, budget, scanId } = setup([ok()], { budgetUsd: 1 });
    budget.add(scanId, 1);
    await expect(client.structured(call())).rejects.toMatchObject({ code: 'BUDGET_EXHAUSTED', kind: 'budget' });
    expect(transport.send).not.toHaveBeenCalled();
  });

  it('checks the budget again before the repair send', async () => {
    // First call costs (1000*2 + 100*10 + 500*0.2)/1e6 = 0.0031 USD, which exhausts a 0.003 USD budget.
    const { client, call, transport } = setup([{ text: 'not json' }, ok()], { budgetUsd: 0.003 });
    await expect(client.structured(call())).rejects.toMatchObject({ code: 'BUDGET_EXHAUSTED' });
    expect(transport.send).toHaveBeenCalledOnce();
  });

  it('reserves worst-case cost per attempt; a call blocked only by in-flight reservations waits, then runs', async () => {
    // Worst case per call: deep = claude-sonnet-5, output $10/1M × 4_000 max tokens = $0.04, plus a few
    // input tokens at $2/1M ≈ $0.0001. A $0.10 budget fits two such reservations, never a third at once.
    const { client, call, transport, budget, scanId } = setup([], { budgetUsd: 0.1 });
    const gates: Array<() => void> = [];
    vi.mocked(transport.send).mockImplementation(async (req: LlmRequest) => {
      await new Promise<void>((resolve) => gates.push(resolve));
      return msg(req.model, JSON.stringify({ verdict: 'safe', reason: 'ok' }));
    });
    const c = call({ maxTokens: 4_000 });
    const first = client.structured(c);
    const second = client.structured(c);
    await vi.waitFor(() => expect(transport.send).toHaveBeenCalledTimes(2));
    expect(budget.reservedUsd(scanId)).toBeGreaterThan(0.08);
    expect(budget.reservedUsd(scanId)).toBeLessThan(0.1);

    const third = client.structured(c);
    await new Promise((r) => setTimeout(r, 20));
    expect(transport.send).toHaveBeenCalledTimes(2); // waiting on the in-flight reservations, not failed
    expect(budget.reservedUsd(scanId)).toBeLessThan(0.1);

    gates.splice(0).forEach((release) => release());
    const results = await Promise.all([first, second]);
    // Actual usage per call: (1000×2 + 100×10 + 500×0.2)/1e6 = $0.0031 — far below the reserved worst case.
    expect(results.map((r) => r.costUsd)).toEqual([expect.closeTo(0.0031, 9), expect.closeTo(0.0031, 9)]);
    await vi.waitFor(() => expect(transport.send).toHaveBeenCalledTimes(3));
    gates.splice(0).forEach((release) => release());
    await expect(third).resolves.toMatchObject({ costUsd: expect.closeTo(0.0031, 9) });
    expect(budget.reservedUsd(scanId)).toBe(0);
    expect(budget.spentUsd(scanId)).toBeCloseTo(0.0093, 9);
  });

  it('fails with BUDGET_EXHAUSTED when committed spend alone leaves no room for the worst case', async () => {
    const { client, call, transport, budget, scanId } = setup([ok()], { budgetUsd: 0.1 });
    budget.add(scanId, 0.07); // 0.07 + ~0.0401 worst case > 0.10 with nothing in flight → waiting cannot help
    await expect(client.structured(call({ maxTokens: 4_000 }))).rejects.toMatchObject({ code: 'BUDGET_EXHAUSTED', kind: 'budget' });
    expect(transport.send).not.toHaveBeenCalled();
  });

  it('lets 8 concurrent deep calls finish on the last $1 of a $5 budget (no spurious BUDGET_EXHAUSTED)', async () => {
    // Review scenario: $4 committed; each call's worst case at 16_000 max tokens ≈ $0.16 (so the
    // reservations do not all fit at once) but each actually costs ≈ $0.05.
    const { client, call, transport, budget, scanId } = setup([], { budgetUsd: 5, semaphore: new Semaphore(8) });
    budget.add(scanId, 4);
    vi.mocked(transport.send).mockImplementation(async (req: LlmRequest) => {
      await new Promise((r) => setTimeout(r, 5));
      const m = msg(req.model, JSON.stringify({ verdict: 'safe', reason: 'ok' }));
      // (1000×2 + 4_800×10 + 500×0.2)/1e6 = $0.0501
      return { ...m, usage: { ...m.usage, output_tokens: 4_800 } } as Anthropic.Message;
    });
    const results = await Promise.all(Array.from({ length: 8 }, () => client.structured(call({ maxTokens: 16_000 }))));
    expect(results).toHaveLength(8);
    expect(results.every((r) => Math.abs(r.costUsd - 0.0501) < 1e-9)).toBe(true);
    expect(budget.spentUsd(scanId)).toBeCloseTo(4 + 8 * 0.0501, 9);
    expect(budget.reservedUsd(scanId)).toBe(0);
  });

  it('uses per-role default max_tokens for the role actually sent (after degrade)', async () => {
    const { client, call, seen } = setup([transient(), transient(), transient(), transient(), transient(), ok()]);
    await client.structured(call({ role: 'deep' }));
    expect(seen[0]).toMatchObject({ model: 'claude-sonnet-5', maxTokens: 8_192 });
    expect(seen.at(-1)).toMatchObject({ model: 'claude-haiku-4-5', maxTokens: 4_096 });
    const s = setup([ok()]);
    await s.client.structured(s.call({ role: 'synthesis' }));
    expect(s.seen[0]).toMatchObject({ maxTokens: 16_000 });
    const explicit = setup([ok()]);
    await explicit.client.structured(explicit.call({ maxTokens: 1_234 }));
    expect(explicit.seen[0]).toMatchObject({ maxTokens: 1_234 });
  });

  it('coalesces cost events to at most one per second per scan, ending with the full totals', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const { client, call, onUsage, scanId, calls } = setup([], { now: () => 1_000_000 });
      for (let i = 0; i < 5; i++) await client.structured(call());
      expect(onUsage).toHaveBeenCalledTimes(1); // leading emit; the rest coalesce into one trailing emit
      vi.advanceTimersByTime(1_000);
      expect(onUsage).toHaveBeenCalledTimes(2);
      expect(onUsage).toHaveBeenLastCalledWith(scanId, expect.objectContaining({ calls: 5 }));
      expect(onUsage.mock.lastCall![1]).toEqual(calls.totals(scanId));
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not emit cost events for zero-cost (failed) attempts', async () => {
    const { client, call, onUsage, calls, scanId } = setup([{ error: new AppError('LLM_UNAVAILABLE', 'permanent', 'x') }]);
    await expect(client.structured(call())).rejects.toMatchObject({ kind: 'permanent' });
    expect(calls.totals(scanId)).toMatchObject({ calls: 1, failedCalls: 1 });
    expect(onUsage).not.toHaveBeenCalled();
  });

  it('records the call row and the scan cost atomically; the budget still counts a cost whose insert failed', async () => {
    // Conservative by design: the budget is settled with the actual cost BEFORE the DB transaction, so a
    // failed write never lets in-memory spend under-count money really spent at the API.
    const { client, call, calls, scans, scanId, budget, db } = setup([ok()]);
    const realInsert = calls.insert.bind(calls);
    vi.spyOn(calls, 'insert').mockImplementation((c) => {
      realInsert(c); // the row is written, then the insert fails → the transaction must roll it back
      throw new Error('disk full');
    });
    await expect(client.structured(call())).rejects.toMatchObject({ code: 'INTERNAL' });
    expect((db.prepare('SELECT COUNT(*) AS n FROM llm_calls').get() as { n: number }).n).toBe(0);
    expect(scans.getDto(scanId)!.costUsd).toBe(0);
    expect(budget.spentUsd(scanId)).toBeCloseTo(0.0031, 9);
    expect(budget.reservedUsd(scanId)).toBe(0);
  });

  it('exposes circuit-breaker trips', () => {
    expect(setup([]).client.breakerTrips).toBe(0);
  });

  it('frees the reservation of a failed attempt', async () => {
    const { client, call, budget, scanId } = setup([{ error: new AppError('LLM_UNAVAILABLE', 'permanent', 'x') }]);
    await expect(client.structured(call())).rejects.toMatchObject({ kind: 'permanent' });
    expect(budget.reservedUsd(scanId)).toBe(0);
    expect(budget.spentUsd(scanId)).toBe(0);
  });

  it('does not retry permanent errors and stops on cancellation', async () => {
    const perm = setup([{ error: new AppError('LLM_UNAVAILABLE', 'permanent', 'bad key') }]);
    await expect(perm.client.structured(perm.call())).rejects.toMatchObject({ kind: 'permanent' });
    expect(perm.transport.send).toHaveBeenCalledOnce();
    const ac = new AbortController();
    ac.abort();
    const c = setup([ok()]);
    await expect(c.client.structured(c.call({ signal: ac.signal }))).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(c.transport.send).not.toHaveBeenCalled();
  });

  it('does not record cancelled attempts', async () => {
    const { client, call, calls, scanId } = setup([{ error: new AppError('CANCELLED', 'cancelled', 'stop') }]);
    await expect(client.structured(call())).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(calls.totals(scanId)).toMatchObject({ calls: 0 });
  });

  it('always releases the semaphore slot, even on failure', async () => {
    const semaphore = new Semaphore(1);
    const { client, call } = setup([{ text: '', stop: 'max_tokens' }, { error: new AppError('LLM_UNAVAILABLE', 'permanent', 'x') }, ok()], { semaphore });
    await expect(client.structured(call())).rejects.toMatchObject({ code: 'LLM_OUTPUT_INVALID' });
    await expect(client.structured(call())).rejects.toMatchObject({ kind: 'permanent' });
    await expect(client.structured(call())).resolves.toBeDefined();
  });

  it('works without a scan (no cost attribution)', async () => {
    const { client, call, calls, scans, scanId, onUsage } = setup([ok()]);
    await expect(client.structured(call({ scanId: null }))).resolves.toMatchObject({ output: { verdict: 'vulnerable' } });
    expect(onUsage).not.toHaveBeenCalled();
    expect(scans.getDto(scanId)!.costUsd).toBe(0);
    expect(calls.totals(scanId)).toMatchObject({ calls: 0 });
  });
});
