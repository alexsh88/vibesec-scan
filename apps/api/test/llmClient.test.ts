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

function setup(steps: Step[], opts: { budgetUsd?: number; semaphore?: Semaphore } = {}) {
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
  });
  const call = (over: Partial<StructuredCall<z.infer<typeof Out>>> = {}): StructuredCall<z.infer<typeof Out>> => ({
    scanId, analyzer: 'sast', purpose: 'review-file', promptVersion: 'v1', role: 'deep',
    system: 'You review code.', prompt: 'review', schema: Out, signal: new AbortController().signal, ...over,
  });
  return { client, call, calls, scans, scanId, seen, transport, penalize, onUsage, budget };
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
