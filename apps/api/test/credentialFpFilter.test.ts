import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type Anthropic from '@anthropic-ai/sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ScanOptionsSchema } from '@vibesec/shared';
import type { SecretCandidate } from '../src/analyzers/credentials/scanText';
import {
  credentialsFpMockResponder, FP_FILTER_PROMPT_VERSION, filterCandidates, shouldDrop, type FpVerdict,
} from '../src/analyzers/credentials/fpFilter';
import { loadConfig } from '../src/config';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { BudgetTracker } from '../src/llm/budget';
import { createTransport } from '../src/llm/createTransport';
import { LlmClient, type StructuredCall, type StructuredResult } from '../src/llm/LlmClient';
import type { MockResponder } from '../src/llm/mockTransport';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import type { LlmRequest, LlmTransport } from '../src/llm/transport';
import { memoryDb } from './helpers';

type FpOutput = { results: Array<{ id: string; isLikelyReal: boolean; confidence: 'high' | 'medium' | 'low'; reason: string }> };

const ZERO_USAGE = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };

function candidate(over: Partial<SecretCandidate> & { id: string }): SecretCandidate {
  return {
    type: 'generic-secret', file: 'src/app.ts', line: 10, endLine: 10, startCol: 0,
    value: 'RAW-SECRET-VALUE-NEVER-SENT', redacted: 'RAW…ENT', hash: 'h', snippet: 'const token = "RAW…ENT";',
    clientExposed: false, source: 'tree' as const,
    ...over,
  };
}

/** A `Pick<LlmClient, 'structured'>` stub: no transport/DB involved — just the StructuredCall it was given. */
function stubLlm(impl: (call: StructuredCall<FpOutput>) => Promise<StructuredResult<FpOutput>>): {
  llm: Pick<LlmClient, 'structured'>;
  calls: StructuredCall<FpOutput>[];
} {
  const calls: StructuredCall<FpOutput>[] = [];
  const structured = async (call: StructuredCall<FpOutput>) => {
    calls.push(call);
    return impl(call);
  };
  return { llm: { structured: structured as unknown as LlmClient['structured'] }, calls };
}

function okResult(results: FpOutput['results']): StructuredResult<FpOutput> {
  return { output: { results }, model: 'claude-haiku-4-5', usage: ZERO_USAGE, costUsd: 0, callIds: ['c'], degraded: false, fellBackOnRefusal: false };
}

/** A minimal real LlmClient (DB-backed) wired to a given transport — for tests that must inspect
 *  the actual LlmRequest the transport receives (post buildRequestParts). */
function buildRealClient(transport: LlmTransport) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({
    repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false,
  }).id;
  const calls = new LlmCallRepo(db);
  const limiter = new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 10_000_000 });
  const budget = new BudgetTracker(5, (id) => scans.getDto(id)?.costUsd ?? 0);
  const client = new LlmClient({
    transport, models: { fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' },
    limiter, semaphore: new Semaphore(4), budget, calls, scans, retryDeps: { sleep: async () => {} },
    atomically: (fn) => db.transaction(fn)(),
  });
  return { client, scanId };
}

function capturingTransport(respond: (req: LlmRequest) => unknown): { transport: LlmTransport; seen: LlmRequest[] } {
  const seen: LlmRequest[] = [];
  const transport: LlmTransport = {
    mode: 'mock',
    send: vi.fn(async (req: LlmRequest) => {
      seen.push(req);
      const text = JSON.stringify(respond(req));
      return {
        id: 'm', type: 'message', role: 'assistant', model: req.model,
        content: [{ type: 'text', text, citations: null }],
        stop_reason: 'end_turn', stop_sequence: null,
        usage: { input_tokens: 10, output_tokens: 10, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
      } as unknown as Anthropic.Message;
    }),
  };
  return { transport, seen };
}

describe('filterCandidates', () => {
  it('skips high-precision prefixed types and only sends judgement types, batched at <= batchSize', async () => {
    const judged = Array.from({ length: 45 }, (_, i) => candidate({ id: `j${i}`, type: 'jwt', file: `src/f${i}.ts` }));
    const skipped = [
      candidate({ id: 's1', type: 'github-token' }),
      candidate({ id: 's2', type: 'aws-access-key' }),
      candidate({ id: 's3', type: 'stripe-secret-key' }),
      candidate({ id: 's4', type: 'stripe-restricted-key' }),
      candidate({ id: 's5', type: 'slack-token' }),
      candidate({ id: 's6', type: 'slack-webhook' }),
      candidate({ id: 's7', type: 'openai-api-key' }),
      candidate({ id: 's8', type: 'anthropic-api-key' }),
      candidate({ id: 's9', type: 'sendgrid-api-key' }),
      candidate({ id: 's10', type: 'twilio-api-key' }),
      candidate({ id: 's11', type: 'supabase-service-role' }),
    ];
    const { llm, calls } = stubLlm(async () => okResult([]));

    await filterCandidates(llm, 'scan1', [...judged, ...skipped], new AbortController().signal);

    expect(calls).toHaveLength(3); // ceil(45 / 20)
    for (const call of calls) {
      expect(call).toMatchObject({ role: 'fast', analyzer: 'credentials', purpose: 'fp-filter', promptVersion: FP_FILTER_PROMPT_VERSION });
    }
    const allPrompts = calls.map((c) => c.prompt).join('\n');
    for (const s of skipped) expect(allPrompts).not.toContain(`id="${s.id}"`);
    for (const j of judged) expect(allPrompts).toContain(`id="${j.id}"`);
  });

  it('honors a custom batchSize', async () => {
    const cands = Array.from({ length: 5 }, (_, i) => candidate({ id: `c${i}`, type: 'database-url' }));
    const { llm, calls } = stubLlm(async () => okResult([]));
    await filterCandidates(llm, 'scan1', cands, new AbortController().signal, { batchSize: 2 });
    expect(calls).toHaveLength(3); // ceil(5/2)
  });

  it('returns an empty map without calling the LLM when no candidate needs judgement', async () => {
    const { llm, calls } = stubLlm(async () => okResult([]));
    const verdicts = await filterCandidates(llm, 'scan1', [candidate({ id: 'g1', type: 'github-token' })], new AbortController().signal);
    expect(calls).toHaveLength(0);
    expect(verdicts.size).toBe(0);
  });

  it('maps verdicts by id; ignores unknown ids; leaves ids missing from the response absent', async () => {
    const c1 = candidate({ id: 'c1', type: 'jwt' });
    const c2 = candidate({ id: 'c2', type: 'database-url' });
    const c3 = candidate({ id: 'c3', type: 'private-key' });
    const { llm } = stubLlm(async () => okResult([
      { id: 'c1', isLikelyReal: true, confidence: 'high', reason: 'looks real' },
      { id: 'not-a-real-candidate-id', isLikelyReal: false, confidence: 'low', reason: 'nope' },
    ]));

    const verdicts = await filterCandidates(llm, 'scan1', [c1, c2, c3], new AbortController().signal);

    expect(verdicts.get('c1')).toEqual({ isLikelyReal: true, confidence: 'high', reason: 'looks real' });
    expect(verdicts.has('not-a-real-candidate-id')).toBe(false);
    expect(verdicts.has('c2')).toBe(false);
    expect(verdicts.has('c3')).toBe(false);
  });

  it('fails open on a non-cancellation error: warns once, keeps no verdicts, does not throw', async () => {
    const cands = Array.from({ length: 4 }, (_, i) => candidate({ id: `c${i}`, type: 'jwt' }));
    const { llm, calls } = stubLlm(async () => { throw new AppError('LLM_UNAVAILABLE', 'transient', 'overloaded'); });
    const warn = vi.fn();

    const verdicts = await filterCandidates(llm, 'scan1', cands, new AbortController().signal, { batchSize: 2, warn });

    expect(calls).toHaveLength(2); // both batches attempted
    expect(verdicts.size).toBe(0);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith('CREDENTIALS_FP_FILTER_UNAVAILABLE', expect.any(String));
  });

  it('keeps verdicts from batches that succeed even when another batch fails', async () => {
    const cands = Array.from({ length: 4 }, (_, i) => candidate({ id: `c${i}`, type: 'jwt' }));
    let n = 0;
    const { llm } = stubLlm(async () => {
      n += 1;
      if (n === 1) throw new AppError('LLM_UNAVAILABLE', 'transient', 'overloaded');
      return okResult([
        { id: 'c2', isLikelyReal: true, confidence: 'high', reason: 'real' },
        { id: 'c3', isLikelyReal: false, confidence: 'medium', reason: 'fixture' },
      ]);
    });
    const warn = vi.fn();

    const verdicts = await filterCandidates(llm, 'scan1', cands, new AbortController().signal, { batchSize: 2, warn });

    expect(verdicts.get('c2')).toMatchObject({ isLikelyReal: true });
    expect(verdicts.get('c3')).toMatchObject({ isLikelyReal: false });
    expect(verdicts.has('c0')).toBe(false);
    expect(verdicts.has('c1')).toBe(false);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('rethrows an AppError cancellation instead of failing open', async () => {
    const cands = [candidate({ id: 'c1', type: 'jwt' })];
    const { llm } = stubLlm(async () => { throw new AppError('CANCELLED', 'cancelled', 'stop'); });
    const warn = vi.fn();

    await expect(filterCandidates(llm, 'scan1', cands, new AbortController().signal, { warn }))
      .rejects.toMatchObject({ code: 'CANCELLED' });
    expect(warn).not.toHaveBeenCalled();
  });

  it('rethrows on an aborted signal even when the error is a generic AbortError', async () => {
    const cands = [candidate({ id: 'c1', type: 'jwt' })];
    const abortErr = Object.assign(new Error('aborted'), { name: 'AbortError' });
    const { llm } = stubLlm(async () => { throw abortErr; });

    await expect(filterCandidates(llm, 'scan1', cands, new AbortController().signal))
      .rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('never sends the raw value or pairedSecret to the transport', async () => {
    const RAW = 'sk-super-secret-RAW-VALUE-1234567890';
    const PAIRED = 'PAIRED-RAW-SECRET-abcdef0123456789';
    const cand = candidate({
      id: 'cX', type: 'generic-secret', value: RAW, pairedSecret: PAIRED,
      redacted: 'sk-s…890', snippet: 'const key = "sk-s…890";',
    });
    const { transport, seen } = capturingTransport(() => ({ results: [] }));
    const { client, scanId } = buildRealClient(transport);

    await filterCandidates(client, scanId, [cand], new AbortController().signal);

    expect(seen.length).toBeGreaterThan(0);
    for (const req of seen) {
      const text = JSON.stringify(req.system) + JSON.stringify(req.messages);
      expect(text).not.toContain(RAW);
      expect(text).not.toContain(PAIRED);
      expect(text).toContain('sk-s…890'); // the redacted form is expected to be present
    }
  });
});

describe('shouldDrop', () => {
  const v = (isLikelyReal: boolean, confidence: FpVerdict['confidence']): FpVerdict => ({ isLikelyReal, confidence, reason: 'r' });

  it.each([
    [v(false, 'high'), true],
    [v(false, 'medium'), true],
    [v(false, 'low'), false],
    [v(true, 'high'), false],
    [v(true, 'medium'), false],
    [v(true, 'low'), false],
    [undefined, false],
  ] as const)('shouldDrop(%o) -> %s', (verdict, expected) => {
    expect(shouldDrop(verdict)).toBe(expected);
  });
});

describe('credentialsFpMockResponder', () => {
  it('ignores requests whose system prompt does not carry the FP filter task marker', () => {
    const req: LlmRequest = {
      model: 'claude-haiku-4-5', system: [{ type: 'text', text: 'some other task' }],
      messages: [{ role: 'user', content: [{ type: 'text', text: '<candidate id="x" path="y"></candidate>' }] }],
      maxTokens: 100, thinking: false, schema: z.object({}),
    };
    expect(credentialsFpMockResponder(req)).toBeUndefined();
  });

  it('produces schema-valid verdicts end-to-end through createTransport: drops a test path, keeps a src path', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vibesec-fp-'));
    try {
      const config = loadConfig({ SCAN_MODE: 'mock', LLM_RECORDINGS_DIR: dir });
      const transport = createTransport(config, [credentialsFpMockResponder]);
      const { client, scanId } = buildRealClient(transport);
      const testCand = candidate({ id: 'test-cand', type: 'jwt', file: 'test/fixtures/secrets.ts' });
      const srcCand = candidate({ id: 'src-cand', type: 'jwt', file: 'src/config.ts' });

      const verdicts = await filterCandidates(client, scanId, [testCand, srcCand], new AbortController().signal);

      expect(shouldDrop(verdicts.get('test-cand'))).toBe(true);
      expect(shouldDrop(verdicts.get('src-cand'))).toBe(false);
      expect(verdicts.get('src-cand')?.isLikelyReal).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('createTransport', () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vibesec-ct-')); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it('still returns a MockTransport in mock mode with no responders (default param)', () => {
    const config = loadConfig({ SCAN_MODE: 'mock', LLM_RECORDINGS_DIR: dir });
    const transport = createTransport(config);
    expect(transport.mode).toBe('mock');
  });

  it('passes responders through to MockTransport in mock mode', async () => {
    const config = loadConfig({ SCAN_MODE: 'mock', LLM_RECORDINGS_DIR: dir });
    const responder: MockResponder = () => ({ sentinel: true });
    const transport = createTransport(config, [responder]);

    const req: LlmRequest = {
      model: 'claude-haiku-4-5', system: [{ type: 'text', text: 's' }],
      messages: [{ role: 'user', content: [{ type: 'text', text: 'hi' }] }],
      maxTokens: 100, thinking: false, schema: z.object({ sentinel: z.boolean() }),
    };
    const message = await transport.send(req, new AbortController().signal);
    const text = message.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('');
    expect(JSON.parse(text)).toEqual({ sentinel: true });
  });

  it('returns a live AnthropicTransport in live mode (responders are ignored there)', () => {
    const config = loadConfig({ SCAN_MODE: 'live', ANTHROPIC_API_KEY: 'sk-ant-test-key' });
    const transport = createTransport(config, [credentialsFpMockResponder]);
    expect(transport.mode).toBe('live');
  });

  it('returns a RecordingTransport in record mode', () => {
    const config = loadConfig({ SCAN_MODE: 'record', ANTHROPIC_API_KEY: 'sk-ant-test-key', LLM_RECORDINGS_DIR: dir });
    const transport = createTransport(config);
    expect(transport.mode).toBe('record');
  });
});
