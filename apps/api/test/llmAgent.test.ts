import type Anthropic from '@anthropic-ai/sdk';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ScanOptionsSchema } from '@vibesec/shared';
import { LlmCallRepo } from '../src/db/llmCallRepo';
import { ScanRepo } from '../src/db/scanRepo';
import { AppError } from '../src/errors/AppError';
import { BudgetTracker } from '../src/llm/budget';
import { AGENT_TOOL_RESULT_MAX_CHARS, defineTool, LlmClient, type AgentCall, type AgentTool } from '../src/llm/LlmClient';
import { MockTransport, mockRefusal, mockText, mockToolUse, mockToolUses, mockTurnIndex, type MockResponder } from '../src/llm/mockTransport';
import { RateLimiter, Semaphore } from '../src/llm/rateLimiter';
import { requestHash, type LlmRequest, type LlmTransport } from '../src/llm/transport';
import { memoryDb } from './helpers';

const Flow = z.object({ title: z.string(), line: z.number().int().positive() });
type Flow = z.infer<typeof Flow>;

function setup(opts: { responders?: MockResponder[]; transport?: LlmTransport; budgetUsd?: number } = {}) {
  const db = memoryDb();
  const scans = new ScanRepo(db);
  const repo = scans.upsertRepo({ owner: 'acme', name: 'app', isPrivate: false });
  const scanId = scans.insertScan({ repoId: repo.id, ref: null, options: ScanOptionsSchema.parse({}), optionsHash: 'h', idempotencyKey: null, hasAuth: false }).id;
  const calls = new LlmCallRepo(db);
  const seen: LlmRequest[] = [];
  const inner = opts.transport ?? new MockTransport({ responders: opts.responders ?? [] });
  const transport: LlmTransport = { mode: inner.mode, send: vi.fn(async (req: LlmRequest, signal: AbortSignal) => { seen.push(structuredClone({ ...req, schema: undefined })); return inner.send(req, signal); }) };
  const onUsage = vi.fn();
  const budget = new BudgetTracker(opts.budgetUsd ?? 5, (id) => scans.getDto(id)?.costUsd ?? 0);
  const client = new LlmClient({
    transport, models: { fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' },
    limiter: new RateLimiter({ requestsPerMinute: 1_000, inputTokensPerMinute: 10_000_000 }), semaphore: new Semaphore(4),
    budget, calls, scans, onUsage, retryDeps: { sleep: async () => {} }, atomically: (fn) => db.transaction(fn)(),
  });
  const readFile = vi.fn((input: { path: string }) => `contents of ${input.path}`);
  const tools: AgentTool[] = [
    defineTool({ name: 'read_file', description: 'Read a file', input: z.object({ path: z.string() }), run: readFile }),
    defineTool({ name: 'report_flow', description: 'Report a flow', input: Flow, run: () => 'Recorded.' }),
  ];
  const call = (over: Partial<AgentCall<Flow>> = {}): AgentCall<Flow> => ({
    scanId, analyzer: 'taint', purpose: 'trace', promptVersion: 'v1', role: 'deep', system: 'You trace taint.',
    prompt: 'Trace req.query.id', tools, finishTool: 'report_flow', signal: new AbortController().signal, ...over,
  });
  return { client, call, calls, scans, scanId, seen, transport, onUsage, budget, readFile, tools };
}

/** Text of the tool_result blocks in the last user message of a request. */
function lastToolResults(req: LlmRequest): Array<{ content: string; is_error?: boolean; tool_use_id: string }> {
  const last = req.messages.at(-1)!;
  return (last.content as Anthropic.ContentBlockParam[]).filter((b) => b.type === 'tool_result') as never;
}

const flow = { title: 'SQL injection', line: 12 };

describe('LlmClient.agent', () => {
  it('runs a scripted multi-turn loop: tool call → result fed back → finish tool → end', async () => {
    const script: MockResponder = (req) => [
      mockToolUse('read_file', { path: 'src/db.ts' }),
      mockToolUse('report_flow', flow),
      mockText('Done.'),
    ][mockTurnIndex(req)];
    const { client, call, seen, readFile, calls, scanId, scans, onUsage } = setup({ responders: [script] });
    const r = await client.agent(call());
    expect(r).toMatchObject({ finished: [flow], turns: 3, stopReason: 'end_turn', degraded: false, model: 'claude-sonnet-5' });
    expect(readFile).toHaveBeenCalledWith({ path: 'src/db.ts' }, expect.objectContaining({ signal: expect.any(AbortSignal) }));
    // turn 2 sees the tool result of turn 1, paired with the tool_use id
    const assistant = seen[1]!.messages.at(-2)!;
    expect(assistant.role).toBe('assistant');
    const use = (assistant.content as Anthropic.ToolUseBlockParam[])[0]!;
    expect(use).toMatchObject({ type: 'tool_use', name: 'read_file', input: { path: 'src/db.ts' } });
    expect(lastToolResults(seen[1]!)).toEqual([expect.objectContaining({ tool_use_id: use.id, content: 'contents of src/db.ts' })]);
    expect(lastToolResults(seen[2]!)[0]).toMatchObject({ content: 'Recorded.' });
    // tools offered every turn, no structured-output schema
    expect(seen[0]!.tools!.map((t) => t.name)).toEqual(['read_file', 'report_flow']);
    expect(seen[0]!.tools![0]!.input_schema).toMatchObject({ type: 'object', required: ['path'] });
    expect(seen[0]!.tools![0]!.input_schema).not.toHaveProperty('$schema');
    // accounting: one llm_calls row per turn, scan cost and cost events
    expect(r.callIds).toHaveLength(3);
    expect(calls.totals(scanId)).toMatchObject({ calls: 3, failedCalls: 0 });
    expect(scans.getDto(scanId)!.costUsd).toBeCloseTo(r.costUsd, 9);
    expect(r.costUsd).toBeGreaterThan(0);
    expect(r.usage.inputTokens).toBeGreaterThan(0);
    expect(onUsage).toHaveBeenCalledWith(scanId, expect.objectContaining({ calls: expect.any(Number) }));
  });

  it('collects several finish-tool calls (also parallel ones in one turn)', async () => {
    const second = { title: 'XSS', line: 40 };
    const script: MockResponder = (req) => [
      mockToolUses([{ name: 'report_flow', input: flow }, { name: 'report_flow', input: second }]),
      mockText(''),
    ][mockTurnIndex(req)];
    const { client, call, seen } = setup({ responders: [script] });
    const r = await client.agent(call());
    expect(r.finished).toEqual([flow, second]);
    const results = lastToolResults(seen[1]!);
    expect(results).toHaveLength(2);
    expect(new Set(results.map((x) => x.tool_use_id)).size).toBe(2);
  });

  it('marks the transcript tail with a cache breakpoint each turn (system stays cached, stored transcript unmarked)', async () => {
    const script: MockResponder = (req) => [mockToolUse('read_file', { path: 'a.ts' }), mockText('')][mockTurnIndex(req)];
    const { client, call, seen } = setup({ responders: [script] });
    await client.agent(call({ context: 'context pack' }));
    const countBreakpoints = (req: LlmRequest) => JSON.stringify(req).split('"cache_control"').length - 1;
    expect(seen[0]!.system[0]).toMatchObject({ cache_control: { type: 'ephemeral' } });
    const tail = (seen[1]!.messages.at(-1)!.content as Anthropic.ContentBlockParam[]).at(-1)!;
    expect(tail).toMatchObject({ type: 'tool_result', cache_control: { type: 'ephemeral' } });
    // system + context + tail; the first turn's tail mark was not carried into the second request
    expect(countBreakpoints(seen[0]!)).toBe(3);
    expect(countBreakpoints(seen[1]!)).toBe(3);
  });

  it('feeds invalid tool input and unknown tools back as is_error results and keeps looping', async () => {
    const script: MockResponder = (req) => [
      mockToolUses([{ name: 'read_file', input: { path: 42 } }, { name: 'delete_repo', input: {} }, { name: 'report_flow', input: { title: 'x' } }]),
      mockToolUse('report_flow', flow),
      mockText(''),
    ][mockTurnIndex(req)];
    const { client, call, seen, readFile } = setup({ responders: [script] });
    const r = await client.agent(call());
    const results = lastToolResults(seen[1]!);
    expect(results.map((x) => x.is_error)).toEqual([true, true, true]);
    expect(results[0]!.content).toMatch(/Invalid input for read_file: path/);
    expect(results[1]!.content).toMatch(/Unknown tool "delete_repo"/);
    expect(readFile).not.toHaveBeenCalled();
    expect(r).toMatchObject({ finished: [flow], stopReason: 'end_turn', turns: 3 });
  });

  it('turns a throwing tool into an is_error result; long results are truncated', async () => {
    const script: MockResponder = (req) => [
      mockToolUses([{ name: 'boom', input: {} }, { name: 'big', input: {} }]),
      mockText(''),
    ][mockTurnIndex(req)];
    const { client, call, seen, tools } = setup({ responders: [script] });
    const extra: AgentTool[] = [
      defineTool({ name: 'boom', description: 'fails', input: z.object({}), run: () => { throw new Error('disk on fire'); } }),
      defineTool({ name: 'big', description: 'large', input: z.object({}), run: async () => 'x'.repeat(AGENT_TOOL_RESULT_MAX_CHARS + 500) }),
    ];
    const r = await client.agent(call({ tools: [...tools, ...extra] }));
    expect(r.stopReason).toBe('end_turn');
    const [boom, big] = lastToolResults(seen[1]!);
    expect(boom).toMatchObject({ is_error: true, content: 'Tool boom failed: disk on fire' });
    expect(big!.is_error).toBeUndefined();
    expect(big!.content.length).toBeLessThan(AGENT_TOOL_RESULT_MAX_CHARS + 100);
    expect(big!.content).toMatch(/truncated 500 chars/);
  });

  it('stops after maxTurns, returning what was collected', async () => {
    const script: MockResponder = (req) => (mockTurnIndex(req) === 0 ? mockToolUse('report_flow', flow) : mockToolUse('read_file', { path: 'x' }));
    const { client, call, transport } = setup({ responders: [script] });
    const r = await client.agent(call({ maxTurns: 3 }));
    expect(r).toMatchObject({ stopReason: 'max_turns', turns: 3, finished: [flow] });
    expect(transport.send).toHaveBeenCalledTimes(3);
  });

  it('stops on the wall clock, aborting an in-flight send, with partial results', async () => {
    let turn = 0;
    const slow: LlmTransport = {
      mode: 'mock',
      send: async (req, signal) => {
        if (turn++ === 0) return new MockTransport({ responders: [() => mockToolUse('report_flow', flow)] }).send(req, signal);
        await new Promise<void>((resolve, reject) => {
          const t = setTimeout(resolve, 5_000);
          signal.addEventListener('abort', () => { clearTimeout(t); reject(new AppError('CANCELLED', 'cancelled', 'aborted')); }, { once: true });
        });
        throw new Error('unreachable');
      },
    };
    const { client, call } = setup({ transport: slow });
    const started = Date.now();
    const r = await client.agent(call({ wallClockMs: 50 }));
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(r).toMatchObject({ stopReason: 'timeout', finished: [flow], turns: 1 });
  });

  it('stops with stopReason budget when the scan budget runs out mid-loop', async () => {
    const script: MockResponder = (req) => (mockTurnIndex(req) === 0 ? mockToolUse('report_flow', flow) : mockToolUse('read_file', { path: 'x' }));
    const { client, call, budget, scanId, transport } = setup({ responders: [script], budgetUsd: 1 });
    const send = vi.mocked(transport.send);
    const original = send.getMockImplementation()!;
    send.mockImplementation(async (req, signal) => {
      const m = await original(req, signal);
      if (send.mock.calls.length === 2) budget.add(scanId, 1); // exhausted after the second turn
      return m;
    });
    const r = await client.agent(call());
    expect(r).toMatchObject({ stopReason: 'budget', finished: [flow], turns: 2 });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('ends on refusal with whatever was collected', async () => {
    const script: MockResponder = (req) => [mockToolUse('report_flow', flow), mockRefusal()][mockTurnIndex(req)];
    const { client, call, calls, scanId } = setup({ responders: [script] });
    const r = await client.agent(call());
    expect(r).toMatchObject({ stopReason: 'refusal', finished: [flow], turns: 2 });
    expect(calls.totals(scanId).calls).toBe(2);
  });

  it('propagates cancellation (before and during the loop)', async () => {
    const pre = new AbortController();
    pre.abort();
    const a = setup();
    await expect(a.client.agent(a.call({ signal: pre.signal }))).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(a.transport.send).not.toHaveBeenCalled();

    const ac = new AbortController();
    const b = setup({ responders: [(req) => (mockTurnIndex(req) === 0 ? mockToolUse('read_file', { path: 'x' }) : mockText(''))] });
    b.readFile.mockImplementation((input) => { ac.abort(); return `contents of ${input.path}`; });
    await expect(b.client.agent(b.call({ signal: ac.signal }))).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(b.transport.send).toHaveBeenCalledOnce();
  });

  it('degrades one tier on a first-turn outage, retries transient failures and records each attempt', async () => {
    let n = 0;
    const flaky: LlmTransport = {
      mode: 'mock',
      send: async (req, signal) => {
        if (n++ < 5) throw new AppError('LLM_UNAVAILABLE', 'transient', 'overloaded');
        return new MockTransport().send(req, signal);
      },
    };
    const { client, call, calls, scanId, seen } = setup({ transport: flaky });
    const r = await client.agent(call());
    expect(r).toMatchObject({ degraded: true, model: 'claude-haiku-4-5', stopReason: 'end_turn', finished: [] });
    expect(seen.at(-1)!.model).toBe('claude-haiku-4-5');
    expect(calls.totals(scanId)).toMatchObject({ calls: 6, failedCalls: 5 });
  });

  it('throws permanent failures when nothing was collected, else returns stopReason error', async () => {
    const perm = new AppError('LLM_UNAVAILABLE', 'permanent', 'bad key');
    const a = setup({ transport: { mode: 'mock', send: async () => { throw perm; } } });
    await expect(a.client.agent(a.call())).rejects.toBe(perm);

    let n = 0;
    const b = setup({
      transport: {
        mode: 'mock',
        send: async (req, signal) => {
          if (n++ === 0) return new MockTransport({ responders: [() => mockToolUse('report_flow', flow)] }).send(req, signal);
          throw perm;
        },
      },
    });
    await expect(b.client.agent(b.call())).resolves.toMatchObject({ stopReason: 'error', finished: [flow], error: perm });
  });

  it('returns stopReason truncated when a turn hits max_tokens', async () => {
    const trunc: LlmTransport = {
      mode: 'mock',
      send: async (req, signal) => ({ ...(await new MockTransport().send(req, signal)), stop_reason: 'max_tokens' }) as Anthropic.Message,
    };
    const { client, call } = setup({ transport: trunc });
    await expect(client.agent(call())).resolves.toMatchObject({ stopReason: 'truncated', turns: 0 });
  });

  it('mock default: no matching responder → end_turn immediately with nothing collected', async () => {
    const { client, call, transport } = setup();
    const r = await client.agent(call());
    expect(r).toMatchObject({ stopReason: 'end_turn', finished: [], turns: 1 });
    expect(transport.send).toHaveBeenCalledOnce();
  });

  it('rejects a finishTool that is not among the tools, and non-object tool schemas', async () => {
    const { client, call, tools } = setup();
    await expect(client.agent(call({ finishTool: 'nope' }))).rejects.toMatchObject({ code: 'INTERNAL' });
    const bad = defineTool({ name: 'bad', description: 'x', input: z.string(), run: () => '' });
    await expect(client.agent(call({ tools: [...tools, bad] }))).rejects.toMatchObject({ code: 'INTERNAL' });
  });

  it('request hashes include the tools', () => {
    const base: LlmRequest = { model: 'm', system: [], messages: [], maxTokens: 1, thinking: false };
    const tool = { name: 't', description: 'd', input_schema: { type: 'object' as const } };
    expect(requestHash({ ...base, tools: [tool] })).not.toBe(requestHash(base));
  });

  it('leaves structured() unaffected (schema output, no tools)', async () => {
    const Out = z.object({ verdict: z.enum(['safe', 'vulnerable']) });
    const { client, call, seen } = setup();
    const r = await client.structured({ ...call(), schema: Out });
    expect(r.output).toEqual({ verdict: 'safe' });
    expect(seen[0]!.tools).toBeUndefined();
  });
});
