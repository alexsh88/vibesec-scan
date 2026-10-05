import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type Anthropic from '@anthropic-ai/sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { fakeFromSchema, MockTransport, RecordingTransport } from '../src/llm/mockTransport';
import { requestHash, type LlmRequest, type LlmTransport } from '../src/llm/transport';

const Finding = z.object({
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  title: z.string().min(3),
  line: z.number().int().min(1),
  tags: z.array(z.string()),
  fixed: z.boolean(),
  note: z.string().nullable(),
  nested: z.object({ score: z.number().min(0).max(10) }),
  maybe: z.string().optional(),
});
const Out = z.object({ findings: z.array(Finding).min(1), summary: z.string() });

const req = (schema: z.ZodType = Out, text = 'review src/a.ts'): LlmRequest => ({
  model: 'claude-sonnet-5', system: [{ type: 'text', text: 'sys' }],
  messages: [{ role: 'user', content: [{ type: 'text', text }] }], maxTokens: 1_000, thinking: false, schema,
});
const textOf = (m: Anthropic.Message) => m.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('');

let dir: string;
beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vibesec-rec-')); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe('fakeFromSchema', () => {
  it('produces a value that passes the schema, honoring enums, mins and nested objects', () => {
    expect(() => Out.parse(fakeFromSchema(Out))).not.toThrow();
  });
});

describe('MockTransport', () => {
  it('falls back to a schema-valid fake with estimated usage', async () => {
    const m = await new MockTransport({ recordingsDir: dir }).send(req(), new AbortController().signal);
    expect(m.stop_reason).toBe('end_turn');
    expect(() => Out.parse(JSON.parse(textOf(m)))).not.toThrow();
    expect(m.usage.input_tokens).toBeGreaterThan(0);
    expect(m.usage.output_tokens).toBeGreaterThan(0);
  });

  it('prefers a registered responder over the fake', async () => {
    const canned = { findings: [], summary: 'nothing found' };
    const t = new MockTransport({ recordingsDir: dir, responders: [(r) => (JSON.stringify(r.messages).includes('src/a.ts') ? canned : undefined)] });
    expect(JSON.parse(textOf(await t.send(req(), new AbortController().signal)))).toEqual(canned);
  });

  it('prefers a recording over responders', async () => {
    const recorded = { id: 'msg_rec', type: 'message', role: 'assistant', model: 'claude-sonnet-5',
      content: [{ type: 'text', text: '{"findings":[],"summary":"recorded"}', citations: null }],
      stop_reason: 'end_turn', stop_sequence: null,
      usage: { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 } };
    await writeFile(join(dir, `${requestHash(req())}.json`), JSON.stringify(recorded));
    const t = new MockTransport({ recordingsDir: dir, responders: [() => ({ findings: [], summary: 'responder' })] });
    expect(JSON.parse(textOf(await t.send(req(), new AbortController().signal))).summary).toBe('recorded');
  });

  it('is deterministic for the same request', async () => {
    const t = new MockTransport({ recordingsDir: dir });
    const a = await t.send(req(), new AbortController().signal);
    const b = await t.send(req(), new AbortController().signal);
    expect(textOf(a)).toBe(textOf(b));
    expect(a.id).toBe(b.id);
  });

  it('honors cancellation', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(new MockTransport({ recordingsDir: dir }).send(req(), ac.signal)).rejects.toMatchObject({ code: 'CANCELLED' });
  });
});

describe('RecordingTransport', () => {
  it('records live responses keyed by request hash', async () => {
    const live: LlmTransport = { mode: 'live', send: vi.fn(async () => ({ id: 'msg_live' } as unknown as Anthropic.Message)) };
    const t = new RecordingTransport(live, dir);
    await t.send(req(), new AbortController().signal);
    const files = await readdir(dir);
    expect(files).toEqual([`${requestHash(req())}.json`]);
    expect(JSON.parse(await readFile(join(dir, files[0]!), 'utf8')).id).toBe('msg_live');
  });
});
