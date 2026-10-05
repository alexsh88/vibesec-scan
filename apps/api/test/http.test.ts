import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { loadConfig } from '../src/config';
import { createContainer, type Container } from '../src/container';
import { buildApp } from '../src/http/app';
import { createStubPipeline } from '../src/pipeline/stubPipeline';

let app: FastifyInstance;
let c: Container;

async function start() {
  const config = loadConfig({ DB_PATH: ':memory:' });
  c = createContainer(config, { pipeline: createStubPipeline(1) });
  app = await buildApp(c, { logger: false });
  return app;
}

afterEach(async () => {
  await c.runner.shutdown(0);
  await app.close();
  c.db.close();
});

const createScan = (headers: Record<string, string> = {}) => app.inject({
  method: 'POST', url: '/api/scans', headers, payload: { repoUrl: 'https://github.com/acme/app' },
});

function parseSse(body: string) {
  return body.split('\n\n').filter((b) => b.includes('data: ')).map((block) => ({
    id: Number(block.match(/^id: (\d+)$/m)?.[1]),
    event: block.match(/^event: (.+)$/m)?.[1],
  }));
}

describe('HTTP API', () => {
  it('rejects invalid input with VALIDATION and issues', async () => {
    await start();
    const res = await app.inject({ method: 'POST', url: '/api/scans', payload: { repoUrl: 'https://evil.com/a/b' } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('VALIDATION');
    expect(res.json().error.issues.length).toBeGreaterThan(0);
  });

  it('creates a scan (202) and reads it back', async () => {
    await start();
    const res = await createScan();
    expect(res.statusCode).toBe(202);
    const { scanId } = res.json();
    const get = await app.inject({ method: 'GET', url: `/api/scans/${scanId}` });
    expect(get.statusCode).toBe(200);
    expect(get.json().repo).toMatchObject({ owner: 'acme', name: 'app' });
  });

  it('honors Idempotency-Key', async () => {
    await start();
    const a = await createScan({ 'idempotency-key': 'k1' });
    const b = await createScan({ 'idempotency-key': 'k1' });
    expect(b.statusCode).toBe(200);
    expect(b.json()).toMatchObject({ scanId: a.json().scanId, deduplicated: true });
  });

  it('returns 404 for unknown scans and 409 when cancelling a finished scan', async () => {
    await start();
    expect((await app.inject({ method: 'GET', url: '/api/scans/nope' })).json().error.code).toBe('NOT_FOUND');
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const res = await app.inject({ method: 'POST', url: `/api/scans/${scanId}/cancel` });
    expect(res.statusCode).toBe(409);
  });

  it('replays SSE for a finished scan and honors Last-Event-ID', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/events` });
    expect(res.headers['content-type']).toContain('text/event-stream');
    const events = parseSse(res.body);
    expect(events.at(-1)?.event).toBe('done');
    expect(events.map((e) => e.id)).toEqual([...events.map((e) => e.id)].sort((x, y) => x - y));
    const lastId = events.at(-1)!.id;
    const resumed = await app.inject({
      method: 'GET', url: `/api/scans/${scanId}/events`, headers: { 'last-event-id': String(lastId - 1) },
    });
    expect(parseSse(resumed.body)).toEqual([{ id: lastId, event: 'done' }]);
  });

  it('streams live SSE until done', async () => {
    await start();
    await app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    const { scanId } = (await createScan()).json();
    const res = await fetch(`http://127.0.0.1:${port}/api/scans/${scanId}/events`);
    const events = parseSse(await res.text());
    expect(events.some((e) => e.event === 'progress')).toBe(true);
    expect(events.at(-1)?.event).toBe('done');
  });

  it('exposes the audit log and verifies it', async () => {
    await start();
    await createScan();
    const list = await app.inject({ method: 'GET', url: '/api/audit?action=scan.created' });
    expect(list.json().items).toHaveLength(1);
    const verify = await app.inject({ method: 'GET', url: '/api/audit/verify' });
    expect(verify.json()).toMatchObject({ ok: true });
  });

  it('#1: answers 503 during shutdown without persisting a scan', async () => {
    await start();
    await c.runner.shutdown(0);
    const res = await createScan({ 'idempotency-key': 'k-shutdown' });
    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe('QUEUE_FULL');
    expect(c.scans.findByIdempotencyKey('k-shutdown')).toBeUndefined();
    expect(c.scans.listNonTerminal()).toEqual([]);
  });

  it('reports health', async () => {
    await start();
    const res = await app.inject({ method: 'GET', url: '/api/health' });
    expect(res.json()).toMatchObject({ status: 'ok', scanMode: 'mock' });
  });

  it('exposes the repository index of a scan', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    c.indexRepo.replace(scanId, {
      files: [{ path: 'src/a.ts', blobSha: 'a'.repeat(40), size: 1, language: 'typescript', category: 'source', tags: [], skipReason: null }],
      imports: [{ from: 'src/a.ts', specifier: 'express', kind: 'package', to: null, pkg: 'express', line: 1 }],
      entrypoints: [{ path: 'src/a.ts', kind: 'http-route', line: 2, detail: 'GET /' }],
      stats: { totalFiles: 1, indexedFiles: 1, skipped: {}, byLanguage: { typescript: 1 }, imports: 1, entrypoints: 1, truncated: false },
    });
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}/index` });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      stats: expect.objectContaining({ indexedFiles: 1 }),
      entrypoints: [{ path: 'src/a.ts', kind: 'http-route', line: 2, detail: 'GET /' }],
      packages: [{ name: 'express', importers: 1 }],
    });
  });

  it('returns 404 for the index of an unknown scan', async () => {
    await start();
    expect((await app.inject({ method: 'GET', url: '/api/scans/nope/index' })).statusCode).toBe(404);
  });

  it('reports LLM mode and models in health', async () => {
    await start();
    expect((await app.inject({ method: 'GET', url: '/api/health' })).json()).toMatchObject({
      llm: { mode: 'mock', models: { fast: 'claude-haiku-4-5', deep: 'claude-sonnet-5', synthesis: 'claude-opus-5' } },
    });
  });

  it('streams cost events and exposes per-analyzer LLM diagnostics', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const r = await c.llm.structured({
      scanId, analyzer: 'sast', purpose: 'test', promptVersion: 'v1', role: 'deep',
      system: 'You review code.', prompt: 'review', schema: z.object({ ok: z.boolean() }), signal: new AbortController().signal,
    });
    expect(r.output).toEqual({ ok: false });
    const costEvents = c.bus.replay(scanId, 0).filter((e) => e.event.type === 'cost');
    expect(costEvents.length).toBe(1);
    expect(costEvents[0]!.event).toMatchObject({ type: 'cost', usd: r.costUsd });

    const diag = (await app.inject({ method: 'GET', url: `/api/scans/${scanId}/diagnostics` })).json();
    expect(diag).toMatchObject({
      scanId,
      llm: { mode: 'mock', budgetUsd: 5, totals: { calls: 1, failedCalls: 0 }, byAnalyzer: [{ analyzer: 'sast', calls: 1 }] },
    });
    expect(diag.llm.totals.costUsd).toBeCloseTo(r.costUsd, 9);
    expect(diag.llm.reservedUsd).toBe(0);
    expect(diag.llm.breakerTrips).toBe(0);
    // Mock transport reports no cache reads → ratio 0 (never NaN on an empty denominator either).
    expect(diag.llm.cacheHitRatio).toBe(0);
  });

  it('returns 404 diagnostics for an unknown scan', async () => {
    await start();
    expect((await app.inject({ method: 'GET', url: '/api/scans/nope/diagnostics' })).statusCode).toBe(404);
  });

  it('lists, filters and fetches findings of a scan', async () => {
    await start();
    const { scanId } = (await createScan()).json();
    await c.runner.whenIdle();
    const base = {
      scanId, category: 'secret' as const, ruleId: 'secret/x', baseSeverity: 'high' as const, riskScore: 70, riskFactors: [],
      confidence: 'high' as const, explanation: 'e', impact: 'i', remediation: { summary: 'r' }, scanStatus: 'new' as const,
      location: { file: 'a.ts', startLine: 1, endLine: 1, snippet: 's', permalink: 'p' },
    };
    c.findings.replaceForAnalyzer(scanId, 'secrets', [
      { ...base, id: 'f1', fingerprint: 'a', title: 'High one', severity: 'high' },
      { ...base, id: 'f2', fingerprint: 'b', title: 'Critical one', severity: 'critical', riskScore: 95 },
    ]);
    const list = (await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings` })).json();
    expect(list.items.map((f: { id: string }) => f.id)).toEqual(['f2', 'f1']);
    expect(list.counts).toEqual({ total: 2, bySeverity: { critical: 1, high: 1 }, byCategory: { secret: 2 } });
    expect((await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?severity=critical` })).json().items).toHaveLength(1);
    expect((await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings/f1` })).json().title).toBe('High one');
    expect((await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings/nope` })).statusCode).toBe(404);
    expect((await app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?severity=urgent` })).statusCode).toBe(400);
    expect((await app.inject({ method: 'GET', url: `/api/scans/missing/findings` })).statusCode).toBe(404);
  });
});
