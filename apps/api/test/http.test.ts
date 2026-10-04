import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
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
});
