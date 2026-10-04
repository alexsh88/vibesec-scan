import type { ServerResponse } from 'node:http';
import type { FastifyInstance } from 'fastify';
import { isTerminalState, type StoredScanEvent } from '@vibesec/shared';
import type { EventBus } from '../../events/EventBus';
import type { ScanService } from '../../scans/ScanService';

const PING_MS = 15_000;

export function eventRoutes(app: FastifyInstance, service: ScanService, bus: EventBus): void {
  const open = new Set<ServerResponse>();

  app.addHook('preClose', async () => {
    for (const res of open) {
      res.write('event: reconnect\ndata: {}\n\n');
      res.end();
    }
    open.clear();
  });

  app.get<{ Params: { id: string }; Querystring: { after?: string } }>('/api/scans/:id/events', (req, reply) => {
    const scanId = req.params.id;
    service.get(scanId); // 404 before we take over the socket
    const header = req.headers['last-event-id'];
    const afterSeq = Number(typeof header === 'string' ? header : req.query.after ?? 0) || 0;

    reply.hijack();
    const res = reply.raw;
    res.writeHead(200, {
      ...(reply.getHeaders() as Record<string, string>),
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.write('retry: 3000\n\n');
    open.add(res);

    let lastSent = afterSeq;
    let closed = false;
    let replaying = true;
    const buffered: StoredScanEvent[] = [];

    function end(): void {
      if (closed) return;
      closed = true;
      clearInterval(ping);
      unsubscribe();
      open.delete(res);
      res.end();
    }

    function write(e: StoredScanEvent): void {
      if (closed || e.seq <= lastSent) return;
      lastSent = e.seq;
      res.write(`id: ${e.seq}\nevent: ${e.event.type}\ndata: ${JSON.stringify({ ...e.event, seq: e.seq, at: e.at })}\n\n`);
      if (e.event.type === 'done') end();
    }

    const unsubscribe = bus.subscribe(scanId, (e) => (replaying ? buffered.push(e) : write(e)));
    const ping = setInterval(() => res.write(': ping\n\n'), PING_MS);
    req.raw.on('close', end);

    for (const e of bus.replay(scanId, afterSeq)) write(e);
    replaying = false;
    for (const e of buffered) write(e);

    if (!closed && isTerminalState(service.get(scanId).state)) end();
  });
}
