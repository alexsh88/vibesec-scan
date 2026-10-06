import type { FastifyInstance, FastifyRequest } from 'fastify';
import { CreateScanRequestSchema } from '@vibesec/shared';
import type { RequestMeta, ScanService } from '../../scans/ScanService';

type IdParams = { Params: { id: string } };

export function requestMeta(req: FastifyRequest): RequestMeta {
  const key = req.headers['idempotency-key'];
  return {
    ip: req.ip ?? null,
    userAgent: req.headers['user-agent'] ?? null,
    idempotencyKey: typeof key === 'string' && key.length > 0 && key.length <= 200 ? key : null,
  };
}

export function scanRoutes(app: FastifyInstance, service: ScanService): void {
  app.post('/api/scans', async (req, reply) => {
    const body = CreateScanRequestSchema.parse(req.body);
    const { scan, deduplicated } = service.create(body, requestMeta(req));
    return reply.code(deduplicated ? 200 : 202).send({
      scanId: scan.id, status: scan.state, cacheHit: scan.cacheHit, deduplicated, scan,
    });
  });

  app.get<IdParams>('/api/scans/:id', async (req) => service.get(req.params.id));

  app.post<IdParams>('/api/scans/:id/cancel', async (req, reply) => {
    return reply.code(202).send(service.cancel(req.params.id, requestMeta(req)));
  });

  app.get('/api/repos', async () => ({ items: service.listRepos() }));

  app.get<IdParams>('/api/repos/:id/scans', async (req) => ({ items: service.listScans(req.params.id) }));

  // Deletes the repo's scan history so the next scan starts fresh; ?purgeAiCache=1 also clears the
  // shared AI result caches. 409 while a scan of the repo is still running.
  app.delete<IdParams & { Querystring: { purgeAiCache?: string } }>('/api/repos/:id', async (req) => {
    const purgeAiCaches = req.query.purgeAiCache === '1' || req.query.purgeAiCache === 'true';
    return service.deleteRepo(req.params.id, { purgeAiCaches }, requestMeta(req));
  });
}
