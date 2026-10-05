import type { FastifyInstance } from 'fastify';
import { CategorySchema, SeveritySchema } from '@vibesec/shared';
import { z } from 'zod';
import type { Container } from '../../container';
import { AppError } from '../../errors/AppError';

const FindingQuerySchema = z.object({
  category: CategorySchema.optional(),
  severity: SeveritySchema.optional(),
  file: z.string().max(1000).optional(),
  q: z.string().max(200).optional(),
  cursor: z.string().max(100).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

type IdParams = { Params: { id: string } };
type FindingParams = { Params: { id: string; findingId: string } };

export function findingRoutes(app: FastifyInstance, c: Container): void {
  app.get<IdParams>('/api/scans/:id/findings', async (req) => {
    c.service.get(req.params.id); // 404 for unknown scans
    const query = FindingQuerySchema.parse(req.query);
    const { items, nextCursor } = c.findings.list(req.params.id, query);
    const counts = c.findings.counts(req.params.id);
    return { items, nextCursor, counts };
  });

  app.get<FindingParams>('/api/scans/:id/findings/:findingId', async (req) => {
    c.service.get(req.params.id); // 404 for unknown scans
    const finding = c.findings.get(req.params.id, req.params.findingId);
    if (!finding) throw new AppError('NOT_FOUND', 'permanent', 'Finding not found');
    return finding;
  });
}
