import type { FastifyInstance } from 'fastify';
import { CategorySchema, SeveritySchema, TriageStatusSchema } from '@vibesec/shared';
import { z } from 'zod';
import type { Container } from '../../container';
import { AppError } from '../../errors/AppError';
import { requestMeta } from './scans';

const FindingQuerySchema = z.object({
  category: CategorySchema.optional(),
  severity: SeveritySchema.optional(),
  file: z.string().max(1000).optional(),
  q: z.string().max(200).optional(),
  triage: z.enum(['open', 'suppressed', 'all']).default('all'),
  /** Omitted: the scan's current findings (new + existing); 'fixed' = in the previous scan, gone in this one. */
  scanStatus: z.enum(['new', 'existing', 'fixed']).optional(),
  cursor: z.string().max(100).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

const TriageBodySchema = z.object({
  status: TriageStatusSchema,
  reason: z.string().min(1).max(1000),
  /** Must be in the future: a decision that is already expired would never suppress anything. */
  expiresAt: z.iso.datetime()
    .refine((v) => Date.parse(v) > Date.now(), 'expiresAt must be in the future')
    .optional(),
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

  app.put<FindingParams>('/api/scans/:id/findings/:findingId/triage', async (req) => {
    c.service.get(req.params.id); // 404 for unknown scans
    const body = TriageBodySchema.parse(req.body);
    return c.suppressions.setTriage(req.params.id, req.params.findingId, body, requestMeta(req));
  });

  app.delete<FindingParams>('/api/scans/:id/findings/:findingId/triage', async (req) => {
    c.service.get(req.params.id); // 404 for unknown scans
    return c.suppressions.clearTriage(req.params.id, req.params.findingId, requestMeta(req));
  });
}
