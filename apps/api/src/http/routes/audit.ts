import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AUDIT_ACTIONS, type AuditLogger } from '../../audit/AuditLogger';
import { requestMeta } from './scans';

const AuditQuerySchema = z.object({
  action: z.enum(AUDIT_ACTIONS).optional(),
  targetType: z.string().max(50).optional(),
  targetId: z.string().max(100).optional(),
  from: z.iso.datetime().optional(),
  to: z.iso.datetime().optional(),
  before: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

export function auditRoutes(app: FastifyInstance, audit: AuditLogger): void {
  app.get('/api/audit', async (req) => {
    const q = AuditQuerySchema.parse(req.query);
    return audit.list({ ...q, beforeSeq: q.before });
  });

  app.get('/api/audit/verify', async (req) => {
    const result = audit.verify();
    const meta = requestMeta(req);
    audit.append({
      action: 'audit.verified', targetType: 'audit_log', targetId: 'chain',
      actorIp: meta.ip, userAgent: meta.userAgent, details: { ...result },
    });
    return result;
  });
}
