import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AUDIT_ACTIONS, type AuditLogger } from '../../audit/AuditLogger';
import { requestMeta } from './scans';

const AuditQuerySchema = z.object({
  action: z.enum(AUDIT_ACTIONS).optional(),
  targetType: z.string().max(50).optional(),
  targetId: z.string().max(100).optional(),
  scanId: z.string().max(100).optional(),
  from: z.iso.datetime().optional(),
  to: z.iso.datetime().optional(),
  before: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

/** `record=1` is the only way to append an `audit.verified` entry; anything else (including absent) just verifies. */
const VerifyQuerySchema = z.object({
  record: z.literal('1').optional(),
});

export function auditRoutes(app: FastifyInstance, audit: AuditLogger): void {
  app.get('/api/audit', async (req) => {
    const q = AuditQuerySchema.parse(req.query);
    return audit.list({ ...q, beforeSeq: q.before });
  });

  // Side-effect free by default (walking the chain shouldn't itself grow the chain on every page
  // visit); pass ?record=1 to explicitly append an `audit.verified` entry for this check.
  app.get('/api/audit/verify', async (req) => {
    const { record } = VerifyQuerySchema.parse(req.query);
    const result = audit.verify();
    if (record) {
      const meta = requestMeta(req);
      audit.append({
        action: 'audit.verified', targetType: 'audit_log', targetId: 'chain',
        actorIp: meta.ip, userAgent: meta.userAgent, details: { ...result },
      });
    }
    return result;
  });
}
