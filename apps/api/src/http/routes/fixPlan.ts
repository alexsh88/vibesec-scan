import type { FastifyInstance } from 'fastify';
import type { FixPlan } from '@vibesec/shared';
import type { Container } from '../../container';

type IdParams = { Params: { id: string } };

export function fixPlanRoutes(app: FastifyInstance, c: Container): void {
  app.get<IdParams>('/api/scans/:id/fix-plan', async (req): Promise<FixPlan> => {
    c.service.get(req.params.id); // 404 for unknown scans
    return c.fixPlans.get(req.params.id) ?? { scanId: req.params.id, actions: [], unfixable: [] };
  });
}
