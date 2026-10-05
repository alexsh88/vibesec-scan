import type { FastifyInstance } from 'fastify';
import type { ScanSummary } from '@vibesec/shared';
import type { Container } from '../../container';
import { AppError } from '../../errors/AppError';

type IdParams = { Params: { id: string } };

export function summaryRoutes(app: FastifyInstance, c: Pick<Container, 'service' | 'summaries'>): void {
  app.get<IdParams>('/api/scans/:id/summary', async (req): Promise<ScanSummary> => {
    c.service.get(req.params.id); // 404 NOT_FOUND for unknown scans
    const summary = c.summaries.get(req.params.id);
    if (!summary) throw new AppError('NOT_READY', 'permanent', 'The scan summary is not ready yet');
    return summary;
  });
}
