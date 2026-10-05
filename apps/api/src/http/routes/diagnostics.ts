import type { FastifyInstance } from 'fastify';
import type { Container } from '../../container';

export function diagnosticsRoutes(app: FastifyInstance, c: Container): void {
  app.get<{ Params: { id: string } }>('/api/scans/:id/diagnostics', async (req) => {
    const scan = c.service.get(req.params.id); // 404 for unknown scans
    const started = scan.startedAt ? Date.parse(scan.startedAt) : null;
    const finished = scan.finishedAt ? Date.parse(scan.finishedAt) : null;
    const totals = c.llmCalls.totals(scan.id);
    const cacheable = totals.inputTokens + totals.cacheReadTokens;
    return {
      scanId: scan.id,
      state: scan.state,
      durationMs: started !== null && finished !== null ? finished - started : null,
      warnings: scan.warnings,
      index: c.indexRepo.stats(scan.id),
      llm: {
        mode: c.llm.mode,
        budgetUsd: c.config.scanBudgetUsd,
        totals,
        byAnalyzer: c.llmCalls.byAnalyzer(scan.id),
        reservedUsd: c.budget.reservedUsd(scan.id),
        breakerTrips: c.llm.breakerTrips,
        /** Share of prompt tokens served from the prompt cache. */
        cacheHitRatio: cacheable > 0 ? Math.round((totals.cacheReadTokens / cacheable) * 10_000) / 10_000 : 0,
      },
    };
  });
}
