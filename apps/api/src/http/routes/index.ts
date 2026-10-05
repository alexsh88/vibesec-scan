import type { FastifyInstance } from 'fastify';
import type { IndexRepo } from '../../db/indexRepo';
import type { ScanService } from '../../scans/ScanService';

export function indexRoutes(app: FastifyInstance, service: ScanService, indexRepo: IndexRepo): void {
  app.get<{ Params: { id: string } }>('/api/scans/:id/index', async (req) => {
    service.get(req.params.id); // 404 for unknown scans
    const counts = new Map<string, Set<string>>();
    for (const e of indexRepo.imports(req.params.id)) {
      if (e.kind !== 'package' || !e.pkg) continue;
      const importers = counts.get(e.pkg) ?? new Set<string>();
      importers.add(e.from);
      counts.set(e.pkg, importers);
    }
    return {
      stats: indexRepo.stats(req.params.id),
      entrypoints: indexRepo.entrypoints(req.params.id),
      packages: [...counts].map(([name, importers]) => ({ name, importers: importers.size }))
        .sort((a, b) => b.importers - a.importers || a.name.localeCompare(b.name)),
    };
  });
}
