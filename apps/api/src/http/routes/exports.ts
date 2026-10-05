import type { FastifyInstance } from 'fastify';
import type { Container } from '../../container';
import { buildCycloneDx } from '../../export/cyclonedx';
import { buildSarif } from '../../export/sarif';
import { requestMeta } from './scans';

type IdParams = { Params: { id: string } };

const sha7 = (commitSha: string | null): string => (commitSha ? commitSha.slice(0, 7) : 'unknown');

function filenameFor(owner: string, name: string, commitSha: string | null, ext: string): string {
  return `vibesec-${owner}-${name}-${sha7(commitSha)}.${ext}`;
}

export function exportRoutes(app: FastifyInstance, c: Container): void {
  app.get<IdParams>('/api/scans/:id/export/sarif', async (req, reply) => {
    const scan = c.service.get(req.params.id); // 404 for unknown scans
    const findings = c.findings.all(scan.id).map((r) => r.finding);
    const sarif = buildSarif(scan, findings);
    const meta = requestMeta(req);
    c.audit.append({
      action: 'export.downloaded', targetType: 'scan', targetId: scan.id, scanId: scan.id,
      actorIp: meta.ip, userAgent: meta.userAgent, details: { format: 'sarif' },
    });
    return reply
      .header('content-type', 'application/sarif+json')
      .header('content-disposition', `attachment; filename="${filenameFor(scan.repo.owner, scan.repo.name, scan.commitSha, 'sarif')}"`)
      .send(sarif);
  });

  app.get<IdParams>('/api/scans/:id/export/cyclonedx', async (req, reply) => {
    const scan = c.service.get(req.params.id); // 404 for unknown scans
    const findings = c.findings.all(scan.id).map((r) => r.finding);
    const bom = buildCycloneDx(scan, findings);
    const meta = requestMeta(req);
    c.audit.append({
      action: 'export.downloaded', targetType: 'scan', targetId: scan.id, scanId: scan.id,
      actorIp: meta.ip, userAgent: meta.userAgent, details: { format: 'cyclonedx' },
    });
    return reply
      .header('content-type', 'application/json')
      .header('content-disposition', `attachment; filename="${filenameFor(scan.repo.owner, scan.repo.name, scan.commitSha, 'cyclonedx.json')}"`)
      .send(bom);
  });
}
