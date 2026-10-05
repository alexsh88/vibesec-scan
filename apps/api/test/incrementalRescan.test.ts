// End-to-end incremental rescans (spec §11) over a local git copy of fixtures/vuln-app with four commits,
// through the real container wiring and HTTP API in mock-LLM mode:
//   v0  the vuln-app as is                                      → base scan (full)
//   v1  api/src/routes/logs.ts rewritten: its path traversal is gone, a command injection is new
//                                                               → incremental: only changed/affected files are analyzed
//   v2  a comment appended to most source files (> 40% changed) → full scan + info warning
//   v3  README tweak, but the newest "base" points at a commit the repo does not have
//                                                               → full scan + info warning
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Finding, ScanDto } from '@vibesec/shared';
import { findingsOf, startVulnAppHarness, vulnAppFakeFetch, type VulnAppHarness } from '../scripts/vulnApp';

const MOCK_ENV = { SCAN_MODE: 'mock', LLM_REQUESTS_PER_MINUTE: '100000', LLM_INPUT_TOKENS_PER_MINUTE: '1000000000' };
const LOGS = 'api/src/routes/logs.ts';
const LOGS_V1 = `import { Router } from 'express';
import { execSync } from 'node:child_process';

export const logsRouter = Router();

const LOG_FILES: Record<string, string> = { app: '/var/log/vuln-app/app.log', worker: '/var/log/vuln-app/worker.log' };

logsRouter.get('/', (req, res) => {
  const lines = req.query.lines as string;
  const file = LOG_FILES[String(req.query.name)] ?? LOG_FILES.app;
  const output = execSync('tail -n ' + lines + ' ' + file).toString();
  res.type('text/plain').send(output);
});
`;

type Diagnostics = {
  cacheHit: string;
  reuse: ScanDto['reuse'];
  coverage: { byAnalyzer: Record<string, Record<string, number>> };
};

let h: VulnAppHarness;
let base: string;
let incremental: string;

beforeAll(async () => {
  h = await startVulnAppHarness({
    env: MOCK_ENV, fetch: vulnAppFakeFetch,
    commits: (files) => [
      { files },
      { files: { [LOGS]: LOGS_V1 } },
      {
        files: Object.fromEntries(Object.entries(files)
          .filter(([p]) => /\.(ts|tsx|py)$/.test(p) && p !== LOGS)
          .map(([p, text]) => [p, `${text}\n${p.endsWith('.py') ? '#' : '//'} v2\n`])),
      },
      { files: { 'README.md': `${files['README.md'] ?? ''}\nv3\n` } },
    ],
  });
}, 120_000);

afterAll(async () => {
  await h?.close();
});

const dto = (id: string) => h.container.scans.getDto(id)!;
const coverageOf = (scanId: string, analyzer: string) => new Map(
  (h.container.db.prepare('SELECT path, status FROM scan_coverage WHERE scan_id = ? AND analyzer = ?').all(scanId, analyzer) as Array<{ path: string; status: string }>)
    .map((r) => [r.path, r.status]),
);
const callsOf = (scanId: string, analyzer: string) => (h.container.db.prepare('SELECT COUNT(*) AS c FROM llm_calls WHERE scan_id = ? AND analyzer = ?')
  .get(scanId, analyzer) as { c: number }).c;
const reviewedPaths = (scanId: string, analyzer: string) =>
  [...coverageOf(scanId, analyzer)].filter(([, s]) => s === 'reviewed' || s === 'reviewed-fast').map(([p]) => p).sort();

async function list(scanId: string, query = ''): Promise<{ items: Finding[]; counts: { total: number; byScanStatus: Record<'new' | 'existing' | 'fixed', number> } }> {
  const res = await h.app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?limit=200${query}` });
  expect(res.statusCode).toBe(200);
  return res.json();
}

describe('incremental rescans over fixtures/vuln-app (mock LLM)', () => {
  it('scans the base commit in full', async () => {
    base = (await h.scan({}, h.repo.shas[0])).scanId;
    expect(dto(base)).toMatchObject({ commitSha: h.repo.shas[0], cacheHit: 'none', reuse: null });
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(dto(base).state);
    expect(findingsOf(h.container, base).every((f) => f.scanStatus === 'new')).toBe(true);
  }, 120_000);

  it('rescans only the changed/affected files and re-attaches the rest', async () => {
    incremental = (await h.scan({}, h.repo.shas[1])).scanId;
    const scan = dto(incremental);
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(scan.state);
    expect(scan.cacheHit).toBe('partial');
    const indexed = h.container.indexRepo.files(incremental).length;
    expect(scan.reuse).toMatchObject({ baseScanId: base, filesChanged: 1, filesDeleted: 0, filesReused: indexed - 1 });
    expect(scan.reuse!.estimatedSavedUsd).toBeGreaterThan(0);
    expect(scan.costUsd).toBeLessThan(dto(base).costUsd);

    const diag = (await h.app.inject({ method: 'GET', url: `/api/scans/${incremental}/diagnostics` })).json() as Diagnostics;
    expect(diag).toMatchObject({ cacheHit: 'partial', reuse: scan.reuse });
    const cacheEvent = h.container.bus.replay(incremental, 0).map((e) => e.event).find((e) => e.type === 'cache');
    expect(cacheEvent).toEqual({ type: 'cache', filesReused: indexed - 1, filesAnalyzed: 1, savedUsd: scan.reuse!.estimatedSavedUsd });

    // Only the changed file is triaged / quality-reviewed / hunted again; one triage batch in total.
    expect(reviewedPaths(incremental, 'triage')).toEqual([LOGS]);
    expect(callsOf(incremental, 'triage')).toBe(1);
    expect(coverageOf(incremental, 'triage').get('api/src/routes/invoices.ts')).toBe('cached');
    for (const a of ['quality', 'credential-hunter']) {
      for (const p of reviewedPaths(incremental, a)) expect(p).toBe(LOGS);
      expect([...coverageOf(incremental, a).values()]).toContain('cached');
    }
    expect(callsOf(incremental, 'quality')).toBe(reviewedPaths(incremental, 'quality').length);
    // SAST: only files whose own prompt changed (the file or its local import context) miss the cache.
    const affected = new Set([LOGS, 'api/src/server.ts']);
    for (const p of reviewedPaths(incremental, 'sast')) expect(affected.has(p), p).toBe(true);
    expect(callsOf(incremental, 'sast')).toBe(reviewedPaths(incremental, 'sast').length);
    expect(coverageOf(incremental, 'sast').get('api/src/services/invoiceService.ts')).toBe('cached');
    // Taint: only the affected entrypoint is traced again; every other entrypoint's flows are re-attached.
    expect(reviewedPaths(incremental, 'taint')).toEqual([LOGS]);
    expect(coverageOf(incremental, 'taint').get('api/src/routes/invoices.ts')).toBe('cached');
    expect(callsOf(incremental, 'taint')).toBeGreaterThan(0);
    expect(callsOf(incremental, 'taint')).toBeLessThan(callsOf(base, 'taint'));
  }, 120_000);

  it('reports the fixed vulnerability as fixed, the new one as new and the rest as existing', async () => {
    const current = await list(incremental);
    const byFile = (items: Finding[], file: string) => items.filter((f) => f.location.file === file);

    // Re-attached, re-validated taint flow (SQL injection traced from the unchanged invoices route): existing.
    const sqli = current.items.find((f) => f.category === 'taint' && f.location.file === 'api/src/services/invoiceService.ts');
    expect(sqli).toMatchObject({ ruleId: 'taint/sql-injection', scanStatus: 'existing', scanId: incremental });
    expect(sqli!.taintTrace![0]).toMatchObject({ kind: 'source', file: 'api/src/routes/invoices.ts' });
    expect(sqli!.location.permalink).toContain(h.repo.shas[1]!);

    const fresh = byFile(current.items, LOGS).find((f) => f.ruleId === 'taint/command-injection');
    expect(fresh?.scanStatus).toBe('new');

    const fixed = await list(incremental, '&scanStatus=fixed');
    const goneTraversal = byFile(fixed.items, LOGS).find((f) => f.ruleId === 'taint/path-traversal');
    expect(goneTraversal).toMatchObject({ scanStatus: 'fixed', scanId: incremental });
    expect(current.items.some((f) => f.scanStatus === 'fixed')).toBe(false);

    const statuses = new Set(current.items.map((f) => f.scanStatus));
    expect(statuses.has('existing')).toBe(true);
    expect(current.counts.total).toBe(current.items.length);
    expect(current.counts.byScanStatus.fixed).toBe(fixed.items.length);
    expect(current.counts.byScanStatus.new + current.counts.byScanStatus.existing).toBe(current.counts.total);
    // Findings of untouched files keep their identity across the rescan.
    const baseFps = new Set(findingsOf(h.container, base).map((f) => f.fingerprint));
    for (const f of current.items.filter((x) => x.location.file !== LOGS && x.category !== 'dependency')) {
      expect(baseFps.has(f.fingerprint), `${f.ruleId} ${f.location.file}`).toBe(true);
    }
  }, 120_000);

  it('falls back to a full scan with an info warning when the diff is too large', async () => {
    const { scanId } = await h.scan({}, h.repo.shas[2]);
    const scan = dto(scanId);
    expect(scan.cacheHit).toBe('none');
    expect(scan.reuse).toBeNull();
    expect(scan.warnings).toContainEqual(expect.objectContaining({ code: 'INCREMENTAL_DIFF_TOO_LARGE', level: 'info' }));
    expect(reviewedPaths(scanId, 'taint').length).toBeGreaterThan(1);
  }, 120_000);

  it('falls back to a full scan with an info warning when the base commit is no longer in the repository', async () => {
    // A newer completed scan of the same configuration at a commit the repository does not have (force-push).
    const latest = h.container.scans.getRow(h.container.scans.listByRepo(dto(base).repo.id)[0]!.id)!;
    const ghost = h.container.scans.insertScan({
      repoId: latest.repo_id, ref: null, options: JSON.parse(latest.options_json), optionsHash: 'ghost', idempotencyKey: null, hasAuth: false,
    });
    h.container.db.prepare(
      `UPDATE scans SET state = 'COMPLETED', commit_sha = ?, result_options_hash = ?, analyzer_versions_hash = ?, finished_at = ? WHERE id = ?`,
    ).run('f'.repeat(40), latest.result_options_hash, latest.analyzer_versions_hash, new Date(Date.now() + 60_000).toISOString(), ghost.id);

    const { scanId } = await h.scan({}, h.repo.shas[3]);
    const scan = dto(scanId);
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(scan.state);
    expect(scan.cacheHit).toBe('none');
    expect(scan.warnings).toContainEqual(expect.objectContaining({ code: 'INCREMENTAL_BASE_UNAVAILABLE', level: 'info' }));
  }, 120_000);
});
