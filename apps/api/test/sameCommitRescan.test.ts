// A rescan of the SAME commit once the full-scan cache no longer applies (older than FULL_CACHE_TTL_HOURS):
// it runs as an incremental rescan against the earlier scan of that commit, so every per-file AI result is
// reused (empty diff) while the deterministic checks still run, and new/existing/fixed reports nothing as
// new or fixed. FULL_CACHE_TTL_HOURS is set to a few milliseconds so the second scan is past the TTL.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Finding } from '@vibesec/shared';
import { startVulnAppHarness, vulnAppFakeFetch, type VulnAppHarness } from '../scripts/vulnApp';

const ENV = {
  SCAN_MODE: 'mock', LLM_REQUESTS_PER_MINUTE: '100000', LLM_INPUT_TOKENS_PER_MINUTE: '1000000000',
  FULL_CACHE_TTL_HOURS: '0.000001',
};

let h: VulnAppHarness;

beforeAll(async () => {
  h = await startVulnAppHarness({ env: ENV, fetch: vulnAppFakeFetch });
}, 120_000);

afterAll(async () => {
  await h?.close();
});

const dto = (id: string) => h.container.scans.getDto(id)!;
const callsOf = (scanId: string, analyzer: string) => (h.container.db.prepare('SELECT COUNT(*) AS c FROM llm_calls WHERE scan_id = ? AND analyzer = ?')
  .get(scanId, analyzer) as { c: number }).c;

async function findings(scanId: string): Promise<{ items: Finding[]; counts: { total: number; byScanStatus: Record<'new' | 'existing' | 'fixed', number> } }> {
  const res = await h.app.inject({ method: 'GET', url: `/api/scans/${scanId}/findings?limit=200` });
  expect(res.statusCode).toBe(200);
  return res.json();
}

describe('same-commit rescan past the full-cache TTL (mock LLM)', () => {
  it('reuses every per-file AI result and reports nothing as new or fixed', async () => {
    const first = (await h.scan({}, h.repo.shas[0])).scanId;
    expect(dto(first).cacheHit).toBe('none');
    await new Promise((r) => setTimeout(r, 20)); // past the (milliseconds) TTL

    const second = (await h.scan({}, h.repo.shas[0])).scanId;
    const scan = dto(second);
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(scan.state);
    expect(scan.cacheHit).toBe('partial'); // not served whole from the full-scan cache
    const indexed = h.container.indexRepo.files(second).length;
    expect(scan.reuse).toMatchObject({ baseScanId: first, filesChanged: 0, filesDeleted: 0, filesReused: indexed });
    expect(scan.costUsd).toBeLessThan(dto(first).costUsd);

    // The per-file AI reviews are reused instead of being asked again.
    for (const analyzer of ['quality', 'credential-hunter', 'taint', 'triage', 'sast']) {
      expect(callsOf(second, analyzer), analyzer).toBe(0);
    }

    // Identical findings, all existing; nothing fixed, no variation note.
    const a = await findings(first);
    const b = await findings(second);
    expect(b.items.map((f) => f.fingerprint).sort()).toEqual(a.items.map((f) => f.fingerprint).sort());
    expect(b.counts.byScanStatus).toMatchObject({ new: 0, fixed: 0, existing: b.counts.total });
    expect(scan.warnings.map((w) => w.code)).not.toContain('SAME_COMMIT_RESULTS_VARIED');
  }, 240_000);
});
