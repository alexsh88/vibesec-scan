// End-to-end: the REAL container wiring (createContainer — every analyzer, mock responder, budget lane,
// cache and the coverage report) runs a full scan (RESOLVING -> CLONING -> INDEXING -> ANALYZING) over
// a local git repo built from fixtures/vuln-app, through the HTTP layer, in mock-LLM mode, with OSV and
// the npm/PyPI registries served from offline fixtures. Harness: scripts/vulnApp.ts (shared with the
// eval script). A second scan runs with budgetUsd 0.5 and a fake cost model (every mock reply reports
// 10x the input tokens) to exercise budget-driven coverage.
import type Anthropic from '@anthropic-ai/sdk';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FindingSchema, type Finding } from '@vibesec/shared';
import { findingsOf, startVulnAppHarness, vulnAppFakeFetch, type VulnAppHarness } from '../scripts/vulnApp';
import { loadExpected, scoreFindings } from '../scripts/vulnAppScore';
import type { LlmTransport } from '../src/llm/transport';

const PARTNER_KEY_B64 = 'cGFydG5lcktleV9saXZlXzkyYWY0NGUwX2RvMWo4Znpx';
const RAW_CREDENTIALS = [
  PARTNER_KEY_B64,
  Buffer.from(PARTNER_KEY_B64, 'base64').toString('utf8'),
  'Sup3rS3cretPw!',
  'Tr0ub4dor&3xyzQ9',
];
/** No rate limiting in mock mode (the limiter models the real API's limits). */
const MOCK_ENV = { SCAN_MODE: 'mock', LLM_REQUESTS_PER_MINUTE: '100000', LLM_INPUT_TOKENS_PER_MINUTE: '1000000000' };
const TIER1 = ['triage', 'sast', 'taint', 'config', 'credential-hunter'];

type Diagnostics = {
  warnings: Array<{ code: string; message: string }>;
  coverage: {
    totals: Record<string, number>;
    byAnalyzer: Record<string, Record<string, number>>;
    budgetSkipped: Array<{ analyzer: string; path: string }>;
  };
  llm: { budgetUsd: number; totals: { costUsd: number } };
};

/** Fake cost model: every reply reports 10x the input tokens, so the spend is real money-sized. */
function inflateCost(inner: LlmTransport): LlmTransport {
  return {
    mode: inner.mode,
    async send(req, signal) {
      const msg = await inner.send(req, signal);
      return { ...msg, usage: { ...msg.usage, input_tokens: msg.usage.input_tokens * 10 } } as Anthropic.Message;
    },
  };
}

let full: VulnAppHarness;
let low: VulnAppHarness;

beforeAll(async () => {
  [full, low] = await Promise.all([
    startVulnAppHarness({ env: MOCK_ENV, fetch: vulnAppFakeFetch }),
    startVulnAppHarness({ env: MOCK_ENV, fetch: vulnAppFakeFetch, wrapTransport: inflateCost }),
  ]);
}, 120_000);

afterAll(async () => {
  await Promise.all([full?.close(), low?.close()]);
});

async function diagnostics(h: VulnAppHarness, scanId: string): Promise<Diagnostics> {
  const res = await h.app.inject({ method: 'GET', url: `/api/scans/${scanId}/diagnostics` });
  expect(res.statusCode).toBe(200);
  return res.json() as Diagnostics;
}

describe('Claude code analyzers, end to end over fixtures/vuln-app (mock LLM)', () => {
  it('finds sast, taint, config, secret, quality and dependency issues with valid findings, coverage and no leaked credential', async () => {
    const { scanId } = await full.scan();
    const scan = full.container.scans.getDto(scanId)!;
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(scan.state);
    expect(scan.warnings.map((w) => w.code)).not.toContain('ANALYZER_FAILED');
    expect(scan.warnings.map((w) => w.code)).not.toContain('BUDGET_COVERAGE_PARTIAL');

    const findings = findingsOf(full.container, scanId);
    for (const f of findings) expect(() => FindingSchema.parse(f)).not.toThrow();
    const byCategory = (c: Finding['category']) => findings.filter((f) => f.category === c);
    for (const c of ['sast', 'taint', 'config', 'secret', 'quality', 'dependency'] as const) {
      expect(byCategory(c).length, `no ${c} findings`).toBeGreaterThan(0);
    }

    // Taint: the SQL injection is traced from the route through the service, across files.
    const sqli = byCategory('taint').find((f) => f.location.file === 'api/src/services/invoiceService.ts');
    expect(sqli?.ruleId).toBe('taint/sql-injection');
    expect(sqli!.taintTrace!.length).toBeGreaterThanOrEqual(3);
    expect(sqli!.taintTrace![0]).toMatchObject({ kind: 'source', file: 'api/src/routes/invoices.ts' });
    expect(sqli!.taintTrace!.at(-1)).toMatchObject({ kind: 'sink', file: 'api/src/services/invoiceService.ts' });

    // Credential hunter: the base64-encoded partner key no regex recognizes, masked.
    const hunter = findings.find((f) => f.analyzer === 'credential-hunter' && f.location.file === 'api/src/config.ts');
    expect(hunter).toMatchObject({ ruleId: 'secret/hunter-encoded', location: { startLine: 1 } });
    // SAST fast pass (Haiku) covered the low-relevance files; the deep pass the rest.
    expect(byCategory('sast').every((f) => f.producedBy?.[0] === 'sast:llm' || f.producedBy?.[0] === 'sast:llm-fast')).toBe(true);

    const diag = await diagnostics(full, scanId);
    expect(diag.llm.budgetUsd).toBe(10);
    expect(diag.coverage.totals['budget-skipped']).toBe(0);
    expect(diag.coverage.budgetSkipped).toEqual([]);
    for (const a of ['triage', 'sast', 'taint', 'quality', 'config', 'credential-hunter']) {
      expect(diag.coverage.byAnalyzer[a]?.reviewed ?? 0, `${a} reviewed nothing`).toBeGreaterThan(0);
    }
    expect(diag.coverage.byAnalyzer.sast!['reviewed-fast']).toBeGreaterThan(0);
    expect(diag.coverage.byAnalyzer.sast!['not-relevant']).toBeGreaterThan(0); // relevance-0 + test files, recorded

    // The ground-truth scorer agrees: no false positive on a safe look-alike, every category hit.
    const report = scoreFindings(findings, loadExpected());
    expect(report.falsePositives).toEqual([]);
    for (const c of ['sast', 'taint', 'config', 'secret', 'dependency']) expect(report.recallByCategory[c]!.found).toBeGreaterThan(0);

    // Dump EVERY table and column plus every emitted event: no raw fixture credential anywhere.
    const tables = (full.container.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as Array<{ name: string }>).map((r) => r.name);
    expect(tables).toEqual(expect.arrayContaining(['scan_coverage', 'sast_cache', 'triage_cache']));
    const dumps = tables.map((t) => JSON.stringify(full.container.db.prepare(`SELECT * FROM "${t}"`).all()));
    dumps.push(JSON.stringify(full.container.bus.replay(scanId, 0)));
    const haystack = dumps.join('\n');
    for (const raw of RAW_CREDENTIALS) expect(haystack.includes(raw), `leaked ${raw.slice(0, 4)}…`).toBe(false);
  }, 120_000);

  it('answers a rescan of the same commit from the full-scan cache: instantly, $0, identical findings', async () => {
    const first = full.container.scans.listByRepo(full.container.scans.findRepo('acme', 'vuln-app')!.id).at(-1)!;
    const { scanId } = await full.scan();
    const scan = full.container.scans.getDto(scanId)!;
    expect(scan).toMatchObject({ state: first.state, cacheHit: 'full', costUsd: 0, commitSha: first.commitSha });
    expect(scan.reuse).toMatchObject({ baseScanId: first.id, filesChanged: 0 });
    expect(scan.reuse!.filesReused).toBeGreaterThan(0);
    expect(scan.reuse!.estimatedSavedUsd).toBeCloseTo(first.costUsd, 6);
    expect(full.container.llmCalls.totals(scanId).calls).toBe(0);
    const strip = (fs: Finding[]) => fs.map(({ id: _id, scanId: _s, ...rest }) => rest).sort((x, y) => (x.fingerprint < y.fingerprint ? -1 : 1));
    expect(strip(findingsOf(full.container, scanId))).toEqual(strip(findingsOf(full.container, first.id)));
    expect(full.container.summaries.get(scanId)?.riskGrade).toBe(full.container.summaries.get(first.id)?.riskGrade);
    // Straight from RESOLVING to the terminal state; the UI gets the reuse numbers in a `cache` event.
    const events = full.container.bus.replay(scanId, 0).map((e) => e.event);
    expect(events.flatMap((e) => (e.type === 'state' ? [e.state] : []))).toEqual(['QUEUED', 'RESOLVING', first.state]);
    expect(events).toContainEqual(expect.objectContaining({ type: 'cache', filesAnalyzed: 0, filesReused: scan.reuse!.filesReused }));
    expect(events.at(-1)).toEqual({ type: 'done', state: first.state });
  }, 120_000);

  it('serves a rescan with other options (no full-cache hit, no incremental base) from the SAST and triage caches', async () => {
    const { scanId } = await full.scan({ budgetUsd: 9 });
    expect(full.container.scans.getDto(scanId)?.cacheHit).toBe('none');
    const diag = await diagnostics(full, scanId);
    expect(diag.coverage.byAnalyzer.sast!.cached).toBeGreaterThan(0);
    expect(diag.coverage.byAnalyzer.sast!.reviewed ?? 0).toBe(0);
    expect(diag.coverage.byAnalyzer.triage!.cached).toBeGreaterThan(0);
  }, 120_000);

  it('with budgetUsd 0.5 and a fake cost model: BUDGET_COVERAGE_PARTIAL lists the skipped files, lower tiers skipped first', async () => {
    const { scanId } = await low.scan({ budgetUsd: 0.5 });
    const scan = low.container.scans.getDto(scanId)!;
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(scan.state);
    const warning = scan.warnings.find((w) => w.code === 'BUDGET_COVERAGE_PARTIAL');
    expect(warning?.message).toMatch(/file review\(s\) were skipped/);
    expect(warning?.message).toContain('budgetUsd');

    const diag = await diagnostics(low, scanId);
    expect(diag.llm.budgetUsd).toBe(0.5);
    expect(diag.coverage.budgetSkipped.length).toBeGreaterThan(0);
    expect(diag.coverage.totals['budget-skipped']).toBe(diag.coverage.budgetSkipped.length);
    for (const s of diag.coverage.budgetSkipped) expect(typeof s.path).toBe('string');

    // Risk-first: lower tiers never spend while tier-1 work goes unreviewed for lack of budget.
    const skipped = (a: string) => diag.coverage.byAnalyzer[a]?.['budget-skipped'] ?? 0;
    const tier1Skipped = TIER1.reduce((n, a) => n + skipped(a), 0);
    const quality = diag.coverage.byAnalyzer.quality ?? {};
    expect(tier1Skipped).toBeGreaterThan(0); // the budget really is too small for the security work…
    expect(skipped('quality')).toBeGreaterThan(0);
    expect(quality.reviewed ?? 0).toBe(0); // …so tier 3 (quality) got nothing
    expect(diag.coverage.byAnalyzer.sast?.['reviewed-fast'] ?? 0).toBe(0); // …nor tier 2 (SAST fast pass)
    expect(diag.coverage.byAnalyzer.triage?.reviewed ?? 0).toBeGreaterThan(0); // while tier 1 ran first
    expect(diag.llm.totals.costUsd).toBeLessThanOrEqual(0.5 * 1.5); // in-flight overshoot is bounded
  }, 120_000);
});
