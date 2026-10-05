// npm run eval:vuln-app — measures a full scan of fixtures/vuln-app against its ground truth.
//
// Runs the real pipeline in-process (scripts/vulnApp.ts harness: createContainer wiring, local git
// clone, HTTP API via app.inject) using the configured SCAN_MODE:
//   - mock (default, no ANTHROPIC_API_KEY): deterministic mock LLM responders; OSV + npm/PyPI are
//     served from offline fixtures (vulnAppFakeFetch), so the run is hermetic and free;
//   - live (ANTHROPIC_API_KEY loaded from the environment or the repo's dotenv file): real Claude
//     calls, and OSV/registries are queried live — this costs money (bounded by the scan budget;
//     pass --budget=<usd> or EVAL_BUDGET_USD to set budgetUsd for the scan).
// Prints a per-issue table (found/missed + which analyzer), recall overall and per category, false
// positives on the safe look-alikes, total findings, cost (USD + tokens by analyzer, from the
// diagnostics endpoint) and duration, and writes the full JSON report to $TEMP (path printed) —
// never into the repository. Always exits 0 (it is a measurement) unless the scan itself fails.

import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadDotEnv } from '../src/config';
import { findingsOf, startVulnAppHarness, vulnAppFakeFetch } from './vulnApp';
import { loadExpected, scoreFindings } from './vulnAppScore';

type Diagnostics = {
  state: string;
  warnings: Array<{ code: string; message: string }>;
  coverage: { totals: Record<string, number>; byAnalyzer: Record<string, Record<string, number>>; budgetSkipped: Array<{ analyzer: string; path: string }> };
  llm: {
    mode: string; budgetUsd: number;
    totals: { calls: number; inputTokens: number; outputTokens: number; cacheReadTokens: number; costUsd: number };
    byAnalyzer: Array<{ analyzer: string; calls: number; inputTokens: number; outputTokens: number; cacheReadTokens: number; costUsd: number }>;
  };
};

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
const pad = (s: string, n: number) => (s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length));

function budgetArg(): number | undefined {
  const arg = process.argv.find((a) => a.startsWith('--budget='))?.slice('--budget='.length) ?? process.env.EVAL_BUDGET_USD;
  const n = arg ? Number(arg) : NaN;
  return Number.isFinite(n) ? n : undefined;
}

async function main(): Promise<number> {
  loadDotEnv();
  const mode = process.env.SCAN_MODE ?? (process.env.ANTHROPIC_API_KEY ? 'live' : 'mock');
  const harness = await startVulnAppHarness({
    // The rate limiter models the real API; mock replies need none of it.
    env: mode === 'mock'
      ? { LLM_REQUESTS_PER_MINUTE: '100000', LLM_INPUT_TOKENS_PER_MINUTE: '1000000000', ...process.env }
      : { ...process.env },
    ...(mode === 'mock' ? { fetch: vulnAppFakeFetch } : {}),
  });
  try {
    const budgetUsd = budgetArg();
    console.log(`vuln-app eval — SCAN_MODE=${mode}${budgetUsd ? `, budgetUsd=${budgetUsd}` : ''} (OSV/registries: ${mode === 'mock' ? 'offline fixtures' : 'live'})`);
    const { scanId, durationMs } = await harness.scan(budgetUsd ? { budgetUsd } : {});
    const scan = harness.container.scans.getDto(scanId)!;
    if (scan.state !== 'COMPLETED' && scan.state !== 'COMPLETED_WITH_WARNINGS') {
      console.error(`Scan ${scanId} ended in ${scan.state}: ${scan.errorCode ?? ''} ${scan.errorMessage ?? ''}`);
      return 1;
    }
    const diag = (await harness.app.inject({ method: 'GET', url: `/api/scans/${scanId}/diagnostics` })).json() as Diagnostics;
    const findings = findingsOf(harness.container, scanId);
    const expected = loadExpected();
    const report = scoreFindings(findings, expected);

    console.log('');
    console.log(`${pad('ID', 5)}${pad('CATEGORY', 11)}${pad('RULE HINT', 28)}${pad('LOCATION', 42)}${pad('RESULT', 8)}ANALYZER(S)`);
    for (const v of report.verdicts) {
      const by = [...new Set(v.matchedBy.map((m) => `${m.analyzer} (${m.ruleId})`))].join(', ');
      console.log(`${pad(v.issue.id, 5)}${pad(v.issue.category, 11)}${pad(v.issue.ruleHint, 28)}${pad(`${v.issue.file}:${v.issue.line}`, 42)}${pad(v.found ? 'FOUND' : 'MISSED', 8)}${by}`);
    }
    console.log('');
    const found = report.verdicts.filter((v) => v.found).length;
    console.log(`Recall: ${found}/${report.verdicts.length} = ${pct(report.recall)}`);
    for (const [cat, r] of Object.entries(report.recallByCategory).sort()) console.log(`  ${pad(cat, 11)} ${r.found}/${r.total} = ${pct(r.recall)}`);
    console.log(`False positives on safe look-alikes: ${report.falsePositives.length}/${expected.safe.length}`);
    for (const fp of report.falsePositives) console.log(`  ${fp.safe.file}:${fp.safe.line} <- ${fp.findings.map((f) => `${f.ruleId}@${f.line}`).join(', ')}`);
    const byCategory = new Map<string, number>();
    for (const f of findings) byCategory.set(f.category, (byCategory.get(f.category) ?? 0) + 1);
    console.log(`Total findings: ${findings.length} (${[...byCategory.entries()].map(([c, n]) => `${c} ${n}`).join(', ')})`);
    console.log(`Cost: $${diag.llm.totals.costUsd.toFixed(4)} of $${diag.llm.budgetUsd} budget — ${diag.llm.totals.calls} calls, ${diag.llm.totals.inputTokens} in / ${diag.llm.totals.outputTokens} out / ${diag.llm.totals.cacheReadTokens} cache-read tokens (mode ${diag.llm.mode})`);
    for (const a of diag.llm.byAnalyzer) {
      console.log(`  ${pad(a.analyzer, 19)} $${a.costUsd.toFixed(4)}  ${a.calls} calls  ${a.inputTokens} in / ${a.outputTokens} out`);
    }
    const t = diag.coverage.totals;
    console.log(`Coverage: reviewed ${t.reviewed ?? 0}, fast ${t['reviewed-fast'] ?? 0}, cached ${t.cached ?? 0}, not-relevant ${t['not-relevant'] ?? 0}, budget-skipped ${t['budget-skipped'] ?? 0}, failed ${t.failed ?? 0}`);
    console.log(`Warnings: ${diag.warnings.map((w) => w.code).join(', ') || 'none'}`);
    console.log(`Duration: ${(durationMs / 1000).toFixed(1)}s`);

    const out = join(tmpdir(), `vibesec-eval-vuln-app-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
    await writeFile(out, JSON.stringify({
      scanId, mode, durationMs, state: scan.state, report,
      cost: diag.llm, coverage: diag.coverage, warnings: diag.warnings,
      findings: findings.map((f) => ({ analyzer: f.analyzer, ruleId: f.ruleId, category: f.category, severity: f.severity, file: f.location.file, line: f.location.startLine })),
    }, null, 2));
    console.log(`JSON report: ${out}`);
    return 0;
  } finally {
    await harness.close();
  }
}

main().then((code) => process.exit(code), (err: unknown) => {
  console.error(err);
  process.exit(1);
});
