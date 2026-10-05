// Reproduces (in-process, no GitHub, no real Docker) why a mock-mode scan of a repo with dependencies
// used to end COMPLETED_WITH_WARNINGS even though nothing was actually degraded: with SANDBOX_ENABLED
// left at its default 'true' and no Docker available (or sandbox images never built — the normal state
// outside a full deploy, and the exact condition the UI agents hit scanning a real public repo), the
// dependencies analyzer warns SANDBOX_UNAVAILABLE and falls back to the import index. Before
// pipeline/warningLevels.ts classified that as 'info', ANY warning (regardless of whether it signalled
// real degradation) flipped the scan to COMPLETED_WITH_WARNINGS and permanently excluded it from the
// full-scan cache (ScanRepo.findFullCacheSource only serves a clean COMPLETED/all-info result) — so a
// demo could never get a full-cache hit on a second identical scan.
import type { ContainerSandbox } from '../src/container';
import { afterEach, describe, expect, it } from 'vitest';
import { classifyWarningLevel } from '../src/pipeline/warningLevels';
import { startVulnAppHarness, vulnAppFakeFetch, type VulnAppHarness } from '../scripts/vulnApp';

const MOCK_ENV = { SCAN_MODE: 'mock', LLM_REQUESTS_PER_MINUTE: '100000', LLM_INPUT_TOKENS_PER_MINUTE: '1000000000' };

/** Deterministic stand-in for "Docker unavailable / sandbox images not built" — no real Docker daemon
 *  needed, and no dependence on whether the box running this test happens to have one. */
const SANDBOX_UNAVAILABLE_STUB: ContainerSandbox = {
  availability: async () => ({ ok: false, reason: 'sandbox image vibesec-sandbox-node:v1 not found (never built in this environment)' }),
  install: async () => { throw new Error('unreachable: availability() already failed'); },
  analyze: async () => { throw new Error('unreachable: availability() already failed'); },
  sweep: async () => undefined,
};

let harness: VulnAppHarness | undefined;
afterEach(async () => {
  await harness?.close();
  harness = undefined;
});

describe('mock-mode scan of the vuln-app harness — warning classification', () => {
  it('a sandbox-unavailable mock scan ends COMPLETED (info-only), and a second identical scan is a full-cache hit', async () => {
    harness = await startVulnAppHarness({
      env: { ...MOCK_ENV, SANDBOX_ENABLED: 'true' },
      fetch: vulnAppFakeFetch,
      sandbox: SANDBOX_UNAVAILABLE_STUB,
    });

    const { scanId } = await harness.scan();
    const scan = harness.container.scans.getDto(scanId)!;

    // Reproduced: the sandbox-unavailable path really does fire for this harness/config.
    expect(scan.warnings.map((w) => w.code)).toContain('SANDBOX_UNAVAILABLE');
    // Every warning this clean scan produced is classified, and every single one is 'info' — nothing
    // here signals real degradation (no analyzer failed, no budget was exhausted, no AI call failed).
    for (const w of scan.warnings) {
      expect(classifyWarningLevel(w.code), `${w.code}: ${w.message}`).toBe('info');
      expect(w.level, `${w.code} was persisted with the wrong level`).toBe('info');
    }
    // So the scan is fully clean: COMPLETED, not COMPLETED_WITH_WARNINGS.
    expect(scan.state).toBe('COMPLETED');

    // A second identical scan is a full-cache hit: $0, instant, no re-analysis.
    const second = await harness.scan();
    const rescan = harness.container.scans.getDto(second.scanId)!;
    expect(rescan.cacheHit).toBe('full');
    expect(rescan.costUsd).toBe(0);
    expect(harness.container.llmCalls.totals(second.scanId).calls).toBe(0);
  }, 120_000);

  it('a clean mock scan with the sandbox disabled (no dependency warnings at all) also ends COMPLETED and full-cache-hits', async () => {
    harness = await startVulnAppHarness({ env: MOCK_ENV, fetch: vulnAppFakeFetch }); // SANDBOX_ENABLED defaults 'false'

    const { scanId } = await harness.scan();
    const scan = harness.container.scans.getDto(scanId)!;
    expect(['COMPLETED', 'COMPLETED_WITH_WARNINGS']).toContain(scan.state);
    for (const w of scan.warnings) expect(classifyWarningLevel(w.code), `${w.code}: ${w.message}`).toBe('info');
    expect(scan.state).toBe('COMPLETED');

    const second = await harness.scan();
    expect(harness.container.scans.getDto(second.scanId)!.cacheHit).toBe('full');
  }, 120_000);
});
