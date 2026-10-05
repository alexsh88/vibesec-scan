import { z } from 'zod';
import { loadConfig } from '../src/config';
import { createContainer } from '../src/container';
import type { ModelRole } from '../src/llm/models';

/**
 * One tiny structured call per model tier against the real API.
 *   ANTHROPIC_API_KEY=… npm run llm:smoke                 → live
 *   ANTHROPIC_API_KEY=… SCAN_MODE=record npm run llm:smoke → live + write recordings
 * Without a key it exits 0 after printing that it skipped.
 */
async function main(): Promise<void> {
  const config = loadConfig();
  if (config.scanMode === 'mock') {
    console.log('SCAN_MODE=mock (no ANTHROPIC_API_KEY): skipping the live LLM smoke test.');
    return;
  }
  const c = createContainer({ ...config, dbPath: ':memory:' });
  const Echo = z.object({ ok: z.boolean(), echo: z.string() });
  let failures = 0;
  for (const role of ['fast', 'deep', 'synthesis'] as ModelRole[]) {
    try {
      const r = await c.llm.structured({
        scanId: null, analyzer: 'smoke', purpose: 'smoke', promptVersion: 'smoke-v1', role,
        system: 'You are a terse assistant that answers in JSON.',
        prompt: 'Set ok to true and echo the single word "vibesec".',
        schema: Echo, maxTokens: 1_024, signal: AbortSignal.timeout(90_000),
      });
      console.log(`${role.padEnd(9)} ${r.model.padEnd(18)} ${JSON.stringify(r.output)}  in=${r.usage.inputTokens} out=${r.usage.outputTokens} $${r.costUsd.toFixed(5)}`);
      if (!r.output.ok || r.output.echo.toLowerCase() !== 'vibesec') failures++;
    } catch (err) {
      failures++;
      console.error(`${role.padEnd(9)} FAILED: ${(err as Error).message}`);
    }
  }
  c.db.close();
  if (failures) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
