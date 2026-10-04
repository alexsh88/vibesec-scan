import { setTimeout as sleep } from 'node:timers/promises';
import type { Pipeline, PipelineContext, StageName, StageSpec } from './types';

const ANALYZERS = ['secrets', 'deps', 'triage', 'sast', 'taint', 'quality', 'config'] as const;

/** P1 placeholder: walks every stage with realistic events so the API and UI can be built end to end. */
export function createStubPipeline(stepMs = 400): Pipeline {
  const step = (ctx: PipelineContext) => sleep(stepMs, undefined, { signal: ctx.signal });
  const simple = (name: StageName, fatal: boolean): StageSpec => ({ name, fatal, run: step });

  return {
    stages: [
      {
        name: 'RESOLVING', fatal: true,
        run: async (ctx) => {
          await step(ctx);
          ctx.checkpointData.commitSha = '0'.repeat(40);
        },
      },
      simple('CLONING', true),
      simple('INDEXING', true),
      {
        // The real ANALYZING stage must throw a fatal AppError when EVERY analyzer fails (spec §14.6:
        // "all analyzers failed ⇒ FAILED"); see StageSpec in ./types. The stub never fails.
        name: 'ANALYZING', fatal: false,
        run: async (ctx) => {
          for (const [i, analyzer] of ANALYZERS.entries()) {
            await step(ctx);
            ctx.emit({ type: 'progress', analyzer, done: i + 1, total: ANALYZERS.length });
          }
          ctx.emit({
            type: 'finding',
            finding: {
              id: 'stub-1', category: 'secret', severity: 'high',
              title: 'Example finding from the stub pipeline',
              location: { file: 'src/config.ts', startLine: 3, endLine: 3, snippet: 'const KEY = "…"', permalink: '' },
            },
          });
        },
      },
      simple('VERIFYING', false),
      simple('SCORING', true),
      simple('SYNTHESIZING', false),
    ],
  };
}
