/**
 * VERIFYING stage (runs after ANALYZING, before SCORING). Degradable (`fatal: false`): any failure
 * leaves the findings as ANALYZING persisted them and records a VERIFY_PARTIAL warning.
 *
 *   1. Cross-analyzer dedupe over ALL findings of the scan (findings/crossDedupe.ts): the same bug
 *      reported by SAST + taint (+ config/quality) collapses into one, losers are removed.
 *   2. Skeptic pass (findings/skeptic.ts): Claude argues against each remaining critical/high SAST or
 *      taint finding with the real code in front of it. Refuted findings are downgraded to info (with
 *      an 'ai_refuted' risk factor), never deleted.
 *   3. One atomic `findings.update(scanId, changed, removedIds)`.
 *
 * Events: `finding` events were already emitted by ANALYZING (consumers dedupe by id and re-fetch the
 * list at the end of the scan), so this stage emits none; it only emits `progress` events
 * (analyzer 'verify', done/total skeptic batches) and at most one VERIFY_PARTIAL warning.
 * Idempotent: a re-run finds no duplicates left and skips findings already marked 'skeptic:*'.
 */

import { lstat, open } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import type { Finding } from '@vibesec/shared';
import type { FindingRepo } from '../../db/findingRepo';
import { toAppError } from '../../errors/AppError';
import { crossDedupe } from '../../findings/crossDedupe';
import { partialSummary, runSkeptic } from '../../findings/skeptic';
import type { GitService } from '../../git/GitService';
import type { LlmClient } from '../../llm/LlmClient';
import type { StageSpec } from '../types';

export type VerifyStageDeps = {
  findings: Pick<FindingRepo, 'all' | 'update'>;
  llm: Pick<LlmClient, 'structured'>;
  git: Pick<GitService, 'repoDir'>;
  /** Safety cap on skeptic-reviewed findings (≤ 200); the scan budget usually binds first. */
  maxSkeptic?: number;
  concurrency?: number;
};

const MAX_FILE_BYTES = 256 * 1024;
const NUL_PROBE_BYTES = 8_192;

/** Repo-confined utf8 read (no symlinks, no binaries, ≤ 256 KiB); null when unreadable/unsafe. */
export async function readRepoFile(repoDir: string, path: string): Promise<string | null> {
  const root = resolve(repoDir);
  const abs = resolve(join(root, ...path.split('/')));
  if (!abs.startsWith(root + sep)) return null;
  const st = await lstat(abs).catch(() => null);
  if (!st || !st.isFile()) return null;
  const handle = await open(abs, 'r').catch(() => null);
  if (!handle) return null;
  try {
    const length = Math.min(st.size, MAX_FILE_BYTES);
    const buffer = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const { bytesRead } = await handle.read(buffer, read, length - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    if (buffer.subarray(0, Math.min(NUL_PROBE_BYTES, read)).includes(0)) return null;
    return buffer.subarray(0, read).toString('utf8');
  } catch {
    return null;
  } finally {
    await handle.close();
  }
}

export function verifyStage(deps: VerifyStageDeps): StageSpec {
  return {
    name: 'VERIFYING',
    fatal: false,
    run: async (ctx) => {
      const warnPartial = (message: string) => ctx.warn({ code: 'VERIFY_PARTIAL', message, stage: 'VERIFYING' });
      const rows = deps.findings.all(ctx.scanId);
      if (rows.length === 0) return;

      const dedupe = crossDedupe(rows);
      const changed = new Map<string, Finding>(dedupe.changed.map((f) => [f.id, f]));
      try {
        const repoDir = deps.git.repoDir(ctx.scanId);
        const skeptic = await runSkeptic(dedupe.kept, {
          scanId: ctx.scanId,
          signal: ctx.signal,
          touch: ctx.touch,
          onProgress: (done, total) => ctx.emit({ type: 'progress', analyzer: 'verify', done, total }),
        }, {
          llm: deps.llm,
          readFile: (path) => readRepoFile(repoDir, path),
          ...(deps.maxSkeptic !== undefined ? { maxSkeptic: deps.maxSkeptic } : {}),
          ...(deps.concurrency !== undefined ? { concurrency: deps.concurrency } : {}),
        });
        for (const f of skeptic.changed) changed.set(f.id, f);
        const partial = partialSummary(skeptic);
        if (partial) warnPartial(partial);
      } catch (raw) {
        const err = toAppError(raw);
        if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
        // Fail-open: keep the dedupe result; findings stay unverified.
        warnPartial('The AI skeptic review could not run; critical/high findings are reported unverified.');
      }

      if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      if (changed.size > 0 || dedupe.removedIds.length > 0) {
        deps.findings.update(ctx.scanId, [...changed.values()], dedupe.removedIds);
      }
    },
  };
}
