import { createHash } from 'node:crypto';
import type { ScanOptions } from '@vibesec/shared';
import { canonicalJson } from '../audit/canonicalJson';
import type { ScanCacheKeys } from '../db/scanRepo';

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

/** Everything besides the code and the options that decides what a scan reports (spec §11). */
export type ResultConfiguration = {
  /** Every analyzer as `id@version`. */
  analyzers: ReadonlyArray<{ id: string; version: string }>;
  /** Every prompt version that shapes a result (analyzers, triage, skeptic, synthesis …). */
  promptVersions: readonly string[];
  /** Model id per tier. */
  models: Readonly<Record<string, string>>;
  /** live / record / mock: mock answers must never be served for a live scan (and vice versa). */
  llmMode: string;
};

/**
 * analyzerVersionsHash = sha256 of every analyzer id+version, prompt version and model id (and the LLM
 * mode). Bumping any of them invalidates the full-scan cache and incremental reuse in one go.
 */
export function analyzerVersionsHash(cfg: ResultConfiguration): string {
  return sha256(canonicalJson({
    analyzers: [...cfg.analyzers].map((a) => `${a.id}@${a.version}`).sort(),
    promptVersions: [...new Set(cfg.promptVersions)].sort(),
    models: cfg.models,
    llmMode: cfg.llmMode,
  }));
}

/**
 * Hash of the result-defining options. Unlike ScanService's options hash (dedupe of in-flight scans:
 * ref + options) it leaves the ref out — the resolved commit SHA already pins the code, so scanning
 * `main` and a tag on the same commit is the same work.
 */
export function resultOptionsHash(options: ScanOptions): string {
  return sha256(canonicalJson({ ...options, categories: [...new Set(options.categories)].sort() }));
}

export function scanCacheKeys(options: ScanOptions, cfg: ResultConfiguration): ScanCacheKeys {
  return { resultOptionsHash: resultOptionsHash(options), analyzerVersionsHash: analyzerVersionsHash(cfg) };
}
