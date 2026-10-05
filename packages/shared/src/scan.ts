import { z } from 'zod';
import { CATEGORIES, CategorySchema, ScanStateSchema } from './enums';

// Owner: alphanumeric, may contain interior hyphens, but can't start/end with one (GitHub rule).
const REPO_URL_RE = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/;

export function parseRepoUrl(url: string): { owner: string; name: string } | null {
  const m = url.match(REPO_URL_RE);
  if (!m || !m[1] || !m[2]) return null;
  const owner = m[1];
  const name = m[2];
  if (name === '.' || name === '..') return null;
  return { owner, name };
}

// Mirrors the subset of `git check-ref-format` rules relevant to option-injection and
// path-escape safety, since P2 passes `ref` straight to git. A leading `-` could be
// parsed as a CLI flag (e.g. `-u./evil.sh`); `..`, `//`, `@{`, backslashes, whitespace/
// control chars, and a trailing `/`/`.lock` are all invalid or dangerous ref components.
const REF_CHAR_RE = /^[\w./-]+$/;

export function isValidRef(ref: string): boolean {
  if (!REF_CHAR_RE.test(ref)) return false;
  if (ref.startsWith('-')) return false;
  if (ref.includes('..')) return false;
  if (ref.includes('//')) return false;
  if (ref.includes('@{')) return false;
  if (ref.endsWith('/') || ref.endsWith('.lock')) return false;
  if (ref === '@') return false;
  return true;
}

export const ScanOptionsSchema = z.object({
  verifySecrets: z.boolean().default(false),
  historyDepth: z.number().int().min(0).max(500).default(50),
  categories: z.array(CategorySchema).min(1).default([...CATEGORIES]),
  /** Per-scan AI budget in USD (defaults to the server's SCAN_BUDGET_USD). Part of the options hash. */
  budgetUsd: z.number().min(0.5).max(100).optional(),
});
export type ScanOptions = z.infer<typeof ScanOptionsSchema>;

export const CreateScanRequestSchema = z.object({
  repoUrl: z.string().refine((u) => parseRepoUrl(u) !== null, 'Must be https://github.com/<owner>/<repo>'),
  ref: z.string().min(1).max(255).refine(isValidRef, 'Invalid git ref').optional(),
  auth: z.object({ type: z.literal('pat'), token: z.string().min(10).max(255) }).optional(),
  options: ScanOptionsSchema.default(() => ScanOptionsSchema.parse({})),
});
export type CreateScanRequest = z.infer<typeof CreateScanRequestSchema>;

export const CacheHitSchema = z.enum(['none', 'partial', 'full']);

/**
 * What a cached rescan reused from an earlier scan (spec §11): 'full' = same commit + same result
 * configuration → every result copied, $0; 'partial' = incremental rescan, only changed/affected files
 * were analyzed again. `estimatedSavedUsd` is an estimate (see apps/api/src/pipeline/incremental.ts).
 */
export const ReuseStatsSchema = z.object({
  baseScanId: z.string(),
  filesChanged: z.number().int().nonnegative(),
  filesDeleted: z.number().int().nonnegative().optional(),
  filesReused: z.number().int().nonnegative(),
  estimatedSavedUsd: z.number().nonnegative(),
});
export type ReuseStats = z.infer<typeof ReuseStatsSchema>;

/** `level: 'info'` warnings are notes (e.g. "rescan fell back to a full scan"): they never make a scan COMPLETED_WITH_WARNINGS. */
export const ScanWarningSchema = z.object({
  code: z.string(), message: z.string(), stage: z.string().optional(), level: z.enum(['info', 'warning']).optional(),
});

export const ScanDtoSchema = z.object({
  id: z.string(),
  repo: z.object({ id: z.string(), owner: z.string(), name: z.string(), isPrivate: z.boolean() }),
  ref: z.string().nullable(),
  commitSha: z.string().nullable(),
  state: ScanStateSchema,
  errorCode: z.string().nullable(),
  errorMessage: z.string().nullable(),
  cacheHit: CacheHitSchema,
  options: ScanOptionsSchema,
  costUsd: z.number(),
  createdAt: z.string(),
  startedAt: z.string().nullable(),
  finishedAt: z.string().nullable(),
  warnings: z.array(ScanWarningSchema),
  /** The earlier scan whose results were reused (cacheHit 'full' | 'partial'), with reuse stats. */
  reuse: ReuseStatsSchema.nullable().optional(),
});
export type ScanDto = z.infer<typeof ScanDtoSchema>;
