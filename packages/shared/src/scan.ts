import { z } from 'zod';
import { CATEGORIES, CategorySchema, ScanStateSchema } from './enums';

const REPO_URL_RE = /^https:\/\/github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/;

export function parseRepoUrl(url: string): { owner: string; name: string } | null {
  const m = url.match(REPO_URL_RE);
  if (!m || !m[1] || !m[2]) return null;
  return { owner: m[1], name: m[2] };
}

export const ScanOptionsSchema = z.object({
  verifySecrets: z.boolean().default(false),
  historyDepth: z.number().int().min(0).max(500).default(50),
  categories: z.array(CategorySchema).min(1).default([...CATEGORIES]),
});
export type ScanOptions = z.infer<typeof ScanOptionsSchema>;

export const CreateScanRequestSchema = z.object({
  repoUrl: z.string().refine((u) => parseRepoUrl(u) !== null, 'Must be https://github.com/<owner>/<repo>'),
  ref: z.string().min(1).max(255).regex(/^[\w./-]+$/).optional(),
  auth: z.object({ type: z.literal('pat'), token: z.string().min(10).max(255) }).optional(),
  options: ScanOptionsSchema.default(ScanOptionsSchema.parse({})),
});
export type CreateScanRequest = z.infer<typeof CreateScanRequestSchema>;

export const CacheHitSchema = z.enum(['none', 'partial', 'full']);

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
  warnings: z.array(z.object({ code: z.string(), message: z.string(), stage: z.string().optional() })),
});
export type ScanDto = z.infer<typeof ScanDtoSchema>;
