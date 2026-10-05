import { z } from 'zod';
import { SeveritySchema } from './enums';

/** One advisory on one installed package version that a fix action resolves. */
export const FixResolvesSchema = z.object({
  findingId: z.string(),
  advisoryId: z.string(),
  severity: SeveritySchema,
  package: z.string(),
  version: z.string(),
});
export type FixResolves = z.infer<typeof FixResolvesSchema>;

export const FixActionKindSchema = z.enum(['upgrade-direct', 'upgrade-parent', 'override', 'remove']);
export type FixActionKindDto = z.infer<typeof FixActionKindSchema>;

/**
 * One "next action" for dependency vulnerabilities. Advisories are aggregated per action, so a
 * single upgrade lists everything it fixes ("fixing X also fixes Y and Z").
 */
export const FixActionSchema = z.object({
  id: z.string(),
  scanId: z.string(),
  ecosystem: z.enum(['npm', 'PyPI']),
  manifestDir: z.string(),
  lockfile: z.string(),
  kind: FixActionKindSchema,
  /** The package the user changes: the direct dep for upgrade-direct/parent, the vulnerable package for override/remove. */
  package: z.string(),
  from: z.string(),
  /** null when no fixed version exists (kind 'remove'). */
  to: z.string().nullable(),
  semverJump: z.enum(['patch', 'minor', 'major']).nullable(),
  breakingRisk: z.boolean(),
  resolves: z.array(FixResolvesSchema),
  /** Distinct advisories resolved. */
  resolvedCount: z.number().int(),
  /** Sum of the resolved findings' risk scores (each finding counted once). */
  riskReduced: z.number(),
  effort: z.number(),
  /** riskReduced / effort — actions are sorted by this, descending. */
  priority: z.number(),
  command: z.string(),
  notes: z.array(z.string()),
});
export type FixAction = z.infer<typeof FixActionSchema>;

export const UnfixableSchema = z.object({
  package: z.string(),
  version: z.string(),
  advisoryIds: z.array(z.string()),
  reason: z.string(),
});
export type Unfixable = z.infer<typeof UnfixableSchema>;

export const FixPlanSchema = z.object({
  scanId: z.string(),
  actions: z.array(FixActionSchema),
  unfixable: z.array(UnfixableSchema),
});
export type FixPlan = z.infer<typeof FixPlanSchema>;
