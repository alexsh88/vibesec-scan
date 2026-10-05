import { z } from 'zod';
import { CategorySchema, SeveritySchema } from './enums';

export const RISK_GRADES = ['A', 'B', 'C', 'D', 'F'] as const;
export const RiskGradeSchema = z.enum(RISK_GRADES);
export type RiskGrade = z.infer<typeof RiskGradeSchema>;

export const EffortSchema = z.enum(['minutes', 'hours', 'days']);
export type SummaryEffort = z.infer<typeof EffortSchema>;

export const TopRiskSchema = z.object({
  title: z.string().min(1).max(160),
  whyItMatters: z.string().min(1).max(400),
  /** Real finding ids of the scan (unknown ids are dropped server-side; a risk with none left is dropped). */
  findingIds: z.array(z.string()).min(1),
  severity: SeveritySchema,
});
export type TopRisk = z.infer<typeof TopRiskSchema>;

export const NextActionSchema = z.object({
  title: z.string().min(1).max(160),
  detail: z.string().min(1).max(400),
  effort: EffortSchema,
  /** A FixAction id from the scan's fix plan, when this action is a dependency upgrade/removal. */
  fixActionId: z.string().optional(),
  findingIds: z.array(z.string()),
});
export type NextAction = z.infer<typeof NextActionSchema>;

export const SummaryStatsSchema = z.object({
  /** Every severity key is present (zero-filled), including 'info'. */
  bySeverity: z.record(SeveritySchema, z.number().int().nonnegative()),
  byCategory: z.record(CategorySchema, z.number().int().nonnegative()),
  total: z.number().int().nonnegative(),
});
export type SummaryStats = z.infer<typeof SummaryStatsSchema>;

/** The first screen of a scan's results (spec §9.3): built by Opus from findings only, never from code. */
export const ScanSummarySchema = z.object({
  scanId: z.string(),
  riskGrade: RiskGradeSchema,
  headline: z.string().min(1).max(160),
  /** 2–4 sentences. */
  overview: z.string().min(1).max(800),
  /** 3–5 (fewer when the scan has fewer findings), most important first. */
  topRisks: z.array(TopRiskSchema).max(5),
  /** Ordered: do the first one first. */
  nextActions: z.array(NextActionSchema).max(8),
  /** Only evidenced strengths (e.g. no credentials found in a scan that looked for them). */
  positiveObservations: z.array(z.string().min(1).max(300)).max(5),
  stats: SummaryStatsSchema,
  generatedBy: z.enum(['llm', 'fallback']),
  model: z.string().optional(),
});
export type ScanSummary = z.infer<typeof ScanSummarySchema>;
