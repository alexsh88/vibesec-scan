import { z } from 'zod';
import { CategorySchema, ConfidenceSchema, SeveritySchema } from './enums';

export const TaintStepSchema = z.object({
  kind: z.enum(['source', 'propagator', 'sanitizer', 'sink']),
  file: z.string(), line: z.number().int().positive(), code: z.string(), note: z.string(),
});

export const AdvisorySchema = z.object({
  id: z.string(), aliases: z.array(z.string()), summary: z.string(),
  severity: SeveritySchema, cvss: z.number().nullable(), fixedIn: z.string().nullable(), url: z.string().nullable(),
});
export type Advisory = z.infer<typeof AdvisorySchema>;

export const FindingSchema = z.object({
  id: z.string(),
  scanId: z.string(),
  fingerprint: z.string(),
  category: CategorySchema,
  ruleId: z.string(),
  cwe: z.string().optional(),
  title: z.string(),
  baseSeverity: SeveritySchema,
  riskScore: z.number().min(0).max(100),
  severity: SeveritySchema,
  riskFactors: z.array(z.object({ factor: z.string(), effect: z.number(), reason: z.string() })),
  confidence: ConfidenceSchema,
  location: z.object({
    file: z.string(), startLine: z.number().int().positive(), endLine: z.number().int().positive(),
    startCol: z.number().int().nonnegative().optional(), snippet: z.string(), permalink: z.string(),
  }),
  taintTrace: z.array(TaintStepSchema).optional(),
  secret: z.object({
    type: z.string(), redacted: z.string(),
    liveness: z.enum(['live', 'revoked', 'unknown', 'not_checked']),
    checkedAt: z.string().optional(), inHistoryOnly: z.boolean(), commit: z.string().optional(),
  }).optional(),
  dependency: z.object({
    ecosystem: z.enum(['npm', 'PyPI']), name: z.string(), version: z.string(),
    scope: z.enum(['prod', 'dev']), direct: z.boolean(), paths: z.array(z.array(z.string())),
    advisories: z.array(AdvisorySchema), fixedIn: z.string().optional(),
    reachability: z.enum(['reachable', 'imported', 'unreachable', 'unknown']),
    reachabilityEvidence: z.array(z.object({ file: z.string(), line: z.number().int() })).optional(),
  }).optional(),
  explanation: z.string(),
  impact: z.string(),
  remediation: z.object({ summary: z.string(), patch: z.string().optional() }),
  scanStatus: z.enum(['new', 'existing', 'fixed']),
  producedBy: z.array(z.string()).optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const FindingSummarySchema = FindingSchema.pick({
  id: true, category: true, title: true, severity: true, location: true,
});
export type FindingSummary = z.infer<typeof FindingSummarySchema>;
