// SARIF 2.1.0 export (P7 Task B). We emit a single `run` and validate the exact shape we produce
// against a minimal hand-written zod schema below (no external schema download/validation).
import { z } from 'zod';
import { activeTriage, type Finding, type ScanDto, type Severity } from '@vibesec/shared';

type TaintStep = NonNullable<Finding['taintTrace']>[number];

export const VIBESEC_TOOL_VERSION = '0.1.0';
export const VIBESEC_INFORMATION_URI = 'https://github.com/vibesec/vibesec';

const SarifLevelSchema = z.enum(['error', 'warning', 'note']);

const SarifRuleSchema = z.object({
  id: z.string(),
  shortDescription: z.object({ text: z.string() }),
  helpUri: z.string().optional(),
  properties: z.object({ tags: z.array(z.string()) }),
  defaultConfiguration: z.object({ level: SarifLevelSchema }),
});

const SarifRegionSchema = z.object({
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  snippet: z.object({ text: z.string() }),
});

const SarifLocationSchema = z.object({
  physicalLocation: z.object({
    artifactLocation: z.object({ uri: z.string() }),
    region: SarifRegionSchema,
  }),
});

const SarifThreadFlowLocationSchema = z.object({
  location: z.object({
    physicalLocation: z.object({
      artifactLocation: z.object({ uri: z.string() }),
      region: z.object({ startLine: z.number().int().positive() }),
    }),
    message: z.object({ text: z.string() }),
  }),
});

const SarifResultSchema = z.object({
  ruleId: z.string(),
  level: SarifLevelSchema,
  message: z.object({ text: z.string() }),
  locations: z.array(SarifLocationSchema),
  partialFingerprints: z.record(z.string(), z.string()),
  codeFlows: z.array(z.object({ threadFlows: z.array(z.object({ locations: z.array(SarifThreadFlowLocationSchema) })) })).optional(),
  properties: z.object({
    riskScore: z.number(), confidence: z.string(), category: z.string(), scanStatus: z.string(),
  }),
  suppressions: z.array(z.object({ kind: z.literal('external'), status: z.literal('accepted'), justification: z.string() })).optional(),
});

export const SarifLogSchema = z.object({
  $schema: z.string(),
  version: z.literal('2.1.0'),
  runs: z.array(z.object({
    tool: z.object({
      driver: z.object({
        name: z.literal('VibeSec'),
        version: z.string(),
        informationUri: z.string(),
        rules: z.array(SarifRuleSchema),
      }),
    }),
    results: z.array(SarifResultSchema),
    versionControlProvenance: z.array(z.object({ repositoryUri: z.string(), revisionId: z.string() })),
  })),
});

export type SarifLog = z.infer<typeof SarifLogSchema>;

const MAX_MESSAGE = 1000;
const truncate = (s: string, max: number): string => (s.length > max ? `${s.slice(0, max - 1)}…` : s);

function levelFor(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note'; // low | info
}

/** A repo-relative path as a SARIF artifact URI (a URI reference): each path segment percent-encoded. */
export function artifactUri(path: string): string {
  return path.split('/').map((seg) => encodeURIComponent(seg)).join('/');
}

function cweHelpUri(cwe: string | undefined): string | undefined {
  const n = cwe?.match(/^CWE-(\d+)$/)?.[1];
  return n ? `https://cwe.mitre.org/data/definitions/${n}.html` : undefined;
}

function buildRules(findings: readonly Finding[]): SarifLog['runs'][number]['tool']['driver']['rules'] {
  const byRuleId = new Map<string, Finding>();
  for (const f of findings) if (!byRuleId.has(f.ruleId)) byRuleId.set(f.ruleId, f);
  return [...byRuleId.values()].map((f) => ({
    id: f.ruleId,
    shortDescription: { text: truncate(f.title, MAX_MESSAGE) },
    ...(cweHelpUri(f.cwe) ? { helpUri: cweHelpUri(f.cwe)! } : {}),
    properties: { tags: [f.category, ...(f.cwe ? [f.cwe] : [])] },
    defaultConfiguration: { level: levelFor(f.severity) },
  }));
}

function codeFlowsFor(trace: readonly TaintStep[] | undefined): SarifResult['codeFlows'] {
  if (!trace || trace.length === 0) return undefined;
  return [{
    threadFlows: [{
      locations: trace.map((step) => ({
        location: {
          physicalLocation: { artifactLocation: { uri: artifactUri(step.file) }, region: { startLine: step.line } },
          message: { text: `${step.kind}: ${step.note}` },
        },
      })),
    }],
  }];
}

type SarifResult = z.infer<typeof SarifResultSchema>;

function buildResult(f: Finding, now: string): SarifResult {
  const codeFlows = codeFlowsFor(f.taintTrace);
  const triage = activeTriage(f, now); // an expired decision no longer suppresses
  return {
    ruleId: f.ruleId,
    level: levelFor(f.severity),
    message: { text: truncate(`${f.title} — ${f.explanation}`, MAX_MESSAGE) },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: artifactUri(f.location.file) },
        region: { startLine: f.location.startLine, endLine: f.location.endLine, snippet: { text: f.location.snippet } },
      },
    }],
    partialFingerprints: { 'vibesecFingerprint/v1': f.fingerprint },
    ...(codeFlows ? { codeFlows } : {}),
    properties: { riskScore: f.riskScore, confidence: f.confidence, category: f.category, scanStatus: f.scanStatus },
    ...(triage ? { suppressions: [{ kind: 'external' as const, status: 'accepted' as const, justification: truncate(triage.reason, MAX_MESSAGE) }] } : {}),
  };
}

/** Builds and validates a SARIF 2.1.0 log for one scan's findings. */
export function buildSarif(scan: ScanDto, findings: readonly Finding[], now: string = new Date().toISOString()): SarifLog {
  const log: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'VibeSec', version: VIBESEC_TOOL_VERSION, informationUri: VIBESEC_INFORMATION_URI,
          rules: buildRules(findings),
        },
      },
      results: findings.map((f) => buildResult(f, now)),
      versionControlProvenance: [{
        repositoryUri: `https://github.com/${scan.repo.owner}/${scan.repo.name}`,
        revisionId: scan.commitSha ?? '',
      }],
    }],
  };
  return SarifLogSchema.parse(log);
}
