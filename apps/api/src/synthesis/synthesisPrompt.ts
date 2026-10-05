// SECURITY (spec §9.3): the synthesis model sees FINDINGS ONLY — never code. The digest below carries
// no snippets, taint-trace code, patches, impact prose or credential values (not even redacted ones);
// explanations are cut to 200 chars with inline code and long token-like strings scrubbed. Titles and
// explanations came from repo-influenced AI output, so the whole digest is wrapped as untrusted text.
import { CATEGORIES, SEVERITIES, type Category, type Finding, type FixPlan, type RiskGrade, type Severity } from '@vibesec/shared';
import { z } from 'zod';
import type { CoverageStatus } from '../analyzers/types';
import type { MockResponder } from '../llm/mockTransport';
import { untrustedText } from '../llm/prompt';
import type { LlmRequest } from '../llm/transport';

export const SYNTHESIS_PROMPT_VERSION = 'synthesis-v1';
/** Appears verbatim in the system prompt; `synthesisMockResponder` keys on it. */
export const SYNTHESIS_TASK_MARKER = 'Task: scan-synthesis';
/** Findings sent in full (by riskScore); the rest are summarized as counts. */
export const DIGEST_MAX_FINDINGS = 150;
export const DIGEST_MAX_FIX_ACTIONS = 30;
const EXPLANATION_MAX = 200;

/** One finding as the synthesis model sees it: facts only, no code. */
export type DigestEntry = {
  id: string;
  category: Category;
  ruleId: string;
  cwe?: string;
  title: string;
  severity: Severity;
  riskScore: number;
  confidence: Finding['confidence'];
  file: string;
  reachability?: 'reachable' | 'imported' | 'unreachable' | 'unknown';
  liveness?: 'live' | 'revoked' | 'unknown' | 'not_checked';
  historyOnly?: boolean;
  package?: string;
  riskFactors: string[];
  explanation: string;
};

export type DigestFixAction = {
  id: string; package: string; from: string; to: string | null; resolvedCount: number; command: string;
};

export type SynthesisInput = {
  scanId: string;
  findings: readonly Finding[];
  fixPlan?: FixPlan | undefined;
  /** Files per AI-review coverage status (CoverageRepo.summary().totals). */
  coverage?: Partial<Record<CoverageStatus, number>> | undefined;
  /** Scan warning codes so far (degraded analyzers, budget, …). */
  warningCodes?: readonly string[];
  /** "Now" for triage expiry (ISO; default: the current time). */
  now?: string | undefined;
  /** Categories the scan looked for; a category with zero findings is only "clean" if it was scanned. */
  scannedCategories?: readonly Category[];
};

export type Digest = {
  entries: DigestEntry[];
  fixActions: DigestFixAction[];
  /** Non-info findings left out of `entries` (beyond the cap). */
  omitted: { total: number; bySeverity: Partial<Record<Severity, number>>; byCategory: Partial<Record<Category, number>> };
  infoCount: number;
};

const INLINE_CODE_RE = /`{1,3}[^`]*`{1,3}/g;
/** Anything token-shaped (keys, hashes, base64 blobs) is scrubbed: no credential value ever reaches the prompt. */
const TOKEN_LIKE_RE = /[A-Za-z0-9_\-+/=.]{24,}/g;

export function scrubText(text: string, max: number): string {
  const clean = text.replace(INLINE_CODE_RE, '[code]').replace(TOKEN_LIKE_RE, '[redacted]').replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

export function toDigestEntry(f: Finding): DigestEntry {
  const e: DigestEntry = {
    id: f.id, category: f.category, ruleId: f.ruleId, title: scrubText(f.title, 160), severity: f.severity,
    riskScore: f.riskScore, confidence: f.confidence, file: f.location.file,
    riskFactors: f.riskFactors.map((r) => r.factor), explanation: scrubText(f.explanation, EXPLANATION_MAX),
  };
  if (f.cwe) e.cwe = f.cwe;
  if (f.dependency) {
    e.reachability = f.dependency.reachability;
    e.package = `${f.dependency.name}@${f.dependency.version}`;
  }
  if (f.secret) {
    e.liveness = f.secret.liveness;
    e.historyOnly = f.secret.inHistoryOnly;
  }
  return e;
}

export function buildDigest(input: SynthesisInput): Digest {
  const ranked = input.findings.filter((f) => f.severity !== 'info')
    .sort((a, b) => b.riskScore - a.riskScore || a.id.localeCompare(b.id));
  const kept = ranked.slice(0, DIGEST_MAX_FINDINGS);
  const omitted: Digest['omitted'] = { total: 0, bySeverity: {}, byCategory: {} };
  for (const f of ranked.slice(DIGEST_MAX_FINDINGS)) {
    omitted.total++;
    omitted.bySeverity[f.severity] = (omitted.bySeverity[f.severity] ?? 0) + 1;
    omitted.byCategory[f.category] = (omitted.byCategory[f.category] ?? 0) + 1;
  }
  const fixActions = (input.fixPlan?.actions ?? []).slice(0, DIGEST_MAX_FIX_ACTIONS).map((a) => ({
    id: a.id, package: a.package, from: a.from, to: a.to, resolvedCount: a.resolvedCount, command: a.command,
  }));
  return {
    entries: kept.map(toDigestEntry), fixActions, omitted,
    infoCount: input.findings.length - ranked.length,
  };
}

// ---------------------------------------------------------------------------------------------
// Grade rubric (shared by the system prompt, the deterministic fallback and the mock responder)
// ---------------------------------------------------------------------------------------------

export type GradeFacts = Pick<DigestEntry, 'severity' | 'category' | 'confidence' | 'reachability' | 'liveness'>;

/** Confirmed exploitable: a reachable vulnerable dependency, a live credential, or a high-confidence code finding. */
export function isExploitable(f: GradeFacts): boolean {
  if (f.category === 'dependency') return f.reachability === 'reachable';
  if (f.category === 'secret') return f.liveness === 'live';
  return f.confidence === 'high';
}

/**
 * F: any critical that is reachable / live / high-confidence. D: any other critical, or an exploitable high.
 * C: any high. B: any medium. A: only low/info, or nothing at all.
 */
export function gradeFor(findings: readonly GradeFacts[]): RiskGrade {
  const has = (sev: Severity, exploitable = false) => findings.some((f) => f.severity === sev && (!exploitable || isExploitable(f)));
  if (has('critical', true)) return 'F';
  if (has('critical') || has('high', true)) return 'D';
  if (has('high')) return 'C';
  if (has('medium')) return 'B';
  return 'A';
}

export const GRADE_RUBRIC = [
  'Risk grade rubric (apply strictly, worst rule wins):',
  '- F: any critical finding that is confirmed exploitable — a reachable vulnerable dependency, a live (verified) credential, or a high-confidence code finding.',
  '- D: any other critical finding, or a high finding that is confirmed exploitable as above.',
  '- C: any high finding.',
  '- B: any medium finding.',
  '- A: no findings, or only low/info findings.',
].join('\n');

export const SYNTHESIS_SYSTEM = [
  SYNTHESIS_TASK_MARKER,
  'You are a senior application-security lead writing the first screen of a security scan report for the developer team that owns the repository.',
  'You receive a digest of the scan\'s findings (no source code), the dependency fix plan, AI-review coverage counts and scan warning codes.',
  'Produce: a risk grade, a one-line headline (max 160 chars), an overview of 2–4 sentences, 3–5 top risks (fewer if there are fewer findings),',
  'up to 8 ordered next actions (the most valuable, cheapest-to-do first), and up to 5 positive observations.',
  '',
  GRADE_RUBRIC,
  '',
  'Rules:',
  '- Every top risk MUST cite at least one finding id from the digest in findingIds. Group related findings into one risk.',
  '- Every next action MUST cite real ids: a fix-plan action id in fixActionId (for dependency upgrades) and/or finding ids in findingIds. Never invent ids.',
  '- Effort: "minutes" for a one-line config or patch-level upgrade, "hours" for a code change or credential rotation, "days" for a redesign or major upgrade.',
  '- Plain English, concrete and specific (name the file, package or rule). No fear-mongering, no marketing language, no generic advice.',
  '- Positive observations only when the input evidences them (e.g. a category that was scanned has zero findings, or coverage shows the code was reviewed). If unsure, leave them out.',
  '- Mention when coverage was partial or warnings indicate degraded analysis, so the team knows what was not checked.',
  '- Do not quote code or credential values; you have none and must not make any up.',
  'Reply with JSON only, matching the schema.',
].join('\n');

/** What the model returns; ids are validated and stats/scanId/generatedBy are added server-side. */
export const SynthesisOutputSchema = z.object({
  riskGrade: z.enum(['A', 'B', 'C', 'D', 'F']),
  headline: z.string().min(1).max(160),
  overview: z.string().min(1).max(800),
  topRisks: z.array(z.object({
    title: z.string().min(1).max(160),
    whyItMatters: z.string().min(1).max(400),
    findingIds: z.array(z.string()).min(1),
    severity: z.enum(SEVERITIES),
  })).max(5),
  nextActions: z.array(z.object({
    title: z.string().min(1).max(160),
    detail: z.string().min(1).max(400),
    effort: z.enum(['minutes', 'hours', 'days']),
    fixActionId: z.string().optional(),
    findingIds: z.array(z.string()),
  })).max(8),
  positiveObservations: z.array(z.string().min(1).max(300)).max(5),
});
export type SynthesisOutput = z.infer<typeof SynthesisOutputSchema>;

const FINDINGS_SOURCE = 'findings-digest';
const FIX_PLAN_SOURCE = 'fix-plan';

function countsLine(counts: Partial<Record<string, number>>): string {
  const parts = Object.entries(counts).filter(([, n]) => (n ?? 0) > 0).map(([k, n]) => `${k}: ${n}`);
  return parts.length ? parts.join(', ') : 'none';
}

/** Volatile per-scan prompt: scan facts, then the fix plan and the findings digest (both untrusted). */
export function buildSynthesisPrompt(input: SynthesisInput, digest: Digest): string {
  const bySeverity: Partial<Record<Severity, number>> = {};
  const byCategory: Partial<Record<Category, number>> = {};
  for (const f of input.findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }
  const scanned = input.scannedCategories ?? CATEGORIES;
  const clean = scanned.filter((c) => !byCategory[c]);
  const lines = [
    'Scan facts:',
    `- Total findings: ${input.findings.length} (by severity: ${countsLine(bySeverity)}; by category: ${countsLine(byCategory)}).`,
    `- Info-level findings excluded from the digest: ${digest.infoCount}.`,
    `- Digest lists the top ${digest.entries.length} non-info findings by riskScore; ${digest.omitted.total} more are summarized only`
      + (digest.omitted.total ? ` (by severity: ${countsLine(digest.omitted.bySeverity)}; by category: ${countsLine(digest.omitted.byCategory)}).` : '.'),
    `- Categories scanned: ${scanned.join(', ') || 'none'}. Scanned categories with zero findings: ${clean.join(', ') || 'none'}.`,
    `- AI-review coverage (files per status): ${input.coverage ? countsLine(input.coverage) : 'not recorded'}.`,
    `- Scan warnings: ${input.warningCodes?.length ? [...new Set(input.warningCodes)].join(', ') : 'none'}.`,
    '',
    `Fix plan actions (${digest.fixActions.length} of ${input.fixPlan?.actions.length ?? 0}), one JSON object per line:`,
    untrustedText(FIX_PLAN_SOURCE, digest.fixActions.map((a) => JSON.stringify(a)).join('\n')),
    '',
    'Findings digest, one JSON object per line:',
    untrustedText(FINDINGS_SOURCE, digest.entries.map((e) => JSON.stringify(e)).join('\n')),
  ];
  return lines.join('\n');
}

// ---------------------------------------------------------------------------------------------
// Mock responder (MockTransport): deterministic, uses only ids present in the prompt
// ---------------------------------------------------------------------------------------------

function textOfRequest(req: LlmRequest): { system: string; user: string } {
  const system = req.system.map((b) => b.text).join('\n');
  const user = req.messages
    .flatMap((m) => (Array.isArray(m.content) ? m.content : []))
    .flatMap((b) => (b.type === 'text' ? [b.text] : []))
    .join('\n');
  return { system, user };
}

function jsonLinesOf<T>(user: string, source: string): T[] {
  const open = `<untrusted_text source="${source}">`;
  const start = user.indexOf(open);
  if (start === -1) return [];
  const end = user.indexOf('</untrusted_text>', start);
  const body = user.slice(start + open.length, end === -1 ? undefined : end);
  const out: T[] = [];
  for (const line of body.split('\n')) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line) as T); } catch { /* not a digest line */ }
  }
  return out;
}

export const synthesisMockResponder: MockResponder = (req: LlmRequest) => {
  const { system, user } = textOfRequest(req);
  if (!system.includes(SYNTHESIS_TASK_MARKER)) return undefined;
  const entries = jsonLinesOf<DigestEntry>(user, FINDINGS_SOURCE);
  const actions = jsonLinesOf<DigestFixAction>(user, FIX_PLAN_SOURCE);
  const grade = gradeFor(entries);
  const top = entries.slice(0, 3);
  const output: SynthesisOutput = {
    riskGrade: grade,
    headline: entries.length ? `Grade ${grade}: ${entries.length} finding(s) to review` : 'No significant security findings',
    overview: entries.length
      ? `The scan reported ${entries.length} finding(s) worth attention. Start with the top risks below.`
      : 'The scan found no significant security issues. Keep dependencies and credentials under review.',
    topRisks: top.map((e) => ({
      title: e.title.slice(0, 160) || e.ruleId, whyItMatters: `Rated ${e.severity} (risk ${e.riskScore}) in ${e.file}.`.slice(0, 400),
      findingIds: [e.id], severity: e.severity,
    })),
    nextActions: [
      ...actions.slice(0, 3).map((a) => ({
        title: `Upgrade ${a.package}`.slice(0, 160), detail: `Run ${a.command}`.slice(0, 400), effort: 'minutes' as const,
        fixActionId: a.id, findingIds: [],
      })),
      ...top.map((e) => ({ title: `Fix ${e.ruleId}`.slice(0, 160), detail: `Address the finding in ${e.file}.`.slice(0, 400), effort: 'hours' as const, findingIds: [e.id] })),
    ].slice(0, 8),
    positiveObservations: [],
  };
  return output;
};
