import {
  CATEGORIES, SEVERITIES, ScanSummarySchema,
  type Category, type Finding, type FixAction, type NextAction, type ScanSummary, type Severity, type SummaryStats, type TopRisk,
} from '@vibesec/shared';
import { toAppError } from '../errors/AppError';
import type { LlmClient } from '../llm/LlmClient';
import {
  buildDigest, buildSynthesisPrompt, gradeFor, scrubText, SYNTHESIS_PROMPT_VERSION, SYNTHESIS_SYSTEM, SynthesisOutputSchema,
  toDigestEntry, type SynthesisInput, type SynthesisOutput,
} from './synthesisPrompt';

export type SynthesisResult = {
  summary: ScanSummary;
  /** Set when the deterministic fallback was used (LLM unavailable, budget, refusal, invalid output). */
  fallbackReason?: string;
};

export type SynthesizeDeps = { llm: Pick<LlmClient, 'structured'> };
export type SynthesizeOpts = { signal: AbortSignal; onActivity?: () => void };

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const worst = (sevs: readonly Severity[]): Severity => [...sevs].sort((a, b) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b])[0] ?? 'info';

export function computeStats(findings: readonly Finding[]): SummaryStats {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  const byCategory = Object.fromEntries(CATEGORIES.map((c) => [c, 0])) as Record<Category, number>;
  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory[f.category]++;
  }
  return { bySeverity, byCategory, total: findings.length };
}

/**
 * Keeps only references to ids that were actually in the input: unknown finding ids and fix-action ids are
 * dropped, a top risk left without findings is dropped, and so is a next action left with no reference at
 * all. A top risk's severity is recomputed from the findings it cites (the model cannot inflate/deflate it).
 */
export function validateReferences(
  output: SynthesisOutput, findingsById: ReadonlyMap<string, Pick<Finding, 'severity'>>, fixActionIds: ReadonlySet<string>,
): Pick<SynthesisOutput, 'topRisks' | 'nextActions'> {
  const known = (ids: readonly string[]) => [...new Set(ids.filter((id) => findingsById.has(id)))];
  const topRisks: TopRisk[] = [];
  for (const r of output.topRisks) {
    const findingIds = known(r.findingIds);
    if (!findingIds.length) continue;
    topRisks.push({ ...r, findingIds, severity: worst(findingIds.map((id) => findingsById.get(id)!.severity)) });
  }
  const nextActions: NextAction[] = [];
  for (const a of output.nextActions) {
    const findingIds = known(a.findingIds);
    const fixActionId = a.fixActionId && fixActionIds.has(a.fixActionId) ? a.fixActionId : undefined;
    if (!fixActionId && !findingIds.length) continue;
    nextActions.push({ title: a.title, detail: a.detail, effort: a.effort, findingIds, ...(fixActionId ? { fixActionId } : {}) });
  }
  return { topRisks, nextActions };
}

// ---------------------------------------------------------------------------------------------
// Deterministic fallback
// ---------------------------------------------------------------------------------------------

const CATEGORY_RISK: Record<Category, { title: string; why: string }> = {
  secret: { title: 'Exposed credentials', why: 'Credentials committed to the repository can be used by anyone with read access to it, including its history; rotate them and move them to a secret store.' },
  sast: { title: 'Insecure code patterns', why: 'These code patterns are common entry points for attacks such as injection or broken access control.' },
  taint: { title: 'Untrusted input reaching sensitive operations', why: 'User-controlled data flows into a sensitive operation without adequate sanitization, which can let an attacker control it.' },
  quality: { title: 'Security-relevant code quality issues', why: 'These weaknesses make the code easier to misuse and harder to secure, even if not directly exploitable today.' },
  dependency: { title: 'Vulnerable dependencies', why: 'Known-vulnerable packages ship publicly documented exploits; upgrading is usually the cheapest risk reduction available.' },
  config: { title: 'Insecure configuration', why: 'Misconfiguration can expose data or services regardless of how secure the application code is.' },
};

const clip = (s: string, max: number) => (s.length > max ? `${s.slice(0, max - 1)}…` : s);

function fixActionStep(a: FixAction): NextAction {
  const title = a.to ? `Upgrade ${a.package} ${a.from} → ${a.to}` : `Remove ${a.package} ${a.from}`;
  const effort = a.kind === 'remove' || a.semverJump === 'major' ? 'hours' : 'minutes';
  return {
    title: clip(title, 160),
    detail: clip(`Run \`${a.command}\`. Resolves ${a.resolvedCount} advisor${a.resolvedCount === 1 ? 'y' : 'ies'}${a.breakingRisk ? '; may include breaking changes, so run your tests' : ''}.`, 400),
    effort, fixActionId: a.id, findingIds: [...new Set(a.resolves.map((r) => r.findingId))],
  };
}

function findingStep(f: Finding): NextAction {
  const verb = f.category === 'secret' ? 'Rotate and remove' : 'Fix';
  return {
    title: clip(`${verb}: ${scrubText(f.title, 150)}`, 160),
    detail: clip(`${f.location.file}:${f.location.startLine} — ${scrubText(f.remediation.summary, 340)}`, 400),
    effort: f.category === 'dependency' ? 'minutes' : 'hours', findingIds: [f.id],
  };
}

function positiveObservations(input: SynthesisInput, stats: SummaryStats): string[] {
  const scanned = new Set(input.scannedCategories ?? CATEGORIES);
  const reviewed = (input.coverage?.reviewed ?? 0) + (input.coverage?.['reviewed-fast'] ?? 0) + (input.coverage?.cached ?? 0);
  const out: string[] = [];
  if (scanned.has('secret') && !stats.byCategory.secret) out.push('No hard-coded credentials were found in the code or the scanned git history.');
  if (scanned.has('dependency') && !stats.byCategory.dependency) out.push('No dependencies with known vulnerabilities were found.');
  if (reviewed > 0 && scanned.has('taint') && !stats.byCategory.taint) out.push('No untrusted-input-to-sink data flows were found in the reviewed code.');
  if (reviewed > 0 && scanned.has('config') && !stats.byCategory.config) out.push('No insecure configuration was found.');
  return out.slice(0, 5);
}

export function fallbackSummary(input: SynthesisInput): ScanSummary {
  const stats = computeStats(input.findings);
  const relevant = input.findings.filter((f) => f.severity !== 'info')
    .sort((a, b) => b.riskScore - a.riskScore || a.id.localeCompare(b.id));
  const riskGrade = gradeFor(relevant.map(toDigestEntry));

  // Top risks: the 3 categories holding the highest-risk findings, each citing its findings by risk.
  const byCategory = new Map<Category, Finding[]>();
  for (const f of relevant) byCategory.set(f.category, [...(byCategory.get(f.category) ?? []), f]);
  const topRisks: TopRisk[] = [...byCategory.entries()].slice(0, 3).map(([cat, fs]) => ({
    title: clip(`${CATEGORY_RISK[cat].title} (${fs.length})`, 160),
    whyItMatters: CATEGORY_RISK[cat].why,
    findingIds: fs.slice(0, 10).map((f) => f.id),
    severity: worst(fs.map((f) => f.severity)),
  }));

  const actions = input.fixPlan?.actions ?? [];
  const covered = new Set(actions.flatMap((a) => a.resolves.map((r) => r.findingId)));
  const nextActions = [
    ...actions.slice(0, 3).map(fixActionStep),
    ...relevant.filter((f) => !covered.has(f.id)).slice(0, 5).map(findingStep),
  ].slice(0, 8);

  const crit = stats.bySeverity.critical;
  const high = stats.bySeverity.high;
  const headline = relevant.length === 0
    ? 'No significant security issues found'
    : crit + high > 0
      ? `${crit + high} high-priority issue${crit + high === 1 ? '' : 's'} need${crit + high === 1 ? 's' : ''} attention (${crit} critical, ${high} high)`
      : `${relevant.length} lower-severity issue${relevant.length === 1 ? '' : 's'} to review`;
  const sentences = [
    `This scan reported ${stats.total} finding${stats.total === 1 ? '' : 's'} (${crit} critical, ${high} high, ${stats.bySeverity.medium} medium, ${stats.bySeverity.low} low) for an overall grade of ${riskGrade}.`,
    topRisks.length ? `The biggest areas of risk are: ${[...byCategory.keys()].slice(0, 3).map((c) => CATEGORY_RISK[c].title.toLowerCase()).join(', ')}.` : 'Nothing above informational level was found.',
    actions.length ? `${actions.length} dependency fix${actions.length === 1 ? '' : 'es'} in the fix plan resolve known advisories with a single command each.` : '',
    'This summary was generated without AI assistance; open the findings for full details.',
  ].filter(Boolean);

  return ScanSummarySchema.parse({
    scanId: input.scanId, riskGrade, headline: clip(headline, 160), overview: clip(sentences.join(' '), 800),
    topRisks, nextActions, positiveObservations: positiveObservations(input, stats), stats, generatedBy: 'fallback',
  });
}

// ---------------------------------------------------------------------------------------------
// LLM synthesis (Opus, findings-only input)
// ---------------------------------------------------------------------------------------------

export async function synthesizeSummary(deps: SynthesizeDeps, input: SynthesisInput, opts: SynthesizeOpts): Promise<SynthesisResult> {
  const digest = buildDigest(input);
  const stats = computeStats(input.findings);
  let output: SynthesisOutput;
  let model: string;
  try {
    const res = await deps.llm.structured({
      scanId: input.scanId, analyzer: 'synthesis', purpose: 'scan-summary', promptVersion: SYNTHESIS_PROMPT_VERSION,
      role: 'synthesis', system: SYNTHESIS_SYSTEM, prompt: buildSynthesisPrompt(input, digest),
      schema: SynthesisOutputSchema, signal: opts.signal, ...(opts.onActivity ? { onActivity: opts.onActivity } : {}),
    });
    output = res.output;
    model = res.model;
  } catch (raw) {
    const err = toAppError(raw);
    if (err.kind === 'cancelled' || opts.signal.aborted) throw err;
    return { summary: fallbackSummary(input), fallbackReason: `${err.code}: ${err.userMessage}` };
  }

  const findingsById = new Map(digest.entries.map((e) => [e.id, e]));
  const fixActionIds = new Set(digest.fixActions.map((a) => a.id));
  let { topRisks, nextActions } = validateReferences(output, findingsById, fixActionIds);
  // The model cited nothing real although there is something to report: use the deterministic risks.
  if (!topRisks.length && digest.entries.length) topRisks = fallbackSummary(input).topRisks;
  if (!nextActions.length && digest.entries.length) nextActions = fallbackSummary(input).nextActions;

  const summary = ScanSummarySchema.parse({
    scanId: input.scanId, riskGrade: output.riskGrade, headline: output.headline, overview: output.overview,
    topRisks, nextActions, positiveObservations: output.positiveObservations, stats, generatedBy: 'llm', model,
  });
  return { summary };
}
