// AI config analyzer (P6, Task B): Claude reviews workflows/Dockerfiles/env/IaC and writes the
// findings. The deterministic rules in this directory (githubActions.ts, dockerfile.ts,
// envExposure.ts, aggregated by configIssues() in index.ts) are HINTS — "these lines matched a
// known-dangerous pattern, confirm or refute each, then look for anything else." A hint ALWAYS
// becomes a finding: Claude confirming it keeps its original severity (producedBy adds
// 'config:llm'); Claude refuting it downgrades it to info/low confidence with an 'ai_refuted'
// riskFactor explaining why (never dropped — same product rule as credentials); and a hint Claude
// never returned a verdict for (whole-batch AI failure, budget skip, or simply omitted from an
// otherwise-successful response) stays at its original severity but low confidence with an
// 'ai_unreviewed' riskFactor (fail-open for security).
//
// .env values are NEVER sent to the model (and never land in a finding): redacted to "<key>=<first
// two chars>…" before anything is read, numbered, or verified against.
//
// Pattern follows triage.ts / credentials/fpFilter.ts: bounded-concurrency safe reads confined to
// repoDir, token-bounded batching, an injection-safe untrusted wrapper per file, verification before
// an additional (non-hint) issue becomes a Finding, and a deterministic mock responder keyed by a
// task marker in the system prompt.

import { open } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { isMap, isScalar, parseDocument } from 'yaml';
import { z } from 'zod';
import type { Finding, Severity } from '@vibesec/shared';
import { toAppError } from '../../../errors/AppError';
import { provisionalScore } from '../../../findings/helpers';
import { verifyIssueLocation } from '../../../findings/verify';
import type { LlmClient, StructuredCall } from '../../../llm/LlmClient';
import type { MockResponder } from '../../../llm/mockTransport';
import { estimateTokens, untrustedFile, untrustedText } from '../../../llm/prompt';
import type { LlmRequest } from '../../../llm/transport';
import type { IndexedFile } from '../../../index/types';
import type { WorkLease } from '../../../llm/budget';
import { NO_LEASE, type BudgetLanes } from '../../../llm/budgetLanes';
import type { Analyzer, AnalyzerContext, CoverageStatus } from '../../types';
import { issueToFinding } from '../toFinding';
import type { RawCodeIssue } from '../types';
import { isDockerfile } from './dockerfile';
import { isEnvFile, isEnvTemplateFile } from './envExposure';
import { isGithubActionsWorkflow } from './githubActions';
import { configIssues } from './index';

export const CONFIG_PROMPT_VERSION = 'config-v2';
/** Appears verbatim in the system prompt; `configMockResponder` keys on it. */
export const CONFIG_TASK_MARKER = 'Task: config-review';

/** Projection of one batch review (budget tier 1): system prompt + batch, and a typical reply. */
const PROJECTED_SYSTEM_TOKENS = 1_500;
const PROJECTED_OUTPUT_TOKENS = 2_000;
const MAX_FILE_BYTES = 200 * 1024;
const READ_CONCURRENCY = 16;
const BATCH_TOKENS = 10_000;
const BATCH_CONCURRENCY = 3;
const PER_FILE_OVERHEAD_TOKENS = 100;
const CHARS_PER_TOKEN = 3.5; // matches estimateTokens() in llm/prompt.ts
const NUL_PROBE_BYTES = 8_192;
const TRUNCATION_NOTE = '\n[TRUNCATED: file content was shortened to fit the config review batch token budget]';

// --- extra path matchers (beyond githubActions.ts/dockerfile.ts/envExposure.ts) ------------------

const COMPOSE_RE = /(^|\/)docker-compose[^/]*\.ya?ml$/i;
const SUPABASE_MIGRATION_RE = /(^|\/)supabase\/migrations\/[^/]+\.sql$/i;
const FIREBASE_JSON_RE = /(^|\/)firebase\.json$/i;
const RULES_FILE_RE = /(^|\/)[^/]+\.rules$/i; // covers firestore.rules, storage.rules, *.rules
const VERCEL_JSON_RE = /(^|\/)vercel\.json$/i;
const NETLIFY_TOML_RE = /(^|\/)netlify\.toml$/i;
const TERRAFORM_RE = /(^|\/)[^/]+\.tf$/i;
const YAML_RE = /\.ya?ml$/i;

/** Every config path EXCEPT Kubernetes manifests, which need their content (apiVersion+kind) to
 *  recognize, not just their path. */
function isStrictConfigPath(path: string): boolean {
  return (
    isGithubActionsWorkflow(path)
    || isDockerfile(path)
    || COMPOSE_RE.test(path)
    || (isEnvFile(path) && !isEnvTemplateFile(path))
    || SUPABASE_MIGRATION_RE.test(path)
    || FIREBASE_JSON_RE.test(path)
    || RULES_FILE_RE.test(path)
    || VERCEL_JSON_RE.test(path)
    || NETLIFY_TOML_RE.test(path)
    || TERRAFORM_RE.test(path)
  );
}

/** True when a YAML document's top level has both `apiVersion` and `kind` string keys — the
 *  minimal, reliable signature of a Kubernetes manifest (vs. an arbitrary YAML config file). */
function looksLikeK8sManifest(text: string): boolean {
  let doc;
  try {
    doc = parseDocument(text);
  } catch {
    return false;
  }
  const contents = doc.contents;
  if (!isMap(contents)) return false;
  let hasApiVersion = false;
  let hasKind = false;
  for (const pair of contents.items) {
    if (!isScalar(pair.key)) continue;
    if (pair.key.value === 'apiVersion' && isScalar(pair.value) && typeof pair.value.value === 'string') hasApiVersion = true;
    if (pair.key.value === 'kind' && isScalar(pair.value) && typeof pair.value.value === 'string') hasKind = true;
  }
  return hasApiVersion && hasKind;
}

// --- .env redaction (values never leave this process; only "<key>=<2 chars>…" does) --------------

const ENV_LINE_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

function stripQuotes(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
    return v.slice(1, -1);
  }
  return v;
}

function redactValue(value: string): string {
  return value.length <= 2 ? '…' : `${value.slice(0, 2)}…`;
}

/** Redacts every assignment's value in an .env file: keeps the key, replaces the value with its
 *  first 2 characters + '…'. Comments/blank/malformed lines pass through unchanged (nothing to
 *  redact). This is the ONLY text from an .env file that is ever sent to the model, numbered, or
 *  used as the ground truth for verifying a reported finding — the raw value never leaves this
 *  function. */
function redactEnvFile(text: string): string {
  return text.split('\n').map((line) => {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return line;
    const m = ENV_LINE_RE.exec(line);
    if (!m) return line;
    const name = m[1]!;
    const value = stripQuotes(m[2] ?? '');
    if (value === '') return line;
    return `${name}=${redactValue(value)}`;
  }).join('\n');
}

// --- schema --------------------------------------------------------------------------------------

const HintVerdictSchema = z.object({ hintId: z.string().min(1).max(200), confirmed: z.boolean(), reason: z.string().max(300) });
const AdditionalIssueSchema = z.object({
  ruleId: z.string().min(1).max(100),
  title: z.string().min(1).max(200),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  confidence: z.enum(['high', 'medium', 'low']),
  file: z.string().min(1).max(1_024),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  snippet: z.string().min(1).max(2_000),
  explanation: z.string().min(1).max(2_000),
  impact: z.string().min(1).max(2_000),
  remediation: z.string().min(1).max(2_000),
});
const ConfigOutputSchema = z.object({
  hintVerdicts: z.array(HintVerdictSchema).max(200),
  issues: z.array(AdditionalIssueSchema).max(50),
});
type ConfigOutput = z.infer<typeof ConfigOutputSchema>;

// --- system prompt ---------------------------------------------------------------------------

const SYSTEM_PROMPT = [
  CONFIG_TASK_MARKER,
  '',
  'You are reviewing configuration/infrastructure files from a repository: GitHub Actions workflows,',
  'Dockerfiles/Containerfiles, docker-compose files, .env files, Supabase SQL migrations,',
  'Firebase/Firestore/Storage rules, Vercel/Netlify config, Terraform, and Kubernetes manifests.',
  '',
  'Each file is wrapped in an <untrusted_file> block with 1-based line numbers. Some files are',
  'followed by one or more <hint> blocks: a high-precision deterministic pattern-matcher already',
  'flagged that line as a known-dangerous pattern (its ruleId, severity, line and matched snippet are',
  'given). These rules have a low false-positive rate by design, so start from the presumption that',
  'each hint is real. For EVERY hint you are given, decide whether it is a real issue in this file or',
  'a false positive, by looking at the actual file content — not just the hint text — and return',
  'exactly one entry per hintId in "hintVerdicts": { hintId, confirmed, reason }.',
  '',
  'Refuting a hint (confirmed: false) requires concrete, visible evidence in THIS file that the',
  'dangerous pattern is actually safe here — for example: the `curl|wget … | sh` target is a pinned,',
  'checksum- or signature-verified script (the verification step is visible in the file, not assumed);',
  'a later USER instruction in the same build stage switches off root before the container runs; or the',
  'matched line is unreachable/commented out. Noting that the file "looks like a demo/test/example" is',
  'NOT by itself a reason to refute — demo and test files ship in real images and run with the same',
  'privileges as anything else. If you are not sure, or the evidence is anything less than concrete and',
  'visible in the file, confirm the hint (confirmed: true) rather than guessing it away: an unconfirmed',
  'hint still gets a human look, but a wrongly refuted one disappears from review entirely. A hint is',
  'never dropped outright by your verdict — refuting it only lowers its severity — so there is no harm',
  'in confirming when unsure.',
  '',
  'Separately, look for ANY other configuration/infrastructure security issue in the file, hinted or',
  'not — for example (not exhaustive): a Supabase table created without enabling row-level security,',
  'wide-open Firebase/Firestore rules, a privileged docker-compose service, a privileged Kubernetes',
  'container (privileged: true, hostNetwork, hostPID, or running as root with no securityContext), a',
  'public/open Terraform storage bucket, a wildcard CORS origin, or a debug mode left enabled in a',
  'production-looking config. Report these in "issues", each with a ruleId shaped like',
  '"config/<kebab-case-name>" (reuse a hint\'s ruleId if it is the same issue, otherwise a new one,',
  'e.g. "config/supabase-table-without-rls", "config/firebase-open-rules",',
  '"config/docker-compose-privileged", "config/k8s-privileged-container",',
  '"config/terraform-public-bucket", "config/cors-wildcard", "config/debug-mode-enabled"), a title,',
  'severity, confidence, which "file" (exact path, one of the files given below) it is in, the exact',
  'startLine/endLine and snippet (copied verbatim from that file\'s numbered content so it can be',
  'verified), and an explanation, impact and remediation. Do not re-report a hint you already',
  'confirmed as a new issue.',
  '',
  '.env file values were redacted by the scanner before you ever saw them — only the key and the',
  'first two characters of the value remain, followed by "…". That redaction is expected and is not',
  'itself a finding; never guess, reconstruct, or invent a real value in your findings.',
  '',
  'Return exactly one hintVerdicts entry per hintId you were given, and no entries for hintIds you',
  'were not given. "issues" may be empty.',
].join('\n');
// Note: UNTRUSTED_POLICY is appended automatically by LlmClient (via buildRequestParts), so it is
// deliberately not duplicated here.

// --- safe file read (confined to repoDir, bounded, binary-safe) --------------------------------

async function readFileSafe(repoDir: string, path: string, maxBytes: number): Promise<string | null> {
  const resolvedRepoDir = resolve(repoDir);
  const repoDirPrefix = resolvedRepoDir + sep;
  const abs = resolve(join(repoDir, ...path.split('/')));
  if (abs !== resolvedRepoDir && !abs.startsWith(repoDirPrefix)) return null;

  const handle = await open(abs, 'r').catch(() => null);
  if (!handle) return null;
  try {
    const { size } = await handle.stat();
    const length = Math.max(0, Math.min(size, maxBytes));
    if (length === 0) return '';
    const buffer = Buffer.allocUnsafe(length);
    let bytesRead = 0;
    while (bytesRead < length) {
      const { bytesRead: n } = await handle.read(buffer, bytesRead, length - bytesRead, bytesRead);
      if (n === 0) break;
      bytesRead += n;
    }
    const probeLen = Math.min(NUL_PROBE_BYTES, bytesRead);
    if (buffer.subarray(0, probeLen).includes(0)) return null;
    return buffer.subarray(0, bytesRead).toString('utf8');
  } catch {
    return null;
  } finally {
    await handle.close();
  }
}

/** Runs `fn` over `items` with at most `limit` in flight; stops every worker as soon as one throws
 *  (so cancellation propagates promptly), rethrowing that error once every worker has unwound. */
async function forEachLimit<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  let stopped = false;
  const worker = async () => {
    while (!stopped && next < items.length) {
      const item = items[next++]!;
      try {
        await fn(item);
      } catch (err) {
        stopped = true;
        throw err;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
}

// --- prompt building --------------------------------------------------------------------------

function numberLines(content: string): string {
  return content.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
}

function fitToTokenBudget(text: string, maxTokens: number): { text: string; truncated: boolean } {
  if (estimateTokens(text) <= maxTokens) return { text, truncated: false };
  const maxChars = Math.max(0, Math.floor(maxTokens * CHARS_PER_TOKEN));
  return { text: text.slice(0, maxChars), truncated: true };
}

function escapeAttr(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function unescapeAttr(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

const HINT_TAG_RE = /<(\/?)\s*hint\b/gi;

/** Escapes any literal `<hint`/`</hint` text inside repo content so it can never forge a sibling
 *  <hint> block (same rationale as CANDIDATE_TAG_RE in credentials/fpFilter.ts). */
function neutralizeHintTag(text: string): string {
  return text.replace(HINT_TAG_RE, (_m, slash: string) => `&lt;${slash}hint`);
}

type HintEntry = { id: string; hint: RawCodeIssue };

function hintBlock(entry: HintEntry): string {
  const body = [
    `ruleId: ${entry.hint.ruleId}`,
    `severity: ${entry.hint.severity}`,
    `line: ${entry.hint.startLine}`,
    `snippet: ${entry.hint.snippet}`,
    `why flagged: ${entry.hint.explanation}`,
  ].join('\n');
  return [`<hint id="${escapeAttr(entry.id)}">`, untrustedText(`hint ${entry.id}`, neutralizeHintTag(body)), '</hint>'].join('\n');
}

type PromptFile = { path: string; block: string; blockTokens: number };

function buildPromptFile(path: string, text: string, hints: readonly HintEntry[], batchTokens: number): PromptFile {
  const budget = Math.max(0, batchTokens - PER_FILE_OVERHEAD_TOKENS);
  const { text: fitted, truncated } = fitToTokenBudget(numberLines(text), budget);
  const body = truncated ? `${fitted}${TRUNCATION_NOTE}` : fitted;
  const fileBlock = untrustedFile(path, neutralizeHintTag(body));
  const hintsText = hints.length > 0
    ? ['Hints for this file (confirm or refute each by hintId; also look for anything else):', ...hints.map(hintBlock)].join('\n')
    : 'No deterministic hints matched this file — review it directly for anything worth flagging.';
  const block = [fileBlock, hintsText].join('\n\n');
  return { path, block, blockTokens: estimateTokens(block) };
}

/** Greedy bin-packing by estimated tokens, same approach as triage.ts's packBatches. */
function packBatches(files: readonly PromptFile[], batchTokens: number): PromptFile[][] {
  const batches: PromptFile[][] = [];
  let current: PromptFile[] = [];
  let tokens = 0;
  for (const f of files) {
    if (current.length > 0 && tokens + f.blockTokens > batchTokens) {
      batches.push(current);
      current = [];
      tokens = 0;
    }
    current.push(f);
    tokens += f.blockTokens;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

// --- ruleId normalization -------------------------------------------------------------------

function kebab(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'issue';
}

function normalizeRuleId(ruleId: string): string {
  return ruleId.startsWith('config/') ? ruleId : `config/${kebab(ruleId)}`;
}

function overlaps(a: RawCodeIssue, b: RawCodeIssue): boolean {
  return a.file === b.file && a.startLine <= b.endLine && b.startLine <= a.endLine;
}

// --- hint-verdict outcomes (never let an AI verdict make a deterministic hint disappear) ----------
// Same product rule already applied to credentials (see credentials/credentialsAnalyzer.ts
// buildFinding's I6 comment): the AI may DOWNGRADE a deterministic signal, but it may never make it
// disappear. A refuted hint and an unreviewed hint both still become findings below, just at reduced
// severity/confidence with a riskFactor recording why.

const SEV_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const sevIndex = (s: Severity): number => SEV_ORDER.indexOf(s);
const AI_REFUTED_REASON_MAX = 200;

/** A hint Claude reviewed and refuted: downgraded to info/low, never dropped. */
function buildRefutedHintFinding(
  ctx: Pick<AnalyzerContext, 'scanId' | 'repo' | 'commitSha'>,
  hint: RawCodeIssue,
  reason: string,
): Finding {
  const finding = issueToFinding(ctx, 'config', hint, ['config:rule', 'config:llm']);
  const truncatedReason = reason.slice(0, AI_REFUTED_REASON_MAX);
  finding.riskFactors = [{ factor: 'ai_refuted', effect: sevIndex('info') - sevIndex(hint.severity), reason: truncatedReason }];
  finding.severity = 'info';
  finding.confidence = 'low';
  finding.riskScore = provisionalScore('info');
  finding.explanation = `${finding.explanation} AI review judged this a likely false positive: ${truncatedReason}`;
  return finding;
}

/**
 * A hint Claude never returned a verdict for — either the whole batch's AI call failed/was
 * budget-skipped, or the model's otherwise-successful response simply omitted this hintId. Fail-open:
 * kept at its original severity, dropped to low confidence, flagged as unreviewed.
 */
function buildUnreviewedHintFinding(
  ctx: Pick<AnalyzerContext, 'scanId' | 'repo' | 'commitSha'>,
  hint: RawCodeIssue,
): Finding {
  const finding = issueToFinding(ctx, 'config', { ...hint, confidence: 'low' }, ['config:rule']);
  finding.riskFactors = [{
    factor: 'ai_unreviewed', effect: 0,
    reason: 'AI review returned no verdict for this hint; kept at its original severity (fail-open)',
  }];
  return finding;
}

// --- service ---------------------------------------------------------------------------------

export type ConfigAnalyzerDeps = {
  llm: Pick<LlmClient, 'structured'>;
  /** Budget lanes: a tier-1 lease projecting the remaining batches (llm/budget.ts). */
  lanes?: BudgetLanes;
};

export function createConfigAnalyzer(deps: ConfigAnalyzerDeps): Analyzer {
  return {
    id: 'config',
    version: '2',
    category: 'config',

    async run(ctx: AnalyzerContext): Promise<Finding[]> {
      if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      const lease = deps.lanes?.open(ctx.scanId) ?? NO_LEASE; // before the first await (see llm/budget.ts)
      try {
        return await review(ctx, lease);
      } finally {
        lease.close();
      }
    },
  };

  async function review(ctx: AnalyzerContext, lease: WorkLease): Promise<Finding[]> {
      const checkAbort = () => {
        if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      };
      const record = (path: string, status: CoverageStatus) => ctx.recordCoverage?.('config', path, status);

      const strictCandidates = ctx.files.filter((f: IndexedFile) => f.skipReason === null && isStrictConfigPath(f.path));
      const yamlSniffCandidates = ctx.files.filter((f: IndexedFile) => f.skipReason === null && YAML_RE.test(f.path) && !isStrictConfigPath(f.path));

      const rawByPath = new Map<string, string>();
      await forEachLimit([...strictCandidates, ...yamlSniffCandidates], READ_CONCURRENCY, async (f) => {
        checkAbort();
        const text = await readFileSafe(ctx.repoDir, f.path, MAX_FILE_BYTES);
        if (text !== null) rawByPath.set(f.path, text);
        ctx.touch();
      });

      const matchedPaths = new Set(strictCandidates.filter((f) => rawByPath.has(f.path)).map((f) => f.path));
      for (const f of yamlSniffCandidates) {
        const text = rawByPath.get(f.path);
        if (text !== undefined && looksLikeK8sManifest(text)) matchedPaths.add(f.path);
      }

      for (const f of strictCandidates) if (!rawByPath.has(f.path)) record(f.path, 'failed');
      const selectedPaths = [...matchedPaths].sort();
      if (selectedPaths.length === 0) return [];

      const rawFiles = selectedPaths.map((path) => ({ path, text: rawByPath.get(path)! }));

      // Hints are computed from the RAW (never-redacted) text: envFileCommittedIssues needs the real
      // value to judge whether it looks like a placeholder. Hint snippets are already redacted by
      // envExposureIssues itself for env files, so they stay safe to surface.
      const hints = configIssues(rawFiles);
      const hintsByFile = new Map<string, RawCodeIssue[]>();
      for (const h of hints) {
        const list = hintsByFile.get(h.file);
        if (list) list.push(h);
        else hintsByFile.set(h.file, [h]);
      }

      // Effective text — what is actually sent to the model AND used as ground truth for verifying
      // any additional issue — is redacted for .env files. The raw value never reaches either.
      const effectiveTextByPath = new Map<string, string>();
      const hintEntriesByPath = new Map<string, HintEntry[]>();
      for (const f of rawFiles) {
        effectiveTextByPath.set(f.path, isEnvFile(f.path) ? redactEnvFile(f.text) : f.text);
        const fileHints = hintsByFile.get(f.path) ?? [];
        hintEntriesByPath.set(f.path, fileHints.map((hint, i) => ({ id: `${f.path}#${i}`, hint })));
      }

      const promptFiles = rawFiles.map((f) =>
        buildPromptFile(f.path, effectiveTextByPath.get(f.path)!, hintEntriesByPath.get(f.path) ?? [], BATCH_TOKENS));
      const batches = packBatches(promptFiles, BATCH_TOKENS);
      const batchUsd = (batch: PromptFile[]) => deps.lanes?.estimateUsd(
        'deep', PROJECTED_SYSTEM_TOKENS + batch.reduce((n, f) => n + f.blockTokens, 0), PROJECTED_OUTPUT_TOKENS,
      ) ?? 0;
      let remainingUsd = batches.reduce((sum, b) => sum + batchUsd(b), 0);
      lease.project(remainingUsd);
      let budgetExhausted = false;

      const findings: Finding[] = [];
      let warnedUnavailable = false;
      let batchesDone = 0;

      await forEachLimit(batches, BATCH_CONCURRENCY, async (batch) => {
        try {
          await reviewBatch(batch);
        } finally {
          remainingUsd -= batchUsd(batch);
          lease.project(remainingUsd);
          batchesDone++;
          ctx.reportProgress?.(batchesDone, batches.length);
        }
      });

      return findings;

      async function reviewBatch(batch: PromptFile[]): Promise<void> {
        checkAbort();
        const batchPaths = new Set(batch.map((f) => f.path));
        const batchHintEntries = batch.flatMap((f) => hintEntriesByPath.get(f.path) ?? []);
        const batchHintById = new Map(batchHintEntries.map((e) => [e.id, e]));

        const call: StructuredCall<ConfigOutput> = {
          scanId: ctx.scanId, analyzer: 'config', purpose: 'config-review', promptVersion: CONFIG_PROMPT_VERSION,
          role: 'deep', system: SYSTEM_PROMPT, prompt: batch.map((f) => f.block).join('\n\n'), schema: ConfigOutputSchema,
          signal: ctx.signal, onActivity: ctx.touch,
        };

        const keepHintsUnconfirmed = (status: CoverageStatus) => {
          // Fail-open for security: an unconfirmed hint still becomes a finding, just at low confidence
          // with an 'ai_unreviewed' riskFactor, rather than silently disappearing because the AI step
          // was unavailable.
          for (const entry of batchHintEntries) {
            findings.push(buildUnreviewedHintFinding(ctx, entry.hint));
          }
          for (const f of batch) record(f.path, status);
          if (!warnedUnavailable) {
            warnedUnavailable = true;
            ctx.warn('CONFIG_AI_UNAVAILABLE', 'AI config review was unavailable for one or more files; unconfirmed rule hints were kept at low confidence');
          }
        };
        if (budgetExhausted) { keepHintsUnconfirmed('budget-skipped'); return; }

        try {
          const result = await deps.llm.structured(call);

          const confirmedHintIssues: RawCodeIssue[] = [];
          const verdictedHintIds = new Set<string>();
          for (const v of result.output.hintVerdicts) {
            const entry = batchHintById.get(v.hintId);
            if (!entry) continue;
            verdictedHintIds.add(v.hintId);
            if (v.confirmed) {
              const confirmedIssue: RawCodeIssue = {
                ...entry.hint,
                explanation: `${entry.hint.explanation} AI review: ${v.reason}`.slice(0, 4_000),
              };
              confirmedHintIssues.push(confirmedIssue);
              findings.push(issueToFinding(ctx, 'config', confirmedIssue, ['config:rule', 'config:llm']));
            } else {
              // Refuted, not dropped: downgraded to info/low with an 'ai_refuted' riskFactor (see
              // buildRefutedHintFinding above) — the AI may downgrade a deterministic signal, never
              // make it disappear.
              findings.push(buildRefutedHintFinding(ctx, entry.hint, v.reason));
            }
          }
          // A hintId the model's response simply never mentioned: same fail-open treatment as a
          // whole-batch AI failure (keepHintsUnconfirmed), just scoped to the missing ones.
          for (const entry of batchHintEntries) {
            if (verdictedHintIds.has(entry.id)) continue;
            findings.push(buildUnreviewedHintFinding(ctx, entry.hint));
          }

          for (const raw of result.output.issues) {
            if (!batchPaths.has(raw.file)) continue;
            const text = effectiveTextByPath.get(raw.file);
            if (text === undefined) continue;
            const candidateIssue: RawCodeIssue = {
              ruleId: normalizeRuleId(raw.ruleId), title: raw.title, severity: raw.severity, confidence: raw.confidence,
              file: raw.file, startLine: raw.startLine, endLine: raw.endLine, snippet: raw.snippet,
              explanation: raw.explanation, impact: raw.impact, remediation: raw.remediation,
            };
            const outcome = verifyIssueLocation(candidateIssue, text);
            if (outcome.status === 'dropped') continue;
            const isDuplicateOfConfirmedHint = confirmedHintIssues.some(
              (h) => h.ruleId === outcome.issue.ruleId && overlaps(h, outcome.issue),
            );
            if (isDuplicateOfConfirmedHint) continue;
            findings.push(issueToFinding(ctx, 'config', outcome.issue, ['config:llm']));
          }
          for (const f of batch) record(f.path, 'reviewed');
        } catch (rawErr) {
          const err = toAppError(rawErr);
          if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
          if (err.kind === 'budget') budgetExhausted = true;
          keepHintsUnconfirmed(err.kind === 'budget' ? 'budget-skipped' : 'failed');
        }
        ctx.touch();
      }
  }
}

// --- mock responder ------------------------------------------------------------------------------

const HINT_OPEN_RE = /<hint\s+id="([^"]*)">/g;
const FILE_BLOCK_RE = /<untrusted_file\s+path="([^"]*)">([\s\S]*?)<\/untrusted_file>/g;
const CREATE_TABLE_RE = /create\s+table/i;
const ENABLE_RLS_RE = /enable\s+row\s+level\s+security/i;
const NUMBERED_LINE_RE = /^(\d+): ?(.*)$/;

function textOfRequest(req: LlmRequest): { system: string; user: string } {
  const system = req.system.map((b) => b.text).join('\n');
  const user = req.messages
    .flatMap((m) => (Array.isArray(m.content) ? m.content : []))
    .flatMap((b) => (b.type === 'text' ? [b.text] : []))
    .join('\n');
  return { system, user };
}

/**
 * Deterministic stand-in for the real model (MockTransport). Answers only requests whose system
 * prompt carries CONFIG_TASK_MARKER. Confirms every hint it is given, and additionally flags a
 * Supabase-style "create table" that has no matching "enable row level security" anywhere in the
 * same file as `config/supabase-table-without-rls`.
 */
export const configMockResponder: MockResponder = (req: LlmRequest) => {
  const { system, user } = textOfRequest(req);
  if (!system.includes(CONFIG_TASK_MARKER)) return undefined;

  const hintVerdicts: ConfigOutput['hintVerdicts'] = [];
  HINT_OPEN_RE.lastIndex = 0;
  let hm: RegExpExecArray | null = HINT_OPEN_RE.exec(user);
  while (hm !== null) {
    const id = unescapeAttr(hm[1] ?? '');
    if (id) hintVerdicts.push({ hintId: id, confirmed: true, reason: 'Confirmed by mock heuristic' });
    hm = HINT_OPEN_RE.exec(user);
  }

  const issues: ConfigOutput['issues'] = [];
  FILE_BLOCK_RE.lastIndex = 0;
  let fm: RegExpExecArray | null = FILE_BLOCK_RE.exec(user);
  while (fm !== null) {
    const path = unescapeAttr(fm[1] ?? '');
    const content = unescapeAttr(fm[2] ?? '');
    if (CREATE_TABLE_RE.test(content) && !ENABLE_RLS_RE.test(content)) {
      const lines = content.split('\n');
      const idx = lines.findIndex((l) => CREATE_TABLE_RE.test(l));
      if (idx !== -1) {
        const m = NUMBERED_LINE_RE.exec(lines[idx] ?? '');
        const line = m ? Number(m[1]) : 1;
        const snippet = (m ? m[2] : lines[idx]) || 'create table';
        issues.push({
          ruleId: 'config/supabase-table-without-rls',
          title: 'Table created without enabling row-level security',
          severity: 'high',
          confidence: 'medium',
          file: path,
          startLine: line,
          endLine: line,
          snippet,
          explanation: 'A table is created without an accompanying ENABLE ROW LEVEL SECURITY statement (mock heuristic).',
          impact: 'Without RLS, any client holding a valid anon/service key can read or write every row in this table.',
          remediation: 'Add ALTER TABLE ... ENABLE ROW LEVEL SECURITY and appropriate policies.',
        });
      }
    }
    fm = FILE_BLOCK_RE.exec(user);
  }

  return { hintVerdicts, issues };
};
