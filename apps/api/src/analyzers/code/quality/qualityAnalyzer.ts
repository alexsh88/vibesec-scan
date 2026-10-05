// AI code-quality analyzer (P6, Task A): deterministic metrics (metrics.ts) are EVIDENCE only — they
// decide WHICH files are worth a review and are handed to Claude as facts in the prompt, but Claude
// always writes the findings (quality is not security-critical, so there is no fail-open emission of
// raw metrics as findings; a file whose AI review fails simply produces no quality findings).
//
// Coverage: EVERY JS/TS/Python file is reviewed (Haiku), worst metrics first, in budget tier 3 — the
// lowest priority (llm/budget.ts): quality only spends what security work does not project to need,
// and files the budget could not cover are recorded as 'budget-skipped' coverage, never silently.
//
// Pattern follows triage.ts / credentials/fpFilter.ts: bounded-concurrency safe reads confined to
// repoDir, an injection-safe untrusted wrapper per file, verification before a Finding is ever built,
// and a deterministic mock responder keyed by a task marker in the system prompt.

import { open } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { z } from 'zod';
import type { Finding, Severity } from '@vibesec/shared';
import { toAppError } from '../../../errors/AppError';
import { SEVERITY_RANK } from '../../../findings/helpers';
import { verifyIssueLocation } from '../../../findings/verify';
import { formatFailureReasons, llmFailureReason, type LlmFailureReason } from '../../../llm/failureReason';
import type { LlmClient, StructuredCall } from '../../../llm/LlmClient';
import type { MockResponder } from '../../../llm/mockTransport';
import { untrustedFile } from '../../../llm/prompt';
import type { LlmRequest } from '../../../llm/transport';
import type { IndexedFile, Language } from '../../../index/types';
import { reusablePaths, reusedFindings } from '../../reuse';
import type { Analyzer, AnalyzerContext, CoverageStatus } from '../../types';
import { issueToFinding } from '../toFinding';
import type { RawCodeIssue } from '../types';
import {
  computeFileMetrics, findDuplicateBlocks, rankFilesForQualityReview,
  DEEP_NESTING_DEPTH, LONG_FILE_LINES, LONG_FUNCTION_LINES, TODO_DENSITY_THRESHOLD,
  type DuplicateBlock, type FileMetrics, type QualityLanguage,
} from './metrics';

export const QUALITY_PROMPT_VERSION = 'quality-v2';
/** Appears verbatim in the system prompt; `qualityMockResponder` keys on it. */
export const QUALITY_TASK_MARKER = 'Task: code-quality-review';

const MAX_FILE_BYTES = 200 * 1024;
const READ_CONCURRENCY = 16;
const REVIEW_CONCURRENCY = 4;
const MAX_ISSUES_PER_FILE = 5;
const SCHEMA_MAX_ISSUES = 10;
/** Haiku's role default is 4096; up to 10 issues with verbatim snippets + prose need headroom so a
 *  verbose reply is not cut off mid-JSON (a truncated reply is unusable and is not retried). */
const QUALITY_MAX_TOKENS = 8_192;
const NUL_PROBE_BYTES = 8_192;

const LANG_MAP: Partial<Record<Language, QualityLanguage>> = {
  typescript: 'ts',
  javascript: 'js',
  python: 'py',
};

// --- schema --------------------------------------------------------------------------------------

/**
 * Fixed maintainability/reliability catalogue. The output schema enforces it (server-side enum), so the
 * model cannot drift into security vulnerabilities — those belong to SAST/taint/credentials/config, and
 * duplicating them as quality findings only adds noise (first live eval: 60 quality findings, most of
 * them re-reported injections and hardcoded credentials).
 */
export const QUALITY_RULES = {
  'quality/swallowed-error': 'catch block that ignores or only logs an error, so the caller continues in a bad state',
  'quality/unhandled-promise': 'promise whose rejection is never handled (fire-and-forget async call, missing .catch)',
  'quality/missing-await': 'async call not awaited where the result or its completion is relied on',
  'quality/inconsistent-error-handling': 'error paths handled differently in the same module (some throw, some return null, some respond twice)',
  'quality/null-dereference': 'value that can be null/undefined/empty (query result, lookup, optional field) used without a check',
  'quality/missing-input-validation': 'non-security data hygiene: a request/input value used without checking its type/shape/range, leading to crashes or wrong results',
  'quality/type-coercion': 'implicit or unchecked conversion (Number(), parseInt without radix/NaN check, == comparisons) that silently yields wrong values',
  'quality/resource-leak': 'file handle, connection, timer or listener that is opened but never closed/released on every path',
  'quality/race-condition': 'check-then-act or shared mutable state updated concurrently without coordination',
  'quality/missing-timeout': 'network/IO call with no timeout, so one slow dependency can hang a request or worker',
  'quality/blocking-io-in-handler': 'synchronous filesystem/CPU-heavy work inside a request handler that blocks the event loop',
  'quality/n-plus-one-query': 'database/API query issued inside a loop instead of one batched query',
  'quality/dead-code': 'unreachable branch, or unused variable/parameter/import that suggests an incomplete change',
  'quality/complex-function': 'function long or deeply nested enough to hide bugs (cite where the complexity actually hurts)',
  'quality/duplicated-logic': 'logic copy-pasted across places that must be kept in sync by hand',
  'quality/magic-values': 'unexplained literal (limit, timeout, status code, path) repeated or likely to need changing',
  'quality/todo-hack': 'TODO/FIXME/HACK marking known-incomplete behaviour on a live code path',
} as const;
export type QualityRuleId = keyof typeof QUALITY_RULES;
export const QUALITY_RULE_IDS = Object.keys(QUALITY_RULES) as [QualityRuleId, ...QualityRuleId[]];
const QUALITY_RULE_SET: ReadonlySet<string> = new Set(QUALITY_RULE_IDS);

const QualityIssueSchema = z.object({
  ruleId: z.enum(QUALITY_RULE_IDS),
  title: z.string().min(1).max(200),
  severity: z.enum(['medium', 'low', 'info']),
  confidence: z.enum(['high', 'medium', 'low']),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  snippet: z.string().min(1).max(2_000),
  explanation: z.string().min(1).max(2_000),
  impact: z.string().min(1).max(2_000),
  remediation: z.string().min(1).max(2_000),
});
// The array bound is deliberately looser than MAX_ISSUES_PER_FILE: maxItems is only advisory in the
// server-side schema, so a model that returns 6 issues should not cost a repair turn — the analyzer
// keeps the most severe MAX_ISSUES_PER_FILE itself.
export const QualityOutputSchema = z.object({ issues: z.array(QualityIssueSchema).max(SCHEMA_MAX_ISSUES) });
type QualityOutput = z.infer<typeof QualityOutputSchema>;

// --- system prompt ---------------------------------------------------------------------------

const RULE_LINES = Object.entries(QUALITY_RULES).map(([id, desc]) => `  - ${id}: ${desc}`);

const SYSTEM_PROMPT = [
  QUALITY_TASK_MARKER,
  '',
  'You are reviewing ONE source file for maintainability and reliability problems that are specific,',
  "real, and worth a developer's time. The <untrusted_file> block has 1-based line numbers prefixed to",
  'each line so you can cite them exactly. After it, "Metrics for <path>" lists facts computed by static',
  'analysis (line counts, function lengths, nesting depth, TODO density, duplicate code elsewhere in the',
  'repo). Those facts are evidence to guide your review, not findings themselves — you decide whether',
  'each is an actual problem, and you may also flag issues the metrics never mention.',
  '',
  'Security vulnerabilities are out of scope: another analyzer owns them. Do NOT report injection (SQL,',
  'command, code, prompt), XSS, SSRF, path traversal, open redirects, unsafe deserialization, hardcoded',
  'or exposed credentials, weak crypto/hashing, CORS, authentication/authorization or JWT problems —',
  'not even rephrased as "missing validation" or "unsafe" quality issues. Also skip noise: reading a',
  'documented public config value (e.g. a NEXT_PUBLIC_* anon/publishable key) without a presence',
  'check, style/naming nits, and generic "add error handling" advice where the framework already',
  'handles the error.',
  '',
  'Rule ids — use exactly one of:',
  ...RULE_LINES,
  '',
  `Report at most ${MAX_ISSUES_PER_FILE} issues; prefer fewer, high-value ones (most files deserve 0-2). Each`,
  'issue needs: a ruleId from the list, a short title, a severity of "medium", "low" or "info" (quality',
  'issues are never critical/high), a confidence, the exact startLine/endLine and the snippet of code at',
  'that location (copy it verbatim from the numbered file, without the "12: " prefix, so it can be',
  'verified), and a brief explanation, impact and remediation (1-3 sentences each). If nothing is worth',
  'reporting, return an empty issues array — do not invent problems to fill a quota.',
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

function longestFunction(m: FileMetrics): FileMetrics['functions'][number] | undefined {
  return m.functions.reduce<FileMetrics['functions'][number] | undefined>(
    (best, f) => (!best || f.length > best.length ? f : best),
    undefined,
  );
}

function buildFacts(m: FileMetrics, duplicates: readonly DuplicateBlock[]): string {
  const lines: string[] = [
    `Metrics for ${m.path} (computed by static analysis, not an AI judgement — evidence only, never a finding by itself):`,
    `- total lines: ${m.lines}${m.lines > LONG_FILE_LINES ? ` (exceeds long-file threshold of ${LONG_FILE_LINES})` : ''}`,
    `- code lines: ${m.codeLines}`,
  ];
  const longest = longestFunction(m);
  if (longest) {
    lines.push(`- Longest function: "${longest.name}" lines ${longest.startLine}-${longest.endLine} (length ${longest.length}, maxNesting ${longest.maxNesting})`);
  }
  if (m.longFunctions > 0) lines.push(`- ${m.longFunctions} function(s) longer than ${LONG_FUNCTION_LINES} lines`);
  if (m.deepNesting > 0) lines.push(`- ${m.deepNesting} function(s) nested deeper than ${DEEP_NESTING_DEPTH} levels`);
  if (m.todoCount > 0) {
    lines.push(`- ${m.todoCount} TODO/FIXME/XXX/HACK marker(s), ${m.todoDensity} per 100 code lines${m.todoDensity > TODO_DENSITY_THRESHOLD ? ` (exceeds threshold ${TODO_DENSITY_THRESHOLD})` : ''}`);
  }
  if (duplicates.length > 0) {
    lines.push('- duplicate code blocks also appearing elsewhere in the repository:');
    for (const dup of duplicates) {
      const mine = dup.occurrences.find((o) => o.path === m.path);
      const others = dup.occurrences
        .filter((o) => !(o.path === mine?.path && o.startLine === mine?.startLine))
        .map((o) => `${o.path}:${o.startLine}`);
      lines.push(`  - starting at line ${mine?.startLine ?? '?'} (also at ${others.join(', ') || 'another location'})`);
    }
  }
  return lines.join('\n');
}

// --- severity/ruleId normalization --------------------------------------------------------------

/** Quality findings are never critical/high — clamp anything worse than 'medium' down to it. */
function clampSeverity(s: Severity): Severity {
  return SEVERITY_RANK[s] < SEVERITY_RANK.medium ? 'medium' : s;
}

const CONFIDENCE_RANK: Record<QualityOutput['issues'][number]['confidence'], number> = { high: 0, medium: 1, low: 2 };

/** Catalogue rule ids only (defence in depth — the schema enum already enforces it), most severe and
 *  most confident first (stable among equals), capped at MAX_ISSUES_PER_FILE. */
function selectIssues(issues: readonly QualityOutput['issues'][number][]): QualityOutput['issues'] {
  return issues
    .filter((i) => QUALITY_RULE_SET.has(i.ruleId))
    .map((issue, index) => ({ issue, index }))
    .sort((a, b) =>
      SEVERITY_RANK[clampSeverity(a.issue.severity)] - SEVERITY_RANK[clampSeverity(b.issue.severity)]
      || CONFIDENCE_RANK[a.issue.confidence] - CONFIDENCE_RANK[b.issue.confidence]
      || a.index - b.index)
    .slice(0, MAX_ISSUES_PER_FILE)
    .map((x) => x.issue);
}

// --- service ---------------------------------------------------------------------------------

export type QualityAnalyzerDeps = {
  llm: Pick<LlmClient, 'structured'>;
};

export function createQualityAnalyzer(deps: QualityAnalyzerDeps): Analyzer {
  return {
    id: 'quality',
    version: '2',
    category: 'quality',

    async run(ctx: AnalyzerContext): Promise<Finding[]> {
      const checkAbort = () => {
        if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      };
      checkAbort();

      const record = (path: string, status: CoverageStatus) => ctx.recordCoverage?.('quality', path, status);

      const candidates = ctx.files.filter((f: IndexedFile) => f.skipReason === null && LANG_MAP[f.language] !== undefined);
      const contentOf = new Map<string, string>();
      await forEachLimit(candidates, READ_CONCURRENCY, async (f) => {
        checkAbort();
        const text = await readFileSafe(ctx.repoDir, f.path, MAX_FILE_BYTES);
        if (text !== null) contentOf.set(f.path, text);
        ctx.touch();
      });

      const withLang = candidates
        .filter((f) => contentOf.has(f.path))
        .map((f) => ({ path: f.path, text: contentOf.get(f.path)!, lang: LANG_MAP[f.language]! }));
      if (withLang.length === 0) return [];

      const metrics = withLang.map((f) => computeFileMetrics(f.path, f.text, f.lang));
      const duplicates = findDuplicateBlocks(withLang.map((f) => ({ path: f.path, text: f.text })));
      const duplicatesByPath = new Map<string, DuplicateBlock[]>();
      for (const dup of duplicates) {
        for (const occ of dup.occurrences) {
          const list = duplicatesByPath.get(occ.path);
          if (list) list.push(dup);
          else duplicatesByPath.set(occ.path, [dup]);
        }
      }

      const metricsByPath = new Map(metrics.map((m) => [m.path, m]));
      const textByPath = new Map(withLang.map((f) => [f.path, f.text]));
      for (const f of candidates) if (!contentOf.has(f.path)) record(f.path, 'failed');
      const ranked = rankFilesForQualityReview(metrics);
      // Incremental rescan: unchanged files the base scan reviewed keep their findings (re-attached), no call.
      const reused = reusablePaths(ctx, 'quality', ranked);
      for (const path of reused) record(path, 'cached');
      const selected = ranked.filter((p) => !reused.has(p));
      let budgetExhausted = false;

      const findings: Finding[] = reusedFindings(ctx, 'quality', reused);
      const failures = new Map<LlmFailureReason, number>();
      let reviewedCount = 0;

      await forEachLimit(selected, REVIEW_CONCURRENCY, async (path) => {
        try {
          checkAbort();
          const m = metricsByPath.get(path);
          const text = textByPath.get(path);
          if (!m || text === undefined) return;
          if (budgetExhausted) { record(path, 'budget-skipped'); return; }

          const prompt = `${untrustedFile(path, numberLines(text))}\n\n${buildFacts(m, duplicatesByPath.get(path) ?? [])}`;
          const call: StructuredCall<QualityOutput> = {
            scanId: ctx.scanId, analyzer: 'quality', purpose: 'quality-review', promptVersion: QUALITY_PROMPT_VERSION,
            role: 'fast', tier: 3, system: SYSTEM_PROMPT, prompt, schema: QualityOutputSchema,
            maxTokens: QUALITY_MAX_TOKENS, signal: ctx.signal, onActivity: ctx.touch,
          };

          try {
            const result = await deps.llm.structured(call);
            for (const raw of selectIssues(result.output.issues)) {
              const issue: RawCodeIssue = {
                ruleId: raw.ruleId,
                title: raw.title,
                severity: clampSeverity(raw.severity),
                confidence: raw.confidence,
                file: path,
                startLine: raw.startLine,
                endLine: raw.endLine,
                snippet: raw.snippet,
                explanation: raw.explanation,
                impact: raw.impact,
                remediation: raw.remediation,
              };
              const outcome = verifyIssueLocation(issue, text);
              if (outcome.status === 'dropped') continue;
              findings.push(issueToFinding(ctx, 'quality', outcome.issue, ['quality:llm']));
            }
            record(path, 'reviewed');
          } catch (rawErr) {
            const err = toAppError(rawErr);
            if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
            if (err.kind === 'budget') {
              budgetExhausted = true;
              record(path, 'budget-skipped');
              return;
            }
            record(path, 'failed');
            // Quality is not security-critical: a file whose AI review fails produces NO findings, only
            // one aggregated warning per run (unlike config's fail-open, which keeps low-confidence hints).
            const reason = llmFailureReason(err);
            failures.set(reason, (failures.get(reason) ?? 0) + 1);
          }
          ctx.touch();
        } finally {
          reviewedCount++;
          ctx.reportProgress?.(reviewedCount, selected.length);
        }
      });

      if (failures.size > 0) {
        const failed = [...failures.values()].reduce((a, b) => a + b, 0);
        ctx.warn('QUALITY_PARTIAL', `AI code-quality review failed for ${failed} file(s) (${formatFailureReasons(failures)}); those files produced no quality findings`);
      }
      return findings;
    },
  };
}

// --- mock responder ------------------------------------------------------------------------------

const FACT_LONGEST_RE = /Longest function: "([^"]*)" lines (\d+)-(\d+)/;
const FILE_BLOCK_RE = /<untrusted_file\s+path="([^"]*)">([\s\S]*?)<\/untrusted_file>/;

function unescapeAttr(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

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
 * prompt carries QUALITY_TASK_MARKER. Returns one issue for the file's longest function (read off the
 * "Longest function: ..." fact line this module itself writes into the prompt), citing the real line
 * at its reported startLine so the issue survives verifyIssueLocation. Returns no issues when the
 * file has no functions (no "Longest function" fact to act on).
 */
export const qualityMockResponder: MockResponder = (req: LlmRequest) => {
  const { system, user } = textOfRequest(req);
  if (!system.includes(QUALITY_TASK_MARKER)) return undefined;

  const fileMatch = FILE_BLOCK_RE.exec(user);
  const factMatch = FACT_LONGEST_RE.exec(user);
  if (!fileMatch || !factMatch) return { issues: [] };

  const content = unescapeAttr(fileMatch[2] ?? '');
  const name = factMatch[1] ?? 'anonymous';
  const start = Number(factMatch[2]);
  // Find the line by its own "N: " prefix rather than by array index: untrustedFile() wraps content
  // with a leading/trailing newline, so content.split('\n')[start - 1] is NOT reliably line `start`.
  const prefix = `${start}: `;
  const raw = content.split('\n').find((l) => l.startsWith(prefix));
  const snippet = raw !== undefined ? raw.slice(prefix.length) : '';
  if (snippet.trim() === '') return { issues: [] };

  const issues: QualityOutput['issues'] = [{
    ruleId: 'quality/complex-function',
    title: `Long function '${name}'`,
    severity: 'medium',
    confidence: 'medium',
    startLine: start,
    endLine: start,
    snippet,
    explanation: `Function '${name}' is the longest in this file, per the longest-function metric (mock heuristic).`,
    impact: 'Long functions are harder to review, test and reason about, and more likely to hide bugs.',
    remediation: 'Extract smaller functions with a single responsibility.',
  }];
  return { issues };
};
