// AI code-quality analyzer (P6, Task A): deterministic metrics (metrics.ts) are EVIDENCE only — they
// decide WHICH files are worth a review and are handed to Claude as facts in the prompt, but Claude
// always writes the findings (quality is not security-critical, so there is no fail-open emission of
// raw metrics as findings; a file whose AI review fails simply produces no quality findings).
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
import type { LlmClient, StructuredCall } from '../../../llm/LlmClient';
import type { MockResponder } from '../../../llm/mockTransport';
import { untrustedFile } from '../../../llm/prompt';
import type { LlmRequest } from '../../../llm/transport';
import type { IndexedFile, Language } from '../../../index/types';
import type { Analyzer, AnalyzerContext } from '../../types';
import { issueToFinding } from '../toFinding';
import type { RawCodeIssue } from '../types';
import {
  computeFileMetrics, findDuplicateBlocks, rankFilesForQualityReview,
  DEEP_NESTING_DEPTH, LONG_FILE_LINES, LONG_FUNCTION_LINES, TODO_DENSITY_THRESHOLD,
  type DuplicateBlock, type FileMetrics, type QualityLanguage,
} from './metrics';

export const QUALITY_PROMPT_VERSION = 'quality-v1';
/** Appears verbatim in the system prompt; `qualityMockResponder` keys on it. */
export const QUALITY_TASK_MARKER = 'Task: code-quality-review';

const DEFAULT_MAX_FILES = 12;
const MAX_FILE_BYTES = 200 * 1024;
const READ_CONCURRENCY = 16;
const REVIEW_CONCURRENCY = 4;
const MAX_ISSUES_PER_FILE = 8;
const NUL_PROBE_BYTES = 8_192;

const LANG_MAP: Partial<Record<Language, QualityLanguage>> = {
  typescript: 'ts',
  javascript: 'js',
  python: 'py',
};

// --- schema --------------------------------------------------------------------------------------

const QualityIssueSchema = z.object({
  ruleId: z.string().min(1).max(100),
  title: z.string().min(1).max(200),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  confidence: z.enum(['high', 'medium', 'low']),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  snippet: z.string().min(1).max(2_000),
  explanation: z.string().min(1).max(2_000),
  impact: z.string().min(1).max(2_000),
  remediation: z.string().min(1).max(2_000),
});
const QualityOutputSchema = z.object({ issues: z.array(QualityIssueSchema).max(MAX_ISSUES_PER_FILE) });
type QualityOutput = z.infer<typeof QualityOutputSchema>;

// --- system prompt ---------------------------------------------------------------------------

const SYSTEM_PROMPT = [
  QUALITY_TASK_MARKER,
  '',
  'You are reviewing ONE source file for code-quality issues that are plausible, specific, and worth',
  "a developer's time. The <untrusted_file> block has 1-based line numbers prefixed to each line so",
  'you can cite them exactly. After it, "Metrics for <path>" lists facts computed by static analysis',
  '(line counts, function lengths, nesting depth, TODO density, duplicate code elsewhere in the repo).',
  'Those facts are evidence to guide your review, not findings themselves — they point at what might',
  'be worth flagging, but you decide whether each is an actual problem, and you may also flag issues',
  'the metrics never mention.',
  '',
  'Focus your review on:',
  '  - error handling: swallowed errors (empty or log-only catch blocks), missing awaits on promises,',
  '    unchecked error paths that can leave the system in a bad state.',
  '  - input validation hygiene: data used without checking its shape/type/bounds, especially before',
  '    it reaches a sink.',
  '  - dead code: unreachable branches, unused parameters/variables that suggest an incomplete fix.',
  '  - complexity/readability hot spots that are likely to hide bugs (not simply "this is long").',
  '  - maintainability risks in security-relevant code (auth, crypto, data access, request handling).',
  '',
  `Report at most ${MAX_ISSUES_PER_FILE} issues, each with: a ruleId formatted as "quality/<kebab-case-name>"`,
  '(e.g. "quality/swallowed-error"), a short title, a severity no higher than "medium" (quality issues',
  'are never critical/high — clamp your own judgement to at most medium), a confidence, the exact',
  'startLine/endLine and the snippet of code at that location (copy it verbatim from the numbered file',
  'so it can be verified), and an explanation, impact and remediation. If you find nothing worth',
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

function kebab(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'issue';
}

function normalizeRuleId(ruleId: string): string {
  return ruleId.startsWith('quality/') ? ruleId : `quality/${kebab(ruleId)}`;
}

// --- service ---------------------------------------------------------------------------------

export type QualityAnalyzerDeps = {
  llm: Pick<LlmClient, 'structured'>;
  /** Top N files (by rankFilesForQualityReview) actually sent to the model. Default 12. */
  maxFiles?: number;
};

export function createQualityAnalyzer(deps: QualityAnalyzerDeps): Analyzer {
  return {
    id: 'quality',
    version: '1',
    category: 'quality',

    async run(ctx: AnalyzerContext): Promise<Finding[]> {
      const checkAbort = () => {
        if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      };
      checkAbort();

      const maxFiles = deps.maxFiles ?? DEFAULT_MAX_FILES;

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
      const selected = rankFilesForQualityReview(metrics).slice(0, Math.max(0, maxFiles));

      const findings: Finding[] = [];
      let warnedPartial = false;

      await forEachLimit(selected, REVIEW_CONCURRENCY, async (path) => {
        checkAbort();
        const m = metricsByPath.get(path);
        const text = textByPath.get(path);
        if (!m || text === undefined) return;

        const prompt = `${untrustedFile(path, numberLines(text))}\n\n${buildFacts(m, duplicatesByPath.get(path) ?? [])}`;
        const call: StructuredCall<QualityOutput> = {
          scanId: ctx.scanId, analyzer: 'quality', purpose: 'quality-review', promptVersion: QUALITY_PROMPT_VERSION,
          role: 'fast', system: SYSTEM_PROMPT, prompt, schema: QualityOutputSchema,
          signal: ctx.signal, onActivity: ctx.touch,
        };

        try {
          const result = await deps.llm.structured(call);
          for (const raw of result.output.issues) {
            const issue: RawCodeIssue = {
              ruleId: normalizeRuleId(raw.ruleId),
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
        } catch (rawErr) {
          const err = toAppError(rawErr);
          if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
          // Quality is not security-critical: a file whose AI review fails produces NO findings,
          // only a once-per-run warning (unlike config's fail-open, which keeps low-confidence hints).
          if (!warnedPartial) {
            warnedPartial = true;
            ctx.warn('QUALITY_PARTIAL', 'AI code-quality review failed for one or more files; those files produced no quality findings');
          }
        }
        ctx.touch();
      });

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
    ruleId: 'quality/long-function',
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
