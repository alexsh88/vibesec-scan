/**
 * Skeptic pass (VERIFYING stage): Claude (Sonnet, role 'deep', budget tier 1) re-reads the real code
 * around every remaining critical/high SAST or taint finding and argues AGAINST it — is the input
 * really attacker-controlled, is there sanitization/validation/auth upstream, is it dead/test code, is
 * the sink actually dangerous here? Deterministic code only selects, packs and applies verdicts.
 *
 * Verdicts (AI-first, never silent):
 *   upheld   → unchanged, producedBy += 'skeptic:upheld'
 *   weakened → confidence one step lower, riskFactor 'skeptic_weakened' (effect 0), producedBy += 'skeptic:weakened'
 *   refuted  → severity 'info', confidence 'low', riskFactor 'ai_refuted' (effect = −severity steps),
 *              explanation sentence, producedBy += 'skeptic:refuted'. The finding STAYS (hidden by the
 *              UI's default severity filter, never deleted).
 * A degraded reply (served by a lower model tier) may not refute: 'refuted' is applied as 'weakened'.
 *
 * Findings already carrying a 'skeptic:*' producedBy marker are never re-reviewed (idempotent re-runs).
 * Fail-open: a failed call leaves its findings unchanged and is counted by safe reason category; a
 * budget refusal stops the pass (remaining findings stay unreviewed); cancellation propagates.
 */

import type { Finding, Severity } from '@vibesec/shared';
import { toAppError } from '../errors/AppError';
import { llmFailureReason, type LlmFailureReason } from '../llm/failureReason';
import type { LlmClient, StructuredCall } from '../llm/LlmClient';
import type { MockResponder } from '../llm/mockTransport';
import { untrustedFile, untrustedText } from '../llm/prompt';
import type { LlmRequest } from '../llm/transport';
import { provisionalScore, SEVERITY_RANK } from './helpers';
import {
  SKEPTIC_BATCH_SIZE, SKEPTIC_PROMPT_VERSION, SKEPTIC_REASON_MAX, SKEPTIC_SYSTEM_PROMPT, SKEPTIC_TASK_MARKER,
  SkepticOutputSchema, type SkepticOutput, type SkepticVerdict,
} from './skepticPrompt';

export { SKEPTIC_PROMPT_VERSION, SKEPTIC_TASK_MARKER } from './skepticPrompt';

export const DEFAULT_MAX_SKEPTIC = 200;
const DEFAULT_CONCURRENCY = 4;
const LOCATION_CONTEXT_LINES = 40;
const TRACE_CONTEXT_LINES = 10;
const MAX_CODE_LINES_PER_CALL = 600;
const MAX_LINE_CHARS = 300;
const MAX_META_CHARS = 1_500;

const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const LOWER_CONFIDENCE: Record<Finding['confidence'], Finding['confidence']> = { high: 'medium', medium: 'low', low: 'low' };
const CONFIDENCE_RANK: Record<Finding['confidence'], number> = { high: 0, medium: 1, low: 2 };

export type SkepticDeps = {
  llm: Pick<LlmClient, 'structured'>;
  /** Repo-confined, size-capped read of a repository file (null when unreadable). */
  readFile: (path: string) => Promise<string | null>;
  maxSkeptic?: number;
  concurrency?: number;
};

export type SkepticRunContext = {
  scanId: string;
  signal: AbortSignal;
  touch: () => void;
  onProgress?: (done: number, total: number) => void;
};

export type SkepticResult = {
  /** Findings whose state changed (verdict applied). */
  changed: Finding[];
  reviewed: number;
  /** Findings that should have been reviewed but were not, by cause. */
  failures: Map<LlmFailureReason, number>;
  budgetSkipped: number;
  capSkipped: number;
  codeUnavailable: number;
};

export function isSkepticReviewed(f: Finding): boolean {
  return (f.producedBy ?? []).some((p) => p.startsWith('skeptic:'));
}

export function needsSkeptic(f: Finding): boolean {
  return (f.category === 'sast' || f.category === 'taint')
    && (f.severity === 'critical' || f.severity === 'high')
    && !isSkepticReviewed(f);
}

function riskOrder(a: Finding, b: Finding): number {
  const taint = (f: Finding) => (f.category === 'taint' ? 0 : 1);
  return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    || taint(a) - taint(b)
    || CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence]
    || (a.location.file < b.location.file ? -1 : a.location.file > b.location.file ? 1 : 0)
    || a.location.startLine - b.location.startLine
    || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/** Risk-ordered batches of ≤ SKEPTIC_BATCH_SIZE findings, each batch within one file. */
export function planBatches(findings: readonly Finding[]): Finding[][] {
  const byFile = new Map<string, Finding[]>();
  for (const f of [...findings].sort(riskOrder)) {
    const list = byFile.get(f.location.file);
    if (list) list.push(f);
    else byFile.set(f.location.file, [f]);
  }
  const batches: Finding[][] = [];
  for (const list of byFile.values()) {
    for (let i = 0; i < list.length; i += SKEPTIC_BATCH_SIZE) batches.push(list.slice(i, i + SKEPTIC_BATCH_SIZE));
  }
  return batches.sort((a, b) => riskOrder(a[0]!, b[0]!));
}

// --- prompt ---------------------------------------------------------------------------------------

type Range = { start: number; end: number };

function mergeRanges(ranges: Range[]): Range[] {
  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  const out: Range[] = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last && r.start <= last.end + 1) last.end = Math.max(last.end, r.end);
    else out.push({ ...r });
  }
  return out;
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function findingBlock(f: Finding, index: number): string {
  const lines = [
    `ruleId: ${f.ruleId}`,
    `title: ${clip(f.title, 200)}`,
    `cwe: ${f.cwe ?? 'none'}`,
    `severity: ${f.severity} (confidence ${f.confidence})`,
    `location: ${f.location.file}:${f.location.startLine}-${f.location.endLine}`,
    `explanation: ${clip(f.explanation, MAX_META_CHARS)}`,
  ];
  if (f.taintTrace?.length) {
    lines.push('taint trace:');
    for (const s of f.taintTrace) lines.push(`  - ${s.kind} at ${s.file}:${s.line}: ${clip(s.code, 200)} (${clip(s.note, 200)})`);
  }
  return `FINDING findingIndex=${index}\n${untrustedText(`finding-${index}`, lines.join('\n'))}`;
}

/** Builds the per-batch prompt; returns null when none of the code could be read. */
export async function buildSkepticPrompt(batch: readonly Finding[], readFile: SkepticDeps['readFile']): Promise<string | null> {
  const wanted = new Map<string, Range[]>();
  const add = (file: string, r: Range) => {
    const list = wanted.get(file);
    if (list) list.push(r);
    else wanted.set(file, [r]);
  };
  for (const f of batch) {
    add(f.location.file, { start: f.location.startLine - LOCATION_CONTEXT_LINES, end: f.location.endLine + LOCATION_CONTEXT_LINES });
    for (const s of f.taintTrace ?? []) add(s.file, { start: s.line - TRACE_CONTEXT_LINES, end: s.line + TRACE_CONTEXT_LINES });
  }

  const blocks: string[] = [];
  let budget = MAX_CODE_LINES_PER_CALL;
  let primaryRead = false;
  for (const [file, ranges] of wanted) {
    if (budget <= 0) break;
    const text = await readFile(file);
    if (text === null) continue;
    if (file === batch[0]!.location.file) primaryRead = true;
    const lines = text.split(/\r?\n/);
    const parts: string[] = [];
    for (const r of mergeRanges(ranges)) {
      const start = Math.max(1, r.start);
      const end = Math.min(lines.length, r.end, start + budget - 1);
      if (end < start) continue;
      if (parts.length > 0) parts.push('…');
      for (let ln = start; ln <= end; ln++) parts.push(`${ln}: ${clip(lines[ln - 1] ?? '', MAX_LINE_CHARS)}`);
      budget -= end - start + 1;
      if (budget <= 0) break;
    }
    if (parts.length > 0) blocks.push(untrustedFile(file, parts.join('\n')));
  }
  if (!primaryRead) return null;

  return [
    `Review ${batch.length} finding(s) reported in ${JSON.stringify(batch[0]!.location.file)}. Argue against each one using the code below, then give your verdicts.`,
    '',
    ...batch.map((f, i) => findingBlock(f, i)),
    '',
    'CODE (numbered lines from the repository at the scanned commit):',
    ...blocks,
  ].join('\n');
}

// --- verdicts -------------------------------------------------------------------------------------

function withMarker(f: Finding, marker: string): string[] {
  return [...new Set([...(f.producedBy ?? []), marker])];
}

function reasonText(v: SkepticVerdict): string {
  const reason = clip(v.reason.trim(), SKEPTIC_REASON_MAX);
  return v.evidenceLines?.length ? `${reason} (evidence: line ${v.evidenceLines.slice(0, 10).join(', ')})` : reason;
}

export function applyVerdict(f: Finding, v: SkepticVerdict, degraded = false): Finding {
  const verdict = degraded && v.verdict === 'refuted' ? 'weakened' : v.verdict;
  const reason = reasonText(v);
  if (verdict === 'upheld') return { ...f, producedBy: withMarker(f, 'skeptic:upheld') };
  if (verdict === 'weakened') {
    return {
      ...f,
      confidence: LOWER_CONFIDENCE[f.confidence],
      riskFactors: [...f.riskFactors, { factor: 'skeptic_weakened', effect: 0, reason }],
      producedBy: withMarker(f, 'skeptic:weakened'),
    };
  }
  return {
    ...f,
    severity: 'info',
    confidence: 'low',
    riskScore: provisionalScore('info'),
    riskFactors: [...f.riskFactors, { factor: 'ai_refuted', effect: SEVERITY_ORDER.indexOf('info') - SEVERITY_ORDER.indexOf(f.severity), reason }],
    explanation: `${f.explanation} AI skeptic review judged this a likely false positive: ${reason}`,
    producedBy: withMarker(f, 'skeptic:refuted'),
  };
}

// --- pass -----------------------------------------------------------------------------------------

async function forEachLimit<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  let failed = false;
  const worker = async () => {
    while (!failed && next < items.length) {
      const item = items[next++]!;
      try {
        await fn(item);
      } catch (err) {
        failed = true;
        throw err;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
}

export async function runSkeptic(findings: readonly Finding[], ctx: SkepticRunContext, deps: SkepticDeps): Promise<SkepticResult> {
  const cap = Math.max(0, Math.min(deps.maxSkeptic ?? DEFAULT_MAX_SKEPTIC, DEFAULT_MAX_SKEPTIC));
  const eligible = findings.filter(needsSkeptic).sort(riskOrder);
  const selected = eligible.slice(0, cap);
  const result: SkepticResult = {
    changed: [], reviewed: 0, failures: new Map(), budgetSkipped: 0, capSkipped: eligible.length - selected.length, codeUnavailable: 0,
  };
  const batches = planBatches(selected);
  if (batches.length === 0) return result;

  const fileCache = new Map<string, Promise<string | null>>();
  const readFile = (path: string) => {
    let p = fileCache.get(path);
    if (!p) { p = deps.readFile(path); fileCache.set(path, p); }
    return p;
  };
  const fail = (reason: LlmFailureReason, n: number) => result.failures.set(reason, (result.failures.get(reason) ?? 0) + n);
  let exhausted = false;
  let done = 0;
  const checkAbort = () => {
    if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
  };

  await forEachLimit(batches, deps.concurrency ?? DEFAULT_CONCURRENCY, async (batch) => {
    checkAbort();
    try {
      if (exhausted) { result.budgetSkipped += batch.length; return; }
      const prompt = await buildSkepticPrompt(batch, readFile);
      if (prompt === null) { result.codeUnavailable += batch.length; return; }
      const call: StructuredCall<SkepticOutput> = {
        scanId: ctx.scanId, analyzer: 'verify', purpose: 'skeptic', promptVersion: SKEPTIC_PROMPT_VERSION,
        role: 'deep', tier: 1, system: SKEPTIC_SYSTEM_PROMPT, prompt, schema: SkepticOutputSchema,
        signal: ctx.signal, onActivity: ctx.touch,
      };
      let output: SkepticOutput;
      let degraded = false;
      try {
        const res = await deps.llm.structured(call);
        output = res.output;
        degraded = res.degraded;
      } catch (raw) {
        const err = toAppError(raw);
        if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
        if (err.kind === 'budget') { exhausted = true; result.budgetSkipped += batch.length; return; }
        fail(llmFailureReason(err), batch.length);
        return;
      } finally {
        ctx.touch();
      }
      const byIndex = new Map<number, SkepticVerdict>();
      for (const v of output.verdicts) if (!byIndex.has(v.findingIndex)) byIndex.set(v.findingIndex, v);
      batch.forEach((f, i) => {
        const v = byIndex.get(i);
        if (!v) { fail('validation', 1); return; }
        result.changed.push(applyVerdict(f, v, degraded));
        result.reviewed++;
      });
    } finally {
      done++;
      ctx.onProgress?.(done, batches.length);
    }
  });
  return result;
}

/** One-line, content-free summary for the VERIFY_PARTIAL warning (null when everything was reviewed). */
export function partialSummary(r: SkepticResult): string | null {
  const parts: string[] = [];
  const failed = [...r.failures.values()].reduce((a, b) => a + b, 0);
  if (failed > 0) {
    const order: LlmFailureReason[] = ['truncated', 'too-large', 'validation', 'refusal', 'transport', 'other'];
    parts.push(`${failed} failed (${order.filter((k) => (r.failures.get(k) ?? 0) > 0).map((k) => `${r.failures.get(k)} ${k}`).join(', ')})`);
  }
  if (r.budgetSkipped > 0) parts.push(`${r.budgetSkipped} skipped: AI budget exhausted`);
  if (r.capSkipped > 0) parts.push(`${r.capSkipped} skipped: review cap reached`);
  if (r.codeUnavailable > 0) parts.push(`${r.codeUnavailable} skipped: code unreadable`);
  if (parts.length === 0) return null;
  return `The AI skeptic review did not check every critical/high finding — ${parts.join('; ')}. Those findings are reported unverified.`;
}

// --- mock responder -------------------------------------------------------------------------------

const FINDING_BLOCK_RE = /<untrusted_text source="finding-(\d+)">\n([\s\S]*?)\n<\/untrusted_text>/g;
const FILE_BLOCK_RE = /<untrusted_file path="([^"]*)">\n([\s\S]*?)\n<\/untrusted_file>/g;
/** Lines above the sink (and the sink itself) the mock inspects for a sanitizer. */
const MOCK_NEAR_LINES = 6;
const MOCK_SANITIZERS: ReadonlyArray<{ re: RegExp; why: string }> = [
  { re: /\.startsWith\(\s*['"`]\/['"`]\s*\)/, why: 'the redirect target is restricted to a same-site path (startsWith("/") check)' },
  { re: /\bpath\.basename\s*\(/, why: 'the path is reduced to its basename before use' },
  { re: /['"`][^'"`]*(?:\?|\$\d+)[^'"`]*['"`]\s*,\s*\[/, why: 'the query uses bound parameters (placeholders), not string building' },
  { re: /\b(?:escape\w*|\w*[sS]anitize\w*)\s*\(/, why: 'the value passes through an escaping/sanitizing function before the sink' },
];
const MOCK_TESTISH_RE = /(^|\/)(test|tests|__tests__|spec|examples?)\/|\.(test|spec)\.[a-z]+$/i;

function unescapeAttr(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

/**
 * Deterministic stand-in for Claude in mock mode (SKEPTIC_TASK_MARKER requests only): refutes a
 * finding when a sanitizer/allowlist pattern appears within MOCK_NEAR_LINES above its location,
 * weakens it when it lives under test/ or examples/, and upholds it otherwise.
 */
export const skepticMockResponder: MockResponder = (req: LlmRequest) => {
  const system = req.system.map((b) => b.text).join('\n');
  if (!system.includes(SKEPTIC_TASK_MARKER)) return undefined;
  const user = req.messages
    .flatMap((m) => (Array.isArray(m.content) ? m.content : []))
    .flatMap((b) => (b.type === 'text' ? [b.text] : []))
    .join('\n');

  const code = new Map<string, Map<number, string>>();
  for (const m of user.matchAll(FILE_BLOCK_RE)) {
    const file = unescapeAttr(m[1] ?? '');
    const lines = code.get(file) ?? new Map<number, string>();
    for (const raw of (m[2] ?? '').split('\n')) {
      const lm = /^(\d+): (.*)$/.exec(raw);
      if (lm) lines.set(Number(lm[1]), lm[2] ?? '');
    }
    code.set(file, lines);
  }

  const verdicts: SkepticVerdict[] = [];
  for (const m of user.matchAll(FINDING_BLOCK_RE)) {
    const index = Number(m[1]);
    const loc = /^location: (.*):(\d+)-(\d+)$/m.exec(m[2] ?? '');
    if (!loc || index >= SKEPTIC_BATCH_SIZE) continue;
    const file = loc[1] ?? '';
    const start = Number(loc[2]);
    const end = Number(loc[3]);
    const lines = code.get(file);
    let refuted: { why: string; line: number } | undefined;
    for (let ln = Math.max(1, start - MOCK_NEAR_LINES); ln <= end && !refuted; ln++) {
      const text = lines?.get(ln);
      const hit = text === undefined ? undefined : MOCK_SANITIZERS.find((s) => s.re.test(text));
      if (hit) refuted = { why: hit.why, line: ln };
    }
    if (refuted) {
      verdicts.push({ findingIndex: index, verdict: 'refuted', reason: `[mock] Not exploitable: ${refuted.why}.`, evidenceLines: [refuted.line] });
    } else if (MOCK_TESTISH_RE.test(file)) {
      verdicts.push({ findingIndex: index, verdict: 'weakened', reason: '[mock] The code lives in test/example code that does not ship to production.' });
    } else {
      verdicts.push({ findingIndex: index, verdict: 'upheld', reason: '[mock] No sanitization, validation or auth check found upstream of the sink.' });
    }
  }
  return { verdicts } satisfies SkepticOutput;
};
