// Optional LLM (Sonnet, role 'deep') upgrade of a deterministic 'imported' verdict to 'reachable':
// given the advisory text and the app's call sites of the vulnerable package, does the app actually
// exercise the vulnerable code path? Pattern follows credentials/fpFilter.ts: batching, fail-open
// (any non-cancellation failure keeps the deterministic result), injection-safe item tags, and a
// deterministic mock responder keyed by a task marker in the system prompt.
//
// The judge can only UPGRADE ('imported' → 'reachable'); it never downgrades anything.

import { z } from 'zod';
import { toAppError } from '../../errors/AppError';
import type { LlmClient, StructuredCall } from '../../llm/LlmClient';
import type { MockResponder } from '../../llm/mockTransport';
import { untrustedText } from '../../llm/prompt';
import type { LlmRequest } from '../../llm/transport';
import type { ReachabilityVerdict } from './reachability';

export const REACHABILITY_JUDGE_PROMPT_VERSION = 'dep-reach-v1';
/** Appears verbatim in the system prompt; `dependencyReachabilityMockResponder` keys on it. */
export const REACHABILITY_JUDGE_TASK_MARKER = 'Task: dependency-reachability-judge';

const BATCH_SIZE = 5;
const DEFAULT_MAX_ITEMS = 30;
const MAX_CALL_SITES = 8;
const MAX_DETAILS = 1500;
const MAX_CODE = 300;

export type JudgeAdvisory = { id: string; summary: string; details: string; affectedSymbols: string[]; cvss?: number | null };
export type JudgeCallSite = { file: string; line: number; code: string };
export type JudgeItem = { key: string; package: string; version: string; advisories: JudgeAdvisory[]; callSites: JudgeCallSite[] };

export type ReachabilityJudgement = {
  reachable: boolean;
  confidence: 'high' | 'medium' | 'low';
  reason: string;
  matchedCallSite?: { file: string; line: number };
  /** True when this judgement upgrades the item to 'reachable' (reachable && confidence !== 'low'). */
  upgrade: boolean;
};

const ResultSchema = z.object({
  key: z.string(),
  reachable: z.boolean(),
  confidence: z.enum(['high', 'medium', 'low']),
  reason: z.string().max(400),
  matchedCallSite: z.object({ file: z.string(), line: z.number().int() }).optional(),
});
const OutputSchema = z.object({ results: z.array(ResultSchema) });
type JudgeOutput = z.infer<typeof OutputSchema>;

const SYSTEM_PROMPT = [
  REACHABILITY_JUDGE_TASK_MARKER,
  '',
  'You are assessing whether known vulnerabilities in a third-party package are reachable from the',
  'application that depends on it. Each <dependency> block below gives the package, its advisories',
  '(id, the symbols OSV lists as affected, and the advisory text) and the call sites where the',
  'application code uses the package (file, line and the code on that line).',
  '',
  'For each dependency decide whether at least one call site plausibly invokes the vulnerable',
  'function, method or code path described by an advisory. Only answer reachable=true when a',
  'specific call site supports it, and then name it in matchedCallSite (one of the call sites you',
  'were given). Use confidence "high" when the call site clearly calls an affected symbol with',
  'attacker-influenced input, "medium" when it calls the affected API but the input is unclear, and',
  '"low" when you are guessing. Merely importing the package is NOT enough.',
  '',
  'Return exactly one result per dependency key you were given, and no results for keys you were not',
  'given. Keep each reason under 400 characters.',
].join('\n');

function escapeAttr(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function unescapeAttr(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

const ITEM_TAG_RE = /<(\/?)\s*(dependency|advisory|call_site)\b/gi;

/** Escapes our own structural tags inside untrusted text so it can never forge a sibling block. */
function neutralizeItemTags(text: string): string {
  return text.replace(ITEM_TAG_RE, (_m, slash: string, tag: string) => `&lt;${slash}${tag}`);
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function itemBlock(item: JudgeItem): string {
  const lines = [`<dependency key="${escapeAttr(item.key)}" package="${escapeAttr(item.package)}" version="${escapeAttr(item.version)}">`];
  for (const a of item.advisories) {
    lines.push(`<advisory id="${escapeAttr(a.id)}" affectedSymbols="${escapeAttr(a.affectedSymbols.join(','))}">`);
    lines.push(untrustedText(`advisory ${a.id}`, neutralizeItemTags(`${a.summary}\n\n${truncate(a.details, MAX_DETAILS)}`)));
    lines.push('</advisory>');
  }
  for (const c of item.callSites.slice(0, MAX_CALL_SITES)) {
    lines.push(`<call_site file="${escapeAttr(c.file)}" line="${c.line}">`);
    lines.push(untrustedText(`${c.file}:${c.line}`, neutralizeItemTags(truncate(c.code, MAX_CODE))));
    lines.push('</call_site>');
  }
  lines.push('</dependency>');
  return lines.join('\n');
}

function maxCvss(item: JudgeItem): number {
  return item.advisories.reduce((m, a) => Math.max(m, a.cvss ?? 0), 0);
}

/**
 * Asks the model whether each item's vulnerable code is exercised by its call sites. Items without
 * call sites are skipped; at most `maxItems` (default 30) are judged, prioritized by max advisory
 * CVSS (ties by key). Batches of ≤ 5. Fails open: a failed batch yields no judgements (the caller
 * keeps 'imported'); `warn('DEPENDENCY_REACHABILITY_JUDGE_UNAVAILABLE', …)` fires at most once.
 * Cancellation is rethrown.
 */
export async function judgeReachability(
  llm: Pick<LlmClient, 'structured'>,
  scanId: string,
  items: readonly JudgeItem[],
  signal: AbortSignal,
  opts: { maxItems?: number; warn?: (code: string, message: string) => void; onActivity?: () => void } = {},
): Promise<Map<string, ReachabilityJudgement>> {
  const maxItems = opts.maxItems ?? DEFAULT_MAX_ITEMS;
  const eligible = items
    .filter((i) => i.callSites.length > 0)
    .sort((a, b) => maxCvss(b) - maxCvss(a) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .slice(0, Math.max(0, maxItems));
  const out = new Map<string, ReachabilityJudgement>();
  let warned = false;

  for (let i = 0; i < eligible.length; i += BATCH_SIZE) {
    const batch = eligible.slice(i, i + BATCH_SIZE);
    const byKey = new Map(batch.map((it) => [it.key, it]));
    const call: StructuredCall<JudgeOutput> = {
      scanId, analyzer: 'dependencies', purpose: 'reachability-judge', promptVersion: REACHABILITY_JUDGE_PROMPT_VERSION,
      role: 'deep', system: SYSTEM_PROMPT, prompt: batch.map(itemBlock).join('\n\n'), schema: OutputSchema, signal,
      ...(opts.onActivity ? { onActivity: opts.onActivity } : {}),
    };
    try {
      const result = await llm.structured(call);
      for (const r of result.output.results) {
        const item = byKey.get(r.key);
        if (!item || out.has(r.key)) continue;
        const site = r.matchedCallSite && item.callSites.slice(0, MAX_CALL_SITES).some((c) => c.file === r.matchedCallSite!.file && c.line === r.matchedCallSite!.line)
          ? { file: r.matchedCallSite.file, line: r.matchedCallSite.line } : undefined;
        out.set(r.key, {
          reachable: r.reachable, confidence: r.confidence, reason: r.reason,
          ...(site ? { matchedCallSite: site } : {}),
          upgrade: r.reachable && r.confidence !== 'low',
        });
      }
    } catch (raw) {
      const err = toAppError(raw);
      if (err.kind === 'cancelled' || signal.aborted) throw err;
      if (!warned) {
        opts.warn?.('DEPENDENCY_REACHABILITY_JUDGE_UNAVAILABLE', 'AI reachability judgement was skipped for some vulnerable dependencies');
        warned = true;
      }
    }
  }
  return out;
}

/** Applies a judgement to a deterministic verdict: only 'imported' → 'reachable' upgrades happen. */
export function applyJudgement(verdict: ReachabilityVerdict, j: ReachabilityJudgement | undefined): ReachabilityVerdict {
  if (!j || !j.upgrade || verdict.reachability !== 'imported') return verdict;
  const site = j.matchedCallSite;
  const evidence = site
    ? [{ file: site.file, line: site.line, symbol: null }, ...verdict.evidence.filter((e) => e.file !== site.file || e.line !== site.line)].slice(0, 10)
    : verdict.evidence;
  return { ...verdict, reachability: 'reachable', evidence, reason: `AI review (${j.confidence} confidence): ${j.reason}` };
}

// --- mock responder ----------------------------------------------------------------------------

const DEP_BLOCK_RE = /<dependency\s+([^>]*)>([\s\S]*?)<\/dependency>/g;
const ADVISORY_RE = /<advisory\s+([^>]*)>([\s\S]*?)<\/advisory>/g;
const CALL_SITE_RE = /<call_site\s+([^>]*)>([\s\S]*?)<\/call_site>/g;
const ATTR_RE = /([\w-]+)="([^"]*)"/g;

function parseAttrs(text: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const m of text.matchAll(ATTR_RE)) if (m[1] && m[2] !== undefined) attrs[m[1]] = unescapeAttr(m[2]);
  return attrs;
}

/** Function names an advisory summary mentions: `name()` or backticked identifiers. */
function mentionedFunctions(text: string): string[] {
  const names = new Set<string>();
  for (const m of text.matchAll(/([A-Za-z_$][\w$.]*)\s*\(\)/g)) if (m[1]) names.add(m[1]);
  for (const m of text.matchAll(/`([A-Za-z_$][\w$.]*)`/g)) if (m[1]) names.add(m[1]);
  return [...names];
}

function codeHas(code: string, symbol: string): boolean {
  const s = symbol.slice(symbol.lastIndexOf('.') + 1);
  if (!s) return false;
  return new RegExp(`(^|[^\\w$])${s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^\\w$]|$)`).test(code);
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
 * Deterministic stand-in for the model (MockTransport). Answers only requests carrying
 * REACHABILITY_JUDGE_TASK_MARKER. reachable=true (confidence 'medium') iff some call site's code
 * contains one of the advisory's affectedSymbols (or a function name the advisory summary mentions)
 * as an identifier; the first such call site is reported as matchedCallSite.
 */
export const dependencyReachabilityMockResponder: MockResponder = (req: LlmRequest) => {
  const { system, user } = textOfRequest(req);
  if (!system.includes(REACHABILITY_JUDGE_TASK_MARKER)) return undefined;
  const results: JudgeOutput['results'] = [];
  for (const dep of user.matchAll(DEP_BLOCK_RE)) {
    const key = parseAttrs(dep[1] ?? '').key;
    if (!key) continue;
    const body = dep[2] ?? '';
    const symbols = new Set<string>();
    for (const a of body.matchAll(ADVISORY_RE)) {
      for (const s of (parseAttrs(a[1] ?? '').affectedSymbols ?? '').split(',')) if (s) symbols.add(s);
      const summary = (a[2] ?? '').split('\n\n')[0] ?? '';
      for (const s of mentionedFunctions(summary)) symbols.add(s);
    }
    let match: { file: string; line: number; symbol: string } | null = null;
    for (const c of body.matchAll(CALL_SITE_RE)) {
      const attrs = parseAttrs(c[1] ?? '');
      const code = c[2] ?? '';
      const sym = [...symbols].find((s) => codeHas(code, s));
      if (sym && attrs.file !== undefined) {
        match = { file: attrs.file, line: Number(attrs.line), symbol: sym };
        break;
      }
    }
    results.push(match
      ? { key, reachable: true, confidence: 'medium', reason: `Call site uses ${match.symbol} (mock heuristic)`, matchedCallSite: { file: match.file, line: match.line } }
      : { key, reachable: false, confidence: 'medium', reason: 'No call site uses an affected symbol (mock heuristic)' });
  }
  return { results };
};
