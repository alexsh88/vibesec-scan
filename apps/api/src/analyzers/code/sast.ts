// Claude SAST analyzer (P6). The findings come from Claude, guided by the OWASP Top 10 + VibeSec rule
// catalogue in sastPrompt.ts. The WHOLE repository is covered, risk first, under the scan's dollar
// budget (no file-count cap):
//   - deep pass (Sonnet, budget tier 1): every file triage rated relevance >= 2, or with any sink, or a
//     detected entrypoint, plus Supabase migrations / Firebase rules — ordered by risk (relevance,
//     entrypoint, number of sinks/sources);
//   - fast pass (Haiku, budget tier 2, same prompt/schema): every relevance-1 file; findings are
//     marked producedBy 'sast:llm-fast' with confidence capped at 'medium';
//   - relevance 0 (and test/example files): not SAST-reviewed (triage already read them) — recorded as
//     'not-relevant' coverage. Budget refusals are recorded as 'budget-skipped', never silent.
// Deterministic code here only (a) orders the work, (b) packs context for the model, and (c) verifies
// what the model says — every reported snippet is re-located in the real file (findings/verify.ts)
// and anything that cannot be found, or that points at another file, is dropped as a probable
// hallucination / injection.
//
// Context layout (prompt-cache friendly, see llm/prompt.ts buildRequestParts):
//   system  — SAST_SYSTEM_PROMPT (frozen per prompt version, cached across every scan)
//   context — shared per-scan pack: detected frameworks + entrypoint list (cached across the files
//             of one scan)
//   prompt  — volatile per file: the numbered target file, exported signatures of up to 4 locally
//             imported files (<= ~6k tokens), and the triage hints for the file.
//
// Rough token budget per file (estimateTokens = chars / 3.5): system ~2.6k (cache read after the
// first call), shared context 0.2–1.5k (cache read), target file ~10 tokens/line (a 300-line file
// ≈ 3–4k, capped at FILE_TOKEN_CAP), local context ≤ 6k, hints ≤ 0.4k, output typically 0.3–3k
// (max_tokens = role default 8192). So ≈ 5–15k fresh input tokens per file (≈ $0.02–0.05 on Sonnet).
//
// Caching: an optional per-file result cache (deps.cache, persisted by db/sastCacheRepo.ts) keyed by
// sha256(per-file prompt) + SAST_PROMPT_VERSION + the model id of the pass (deep or fast). The
// per-file prompt embeds the file content, its local context and its hints, so an unchanged file in
// an unchanged neighbourhood hits. Only VERIFIED issues are cached, as locations + the model's prose,
// never code: on a hit the snippet is re-read from the (byte-identical) file. Degraded results are
// never cached.

import { createHash } from 'node:crypto';
import { lstat, open } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import type { Finding } from '@vibesec/shared';
import type { IndexRepo } from '../../db/indexRepo';
import { toAppError } from '../../errors/AppError';
import type { Entrypoint, ImportEdge, IndexedFile } from '../../index/types';
import type { WorkLease } from '../../llm/budget';
import { NO_LEASE, tokensForBytes, type BudgetLanes } from '../../llm/budgetLanes';
import { formatFailureReasons, llmFailureReason, type LlmFailureReason } from '../../llm/failureReason';
import type { LlmClient, StructuredCall } from '../../llm/LlmClient';
import type { MockResponder } from '../../llm/mockTransport';
import { estimateTokens, untrustedFile, untrustedText } from '../../llm/prompt';
import type { LlmRequest } from '../../llm/transport';
import { verifyIssueLocation } from '../../findings/verify';
import type { Analyzer, AnalyzerContext, CoverageStatus } from '../types';
import {
  SAST_PROMPT_VERSION, SAST_SYSTEM_PROMPT, SAST_TASK_MARKER, SastOutputSchema, type SastIssue, type SastOutput,
} from './sastPrompt';
import { clientExposedCredentialIssues } from './config/envExposure';
import { issueToFinding } from './toFinding';
import { selectForSast, type TriageService } from './triage';
import type { FileTriage, RawCodeIssue } from './types';

export { SAST_PROMPT_VERSION, SAST_TASK_MARKER } from './sastPrompt';

const DEFAULT_CONCURRENCY = 4;
const MAX_FILE_BYTES = 256 * 1024;
/** Projection of one file review: system + shared/local context + hints, and a typical reply. */
const PROJECTED_OVERHEAD_TOKENS = 6_000;
const PROJECTED_OUTPUT_TOKENS = 1_500;
const NUL_PROBE_BYTES = 8_192;
const CHARS_PER_TOKEN = 3.5; // matches estimateTokens()
/** The target file is truncated beyond this (very large files are rare among triaged sources). */
const FILE_TOKEN_CAP = 30_000;
const LOCAL_CONTEXT_MAX_FILES = 4;
const LOCAL_CONTEXT_TOKEN_CAP = 6_000;
const LOCAL_CONTEXT_HEAD_LINES = 80;
const LOCAL_CONTEXT_MAX_SIGNATURES = 60;
const MAX_ENTRYPOINTS_IN_CONTEXT = 80;
const MAX_MANIFESTS = 10;
const PRODUCED_BY = ['sast:llm'];
const PRODUCED_BY_FAST = ['sast:llm-fast'];

const SEVERITY_RANK: Record<RawCodeIssue['severity'], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const LOWER_CONFIDENCE: Record<RawCodeIssue['confidence'], RawCodeIssue['confidence']> = { high: 'medium', medium: 'low', low: 'low' };
const CAP_MEDIUM: Record<RawCodeIssue['confidence'], RawCodeIssue['confidence']> = { high: 'medium', medium: 'medium', low: 'low' };

/** Supabase migrations and Firebase rules are not JS/TS/Python, so triage never sees them; they are
 *  reviewed anyway because "no RLS" / "allow read, write: if true" is a top vibe-coding failure. */
const POLICY_FILE_RE = /(^|\/)supabase\/migrations\/[^/]+\.sql$|(^|\/)(firestore|storage)\.rules$|(^|\/)database\.rules\.json$/i;

// --- deps ----------------------------------------------------------------------------------------

/** A verified issue as cached: its (relocated) location and the model's prose — no code snippet. */
export type CachedSastIssue = Omit<SastIssue, 'snippet'>;

/** Per-file verified-issue cache (see header). Implementations must treat keys as opaque. */
export type SastResultCache = {
  get(key: string): CachedSastIssue[] | undefined;
  set(key: string, issues: CachedSastIssue[]): void;
};

export type SastPass = 'deep' | 'fast';

export type SastAnalyzerDeps = {
  llm: Pick<LlmClient, 'structured'>;
  triage: Pick<TriageService, 'forScan'>;
  indexRepo: Pick<IndexRepo, 'imports' | 'entrypoints'>;
  /** Budget lanes: the deep pass holds a tier-1 lease projecting its remaining cost (llm/budget.ts). */
  lanes?: BudgetLanes;
  concurrency?: number;
  /** Optional result cache; `model(pass)` (current model id of that pass's tier) is part of the key. */
  cache?: { store: SastResultCache; model: (pass: SastPass) => string };
};

// --- file reading ----------------------------------------------------------------------------

/** Repo-confined utf8 read (no symlinks, no binaries); null when unreadable/unsafe. */
async function readRepoFile(repoDir: string, path: string): Promise<string | null> {
  const root = resolve(repoDir);
  const abs = resolve(join(root, ...path.split('/')));
  if (!abs.startsWith(root + sep)) return null;
  const st = await lstat(abs).catch(() => null);
  if (!st || !st.isFile()) return null;
  const handle = await open(abs, 'r').catch(() => null);
  if (!handle) return null;
  try {
    const length = Math.min(st.size, MAX_FILE_BYTES);
    const buffer = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const { bytesRead } = await handle.read(buffer, read, length - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    if (buffer.subarray(0, Math.min(NUL_PROBE_BYTES, read)).includes(0)) return null;
    return buffer.subarray(0, read).toString('utf8');
  } catch {
    return null;
  } finally {
    await handle.close();
  }
}

// --- context packs ---------------------------------------------------------------------------

function numberLines(content: string, from = 1): string {
  return content.split('\n').map((line, i) => `${i + from}: ${line}`).join('\n');
}

function capTokens(text: string, maxTokens: number): { text: string; truncated: boolean } {
  if (estimateTokens(text) <= maxTokens) return { text, truncated: false };
  return { text: text.slice(0, Math.floor(maxTokens * CHARS_PER_TOKEN)), truncated: true };
}

/** Library → label; only names from this fixed list ever reach the (trusted) shared context. */
const KNOWN_LIBS: ReadonlyArray<readonly [string, string]> = [
  ['next', 'Next.js'], ['express', 'Express'], ['fastify', 'Fastify'], ['koa', 'Koa'], ['hono', 'Hono'],
  ['@nestjs/core', 'NestJS'], ['react', 'React'], ['vite', 'Vite'], ['vue', 'Vue'], ['svelte', 'Svelte'],
  ['@remix-run/node', 'Remix'], ['@supabase/supabase-js', 'Supabase'], ['firebase', 'Firebase'], ['firebase-admin', 'Firebase Admin'],
  ['prisma', 'Prisma'], ['@prisma/client', 'Prisma'], ['mongoose', 'Mongoose'], ['sequelize', 'Sequelize'], ['drizzle-orm', 'Drizzle'],
  ['pg', 'node-postgres'], ['mysql2', 'mysql2'], ['jsonwebtoken', 'jsonwebtoken'], ['next-auth', 'NextAuth'], ['@clerk/nextjs', 'Clerk'],
  ['openai', 'OpenAI SDK'], ['@anthropic-ai/sdk', 'Anthropic SDK'], ['ai', 'Vercel AI SDK'], ['langchain', 'LangChain'],
  ['flask', 'Flask'], ['django', 'Django'], ['fastapi', 'FastAPI'], ['sqlalchemy', 'SQLAlchemy'], ['pyjwt', 'PyJWT'],
  ['requests', 'requests'], ['pyyaml', 'PyYAML'], ['anthropic', 'Anthropic SDK'],
];
const KNOWN_LIB_MAP = new Map(KNOWN_LIBS);

function depsFromManifest(path: string, text: string): string[] {
  const base = path.split('/').pop()!.toLowerCase();
  if (base === 'package.json') {
    try {
      const pkg = JSON.parse(text) as Record<string, unknown>;
      const names: string[] = [];
      for (const key of ['dependencies', 'devDependencies', 'peerDependencies']) {
        const deps = pkg[key];
        if (deps && typeof deps === 'object') names.push(...Object.keys(deps));
      }
      return names;
    } catch {
      return [];
    }
  }
  // requirements*.txt / pyproject.toml / Pipfile: crude but safe — only known names are kept anyway.
  return [...text.matchAll(/^\s*["']?([A-Za-z0-9_.-]+)/gm)].map((m) => (m[1] ?? '').toLowerCase());
}

const MANIFEST_RE = /(^|\/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile)$/;

async function buildSharedContext(ctx: AnalyzerContext, entrypoints: readonly Entrypoint[]): Promise<string> {
  const manifests = ctx.files
    .filter((f) => f.skipReason === null && MANIFEST_RE.test(f.path) && !f.path.includes('node_modules/'))
    .sort((a, b) => a.path.split('/').length - b.path.split('/').length || (a.path < b.path ? -1 : 1))
    .slice(0, MAX_MANIFESTS);
  const libs = new Set<string>();
  for (const m of manifests) {
    const text = await readRepoFile(ctx.repoDir, m.path);
    if (text === null) continue;
    for (const name of depsFromManifest(m.path, text)) {
      const label = KNOWN_LIB_MAP.get(name);
      if (label) libs.add(label);
    }
  }
  const epLines = entrypoints.slice(0, MAX_ENTRYPOINTS_IN_CONTEXT)
    .map((e) => `${e.path} (${e.kind}${e.line ? `, line ${e.line}` : ''}${e.detail ? `: ${e.detail}` : ''})`);
  if (entrypoints.length > MAX_ENTRYPOINTS_IN_CONTEXT) epLines.push(`… and ${entrypoints.length - MAX_ENTRYPOINTS_IN_CONTEXT} more`);
  return [
    'Shared repository context (same for every file in this scan):',
    `Detected frameworks/libraries: ${libs.size ? [...libs].sort().join(', ') : 'none detected'}`,
    'Known entrypoints (routes, handlers, CLIs) — paths come from the repository:',
    untrustedText('entrypoints', epLines.length ? epLines.join('\n') : '(none detected)'),
  ].join('\n');
}

const SIGNATURE_RE = /^\s*(export\s|module\.exports|exports\.\w+\s*=|def\s|async\s+def\s|class\s|@app\.|@router\.)/;

/** Exported signatures (with line numbers) of an imported file, else its first 80 lines. */
function summarizeImported(content: string): string {
  const lines = content.split('\n');
  const sigs: string[] = [];
  for (let i = 0; i < lines.length && sigs.length < LOCAL_CONTEXT_MAX_SIGNATURES; i++) {
    const line = lines[i]!;
    if (SIGNATURE_RE.test(line)) sigs.push(`${i + 1}: ${line.slice(0, 240)}`);
  }
  if (sigs.length > 0) return `[exported signatures only]\n${sigs.join('\n')}`;
  return `[first ${LOCAL_CONTEXT_HEAD_LINES} lines]\n${numberLines(lines.slice(0, LOCAL_CONTEXT_HEAD_LINES).join('\n'))}`;
}

async function buildLocalContext(ctx: AnalyzerContext, path: string, imports: readonly ImportEdge[], indexed: ReadonlySet<string>): Promise<string> {
  const targets: string[] = [];
  for (const e of imports) {
    if (e.from !== path || e.kind !== 'local' || !e.to || e.to === path || targets.includes(e.to) || !indexed.has(e.to)) continue;
    targets.push(e.to);
    if (targets.length >= LOCAL_CONTEXT_MAX_FILES) break;
  }
  const blocks: string[] = [];
  let remaining = LOCAL_CONTEXT_TOKEN_CAP;
  for (const t of targets) {
    if (remaining <= 100) break;
    const content = await readRepoFile(ctx.repoDir, t);
    if (content === null) continue;
    const { text, truncated } = capTokens(summarizeImported(content), remaining - 40);
    const block = untrustedFile(t, truncated ? `${text}\n[TRUNCATED]` : text);
    remaining -= estimateTokens(block);
    blocks.push(block);
  }
  return blocks.length ? blocks.join('\n\n') : '(no locally imported files)';
}

function hintsFor(t: FileTriage | undefined): string {
  if (!t) return '(no triage hints for this file)';
  return untrustedText('triage-hints', [
    `relevance: ${t.relevance}`,
    `sources: ${t.sources.join('; ') || 'none'}`,
    `sinks: ${t.sinks.join('; ') || 'none'}`,
    `topics: ${t.securityTopics.join(', ') || 'none'}`,
  ].join('\n'));
}

/** Deterministic per-file rule → the SAST catalogue id the model should use if it confirms the hint. */
const RULE_HINT_IDS: Record<string, SastIssue['ruleId']> = {
  'config/client-exposed-credential': 'vibesec/client-exposed-credential',
};

/**
 * Cheap deterministic pattern matches on the target file itself (today: credential-shaped env vars
 * read through a client-exposed prefix such as NEXT_PUBLIC_*). They are HINTS only — handed to Claude
 * to confirm or refute, exactly like the config analyzer's hints; a hint never becomes a finding by
 * itself. Without them the code path never saw these rules (envExposure only ran on config files).
 */
function ruleHintIssues(path: string, content: string): Array<RawCodeIssue & { sastRuleId: SastIssue['ruleId'] }> {
  return clientExposedCredentialIssues([{ path, text: content }]).flatMap((h) => {
    const sastRuleId = RULE_HINT_IDS[h.ruleId];
    return sastRuleId ? [{ ...h, sastRuleId }] : [];
  });
}

function ruleHintsFor(path: string, content: string): string {
  const lines: string[] = [];
  for (const h of ruleHintIssues(path, content)) {
    lines.push(`- line ${h.startLine}: ${h.sastRuleId} (${h.cwe ?? 'no CWE'}) — ${h.explanation} Code: ${h.snippet}`);
  }
  return lines.length ? untrustedText('rule-hints', lines.join('\n')) : '(no rule hints for this file)';
}

function buildPrompt(path: string, content: string, localContext: string, hints: string, ruleHints = '(no rule hints for this file)'): string {
  const { text, truncated } = capTokens(numberLines(content), FILE_TOKEN_CAP);
  const body = truncated ? `${text}\n[TRUNCATED: the rest of the file was not included]` : text;
  return [
    `TARGET FILE: ${JSON.stringify(path)} — report issues in this file only.`,
    untrustedFile(path, body),
    '',
    'LOCAL CONTEXT (files imported by the target; do not report issues in them):',
    localContext,
    '',
    'TRIAGE HINTS (unverified):',
    hints,
    '',
    'RULE HINTS (deterministic pattern matches in the target file — confirm or refute each against the code):',
    ruleHints,
  ].join('\n');
}

// --- concurrency -------------------------------------------------------------------------------

async function forEachLimit<T>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<void>): Promise<void> {
  let next = 0;
  let stopped = false;
  const worker = async () => {
    while (!stopped && next < items.length) {
      const i = next++;
      try {
        await fn(items[i]!, i);
      } catch (err) {
        stopped = true;
        throw err;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
}

// --- analyzer ----------------------------------------------------------------------------------

function cacheKey(prompt: string, model: string): string {
  return `${createHash('sha256').update(prompt, 'utf8').digest('hex')}:${SAST_PROMPT_VERSION}:${model}`;
}

function toRaw(issue: SastIssue, degraded: boolean): RawCodeIssue {
  const raw: RawCodeIssue = {
    ruleId: issue.ruleId, title: issue.title, severity: issue.severity,
    confidence: degraded ? LOWER_CONFIDENCE[issue.confidence] : issue.confidence,
    file: issue.file, startLine: issue.startLine, endLine: Math.max(issue.startLine, issue.endLine),
    snippet: issue.snippet, explanation: issue.explanation, impact: issue.impact, remediation: issue.remediation,
  };
  if (issue.cwe) raw.cwe = issue.cwe;
  if (issue.patch) raw.patch = issue.patch;
  return raw;
}

/** Verified issue → cache entry (location + prose; the snippet is re-read from the file on a hit). */
function toCached(issue: RawCodeIssue): CachedSastIssue {
  const cached: CachedSastIssue = {
    ruleId: issue.ruleId as SastIssue['ruleId'], title: issue.title, severity: issue.severity as SastIssue['severity'],
    confidence: issue.confidence, file: issue.file, startLine: issue.startLine, endLine: issue.endLine,
    explanation: issue.explanation, impact: issue.impact, remediation: issue.remediation,
  };
  if (issue.cwe) cached.cwe = issue.cwe;
  if (issue.patch) cached.patch = issue.patch;
  return cached;
}

function fromCached(c: CachedSastIssue, content: string): RawCodeIssue | null {
  const lines = content.split(/\r?\n/);
  const snippet = lines.slice(c.startLine - 1, c.endLine).join('\n');
  if (snippet.trim() === '') return null;
  const raw: RawCodeIssue = {
    ruleId: c.ruleId, title: c.title, severity: c.severity, confidence: c.confidence, file: c.file,
    startLine: c.startLine, endLine: c.endLine, snippet, explanation: c.explanation, impact: c.impact, remediation: c.remediation,
  };
  if (c.cwe) raw.cwe = c.cwe;
  if (c.patch) raw.patch = c.patch;
  return raw;
}

type WorkItem = { path: string; pass: SastPass };

/**
 * Risk-ordered SAST plan over the whole repo (see header): deep = relevance-3 files, then
 * Supabase/Firebase policy files, then the rest of the deep set; fast = relevance-1 files;
 * notRelevant = relevance 0 and test/example files (with their reason recorded as coverage).
 */
function planFiles(
  ctx: AnalyzerContext, triaged: Map<string, FileTriage>, entrypoints: ReadonlySet<string>,
): { deep: string[]; fast: string[]; notRelevant: string[]; zeroRelevance: string[] } {
  const indexed = ctx.files.filter((f) => f.skipReason === null);
  const isTestish = (f: IndexedFile) => f.tags.includes('test') || f.tags.includes('example');
  const usable = new Set(indexed.filter((f) => !isTestish(f)).map((f) => f.path));
  const notRelevant: string[] = indexed.filter((f) => isTestish(f) && triaged.has(f.path)).map((f) => f.path);

  const deepSet = new Set(selectForSast({ files: triaged, skipped: [], warnings: [] }, entrypoints).filter((p) => usable.has(p)));
  const risk = (p: string): number[] => {
    const t = triaged.get(p);
    return [t?.relevance ?? 0, entrypoints.has(p) ? 1 : 0, t?.sinks.length ?? 0, t?.sources.length ?? 0];
  };
  const byRisk = (a: string, b: string): number => {
    const ra = risk(a);
    const rb = risk(b);
    for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return rb[i]! - ra[i]!;
    return a < b ? -1 : a > b ? 1 : 0;
  };
  const ordered = [...deepSet].sort(byRisk);
  const top = ordered.filter((p) => triaged.get(p)?.relevance === 3);
  const rest = ordered.filter((p) => triaged.get(p)?.relevance !== 3);
  const policy = indexed
    .filter((f) => usable.has(f.path) && POLICY_FILE_RE.test(f.path) && !triaged.has(f.path))
    .map((f) => f.path)
    .sort();

  const fast: string[] = [];
  const zeroRelevance: string[] = [];
  for (const [path, t] of triaged) {
    if (!usable.has(path) || deepSet.has(path)) continue;
    if (t.relevance >= 1) fast.push(path);
    else zeroRelevance.push(path);
  }
  fast.sort(byRisk);
  return { deep: [...top, ...policy, ...rest], fast, notRelevant: [...notRelevant, ...zeroRelevance].sort(), zeroRelevance: zeroRelevance.sort() };
}

export function createSastAnalyzer(deps: SastAnalyzerDeps): Analyzer {
  const concurrency = deps.concurrency ?? DEFAULT_CONCURRENCY;

  return {
    id: 'sast',
    version: '2',
    category: 'sast',

    async run(ctx: AnalyzerContext): Promise<Finding[]> {
      const checkAbort = () => {
        if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      };
      checkAbort();
      // Opened before the first await, so lower budget tiers wait until the deep pass declares its demand.
      const lease = deps.lanes?.open(ctx.scanId) ?? NO_LEASE;
      try {
        return await review(ctx, checkAbort, lease);
      } finally {
        lease.close();
      }
    },
  };

  async function review(ctx: AnalyzerContext, checkAbort: () => void, lease: WorkLease): Promise<Finding[]> {
    const record = (path: string, status: CoverageStatus) => ctx.recordCoverage?.('sast', path, status);
    const triage = await deps.triage.forScan(ctx);
    checkAbort();
    const entrypoints = deps.indexRepo.entrypoints(ctx.scanId);
    const imports = deps.indexRepo.imports(ctx.scanId);
    const entrySet = new Set(entrypoints.map((e) => e.path));

    const plan = planFiles(ctx, triage.files, entrySet);
    // A deterministic rule hint overrides a relevance-0 triage verdict: the file gets a deep review so
    // Claude can confirm or refute the hint (otherwise the hint would never reach a model).
    const promoted = new Set<string>();
    for (const p of plan.zeroRelevance) {
      const content = await readRepoFile(ctx.repoDir, p);
      if (content !== null && ruleHintIssues(p, content).length > 0) promoted.add(p);
    }
    plan.deep.push(...promoted);
    for (const p of plan.notRelevant) if (!promoted.has(p)) record(p, 'not-relevant');

    // Tier-1 demand projection for the deep pass, shrinking as files finish (see llm/budget.ts).
    const sizeOf = new Map(ctx.files.map((f) => [f.path, f.size]));
    const projectedUsd = (path: string) => deps.lanes?.estimateUsd(
      'deep', tokensForBytes(Math.min(sizeOf.get(path) ?? 0, MAX_FILE_BYTES)) + PROJECTED_OVERHEAD_TOKENS, PROJECTED_OUTPUT_TOKENS,
    ) ?? 0;
    let remainingUsd = plan.deep.reduce((sum, p) => sum + projectedUsd(p), 0);
    let deepLeft = plan.deep.length;
    if (deepLeft === 0) lease.close();
    else lease.project(remainingUsd);
    const deepDone = (path: string) => {
      remainingUsd -= projectedUsd(path);
      if (--deepLeft === 0) lease.close();
      else lease.project(remainingUsd);
    };

    const work: WorkItem[] = [...plan.deep.map((path) => ({ path, pass: 'deep' as const })), ...plan.fast.map((path) => ({ path, pass: 'fast' as const }))];
    if (work.length === 0) return [];

    const indexed = new Set(ctx.files.filter((f) => f.skipReason === null).map((f) => f.path));
    const sharedContext = await buildSharedContext(ctx, entrypoints);
    ctx.touch();

    const byFingerprint = new Map<string, Finding>();
    let dropped = 0;
    const failures = new Map<LlmFailureReason, number>();
    const exhausted: Record<SastPass, boolean> = { deep: false, fast: false };
    let done = 0;

    const keep = (issue: RawCodeIssue, pass: SastPass) => {
      const finding = issueToFinding(ctx, 'sast', issue, pass === 'deep' ? PRODUCED_BY : PRODUCED_BY_FAST);
      const existing = byFingerprint.get(finding.fingerprint);
      if (!existing || SEVERITY_RANK[finding.severity] < SEVERITY_RANK[existing.severity]) byFingerprint.set(finding.fingerprint, finding);
    };

    // Reports against every work item (cached/budget-skipped/failed included), so the final call always
    // reaches done === work.length — `done` above only counts actual reviews, for the free-text message.
    let processed = 0;
    const reviewOne = async ({ path, pass }: WorkItem): Promise<void> => {
      try {
        checkAbort();
        const content = await readRepoFile(ctx.repoDir, path);
        if (content === null) { record(path, 'failed'); return; }
        const prompt = buildPrompt(path, content, await buildLocalContext(ctx, path, imports, indexed), hintsFor(triage.files.get(path)), ruleHintsFor(path, content));

        const key = deps.cache ? cacheKey(prompt, deps.cache.model(pass)) : null;
        const cached = key ? deps.cache!.store.get(key) : undefined;
        if (cached) {
          for (const c of cached) {
            const raw = fromCached(c, content);
            const outcome = raw ? verifyIssueLocation(raw, content) : null; // re-clips exactly like the first run
            if (outcome && outcome.status !== 'dropped') keep(outcome.issue, pass);
          }
          record(path, 'cached');
          return;
        }
        if (exhausted[pass] || (pass === 'fast' && exhausted.deep)) { record(path, 'budget-skipped'); return; }

        const call: StructuredCall<SastOutput> = {
          scanId: ctx.scanId, analyzer: 'sast', purpose: pass === 'deep' ? 'sast-file' : 'sast-file-fast', promptVersion: SAST_PROMPT_VERSION,
          role: pass, system: SAST_SYSTEM_PROMPT, context: sharedContext, prompt,
          schema: SastOutputSchema, signal: ctx.signal, onActivity: ctx.touch,
          ...(pass === 'deep' ? { effort: 'medium' as const } : { tier: 2 as const }),
        };
        let issues: SastIssue[];
        let degraded = false;
        try {
          const result = await deps.llm.structured(call);
          issues = result.output.issues;
          degraded = result.degraded;
        } catch (raw) {
          const err = toAppError(raw);
          if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
          if (err.kind === 'budget') {
            exhausted[pass] = true;
            record(path, 'budget-skipped');
            return;
          }
          record(path, 'failed');
          const reason = llmFailureReason(err);
          failures.set(reason, (failures.get(reason) ?? 0) + 1);
          return;
        } finally {
          ctx.touch();
        }

        const verified: RawCodeIssue[] = [];
        for (const issue of issues) {
          if (issue.file !== path) { dropped++; continue; }
          const raw = toRaw(issue, degraded);
          if (pass === 'fast') raw.confidence = CAP_MEDIUM[raw.confidence];
          const outcome = verifyIssueLocation(raw, content);
          if (outcome.status === 'dropped') { dropped++; continue; }
          verified.push(outcome.issue);
          keep(outcome.issue, pass);
        }
        if (key && !degraded) deps.cache!.store.set(key, verified.map(toCached));
        record(path, pass === 'deep' ? 'reviewed' : 'reviewed-fast');
        done++;
        ctx.progress(`SAST: reviewed ${done}/${work.length} files`);
      } finally {
        processed++;
        ctx.reportProgress?.(processed, work.length);
      }
    };

    await forEachLimit(work, concurrency, async (item) => {
      try {
        await reviewOne(item);
      } finally {
        if (item.pass === 'deep') deepDone(item.path);
      }
    });

    if (failures.size > 0) {
      const failed = [...failures.values()].reduce((a, b) => a + b, 0);
      ctx.warn('SAST_PARTIAL', `AI code review failed for ${failed} file(s) (${formatFailureReasons(failures)}); those files have no SAST findings`);
    }
    if (dropped > 0) {
      ctx.warn('SAST_UNVERIFIED_DROPPED', `${dropped} AI-reported issue(s) were dropped because the cited code could not be found in the reviewed file`);
    }
    return [...byFingerprint.values()];
  }
}

// --- mock responder ------------------------------------------------------------------------------

type MockRule = { re: RegExp; ruleId: SastIssue['ruleId']; cwe: string; severity: SastIssue['severity']; title: string };

const MOCK_RULES: readonly MockRule[] = [
  { re: /\.query\s*\(\s*(?:['"][^'"]*['"]\s*\+|`[^`]*\$\{)/, ruleId: 'sast/sql-injection', cwe: 'CWE-89', severity: 'high', title: 'SQL query built by string concatenation' },
  { re: /\b(?:exec|execSync)\s*\(\s*(?:[A-Za-z_$][\w$.]*\s*[,)]|`[^`]*\$\{|['"][^'"]*['"]\s*\+)/, ruleId: 'sast/command-injection', cwe: 'CWE-78', severity: 'critical', title: 'Shell command built from a variable' },
  { re: /(?:^|[^\w.])eval\s*\(/, ruleId: 'sast/code-injection', cwe: 'CWE-95', severity: 'high', title: 'Dynamic code evaluation' },
  { re: /\.innerHTML\s*=|dangerouslySetInnerHTML/, ruleId: 'sast/xss', cwe: 'CWE-79', severity: 'medium', title: 'Unescaped HTML rendering' },
  { re: /\bres\.redirect\s*\(\s*req\./, ruleId: 'sast/open-redirect', cwe: 'CWE-601', severity: 'medium', title: 'Redirect to a request-controlled location' },
  { re: /\b(?:requests|axios)\.get\s*\(\s*(?:req|request)\b/, ruleId: 'sast/ssrf', cwe: 'CWE-918', severity: 'high', title: 'Outbound request to a request-controlled URL' },
  { re: /\byaml\.load\s*\((?![^)]*SafeLoader)/, ruleId: 'sast/unsafe-deserialization', cwe: 'CWE-502', severity: 'high', title: 'Unsafe YAML deserialization' },
  { re: /\bpickle\.loads?\s*\(/, ruleId: 'sast/unsafe-deserialization', cwe: 'CWE-502', severity: 'high', title: 'Unsafe pickle deserialization' },
  { re: /\bmd5\b/i, ruleId: 'sast/weak-crypto', cwe: 'CWE-327', severity: 'low', title: 'Weak hash algorithm (MD5)' },
];

const TARGET_BLOCK_RE = /<untrusted_file\s+path="([^"]*)">\n([\s\S]*?)\n<\/untrusted_file>/;

function unescapeAttr(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

/**
 * Deterministic stand-in for Claude in mock mode: answers only SAST_TASK_MARKER requests, reads the
 * TARGET file (the first <untrusted_file> block of the user turn — the shared context only holds
 * <untrusted_text>), and reports one issue per line matching an obvious pattern, with the exact line
 * text as snippet so the issues survive verification.
 */
export const sastMockResponder: MockResponder = (req: LlmRequest) => {
  const system = req.system.map((b) => b.text).join('\n');
  if (!system.includes(SAST_TASK_MARKER)) return undefined;
  const user = req.messages
    .flatMap((m) => (Array.isArray(m.content) ? m.content : []))
    .flatMap((b) => (b.type === 'text' ? [b.text] : []))
    .join('\n');
  const m = TARGET_BLOCK_RE.exec(user);
  if (!m) return { issues: [] } satisfies SastOutput;
  const file = unescapeAttr(m[1] ?? '');
  const issues: SastIssue[] = [];
  const codeAt = new Map<number, string>();
  for (const numbered of (m[2] ?? '').split('\n')) {
    const lm = /^(\d+): (.*)$/.exec(numbered.replace(/\r$/, ''));
    if (lm) codeAt.set(Number(lm[1]), lm[2] ?? '');
  }
  // Rule hints: the mock "confirms" every client-exposed-credential hint whose cited line exists.
  const hintBlock = /<untrusted_text source="rule-hints">\n([\s\S]*?)\n<\/untrusted_text>/.exec(user);
  for (const h of (hintBlock?.[1] ?? '').matchAll(/^- line (\d+): (vibesec\/client-exposed-credential) /gm)) {
    const line = Number(h[1]);
    const code = codeAt.get(line);
    if (!code || code.trim() === '') continue;
    issues.push({
      ruleId: 'vibesec/client-exposed-credential', title: 'Credential exposed to the client bundle', cwe: 'CWE-200', severity: 'high', confidence: 'medium',
      file, startLine: line, endLine: line, snippet: code,
      explanation: `[mock] Confirmed rule hint: line ${line} reads a credential-shaped env var through a client-exposed prefix.`,
      impact: '[mock] The value is inlined into the browser bundle where anyone can read it.',
      remediation: '[mock] Read it only on the server under a non-public name, and rotate it.',
    });
  }
  for (const numbered of (m[2] ?? '').split('\n')) {
    const lm = /^(\d+): (.*)$/.exec(numbered.replace(/\r$/, ''));
    if (!lm) continue;
    const line = Number(lm[1]);
    const code = lm[2] ?? '';
    if (code.trim() === '') continue;
    const rule = MOCK_RULES.find((r) => r.re.test(code));
    if (!rule) continue;
    issues.push({
      ruleId: rule.ruleId, title: rule.title, cwe: rule.cwe, severity: rule.severity, confidence: 'medium',
      file, startLine: line, endLine: line, snippet: code,
      explanation: `[mock] Line ${line} matches a known-dangerous pattern (${rule.ruleId}).`,
      impact: '[mock] An attacker controlling the input may abuse this operation.',
      remediation: '[mock] Validate/escape the input or use a safe API (parameterized queries, execFile with an argument array, safe loaders).',
    });
    if (issues.length >= 15) break;
  }
  return { issues } satisfies SastOutput;
};
