// Claude SAST analyzer (P6). The findings come from Claude: one Sonnet review per security-relevant
// file, guided by the OWASP Top 10 + VibeSec rule catalogue in sastPrompt.ts. Deterministic code
// here only (a) picks which files deserve a review (Haiku triage + entrypoints + Supabase/Firebase
// policy files), (b) packs context for the model, and (c) verifies what the model says — every
// reported snippet is re-located in the real file (findings/verify.ts) and anything that cannot be
// found, or that points at another file, is dropped as a probable hallucination / injection.
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
// (max_tokens = role default 8192). So ≈ 5–15k fresh input tokens per file; at maxFiles = 60 a full
// scan is ≈ 0.4–0.9M input tokens.
//
// Caching: an optional per-file result cache (deps.cache) keyed by sha256(per-file prompt) +
// SAST_PROMPT_VERSION + model. The per-file prompt embeds the file content, its local context and
// its hints, so an unchanged file in an unchanged neighbourhood hits; raw model issues are cached
// (verification always re-runs). TODO(P7): back it with a sast_cache table (migration + repo, same
// shape as triage_cache) — deliberately not added here to avoid a migration-number collision with
// the other P6 work in flight.

import { createHash } from 'node:crypto';
import { lstat, open } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import type { Finding } from '@vibesec/shared';
import type { IndexRepo } from '../../db/indexRepo';
import { toAppError } from '../../errors/AppError';
import type { Entrypoint, ImportEdge, IndexedFile } from '../../index/types';
import type { BudgetTracker } from '../../llm/budget';
import type { LlmClient, StructuredCall } from '../../llm/LlmClient';
import type { MockResponder } from '../../llm/mockTransport';
import { estimateTokens, untrustedFile, untrustedText } from '../../llm/prompt';
import type { LlmRequest } from '../../llm/transport';
import { verifyIssueLocation } from '../../findings/verify';
import type { Analyzer, AnalyzerContext } from '../types';
import {
  SAST_PROMPT_VERSION, SAST_SYSTEM_PROMPT, SAST_TASK_MARKER, SastOutputSchema, type SastIssue, type SastOutput,
} from './sastPrompt';
import { issueToFinding } from './toFinding';
import { selectForSast, type TriageService } from './triage';
import type { FileTriage, RawCodeIssue } from './types';

export { SAST_PROMPT_VERSION, SAST_TASK_MARKER } from './sastPrompt';

const DEFAULT_MAX_FILES = 60;
const DEFAULT_CONCURRENCY = 4;
const BUDGET_RESTRICT_RATIO = 0.8;
const MAX_FILE_BYTES = 256 * 1024;
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

const SEVERITY_RANK: Record<RawCodeIssue['severity'], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const LOWER_CONFIDENCE: Record<RawCodeIssue['confidence'], RawCodeIssue['confidence']> = { high: 'medium', medium: 'low', low: 'low' };

/** Supabase migrations and Firebase rules are not JS/TS/Python, so triage never sees them; they are
 *  reviewed anyway because "no RLS" / "allow read, write: if true" is a top vibe-coding failure. */
const POLICY_FILE_RE = /(^|\/)supabase\/migrations\/[^/]+\.sql$|(^|\/)(firestore|storage)\.rules$|(^|\/)database\.rules\.json$/i;

// --- deps ----------------------------------------------------------------------------------------

/** Per-file raw-issue cache (see header). Implementations must treat keys as opaque. */
export type SastResultCache = {
  get(key: string): SastIssue[] | undefined;
  set(key: string, issues: SastIssue[]): void;
};

export type SastAnalyzerDeps = {
  llm: Pick<LlmClient, 'structured'>;
  triage: Pick<TriageService, 'forScan'>;
  indexRepo: Pick<IndexRepo, 'imports' | 'entrypoints'>;
  /** Committed-spend ratio of the scan budget; at >= 0.8 only relevance-3 files are reviewed. */
  budget?: Pick<BudgetTracker, 'ratio'>;
  maxFiles?: number;
  concurrency?: number;
  /** Optional result cache; `model` (current deep-tier model id) is part of the key. */
  cache?: { store: SastResultCache; model: () => string };
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

function buildPrompt(path: string, content: string, localContext: string, hints: string): string {
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

/** Orders candidates: relevance-3 triaged files, then policy files (RLS/rules), then the rest. */
function selectFiles(
  ctx: AnalyzerContext, triaged: Map<string, FileTriage>, triageOrder: readonly string[], restrict: boolean,
): string[] {
  const usable = new Set(ctx.files.filter((f) => f.skipReason === null && !f.tags.includes('test') && !f.tags.includes('example')).map((f) => f.path));
  const fromTriage = triageOrder.filter((p) => usable.has(p) && (!restrict || triaged.get(p)?.relevance === 3));
  const top = fromTriage.filter((p) => triaged.get(p)?.relevance === 3);
  const rest = fromTriage.filter((p) => triaged.get(p)?.relevance !== 3);
  const policy = ctx.files
    .filter((f: IndexedFile) => usable.has(f.path) && POLICY_FILE_RE.test(f.path) && !triaged.has(f.path))
    .map((f) => f.path)
    .sort();
  return [...top, ...policy, ...rest];
}

export function createSastAnalyzer(deps: SastAnalyzerDeps): Analyzer {
  const maxFiles = deps.maxFiles ?? DEFAULT_MAX_FILES;
  const concurrency = deps.concurrency ?? DEFAULT_CONCURRENCY;

  return {
    id: 'sast',
    version: '1',
    category: 'sast',

    async run(ctx: AnalyzerContext): Promise<Finding[]> {
      const checkAbort = () => {
        if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      };
      checkAbort();

      const triage = await deps.triage.forScan(ctx);
      checkAbort();
      const entrypoints = deps.indexRepo.entrypoints(ctx.scanId);
      const imports = deps.indexRepo.imports(ctx.scanId);
      const entrySet = new Set(entrypoints.map((e) => e.path));

      const restrict = (deps.budget?.ratio(ctx.scanId) ?? 0) >= BUDGET_RESTRICT_RATIO;
      if (restrict) ctx.warn('SAST_BUDGET_RESTRICTED', 'AI budget is mostly spent; the SAST review was limited to the most security-critical files');
      const candidates = selectFiles(ctx, triage.files, selectForSast(triage, entrySet), restrict);
      const selected = candidates.slice(0, maxFiles);
      if (candidates.length > maxFiles) {
        ctx.warn('SAST_FILE_LIMIT', `AI code review was limited to ${maxFiles} files; ${candidates.length - maxFiles} additional candidate file(s) were not reviewed`);
      }
      if (selected.length === 0) return [];

      const indexed = new Set(ctx.files.filter((f) => f.skipReason === null).map((f) => f.path));
      const sharedContext = await buildSharedContext(ctx, entrypoints);
      ctx.touch();

      const byFingerprint = new Map<string, Finding>();
      let dropped = 0;
      let warnedPartial = false;
      let budgetExhausted = false;
      let done = 0;

      await forEachLimit(selected, concurrency, async (path) => {
        checkAbort();
        if (budgetExhausted) return;
        const content = await readRepoFile(ctx.repoDir, path);
        if (content === null) return;
        const prompt = buildPrompt(path, content, await buildLocalContext(ctx, path, imports, indexed), hintsFor(triage.files.get(path)));

        let issues: SastIssue[];
        let degraded = false;
        const key = deps.cache ? cacheKey(prompt, deps.cache.model()) : null;
        const cached = key ? deps.cache!.store.get(key) : undefined;
        if (cached) {
          issues = cached;
        } else {
          const call: StructuredCall<SastOutput> = {
            scanId: ctx.scanId, analyzer: 'sast', purpose: 'sast-file', promptVersion: SAST_PROMPT_VERSION,
            role: 'deep', effort: 'medium', system: SAST_SYSTEM_PROMPT, context: sharedContext, prompt,
            schema: SastOutputSchema, signal: ctx.signal, onActivity: ctx.touch,
          };
          try {
            const result = await deps.llm.structured(call);
            issues = result.output.issues;
            degraded = result.degraded;
            if (key && !degraded) deps.cache!.store.set(key, issues);
          } catch (raw) {
            const err = toAppError(raw);
            if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
            if (err.kind === 'budget') {
              if (!budgetExhausted) {
                budgetExhausted = true;
                ctx.warn('SAST_BUDGET_EXHAUSTED', 'The AI budget ran out during the SAST review; remaining files were not reviewed');
              }
              return;
            }
            if (!warnedPartial) {
              warnedPartial = true;
              ctx.warn('SAST_PARTIAL', 'AI code review failed for one or more files; those files have no SAST findings');
            }
            return;
          } finally {
            ctx.touch();
          }
        }

        for (const issue of issues) {
          if (issue.file !== path) { dropped++; continue; }
          const outcome = verifyIssueLocation(toRaw(issue, degraded), content);
          if (outcome.status === 'dropped') { dropped++; continue; }
          const finding = issueToFinding(ctx, 'sast', outcome.issue, PRODUCED_BY);
          const existing = byFingerprint.get(finding.fingerprint);
          if (!existing || SEVERITY_RANK[finding.severity] < SEVERITY_RANK[existing.severity]) byFingerprint.set(finding.fingerprint, finding);
        }
        done++;
        ctx.progress(`SAST: reviewed ${done}/${selected.length} files`);
      });

      if (dropped > 0) {
        ctx.warn('SAST_UNVERIFIED_DROPPED', `${dropped} AI-reported issue(s) were dropped because the cited code could not be found in the reviewed file`);
      }
      return [...byFingerprint.values()];
    },
  };
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
