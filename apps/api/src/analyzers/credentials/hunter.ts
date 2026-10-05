// The Claude credential hunter (P6).
//
// Purpose: the regex/entropy scanner in ./rules only recognizes credentials that look like
// *something* (a known provider prefix, a quoted high-entropy literal, a connection-string
// password, ...). It cannot recognize a custom/internal token format, a credential split across
// string concatenations, a base64/hex-encoded value, a secret mentioned only in a comment or doc,
// a hardcoded encryption key/IV/JWT-signing secret with no "secret"-ish variable name, or a
// password buried inside a connection *object* (as opposed to a connection *string*). Those need
// a reader that understands code, not a pattern.
//
// DELIBERATE, DOCUMENTED EXCEPTION (README-note material): everywhere else in this codebase, a raw
// credential value never reaches the LLM (see fpFilter.ts's header). This analyzer is the one
// deliberate exception — it sends the raw content of a SMALL, selected set of files to Claude
// (Haiku), because reading the actual file is the only way to catch what the points above
// describe. The exception is kept as narrow as practical:
//   - the file set is small and targeted: config/CI/infra files (`.github/workflows/*`,
//     Dockerfile*, docker-compose*, `*.env*`, common config extensions under config-ish paths,
//     Terraform, k8s-ish manifests, settings/config entrypoints) PLUS source files that the Haiku
//     triage pass (../code/triage.ts) already flagged `credentialRisk: true` — never the whole repo;
//   - lockfiles, vendored/minified/oversized (> 200 KiB) files are never selected;
//   - every such file is covered (no count cap — cost is bounded by the scan's dollar budget, this
//     being budget tier 1 with a lease projecting its remaining batches, see llm/budget.ts), batched
//     to a small token budget (~10k tokens/batch) on the cheapest ("fast") model tier; batches the
//     budget could not cover are recorded as 'budget-skipped' coverage;
//   - the model is explicitly told never to echo a full credential value anywhere in its reply
//     except the one "snippet" line, which WE redact before it is ever stored or displayed — the
//     model's own words (description, etc.) are also scrubbed of any value we end up masking;
//   - every reported location is re-verified against the real file (verifyIssueLocation) before it
//     becomes a finding, so a hallucinated or prompt-injected location is dropped, not trusted;
//   - results are deduped against the deterministic regex scanner, which stays authoritative (and
//     has liveness checks) for anything it can already recognize.

import { open } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { z } from 'zod';
import type { Finding, Severity } from '@vibesec/shared';
import { toAppError } from '../../errors/AppError';
import { fingerprint, githubPermalink, provisionalScore } from '../../findings/helpers';
import { verifyIssueLocation } from '../../findings/verify';
import type { IndexedFile, SkipReason } from '../../index/types';
import type { LlmClient, StructuredCall } from '../../llm/LlmClient';
import type { MockResponder } from '../../llm/mockTransport';
import { estimateTokens, untrustedFile } from '../../llm/prompt';
import type { LlmRequest } from '../../llm/transport';
import type { RawCodeIssue } from '../code/types';
import type { TriageService } from '../code/triage';
import type { WorkLease } from '../../llm/budget';
import { NO_LEASE, type BudgetLanes } from '../../llm/budgetLanes';
import type { Analyzer, AnalyzerContext, CoverageStatus } from '../types';
import { detectSecrets, redact, secretHash } from './rules';
import { scanText } from './scanText';

export const CREDENTIAL_HUNTER_PROMPT_VERSION = 'credential-hunter-v1';
/** Appears verbatim in the system prompt; `credentialHunterMockResponder` keys on it. */
export const CREDENTIAL_HUNTER_TASK_MARKER = 'Task: credential-hunt';

export type HunterKind = 'custom-token' | 'split-string' | 'encoded' | 'comment' | 'crypto-key' | 'connection-password' | 'other';

/** Projected output of one batch (budget-lane projection only). */
const PROJECTED_OUTPUT_TOKENS = 1_000;
const PROJECTED_SYSTEM_TOKENS = 1_000;
const DEFAULT_BATCH_TOKENS = 10_000;
const DEFAULT_MAX_FILE_BYTES = 200 * 1024;
const READ_CONCURRENCY = 16;
const NUL_PROBE_BYTES = 8_192;
const PER_FILE_OVERHEAD_TOKENS = 60;
const CHARS_PER_TOKEN = 3.5; // matches estimateTokens() in llm/prompt.ts
const TRUNCATION_NOTE = '\n[TRUNCATED: file content was shortened to fit the credential-hunt batch token budget]';

// --- schema ----------------------------------------------------------------------------------

const HunterKindSchema = z.enum(['custom-token', 'split-string', 'encoded', 'comment', 'crypto-key', 'connection-password', 'other']);
const HunterResultSchema = z.object({
  file: z.string(),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive().optional(),
  /** The exact text of the reported line(s), copied verbatim — redacted by us, never trusted raw. */
  snippet: z.string().max(2_000),
  kind: HunterKindSchema,
  description: z.string().max(300),
  confidence: z.enum(['high', 'medium', 'low']),
  /** True when the model had to join string fragments or decode a value to recognize it. */
  reconstructed: z.boolean().optional(),
});
const HunterOutputSchema = z.object({ results: z.array(HunterResultSchema) });
type HunterOutput = z.infer<typeof HunterOutputSchema>;

// --- system prompt ---------------------------------------------------------------------------

const SYSTEM_PROMPT = [
  CREDENTIAL_HUNTER_TASK_MARKER,
  '',
  'You are hunting for credentials that a regex-based secret scanner would miss: custom/internal',
  'token formats, credentials split across string concatenations, base64/hex-encoded values,',
  'credentials mentioned only in comments or docs, hardcoded encryption keys/IVs/JWT signing',
  'secrets, and passwords embedded in connection objects (not just connection strings). Each',
  '<untrusted_file> block below is one file, with 1-based line numbers prefixed to each line so',
  'you can cite them.',
  '',
  'For every credential you find, report:',
  '  file: the file path exactly as given.',
  '  startLine / endLine: the line(s) the credential appears on (omit endLine for a single line).',
  '  snippet: the exact text of the reported line(s), copied verbatim. Do not trim, summarize, or',
  '    reconstruct it — just copy it. Do NOT echo the full credential value anywhere else in your',
  '    reply (not in description, not restated). We redact this snippet ourselves before it is',
  '    ever stored or shown to anyone.',
  '  kind: one of custom-token, split-string, encoded, comment, crypto-key, connection-password, other.',
  '  description: a short, specific reason this looks like a real credential (without restating it).',
  '  confidence: high, medium, or low.',
  '  reconstructed: true only if you had to join string fragments or decode a value to recognize it',
  '    as a credential.',
  '',
  'Ignore obvious placeholders and test fixtures (e.g. "changeme", repeated filler characters,',
  'values that are clearly fake sample/demo data). If you are unsure whether something is a',
  'placeholder or real test data, report it anyway and say so in the description rather than',
  'silently skipping it — a missed real credential costs far more than a false alarm.',
  '',
  'Only report credentials you actually see in the files below; never guess or invent a location.',
].join('\n');
// Note: UNTRUSTED_POLICY is appended automatically by LlmClient (via buildRequestParts).

// --- file selection ------------------------------------------------------------------------------

const WORKFLOW_PATH_RE = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i;
const DOCKERFILE_PATH_RE = /(^|\/)(Dockerfile(\.[^/]+)?|[^/]+\.[Dd]ockerfile|Containerfile(\.[^/]+)?)$/;
const DOCKER_COMPOSE_RE = /(^|\/)docker-compose(\.[\w.-]+)?\.ya?ml$/i;
const TERRAFORM_RE = /\.tf$/i;
const SETTINGS_OR_CONFIG_ENTRYPOINT_RE = /(^|\/)(settings\.py|config\.(?:js|ts|py))$/i;
const CONFIG_EXT_RE = /\.(?:ya?ml|json|toml|ini|cfg|conf|properties|xml)$/i;
const CONFIG_PATH_HINT_RE = /(^|\/)(config|configs|settings|infra|infrastructure|deploy|deployment|k8s|kubernetes|helm|charts|manifests|terraform)(\/|$)/i;

function isEnvFile(base: string): boolean {
  const lower = base.toLowerCase();
  return lower.includes('.env') && !lower.includes('example');
}

/** Config/CI/infra files, selected by path/extension alone — never by content. */
function isConfigCiInfraFile(file: IndexedFile): boolean {
  const path = file.path;
  const base = path.split('/').pop() ?? path;
  if (WORKFLOW_PATH_RE.test(path)) return true;
  if (DOCKERFILE_PATH_RE.test(path)) return true;
  if (DOCKER_COMPOSE_RE.test(path)) return true;
  if (isEnvFile(base)) return true;
  if (TERRAFORM_RE.test(path)) return true;
  if (SETTINGS_OR_CONFIG_ENTRYPOINT_RE.test(path)) return true;
  if (CONFIG_EXT_RE.test(path) && (file.category === 'config' || CONFIG_PATH_HINT_RE.test(path))) return true;
  return false;
}

/** skipReason values that disqualify a file from the hunter regardless of path/size. */
const NEVER_SELECT_SKIP: ReadonlySet<SkipReason> = new Set(['vendor', 'binary', 'minified', 'symlink', 'submodule', 'file_limit', 'too_large']);

function isSelectable(file: IndexedFile, maxFileBytes: number): boolean {
  if (file.category === 'lockfile') return false;
  if (file.skipReason !== null && NEVER_SELECT_SKIP.has(file.skipReason)) return false;
  return file.size <= maxFileBytes;
}

/** 3-tier path-heuristic priority, higher sorts first: env files (most likely to hold real
 *  secrets) > other config/CI/infra files > AI-triaged credential-risk source files. */
function priorityTier(file: IndexedFile): number {
  const base = file.path.split('/').pop() ?? file.path;
  if (isEnvFile(base)) return 0;
  if (isConfigCiInfraFile(file)) return 1;
  return 2;
}

function comparePriority(a: IndexedFile, b: IndexedFile): number {
  const diff = priorityTier(a) - priorityTier(b);
  if (diff !== 0) return diff;
  return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
}

/** Every config/CI/infra file plus every credentialRisk source file, highest priority first (no count cap). */
export function selectHunterFiles(files: readonly IndexedFile[], credentialRiskPaths: ReadonlySet<string>, maxFileBytes: number): IndexedFile[] {
  const selectable = files.filter((f) => isSelectable(f, maxFileBytes));
  const configFiles = selectable.filter((f) => isConfigCiInfraFile(f));
  const configPaths = new Set(configFiles.map((f) => f.path));
  const riskFiles = selectable.filter((f) => !configPaths.has(f.path) && credentialRiskPaths.has(f.path));
  return [...configFiles, ...riskFiles].sort(comparePriority);
}

// --- safe file read (bounded, repo-confined, binary-aware) ---------------------------------------

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

/** Runs `fn` over `items` with at most `limit` in flight; stops dispatching new items (but lets
 *  in-flight ones settle) as soon as any call throws, so cancellation propagates promptly. */
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

// --- prompt batching (numbered content, token-bounded bins) ---------------------------------------

function numberLines(content: string): string {
  return content.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
}

function fitToTokenBudget(text: string, maxTokens: number): { text: string; truncated: boolean } {
  if (estimateTokens(text) <= maxTokens) return { text, truncated: false };
  const maxChars = Math.max(0, Math.floor(maxTokens * CHARS_PER_TOKEN));
  return { text: text.slice(0, maxChars), truncated: true };
}

type PromptFile = { path: string; block: string; blockTokens: number };

function buildPromptFile(path: string, content: string, batchTokens: number): PromptFile {
  const budget = Math.max(0, batchTokens - PER_FILE_OVERHEAD_TOKENS);
  const { text, truncated } = fitToTokenBudget(numberLines(content), budget);
  const body = truncated ? `${text}${TRUNCATION_NOTE}` : text;
  const block = untrustedFile(path, body);
  return { path, block, blockTokens: estimateTokens(block) };
}

/** Greedy bin-packing by estimated tokens. Every item already fits a fresh (empty) batch on its
 *  own (buildPromptFile truncates to the per-file budget), so this always makes progress. */
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

// --- masking (no raw value may survive into a Finding) --------------------------------------------

/** Quoted string literal content (single/double/backtick), used to find candidate secret fragments
 *  even when they don't match any known regex-recognizable credential format. */
const QUOTED_LITERAL_RE = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;
/** An unquoted value after `=` or `:` (e.g. a bare base64/hex token, or an unquoted YAML value). */
const BARE_VALUE_RE = /[:=]\s*([A-Za-z0-9+/_.~-]{8,})/g;
/** Spec threshold: only values at least this long are masked by the generic (untyped) rule. */
const MIN_MASK_LENGTH = 8;

function genericMask(value: string): string {
  return value.length < 3 ? '…' : value.slice(0, 2) + '…';
}

/**
 * Builds a raw-value -> masked-value map for a set of lines: known credential formats (via
 * `detectSecrets`) are masked with the typed `redact()` (keeps a safe, non-secret prefix where one
 * exists); everything else that looks like a quoted literal or an unquoted `key: value`/`key=value`
 * of >= MIN_MASK_LENGTH chars is masked to its first 2 chars + '…' — this is what catches split
 * string fragments and encoded/custom values that no regex recognizes as a specific token type.
 */
function buildRedactionMap(lines: readonly string[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of lines) {
    for (const m of detectSecrets(line, { includeRedactOnly: true })) {
      if (m.value.length > 0 && !map.has(m.value)) map.set(m.value, redact(m.value, m.type));
    }
    for (const m of line.matchAll(QUOTED_LITERAL_RE)) {
      const content = m[2] ?? '';
      if (content.length >= MIN_MASK_LENGTH && !map.has(content)) map.set(content, genericMask(content));
    }
    for (const m of line.matchAll(BARE_VALUE_RE)) {
      const value = m[1] ?? '';
      if (value.length >= MIN_MASK_LENGTH && !map.has(value)) map.set(value, genericMask(value));
    }
  }
  return map;
}

/** Applies every mapping, longest raw value first (so a value that is itself a substring of a
 *  longer one is masked as part of the longer match, not left partially exposed afterwards). */
function applyRedactionMap(text: string, map: ReadonlyMap<string, string>): string {
  let out = text;
  for (const [raw, masked] of [...map.entries()].sort((a, b) => b[0].length - a[0].length)) {
    if (raw.length === 0) continue;
    out = out.split(raw).join(masked);
  }
  return out;
}

// --- dedupe against the regex credential scanner ---------------------------------------------

/** `file:line` keys covered by a regex-detected credential candidate in the same files, so hunter
 *  results that overlap one are dropped (the regex analyzer already reports those, with liveness
 *  checks) rather than double-reported. */
function regexCoverage(filesWithText: ReadonlyMap<string, string>): Set<string> {
  const keys = new Set<string>();
  for (const [path, text] of filesWithText) {
    for (const cand of scanText(path, text)) {
      for (let ln = cand.line; ln <= cand.endLine; ln++) keys.add(`${path}:${ln}`);
    }
  }
  return keys;
}

// --- finding construction -----------------------------------------------------------------------

const HUNTER_TITLE: Record<HunterKind, string> = {
  'custom-token': 'Custom/internal credential token',
  'split-string': 'Credential built from concatenated string fragments',
  encoded: 'Encoded (base64/hex) credential value',
  comment: 'Credential mentioned in a comment or doc',
  'crypto-key': 'Hardcoded cryptographic key, IV, or signing secret',
  'connection-password': 'Password embedded in a connection object',
  other: 'Likely credential flagged by AI review',
};

const HUNTER_IMPACT: Record<HunterKind, string> = {
  'custom-token': 'A non-standard credential format that regex scanners miss can still grant real access to whatever system it authenticates to.',
  'split-string': 'Splitting a credential across concatenated string literals defeats pattern-based scanners while the reconstructed value still works at runtime.',
  encoded: 'An encoded credential is trivially decodable by anyone with read access to the source, defeating the obfuscation.',
  comment: 'A credential left in a comment or doc is just as usable by an attacker as one in executable code, and is easy to miss during review.',
  'crypto-key': 'A hardcoded encryption key, IV, or signing secret lets anyone with source access decrypt protected data or forge signed tokens.',
  'connection-password': 'A password embedded in a connection object grants direct access to whatever service it authenticates to.',
  other: 'The exact impact depends on what this value authenticates to; AI review judged it a likely real credential.',
};

function hunterRemediation(credential: string): string {
  return [
    `Revoke/rotate this ${credential} immediately — rotation is what actually neutralizes the exposure.`,
    'Remove the value from the codebase (replace it with a reference, never a literal).',
    'Load it at runtime from environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault, Doppler).',
    'If it also appears in git history, purge it with `git filter-repo` or the BFG Repo-Cleaner after rotating — deleting the current line does not remove it from past commits.',
  ].join(' ');
}

const HUNTER_REMEDIATION: Record<HunterKind, string> = {
  'custom-token': hunterRemediation('credential'),
  'split-string': hunterRemediation('credential'),
  encoded: hunterRemediation('credential'),
  comment: hunterRemediation('credential'),
  'crypto-key': hunterRemediation('key'),
  'connection-password': hunterRemediation('password'),
  other: hunterRemediation('credential'),
};

const HIGH_RISK_KINDS: ReadonlySet<HunterKind> = new Set(['crypto-key', 'connection-password', 'custom-token']);
const TEST_DATA_RE = /\b(?:test|tests|fixture|fixtures|example|examples|placeholder|dummy|sample|mock|mocks)\b/i;

function baseSeverityFor(kind: HunterKind, confidence: 'high' | 'medium' | 'low'): Severity {
  return HIGH_RISK_KINDS.has(kind) && confidence === 'high' ? 'high' : 'medium';
}

/**
 * Verifies the reported location against the real file, drops it if the snippet can't be found
 * anywhere (hallucination/prompt injection), drops it if a regex candidate already covers the same
 * file+line, then masks the (now real, file-sourced) snippet before it ever becomes part of the
 * returned Finding. Nothing derived from the model's un-redacted view of the file survives past
 * this function except the masked text.
 */
function buildHunterFinding(
  ctx: Pick<AnalyzerContext, 'scanId' | 'repo' | 'commitSha'>,
  result: HunterOutput['results'][number],
  fileText: string,
  regexCoveredLines: ReadonlySet<string>,
): Finding | null {
  const endLine = result.endLine ?? result.startLine;
  const draft: RawCodeIssue = {
    ruleId: `secret/hunter-${result.kind}`,
    title: HUNTER_TITLE[result.kind],
    severity: 'medium',
    confidence: result.confidence,
    file: result.file,
    startLine: result.startLine,
    endLine,
    snippet: result.snippet,
    explanation: result.description,
    impact: HUNTER_IMPACT[result.kind],
    remediation: HUNTER_REMEDIATION[result.kind],
  };

  const outcome = verifyIssueLocation(draft, fileText);
  if (outcome.status === 'dropped') return null;
  const verified = outcome.issue;

  for (let ln = verified.startLine; ln <= verified.endLine; ln++) {
    if (regexCoveredLines.has(`${verified.file}:${ln}`)) return null;
  }

  const rawLines = verified.snippet.split('\n');
  const redactionMap = buildRedactionMap(rawLines);
  const maskedSnippet = applyRedactionMap(verified.snippet, redactionMap);
  const maskedDescription = applyRedactionMap(result.description, redactionMap);
  const hash = secretHash(verified.snippet);

  const likelyTestData = TEST_DATA_RE.test(result.description);
  const severity: Severity = likelyTestData ? 'low' : baseSeverityFor(result.kind, result.confidence);
  const confidence: 'high' | 'medium' | 'low' = likelyTestData ? 'low' : result.confidence;

  const ruleId = `secret/hunter-${result.kind}`;
  const fp = fingerprint(['secret', ruleId, verified.file, hash]);
  const id = fingerprint([ctx.scanId, fp]).slice(0, 32);
  const redactedValue = (maskedSnippet.split('\n')[0] ?? '').trim().slice(0, 200) || '…';

  return {
    id,
    scanId: ctx.scanId,
    fingerprint: fp,
    category: 'secret',
    ruleId,
    cwe: 'CWE-798',
    title: HUNTER_TITLE[result.kind],
    baseSeverity: severity,
    riskScore: provisionalScore(severity),
    severity,
    riskFactors: [],
    confidence,
    location: {
      file: verified.file,
      startLine: verified.startLine,
      endLine: verified.endLine,
      snippet: maskedSnippet,
      permalink: githubPermalink(ctx.repo, ctx.commitSha, verified.file, verified.startLine, verified.endLine),
    },
    secret: {
      type: `hunter-${result.kind}`,
      redacted: redactedValue,
      liveness: 'not_checked',
      inHistoryOnly: false,
    },
    explanation: `${maskedDescription} Found by AI review (not a known token format).`,
    impact: HUNTER_IMPACT[result.kind],
    remediation: { summary: HUNTER_REMEDIATION[result.kind] },
    scanStatus: 'new',
    producedBy: ['credential-hunter:llm'],
  };
}

// --- analyzer -------------------------------------------------------------------------------------

export type CredentialHunterDeps = {
  llm: Pick<LlmClient, 'structured'>;
  triage: Pick<TriageService, 'forScan'>;
  /** Budget lanes: a tier-1 lease projecting the remaining batches (llm/budget.ts). */
  lanes?: BudgetLanes;
  batchTokens?: number;
  maxFileBytes?: number;
};

export function createCredentialHunter(deps: CredentialHunterDeps): Analyzer {
  return {
    id: 'credential-hunter',
    version: '2',
    category: 'secret',

    async run(ctx: AnalyzerContext): Promise<Finding[]> {
      if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      const lease = deps.lanes?.open(ctx.scanId) ?? NO_LEASE; // before the first await (see llm/budget.ts)
      try {
        return await hunt(ctx, lease);
      } finally {
        lease.close();
      }
    },
  };

  async function hunt(ctx: AnalyzerContext, lease: WorkLease): Promise<Finding[]> {
      const checkAbort = (): void => {
        if (ctx.signal.aborted) throw toAppError(ctx.signal.reason ?? new Error('aborted'));
      };
      const record = (path: string, status: CoverageStatus) => ctx.recordCoverage?.('credential-hunter', path, status);
      const batchTokens = deps.batchTokens ?? DEFAULT_BATCH_TOKENS;
      const maxFileBytes = deps.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;

      const triageResult = await deps.triage.forScan(ctx);
      checkAbort();
      const credentialRiskPaths = new Set([...triageResult.files.values()].filter((f) => f.credentialRisk).map((f) => f.path));

      const selected = selectHunterFiles(ctx.files, credentialRiskPaths, maxFileBytes);
      if (selected.length === 0) return [];

      const contentOf = new Map<string, string>();
      await forEachLimit(selected, READ_CONCURRENCY, async (f) => {
        checkAbort();
        const text = await readFileSafe(ctx.repoDir, f.path, maxFileBytes);
        if (text !== null) contentOf.set(f.path, text);
        ctx.touch();
      });
      for (const f of selected) if (!contentOf.has(f.path)) record(f.path, 'failed');
      if (contentOf.size === 0) return [];

      const regexCoveredLines = regexCoverage(contentOf);

      // Priority order (env > config/CI/infra > credentialRisk source), so the budget covers the riskiest first.
      const promptFiles = selected.filter((f) => contentOf.has(f.path)).map((f) => buildPromptFile(f.path, contentOf.get(f.path)!, batchTokens));
      const batches = packBatches(promptFiles, batchTokens);
      const batchUsd = (batch: PromptFile[]) => deps.lanes?.estimateUsd(
        'fast', PROJECTED_SYSTEM_TOKENS + batch.reduce((n, f) => n + f.blockTokens, 0), PROJECTED_OUTPUT_TOKENS,
      ) ?? 0;
      let remainingUsd = batches.reduce((sum, b) => sum + batchUsd(b), 0);
      lease.project(remainingUsd);
      let budgetExhausted = false;

      const findings: Finding[] = [];
      let warnedPartial = false;
      for (const batch of batches) {
        checkAbort();
        remainingUsd -= batchUsd(batch);
        const batchPaths = new Set(batch.map((f) => f.path));
        if (budgetExhausted) {
          for (const f of batch) record(f.path, 'budget-skipped');
          lease.project(remainingUsd);
          continue;
        }
        const call: StructuredCall<HunterOutput> = {
          scanId: ctx.scanId, analyzer: 'credential-hunter', purpose: 'credential-hunt',
          promptVersion: CREDENTIAL_HUNTER_PROMPT_VERSION, role: 'fast', system: SYSTEM_PROMPT,
          prompt: batch.map((f) => f.block).join('\n\n'), schema: HunterOutputSchema,
          signal: ctx.signal, onActivity: ctx.touch,
        };
        let output: HunterOutput;
        try {
          const result = await deps.llm.structured(call);
          output = result.output;
        } catch (raw) {
          const err = toAppError(raw);
          if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
          lease.project(remainingUsd);
          if (err.kind === 'budget') {
            budgetExhausted = true;
            for (const f of batch) record(f.path, 'budget-skipped');
            continue;
          }
          for (const f of batch) record(f.path, 'failed');
          if (!warnedPartial) {
            warnedPartial = true;
            ctx.warn('CREDENTIAL_HUNTER_PARTIAL', 'AI credential hunting failed for one or more file batches; those files were only covered by the regex scanner');
          }
          continue;
        }
        for (const r of output.results) {
          if (!batchPaths.has(r.file)) continue; // only trust files we actually sent in this batch
          const fileText = contentOf.get(r.file);
          if (fileText === undefined) continue;
          const finding = buildHunterFinding(ctx, r, fileText, regexCoveredLines);
          if (finding) findings.push(finding);
        }
        for (const f of batch) record(f.path, 'reviewed');
        lease.project(remainingUsd);
        ctx.touch();
      }

      return findings;
  }
}

// --- mock responder --------------------------------------------------------------------------

const FILE_BLOCK_RE = /<untrusted_file\s+path="([^"]*)">([\s\S]*?)<\/untrusted_file>/g;
// No leading \b: credential-like names are often camelCase (`dbPassword`, `apiToken`), where a
// word-boundary assertion right before the keyword would never match.
const SPLIT_STRING_RE = /(?:password|secret|token|api[_-]?key|apikey)\w*\s*[:=]\s*(?:['"][^'"]*['"]\s*\+\s*){1,}['"][^'"]*['"]/i;
const ENCODED_RE = /Buffer\.from\(\s*['"][^'"]+['"]\s*,\s*['"]base64['"]\s*\)|\batob\(\s*['"][^'"]+['"]\s*\)|base64\.b64decode\(\s*['"][^'"]+['"]\s*\)/;
const PASSWORD_LITERAL_RE = /\bpassword\s*:\s*['"][^'"]+['"]/i;
const NUMBERED_LINE_RE = /^(\d+): (.*)$/;

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
 * Deterministic stand-in for the real model (used by MockTransport). Answers only requests whose
 * system prompt carries CREDENTIAL_HUNTER_TASK_MARKER. Per numbered line: flags a credential-named
 * variable built from 2+ concatenated quoted fragments (split-string, reconstructed), a
 * `Buffer.from(x, 'base64')` / `atob(x)` / `base64.b64decode(x)` call on a literal (encoded,
 * reconstructed), or a `password: '...'` field in an object literal (connection-password).
 */
export const credentialHunterMockResponder: MockResponder = (req: LlmRequest) => {
  const { system, user } = textOfRequest(req);
  if (!system.includes(CREDENTIAL_HUNTER_TASK_MARKER)) return undefined;

  const results: HunterOutput['results'] = [];
  FILE_BLOCK_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FILE_BLOCK_RE.exec(user))) {
    const path = unescapeAttr(m[1] ?? '');
    if (!path) continue;
    const content = unescapeAttr(m[2] ?? '');
    for (const line of content.split('\n')) {
      const lm = NUMBERED_LINE_RE.exec(line);
      if (!lm) continue;
      const startLine = Number(lm[1]);
      const code = lm[2] ?? '';
      if (SPLIT_STRING_RE.test(code)) {
        results.push({
          file: path, startLine, snippet: code, kind: 'split-string',
          description: 'String concatenation builds a credential-like value from literal fragments.',
          confidence: 'high', reconstructed: true,
        });
      } else if (ENCODED_RE.test(code)) {
        results.push({
          file: path, startLine, snippet: code, kind: 'encoded',
          description: 'A base64-decoded literal looks like a credential value.',
          confidence: 'high', reconstructed: true,
        });
      } else if (PASSWORD_LITERAL_RE.test(code)) {
        results.push({
          file: path, startLine, snippet: code, kind: 'connection-password',
          description: 'Object literal contains a password field with a literal value.',
          confidence: 'high',
        });
      }
    }
  }
  return { results };
};
