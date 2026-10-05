// Claude taint agent (P6) — the showcase "AI agent" of the product. For each selected entrypoint a
// Claude agent explores the repository with read-only, confined tools (repoTools.ts), follows every
// untrusted source through calls/imports to dangerous sinks and reports each flow with report_flow.
//
// Nothing the model reports is trusted blindly: every trace step is re-located in the real file
// (verifyTrace); a flow whose source or sink cannot be confirmed is dropped. Surviving flows become
// one finding at the SINK location carrying the full verified source→sink trace (shown in the UI).
//
// Every entrypoint with an untrusted source is traced (no count cap), highest risk first (triage
// relevance, then number of sources), under the scan's dollar budget: the analyzer holds a tier-1
// budget lease projecting the cost of the agents still to run (llm/budget.ts). Entrypoints the budget
// could not cover are recorded as 'budget-skipped' coverage, never dropped silently.
//
// Fail-open per entrypoint (one failing agent never sinks the analyzer), partial results on
// max_turns / timeout / budget, cancellation always propagates.

import { lstat, open, realpath } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import type Anthropic from '@anthropic-ai/sdk';
import type { Finding } from '@vibesec/shared';
import type { IndexRepo } from '../../db/indexRepo';
import { AppError, toAppError } from '../../errors/AppError';
import { verifyTrace } from '../../findings/verify';
import type { Entrypoint, ImportEdge, IndexedFile } from '../../index/types';
import { defineTool, type AgentResult, type AgentStopReason, type LlmClient } from '../../llm/LlmClient';
import { mockText, mockToolUse, mockToolUses, type MockResponder } from '../../llm/mockTransport';
import type { LlmRequest } from '../../llm/transport';
import type { WorkLease } from '../../llm/budget';
import { NO_LEASE, type BudgetLanes } from '../../llm/budgetLanes';
import type { Analyzer, AnalyzerContext, CoverageStatus } from '../types';
import { createRepoTools, normalizeRepoPath, ReportFlowInput } from './repoTools';
import { buildSeedPrompt, SEED_LINES, TAINT_PROMPT_VERSION, TAINT_SYSTEM_PROMPT, TAINT_TASK_MARKER } from './taintPrompt';
import { issueToFinding } from './toFinding';
import { selectForTaint, type TriageService } from './triage';
import type { FileTriage, RawCodeIssue, TraceStep } from './types';

export { TAINT_PROMPT_VERSION, TAINT_TASK_MARKER } from './taintPrompt';

const DEFAULT_CONCURRENCY = 2;
const DEFAULT_MAX_TURNS = 25;
const DEFAULT_WALL_CLOCK_MS = 300_000;
const MAX_VERIFY_FILE_BYTES = 1024 * 1024;
const NUL_PROBE_BYTES = 8_000;
/** Projected cost of one entrypoint agent: ~10 turns over a growing transcript (input mostly cache reads). */
const PROJECTED_AGENT_INPUT_TOKENS = 60_000;
const PROJECTED_AGENT_OUTPUT_TOKENS = 6_000;
const UNREADABLE: ReadonlySet<IndexedFile['skipReason']> = new Set(['binary', 'symlink', 'submodule']);

export type TaintAnalyzerDeps = {
  llm: Pick<LlmClient, 'agent'>;
  triage: Pick<TriageService, 'forScan'>;
  indexRepo: Pick<IndexRepo, 'imports' | 'entrypoints'>;
  /** Budget lanes: a tier-1 lease projecting the cost of the remaining agents (llm/budget.ts). */
  lanes?: BudgetLanes;
  concurrency?: number;
  maxTurns?: number;
  wallClockMs?: number;
};

type Flow = ReportFlowInput & { entrypoint: string; degraded: boolean };
type VerifiedFlow = { flow: Flow; trace: TraceStep[]; ruleId: string; sink: TraceStep };

export function createTaintAnalyzer(deps: TaintAnalyzerDeps): Analyzer {
  return {
    id: 'taint',
    version: '2',
    category: 'taint',
    run: async (ctx) => {
      if (ctx.signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
      const lease = deps.lanes?.open(ctx.scanId) ?? NO_LEASE; // before the first await (see SAST)
      try {
        return await runTaint(deps, ctx, lease);
      } finally {
        lease.close();
      }
    },
  };
}

async function runTaint(deps: TaintAnalyzerDeps, ctx: AnalyzerContext, lease: WorkLease): Promise<Finding[]> {
  const checkAbort = () => {
    if (ctx.signal.aborted) throw new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
  };
  checkAbort();
  const record = (path: string, status: CoverageStatus) => ctx.recordCoverage?.('taint', path, status);

  // 1. Entrypoints worth tracing, ranked by triage relevance then number of sources.
  const entrypoints = deps.indexRepo.entrypoints(ctx.scanId);
  const kindsOf = new Map<string, string[]>();
  for (const ep of entrypoints) {
    const list = kindsOf.get(ep.path) ?? [];
    list.push(describeEntrypoint(ep));
    kindsOf.set(ep.path, list);
  }
  const triage = await deps.triage.forScan(ctx);
  checkAbort();
  const ranked = selectForTaint(triage, new Set(kindsOf.keys()))
    .map((path) => triage.files.get(path)!)
    .sort((a, b) => b.relevance - a.relevance || b.sources.length - a.sources.length || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const rankedPaths = new Set(ranked.map((f) => f.path));
  for (const path of [...kindsOf.keys()].sort()) if (!rankedPaths.has(path)) record(path, 'not-relevant'); // no untrusted source seen
  const perAgentUsd = deps.lanes?.estimateUsd('deep', PROJECTED_AGENT_INPUT_TOKENS, PROJECTED_AGENT_OUTPUT_TOKENS) ?? 0;
  let agentsLeft = ranked.length;
  if (agentsLeft === 0) {
    lease.close();
    return [];
  }
  lease.project(agentsLeft * perAgentUsd);
  const selected = ranked;

  // 2. One agent per entrypoint (bounded concurrency), sharing one set of confined repo tools (and its file cache).
  const imports: ImportEdge[] = deps.indexRepo.imports(ctx.scanId);
  const reader = createConfinedReader(ctx.repoDir, ctx.files);
  const repoTools = createRepoTools({ repoDir: ctx.repoDir, files: ctx.files, imports, signal: ctx.signal });
  const reportFlow = defineTool({
    name: 'report_flow',
    description: 'Report one distinct source→sink taint flow with its ordered, verified-by-reading trace. Call once per flow.',
    input: ReportFlowInput,
    run: () => 'recorded',
  });
  const tools = [...repoTools, reportFlow];

  const flows: Flow[] = [];
  const partialReasons = new Set<AgentStopReason>();
  let failed = 0;
  let budgetExhausted = false;

  await forEachLimit(selected, deps.concurrency ?? DEFAULT_CONCURRENCY, async (file) => {
    try {
      await traceOne(file);
    } finally {
      agentsLeft--;
      lease.project(agentsLeft * perAgentUsd);
    }
  });

  async function traceOne(file: FileTriage): Promise<void> {
    checkAbort();
    if (budgetExhausted) { record(file.path, 'budget-skipped'); return; }
    const text = await reader.read(file.path);
    if (text === null) { record(file.path, 'failed'); return; }
    const lines = toLines(text);
    const prompt = buildSeedPrompt({
      entrypoint: file.path, kinds: kindsOf.get(file.path) ?? [], sources: file.sources, sinks: file.sinks,
      lines: lines.slice(0, SEED_LINES), totalLines: lines.length,
    });
    let result: AgentResult<ReportFlowInput>;
    try {
      result = await deps.llm.agent<ReportFlowInput>({
        scanId: ctx.scanId, analyzer: 'taint', purpose: 'taint-entrypoint', promptVersion: TAINT_PROMPT_VERSION,
        role: 'deep', system: TAINT_SYSTEM_PROMPT, prompt, tools, finishTool: 'report_flow',
        maxTurns: deps.maxTurns ?? DEFAULT_MAX_TURNS, wallClockMs: deps.wallClockMs ?? DEFAULT_WALL_CLOCK_MS,
        signal: ctx.signal, onActivity: ctx.touch,
      });
    } catch (raw) {
      const err = toAppError(raw);
      if (err.kind === 'cancelled' || ctx.signal.aborted) throw err;
      if (err.kind === 'budget') {
        budgetExhausted = true;
        record(file.path, 'budget-skipped');
        return;
      }
      failed++;
      record(file.path, 'failed');
      ctx.progress(`Taint agent failed for ${file.path}: ${err.userMessage}`);
      return;
    }
    ctx.touch();
    for (const f of result.finished) flows.push({ ...f, entrypoint: file.path, degraded: result.degraded });
    if (result.stopReason === 'budget') budgetExhausted = true;
    if (result.stopReason !== 'end_turn' && !partialReasons.has(result.stopReason)) {
      partialReasons.add(result.stopReason);
      ctx.warn('TAINT_PARTIAL', `Taint tracing of ${file.path} stopped early (${result.stopReason}); results for it may be incomplete`);
    }
    // An agent stopped by the budget before its first turn traced nothing: that is a budget skip.
    record(file.path, result.stopReason === 'budget' && result.turns === 0 ? 'budget-skipped' : 'reviewed');
    ctx.progress(`Taint agent traced ${file.path}: ${result.finished.length} flow(s) in ${result.turns} turn(s)`);
  }
  checkAbort();
  if (failed > 0) {
    ctx.warn('TAINT_ENTRYPOINT_FAILED', `Taint tracing failed for ${failed} entrypoint(s); other entrypoints were still analyzed`);
  }

  // 3. Verdict filter → trace verification against the real files.
  let sanitized = 0;
  let unverified = 0;
  const candidates = flows.filter((f) => {
    if (f.verdict !== 'sanitized') return true;
    sanitized++;
    return false;
  });
  const stepFiles = new Set(candidates.flatMap((f) => f.trace.map((s) => safeNormalize(s.file))).filter((p): p is string => p !== null));
  const texts = new Map<string, string | null>();
  await Promise.all([...stepFiles].map(async (p) => { texts.set(p, await reader.read(p)); }));
  checkAbort();

  const verified: VerifiedFlow[] = [];
  for (const flow of candidates) {
    const trace = flow.trace.map((s) => ({ ...s, file: safeNormalize(s.file) ?? s.file }));
    const result = verifyTrace(trace, (p) => texts.get(p) ?? null);
    const sink = result.ok ? [...result.trace].reverse().find((s) => s.kind === 'sink') : undefined;
    const source = result.ok ? result.trace.find((s) => s.kind === 'source') : undefined;
    if (!result.ok || !sink || !source) {
      unverified++;
      continue;
    }
    verified.push({ flow, trace: result.trace, sink, ruleId: toTaintRuleId(flow.ruleId) });
  }
  if (unverified > 0) {
    ctx.warn('TAINT_UNVERIFIED_DROPPED', `${unverified} reported taint flow(s) were dropped because their source or sink could not be found in the code`);
  }
  if (sanitized > 0) ctx.progress(`Taint agent: ${sanitized} sanitized flow(s) not reported`);

  // 4. Dedupe by sink location + rule, then convert at the sink step.
  return dedupeFlows(verified).map((v) => issueToFinding(ctx, 'taint', toIssue(v), ['taint:agent']));
}

// --- conversion / dedupe -----------------------------------------------------------------------

const CONFIDENCE_RANK = { high: 0, medium: 1, low: 2 } as const;
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

function confidenceOf(flow: Flow): RawCodeIssue['confidence'] {
  if (flow.verdict === 'uncertain') return 'low';
  if (flow.degraded && flow.confidence === 'high') return 'medium';
  return flow.confidence;
}

function toIssue(v: VerifiedFlow): RawCodeIssue {
  const f = v.flow;
  const issue: RawCodeIssue = {
    ruleId: v.ruleId, title: f.title, severity: f.severity, confidence: confidenceOf(f),
    file: v.sink.file, startLine: v.sink.line, endLine: v.sink.line, snippet: v.sink.code,
    explanation: f.sanitizersSeen.length
      ? `${f.explanation}\n\nSanitizers/validation seen on the path (judged ineffective or unconfirmed): ${f.sanitizersSeen.join(', ')}.`
      : f.explanation,
    impact: f.impact, remediation: f.remediation, taintTrace: v.trace,
  };
  if (f.cwe) issue.cwe = f.cwe;
  if (f.patch) issue.patch = f.patch;
  return issue;
}

/** Same sink (file:line) + rule → one flow: keep the shortest verified trace, merge step notes, keep the strongest confidence/severity. */
function dedupeFlows(flows: VerifiedFlow[]): VerifiedFlow[] {
  const groups = new Map<string, VerifiedFlow[]>();
  for (const v of flows) {
    const key = `${v.ruleId}\0${v.sink.file}\0${v.sink.line}`;
    const list = groups.get(key);
    if (list) list.push(v);
    else groups.set(key, [v]);
  }
  const out: VerifiedFlow[] = [];
  for (const group of groups.values()) {
    const winner = group.reduce((a, b) => (b.trace.length < a.trace.length ? b : a));
    if (group.length === 1) {
      out.push(winner);
      continue;
    }
    const trace = winner.trace.map((step) => {
      const notes = new Set([step.note]);
      for (const other of group) {
        if (other === winner) continue;
        for (const s of other.trace) if (s.kind === step.kind && s.file === step.file && s.line === step.line && s.note) notes.add(s.note);
      }
      return { ...step, note: [...notes].filter(Boolean).join(' / ') };
    });
    const flow = { ...winner.flow };
    for (const other of group) {
      const conf = confidenceOf(other.flow);
      if (CONFIDENCE_RANK[conf] < CONFIDENCE_RANK[confidenceOf(flow)]) Object.assign(flow, { confidence: other.flow.confidence, verdict: other.flow.verdict, degraded: other.flow.degraded });
      if (SEVERITY_ORDER[other.flow.severity] < SEVERITY_ORDER[flow.severity]) flow.severity = other.flow.severity;
    }
    out.push({ ...winner, flow, trace, sink: trace[trace.length - 1]!.kind === 'sink' ? trace[trace.length - 1]! : winner.sink });
  }
  return out;
}

/** 'SQL Injection' / 'sast/sqlInjection' / 'taint/sql-injection' → 'taint/sql-injection'. */
export function toTaintRuleId(raw: string): string {
  const tail = raw.split('/').filter(Boolean).pop() ?? '';
  const kebab = tail.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  return `taint/${kebab || 'tainted-flow'}`;
}

function describeEntrypoint(ep: Entrypoint): string {
  return [ep.kind, ep.detail, ep.line ? `(line ${ep.line})` : null].filter(Boolean).join(' ');
}

function safeNormalize(path: string): string | null {
  try {
    return normalizeRepoPath(path) || null;
  } catch {
    return null;
  }
}

function toLines(text: string): string[] {
  const lines = text.split(/\r?\n/);
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

// --- confined reader (seed listing + trace verification) -----------------------------------------

/** Repo-confined text reader: indexed files only, no symlinks, realpath inside repoDir, size cap, binary probe. */
function createConfinedReader(repoDir: string, files: readonly IndexedFile[]) {
  const root = resolve(repoDir);
  const index = new Map(files.map((f) => [f.path, f]));
  let realRoot: Promise<string> | undefined;
  const cache = new Map<string, Promise<string | null>>();

  async function load(path: string): Promise<string | null> {
    const file = index.get(path);
    if (!file || UNREADABLE.has(file.skipReason)) return null;
    const abs = join(root, ...path.split('/'));
    const st = await lstat(abs).catch(() => null);
    if (!st || st.isSymbolicLink() || !st.isFile() || st.size > MAX_VERIFY_FILE_BYTES) return null;
    realRoot ??= realpath(root);
    const real = await realpath(abs).catch(() => null);
    if (!real || !real.startsWith((await realRoot) + sep)) return null;
    const handle = await open(real, 'r').catch(() => null);
    if (!handle) return null;
    try {
      const { size } = await handle.stat();
      if (size > MAX_VERIFY_FILE_BYTES) return null;
      const buffer = Buffer.alloc(size);
      let read = 0;
      while (read < size) {
        const { bytesRead } = await handle.read(buffer, read, size - read, read);
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

  return {
    read(raw: string): Promise<string | null> {
      const path = safeNormalize(raw);
      if (!path) return Promise.resolve(null);
      let p = cache.get(path);
      if (!p) {
        p = load(path);
        cache.set(path, p);
      }
      return p;
    },
  };
}

/** At most `limit` in flight; the first throw stops workers from picking up further items. */
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

// --- mock responder ------------------------------------------------------------------------------

const MOCK_MAX_TURNS = 8;
const MOCK_SOURCE_RE = /\b(?:req|request)\.(?:query|params|body|args|form|values|GET|POST|cookies|headers)\b|\bsearchParams\b|\brequest\.get_json\(/;
const MOCK_SINKS: ReadonlyArray<{ re: RegExp; ruleId: string; cwe: string; severity: ReportFlowInput['severity']; title: string }> = [
  { re: /\b(?:query|execute|raw)\s*\(/, ruleId: 'taint/sql-injection', cwe: 'CWE-89', severity: 'high', title: 'SQL injection' },
  { re: /\b(?:execSync|exec|spawn|system|popen)\s*\(/, ruleId: 'taint/command-injection', cwe: 'CWE-78', severity: 'critical', title: 'Command injection' },
  { re: /\b(?:sendFile|send_file|readFile|readFileSync)\s*\(/, ruleId: 'taint/path-traversal', cwe: 'CWE-22', severity: 'high', title: 'Path traversal' },
];
const DEFINITION_RE = /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\b|def\b|class\b)|^\s*(?:import|from)\s/;
const EXPORTED_NAME_RE = /^\s*(?:export\s+(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)|export\s+const\s+([A-Za-z_$][\w$]*)|(?:async\s+)?def\s+([A-Za-z_]\w*))/;
const FILE_BLOCK_RE = /<untrusted_file path="([^"]*)">\n([\s\S]*?)\n<\/untrusted_file>/g;

function unescapeAttr(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

/** Every text the mock "saw": user text blocks and tool_result contents, in order. */
function seenTexts(req: LlmRequest): string[] {
  const out: string[] = [];
  for (const m of req.messages) {
    if (m.role !== 'user' || typeof m.content === 'string') {
      if (typeof m.content === 'string') out.push(m.content);
      continue;
    }
    for (const b of m.content) {
      if (b.type === 'text') out.push(b.text);
      else if (b.type === 'tool_result') {
        if (typeof b.content === 'string') out.push(b.content);
        else for (const c of b.content ?? []) if (c.type === 'text') out.push(c.text);
      }
    }
  }
  return out;
}

function toolUsesSoFar(req: LlmRequest): Anthropic.ToolUseBlockParam[] {
  return req.messages
    .filter((m) => m.role === 'assistant' && typeof m.content !== 'string')
    .flatMap((m) => (m.content as Anthropic.ContentBlockParam[]).filter((b): b is Anthropic.ToolUseBlockParam => b.type === 'tool_use'));
}

/** path → (line → code) from every numbered <untrusted_file> block. */
function parseFiles(texts: string[]): Map<string, Map<number, string>> {
  const files = new Map<string, Map<number, string>>();
  for (const t of texts) {
    for (const m of t.matchAll(FILE_BLOCK_RE)) {
      const path = unescapeAttr(m[1] ?? '');
      const lines = files.get(path) ?? new Map<number, string>();
      for (const row of (m[2] ?? '').split('\n')) {
        const r = row.match(/^\s*(\d+) {2}(.*)$/);
        if (r) lines.set(Number(r[1]), r[2] ?? '');
      }
      files.set(path, lines);
    }
  }
  return files;
}

/** file → local import targets, from get_imports results. */
function parseImports(texts: string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const t of texts) {
    let current: string | null = null;
    let section = '';
    for (const row of t.split('\n')) {
      const head = row.match(/^Imports of (.+):$/);
      if (head) { current = head[1]!; out.set(current, []); section = ''; continue; }
      const sec = row.match(/^([A-Za-z ]+):$/);
      if (sec) { section = sec[1]!; continue; }
      const edge = row.match(/^ {2}(\S+) \(line \d+/);
      if (current && section === 'local' && edge) out.get(current)!.push(edge[1]!);
    }
  }
  return out;
}

const sortedLines = (m: Map<number, string>) => [...m.entries()].sort((a, b) => a[0] - b[0]);

/**
 * Deterministic scripted stand-in for the taint agent (MockTransport, mock mode). Answers only requests
 * whose system prompt carries TAINT_TASK_MARKER. It explores like the real agent would — read_file +
 * get_imports on the entrypoint, then reads (and resolves imports of) every local module it reaches — and,
 * once nothing new is left, reports one flow built by pattern matching on the code it actually received:
 * the first `req.query`/`req.params`/`request.args`… line of the entrypoint, the call sites/definitions
 * along the import chain, and the first `query(` / `exec(` / `sendFile(` line reachable from it. Every
 * cited line is copied from a tool result, so the trace verifies. No source or sink → end_turn, no flows.
 */
export const taintMockResponder: MockResponder = (req: LlmRequest) => {
  const system = req.system.map((b) => b.text).join('\n');
  if (!system.includes(TAINT_TASK_MARKER)) return undefined;
  const texts = seenTexts(req);
  const entry = texts[0]?.match(/^Entrypoint: (.+)$/m)?.[1]?.trim();
  if (!entry) return mockText('No entrypoint given.');
  const uses = toolUsesSoFar(req);
  if (uses.some((u) => u.name === 'report_flow')) return mockText('Done: reported the flows found.');
  const turn = req.messages.filter((m) => m.role === 'assistant').length;

  const files = parseFiles(texts.slice(1)); // tool results only: the trace must cite code read with tools
  const imports = parseImports(texts.slice(1));
  const requested = new Set(uses.map((u) => `${u.name}:${(u.input as { path?: string }).path ?? ''}`));

  // Explore: read + resolve imports of every reachable local module (bounded).
  if (turn < MOCK_MAX_TURNS - 1) {
    const calls: Array<{ name: string; input: unknown }> = [];
    const want = (name: string, path: string) => {
      if (!requested.has(`${name}:${path}`)) calls.push({ name, input: { path } });
    };
    if (!files.has(entry)) want('read_file', entry);
    if (!imports.has(entry)) want('get_imports', entry);
    for (const file of files.keys()) if (!imports.has(file)) want('get_imports', file);
    for (const targets of imports.values()) for (const t of targets) if (!files.has(t)) want('read_file', t);
    if (calls.length === 1) return mockToolUse(calls[0]!.name, calls[0]!.input);
    if (calls.length > 1) return mockToolUses(calls);
  }

  const entryLines = files.get(entry);
  const source = entryLines && sortedLines(entryLines).find(([, code]) => MOCK_SOURCE_RE.test(code));
  if (!source) return mockText('No untrusted source found in the entrypoint.');

  // BFS over the import graph from the entrypoint; first file (in BFS order) holding a sink wins.
  const parent = new Map<string, string | null>([[entry, null]]);
  const queue = [entry];
  let found: { file: string; line: number; code: string; sink: (typeof MOCK_SINKS)[number] } | undefined;
  while (queue.length && !found) {
    const file = queue.shift()!;
    const lines = files.get(file);
    if (lines) {
      for (const [line, code] of sortedLines(lines)) {
        if (DEFINITION_RE.test(code)) continue;
        if (file === entry && line < source[0]) continue;
        const sink = MOCK_SINKS.find((s) => s.re.test(code));
        if (sink) { found = { file, line, code, sink }; break; }
      }
    }
    for (const next of imports.get(file) ?? []) {
      if (!parent.has(next)) { parent.set(next, file); queue.push(next); }
    }
  }
  if (!found) return mockText('No dangerous sink reachable from the source.');

  const chain: string[] = [];
  for (let f: string | null | undefined = found.file; f; f = parent.get(f)) chain.unshift(f);
  const trace: TraceStep[] = [{ kind: 'source', file: entry, line: source[0], code: source[1], note: 'Untrusted request input' }];
  for (let i = 0; i + 1 < chain.length; i++) {
    const from = chain[i]!;
    const to = chain[i + 1]!;
    const toLinesMap = files.get(to) ?? new Map<number, string>();
    for (const [defLine, defCode] of sortedLines(toLinesMap)) {
      const m = defCode.match(EXPORTED_NAME_RE);
      const name = m?.[1] ?? m?.[2] ?? m?.[3];
      if (!name) continue;
      const minLine = from === entry ? source[0] : 0;
      const call = sortedLines(files.get(from) ?? new Map<number, string>())
        .find(([l, c]) => l >= minLine && !DEFINITION_RE.test(c) && c.includes(`${name}(`));
      if (!call) continue;
      trace.push({ kind: 'propagator', file: from, line: call[0], code: call[1], note: `Tainted value passed to ${name}() in ${to}` });
      trace.push({ kind: 'propagator', file: to, line: defLine, code: defCode, note: `${name}() receives the tainted value` });
      break;
    }
  }
  trace.push({ kind: 'sink', file: found.file, line: found.line, code: found.code, note: `${found.sink.title} sink` });

  const flow: ReportFlowInput = {
    title: `${found.sink.title} via ${entry}`,
    ruleId: found.sink.ruleId, cwe: found.sink.cwe, severity: found.sink.severity,
    verdict: 'exploitable', confidence: 'medium', trace, sanitizersSeen: [],
    explanation: `Untrusted input read at ${entry}:${source[0]} reaches the ${found.sink.title.toLowerCase()} sink at ${found.file}:${found.line} without sanitization.`,
    impact: 'An attacker controlling this request input can manipulate the dangerous operation.',
    remediation: 'Validate the input against an allow-list and use a safe API (parameterized query, argument array, resolved-path check).',
  };
  return mockToolUse('report_flow', flow);
};
