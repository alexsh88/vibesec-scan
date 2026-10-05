/**
 * Read-only, confined repository tools for the code agents (taint agent, credential hunter).
 *
 * Everything the model can see is limited to files in the P2 index:
 * - paths are normalized and rejected when absolute, containing `..`, NUL, backslashes or a `.git` segment;
 * - read_file / grep only open indexed files, refuse binary / symlink / submodule entries, lstat every path
 *   component (no symlinked file or directory on the way) and require the realpath to stay inside repoDir;
 * - list_dir is derived from the index (never the live filesystem), so it cannot reveal unindexed paths.
 * Repository content returned to the model is wrapped with untrustedFile/untrustedText; the system prompt's
 * UNTRUSTED_POLICY (appended by buildRequestParts) covers tool results too.
 *
 * Regex grep: model-supplied patterns are length-capped, statically screened (nested quantifiers, quantified
 * alternations, backreferences) and executed inside a `vm` context with a timeout (the per-call matching budget, default 1.5 s), so even a pattern that
 * slips through the screen cannot hang the scan (V8 interrupts a running regex on timeout).
 */
import { lstat, open, realpath } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import vm from 'node:vm';
import { z } from 'zod';
import { SEVERITIES, TaintStepSchema } from '@vibesec/shared';
import type { ImportEdge, IndexedFile } from '../../index/types';
import { defineTool, type AgentTool } from '../../llm/LlmClient';
import { untrustedFile, untrustedText } from '../../llm/prompt';

export const READ_FILE_MAX_LINES = 400;
export const READ_FILE_MAX_BYTES = 256 * 1024;
export const LIST_DIR_MAX_ENTRIES = 500;
export const GREP_MAX_HITS = 100;
export const GREP_HIT_TEXT_MAX = 200;
export const GREP_PATTERN_MAX = 200;
export const GREP_DEFAULT_TIME_BUDGET_MS = 1_500;
/** Lines are cut to this length before regex matching (bounds polynomial backtracking). */
const REGEX_LINE_MAX = 2_000;
const READ_LINE_MAX = 1_000;
/** Whole-call limit for a search including (cold) file reads. */
const GREP_IO_DEADLINE_MS = 30_000;
const READ_CONCURRENCY = 16;
const NUL_PROBE_BYTES = 8_000;
const CACHE_MAX_CHARS = 64 * 1024 * 1024;
const UNREADABLE: ReadonlySet<IndexedFile['skipReason']> = new Set(['binary', 'symlink', 'submodule']);

export class RepoToolError extends Error {}

// ---------------------------------------------------------------------------------------------
// report_flow input (defined by the taint analyzer; shared here for reuse)
// ---------------------------------------------------------------------------------------------

export const ReportFlowInput = z.object({
  title: z.string().min(3).max(200).describe('Short title, e.g. "SQL injection in GET /users/:id"'),
  ruleId: z.string().min(1).max(100).describe("e.g. 'taint/sql-injection'"),
  cwe: z.string().regex(/^CWE-\d+$/).optional().describe("e.g. 'CWE-89'"),
  severity: z.enum(SEVERITIES),
  verdict: z.enum(['exploitable', 'sanitized', 'uncertain']),
  confidence: z.enum(['high', 'medium', 'low']),
  trace: z.array(TaintStepSchema).min(2)
    .refine((t) => t[0]?.kind === 'source' && t[t.length - 1]?.kind === 'sink', { message: 'the first step must be a source and the last a sink' })
    .describe('Ordered steps from the untrusted source to the dangerous sink'),
  sanitizersSeen: z.array(z.string()).describe('Sanitizers/validators on the path (empty if none)'),
  explanation: z.string().min(1),
  impact: z.string().min(1),
  remediation: z.string().min(1),
  patch: z.string().optional().describe('Optional unified diff fixing the issue'),
});
export type ReportFlowInput = z.infer<typeof ReportFlowInput>;

// ---------------------------------------------------------------------------------------------
// Path confinement
// ---------------------------------------------------------------------------------------------

/** Normalized repo-relative path ('' = repo root). Throws RepoToolError for anything unsafe. */
export function normalizeRepoPath(raw: string): string {
  if (raw.length > 1_024) throw new RepoToolError('Path is too long');
  if (raw.includes('\0')) throw new RepoToolError('Path contains a NUL byte');
  if (raw.includes('\\')) throw new RepoToolError('Use forward slashes in paths');
  if (raw.startsWith('/') || /^[A-Za-z]:/.test(raw)) throw new RepoToolError('Paths must be relative to the repository root');
  const segments = raw.split('/').filter((s) => s !== '' && s !== '.');
  if (segments.includes('..')) throw new RepoToolError('Paths must not contain ".."');
  if (segments.some((s) => s.toLowerCase() === '.git')) throw new RepoToolError('The .git directory is not accessible');
  return segments.join('/');
}

// ---------------------------------------------------------------------------------------------
// Regex safety
// ---------------------------------------------------------------------------------------------

/** Why a model-supplied regex is rejected, or null when it passes the static screen. */
export function regexProblem(src: string): string | null {
  if (src.length > GREP_PATTERN_MAX) return `pattern longer than ${GREP_PATTERN_MAX} characters`;
  if (/\\[1-9]|\\k</.test(src)) return 'backreferences are not allowed';
  const groups: Array<{ quantified: boolean; alternation: boolean }> = [];
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') { i++; continue; }
    if (inClass) { if (c === ']') inClass = false; continue; }
    if (c === '[') { inClass = true; continue; }
    const top = groups[groups.length - 1];
    if (c === '(') { groups.push({ quantified: false, alternation: false }); continue; }
    if (c === ')') {
      const group = groups.pop();
      if (!group) continue;
      const next = src[i + 1];
      const repeated = next === '*' || next === '+' || next === '{';
      if (repeated && (group.quantified || group.alternation)) return 'nested or alternated quantifiers like (a+)+ or (a|b)* are not allowed';
      const parent = groups[groups.length - 1];
      if (parent && (group.quantified || repeated)) parent.quantified = true;
      continue;
    }
    if (c === '|' && top) { top.alternation = true; continue; }
    if ((c === '*' || c === '+' || c === '{') && top) top.quantified = true;
  }
  try {
    new RegExp(src);
  } catch (err) {
    return `invalid regular expression (${(err as Error).message})`;
  }
  return null;
}

/** Minimal glob → RegExp: `**` any depth, `*` / `?` within a segment, `{a,b}` alternatives. */
function globToRegExp(glob: string): RegExp {
  let re = '';
  let inBrace = false;
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*' && glob[i + 1] === '*') {
      if (glob[i + 2] === '/') { re += '(?:.*/)?'; i += 2; } else { re += '.*'; i += 1; }
    } else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '{' && !inBrace) { re += '(?:'; inBrace = true; }
    else if (c === '}' && inBrace) { re += ')'; inBrace = false; }
    else if (c === ',' && inBrace) re += '|';
    else re += c.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  }
  if (inBrace) re += ')';
  return new RegExp(`^${re}$`);
}

// ---------------------------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------------------------

export type RepoToolsOptions = {
  repoDir: string;
  /** Index file list (P2). Only these files are visible; skipped entries are listed but not searchable. */
  files: readonly IndexedFile[];
  /** All import edges of the index, or a per-file lookup (then get_imports cannot report importers). */
  imports: readonly ImportEdge[] | ((path: string) => readonly ImportEdge[]);
  signal?: AbortSignal;
  grepTimeBudgetMs?: number;
  now?: () => number;
};

type Lines = string[];

export function createRepoTools(opts: RepoToolsOptions): AgentTool[] {
  const root = resolve(opts.repoDir);
  const now = opts.now ?? Date.now;
  const timeBudget = opts.grepTimeBudgetMs ?? GREP_DEFAULT_TIME_BUDGET_MS;
  const index = new Map(opts.files.map((f) => [f.path, f]));
  const searchable = opts.files.filter((f) => f.skipReason === null).map((f) => f.path).sort();
  const cache = new Map<string, Lines>();
  let cachedChars = 0;
  let realRoot: Promise<string> | undefined;
  /** Memoized lstat verdict per directory prefix (symlinked directories are never traversed). */
  const dirChecks = new Map<string, Promise<'ok' | 'symlink' | 'missing'>>();
  /** Unreadable files are remembered so repeated searches skip them cheaply. */
  const failures = new Map<string, RepoToolError>();

  const checkAbort = (signal?: AbortSignal) => {
    if (opts.signal?.aborted || signal?.aborted) throw new RepoToolError('Cancelled');
  };

  /** Confined read of an indexed file: lstat every component, realpath inside repoDir, size cap, binary probe. */
  async function readLines(path: string): Promise<Lines> {
    const cached = cache.get(path);
    if (cached) return cached;
    const failed = failures.get(path);
    if (failed) throw failed;
    try {
      return await readLinesUncached(path);
    } catch (err) {
      const error = err instanceof RepoToolError ? err : new RepoToolError(`${path} could not be read`);
      failures.set(path, error);
      throw error;
    }
  }

  async function readLinesUncached(path: string): Promise<Lines> {
    const file = index.get(path);
    if (!file) throw new RepoToolError(`${path} is not in the repository index (unknown, excluded or not a file)`);
    if (UNREADABLE.has(file.skipReason)) throw new RepoToolError(`${path} cannot be read (${file.skipReason})`);
    const segments = path.split('/');
    for (let i = 1; i < segments.length; i++) {
      const dir = segments.slice(0, i).join('/');
      let check = dirChecks.get(dir);
      if (!check) {
        check = lstat(join(root, ...segments.slice(0, i))).then(
          (st) => (st.isSymbolicLink() ? 'symlink' : st.isDirectory() ? 'ok' : 'missing'),
          () => 'missing' as const,
        );
        dirChecks.set(dir, check);
      }
      const state = await check;
      if (state === 'symlink') throw new RepoToolError(`${path} goes through a symbolic link and cannot be read`);
      if (state === 'missing') throw new RepoToolError(`${path} does not exist in the checkout`);
    }
    const st = await lstat(join(root, ...segments)).catch(() => null);
    if (!st) throw new RepoToolError(`${path} does not exist in the checkout`);
    if (st.isSymbolicLink()) throw new RepoToolError(`${path} is a symbolic link and cannot be read`);
    if (!st.isFile()) throw new RepoToolError(`${path} is not a regular file`);
    realRoot ??= realpath(root);
    const realRootDir = await realRoot;
    const real = await realpath(join(root, ...segments));
    if (!real.startsWith(realRootDir + sep)) throw new RepoToolError(`${path} resolves outside the repository`);
    const handle = await open(real, 'r');
    let text: string;
    try {
      const { size } = await handle.stat();
      if (size > READ_FILE_MAX_BYTES) throw new RepoToolError(`${path} is larger than ${READ_FILE_MAX_BYTES / 1024} KiB; use grep to find the relevant lines`);
      const buffer = Buffer.alloc(size);
      let read = 0;
      while (read < size) {
        const { bytesRead } = await handle.read(buffer, read, size - read, read);
        if (bytesRead === 0) break;
        read += bytesRead;
      }
      if (buffer.subarray(0, Math.min(NUL_PROBE_BYTES, read)).includes(0)) throw new RepoToolError(`${path} is a binary file`);
      text = buffer.subarray(0, read).toString('utf8');
    } finally {
      await handle.close();
    }
    const lines = text.split(/\r?\n/);
    if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
    if (cachedChars + text.length <= CACHE_MAX_CHARS) {
      cache.set(path, lines);
      cachedChars += text.length;
    }
    return lines;
  }

  type Hit = { path: string; line: number; text: string };
  /**
   * Scans searchable files (optionally glob-filtered) with `matchFile` (returns matching 0-based line
   * indexes, at most `max`). Stops at GREP_MAX_HITS or the time budget.
   */
  async function scan(
    glob: string | undefined, signal: AbortSignal | undefined,
    matchFile: (lines: Lines, max: number, remainingMs: number) => number[] | 'timeout',
  ): Promise<{ hits: Hit[]; timedOut: boolean; more: boolean; unreadable: number }> {
    // Two limits: `timeBudget` bounds the time spent MATCHING (the ReDoS concern), independent of how
    // slow cold file reads are; GREP_IO_DEADLINE_MS bounds the whole call including I/O.
    const ioDeadline = now() + GREP_IO_DEADLINE_MS;
    let matchMs = 0;
    let candidates = searchable;
    if (glob) {
      const re = globToRegExp(normalizeGlob(glob));
      const onBase = !glob.includes('/');
      candidates = candidates.filter((p) => re.test(onBase ? p.slice(p.lastIndexOf('/') + 1) : p));
    }
    const hits: Hit[] = [];
    let unreadable = 0;
    for (let c = 0; c < candidates.length; c += READ_CONCURRENCY) {
      checkAbort(signal);
      if (now() > ioDeadline) return { hits, timedOut: true, more: false, unreadable };
      const chunk = candidates.slice(c, c + READ_CONCURRENCY);
      const loaded = await Promise.all(chunk.map((p) => readLines(p).catch(() => null)));
      for (let k = 0; k < chunk.length; k++) {
        const path = chunk[k]!;
        const lines = loaded[k];
        if (!lines) { unreadable++; continue; }
        const remaining = timeBudget - matchMs;
        if (remaining <= 0) return { hits, timedOut: true, more: false, unreadable };
        const t0 = now();
        const found = matchFile(lines, GREP_MAX_HITS - hits.length + 1, remaining);
        matchMs += now() - t0;
        if (found === 'timeout') return { hits, timedOut: true, more: false, unreadable };
        for (const i of found) {
          if (hits.length === GREP_MAX_HITS) return { hits, timedOut: false, more: true, unreadable };
          hits.push({ path, line: i + 1, text: clip((lines[i] ?? '').trim(), GREP_HIT_TEXT_MAX) });
        }
      }
    }
    return { hits, timedOut: false, more: false, unreadable };
  }

  function renderHits(source: string, r: Awaited<ReturnType<typeof scan>>): string {
    const notes: string[] = [];
    if (r.more) notes.push(`(stopped at ${GREP_MAX_HITS} matches — narrow the pattern or add a glob)`);
    if (r.timedOut) notes.push('(search stopped: time budget exhausted — results are partial; narrow the pattern or add a glob)');
    if (r.unreadable) notes.push(`(${r.unreadable} file(s) could not be read)`);
    if (r.hits.length === 0) return ['No matches.', ...notes].join('\n');
    const body = r.hits.map((h) => `${h.path}:${h.line}: ${h.text}`).join('\n');
    return [`${r.hits.length} match(es):`, untrustedText(source, body), ...notes].join('\n');
  }

  /** Trusted (internally built, linear) regex or plain substring, matched in-process with a deadline. */
  const inProcessMatcher = (test: (line: string) => boolean) => (lines: Lines, max: number, remainingMs: number): number[] | 'timeout' => {
    const deadline = now() + remainingMs;
    const out: number[] = [];
    for (let i = 0; i < lines.length && out.length < max; i++) {
      if ((i & 255) === 255 && now() > deadline) return 'timeout';
      if (test(lines[i]!)) out.push(i);
    }
    return out;
  };

  /** Model-supplied regex: compiled and run inside a vm context whose timeout interrupts runaway backtracking. */
  function sandboxedMatcher(source: string, flags: string) {
    const context = vm.createContext(Object.create(null) as object);
    vm.runInContext(
      `var re = new RegExp(${JSON.stringify(source)}, ${JSON.stringify(flags)});
       function scanLines(lines, max) { var out = []; for (var i = 0; i < lines.length && out.length < max; i++) { if (re.test(lines[i])) out.push(i); } return out; }`,
      context,
    );
    return (lines: Lines, max: number, remainingMs: number): number[] | 'timeout' => {
      (context as { lines?: string[]; max?: number }).lines = lines.map((l) => (l.length > REGEX_LINE_MAX ? l.slice(0, REGEX_LINE_MAX) : l));
      (context as { max?: number }).max = max;
      try {
        const found = vm.runInContext('scanLines(lines, max)', context, { timeout: Math.max(1, Math.floor(remainingMs)) }) as number[];
        return Array.from(found);
      } catch (err) {
        if ((err as { code?: string }).code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') return 'timeout';
        throw err;
      }
    };
  }

  const edgesOf = (path: string): readonly ImportEdge[] =>
    typeof opts.imports === 'function' ? opts.imports(path) : opts.imports.filter((e) => e.from === path);

  const pathArg = z.string().max(1_024);

  return [
    defineTool({
      name: 'list_dir',
      description: `List a directory of the repository (indexed files only). Directories end with "/". At most ${LIST_DIR_MAX_ENTRIES} entries. Use "" or "." for the root.`,
      input: z.object({ path: pathArg.describe('Repository-relative directory, e.g. "src/routes"') }),
      run: ({ path }) => {
        const dir = normalizeRepoPath(path);
        const prefix = dir ? `${dir}/` : '';
        const dirs = new Set<string>();
        const files: string[] = [];
        for (const f of opts.files) {
          if (!f.path.startsWith(prefix)) continue;
          const rest = f.path.slice(prefix.length);
          const slash = rest.indexOf('/');
          if (slash >= 0) dirs.add(`${rest.slice(0, slash)}/`);
          else files.push(f.skipReason ? `${rest}  [skipped: ${f.skipReason}]` : rest);
        }
        if (dir && dirs.size === 0 && files.length === 0) {
          if (index.has(dir)) throw new RepoToolError(`${dir} is a file; use read_file`);
          throw new RepoToolError(`No indexed directory ${dir}`);
        }
        const entries = [...[...dirs].sort(), ...files.sort()];
        const shown = entries.slice(0, LIST_DIR_MAX_ENTRIES);
        const more = entries.length - shown.length;
        return untrustedText(`list_dir ${dir || '.'}`, shown.join('\n')) + (more > 0 ? `\n(${more} more entries not shown)` : '');
      },
    }),
    defineTool({
      name: 'read_file',
      description: `Read lines of an indexed text file, numbered. At most ${READ_FILE_MAX_LINES} lines per call (files up to ${READ_FILE_MAX_BYTES / 1024} KiB); use startLine/endLine to page.`,
      input: z.object({
        path: pathArg.describe('Repository-relative file path'),
        startLine: z.number().int().positive().optional(),
        endLine: z.number().int().positive().optional(),
      }),
      run: async ({ path, startLine, endLine }, ctx) => {
        const p = normalizeRepoPath(path);
        if (!p) throw new RepoToolError('A file path is required');
        checkAbort(ctx.signal);
        const lines = await readLines(p);
        const total = lines.length;
        const start = startLine ?? 1;
        if (total === 0 || (total === 1 && lines[0] === '')) return `${p} is empty.`;
        if (start > total) throw new RepoToolError(`${p} has only ${total} lines`);
        const end = Math.min(total, endLine ?? start + READ_FILE_MAX_LINES - 1, start + READ_FILE_MAX_LINES - 1);
        if (end < start) throw new RepoToolError('endLine must not be before startLine');
        const width = String(end).length;
        const body = lines.slice(start - 1, end)
          .map((l, i) => `${String(start + i).padStart(width)}  ${clip(l, READ_LINE_MAX)}`).join('\n');
        const footer = end < total ? `\n(lines ${start}-${end} of ${total}; continue with startLine=${end + 1})` : `\n(lines ${start}-${end} of ${total})`;
        return untrustedFile(p, body) + footer;
      },
    }),
    defineTool({
      name: 'grep',
      description: `Search indexed text files. Plain substring by default; set regex=true for a JavaScript regular expression (max ${GREP_PATTERN_MAX} chars, no nested quantifiers or backreferences). Optional glob filter (e.g. "*.ts", "src/**/*.py"). Up to ${GREP_MAX_HITS} hits as file:line: text.`,
      input: z.object({
        pattern: z.string().min(1).max(GREP_PATTERN_MAX),
        glob: z.string().min(1).max(200).optional(),
        regex: z.boolean().optional(),
        ignoreCase: z.boolean().optional(),
      }),
      run: async ({ pattern, glob, regex, ignoreCase }, ctx) => {
        let matcher;
        if (regex) {
          const problem = regexProblem(pattern);
          if (problem) throw new RepoToolError(`Regex rejected: ${problem}`);
          matcher = sandboxedMatcher(pattern, ignoreCase ? 'i' : '');
        } else {
          const needle = ignoreCase ? pattern.toLowerCase() : pattern;
          matcher = inProcessMatcher(ignoreCase ? (l) => l.toLowerCase().includes(needle) : (l) => l.includes(needle));
        }
        return renderHits(`grep ${pattern}`, await scan(glob, ctx.signal, matcher));
      },
    }),
    defineTool({
      name: 'find_references',
      description: `Find whole-word occurrences of an identifier across indexed text files (up to ${GREP_MAX_HITS} hits).`,
      input: z.object({ symbol: z.string().regex(/^[A-Za-z_$][\w$]{0,99}$/, 'must be a single identifier') }),
      run: async ({ symbol }, ctx) => {
        const re = new RegExp(`(?<![\\w$])${symbol.replace(/\$/g, '\\$')}(?![\\w$])`);
        return renderHits(`references ${symbol}`, await scan(undefined, ctx.signal, inProcessMatcher((l) => re.test(l))));
      },
    }),
    defineTool({
      name: 'get_imports',
      description: 'Imports of an indexed file from the repository index: resolved local files, packages, builtins, unresolved specifiers, and (when available) the files that import it.',
      input: z.object({ path: pathArg }),
      run: ({ path }) => {
        const p = normalizeRepoPath(path);
        if (!index.has(p)) throw new RepoToolError(`${p || '.'} is not in the repository index`);
        const edges = edgesOf(p);
        const fmt = (e: ImportEdge) => {
          const target = e.kind === 'local' ? e.to : e.kind === 'package' ? e.pkg : e.specifier;
          return `  ${target} (line ${e.line}, ${JSON.stringify(e.specifier)})`;
        };
        const section = (title: string, kind: ImportEdge['kind']) => {
          const list = edges.filter((e) => e.kind === kind);
          return list.length ? [`${title}:`, ...list.map(fmt)] : [];
        };
        const out = [
          `Imports of ${p}:`,
          ...section('local', 'local'), ...section('packages', 'package'), ...section('builtins', 'builtin'), ...section('unresolved', 'unresolved'),
        ];
        if (edges.length === 0) out.push('  (none)');
        if (typeof opts.imports !== 'function') {
          const importers = opts.imports.filter((e) => e.kind === 'local' && e.to === p);
          out.push('Imported by:', ...(importers.length ? importers.map((e) => `  ${e.from} (line ${e.line})`) : ['  (none)']));
        }
        return untrustedText(`imports ${p}`, out.join('\n'));
      },
    }),
  ];
}

function normalizeGlob(glob: string): string {
  if (glob.includes('\0') || glob.includes('\\')) throw new RepoToolError('Invalid glob');
  return glob.replace(/^\.\//, '');
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
