// Text/tree credential scanning on top of the pure rules in ./rules.
//
// SECURITY: `SecretCandidate.value` / `pairedSecret` carry the *raw* credential (in-memory only,
// needed by live verifiers). Everything else on the candidate — `redacted`, `hash`, `snippet` —
// is safe to log/persist. `snippet` is built so it NEVER contains any detected raw credential value.

import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import type { IndexedFile, SkipReason } from '../../index/types';
import { detectSecrets, isClientExposed, redact, secretHash } from './rules';
import type { SecretMatch, SecretType } from './rules';

export type SecretCandidate = {
  id: string;
  type: SecretType;
  file: string;
  line: number;
  endLine: number;
  startCol: number;
  /** Raw credential — in-memory only; never persist/log. See file header. */
  value: string;
  redacted: string;
  hash: string;
  snippet: string;
  clientExposed: boolean;
  jwtRole?: string;
  /** Raw, in-memory only. See file header. */
  pairedSecret?: string;
  source: 'tree' | 'history';
  commit?: string;
};

export type ScanTextOptions = {
  source?: 'tree' | 'history';
  commit?: string;
  lineOffset?: (line: number) => number;
};

function candidateId(type: SecretType, file: string, line: number, hash: string): string {
  return createHash('sha256').update(`${type}|${file}|${line}|${hash}`).digest('hex').slice(0, 16);
}

const SNIPPET_LINE_LIMIT = 300;

/** A standalone 40-char run of the AWS secret-access-key alphabet. */
const AWS_SECRET_SHAPE_RE = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g;
const AWS_CONTEXT_RE = /aws|secret/i;

/**
 * Builds ±1-line snippets in which every detected credential (including redact-only matches) is
 * swapped for its redacted form. Matches are pre-indexed by line (multi-line PEMs registered across
 * their whole range) and each redacted line is computed once and cached, so building all snippets for
 * a file is O(text + matches) instead of O(matches²).
 *
 * Rules per line:
 * - a line strictly inside / at the end of a multi-line match (PEM body) is blanked entirely;
 * - single-line matches are replaced by position (startCol + value length), overlapping ones merged;
 * - on any line mentioning aws/secret, every standalone 40-char AWS-secret-shaped token is redacted
 *   too, paired or not — so an AWS secret never survives into a snippet;
 * - lines are truncated to SNIPPET_LINE_LIMIT chars *after* redaction.
 */
class SnippetBuilder {
  private readonly byLine = new Map<number, SecretMatch[]>();
  private readonly cache = new Map<number, string>();

  constructor(private readonly lines: readonly string[], matches: readonly SecretMatch[]) {
    for (const m of matches) {
      for (let ln = m.line; ln <= m.endLine; ln++) {
        const list = this.byLine.get(ln);
        if (list) list.push(m); else this.byLine.set(ln, [m]);
      }
    }
  }

  snippet(match: SecretMatch): string {
    const windowStart = Math.max(1, match.line - 1);
    const windowEnd = Math.min(this.lines.length, match.endLine + 1);
    const out: string[] = [];
    for (let ln = windowStart; ln <= windowEnd; ln++) out.push(this.redactedLine(ln));
    return out.join('\n');
  }

  private redactedLine(ln: number): string {
    const cached = this.cache.get(ln);
    if (cached !== undefined) return cached;
    const raw = this.lines[ln - 1] ?? '';
    const onLine = this.byLine.get(ln) ?? [];
    let text: string;
    if (onLine.some((m) => m.endLine > m.line && ln > m.line)) {
      text = ''; // body/end line of a multi-line credential: never show any fragment
    } else {
      const spans = onLine
        .map((m) => ({
          start: m.startCol - 1,
          end: m.endLine > m.line ? raw.length : m.startCol - 1 + m.value.length,
          replacement: redact(m.value, m.type),
        }))
        .sort((a, b) => a.start - b.start);
      const parts: string[] = [];
      let cursor = 0;
      for (const span of spans) {
        if (span.start < cursor) {
          // Overlaps the previous span: extend the hidden region, nothing new to show.
          cursor = Math.max(cursor, span.end);
          continue;
        }
        parts.push(raw.slice(cursor, span.start), span.replacement);
        cursor = span.end;
      }
      parts.push(raw.slice(cursor));
      text = parts.join('');
      if (AWS_CONTEXT_RE.test(raw)) text = text.replace(AWS_SECRET_SHAPE_RE, (token) => redact(token));
    }
    if (text.length > SNIPPET_LINE_LIMIT) text = text.slice(0, SNIPPET_LINE_LIMIT);
    this.cache.set(ln, text);
    return text;
  }
}

export function scanText(file: string, text: string, opts: ScanTextOptions = {}): SecretCandidate[] {
  const source = opts.source ?? 'tree';
  // Redact-only matches (public-by-design tokens) are never candidates but must still be hidden in
  // every snippet, so the snippet builder sees them all.
  const matches = detectSecrets(text, { includeRedactOnly: true });
  const lines = text.split('\n');
  const snippets = new SnippetBuilder(lines, matches);
  const seen = new Set<string>();
  const out: SecretCandidate[] = [];
  const exposedByLine = new Map<number, boolean>();
  const clientExposedAt = (line: number): boolean => {
    let v = exposedByLine.get(line);
    if (v === undefined) {
      v = isClientExposed(file, lines[line - 1] ?? '');
      exposedByLine.set(line, v);
    }
    return v;
  };

  for (const m of matches) {
    if (m.redactOnly) continue;
    const hash = secretHash(m.value);
    const line = opts.lineOffset ? opts.lineOffset(m.line) : m.line;
    const endLine = opts.lineOffset ? opts.lineOffset(m.endLine) : m.endLine;
    const dedupeKey = `${m.type}|${hash}|${line}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const redacted = redact(m.value, m.type);
    const candidate: SecretCandidate = {
      id: candidateId(m.type, file, line, hash),
      type: m.type,
      file,
      line,
      endLine,
      startCol: m.startCol,
      value: m.value,
      redacted,
      hash,
      snippet: snippets.snippet(m),
      clientExposed: clientExposedAt(m.line),
      source,
    };
    if (m.jwtRole !== undefined) candidate.jwtRole = m.jwtRole;
    if (m.pairedSecret !== undefined) candidate.pairedSecret = m.pairedSecret;
    if (opts.commit !== undefined) candidate.commit = opts.commit;
    out.push(candidate);
  }

  return out;
}

// --- tree scanning -----------------------------------------------------------------------------

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const CONCURRENCY = 16;
const NUL_PROBE_BYTES = 8_192;

/** skipReason values that still get scanned: credentials hide in oversized dumps, minified bundles
 *  and generated configs just as easily as in ordinary source. */
const SCAN_EVEN_IF_SKIPPED: ReadonlySet<SkipReason> = new Set(['too_large', 'minified', 'generated']);
/** skipReason values that are never scanned, even for `.env*` files: unreadable/untrusted content. */
const NEVER_SCAN: ReadonlySet<SkipReason> = new Set(['binary', 'symlink']);

function isEnvFile(path: string): boolean {
  const base = path.split('/').pop() ?? path;
  return base === '.env' || base.startsWith('.env.');
}

function shouldScan(file: IndexedFile): boolean {
  if (file.skipReason !== null && NEVER_SCAN.has(file.skipReason)) return false;
  if (isEnvFile(file.path)) return true;
  if (file.skipReason === null) return true;
  return SCAN_EVEN_IF_SKIPPED.has(file.skipReason);
}

/** Runs `fn` over `items` with at most `limit` in flight. As soon as any call throws (e.g. on abort),
 *  a shared flag stops every other worker from picking up further items. */
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
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

/** Reads at most `maxBytes` from the start of the file; returns null for binary (NUL in the
 *  first probe window) or unreadable files. The buffer is sized min(file size, maxBytes). */
async function readTextHead(absPath: string, maxBytes: number): Promise<string | null> {
  const handle = await open(absPath, 'r').catch(() => null);
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

export type ScanTreeOptions = {
  repoDir: string;
  files: readonly IndexedFile[];
  signal: AbortSignal;
  touch?: () => void;
  maxFileBytes?: number;
};

export type ScanTreeResult = { candidates: SecretCandidate[]; filesScanned: number; skipped: number };

export async function scanTree(opts: ScanTreeOptions): Promise<ScanTreeResult> {
  const maxFileBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const resolvedRepoDir = resolve(opts.repoDir);
  const repoDirPrefix = resolvedRepoDir + sep;
  const isWithinRepoDir = (absPath: string) => absPath === resolvedRepoDir || absPath.startsWith(repoDirPrefix);

  const candidateFiles = opts.files.filter(shouldScan);
  let skipped = opts.files.length - candidateFiles.length;
  let filesScanned = 0;
  let processed = 0;
  const perFile: SecretCandidate[][] = [];

  await forEachLimit(candidateFiles, CONCURRENCY, async (file) => {
    if (opts.signal.aborted) throw opts.signal.reason;

    const absPath = resolve(join(opts.repoDir, ...file.path.split('/')));
    if (!isWithinRepoDir(absPath)) {
      skipped++;
    } else {
      const text = await readTextHead(absPath, maxFileBytes);
      if (opts.signal.aborted) throw opts.signal.reason; // don't burn CPU scanning after an abort
      if (text === null) {
        skipped++;
      } else {
        filesScanned++;
        perFile.push(scanText(file.path, text, { source: 'tree' }));
      }
    }

    processed++;
    if (processed % 200 === 0) opts.touch?.();
  });

  opts.touch?.();
  return { candidates: perFile.flat(), filesScanned, skipped };
}
