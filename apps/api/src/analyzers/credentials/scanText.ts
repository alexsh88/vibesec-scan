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

/**
 * Builds the ±1-line snippet for `match`, with every detected credential value in that range
 * (from `allMatches`, not just `match` itself) swapped for its redacted form, truncated to
 * `SNIPPET_LINE_LIMIT` chars/line. A multi-line `private-key` match that overlaps the window is
 * blanked line-by-line (its raw body never appears verbatim on a single physical line).
 */
function buildSnippet(lines: readonly string[], match: SecretMatch, allMatches: readonly SecretMatch[]): string {
  const windowStart = Math.max(1, match.line - 1);
  const windowEnd = Math.min(lines.length, match.endLine + 1);
  const out: string[] = [];
  for (let ln = windowStart; ln <= windowEnd; ln++) {
    let lineText = lines[ln - 1] ?? '';
    for (const other of allMatches) {
      if (ln < other.line || ln > other.endLine) continue;
      if (lineText.includes(other.value)) {
        lineText = lineText.split(other.value).join(redact(other.value));
      } else if (other.endLine > other.line) {
        // Multi-line credential (e.g. PEM) whose raw value can't appear as a substring of a single
        // physical line — blank this line defensively so no body fragment leaks.
        lineText = ln === other.line ? redact(other.value) : '';
      }
    }
    out.push(lineText.length > SNIPPET_LINE_LIMIT ? lineText.slice(0, SNIPPET_LINE_LIMIT) : lineText);
  }
  return out.join('\n');
}

export function scanText(file: string, text: string, opts: ScanTextOptions = {}): SecretCandidate[] {
  const source = opts.source ?? 'tree';
  const matches = detectSecrets(text);
  const lines = text.split('\n');
  const seen = new Set<string>();
  const out: SecretCandidate[] = [];

  for (const m of matches) {
    const hash = secretHash(m.value);
    const line = opts.lineOffset ? opts.lineOffset(m.line) : m.line;
    const endLine = opts.lineOffset ? opts.lineOffset(m.endLine) : m.endLine;
    const dedupeKey = `${m.type}|${hash}|${line}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const redacted = redact(m.value);
    const lineText = lines[m.line - 1] ?? '';
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
      snippet: buildSnippet(lines, m, matches),
      clientExposed: isClientExposed(file, lineText),
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

/** Runs `fn` over `items` with at most `limit` in flight, preserving nothing but call order per item. */
async function forEachLimit<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const item = items[next++]!;
      await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

/** Reads at most `maxBytes` from the start of the file; returns null for binary (NUL in the
 *  first probe window) or unreadable files. */
async function readTextHead(absPath: string, maxBytes: number): Promise<string | null> {
  const handle = await open(absPath, 'r').catch(() => null);
  if (!handle) return null;
  try {
    const buffer = Buffer.alloc(maxBytes);
    const { bytesRead } = await handle.read(buffer, 0, maxBytes, 0);
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
