import { AppError } from '../../errors/AppError';

export type AddedChunk = { commit: string; file: string; lines: { line: number; text: string }[] };

const COMMIT_MARKER = '\0COMMIT ';
const HUNK_HEADER_RE = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;
const NO_NEWLINE_MARKER = '\\ No newline at end of file';

/** Decodes a git-quoted path token (`"b/sp\303\251cial.txt"`) to UTF-8 text; a bare token passes through. */
function decodeGitPathToken(token: string): string {
  if (token.length < 2 || !token.startsWith('"') || !token.endsWith('"')) return token;
  const inner = token.slice(1, -1);
  const bytes: number[] = [];
  const simple: Record<string, number> = { '\\': 0x5c, '"': 0x22, n: 0x0a, t: 0x09, r: 0x0d, a: 0x07, b: 0x08, f: 0x0c, v: 0x0b };
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]!;
    if (ch !== '\\') {
      bytes.push(...Buffer.from(ch, 'utf8'));
      continue;
    }
    const octal = inner.slice(i + 1, i + 4);
    if (/^[0-7]{3}$/.test(octal)) {
      bytes.push(parseInt(octal, 8));
      i += 3;
      continue;
    }
    const next = inner[i + 1];
    if (next !== undefined && simple[next] !== undefined) {
      bytes.push(simple[next]!);
      i += 1;
      continue;
    }
    bytes.push(0x5c); // unrecognized escape: keep the backslash literally
  }
  return Buffer.from(bytes).toString('utf8');
}

/** Target path from a `+++ ` header (prefix already stripped); null for /dev/null. */
function targetPath(rest: string): string | null {
  if (rest === '/dev/null') return null;
  const decoded = decodeGitPathToken(rest);
  return decoded.startsWith('b/') ? decoded.slice(2) : decoded;
}

/**
 * Parse `git log -p --unified=0 … --format=format:%x00COMMIT %H` output into the added lines per
 * (commit, file). Deleted lines, binary files and /dev/null targets are ignored. Header lines
 * (`+++`, `---`, `Binary files`) are only recognised between `diff --git` and the first hunk, so an
 * added line whose content starts with `++ ` is never mistaken for a header.
 */
export function parseGitLogPatch(text: string): AddedChunk[] {
  if (!text) return [];
  const chunks: AddedChunk[] = [];
  let commit: string | null = null;
  let file: string | null = null;
  let inHeader = false;
  let binary = false;
  let newLineNo = 0;
  let current: { line: number; text: string }[] = [];

  const flush = () => {
    if (commit !== null && file !== null && !binary && current.length > 0) chunks.push({ commit, file, lines: current });
    current = [];
  };

  for (const raw of text.split(/\r\n|\r|\n/)) {
    if (raw.startsWith(COMMIT_MARKER)) {
      flush();
      commit = raw.slice(COMMIT_MARKER.length).trim();
      file = null;
      inHeader = false;
      binary = false;
      continue;
    }
    if (raw.startsWith('diff --git ')) {
      flush();
      file = null;
      inHeader = true;
      binary = false;
      continue;
    }
    if (inHeader) {
      if (raw.startsWith('+++ ')) file = targetPath(raw.slice(4));
      else if (raw.startsWith('Binary files ') && raw.endsWith(' differ')) binary = true;
      const hunk = raw.match(HUNK_HEADER_RE);
      if (!hunk) continue;
      inHeader = false;
      newLineNo = Number(hunk[1]!);
      continue;
    }
    if (file === null || binary) continue;
    const hunk = raw.match(HUNK_HEADER_RE);
    if (hunk) {
      newLineNo = Number(hunk[1]!);
      continue;
    }
    if (raw.startsWith(NO_NEWLINE_MARKER)) continue;
    if (raw.startsWith('+')) {
      current.push({ line: newLineNo, text: raw.slice(1) });
      newLineNo++;
    } else if (raw.startsWith(' ')) {
      newLineNo++; // context line — absent with --unified=0, handled defensively
    }
  }
  flush();
  return chunks;
}

export type TextScanner<C> = (
  file: string,
  text: string,
  opts: { source: 'history'; commit: string; lineOffset: (line: number) => number },
) => C[];

const cancelled = () => new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');

/**
 * Scan added lines of recent history. Each chunk's lines are joined with '\n' and passed to `scan`;
 * `lineOffset` maps a joined-text line number (1-based) back to the real line number in that commit.
 */
export async function scanHistory<C>(opts: {
  logPatch: (signal: AbortSignal) => Promise<{ text: string; truncated: boolean }>;
  scan: TextScanner<C>;
  signal: AbortSignal;
  touch?: () => void;
  maxChunkBytes?: number;
}): Promise<{ candidates: C[]; commitsScanned: number; truncated: boolean }> {
  if (opts.signal.aborted) throw cancelled();
  const { text, truncated } = await opts.logPatch(opts.signal);
  if (opts.signal.aborted) throw cancelled();

  const maxChunkBytes = opts.maxChunkBytes ?? 1024 * 1024;
  const commits = new Set<string>();
  for (const m of text.matchAll(/\0COMMIT ([0-9a-f]+)/g)) commits.add(m[1]!);

  const candidates: C[] = [];
  let n = 0;
  for (const chunk of parseGitLogPatch(text)) {
    if (opts.signal.aborted) throw cancelled();
    if (n++ % 50 === 0) opts.touch?.();
    const joined = chunk.lines.map((l) => l.text).join('\n');
    if (Buffer.byteLength(joined, 'utf8') > maxChunkBytes) continue;
    const lineOffset = (line: number): number => chunk.lines[line - 1]?.line ?? line;
    candidates.push(...opts.scan(chunk.file, joined, { source: 'history', commit: chunk.commit, lineOffset }));
  }
  return { candidates, commitsScanned: commits.size, truncated };
}
