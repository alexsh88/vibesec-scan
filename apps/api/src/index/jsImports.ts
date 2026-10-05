import { builtinModules } from 'node:module';
import { posix } from 'node:path';
import type { ImportEdge } from './types';

export type RawImport = { specifier: string; line: number };
export type PathConfig = { dir: string; baseUrl: string | null; paths: Array<{ pattern: string; targets: string[] }> };
export type JsResolveContext = { files: ReadonlySet<string>; pathConfigs: readonly PathConfig[] };
export type JsResolution = Pick<ImportEdge, 'kind' | 'to' | 'pkg'>;

const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));
const EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.json'];
const JS_TO_TS: Record<string, string[]> = { '.js': ['.ts', '.tsx'], '.jsx': ['.tsx'], '.mjs': ['.mts'], '.cjs': ['.cts'] };

const STATIC_RE = /\b(?:import|export)\s+(?:type\s+)?(?:[\w$*{}\s,]+?\s+from\s+)?(['"])([^'"\n]+)\1/g;
const CALL_RE = /\b(?:require|import)\s*\(\s*(['"`])([^'"`\n$]+)\1\s*\)/g;

export function extractJsImports(source: string): RawImport[] {
  const code = stripJsComments(source);
  const lineStarts = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') lineStarts.push(i + 1);
  const lineOf = (index: number) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid]! <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };

  const found = new Map<number, RawImport>();
  for (const re of [STATIC_RE, CALL_RE]) {
    for (const m of code.matchAll(re)) {
      const index = m.index ?? 0;
      if (!found.has(index)) found.set(index, { specifier: m[2]!, line: lineOf(index) });
    }
  }
  return [...found.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
}

const REGEX_CONTEXT_PUNCT = new Set('([{,;:!&|?+-*%^~=<>');
const REGEX_CONTEXT_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await',
]);

/** Whether a '/' appearing right after what's already been emitted starts a regex literal rather than division. */
function isRegexContext(out: string): boolean {
  let j = out.length - 1;
  while (j >= 0 && /\s/.test(out[j]!)) j--;
  if (j < 0) return true;
  const ch = out[j]!;
  if (REGEX_CONTEXT_PUNCT.has(ch)) return true;
  if (!/[A-Za-z0-9_$]/.test(ch)) return false;
  let k = j;
  while (k >= 0 && /[A-Za-z0-9_$]/.test(out[k]!)) k--;
  return REGEX_CONTEXT_KEYWORDS.has(out.slice(k + 1, j + 1));
}

/** Scans a possible regex literal starting at src[start] ('/'). Returns the index just past the closing
 *  unescaped '/' (before flags), or null if a newline or end-of-input is hit first (not a regex literal). */
function scanRegexLiteral(src: string, start: number): number | null {
  let inClass = false;
  let j = start + 1;
  while (j < src.length) {
    const c = src[j]!;
    if (c === '\\' && j + 1 < src.length) { j += 2; continue; }
    if (c === '\n') return null;
    if (c === '[') inClass = true;
    else if (c === ']') inClass = false;
    else if (c === '/' && !inClass) return j + 1;
    j++;
  }
  return null;
}

/** Removes // and /* *\/ comments, keeping string/template/regex contents and newlines intact. */
export function stripJsComments(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    const next = src[i + 1];
    if (ch === '/' && next === '/') {
      while (i < src.length && src[i] !== '\n') i++;
    } else if (ch === '/' && next === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') out += '\n';
        i++;
      }
      i += 2;
    } else if (ch === '/' && isRegexContext(out)) {
      const end = scanRegexLiteral(src, i);
      if (end === null) {
        out += ch;
        i++;
      } else {
        out += src.slice(i, end);
        i = end;
        while (i < src.length && /[a-z]/i.test(src[i]!)) { out += src[i]; i++; }
      }
    } else if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      out += ch;
      i++;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\' && i + 1 < src.length) {
          out += src[i]! + src[i + 1]!;
          i += 2;
          continue;
        }
        if (src[i] === '\n' && quote !== '`') break; // unterminated string: stop at end of line
        out += src[i];
        i++;
      }
      if (i < src.length && src[i] === quote) {
        out += quote;
        i++;
      }
    } else {
      out += ch;
      i++;
    }
  }
  return out;
}

/** Parses tsconfig/jsconfig JSONC; returns null when there is nothing useful for resolution. */
export function parsePathConfig(dir: string, text: string): PathConfig | null {
  let json: { compilerOptions?: { baseUrl?: string; paths?: Record<string, string[]> } };
  try {
    json = JSON.parse(stripJsComments(text).replace(/,\s*([}\]])/g, '$1'));
  } catch {
    return null;
  }
  const options = json.compilerOptions;
  if (!options || (!options.baseUrl && !options.paths)) return null;
  const baseUrl = options.baseUrl !== undefined ? normalize(posix.join(dir, options.baseUrl)) : null;
  const root = baseUrl ?? dir;
  const paths = Object.entries(options.paths ?? {}).map(([pattern, targets]) => ({
    pattern,
    targets: targets
      .map((t) => normalize(posix.join(root, t)))
      .filter((t): t is string => t !== null),
  }));
  return { dir, baseUrl, paths };
}

export function resolveJsImport(fromPath: string, specifier: string, ctx: JsResolveContext): JsResolution {
  if (BUILTINS.has(specifier) || specifier.startsWith('node:')) return { kind: 'builtin', to: null, pkg: null };

  if (specifier.startsWith('.')) {
    const target = normalize(posix.join(posix.dirname(fromPath), specifier));
    return local(target === null ? null : probe(target, ctx.files));
  }
  if (specifier.startsWith('/')) return { kind: 'unresolved', to: null, pkg: null };

  const config = nearestConfig(fromPath, ctx.pathConfigs);
  if (config) {
    for (const { pattern, targets } of config.paths) {
      const wildcard = matchPattern(pattern, specifier);
      if (wildcard === null) continue;
      for (const target of targets) {
        const hit = probe(normalize(target.replace('*', wildcard)), ctx.files);
        if (hit) return local(hit);
      }
    }
    if (config.baseUrl !== null) {
      const hit = probe(normalize(posix.join(config.baseUrl, specifier)), ctx.files);
      if (hit) return local(hit);
    }
  }

  const segments = specifier.split('/');
  const pkg = specifier.startsWith('@') ? segments.slice(0, 2).join('/') : segments[0]!;
  return { kind: 'package', to: null, pkg };
}

function local(path: string | null): JsResolution {
  return path ? { kind: 'local', to: path, pkg: null } : { kind: 'unresolved', to: null, pkg: null };
}

function normalize(path: string): string | null {
  const n = posix.normalize(path).replace(/^\.\//, '');
  if (n === '..' || n.startsWith('../')) return null;
  return n === '.' ? '' : n;
}

function probe(target: string | null, files: ReadonlySet<string>): string | null {
  if (target === null) return null;
  const candidates = [target, ...EXTENSIONS.map((e) => target + e)];
  const ext = posix.extname(target);
  for (const tsExt of JS_TO_TS[ext] ?? []) candidates.push(target.slice(0, -ext.length) + tsExt);
  candidates.push(...EXTENSIONS.map((e) => posix.join(target, `index${e}`)));
  return candidates.find((c) => files.has(c)) ?? null;
}

function nearestConfig(fromPath: string, configs: readonly PathConfig[]): PathConfig | null {
  let best: PathConfig | null = null;
  for (const c of configs) {
    const isAncestor = c.dir === '' || fromPath.startsWith(`${c.dir}/`);
    if (isAncestor && (best === null || c.dir.length > best.dir.length)) best = c;
  }
  return best;
}

/** Returns the text matched by `*` (or '' for an exact pattern), or null when it doesn't match. */
function matchPattern(pattern: string, specifier: string): string | null {
  const star = pattern.indexOf('*');
  if (star === -1) return pattern === specifier ? '' : null;
  const prefix = pattern.slice(0, star);
  const suffix = pattern.slice(star + 1);
  if (!specifier.startsWith(prefix) || !specifier.endsWith(suffix) || specifier.length < prefix.length + suffix.length) return null;
  return specifier.slice(prefix.length, specifier.length - suffix.length);
}
