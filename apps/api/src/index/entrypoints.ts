import { posix } from 'node:path';
import type { Entrypoint } from './types';

const JS_FILE = /\.[cm]?[jt]sx?$/;
const NEXT_ROUTE = /(^|\/)app\/(.+\/)?route\.[cm]?[jt]sx?$/;
const NEXT_API = /(^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/;
const EDGE_FUNCTION = /(^|\/)supabase\/functions\/[^/]+\/index\.[jt]sx?$/;
const NEXT_METHODS = /export\s+(?:async\s+)?(?:function|const|let)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
const JS_ROUTE = /\b(?:app|router|server|fastify|api|routes?|r|[A-Za-z_$][\w$]*(?:Router|App))\s*\.\s*(get|post|put|patch|delete|all|options|head)\s*\(\s*(['"`])(\/[^'"`]*)\2/gi;
const JS_SERVERLESS = /export\s+(?:const|let|async\s+function|function)\s+handler\b|(?:module\.)?exports\.handler\s*=/;
const PY_ROUTE = /^\s*@\s*\w+\.(get|post|put|patch|delete|route|api_route|websocket)\s*\(\s*(['"])([^'"]*)\2/;
const PY_SERVERLESS = /^\s*(?:async\s+)?def\s+(?:lambda_)?handler\s*\(\s*event\b/;
const PY_MAIN = /^if\s+__name__\s*==\s*['"]__main__['"]\s*:/;

export function detectEntrypoints(path: string, content: string): Entrypoint[] {
  if (JS_FILE.test(path)) return detectJs(path, content);
  if (path.endsWith('.py')) return detectPy(path, content);
  return [];
}

function detectJs(path: string, content: string): Entrypoint[] {
  const found: Entrypoint[] = [];
  if (NEXT_ROUTE.test(path)) {
    const methods = [...content.matchAll(NEXT_METHODS)].map((m) => m[1]!);
    found.push({ path, kind: 'next-route', line: null, detail: methods.length ? [...new Set(methods)].join(',') : null });
  }
  if (NEXT_API.test(path)) found.push({ path, kind: 'next-api', line: null, detail: null });
  if (EDGE_FUNCTION.test(path)) found.push({ path, kind: 'edge-function', line: null, detail: null });
  if (/^['"]use server['"]/.test(stripLeadingComments(content))) found.push({ path, kind: 'server-action', line: null, detail: null });

  const lines = content.split(/\r?\n/);
  lines.forEach((text, i) => {
    for (const m of text.matchAll(JS_ROUTE)) {
      found.push({ path, kind: 'http-route', line: i + 1, detail: `${m[1]!.toUpperCase()} ${m[3]}` });
    }
    if (JS_SERVERLESS.test(text)) found.push({ path, kind: 'serverless', line: i + 1, detail: null });
  });
  return found;
}

function detectPy(path: string, content: string): Entrypoint[] {
  const found: Entrypoint[] = [];
  if (posix.basename(path) === 'urls.py' && /\b(?:re_)?path\s*\(/.test(content)) {
    found.push({ path, kind: 'django-urls', line: null, detail: null });
  }
  content.split(/\r?\n/).forEach((text, i) => {
    const route = text.match(PY_ROUTE);
    if (route) {
      const verb = route[1]!.toLowerCase();
      const method = verb === 'route' || verb === 'api_route' ? 'ROUTE' : verb.toUpperCase();
      found.push({ path, kind: 'http-route', line: i + 1, detail: `${method} ${route[3]}` });
    }
    if (PY_SERVERLESS.test(text)) found.push({ path, kind: 'serverless', line: i + 1, detail: null });
    if (PY_MAIN.test(text)) found.push({ path, kind: 'script', line: i + 1, detail: null });
  });
  return found;
}

/** package.json `bin` entries are CLI entrypoints (paths resolved relative to the package.json). */
export function packageJsonBins(path: string, content: string): Entrypoint[] {
  let pkg: { name?: string; bin?: string | Record<string, string> };
  try {
    pkg = JSON.parse(content);
  } catch {
    return [];
  }
  const dir = posix.dirname(path) === '.' ? '' : posix.dirname(path);
  const toPath = (p: string) => posix.normalize(posix.join(dir, p)).replace(/^\.\//, '');
  if (typeof pkg.bin === 'string') {
    return [{ path: toPath(pkg.bin), kind: 'cli', line: null, detail: pkg.name ?? null }];
  }
  if (pkg.bin && typeof pkg.bin === 'object') {
    return Object.entries(pkg.bin).map(([name, p]) => ({ path: toPath(p), kind: 'cli' as const, line: null, detail: name }));
  }
  return [];
}

function stripLeadingComments(content: string): string {
  let s = content.trimStart();
  for (;;) {
    if (s.startsWith('//')) s = s.slice(s.indexOf('\n') === -1 ? s.length : s.indexOf('\n') + 1).trimStart();
    else if (s.startsWith('/*') && s.includes('*/')) s = s.slice(s.indexOf('*/') + 2).trimStart();
    else return s;
  }
}
