import { posix } from 'node:path';
import type { ImportEdge } from './types';

export type PyImport = { module: string; level: number; names: string[]; line: number };
export type PyResolveContext = { files: ReadonlySet<string>; roots: readonly string[] };
export type PyResolution = Pick<ImportEdge, 'specifier' | 'kind' | 'to' | 'pkg'>;

const STDLIB = new Set(`__future__ abc argparse array ast asyncio atexit base64 binascii bisect builtins bz2 calendar cmath
codecs collections colorsys concurrent configparser contextlib contextvars copy copyreg csv ctypes dataclasses datetime
decimal difflib dis email encodings enum errno faulthandler fcntl filecmp fileinput fnmatch fractions ftplib functools gc
getopt getpass gettext glob graphlib gzip hashlib heapq hmac html http imaplib importlib inspect io ipaddress itertools
json keyword linecache locale logging lzma mailbox math mimetypes mmap multiprocessing netrc numbers operator optparse os
pathlib pdb pickle pkgutil platform plistlib poplib posixpath pprint profile pstats pty pwd queue quopri random re
readline reprlib resource runpy sched secrets select selectors shelve shlex shutil signal site smtplib socket
socketserver sqlite3 ssl stat statistics string struct subprocess sys sysconfig syslog tarfile tempfile termios
textwrap threading time timeit tkinter token tokenize tomllib trace traceback tracemalloc tty types typing unicodedata
unittest urllib uuid venv warnings wave weakref webbrowser winreg wsgiref xml xmlrpc zipapp zipfile zipimport zlib zoneinfo`
  .split(/\s+/));

/** Import name → PyPI distribution, where they differ (lower-cased distribution names). */
export const IMPORT_TO_DISTRIBUTION: Record<string, string> = {
  yaml: 'pyyaml', PIL: 'pillow', sklearn: 'scikit-learn', cv2: 'opencv-python', bs4: 'beautifulsoup4',
  dateutil: 'python-dateutil', dotenv: 'python-dotenv', jwt: 'pyjwt', jose: 'python-jose', Crypto: 'pycryptodome',
  OpenSSL: 'pyopenssl', magic: 'python-magic', multipart: 'python-multipart', psycopg2: 'psycopg2-binary',
  MySQLdb: 'mysqlclient', google: 'google-api-core', attr: 'attrs', serial: 'pyserial', usb: 'pyusb',
  telegram: 'python-telegram-bot', docx: 'python-docx', pptx: 'python-pptx', git: 'gitpython', kafka: 'kafka-python',
};

const IMPORT_RE = /^\s*import\s+(.+)$/;
const FROM_RE = /^\s*from\s+(\.*)([\w.]*)\s+import\s+(.+)$/;

export function extractPyImports(source: string): PyImport[] {
  const lines = source.split(/\r?\n/);
  const result: PyImport[] = [];
  let inTripleQuote: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const startLine = i + 1;
    let line = lines[i]!;

    const codeOnly = stripComment(line);
    const quotes = codeOnly.match(/"""|'''/g) ?? [];
    if (inTripleQuote) {
      if (quotes.filter((q) => q === inTripleQuote).length % 2 === 1) inTripleQuote = null;
      continue;
    }
    if (quotes.length % 2 === 1) {
      inTripleQuote = quotes[quotes.length - 1]!;
      continue;
    }

    line = stripComment(line);
    while (line.trimEnd().endsWith('\\') && i + 1 < lines.length) {
      line = line.trimEnd().slice(0, -1) + ' ' + stripComment(lines[++i]!);
    }
    if (/^\s*from\s.+\simport\s*\(/.test(line) && !line.includes(')')) {
      while (i + 1 < lines.length && !line.includes(')')) line += ' ' + stripComment(lines[++i]!);
    }

    const from = line.match(FROM_RE);
    if (from) {
      const names = from[3]!.replace(/[()]/g, ' ').split(',')
        .map((n) => n.trim().split(/\s+/)[0] ?? '')
        .filter((n) => n.length > 0 && n !== '*');
      result.push({ module: from[2]!, level: from[1]!.length, names, line: startLine });
      continue;
    }
    const imp = line.match(IMPORT_RE);
    if (imp) {
      for (const part of imp[1]!.split(',')) {
        const module = part.trim().split(/\s+/)[0];
        if (module && /^[\w.]+$/.test(module)) result.push({ module, level: 0, names: [], line: startLine });
      }
    }
  }
  return result;
}

export function pythonRoots(files: ReadonlySet<string>): string[] {
  const roots = [''];
  const add = (r: string) => { if (!roots.includes(r)) roots.push(r); };
  const all = [...files];
  if (all.some((f) => f.startsWith('src/') && f.endsWith('.py'))) add('src');
  for (const f of all) {
    const base = posix.basename(f);
    if (base !== 'pyproject.toml' && base !== 'setup.py' && base !== 'setup.cfg') continue;
    const dir = posix.dirname(f) === '.' ? '' : posix.dirname(f);
    add(dir);
    const src = dir ? `${dir}/src` : 'src';
    if (all.some((p) => p.startsWith(`${src}/`) && p.endsWith('.py'))) add(src);
  }
  return roots;
}

export function resolvePyImport(fromPath: string, imp: PyImport, ctx: PyResolveContext): PyResolution[] {
  const prefix = '.'.repeat(imp.level);
  const modulePath = imp.module ? imp.module.split('.').join('/') : '';
  const parent = (p: string) => (posix.dirname(p) === '.' ? '' : posix.dirname(p));

  let bases: string[];
  if (imp.level > 0) {
    let dir = parent(fromPath);
    const depth = dir === '' ? 0 : dir.split('/').length;
    if (imp.level - 1 > depth) {
      return [{ specifier: `${prefix}${imp.module}`, kind: 'unresolved', to: null, pkg: null }];
    }
    for (let up = 1; up < imp.level; up++) dir = parent(dir);
    bases = [dir];
  } else {
    bases = [...ctx.roots];
  }

  for (const base of bases) {
    const moduleDir = [base, modulePath].filter(Boolean).join('/');
    const moduleFile = findModule(moduleDir, ctx.files);
    const submodules = imp.names
      .map((name) => ({ name, file: findModule([moduleDir, name].filter(Boolean).join('/'), ctx.files) }))
      .filter((s): s is { name: string; file: string } => s.file !== null);
    if (!moduleFile && submodules.length === 0) continue;
    const results: PyResolution[] = [];
    if (moduleFile) results.push({ specifier: `${prefix}${imp.module}`, kind: 'local', to: moduleFile, pkg: null });
    for (const s of submodules) {
      const spec = imp.module ? `${prefix}${imp.module}.${s.name}` : `${prefix}${s.name}`;
      results.push({ specifier: spec, kind: 'local', to: s.file, pkg: null });
    }
    return results;
  }

  const specifier = `${prefix}${imp.module}`;
  if (imp.level > 0) return [{ specifier, kind: 'unresolved', to: null, pkg: null }];
  const top = imp.module.split('.')[0]!;
  if (STDLIB.has(top)) return [{ specifier, kind: 'builtin', to: null, pkg: null }];
  const pkg = (IMPORT_TO_DISTRIBUTION[top] ?? top).toLowerCase().replace(/_/g, '-');
  return [{ specifier, kind: 'package', to: null, pkg }];
}

function findModule(path: string, files: ReadonlySet<string>): string | null {
  if (!path) return files.has('__init__.py') ? '__init__.py' : null;
  if (files.has(`${path}.py`)) return `${path}.py`;
  if (files.has(`${path}/__init__.py`)) return `${path}/__init__.py`;
  return null;
}

function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '#') {
      return line.slice(0, i);
    }
  }
  return line;
}
