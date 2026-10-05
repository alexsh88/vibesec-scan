import { posix } from 'node:path';
import type { ImportEdge } from './types';

export type PyImport = { module: string; level: number; names: string[]; line: number };
export type PyResolveContext = { files: ReadonlySet<string>; roots: readonly string[] };
export type PyResolution = Pick<ImportEdge, 'specifier' | 'kind' | 'to' | 'pkg'>;

// Generated from the local interpreter via:
//   python -c "import sys; print(' '.join(sorted(n for n in sys.stdlib_module_names if not n.startswith('_'))))"
// plus `__future__`, which is special-cased below rather than filtered out.
const STDLIB = new Set(`__future__ abc annotationlib antigravity argparse array ast asyncio atexit base64 bdb binascii
bisect builtins bz2 cProfile calendar cmath cmd code codecs codeop collections colorsys compileall compression concurrent
configparser contextlib contextvars copy copyreg csv ctypes curses dataclasses datetime dbm decimal difflib dis doctest
email encodings ensurepip enum errno faulthandler fcntl filecmp fileinput fnmatch fractions ftplib functools gc
genericpath getopt getpass gettext glob graphlib grp gzip hashlib heapq hmac html http idlelib imaplib importlib inspect
io ipaddress itertools json keyword linecache locale logging lzma mailbox marshal math mimetypes mmap modulefinder
msvcrt multiprocessing netrc nt ntpath nturl2path numbers opcode operator optparse os pathlib pdb pickle pickletools
pkgutil platform plistlib poplib posix posixpath pprint profile pstats pty pwd py_compile pyclbr pydoc pydoc_data pyexpat
queue quopri random re readline reprlib resource rlcompleter runpy sched secrets select selectors shelve shlex shutil
signal site smtplib socket socketserver sqlite3 sre_compile sre_constants sre_parse ssl stat statistics string
stringprep struct subprocess symtable sys sysconfig syslog tabnanny tarfile tempfile termios textwrap this threading
time timeit tkinter token tokenize tomllib trace traceback tracemalloc tty turtle turtledemo types typing unicodedata
unittest urllib uuid venv warnings wave weakref webbrowser winreg winsound wsgiref xml xmlrpc zipapp zipfile zipimport
zlib zoneinfo`
  .split(/\s+/));

// Generated from the local interpreter via:
//   python -c "import sys; print(' '.join(sorted(n for n in sys.stdlib_module_names if n.startswith('_'))))"
// These are real (private) stdlib modules, as opposed to an arbitrary leading-underscore import name
// (e.g. `_cffi_backend`, `_yaml`, `_typeshed`) that merely looks like one — see the `top.startsWith('_')`
// branch below, which now resolves those as 'unresolved' instead of guessing 'builtin'.
/**
 * Stdlib modules removed in Python 3.12/3.13 (distutils, imp, PEP 594 "dead batteries"). Scanned repos often
 * target older Pythons, so these must not be mistaken for third-party packages.
 */
const LEGACY_STDLIB = new Set(`aifc asynchat asyncore audioop cgi cgitb chunk crypt distutils imghdr imp lib2to3 mailcap
msilib nis nntplib ossaudiodev pipes smtpd sndhdr spwd sunau telnetlib uu xdrlib`.split(/\s+/));

const STDLIB_PRIVATE = new Set(`__future__ _abc _aix_support _android_support _apple_support _ast _ast_unparse _asyncio
_bisect _blake2 _bz2 _codecs _codecs_cn _codecs_hk _codecs_iso2022 _codecs_jp _codecs_kr _codecs_tw _collections
_collections_abc _colorize _compat_pickle _contextvars _csv _ctypes _curses _curses_panel _datetime _dbm _decimal
_elementtree _frozen_importlib _frozen_importlib_external _functools _gdbm _hashlib _heapq _hmac _imp _interpchannels
_interpqueues _interpreters _io _ios_support _json _locale _lsprof _lzma _markupbase _md5 _multibytecodec
_multiprocessing _opcode _opcode_metadata _operator _osx_support _overlapped _pickle _posixshmem _posixsubprocess
_py_abc _py_warnings _pydatetime _pydecimal _pyio _pylong _pyrepl _queue _random _remote_debugging _scproxy _sha1
_sha2 _sha3 _signal _sitebuiltins _socket _sqlite3 _sre _ssl _stat _statistics _string _strptime _struct _suggestions
_symtable _sysconfig _thread _threading_local _tkinter _tokenize _tracemalloc _types _typing _uuid _warnings _weakref
_weakrefset _winapi _wmi _zoneinfo _zstd`
  .split(/\s+/));

/** Import name → PyPI distribution, where they differ (lower-cased distribution names). */
export const IMPORT_TO_DISTRIBUTION: Record<string, string> = {
  yaml: 'pyyaml', PIL: 'pillow', sklearn: 'scikit-learn', cv2: 'opencv-python', bs4: 'beautifulsoup4',
  dateutil: 'python-dateutil', dotenv: 'python-dotenv', jwt: 'pyjwt', jose: 'python-jose', Crypto: 'pycryptodome',
  OpenSSL: 'pyopenssl', magic: 'python-magic', multipart: 'python-multipart', psycopg2: 'psycopg2-binary',
  MySQLdb: 'mysqlclient', google: 'google-api-core', attr: 'attrs', serial: 'pyserial', usb: 'pyusb',
  telegram: 'python-telegram-bot', docx: 'python-docx', pptx: 'python-pptx', git: 'gitpython', kafka: 'kafka-python',
  _pytest: 'pytest',
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
    const importerDir = parent(fromPath);
    bases = ctx.roots.includes(importerDir) ? [...ctx.roots] : [...ctx.roots, importerDir];
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
  if (STDLIB.has(top) || STDLIB_PRIVATE.has(top) || LEGACY_STDLIB.has(top)) return [{ specifier, kind: 'builtin', to: null, pkg: null }];
  if (top.startsWith('_') && !(top in IMPORT_TO_DISTRIBUTION)) {
    // Looks like a private stdlib module but isn't one (not in sys.stdlib_module_names) and has no
    // known PyPI distribution — e.g. _cffi_backend, _yaml, _typeshed. Unknown rather than builtin.
    return [{ specifier, kind: 'unresolved', to: null, pkg: null }];
  }
  const pkg = (IMPORT_TO_DISTRIBUTION[top] ?? top).toLowerCase().replace(/_/g, '-').replace(/^-+|-+$/g, '');
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
