# Sandbox package-usage analyzers

Two offline, static analyzers answer "who uses which package API": `sandbox/node/analyze.mjs`
(TypeScript/JavaScript, via the TypeScript compiler API) and `sandbox/python/analyze.py` (Python,
via `ast`). Both run inside the offline scan sandbox (`--network none`, read-only `/src`, optional
read-only `/deps`) and are also runnable directly on the host (tests do this) by overriding the
default paths with CLI flags. Neither ever executes, imports, or `eval`s any code from the
repository being scanned — they only parse syntax trees.

## Invocation

```
node sandbox/node/analyze.mjs [--src=/src] [--deps=/deps] [--in=/in/packages.json] [--out=/out/usages.json]
python sandbox/python/analyze.py [--src=/src] [--deps=/deps] [--in=/in/packages.json] [--out=/out/usages.json]
```

All four flags default to the container paths shown. `--deps` may point at a directory that
doesn't exist; it is simply unused today (reserved for future resolution of re-exports through
installed packages).

The Node analyzer resolves the `typescript` package via the `TS_PATH` environment variable
(a path to the installed `typescript` package directory, or directly to its `lib/typescript.js`)
when set, otherwise via normal Node module resolution relative to the script.

## Input — `/in/packages.json`

```json
{
  "ecosystem": "npm",
  "packages": [
    { "name": "lodash", "importNames": ["lodash", "lodash/merge"] },
    { "name": "pyyaml", "importNames": ["yaml"] }
  ],
  "maxFiles": 20000,
  "maxFileBytes": 1048576
}
```

`importNames` lists every module specifier / top-level module name under which the package may be
imported, including known subpaths. A source-file specifier matches a package when it equals one
of its `importNames` exactly, or starts with one of them followed by `/` (so `lodash/debounce`
matches the `"lodash"` entry, and `lodash/merge` matches either entry — the longest matching
`importNames` entry wins). Scoped npm packages (`@scope/pkg`) work the same way since the whole
scoped name is just a string in `importNames`.

`maxFiles` and `maxFileBytes` are optional; defaults are 20000 and 1048576 respectively if omitted.

## Output — `/out/usages.json`

```json
{
  "version": 1,
  "usages": [
    { "package": "lodash", "file": "src/a.ts", "line": 3, "symbol": "merge", "kind": "call" }
  ],
  "filesScanned": 42,
  "errors": []
}
```

- Paths are repo-relative, forward-slash separated, regardless of host OS.
- `usages` is sorted by `(file, line, package, symbol, kind)` and deduplicated (identical
  `(package, file, line, symbol, kind)` tuples collapse to one entry).
- `errors` holds non-fatal, human-readable strings: per-file read/parse failures, and cap
  notices (e.g. `"usages capped at 200000"`, `"file list capped at 20000 files"`). The process
  still exits `0` when `errors` is non-empty.
- Total `usages` entries are capped at 200000; if more were found, a note is appended to `errors`
  and the excess (by sort order) is dropped.
- The process exits non-zero **only** for a bad input JSON file or an unwritable output path.
  Any other problem (unreadable file, syntax error, oversized file, missing `/deps`) is recorded
  in `errors` and scanning continues.

## File selection

Both analyzers walk `/src` (never following symlinks — checked via `lstat`/`os.path.islink`),
skipping directories named `node_modules`, `dist`, `build`, `.git`, `vendor`, `coverage` (Node) /
`.git`, `venv`, `.venv`, `site-packages`, `node_modules`, `build`, `dist`, `__pycache__` (Python).
Files over `maxFileBytes` are silently skipped (not an error). The Node analyzer additionally
skips minified files (`*.min.js`) and only considers `.js .jsx .mjs .cjs .ts .tsx .mts .cts`
extensions; the Python analyzer only considers `*.py`. If the candidate file list exceeds
`maxFiles`, the excess (sorted by repo-relative path) is dropped and a note is appended to
`errors`.

## Node analyzer — recognized forms and behavior

Parses each file independently with `ts.createSourceFile` (no `ts.Program`/type-checker — fast and
memory-bounded). Recognized specifier forms, each producing one `kind: "import"` usage per bound
name:

- `import x from 'pkg'` → symbol `"default"`.
- `import { a as b } from 'pkg/sub'` → symbol `"a"` (the *original* imported name, never the local
  alias); one usage per named specifier.
- `import * as ns from 'pkg'` → symbol `null`.
- `import 'pkg'` (side effect) → symbol `null`.
- `export * from 'pkg'` / `export * as ns from 'pkg'` → symbol `null`.
- `export { c as d } from 'pkg'` → symbol `"c"` (the original name).
- `require('pkg')` → symbol `null` (or the subpath-derived name, see below); whole-module
  `require` has no ESM "default" concept of its own.
- `const { merge } = require('lodash')` / `const { merge: m } = require('lodash')` → symbol
  `"merge"` (the original name).
- `import('pkg')` with a string literal (dynamic import) → symbol `null` (or subpath-derived).
  Dynamic imports with a template/expression specifier are ignored (can't be resolved statically).
- `import x = require('pkg')` (TS import-equals) → same rule as `import x from 'pkg'`.
- **Subpath imports** (`lodash/merge`) that bind the *whole* subpath module (default import,
  bare `require`, bare dynamic import, or `import x = require(...)`, i.e. no destructuring/named
  specifiers) → symbol is the subpath's last path segment (`"merge"`), replacing `"default"`/`null`.

After the import is recorded, each local binding is tracked (by name only, no scope analysis) for
later `call`/`member` usages, best-effort:

- **default / require-whole-module / subpath-default bindings** (`x` in `import x from 'pkg'`,
  `const x = require('pkg')`, `import x = require('pkg')`, or the subpath forms above):
  - `x(...)` → `kind: "call"`, symbol `"default"` (or the subpath-derived name for subpath
    bindings).
  - `x.merge(...)` → `kind: "call"`, symbol `"merge"`.
  - `x.merge` (not called) → `kind: "member"`, symbol `"merge"`.
- **namespace bindings** (`ns` in `import * as ns from 'pkg'`): same member/call-on-member rules
  as above (`ns.merge(...)` / `ns.merge`); a bare `ns(...)` call is not emitted (a namespace
  object is not meaningfully callable).
- **named bindings** (`b` in `import { a as b } from 'pkg'`, or `merge`/`m` from destructured
  `require`): only `b(...)` is tracked → `kind: "call"`, symbol is the *original* imported name
  (`"a"` / `"merge"`), never the local alias.

### Known limitations (documented, not bugs)

- **No scope analysis.** Bindings are tracked by name across the whole file. A local variable,
  parameter, or shadowing import that reuses an imported binding's name in an unrelated scope can
  produce a false-positive `call`/`member` usage (e.g. a function parameter named `merge` that is
  called inside that function will be reported as a `lodash` usage even though it is unrelated).
  This is an accepted trade-off for speed and simplicity.
- `require('pkg')` used inline without being assigned to a variable or destructured (e.g.
  `require('pkg').fn()`) is recorded only as the `import` usage; the chained `.fn()` access is not
  separately tracked.
- Dynamic `import('pkg')` results (and their destructured bindings, e.g.
  `const { merge } = await import('pkg')`) are not tracked for further `call`/`member` usages —
  only the `import` usage itself is recorded.
- `import type { … }` (type-only imports) are treated the same as value imports; they produce the
  same `import` usage even though they vanish at runtime.
- A file with syntax errors is still best-effort traversed (the TypeScript parser recovers and
  produces a partial tree); an entry is appended to `errors` noting the syntax error count, and
  whatever real imports/usages the recovered tree exposes are still reported.

## Python analyzer — recognized forms and behavior

Parses each file with `ast.parse` (never `exec`/`eval`/`import`s the target code). Recognized
forms, each producing one `kind: "import"` usage:

- `import yaml` → symbol `null`; binds `yaml`.
- `import yaml as y` → symbol `null`; binds `y`.
- `import a.b.c` → symbol `null`; binds the full dotted path `a.b.c` as one binding name (per
  Python semantics, only the top-level name `a` is actually assigned in the namespace, but
  attribute access chains through the dotted path, so the binding is tracked by its full dotted
  name — see below).
- `from yaml import load` → symbol `"load"`; binds `load`.
- `from yaml import safe_load as sl` → symbol `"safe_load"` (the original name); binds `sl`.
- `from yaml.loader import Loader` → symbol `"Loader"`; package matched via the dotted module
  `yaml.loader` (checked against `importNames` both whole and by dotted-prefix, so `"yaml"` in
  `importNames` matches `yaml.loader`).
- Relative imports (`from . import x`, `from .sibling import y`) are always ignored — they refer to
  local modules, never a third-party package.

Module → package matching: a module name matches an `importNames` entry when it equals the entry
exactly, or when the entry is a dotted-prefix of it (`entry == module` or
`module.startswith(entry + '.')`).

Usage tracking after an import, best-effort, by local name only (no scope analysis):

- **`from pkg import load`** (binding `load`, symbol `"load"`): `load(...)` → `kind: "call"`,
  symbol `"load"` (the original name, even if aliased locally).
- **`import yaml as y` / `import a.b.c`** (whole-module binding): `y.safe_load(...)` →
  `kind: "call"`, symbol `"safe_load"`; `y.FullLoader` (not called) → `kind: "member"`, symbol
  `"FullLoader"`. For a dotted `import a.b.c`, attribute access is resolved relative to the bound
  name `a` and only reported once the access walks past the full imported dotted path — e.g. with
  `import a.b.c`, `a.b.c.func()` → `kind: "call"`, symbol `"func"` (the first attribute **after**
  the imported dotted path); `a.b.other` (an attribute that diverges before reaching the end of
  `a.b.c`) is not reported, since it isn't actually a reference into the `a.b.c` submodule.

### Known limitations (documented, not bugs)

- **No scope analysis**, same trade-off as the Node analyzer: a shadowing local name can produce a
  false-positive usage.
- Syntax errors (`SyntaxError` from `ast.parse`) are caught per file, recorded in `errors` with the
  file path and message, and scanning continues with the next file — the broken file contributes
  no usages.
- A recursion-limit guard catches `RecursionError` from pathologically deep/nested ASTs per file
  (recorded in `errors`), so one adversarial file cannot abort the whole scan.
- Star imports (`from pkg import *`) are not resolved to individual symbols (Python gives no static
  way to know what names landed in scope without executing the module); they are ignored (no
  usage recorded) rather than guessed at.

## Platform note (symlinks)

Both analyzers check "is this a symlink" before descending into a directory or reading a file
(`lstat`/`os.path.islink`), which is correct and sufficient on the Linux container the sandbox
actually runs in. On Windows hosts specifically, Python's `os.path.islink()` does not recognize
NTFS junction points (a directory-only reparse point creatable without elevated privilege) as
links, while Node's `fs.lstatSync().isSymbolicLink()` does; a junction could therefore be
followed by the Python analyzer on a Windows host (not in the Linux sandbox, where this distinction
doesn't exist). True Windows symlinks (`mklink`/`fs.symlinkSync` without `'junction'`) are detected
correctly by both.

## Determinism, caps, and safety

- Usages are deduplicated and sorted identically by both analyzers (see Output above), independent
  of filesystem traversal order (file lists are themselves sorted by repo-relative path before
  scanning, so caps truncate deterministically too).
- Both analyzers are read-only with respect to the repository: they only ever read `/src` (and
  optionally stat `/deps`, unused today), write only `/out/usages.json`, and never spawn processes,
  make network calls, or import/exec anything from the scanned repository.
