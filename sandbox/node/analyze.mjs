#!/usr/bin/env node
/**
 * Offline, read-only "who uses which package API" analyzer for JS/TS repos.
 *
 * Runs with no network access, read-only /src (and optional read-only /deps). Never executes,
 * imports, requires, or evals any code from the repo being scanned — it only parses syntax trees
 * via the TypeScript compiler API (`ts.createSourceFile`, no type-checker `ts.Program`).
 *
 * See ../USAGES.md for the input/output schema and documented behavior/limitations.
 */
import { readFileSync, readdirSync, lstatSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, relative, resolve as presolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', '.git', 'vendor', 'coverage']);
const EXTS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);
const DEFAULT_MAX_FILES = 20_000;
const DEFAULT_MAX_FILE_BYTES = 1_048_576;
const MAX_USAGES = 200_000;

function parseArgs(argv) {
  const opts = { src: '/src', deps: '/deps', in: '/in/packages.json', out: '/out/usages.json' };
  for (const arg of argv) {
    const m = /^--(src|deps|in|out)=([\s\S]*)$/.exec(arg);
    if (m) opts[m[1]] = m[2];
  }
  return opts;
}

function fail(message) {
  process.stderr.write(`analyze.mjs: ${message}\n`);
  process.exit(2);
}

async function loadTs() {
  const tsPath = process.env.TS_PATH;
  if (!tsPath) {
    const mod = await import('typescript');
    return mod.default ?? mod;
  }
  const candidates = [tsPath, join(tsPath, 'lib', 'typescript.js'), join(tsPath, 'typescript.js')];
  let lastErr;
  for (const candidate of candidates) {
    try {
      const mod = await import(pathToFileURL(presolve(candidate)).href);
      return mod.default ?? mod;
    } catch (err) {
      lastErr = err;
    }
  }
  throw new Error(`cannot load typescript from TS_PATH=${tsPath}: ${lastErr?.message}`);
}

function readInput(inPath) {
  let raw;
  try {
    raw = readFileSync(inPath, 'utf8');
  } catch (err) {
    fail(`cannot read input ${inPath}: ${err.message}`);
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    fail(`invalid input JSON at ${inPath}: ${err.message}`);
  }
  if (!data || typeof data !== 'object' || !Array.isArray(data.packages)) {
    fail(`invalid input JSON at ${inPath}: missing "packages" array`);
  }
  return {
    ecosystem: data.ecosystem ?? 'npm',
    packages: data.packages,
    maxFiles: Number.isFinite(data.maxFiles) ? data.maxFiles : DEFAULT_MAX_FILES,
    maxFileBytes: Number.isFinite(data.maxFileBytes) ? data.maxFileBytes : DEFAULT_MAX_FILE_BYTES,
  };
}

function toPosix(p) {
  return p.split('\\').join('/');
}

/** Recursively collects candidate file paths under `dir`, skipping symlinks/ignored dirs/exts/size. */
function collectFiles(dir, maxFileBytes, out, errors) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    errors.push(`readdir failed: ${dir}: ${err.message}`);
    return;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const ent of entries) {
    const full = join(dir, ent.name);
    let lst;
    try {
      lst = lstatSync(full);
    } catch {
      continue;
    }
    if (lst.isSymbolicLink()) continue; // never follow symlinks
    if (lst.isDirectory()) {
      if (SKIP_DIRS.has(ent.name)) continue;
      collectFiles(full, maxFileBytes, out, errors);
      continue;
    }
    if (!lst.isFile()) continue;
    const ext = extname(ent.name);
    if (!EXTS.has(ext)) continue;
    if (ent.name.toLowerCase().endsWith('.min.js')) continue;
    if (lst.size > maxFileBytes) continue; // oversized: skipped silently, not an error
    out.push(full);
  }
}

/** specifier -> { pkgName, importName, remainder } | null. Longest matching importName wins. */
function matchPackage(specifier, packages) {
  let best = null;
  for (const pkg of packages) {
    for (const importName of pkg.importNames ?? []) {
      if (specifier === importName) {
        if (!best || importName.length > best.importName.length) {
          best = { pkgName: pkg.name, importName, remainder: null };
        }
      } else if (specifier.startsWith(`${importName}/`)) {
        if (!best || importName.length > best.importName.length) {
          best = { pkgName: pkg.name, importName, remainder: specifier.slice(importName.length + 1) };
        }
      }
    }
  }
  return best;
}

function subpathSymbol(remainder) {
  if (!remainder) return null;
  const parts = remainder.split('/').filter(Boolean);
  return parts.length ? parts[parts.length - 1] : null;
}

/**
 * The "subpath" is relative to the package's real name, not necessarily to whichever importNames
 * entry matched: an entry can itself be a whole subpath (e.g. importNames: ["lodash", "lodash/merge"])
 * and a specifier that matches it exactly (`lodash/merge`) is still a subpath import of `lodash`.
 */
function deriveRemainder(specifier, match) {
  const { pkgName } = match;
  if (specifier === pkgName) return null;
  if (specifier.startsWith(`${pkgName}/`)) return specifier.slice(pkgName.length + 1);
  return match.remainder; // fallback: importName alias unrelated to the package's own name
}

/**
 * Analyzes one already-read source file. Returns usages (package/line/symbol/kind) and whether
 * the file had syntax errors (still best-effort traversed either way).
 */
function analyzeFile(ts, sourceFile, packages) {
  const usages = [];
  const bindings = new Map(); // localName -> { package, behavior, callSymbol }

  const lineOf = (node) => ts.getLineAndCharacterOfPosition(sourceFile, node.getStart(sourceFile)).line + 1;
  const addUsage = (pkgName, line, symbol, kind) => usages.push({ package: pkgName, line, symbol, kind });

  // Pass 1: import/export/require/dynamic-import forms -> import usages + bindings.
  const visitImports = (node) => {
    if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      const specifier = node.moduleSpecifier.text;
      const match = matchPackage(specifier, packages);
      if (match) {
        const subSym = subpathSymbol(deriveRemainder(specifier, match));
        const clause = node.importClause;
        if (!clause) {
          addUsage(match.pkgName, lineOf(node), null, 'import'); // side-effect import
        } else {
          if (clause.name) {
            const symbol = subSym ?? 'default';
            addUsage(match.pkgName, lineOf(clause.name), symbol, 'import');
            bindings.set(clause.name.text, { package: match.pkgName, behavior: 'callable-default', callSymbol: symbol });
          }
          const named = clause.namedBindings;
          if (named && ts.isNamespaceImport(named)) {
            addUsage(match.pkgName, lineOf(named), null, 'import');
            bindings.set(named.name.text, { package: match.pkgName, behavior: 'namespace-only', callSymbol: null });
          } else if (named && ts.isNamedImports(named)) {
            for (const el of named.elements) {
              const origName = (el.propertyName ?? el.name).text;
              addUsage(match.pkgName, lineOf(el), origName, 'import');
              bindings.set(el.name.text, { package: match.pkgName, behavior: 'named', callSymbol: origName });
            }
          }
        }
      }
    } else if (
      ts.isExportDeclaration(node) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      const match = matchPackage(node.moduleSpecifier.text, packages);
      if (match) {
        const clause = node.exportClause;
        if (!clause || ts.isNamespaceExport(clause)) {
          addUsage(match.pkgName, lineOf(node), null, 'import'); // `export * from` / `export * as ns from`
        } else if (ts.isNamedExports(clause)) {
          for (const el of clause.elements) {
            const origName = (el.propertyName ?? el.name).text;
            addUsage(match.pkgName, lineOf(el), origName, 'import');
          }
        }
      }
    } else if (ts.isImportEqualsDeclaration(node)) {
      const ref = node.moduleReference;
      if (ts.isExternalModuleReference(ref) && ref.expression && ts.isStringLiteral(ref.expression)) {
        const specifier = ref.expression.text;
        const match = matchPackage(specifier, packages);
        if (match) {
          const subSym = subpathSymbol(deriveRemainder(specifier, match));
          const symbol = subSym ?? 'default';
          addUsage(match.pkgName, lineOf(node.name), symbol, 'import');
          bindings.set(node.name.text, { package: match.pkgName, behavior: 'callable-default', callSymbol: symbol });
        }
      }
    } else if (ts.isCallExpression(node)) {
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
      if ((isDynamicImport || isRequire) && node.arguments.length >= 1 && ts.isStringLiteral(node.arguments[0])) {
        const specifier = node.arguments[0].text;
        const match = matchPackage(specifier, packages);
        if (match) {
          const subSym = subpathSymbol(deriveRemainder(specifier, match));
          if (isDynamicImport) {
            addUsage(match.pkgName, lineOf(node), subSym, 'import');
          } else {
            const parent = node.parent;
            if (parent && ts.isVariableDeclaration(parent) && parent.initializer === node) {
              if (ts.isIdentifier(parent.name)) {
                const symbol = subSym ?? null;
                addUsage(match.pkgName, lineOf(parent.name), symbol, 'import');
                bindings.set(parent.name.text, { package: match.pkgName, behavior: 'callable-default', callSymbol: subSym ?? 'default' });
              } else if (ts.isObjectBindingPattern(parent.name)) {
                for (const el of parent.name.elements) {
                  if (ts.isOmittedExpression(el) || !ts.isIdentifier(el.name)) continue;
                  const propName = el.propertyName;
                  if (propName && !ts.isIdentifier(propName)) continue; // computed/string-literal keys: skip
                  const origName = (propName ?? el.name).text;
                  addUsage(match.pkgName, lineOf(el), origName, 'import');
                  bindings.set(el.name.text, { package: match.pkgName, behavior: 'named', callSymbol: origName });
                }
              } else {
                addUsage(match.pkgName, lineOf(node), subSym, 'import');
              }
            } else {
              addUsage(match.pkgName, lineOf(node), subSym, 'import');
            }
          }
        }
      }
    }
    ts.forEachChild(node, visitImports);
  };
  visitImports(sourceFile);

  // Pass 2: call/member usages of the tracked bindings.
  const visitUsages = (node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const binding = bindings.get(node.expression.text);
      if (binding) {
        if (binding.behavior === 'named') addUsage(binding.package, lineOf(node.expression), binding.callSymbol, 'call');
        else if (binding.behavior === 'callable-default') addUsage(binding.package, lineOf(node.expression), binding.callSymbol, 'call');
        // namespace-only: a bare `ns(...)` call is not meaningful; not emitted.
      }
    } else if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
      const binding = bindings.get(node.expression.text);
      if (binding && binding.behavior !== 'named') {
        const memberName = node.name.text;
        const parent = node.parent;
        const isCall = !!parent && ts.isCallExpression(parent) && parent.expression === node;
        addUsage(binding.package, lineOf(node.name), memberName, isCall ? 'call' : 'member');
      }
    }
    ts.forEachChild(node, visitUsages);
  };
  visitUsages(sourceFile);

  return usages;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const input = readInput(opts.in);
  const packages = input.packages
    .filter((p) => p && typeof p.name === 'string')
    .map((p) => ({ name: p.name, importNames: Array.isArray(p.importNames) ? p.importNames.filter((n) => typeof n === 'string') : [] }));

  const errors = [];
  const candidates = [];
  collectFiles(opts.src, input.maxFileBytes, candidates, errors);
  candidates.sort((a, b) => toPosix(relative(opts.src, a)).localeCompare(toPosix(relative(opts.src, b))));

  let files = candidates;
  if (files.length > input.maxFiles) {
    files = files.slice(0, input.maxFiles);
    errors.push(`file list capped at ${input.maxFiles} files`);
  }

  const ts = await loadTs();
  const usageMap = new Map();
  let filesScanned = 0;

  for (const absPath of files) {
    const relPath = toPosix(relative(opts.src, absPath));
    let text;
    try {
      text = readFileSync(absPath, 'utf8');
    } catch (err) {
      errors.push(`${relPath}: read failed: ${err.message}`);
      continue;
    }
    let sourceFile;
    try {
      const scriptKind = /\.tsx$/.test(absPath) ? ts.ScriptKind.TSX
        : /\.jsx$/.test(absPath) ? ts.ScriptKind.JSX
        : /\.(ts|mts|cts)$/.test(absPath) ? ts.ScriptKind.TS
        : ts.ScriptKind.JS;
      sourceFile = ts.createSourceFile(absPath, text, ts.ScriptTarget.Latest, true, scriptKind);
      const diagCount = sourceFile.parseDiagnostics ? sourceFile.parseDiagnostics.length : 0;
      if (diagCount > 0) errors.push(`${relPath}: ${diagCount} syntax error(s), parsed best-effort`);
    } catch (err) {
      errors.push(`${relPath}: parse failed: ${err.message}`);
      continue;
    }
    filesScanned += 1;
    let fileUsages;
    try {
      fileUsages = analyzeFile(ts, sourceFile, packages);
    } catch (err) {
      errors.push(`${relPath}: analysis failed: ${err.message}`);
      continue;
    }
    for (const u of fileUsages) {
      const key = `${relPath}\u0000${u.line}\u0000${u.package}\u0000${u.symbol}\u0000${u.kind}`;
      if (!usageMap.has(key)) usageMap.set(key, { package: u.package, file: relPath, line: u.line, symbol: u.symbol, kind: u.kind });
    }
  }

  let usages = Array.from(usageMap.values());
  usages.sort((a, b) =>
    a.file.localeCompare(b.file) ||
    a.line - b.line ||
    a.package.localeCompare(b.package) ||
    String(a.symbol).localeCompare(String(b.symbol)) ||
    a.kind.localeCompare(b.kind),
  );
  if (usages.length > MAX_USAGES) {
    usages = usages.slice(0, MAX_USAGES);
    errors.push(`usages capped at ${MAX_USAGES}`);
  }

  const output = { version: 1, usages, filesScanned, errors };
  try {
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(opts.out, JSON.stringify(output));
  } catch (err) {
    fail(`cannot write output ${opts.out}: ${err.message}`);
  }
}

main().catch((err) => fail(err?.stack ?? String(err)));
