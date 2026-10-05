// Light, literal scanner for by-name package references that are NOT imports, so reachability does not
// call a package "unused" just because no source file imports it:
//   npm:  package.json `scripts` (CLI names, incl. common bin → package aliases like tsc → typescript),
//         string literals in tool config files (babel / eslint / jest / webpack / vite / rollup / postcss /
//         tailwind / next / prettier / mocha / tsconfig …, with eslint-plugin- / eslint-config- /
//         babel-plugin- / babel-preset- shorthands), Procfile / Dockerfile CMD / ENTRYPOINT / compose command.
//   PyPI: Procfile, Dockerfile CMD / ENTRYPOINT, compose `command:` (gunicorn / uvicorn / celery / …,
//         `python -m <module>`, worker classes like uvicorn.workers.UvicornWorker).
// Only direct dependencies are looked for; only files in the graph's manifest dir (entrypoint files also at
// the repo root) are read, through the caller's bounded, path-safe reader. Never throws.

import type { IndexedFile } from '../../index/types';
import { npmPackageRoot, packageForImport } from './importNames';
import type { DepGraph, PackageUsage } from './types';

type Read = (rel: string) => Promise<string[] | null>;

const MAX_FILES = 60;
const MAX_REFS = 2_000;

/** CLI binary → npm package for tools whose bin name differs from the package name. */
const NPM_BIN_ALIASES: Record<string, string> = {
  tsc: 'typescript', tsserver: 'typescript', babel: '@babel/cli', 'babel-node': '@babel/node', ng: '@angular/cli',
  'vue-cli-service': '@vue/cli-service', 'svelte-kit': '@sveltejs/kit', playwright: '@playwright/test',
  'run-s': 'npm-run-all', 'run-p': 'npm-run-all', 'pm2-runtime': 'pm2', ncc: '@vercel/ncc', swc: '@swc/cli',
  nest: '@nestjs/cli', sequelize: 'sequelize-cli',
};

/** Console script → PyPI distribution where they differ. */
const PY_BIN_ALIASES: Record<string, string> = {
  'waitress-serve': 'waitress', 'django-admin': 'django',
};

const CONFIG_FILE_RE = new RegExp(
  '^(?:babel\\.config|\\.babelrc|\\.eslintrc|eslint\\.config|jest\\.config|webpack\\.config|vite\\.config|vitest\\.config'
  + '|rollup\\.config|postcss\\.config|tailwind\\.config|next\\.config|nuxt\\.config|svelte\\.config|astro\\.config'
  + '|\\.prettierrc|prettier\\.config|\\.mocharc|\\.stylelintrc|stylelint\\.config|nodemon|tsconfig(?:\\.[\\w-]+)?|lint-staged\\.config|\\.lintstagedrc)'
  + '(?:\\.(?:c|m)?[jt]s|\\.json|\\.ya?ml)?$',
);
const ENTRYPOINT_FILE_RE = /^(?:Procfile|Dockerfile(?:\.[\w.-]+)?|[\w.-]+\.Dockerfile|docker-compose(?:\.[\w.-]+)?\.ya?ml|compose(?:\.[\w.-]+)?\.ya?ml)$/;
const PROCFILE_LINE_RE = /^[A-Za-z0-9_-]+\s*:\s*(.+)$/;
const COMPOSE_LINE_RE = /^-?\s*(?:command|entrypoint)\s*:\s*(.+)$/;
const DOCKER_LINE_RE = /^(?:CMD|ENTRYPOINT)\s+(.+)$/i;

const baseOf = (p: string): string => p.slice(p.lastIndexOf('/') + 1);
const dirOf = (p: string): string => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

/** Words of a shell-ish command line: split on whitespace and shell / JSON-array punctuation. */
function tokens(line: string): string[] {
  return line.split(/[\s;&|()[\],"'=`]+/).filter((t) => t.length > 0 && t.length <= 214);
}

/** The command part of an entrypoint line, or null when the line declares no command. */
function entrypointCommand(file: string, line: string): string | null {
  const t = line.trim();
  const re = baseOf(file) === 'Procfile' ? PROCFILE_LINE_RE : /\.ya?ml$/i.test(file) ? COMPOSE_LINE_RE : DOCKER_LINE_RE;
  const m = t.match(re);
  return m ? m[1]! : null;
}

export async function findPackageReferences(read: Read, files: readonly IndexedFile[], graph: DepGraph): Promise<PackageUsage[]> {
  const direct = [...graph.nodes.values()].filter((n) => n.direct).map((n) => n.name);
  if (direct.length === 0) return [];
  const names = new Set(direct);
  const eco = graph.ecosystem;
  const out: PackageUsage[] = [];
  const seen = new Set<string>();
  const add = (pkg: string, file: string, line: number): void => {
    const k = `${pkg}\0${file}`;
    if (seen.has(k) || out.length >= MAX_REFS) return;
    seen.add(k);
    out.push({ ecosystem: eco, package: pkg, file, line, symbol: null, kind: 'reference' });
  };

  /** npm: the package a CLI word / config string refers to, if it is a direct dependency. */
  const npmTarget = (word: string): string | null => {
    let w = word.replace(/^(?:\.\/)?node_modules\/\.bin\//, '');
    if (w.startsWith('plugin:')) w = w.slice('plugin:'.length);
    const root = w.startsWith('@') ? npmPackageRoot(w) : w.split('/')[0]!;
    for (const cand of [w, root, NPM_BIN_ALIASES[w], `eslint-plugin-${root}`, `eslint-config-${root}`, `babel-plugin-${root}`, `babel-preset-${root}`]) {
      if (cand !== undefined && names.has(cand)) return cand;
    }
    return null;
  };
  /** PyPI: the distribution a command word refers to (console script or module path). */
  const pyTarget = (word: string): string | null => {
    const w = word.split(':')[0]!;
    const alias = PY_BIN_ALIASES[w];
    if (alias !== undefined && names.has(alias)) return alias;
    if (!/^[A-Za-z_][\w.-]*$/.test(w)) return null;
    return packageForImport('PyPI', w, direct) ?? packageForImport('PyPI', w.split('.')[0]!, direct);
  };
  const resolveWord = (word: string): string | null => {
    const hit = eco === 'npm' ? npmTarget(word) : pyTarget(word);
    return hit !== null && names.has(hit) ? hit : null;
  };

  const inScope = (path: string): boolean => {
    const d = dirOf(path);
    return d === graph.manifestDir || (d === '' && ENTRYPOINT_FILE_RE.test(baseOf(path)));
  };
  const relevant = (path: string): boolean => {
    const b = baseOf(path);
    return ENTRYPOINT_FILE_RE.test(b) || (eco === 'npm' && (b === 'package.json' || CONFIG_FILE_RE.test(b)));
  };
  const candidates = files.map((f) => f.path).filter((p) => inScope(p) && relevant(p)).sort().slice(0, MAX_FILES);

  for (const file of candidates) {
    const lines = await read(file);
    if (!lines) continue;
    const base = baseOf(file);
    if (base === 'package.json') {
      // Only the "scripts" object: from its key to the brace that closes it.
      let inScripts = false;
      let depth = 0;
      for (let i = 0; i < lines.length; i++) {
        let line = lines[i]!;
        if (!inScripts) {
          const at = line.indexOf('"scripts"');
          if (at === -1) continue;
          inScripts = true;
          line = line.slice(at + '"scripts"'.length);
        }
        for (const ch of line) {
          if (ch === '{') depth++;
          else if (ch === '}') depth--;
        }
        for (const t of tokens(line.replace(/^\s*"[^"]*"\s*:/, ' '))) {
          const pkg = resolveWord(t);
          if (pkg !== null) add(pkg, file, i + 1);
        }
        if (depth <= 0 && line.includes('}')) break;
      }
      continue;
    }
    if (ENTRYPOINT_FILE_RE.test(base)) {
      for (let i = 0; i < lines.length; i++) {
        const cmd = entrypointCommand(file, lines[i]!);
        if (cmd === null) continue;
        for (const t of tokens(cmd)) {
          const pkg = resolveWord(t);
          if (pkg !== null) add(pkg, file, i + 1);
        }
      }
      continue;
    }
    // Tool config: every quoted string literal.
    for (let i = 0; i < lines.length; i++) {
      for (const m of lines[i]!.matchAll(/["'`]([^"'`\s]{1,214})["'`]/g)) {
        const pkg = resolveWord(m[1]!);
        if (pkg !== null) add(pkg, file, i + 1);
      }
    }
  }
  return out;
}
