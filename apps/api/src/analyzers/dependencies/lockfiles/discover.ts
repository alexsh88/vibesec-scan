// Locates lockfiles/manifests in the repo index and decides, per directory, which single file of
// each ecosystem family to parse (a lockfile always wins over a manifest-only fallback).

import { posix } from 'node:path';

export type LockfileKind =
  | 'package-lock' | 'npm-shrinkwrap' | 'pnpm-lock' | 'yarn-lock'
  | 'poetry-lock' | 'pipfile-lock' | 'uv-lock' | 'requirements' | 'pyproject'
  | 'package-json';

export type LockfileRef = { path: string; kind: LockfileKind; manifestDir: string };

/** These directories are never scanned for lockfiles, wherever they occur in the tree. */
const VENDOR_SEGMENTS = new Set(['node_modules', 'site-packages', '.venv', 'venv', 'vendor', 'third_party']);

/** skipReason values that mean "don't trust this content at all" — still skipped even though the
 *  task explicitly wants generated/lockfile/too_large files parsed. */
const NEVER_DISCOVER: ReadonlySet<string> = new Set(['binary', 'symlink', 'submodule']);

function isVendored(path: string): boolean {
  const segments = path.split('/');
  for (let i = 0; i < segments.length - 1; i++) {
    if (VENDOR_SEGMENTS.has(segments[i]!)) return true;
  }
  return false;
}

function dirOf(path: string): string {
  const d = posix.dirname(path);
  return d === '.' ? '' : d;
}

const NPM_PRECEDENCE: { basename: string; kind: LockfileKind }[] = [
  { basename: 'npm-shrinkwrap.json', kind: 'npm-shrinkwrap' },
  { basename: 'package-lock.json', kind: 'package-lock' },
  { basename: 'pnpm-lock.yaml', kind: 'pnpm-lock' },
  { basename: 'yarn.lock', kind: 'yarn-lock' },
];

const PY_LOCK_PRECEDENCE: { basename: string; kind: LockfileKind }[] = [
  { basename: 'poetry.lock', kind: 'poetry-lock' },
  { basename: 'uv.lock', kind: 'uv-lock' },
  { basename: 'Pipfile.lock', kind: 'pipfile-lock' },
];

export function discoverLockfiles(files: readonly { path: string; skipReason: string | null }[]): LockfileRef[] {
  // dir -> basename -> repo-relative path
  const byDir = new Map<string, Map<string, string>>();
  for (const f of files) {
    if (f.skipReason !== null && NEVER_DISCOVER.has(f.skipReason)) continue;
    if (isVendored(f.path)) continue;
    const dir = dirOf(f.path);
    const base = posix.basename(f.path);
    let m = byDir.get(dir);
    if (!m) {
      m = new Map();
      byDir.set(dir, m);
    }
    m.set(base, f.path);
  }

  const refs: LockfileRef[] = [];
  for (const [dir, basenames] of byDir) {
    const npmHit = NPM_PRECEDENCE.find((c) => basenames.has(c.basename));
    if (npmHit) {
      refs.push({ path: basenames.get(npmHit.basename)!, kind: npmHit.kind, manifestDir: dir });
    } else if (basenames.has('package.json')) {
      refs.push({ path: basenames.get('package.json')!, kind: 'package-json', manifestDir: dir });
    }

    const pyHit = PY_LOCK_PRECEDENCE.find((c) => basenames.has(c.basename));
    if (pyHit) {
      refs.push({ path: basenames.get(pyHit.basename)!, kind: pyHit.kind, manifestDir: dir });
    } else {
      const reqPaths = [...basenames.entries()]
        .filter(([base]) => /^requirements.*\.txt$/i.test(base))
        .map(([, p]) => p);
      if (reqPaths.length > 0) {
        for (const p of reqPaths) refs.push({ path: p, kind: 'requirements', manifestDir: dir });
      } else if (basenames.has('pyproject.toml')) {
        refs.push({ path: basenames.get('pyproject.toml')!, kind: 'pyproject', manifestDir: dir });
      }
    }
  }

  refs.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return refs;
}
