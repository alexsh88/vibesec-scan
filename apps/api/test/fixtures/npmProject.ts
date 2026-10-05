// Builds a matching package.json + package-lock.json (v3) pair for dependency-analyzer tests.
// Pretty-printed (2 spaces) so every dependency sits on its own line, like real files.

export type NpmPkgSpec = {
  version: string;
  dependencies?: Record<string, string>;
  dev?: boolean;
  hasInstallScript?: boolean;
  resolved?: string;
};

export function npmProject(opts: {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  /** lockfile `packages` entries keyed by install path, e.g. `node_modules/qs`. */
  packages: Record<string, NpmPkgSpec>;
}): { packageJson: string; packageLock: string } {
  const name = opts.name ?? 'fixture-app';
  const manifest = {
    name, version: '1.0.0',
    ...(opts.dependencies ? { dependencies: opts.dependencies } : {}),
    ...(opts.devDependencies ? { devDependencies: opts.devDependencies } : {}),
  };
  const packages: Record<string, unknown> = { '': manifest };
  for (const [path, spec] of Object.entries(opts.packages)) {
    const pkgName = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
    packages[path] = {
      version: spec.version,
      resolved: spec.resolved ?? `https://registry.npmjs.org/${pkgName}/-/${pkgName.split('/').pop()}-${spec.version}.tgz`,
      ...(spec.dependencies ? { dependencies: spec.dependencies } : {}),
      ...(spec.dev ? { dev: true } : {}),
      ...(spec.hasInstallScript ? { hasInstallScript: true } : {}),
    };
  }
  const lock = { name, version: '1.0.0', lockfileVersion: 3, requires: true, packages };
  return { packageJson: `${JSON.stringify(manifest, null, 2)}\n`, packageLock: `${JSON.stringify(lock, null, 2)}\n` };
}
