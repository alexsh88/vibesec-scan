import { describe, expect, it } from 'vitest';
import { parseLockfile } from '../src/analyzers/dependencies/lockfiles/index';
import type { LockfileRef } from '../src/analyzers/dependencies/lockfiles/discover';

function ref(kind: LockfileRef['kind'], path = 'package-lock.json', manifestDir = ''): LockfileRef {
  return { path, kind, manifestDir };
}

describe('npm package-lock v1', () => {
  const manifest = JSON.stringify({
    name: 'demo',
    version: '1.0.0',
    dependencies: { lodash: '^4.17.21' },
    devDependencies: { mocha: '^10.0.0' },
  });

  const lock = JSON.stringify({
    name: 'demo',
    version: '1.0.0',
    lockfileVersion: 1,
    requires: true,
    dependencies: {
      lodash: { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz' },
      mocha: {
        version: '10.2.0',
        resolved: 'https://registry.npmjs.org/mocha/-/mocha-10.2.0.tgz',
        dev: true,
        requires: { ms: '2.1.3', 'supports-color': '8.1.1' },
        dependencies: {
          'supports-color': {
            version: '8.1.1',
            resolved: 'https://registry.npmjs.org/supports-color/-/supports-color-8.1.1.tgz',
            dev: true,
            requires: { 'has-flag': '4.0.0' },
          },
        },
      },
      ms: { version: '2.1.3', resolved: 'https://registry.npmjs.org/ms/-/ms-2.1.3.tgz', dev: true },
      'has-flag': { version: '4.0.0', resolved: 'https://registry.npmjs.org/has-flag/-/has-flag-4.0.0.tgz', dev: true },
    },
  });

  it('resolves direct/transitive deps, nested overrides and scope by reachability', () => {
    const g = parseLockfile(ref('package-lock'), lock, manifest);
    expect(g.ecosystem).toBe('npm');
    expect(g.source).toBe('lockfile');
    expect([...g.nodes.keys()].sort()).toEqual(['npm:has-flag@4.0.0', 'npm:lodash@4.17.21', 'npm:mocha@10.2.0', 'npm:ms@2.1.3', 'npm:supports-color@8.1.1']);

    const lodash = g.nodes.get('npm:lodash@4.17.21')!;
    expect(lodash.direct).toBe(true);
    expect(lodash.scope).toBe('prod');
    expect(lodash.declaredRange).toBe('^4.17.21');

    const mocha = g.nodes.get('npm:mocha@10.2.0')!;
    expect(mocha.direct).toBe(true);
    expect(mocha.scope).toBe('dev');
    expect(mocha.children.sort()).toEqual(['npm:ms@2.1.3', 'npm:supports-color@8.1.1']);

    const supportsColor = g.nodes.get('npm:supports-color@8.1.1')!;
    expect(supportsColor.direct).toBe(false);
    expect(supportsColor.scope).toBe('dev'); // only reachable via the dev root
    expect(supportsColor.children).toEqual(['npm:has-flag@4.0.0']);
    expect(supportsColor.parents).toEqual(['npm:mocha@10.2.0']);

    expect(g.nodes.get('npm:has-flag@4.0.0')!.scope).toBe('dev');
    expect(g.roots.sort()).toEqual(['npm:lodash@4.17.21', 'npm:mocha@10.2.0']);
  });

  it('falls back to lockfile dev flags when no sibling package.json is given', () => {
    const g = parseLockfile(ref('package-lock'), lock);
    expect(g.warnings.some((w) => w.includes('no sibling package.json'))).toBe(true);
    expect(g.nodes.get('npm:lodash@4.17.21')!.direct).toBe(true);
    expect(g.nodes.get('npm:lodash@4.17.21')!.scope).toBe('prod');
  });

  it('never throws on malformed JSON and records a warning instead', () => {
    const g = parseLockfile(ref('package-lock'), '{ not json');
    expect(g.nodes.size).toBe(0);
    expect(g.warnings.length).toBeGreaterThan(0);
  });

  it('ignores a __proto__ key instead of polluting the prototype', () => {
    const malicious = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        __proto__: { version: '9.9.9' },
        safe: { version: '1.0.0' },
      },
    });
    const g = parseLockfile(ref('package-lock'), malicious);
    expect(Object.prototype.hasOwnProperty.call({}, 'polluted')).toBe(false);
    expect([...g.nodes.keys()]).toEqual(['npm:safe@1.0.0']);
  });
});

describe('npm package-lock v2/v3', () => {
  it('resolves nested node_modules, hasInstallScript, non-registry sources and workspaces', () => {
    const lock = JSON.stringify({
      name: 'root',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'root',
          version: '1.0.0',
          workspaces: ['packages/*'],
          dependencies: { a: '^1.0.0' },
          devDependencies: { c: '^1.0.0' },
        },
        'packages/pkg-a': {
          name: '@scope/pkg-a',
          version: '2.0.0',
          dependencies: { d: '^1.0.0' },
        },
        'node_modules/a': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz',
          hasInstallScript: true,
          dependencies: { b: '^2.0.0' },
        },
        'node_modules/a/node_modules/b': {
          version: '2.5.0',
          resolved: 'git+https://github.com/foo/b.git#abc123',
        },
        'node_modules/c': {
          version: '1.0.0',
          dev: true,
          resolved: 'https://registry.npmjs.org/c/-/c-1.0.0.tgz',
        },
        'node_modules/d': {
          version: '1.1.0',
          resolved: 'https://custom-registry.example.com/d/-/d-1.1.0.tgz',
        },
        'node_modules/pkg-a': { resolved: 'packages/pkg-a', link: true },
      },
    });

    const g = parseLockfile(ref('package-lock'), lock);
    expect(g.nodes.get('npm:a@1.0.0')!.hasInstallScript).toBe(true);
    expect(g.nodes.get('npm:b@2.5.0')!.nonRegistrySource).toBe('git');
    expect(g.nodes.get('npm:d@1.1.0')!.nonRegistrySource).toBe('custom-registry.example.com');

    // a -> b via nested node_modules resolution
    expect(g.nodes.get('npm:a@1.0.0')!.children).toEqual(['npm:b@2.5.0']);
    expect(g.nodes.get('npm:b@2.5.0')!.parents).toEqual(['npm:a@1.0.0']);

    // root direct deps: a (prod), c (dev); workspace member pkg-a's own dep d is direct too.
    expect(g.roots.sort()).toEqual(['npm:a@1.0.0', 'npm:c@1.0.0', 'npm:d@1.1.0']);
    expect(g.nodes.get('npm:c@1.0.0')!.scope).toBe('dev');
    expect(g.nodes.get('npm:a@1.0.0')!.scope).toBe('prod');
    expect(g.nodes.get('npm:b@2.5.0')!.scope).toBe('prod'); // reachable from prod root a
    expect(g.nodes.get('npm:c@1.0.0')!.scope).toBe('dev');
    expect(g.nodes.get('npm:d@1.1.0')!.direct).toBe(true);

    // the link entry itself never becomes its own node (no "npm:pkg-a@..." with resolved="packages/pkg-a" path-derived name).
    expect([...g.nodes.keys()].some((k) => k.startsWith('npm:packages/'))).toBe(false);
  });

  it('resolves npm: aliases to the real package name via the packages-map "name" field', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { lodash3: 'npm:lodash@^3.0.0' } },
        'node_modules/lodash3': { name: 'lodash', version: '3.10.1', resolved: 'https://registry.npmjs.org/lodash/-/lodash-3.10.1.tgz' },
      },
    });
    const g = parseLockfile(ref('package-lock'), lock);
    expect([...g.nodes.keys()]).toEqual(['npm:lodash@3.10.1']);
    expect(g.nodes.get('npm:lodash@3.10.1')!.direct).toBe(true);
    expect(g.nodes.get('npm:lodash@3.10.1')!.declaredRange).toBe('npm:lodash@^3.0.0');
  });

  it('caps nodes at the hard limit and emits exactly one warning', () => {
    const packages: Record<string, unknown> = { '': { dependencies: {} } };
    const root = packages[''] as { dependencies: Record<string, string> };
    for (let i = 0; i < 50_010; i++) {
      packages[`node_modules/pkg${i}`] = { version: '1.0.0', resolved: `https://registry.npmjs.org/pkg${i}/-/pkg${i}-1.0.0.tgz` };
      root.dependencies[`pkg${i}`] = '^1.0.0';
    }
    const g = parseLockfile(ref('package-lock'), JSON.stringify({ lockfileVersion: 3, packages }));
    expect(g.nodes.size).toBe(50_000);
    expect(g.warnings.filter((w) => w.includes('node cap'))).toHaveLength(1);
  });
});

describe('package.json manifest-only (no lockfile)', () => {
  it('records declared ranges as unresolved versions with source manifest-only', () => {
    const manifest = JSON.stringify({
      name: 'demo',
      dependencies: { chalk: '^5.0.0' },
      devDependencies: { vitest: '^3.0.0' },
    });
    const g = parseLockfile(ref('package-json', 'package.json'), manifest);
    expect(g.source).toBe('manifest-only');
    expect(g.nodes.get('npm:chalk@^5.0.0')!.direct).toBe(true);
    expect(g.nodes.get('npm:chalk@^5.0.0')!.scope).toBe('prod');
    expect(g.nodes.get('npm:vitest@^3.0.0')!.scope).toBe('dev');
    expect(g.warnings.some((w) => w.includes('no lockfile'))).toBe(true);
  });
});
