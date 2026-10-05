import { describe, expect, it } from 'vitest';
import { parseLockfile } from '../src/analyzers/dependencies/lockfiles/index';
import type { LockfileRef } from '../src/analyzers/dependencies/lockfiles/discover';

function ref(path = 'pnpm-lock.yaml', manifestDir = ''): LockfileRef {
  return { path, kind: 'pnpm-lock', manifestDir };
}

describe('pnpm-lock.yaml v6', () => {
  const yaml = `
lockfileVersion: '6.0'

dependencies:
  a:
    specifier: ^1.0.0
    version: 1.0.0
devDependencies:
  c:
    specifier: ^1.0.0
    version: 1.0.0

packages:
  /a@1.0.0:
    resolution: {integrity: sha512-aaa}
    dependencies:
      b: 2.0.0
    dev: false
  /b@2.0.0:
    resolution: {integrity: sha512-bbb}
    dev: false
  /c@1.0.0:
    resolution: {integrity: sha512-ccc}
    dev: true
  /@scope/d@3.0.0:
    resolution: {integrity: sha512-ddd}
    dev: true
`;

  it('resolves direct/transitive deps and scope-by-reachability', () => {
    const g = parseLockfile(ref(), yaml);
    expect(g.ecosystem).toBe('npm');
    expect([...g.nodes.keys()].sort()).toEqual(['npm:@scope/d@3.0.0', 'npm:a@1.0.0', 'npm:b@2.0.0', 'npm:c@1.0.0']);
    expect(g.roots.sort()).toEqual(['npm:a@1.0.0', 'npm:c@1.0.0']);
    expect(g.nodes.get('npm:a@1.0.0')!.children).toEqual(['npm:b@2.0.0']);
    expect(g.nodes.get('npm:b@2.0.0')!.scope).toBe('prod');
    expect(g.nodes.get('npm:c@1.0.0')!.scope).toBe('dev');
    expect(g.nodes.get('npm:a@1.0.0')!.declaredRange).toBe('^1.0.0');
  });

  it('never throws on malformed YAML', () => {
    const g = parseLockfile(ref(), 'not: [valid: yaml: at all :::');
    expect(g.nodes.size).toBe(0);
    expect(g.warnings.length).toBeGreaterThan(0);
  });
});

describe('pnpm-lock.yaml v9', () => {
  const yaml = `
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      react-dom:
        specifier: ^18.2.0
        version: 18.2.0(react@18.2.0)
    devDependencies:
      c:
        specifier: ^1.0.0
        version: 1.0.0

packages:
  react-dom@18.2.0:
    resolution: {integrity: sha512-xxx}
    peerDependencies:
      react: ^18.2.0
  react@18.2.0:
    resolution: {integrity: sha512-yyy}
  c@1.0.0:
    resolution: {integrity: sha512-zzz}

snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
  react@18.2.0: {}
  c@1.0.0: {}
`;

  it('resolves importers direct deps and snapshot edges, stripping peer-context suffixes', () => {
    const g = parseLockfile(ref(), yaml);
    expect([...g.nodes.keys()].sort()).toEqual(['npm:c@1.0.0', 'npm:react-dom@18.2.0', 'npm:react@18.2.0']);
    expect(g.roots.sort()).toEqual(['npm:c@1.0.0', 'npm:react-dom@18.2.0']);
    expect(g.nodes.get('npm:react-dom@18.2.0')!.children).toEqual(['npm:react@18.2.0']);
    expect(g.nodes.get('npm:react@18.2.0')!.scope).toBe('prod');
    expect(g.nodes.get('npm:c@1.0.0')!.scope).toBe('dev');
  });

  it('supports multiple importers (workspace members) as additional direct-dep sources', () => {
    const multi = `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0
  packages/pkg-a:
    dependencies:
      b:
        specifier: ^2.0.0
        version: 2.0.0
packages:
  a@1.0.0:
    resolution: {integrity: sha512-a}
  b@2.0.0:
    resolution: {integrity: sha512-b}
snapshots:
  a@1.0.0: {}
  b@2.0.0: {}
`;
    const g = parseLockfile(ref(), multi);
    expect(g.roots.sort()).toEqual(['npm:a@1.0.0', 'npm:b@2.0.0']);
  });
});
