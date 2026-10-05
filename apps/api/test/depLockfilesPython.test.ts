import { describe, expect, it } from 'vitest';
import { parseLockfile } from '../src/analyzers/dependencies/lockfiles/index';
import { buildRequirementsGraph, extractPyprojectDirect } from '../src/analyzers/dependencies/lockfiles/python';
import { normalizePypiName } from '../src/analyzers/dependencies/lockfiles/graph';
import type { LockfileRef } from '../src/analyzers/dependencies/lockfiles/discover';

function ref(kind: LockfileRef['kind'], path: string, manifestDir = ''): LockfileRef {
  return { path, kind, manifestDir };
}

describe('normalizePypiName', () => {
  it('applies PEP 503 normalization', () => {
    expect(normalizePypiName('Django_Rest.Framework')).toBe('django-rest-framework');
    expect(normalizePypiName('  Foo--Bar__Baz..Qux  ')).toBe('foo-bar-baz-qux');
  });
});

describe('poetry.lock', () => {
  const pyproject = `[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
`;

  const lock = `[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"

[package.dependencies]
certifi = ">=2017.4.17"
idna = ">=2.5,<4"

[[package]]
name = "certifi"
version = "2023.7.22"
description = "Certifi"
optional = false
python-versions = ">=3.6"

[[package]]
name = "idna"
version = "3.4"
description = "IDNA"
optional = false
python-versions = ">=3.5"

[[package]]
name = "pytest"
version = "7.4.0"
description = "pytest"
optional = false
python-versions = ">=3.7"
`;

  it('resolves PEP-503-normalized nodes/edges and directness/scope from pyproject.toml', () => {
    const g = parseLockfile(ref('poetry-lock', 'poetry.lock'), lock, pyproject);
    expect(g.ecosystem).toBe('PyPI');
    expect([...g.nodes.keys()].sort()).toEqual(['PyPI:certifi@2023.7.22', 'PyPI:idna@3.4', 'PyPI:pytest@7.4.0', 'PyPI:requests@2.31.0']);
    expect(g.roots.sort()).toEqual(['PyPI:pytest@7.4.0', 'PyPI:requests@2.31.0']);
    expect(g.nodes.get('PyPI:requests@2.31.0')!.scope).toBe('prod');
    expect(g.nodes.get('PyPI:requests@2.31.0')!.children.sort()).toEqual(['PyPI:certifi@2023.7.22', 'PyPI:idna@3.4']);
    expect(g.nodes.get('PyPI:certifi@2023.7.22')!.scope).toBe('prod');
    expect(g.nodes.get('PyPI:pytest@7.4.0')!.scope).toBe('dev');
  });

  it('never throws on malformed TOML', () => {
    const g = parseLockfile(ref('poetry-lock', 'poetry.lock'), '[[package\nbroken');
    expect(g.nodes.size).toBe(0);
    expect(g.warnings.length).toBeGreaterThan(0);
  });

  it('ignores a __proto__ dependency key', () => {
    const malicious = `[[package]]
name = "a"
version = "1.0.0"

[package.dependencies]
__proto__ = ">=1"
`;
    const g = parseLockfile(ref('poetry-lock', 'poetry.lock'), malicious);
    expect(Object.prototype.hasOwnProperty.call({}, 'polluted')).toBe(false);
    expect([...g.nodes.keys()]).toEqual(['PyPI:a@1.0.0']);
  });
});

describe('extractPyprojectDirect', () => {
  it('reads [project].dependencies, optional-dependencies and [dependency-groups]', () => {
    const content = `[project]
name = "demo"
dependencies = ["requests>=2.0", "click[extras]~=8.0"]

[project.optional-dependencies]
test = ["pytest>=7"]

[dependency-groups]
lint = ["ruff"]
`;
    const direct = extractPyprojectDirect(content)!;
    expect(direct.get('requests')).toEqual({ scope: 'prod' });
    expect(direct.get('click[extras]')).toBeUndefined(); // pep508Name strips the bracket extras already
    expect(direct.get('click')).toEqual({ scope: 'prod' });
    expect(direct.get('pytest')).toEqual({ scope: 'dev' });
    expect(direct.get('ruff')).toEqual({ scope: 'dev' });
  });
});

describe('uv.lock', () => {
  const pyproject = `[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests"]
`;

  const lock = `version = 1
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "certifi" }, { name = "idna" }]

[[package]]
name = "certifi"
version = "2023.7.22"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "idna"
version = "3.4"
source = { registry = "https://pypi.org/simple" }
`;

  it('resolves array-style dependency entries and directness from pyproject.toml', () => {
    const g = parseLockfile(ref('uv-lock', 'uv.lock'), lock, pyproject);
    expect(g.nodes.get('PyPI:requests@2.31.0')!.children.sort()).toEqual(['PyPI:certifi@2023.7.22', 'PyPI:idna@3.4']);
    expect(g.roots).toEqual(['PyPI:requests@2.31.0']);
    expect(g.nodes.get('PyPI:requests@2.31.0')!.scope).toBe('prod');
    expect(g.nodes.get('PyPI:certifi@2023.7.22')!.scope).toBe('prod');
    // the local/editable project itself is just another node, not treated as a root.
    expect(g.nodes.get('PyPI:demo@0.1.0')!.direct).toBe(false);
  });

  it('never throws on malformed TOML', () => {
    const g = parseLockfile(ref('uv-lock', 'uv.lock'), 'version = 1\n[[package\nbroken');
    expect(g.nodes.size).toBe(0);
    expect(g.warnings.length).toBeGreaterThan(0);
  });
});

describe('Pipfile.lock', () => {
  const pipfile = `[packages]
requests = "*"

[dev-packages]
pytest = "*"
`;

  const lock = JSON.stringify({
    _meta: { hash: { sha256: 'x' } },
    default: {
      requests: { version: '==2.31.0', hashes: ['sha256:aaa'] },
      certifi: { version: '==2023.7.22', hashes: ['sha256:bbb'] },
    },
    develop: {
      pytest: { version: '==7.4.0', hashes: ['sha256:ccc'] },
    },
  });

  it('has no edges; scope comes from the section, direct is narrowed to the sibling Pipfile', () => {
    const g = parseLockfile(ref('pipfile-lock', 'Pipfile.lock'), lock, pipfile);
    expect([...g.nodes.keys()].sort()).toEqual(['PyPI:certifi@2023.7.22', 'PyPI:pytest@7.4.0', 'PyPI:requests@2.31.0']);
    for (const n of g.nodes.values()) expect(n.children).toEqual([]);

    expect(g.nodes.get('PyPI:requests@2.31.0')!.scope).toBe('prod');
    expect(g.nodes.get('PyPI:requests@2.31.0')!.direct).toBe(true);
    expect(g.nodes.get('PyPI:certifi@2023.7.22')!.scope).toBe('prod'); // still prod even though not in Pipfile
    expect(g.nodes.get('PyPI:certifi@2023.7.22')!.direct).toBe(false); // not declared in Pipfile [packages]
    expect(g.nodes.get('PyPI:pytest@7.4.0')!.scope).toBe('dev');
    expect(g.nodes.get('PyPI:pytest@7.4.0')!.direct).toBe(true);
    expect(g.roots.sort()).toEqual(['PyPI:pytest@7.4.0', 'PyPI:requests@2.31.0']);
  });

  it('treats everything as direct when there is no sibling Pipfile', () => {
    const g = parseLockfile(ref('pipfile-lock', 'Pipfile.lock'), lock);
    expect(g.nodes.get('PyPI:certifi@2023.7.22')!.direct).toBe(true);
    expect(g.warnings.some((w) => w.includes('no sibling Pipfile'))).toBe(true);
  });

  it('never throws on malformed JSON', () => {
    const g = parseLockfile(ref('pipfile-lock', 'Pipfile.lock'), '{not json');
    expect(g.nodes.size).toBe(0);
    expect(g.warnings.length).toBeGreaterThan(0);
  });
});

describe('requirements*.txt', () => {
  it('resolves pins, follows -r includes cycle-safely, flags unpinned, honors dev-ish filenames', () => {
    const files = new Map<string, string>([
      ['requirements.txt', 'flask==2.3.3\nclick==8.1.7 # pinned with a comment\n'],
      [
        'requirements-dev.txt',
        [
          '-r requirements.txt',
          '-r requirements-dev.txt', // self-include, must not infinite-loop
          'pytest==7.4.0 \\',
          '    --hash=sha256:abcdef',
          'requests>=2.0',
          '-e ./local-pkg',
          '# a comment line',
          '',
        ].join('\n'),
      ],
    ]);

    const main = buildRequirementsGraph({ path: 'requirements.txt', kind: 'requirements', manifestDir: '' }, files);
    expect([...main.nodes.keys()].sort()).toEqual(['PyPI:click@8.1.7', 'PyPI:flask@2.3.3']);
    expect(main.nodes.get('PyPI:flask@2.3.3')!.scope).toBe('prod');
    expect(main.nodes.get('PyPI:flask@2.3.3')!.direct).toBe(true);
    expect(main.nodes.get('PyPI:flask@2.3.3')!.children).toEqual([]);

    const dev = buildRequirementsGraph({ path: 'requirements-dev.txt', kind: 'requirements', manifestDir: '' }, files);
    expect([...dev.nodes.keys()].sort()).toEqual(['PyPI:click@8.1.7', 'PyPI:flask@2.3.3', 'PyPI:pytest@7.4.0', 'PyPI:requests@>=2.0']);
    expect(dev.nodes.get('PyPI:requests@>=2.0')!.declaredRange).toBe('>=2.0');
    expect(dev.warnings.some((w) => w.includes('unpinned'))).toBe(true);
    expect([...dev.nodes.values()].every((n) => n.scope === 'dev' && n.direct)).toBe(true);
  });

  it('warns instead of throwing when an -r target is missing', () => {
    const files = new Map<string, string>([['requirements.txt', '-r missing.txt\nflask==2.3.3\n']]);
    const g = buildRequirementsGraph({ path: 'requirements.txt', kind: 'requirements', manifestDir: '' }, files);
    expect([...g.nodes.keys()]).toEqual(['PyPI:flask@2.3.3']);
    expect(g.warnings.some((w) => w.includes('missing.txt'))).toBe(true);
  });
});

describe('pyproject.toml manifest-only (no lockfile)', () => {
  it('records declared ranges as unresolved versions', () => {
    const content = `[project]
name = "demo"
dependencies = ["requests>=2.0"]

[project.optional-dependencies]
test = ["pytest>=7"]
`;
    const g = parseLockfile(ref('pyproject', 'pyproject.toml'), content);
    expect(g.source).toBe('manifest-only');
    expect(g.nodes.get('PyPI:requests@>=2.0')!.direct).toBe(true);
    expect(g.nodes.get('PyPI:requests@>=2.0')!.scope).toBe('prod');
    expect(g.nodes.get('PyPI:pytest@>=7')!.scope).toBe('dev');
    expect(g.warnings.some((w) => w.includes('no lockfile'))).toBe(true);
  });

  it('never throws on malformed TOML', () => {
    const g = parseLockfile(ref('pyproject', 'pyproject.toml'), '[project\nbroken');
    expect(g.nodes.size).toBe(0);
    expect(g.warnings.length).toBeGreaterThan(0);
  });
});
