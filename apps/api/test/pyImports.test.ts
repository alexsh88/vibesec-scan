import { describe, expect, it } from 'vitest';
import { extractPyImports, pythonRoots, resolvePyImport, type PyResolveContext } from '../src/index/pyImports';

describe('extractPyImports', () => {
  it('parses import forms with line numbers', () => {
    const src = [
      'import os, sys as system',
      'import app.models.user',
      'from flask import Flask, request',
      'from . import views',
      'from ..core.db import (',
      '    session,',
      '    engine as eng,',
      ')',
      'from yaml import \\',
      '    safe_load',
      '"""',
      'import notreal',
      '"""',
      '    from .utils import helper  # indented import',
    ].join('\n');
    expect(extractPyImports(src)).toEqual([
      { module: 'os', level: 0, names: [], line: 1 },
      { module: 'sys', level: 0, names: [], line: 1 },
      { module: 'app.models.user', level: 0, names: [], line: 2 },
      { module: 'flask', level: 0, names: ['Flask', 'request'], line: 3 },
      { module: '', level: 1, names: ['views'], line: 4 },
      { module: 'core.db', level: 2, names: ['session', 'engine'], line: 5 },
      { module: 'yaml', level: 0, names: ['safe_load'], line: 9 },
      { module: 'utils', level: 1, names: ['helper'], line: 14 },
    ]);
  });

  it('does not treat a triple-quote marker inside a comment as starting a docstring', () => {
    const src = [
      'import real_one',
      'x = 5  # """ looks like a marker',
      'import should_be_found',
    ].join('\n');
    expect(extractPyImports(src)).toEqual([
      { module: 'real_one', level: 0, names: [], line: 1 },
      { module: 'should_be_found', level: 0, names: [], line: 3 },
    ]);
  });
});

describe('pythonRoots', () => {
  it('includes the repo root, src/, and project directories', () => {
    const files = new Set(['src/app/__init__.py', 'services/api/pyproject.toml', 'services/api/src/api/main.py', 'tools/setup.py']);
    expect(pythonRoots(files)).toEqual(['', 'src', 'services/api', 'services/api/src', 'tools']);
  });
});

describe('resolvePyImport', () => {
  const ctx: PyResolveContext = {
    files: new Set([
      'app/__init__.py', 'app/models/__init__.py', 'app/models/user.py', 'app/views.py', 'app/core/db.py',
      'app/api/routes.py', 'src/pkg/__init__.py', 'src/pkg/helpers.py',
    ]),
    roots: ['', 'src'],
  };
  const imp = (module: string, level = 0, names: string[] = []) => ({ module, level, names, line: 1 });

  it('resolves absolute modules and packages', () => {
    expect(resolvePyImport('main.py', imp('app.models.user'), ctx)).toEqual([
      { specifier: 'app.models.user', kind: 'local', to: 'app/models/user.py', pkg: null },
    ]);
    expect(resolvePyImport('main.py', imp('app.models'), ctx)).toEqual([
      { specifier: 'app.models', kind: 'local', to: 'app/models/__init__.py', pkg: null },
    ]);
  });

  it('resolves under src/ roots', () => {
    expect(resolvePyImport('tests/test_x.py', imp('pkg.helpers'), ctx)[0]).toMatchObject({ kind: 'local', to: 'src/pkg/helpers.py' });
  });

  it('resolves from-imports of submodules', () => {
    expect(resolvePyImport('app/api/routes.py', imp('app', 0, ['views', 'missing_name']), ctx)).toEqual([
      { specifier: 'app', kind: 'local', to: 'app/__init__.py', pkg: null },
      { specifier: 'app.views', kind: 'local', to: 'app/views.py', pkg: null },
    ]);
  });

  it('resolves relative imports', () => {
    expect(resolvePyImport('app/api/routes.py', imp('core.db', 2, ['session']), ctx)).toEqual([
      { specifier: '..core.db', kind: 'local', to: 'app/core/db.py', pkg: null },
    ]);
    expect(resolvePyImport('app/api/routes.py', imp('', 2, ['views']), ctx)).toEqual([
      { specifier: '..', kind: 'local', to: 'app/__init__.py', pkg: null },
      { specifier: '..views', kind: 'local', to: 'app/views.py', pkg: null },
    ]);
    expect(resolvePyImport('app/views.py', imp('nothing', 1), ctx)).toEqual([
      { specifier: '.nothing', kind: 'unresolved', to: null, pkg: null },
    ]);
  });

  it('treats a relative import climbing above the repo root as unresolved', () => {
    expect(resolvePyImport('a.py', imp('x', 3), ctx)).toEqual([
      { specifier: '...x', kind: 'unresolved', to: null, pkg: null },
    ]);
  });

  it('does not clamp an over-climbing relative import to the root and wrongly resolve a same-named module there', () => {
    // 'app/__init__.py' exists at the repo root; a naive clamp to '' would wrongly resolve this.
    expect(resolvePyImport('a.py', imp('app', 3), ctx)).toEqual([
      { specifier: '...app', kind: 'unresolved', to: null, pkg: null },
    ]);
  });

  it('classifies stdlib and third-party packages, mapping import names to distributions', () => {
    expect(resolvePyImport('main.py', imp('os.path'), ctx)).toEqual([{ specifier: 'os.path', kind: 'builtin', to: null, pkg: null }]);
    expect(resolvePyImport('main.py', imp('requests'), ctx)).toEqual([{ specifier: 'requests', kind: 'package', to: null, pkg: 'requests' }]);
    expect(resolvePyImport('main.py', imp('yaml'), ctx)[0]?.pkg).toBe('pyyaml');
    expect(resolvePyImport('main.py', imp('PIL.Image'), ctx)[0]?.pkg).toBe('pillow');
    expect(resolvePyImport('main.py', imp('sklearn.linear_model'), ctx)[0]?.pkg).toBe('scikit-learn');
  });
});
