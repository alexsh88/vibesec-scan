import { describe, expect, it } from 'vitest';
import { extractJsImports, parsePathConfig, resolveJsImport, type JsResolveContext } from '../src/index/jsImports';

describe('extractJsImports', () => {
  it('finds static, re-export, side-effect, require and dynamic imports with line numbers', () => {
    const src = [
      "import fs from 'node:fs';",
      'import { a,',
      "  b } from './lib/a';",
      "import type { T } from '@acme/types/x';",
      "export * from './reexport';",
      "export { c } from \"../c\";",
      "import './side-effect.css';",
      "const x = require('lodash/get');",
      "const y = await import('./lazy.js');",
      "const notImport = 'from \"fake\"';",
    ].join('\n');
    expect(extractJsImports(src)).toEqual([
      { specifier: 'node:fs', line: 1 },
      { specifier: './lib/a', line: 2 },
      { specifier: '@acme/types/x', line: 4 },
      { specifier: './reexport', line: 5 },
      { specifier: '../c', line: 6 },
      { specifier: './side-effect.css', line: 7 },
      { specifier: 'lodash/get', line: 8 },
      { specifier: './lazy.js', line: 9 },
    ]);
  });

  it('ignores imports inside comments but not inside code after a comment', () => {
    const src = "// import x from 'commented';\n/* require('also-commented') */ const z = require('real');\nconst url = 'http://x//y';";
    expect(extractJsImports(src)).toEqual([{ specifier: 'real', line: 2 }]);
  });

  it('ignores dynamic imports with template expressions', () => {
    expect(extractJsImports('import(`./locale/${lang}.js`)')).toEqual([]);
  });

  it('treats a / that cannot be a division operator as a regex literal, not a comment', () => {
    const src = "const re = /[/*]/;\nimport './a.js';\nimport './b.js';";
    expect(extractJsImports(src)).toEqual([
      { specifier: './a.js', line: 2 },
      { specifier: './b.js', line: 3 },
    ]);
  });

  it('treats an escaped-slash regex literal correctly, not as a string', () => {
    const src = "const p = /^\\/\\//.test(u); import './after.js';";
    expect(extractJsImports(src)).toEqual([{ specifier: './after.js', line: 1 }]);
  });

  it('treats / between operands as division, still stripping a trailing line comment', () => {
    const src = "const half = total / 2; // note\nimport './x';";
    expect(extractJsImports(src)).toEqual([{ specifier: './x', line: 2 }]);
  });

  it('treats / between operands as division even immediately before a block comment', () => {
    const src = "a = b / c /* c */; import './y';";
    expect(extractJsImports(src)).toEqual([{ specifier: './y', line: 1 }]);
  });

  it('does not treat quote characters inside a regex literal as starting a string', () => {
    const src = "const re = /[\"']/;\nimport './q.js';";
    expect(extractJsImports(src)).toEqual([{ specifier: './q.js', line: 2 }]);
  });
});

describe('parsePathConfig', () => {
  it('parses JSONC with comments and trailing commas, resolving baseUrl relative to the config dir', () => {
    const cfg = parsePathConfig('apps/web', `{
      // comment
      "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"], "~lib": ["lib/index.ts"], }, },
    }`);
    expect(cfg).toEqual({ dir: 'apps/web', baseUrl: 'apps/web', paths: [
      { pattern: '@/*', targets: ['apps/web/src/*'] },
      { pattern: '~lib', targets: ['apps/web/lib/index.ts'] },
    ] });
  });

  it('returns null for invalid JSON or no compilerOptions', () => {
    expect(parsePathConfig('', '{ nope')).toBeNull();
    expect(parsePathConfig('', '{}')).toBeNull();
  });
});

describe('resolveJsImport', () => {
  const ctx: JsResolveContext = {
    files: new Set([
      'src/server.ts', 'src/lib/a.ts', 'src/lib/index.ts', 'src/util.tsx', 'src/data.json',
      'apps/web/src/components/Button.tsx', 'apps/web/src/page.tsx', 'apps/web/lib/index.ts', 'src/esm.ts',
    ]),
    pathConfigs: [
      { dir: 'apps/web', baseUrl: 'apps/web', paths: [{ pattern: '@/*', targets: ['apps/web/src/*'] }, { pattern: '~lib', targets: ['apps/web/lib/index.ts'] }] },
    ],
  };

  it.each([
    ['src/server.ts', './lib/a', { kind: 'local', to: 'src/lib/a.ts', pkg: null }],
    ['src/server.ts', './lib', { kind: 'local', to: 'src/lib/index.ts', pkg: null }],
    ['src/server.ts', './util', { kind: 'local', to: 'src/util.tsx', pkg: null }],
    ['src/server.ts', './data.json', { kind: 'local', to: 'src/data.json', pkg: null }],
    ['src/server.ts', './esm.js', { kind: 'local', to: 'src/esm.ts', pkg: null }],
    ['src/lib/a.ts', '../server', { kind: 'local', to: 'src/server.ts', pkg: null }],
    ['src/server.ts', './missing', { kind: 'unresolved', to: null, pkg: null }],
    ['src/server.ts', '../../outside', { kind: 'unresolved', to: null, pkg: null }],
    ['src/server.ts', 'fs', { kind: 'builtin', to: null, pkg: null }],
    ['src/server.ts', 'node:crypto', { kind: 'builtin', to: null, pkg: null }],
    ['src/server.ts', 'lodash/get', { kind: 'package', to: null, pkg: 'lodash' }],
    ['src/server.ts', '@acme/types/x', { kind: 'package', to: null, pkg: '@acme/types' }],
    ['apps/web/src/page.tsx', '@/components/Button', { kind: 'local', to: 'apps/web/src/components/Button.tsx', pkg: null }],
    ['apps/web/src/page.tsx', '~lib', { kind: 'local', to: 'apps/web/lib/index.ts', pkg: null }],
    ['apps/web/src/page.tsx', 'src/components/Button', { kind: 'local', to: 'apps/web/src/components/Button.tsx', pkg: null }],
    ['src/server.ts', '@/components/Button', { kind: 'package', to: null, pkg: '@/components' }],
  ] as const)('%s imports %s', (from, spec, expected) => {
    expect(resolveJsImport(from, spec, ctx)).toEqual(expected);
  });
});
