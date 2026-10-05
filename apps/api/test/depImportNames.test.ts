import { describe, expect, it } from 'vitest';
import { importNamesFor, packageForImport } from '../src/analyzers/dependencies/importNames';

describe('importNamesFor', () => {
  it('npm: the package name itself (scoped too)', () => {
    expect(importNamesFor('npm', 'lodash')).toEqual(['lodash']);
    expect(importNamesFor('npm', '@babel/core')).toEqual(['@babel/core']);
  });

  it('PyPI: well-known distributions map to their module names', () => {
    expect(importNamesFor('PyPI', 'pyyaml')).toEqual(['yaml']);
    expect(importNamesFor('PyPI', 'PyYAML')).toEqual(['yaml']);
    expect(importNamesFor('PyPI', 'beautifulsoup4')).toEqual(['bs4']);
    expect(importNamesFor('PyPI', 'pillow')).toEqual(['PIL']);
    expect(importNamesFor('PyPI', 'scikit-learn')).toEqual(['sklearn']);
    expect(importNamesFor('PyPI', 'python-dateutil')).toEqual(['dateutil']);
    expect(importNamesFor('PyPI', 'opencv-python')).toEqual(['cv2']);
    expect(importNamesFor('PyPI', 'opencv-python-headless')).toEqual(['cv2']);
    expect(importNamesFor('PyPI', 'pyjwt')).toEqual(['jwt']);
    expect(importNamesFor('PyPI', 'psycopg2-binary')).toEqual(['psycopg2']);
  });

  it('PyPI: default is the normalized name with - → _', () => {
    expect(importNamesFor('PyPI', 'requests')).toEqual(['requests']);
    expect(importNamesFor('PyPI', 'typing-extensions')).toEqual(['typing_extensions']);
    expect(importNamesFor('PyPI', 'Flask_Cors')).toEqual(['flask_cors']);
  });
});

describe('packageForImport', () => {
  const npmKnown = ['lodash', '@babel/core', 'lodash.merge', 'react', 'react-dom'];
  it('npm: exact, subpath, scoped; longest match wins; unknown → null', () => {
    expect(packageForImport('npm', 'lodash', npmKnown)).toBe('lodash');
    expect(packageForImport('npm', 'lodash/merge', npmKnown)).toBe('lodash');
    expect(packageForImport('npm', 'lodash.merge', npmKnown)).toBe('lodash.merge');
    expect(packageForImport('npm', '@babel/core/lib/x', npmKnown)).toBe('@babel/core');
    expect(packageForImport('npm', 'react-dom/client', npmKnown)).toBe('react-dom');
    expect(packageForImport('npm', 'express', npmKnown)).toBeNull();
    expect(packageForImport('npm', 'reactor', npmKnown)).toBeNull();
  });

  it('PyPI: module (dotted) → distribution via reverse mapping and normalization', () => {
    const known = ['pyyaml', 'beautifulsoup4', 'requests', 'typing-extensions', 'pillow'];
    expect(packageForImport('PyPI', 'yaml', known)).toBe('pyyaml');
    expect(packageForImport('PyPI', 'yaml.loader', known)).toBe('pyyaml');
    expect(packageForImport('PyPI', 'bs4', known)).toBe('beautifulsoup4');
    expect(packageForImport('PyPI', 'PIL.Image', known)).toBe('pillow');
    expect(packageForImport('PyPI', 'requests.adapters', known)).toBe('requests');
    expect(packageForImport('PyPI', 'typing_extensions', known)).toBe('typing-extensions');
    expect(packageForImport('PyPI', 'numpy', known)).toBeNull();
  });

  it('PyPI: accepts an index row that already carries the distribution name', () => {
    expect(packageForImport('PyPI', 'pyyaml', ['pyyaml'])).toBe('pyyaml');
    expect(packageForImport('PyPI', 'python-dateutil', ['python-dateutil'])).toBe('python-dateutil');
  });
});
