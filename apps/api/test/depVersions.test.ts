import { describe, expect, it } from 'vitest';
import {
  compareVersions,
  isValidVersion,
  maxSatisfying,
  minVersionAtLeast,
  satisfies,
  semverJump,
} from '../src/analyzers/dependencies/versions';

describe('isValidVersion', () => {
  it('npm: accepts loose semver, rejects garbage', () => {
    expect(isValidVersion('npm', '1.2.3')).toBe(true);
    expect(isValidVersion('npm', '1.2.3-beta.1')).toBe(true);
    expect(isValidVersion('npm', 'v1.2.3')).toBe(true);
    expect(isValidVersion('npm', '^1.2.3')).toBe(false);
    expect(isValidVersion('npm', 'not-a-version')).toBe(false);
  });

  it('PyPI: accepts PEP 440 versions incl. epochs/post/dev, rejects garbage', () => {
    expect(isValidVersion('PyPI', '1.2.3')).toBe(true);
    expect(isValidVersion('PyPI', '1!2.3.4.post1.dev2')).toBe(true);
    expect(isValidVersion('PyPI', '2.0.0a1')).toBe(true);
    expect(isValidVersion('PyPI', '>=1.0')).toBe(false);
    expect(isValidVersion('PyPI', 'not-a-version')).toBe(false);
  });
});

describe('compareVersions', () => {
  it('npm: orders prereleases before their release', () => {
    expect(compareVersions('npm', '1.2.3', '1.2.4')).toBeLessThan(0);
    expect(compareVersions('npm', '1.2.3-beta.1', '1.2.3')).toBeLessThan(0);
    expect(compareVersions('npm', '1.2.3', '1.2.3')).toBe(0);
  });

  it('PyPI: epochs dominate, dev < pre < release < post', () => {
    expect(compareVersions('PyPI', '1.0', '1!0.1')).toBeLessThan(0);
    expect(compareVersions('PyPI', '1.0.dev1', '1.0a1')).toBeLessThan(0);
    expect(compareVersions('PyPI', '1.0a1', '1.0')).toBeLessThan(0);
    expect(compareVersions('PyPI', '1.0', '1.0.post1')).toBeLessThan(0);
  });
});

describe('satisfies', () => {
  it('npm: evaluates caret/tilde ranges, false on invalid version or range', () => {
    expect(satisfies('npm', '1.2.3', '^1.0.0')).toBe(true);
    expect(satisfies('npm', '2.0.0', '^1.0.0')).toBe(false);
    expect(satisfies('npm', 'garbage', '^1.0.0')).toBe(false);
    expect(satisfies('npm', '1.2.3', 'not a range')).toBe(false);
  });

  it('PyPI: evaluates PEP 440 specifiers, false on invalid version or specifier', () => {
    expect(satisfies('PyPI', '1.5.0', '>=1.0,<2.0')).toBe(true);
    expect(satisfies('PyPI', '2.5.0', '>=1.0,<2.0')).toBe(false);
    expect(satisfies('PyPI', 'garbage', '>=1.0')).toBe(false);
    expect(satisfies('PyPI', '1.0', 'not a specifier')).toBe(false);
  });
});

describe('semverJump', () => {
  it('npm: classifies major/minor/patch normally above 1.0', () => {
    expect(semverJump('npm', '1.2.3', '2.0.0')).toBe('major');
    expect(semverJump('npm', '1.2.3', '1.3.0')).toBe('minor');
    expect(semverJump('npm', '1.2.3', '1.2.4')).toBe('patch');
  });

  it('npm: treats a 0.x minor bump as major (breaking by convention)', () => {
    expect(semverJump('npm', '0.5.0', '0.6.0')).toBe('major');
    expect(semverJump('npm', '0.5.0', '0.5.1')).toBe('patch');
  });

  it('PyPI: compares release segments without the 0.x escalation', () => {
    expect(semverJump('PyPI', '0.5.0', '0.6.0')).toBe('minor');
    expect(semverJump('PyPI', '1.2.3', '2.0.0')).toBe('major');
    expect(semverJump('PyPI', '1.2.3', '1.2.4')).toBe('patch');
  });
});

describe('maxSatisfying', () => {
  it('npm: picks the highest matching version, ignoring invalid entries', () => {
    expect(maxSatisfying('npm', ['1.0.0', '1.2.0', 'garbage', '2.0.0'], '^1.0.0')).toBe('1.2.0');
    expect(maxSatisfying('npm', ['1.0.0'], 'not a range')).toBeNull();
    expect(maxSatisfying('npm', [], '^1.0.0')).toBeNull();
  });

  it('PyPI: picks the highest matching version', () => {
    expect(maxSatisfying('PyPI', ['1.0.0', '1.5.0', '2.0.0'], '>=1.0,<2.0')).toBe('1.5.0');
  });
});

describe('minVersionAtLeast', () => {
  it('npm: finds the smallest version >= floor, excluding prereleases by default', () => {
    expect(minVersionAtLeast('npm', ['1.0.0', '1.2.0-beta.1', '1.2.0', '1.3.0'], '1.1.0')).toBe('1.2.0');
  });

  it('npm: includes prereleases when opted in', () => {
    expect(minVersionAtLeast('npm', ['1.0.0', '1.2.0-beta.1', '1.2.0'], '1.1.0', { includePrerelease: true })).toBe('1.2.0-beta.1');
  });

  it('returns null when nothing qualifies, or the floor is invalid', () => {
    expect(minVersionAtLeast('npm', ['1.0.0'], '2.0.0')).toBeNull();
    expect(minVersionAtLeast('npm', ['1.0.0'], 'garbage')).toBeNull();
  });

  it('PyPI: finds the smallest version >= floor, excluding dev/pre releases by default', () => {
    expect(minVersionAtLeast('PyPI', ['1.0', '1.1.dev1', '1.1', '1.2'], '1.0.1')).toBe('1.1');
  });
});
