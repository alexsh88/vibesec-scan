/**
 * Ecosystem-aware version utilities. npm uses `semver` (loose, prerelease-aware); PyPI uses
 * `@renovatebot/pep440` (PEP 440: epochs, pre/post/dev releases, local versions).
 */
import * as pep440 from '@renovatebot/pep440';
import semver from 'semver';
import type { Ecosystem } from './types';

function isNpm(eco: Ecosystem): boolean {
  return eco === 'npm';
}

export function isValidVersion(eco: Ecosystem, v: string): boolean {
  if (isNpm(eco)) return semver.valid(v, { loose: true }) !== null;
  return pep440.valid(v) !== null;
}

/** Assumes both versions are valid for `eco` (see `isValidVersion`); throws otherwise. */
export function compareVersions(eco: Ecosystem, a: string, b: string): number {
  if (isNpm(eco)) return semver.compare(a, b, { loose: true });
  return pep440.compare(a, b);
}

export function satisfies(eco: Ecosystem, version: string, range: string): boolean {
  try {
    if (isNpm(eco)) {
      if (semver.valid(version, { loose: true }) === null) return false;
      if (semver.validRange(range, { loose: true }) === null) return false;
      return semver.satisfies(version, range, { loose: true });
    }
    if (pep440.valid(version) === null) return false;
    if (!pep440.validRange(range)) return false;
    return pep440.satisfies(version, range);
  } catch {
    return false;
  }
}

type ReleaseTriple = { major: number; minor: number; patch: number };

function releaseTriple(eco: Ecosystem, v: string): ReleaseTriple {
  if (isNpm(eco)) {
    const parsed = semver.parse(v, { loose: true });
    if (!parsed) throw new Error(`Invalid npm version: ${v}`);
    return { major: parsed.major, minor: parsed.minor, patch: parsed.patch };
  }
  const explained = pep440.explain(v);
  if (!explained) throw new Error(`Invalid PyPI version: ${v}`);
  const [major = 0, minor = 0, patch = 0] = explained.release;
  return { major, minor, patch };
}

/**
 * Classifies the size of a version jump from `from` to `to` by comparing release segments.
 * For npm, a 0.x MINOR bump is treated as 'major' (breaking), per semver's own convention that
 * 0.x releases have no stability guarantees across minor versions. This 0.x escalation is not
 * applied to PyPI, which has no equivalent community convention.
 */
export function semverJump(eco: Ecosystem, from: string, to: string): 'patch' | 'minor' | 'major' {
  const a = releaseTriple(eco, from);
  const b = releaseTriple(eco, to);
  if (a.major !== b.major) return 'major';
  if (a.minor !== b.minor) return isNpm(eco) && a.major === 0 ? 'major' : 'minor';
  return 'patch';
}

export function maxSatisfying(eco: Ecosystem, versions: readonly string[], range: string): string | null {
  const valid = versions.filter((v) => isValidVersion(eco, v));
  if (valid.length === 0) return null;
  try {
    if (isNpm(eco)) {
      if (semver.validRange(range, { loose: true }) === null) return null;
      return semver.maxSatisfying(valid, range, { loose: true });
    }
    if (!pep440.validRange(range)) return null;
    return pep440.maxSatisfying([...valid], range);
  } catch {
    return null;
  }
}

function isPrereleaseVersion(eco: Ecosystem, v: string): boolean {
  if (isNpm(eco)) {
    const pr = semver.prerelease(v, { loose: true });
    return pr !== null && pr.length > 0;
  }
  const explained = pep440.explain(v);
  return explained ? explained.is_prerelease || explained.is_devrelease : false;
}

/** Smallest version >= floor, excluding prereleases unless `opts.includePrerelease`. */
export function minVersionAtLeast(
  eco: Ecosystem,
  versions: readonly string[],
  floor: string,
  opts: { includePrerelease?: boolean } = {},
): string | null {
  if (!isValidVersion(eco, floor)) return null;
  const includePrerelease = opts.includePrerelease ?? false;
  const candidates = versions
    .filter((v) => isValidVersion(eco, v))
    .filter((v) => includePrerelease || !isPrereleaseVersion(eco, v))
    .filter((v) => compareVersions(eco, v, floor) >= 0);
  if (candidates.length === 0) return null;
  candidates.sort((x, y) => compareVersions(eco, x, y));
  return candidates[0] ?? null;
}
