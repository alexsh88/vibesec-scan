/**
 * Shared contracts for the dependency analyzer (P5). Lockfile parsers produce DepGraphs, the OSV
 * client produces Advisories, the sandbox produces install trees and usage reports; the analyzer
 * (credentials-style orchestration) combines them into `dependency` findings and a fix plan.
 */

export type Ecosystem = 'npm' | 'PyPI';
export type DepScope = 'prod' | 'dev';

/** One resolved package version in one lockfile. */
export type DepNode = {
  /** `${ecosystem}:${name}@${version}` — unique within a graph. */
  key: string;
  ecosystem: Ecosystem;
  /** Canonical name: npm as-is (incl. scope), PyPI normalized per PEP 503 (lowercase, runs of -_. → '-'). */
  name: string;
  version: string;
  /** Declared in the manifest (package.json / pyproject / Pipfile / requirements). */
  direct: boolean;
  /** 'prod' when reachable from any prod direct dependency, else 'dev'. */
  scope: DepScope;
  /** Keys of the nodes that depend on this one (empty for direct-only nodes). */
  parents: string[];
  /** Keys of this node's own dependencies. */
  children: string[];
  /** For direct deps: the range declared in the manifest (e.g. "^4.17.0", ">=2.0,<3"). */
  declaredRange?: string;
  /** npm: lockfile says the package has install scripts (`hasInstallScript`). */
  hasInstallScript?: boolean;
  /** npm: resolved tarball URL host is not the public registry (git/url/file deps). */
  nonRegistrySource?: string;
};

/** The resolved dependency tree of ONE lockfile (monorepos have several). */
export type DepGraph = {
  ecosystem: Ecosystem;
  /** Repo-relative path of the lockfile/manifest the graph came from, forward slashes. */
  lockfile: string;
  /** Repo-relative directory containing it ('' for the repo root). */
  manifestDir: string;
  nodes: Map<string, DepNode>;
  /** Keys of the direct dependencies. */
  roots: string[];
  /** Non-fatal parse problems (unsupported lockfile version, unpinned requirement, …). */
  warnings: string[];
  /** How the graph was obtained. */
  source: 'lockfile' | 'sandbox-install' | 'manifest-only';
};

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AffectedRange = { introduced: string; fixed?: string; lastAffected?: string };

/** A normalized OSV advisory as it applies to one package. */
export type OsvAdvisory = {
  id: string;                 // GHSA-…, PYSEC-…, MAL-…, CVE-…
  aliases: string[];
  summary: string;
  details: string;            // may be long; truncate before prompting
  severity: Severity;         // from CVSS (exact v3 preferred; approximate v4 only without v3) or database_specific severity, else 'medium'
  cvss: number | null;        // base score 0–10 when computable
  cvssVector: string | null;
  /** Fixed versions for this package (ascending, ecosystem-ordered); empty when no fix exists. */
  fixedVersions: string[];
  /**
   * Affected intervals for this package (OSV SEMVER/ECOSYSTEM ranges, one entry per introduced→fixed /
   * last_affected pair; introduced '0' = from the beginning, no fixed/lastAffected = still affected).
   * Empty (with no `affectedVersions`) = unknown: callers fall back to `fixedVersions`.
   */
  affectedRanges: AffectedRange[];
  /** Explicit OSV `versions` list (affected iff listed, in addition to the ranges). */
  affectedVersions?: string[];
  /** Function/module/symbol names the advisory points at, when OSV provides them (ecosystem_specific / database_specific). */
  affectedSymbols: string[];
  cwes: string[];
  url: string | null;         // best reference (advisory page)
  published: string | null;
  malicious: boolean;         // MAL-* (malicious package)
  /** OSV listed this id for the package but its details could not be fetched: a placeholder
   *  (severity 'medium', no ranges/fixes) so the package is never silently reported clean. */
  detailsUnavailable?: boolean;
};

/** A source-code usage of a package found by static analysis (index or sandbox phase B). */
export type PackageUsage = {
  ecosystem: Ecosystem;
  /** Package name as imported, mapped to the canonical dependency name. */
  package: string;
  file: string;
  line: number;
  /** Imported binding / called member, e.g. "merge" for `_.merge(...)`, null for side-effect imports. */
  symbol: string | null;
  /** 'reference': not an import but a by-name use outside code — package.json scripts, tool config files,
   *  Procfile / Dockerfile CMD / ENTRYPOINT (see references.ts). Imported-level evidence. */
  kind: 'import' | 'call' | 'member' | 'reference';
};

export type FixActionKind = 'upgrade-direct' | 'upgrade-parent' | 'override' | 'remove';
