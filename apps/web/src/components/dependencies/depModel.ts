/**
 * Pure view-model helpers for the Dependencies page: dependency findings are already aggregated per
 * library (one finding = one package@version with all its advisories); these helpers join them with
 * the fix plan and derive the numbers the page shows.
 */
import type { Finding, FixAction, Severity } from '@vibesec/shared';
import { SEVERITY_ORDER } from '@/lib/taxonomy';

export type DepFinding = Finding & { dependency: NonNullable<Finding['dependency']> };
export type Reachability = DepFinding['dependency']['reachability'];

export const SUPPLY_CHAIN_PREFIX = 'supply-chain/';

export const isSupplyChain = (f: Finding): boolean => f.ruleId.startsWith(SUPPLY_CHAIN_PREFIX);
export const hasDependency = (f: Finding): f is DepFinding => f.dependency !== undefined;

export const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export type SeverityTally = Record<Severity, number>;

export const emptyTally = (): SeverityTally => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

/** Advisory counts by severity for one library. */
export function advisoryTally(f: DepFinding): SeverityTally {
  const t = emptyTally();
  for (const a of f.dependency.advisories) t[a.severity] += 1;
  return t;
}

export function maxCvss(f: DepFinding): number | null {
  let m: number | null = null;
  for (const a of f.dependency.advisories) if (a.cvss !== null && (m === null || a.cvss > m)) m = a.cvss;
  return m;
}

/** "1 critical, 2 high" — non-zero severities only, most severe first. */
export function tallyText(t: SeverityTally): string {
  return SEVERITY_ORDER.filter((s) => t[s] > 0).map((s) => `${t[s]} ${s}`).join(', ');
}

/** Distinct advisories an action resolves, tallied by severity. */
export function actionTally(a: FixAction): SeverityTally {
  const seen = new Set<string>();
  const t = emptyTally();
  for (const r of a.resolves) {
    if (seen.has(r.advisoryId)) continue;
    seen.add(r.advisoryId);
    t[r.severity] += 1;
  }
  return t;
}

export type ResolvedPackage = { name: string; version: string; findingId: string; advisories: FixAction['resolves'] };

/** Vulnerable packages (name@version) an action fixes, in resolve order. */
export function actionPackages(a: FixAction): ResolvedPackage[] {
  const by = new Map<string, ResolvedPackage>();
  for (const r of a.resolves) {
    const key = `${r.package}@${r.version}`;
    const cur = by.get(key) ?? { name: r.package, version: r.version, findingId: r.findingId, advisories: [] };
    cur.advisories.push(r);
    by.set(key, cur);
  }
  return [...by.values()];
}

/** findingId → the highest-priority action that fixes it (actions arrive sorted by priority). */
export function actionByFinding(actions: readonly FixAction[]): Map<string, FixAction> {
  const m = new Map<string, FixAction>();
  for (const a of actions) for (const r of a.resolves) if (!m.has(r.findingId)) m.set(r.findingId, a);
  return m;
}

export const actionAnchor = (a: Pick<FixAction, 'id'>): string => `fix-${a.id}`;
export const libraryAnchor = (findingId: string): string => `lib-${findingId}`;

const OVERRIDE_RE = /^(add to [^:]+):\s*(.+?)(?:\s+—\s+then run `([^`]+)`)?$/;

/**
 * An override command looks like `add to package.json: "overrides": { "qs": "6.5.3" } — then run \`npm install\``.
 * Split it into the snippet to paste and the follow-up command so each can be copied on its own.
 */
export function splitCommand(command: string): { instruction: string | null; snippet: string; then: string | null } {
  const m = command.match(OVERRIDE_RE);
  if (m && m[1] && m[2]) return { instruction: m[1], snippet: m[2], then: m[3] ?? null };
  return { instruction: null, snippet: command, then: null };
}

export const osvUrl = (id: string): string => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;

export const cveIds = (aliases: readonly string[]): string[] => aliases.filter((a) => a.startsWith('CVE-'));

export type DepFilters = {
  reachability: 'all' | Reachability;
  scope: 'all' | 'prod' | 'dev';
  relation: 'all' | 'direct' | 'transitive';
  minSeverity: 'all' | Severity;
  sort: 'risk' | 'cvss' | 'advisories' | 'name';
};

export const DEFAULT_FILTERS: DepFilters = { reachability: 'all', scope: 'all', relation: 'all', minSeverity: 'all', sort: 'risk' };

export function applyFilters(list: readonly DepFinding[], f: DepFilters): DepFinding[] {
  const out = list.filter((x) => {
    const d = x.dependency;
    if (f.reachability !== 'all' && d.reachability !== f.reachability) return false;
    if (f.scope !== 'all' && d.scope !== f.scope) return false;
    if (f.relation === 'direct' && !d.direct) return false;
    if (f.relation === 'transitive' && d.direct) return false;
    if (f.minSeverity !== 'all' && SEV_RANK[x.severity] < SEV_RANK[f.minSeverity]) return false;
    return true;
  });
  const cmp: Record<DepFilters['sort'], (a: DepFinding, b: DepFinding) => number> = {
    risk: (a, b) => b.riskScore - a.riskScore || SEV_RANK[b.severity] - SEV_RANK[a.severity],
    cvss: (a, b) => (maxCvss(b) ?? -1) - (maxCvss(a) ?? -1) || b.riskScore - a.riskScore,
    advisories: (a, b) => b.dependency.advisories.length - a.dependency.advisories.length || b.riskScore - a.riskScore,
    name: (a, b) => a.dependency.name.localeCompare(b.dependency.name),
  };
  return out.sort(cmp[f.sort]);
}
