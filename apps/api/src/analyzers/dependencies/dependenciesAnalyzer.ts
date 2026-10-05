// Dependencies analyzer: wires the P5 building blocks (lockfile graphs, OSV advisories, sandbox /
// import-index usage evidence, reachability + Sonnet judge, supply-chain signals, fix plan) into the
// Analyzer contract (../types.ts).
//
// Findings:
//   - `dependency/vulnerable-package`: ONE finding per vulnerable package@version per lockfile, with
//     every (non-malicious) advisory aggregated into `dependency.advisories`. Severity starts at the
//     worst advisory and is adjusted by reachability and dev scope (see computeSeverity).
//   - `supply-chain/*`: one finding per supply-chain signal. Malicious (MAL-) advisories are reported
//     ONLY by `supply-chain/malicious-package` (always critical, never lowered) — not also by the
//     vulnerable-package finding — so one malicious package never yields two critical findings.
//
// Degradation (never fails the analyzer for an external dependency being down):
//   - OSV partially failing  → warning DEPENDENCY_ADVISORIES_PARTIAL, findings for what resolved;
//     vuln ids whose details failed still produce findings (placeholder advisories, 'medium').
//   - OSV completely failing (failedKeys = every queried package) → warning
//     DEPENDENCY_ADVISORIES_UNAVAILABLE and supply-chain findings
//     only (install scripts / typosquats / non-registry sources need no OSV). Chosen over throwing so
//     a scan still reports the signals that are independent of OSV.
//   - Docker sandbox unavailable / failing → import-index evidence (SANDBOX_UNAVAILABLE / SANDBOX_PARTIAL).
//   - Registry failing → fix plan from advisory versions (DEPENDENCY_FIX_PLAN_PARTIAL).
// Cancellation (ctx.signal) always propagates.

import { readFile, stat } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { z } from 'zod';
import type { Advisory, Finding, FixAction, FixPlan, Severity } from '@vibesec/shared';
import { AppError, toAppError } from '../../errors/AppError';
import { bumpSeverity, fingerprint, githubPermalink, provisionalScore } from '../../findings/helpers';
import type { IndexRepo } from '../../db/indexRepo';
import type { FixPlanRepo } from '../../db/fixPlanRepo';
import type { LlmClient } from '../../llm/LlmClient';
import type { DockerSandbox } from '../../sandbox/dockerSandbox';
import type { Analyzer, AnalyzerContext } from '../types';
import { buildFixPlan, safeUpgradeVersion, type VulnerablePackage } from './fixPlan';
import { importNamesFor, packageForImport } from './importNames';
import { normalizePypiName, parseDependencyGraphs, pathsTo } from './lockfiles';
import type { OsvClient } from './osv/osvClient';
import { assessReachability, type Reachability, type ReachabilityVerdict } from './reachability';
import { applyJudgement, judgeReachability, type JudgeCallSite, type JudgeItem } from './reachabilityJudge';
import type { RegistryClient } from './registry';
import { supplyChainSignals, type SupplyChainSignal } from './supplyChain';
import type { DepGraph, DepNode, Ecosystem, OsvAdvisory, PackageUsage } from './types';
import { compareVersions, isValidVersion } from './versions';

export type DependenciesAnalyzerDeps = {
  osv: Pick<OsvClient, 'advisoriesFor'>;
  registry: Pick<RegistryClient, 'versions' | 'dependencyRange'>;
  sandbox: Pick<DockerSandbox, 'availability' | 'install' | 'analyze' | 'sweep'> | null;
  indexRepo: Pick<IndexRepo, 'imports'>;
  llm: Pick<LlmClient, 'structured'>;
  fixPlans: Pick<FixPlanRepo, 'save'>;
  sandboxEnabled: boolean;
  /** Parallel sandbox installs/analyses (default 2). */
  maxSandboxConcurrency?: number;
  /** Max vulnerable packages sent to the reachability judge (default 30). */
  maxJudgeItems?: number;
};

type Confidence = 'high' | 'medium' | 'low';
type RiskFactor = { factor: string; effect: number; reason: string };
type UsageSource = 'sandbox' | 'index';

const SEV_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const sevIndex = (s: Severity): number => SEV_ORDER.indexOf(s);
const maxSeverity = (list: readonly Severity[]): Severity =>
  list.reduce<Severity>((m, s) => (sevIndex(s) > sevIndex(m) ? s : m), 'info');

const MAX_SNIPPET = 300;
const MAX_SUMMARY = 300;
const MAX_PATHS = 5;
const MAX_EVIDENCE = 10;
const MAX_CALL_SITES = 8;
const MAX_SCAN_FILES = 5;
const MAX_READ_BYTES = 2 * 1024 * 1024;
const MAX_SANDBOX_USAGES = 50_000;
const MAX_ANALYZE_PACKAGES = 2_000;

const cancelled = (): AppError => new AppError('CANCELLED', 'cancelled', 'Operation was cancelled');
function checkAborted(signal: AbortSignal): void {
  if (signal.aborted) throw cancelled();
}
function isCancellation(err: unknown, signal: AbortSignal): boolean {
  return signal.aborted || toAppError(err).kind === 'cancelled';
}
const truncate = (s: string, max: number): string => (s.length > max ? `${s.slice(0, max - 1)}…` : s);

/** Runs `fn` over `items` with at most `limit` in flight; rethrows the first rejection after all settle. */
async function forEachLimit<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  let firstError: unknown;
  let hasError = false;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      try {
        await fn(items[i]!);
      } catch (err) {
        if (!hasError) { hasError = true; firstError = err; }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  if (hasError) throw firstError;
}

// --- safe repo file access -------------------------------------------------------------------

/** Reads repo files as lines, refusing anything outside repoDir or larger than MAX_READ_BYTES. Cached per run. */
function createLineReader(repoDir: string): (rel: string) => Promise<string[] | null> {
  const root = resolve(repoDir);
  const cache = new Map<string, Promise<string[] | null>>();
  return (rel: string) => {
    let hit = cache.get(rel);
    if (hit) return hit;
    hit = (async () => {
      if (rel.length === 0 || rel.includes('\0')) return null;
      const abs = resolve(root, ...rel.split('/'));
      if (!abs.startsWith(root + sep)) return null;
      try {
        const st = await stat(abs);
        if (!st.isFile() || st.size > MAX_READ_BYTES) return null;
        return (await readFile(abs, 'utf8')).split(/\r?\n/);
      } catch {
        return null;
      }
    })();
    cache.set(rel, hit);
    return hit;
  };
}

const joinRel = (dir: string, base: string): string => (dir === '' ? base : `${dir}/${base}`);
const basenameOf = (p: string): string => p.slice(p.lastIndexOf('/') + 1);

/** Line (1-based) of the first line satisfying `pred`, or null. */
function findLine(lines: readonly string[], pred: (line: string) => boolean): number | null {
  for (let i = 0; i < lines.length; i++) if (pred(lines[i]!)) return i + 1;
  return null;
}

const PY_REQ_NAME_RE = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/;

/** Files + literal matchers that declare `node` (direct deps: the manifest first; then the lockfile). */
function declarationCandidates(graph: DepGraph, node: DepNode): Array<{ file: string; match: (line: string) => boolean }> {
  const lockfile = graph.lockfile;
  const base = basenameOf(lockfile).toLowerCase();
  const name = node.name;
  const pyNorm = normalizePypiName(name);
  const pyLine = (line: string): boolean => {
    const m = PY_REQ_NAME_RE.exec(line.replace(/^\s*"/, ''));
    return m !== null && normalizePypiName(m[1]!) === pyNorm;
  };
  const pyMention = (line: string): boolean => normalizePypiName(line.toLowerCase()).includes(pyNorm);
  const npmManifest = (line: string): boolean => line.trimStart().startsWith(`"${name}"`);
  const npmLock = (line: string): boolean => line.includes(`node_modules/${name}"`);
  const out: Array<{ file: string; match: (line: string) => boolean }> = [];

  if (graph.ecosystem === 'npm') {
    if (node.direct) out.push({ file: joinRel(graph.manifestDir, 'package.json'), match: npmManifest });
    out.push({ file: lockfile, match: base === 'package-lock.json' || base === 'npm-shrinkwrap.json' ? npmLock : (l) => l.includes(name) });
    return out;
  }
  if (/^requirements.*\.txt$/.test(base) || base === 'pyproject.toml') {
    out.push({ file: lockfile, match: base === 'pyproject.toml' ? pyMention : pyLine });
    return out;
  }
  if (node.direct) {
    const manifest = joinRel(graph.manifestDir, base === 'pipfile.lock' ? 'Pipfile' : 'pyproject.toml');
    out.push({ file: manifest, match: pyLine }, { file: manifest, match: pyMention });
  }
  out.push({ file: lockfile, match: (l) => l.includes(`"${name}"`) || l.includes(`"${pyNorm}"`) });
  return out;
}

type Located = { file: string; line: number; snippet: string };

async function locate(read: (rel: string) => Promise<string[] | null>, graph: DepGraph, node: DepNode): Promise<Located> {
  let fallback: { file: string; lines: string[] } | null = null;
  for (const c of declarationCandidates(graph, node)) {
    const lines = await read(c.file);
    if (!lines) continue;
    fallback ??= { file: c.file, lines };
    const line = findLine(lines, c.match);
    if (line !== null) return { file: c.file, line, snippet: truncate(lines[line - 1]!.trim(), MAX_SNIPPET) };
  }
  if (fallback) return { file: fallback.file, line: 1, snippet: truncate((fallback.lines[0] ?? '').trim(), MAX_SNIPPET) };
  return { file: graph.lockfile, line: 1, snippet: '' };
}

// --- usage evidence --------------------------------------------------------------------------

const PY_FILE_RE = /\.pyi?$/i;
const JS_FILE_RE = /\.(?:[cm]?[jt]sx?)$/i;

function underDir(file: string, dir: string): boolean {
  return dir === '' || file.startsWith(`${dir}/`);
}

/** Import-index evidence for one graph: package imports from files under the graph's manifest dir. */
function indexUsages(edges: ReturnType<IndexRepo['imports']>, graph: DepGraph): PackageUsage[] {
  const names = [...new Set([...graph.nodes.values()].map((n) => n.name))];
  const out: PackageUsage[] = [];
  for (const e of edges) {
    if (e.kind !== 'package' || e.pkg === null) continue;
    const eco: Ecosystem | null = PY_FILE_RE.test(e.from) ? 'PyPI' : JS_FILE_RE.test(e.from) ? 'npm' : null;
    if (eco !== graph.ecosystem || !underDir(e.from, graph.manifestDir)) continue;
    const pkg = packageForImport(eco, e.specifier, names) ?? packageForImport(eco, e.pkg, names) ?? e.pkg;
    out.push({ ecosystem: eco, package: pkg, file: e.from, line: e.line, symbol: null, kind: 'import' });
  }
  return out;
}

const SandboxUsageSchema = z.object({
  package: z.string().min(1).max(300),
  file: z.string().min(1).max(1000),
  line: z.number().int().positive(),
  symbol: z.string().max(300).nullable(),
  kind: z.enum(['import', 'call', 'member']),
});
const SandboxUsagesFileSchema = z.object({ usages: z.array(z.unknown()) });

function safeRelPath(p: string): boolean {
  return !p.startsWith('/') && !p.includes('\\') && !p.includes('\0') && !p.split('/').some((s) => s === '..' || s === '.' || s === '');
}

/** Validates sandbox usages.json; invalid entries are dropped, the list is capped. null = unusable file. */
export function parseSandboxUsages(raw: unknown, ecosystem: Ecosystem): PackageUsage[] | null {
  const file = SandboxUsagesFileSchema.safeParse(raw);
  if (!file.success) return null;
  const out: PackageUsage[] = [];
  for (const entry of file.data.usages) {
    const u = SandboxUsageSchema.safeParse(entry);
    if (!u.success || !safeRelPath(u.data.file)) continue;
    out.push({ ecosystem, package: u.data.package, file: u.data.file, line: u.data.line, symbol: u.data.symbol, kind: u.data.kind });
    if (out.length >= MAX_SANDBOX_USAGES) break;
  }
  return out;
}

/** Packages the sandbox analyzer looks for: vulnerable + signal nodes and all their ancestors (for transitive reachability). */
function packagesOfInterest(graph: DepGraph, keys: ReadonlySet<string>): Array<{ name: string; importNames: string[] }> {
  const names = new Set<string>();
  const seen = new Set<string>();
  const stack = [...keys];
  while (stack.length > 0 && names.size < MAX_ANALYZE_PACKAGES) {
    const k = stack.pop()!;
    if (seen.has(k)) continue;
    seen.add(k);
    const n = graph.nodes.get(k);
    if (!n) continue;
    names.add(n.name);
    stack.push(...n.parents);
  }
  return [...names].sort().map((name) => ({ name, importNames: importNamesFor(graph.ecosystem, name) }));
}

// --- severity --------------------------------------------------------------------------------

/** Lowers by `steps`, never below 'low' (and never RAISES something already below 'low'). */
function lowerFloorLow(s: Severity, steps: number): Severity {
  if (sevIndex(s) <= sevIndex('low')) return s;
  const b = bumpSeverity(s, -steps);
  return sevIndex(b) < sevIndex('low') ? 'low' : b;
}

const REACHABILITY_ADJUST: Record<Reachability, { steps: number; confidence: Confidence; text: string }> = {
  reachable: { steps: 0, confidence: 'high', text: 'Vulnerable code is reachable from application code' },
  imported: { steps: 0, confidence: 'medium', text: 'Package is imported by application code' },
  unknown: { steps: 1, confidence: 'medium', text: 'Reachability could not be determined' },
  unreachable: { steps: 2, confidence: 'medium', text: 'Package is not used by application code' },
};

/**
 * Reachability-aware severity for a vulnerable-package finding. Transitive-and-not-imported needs no
 * extra penalty: assessReachability already maps it to 'unknown'/'unreachable'.
 */
export function computeSeverity(
  base: Severity, reachability: Reachability, scope: 'prod' | 'dev',
): { severity: Severity; confidence: Confidence; riskFactors: RiskFactor[] } {
  const adj = REACHABILITY_ADJUST[reachability];
  const riskFactors: RiskFactor[] = [];
  let current = base;
  const afterReach = adj.steps === 0 ? current : lowerFloorLow(current, adj.steps);
  riskFactors.push({ factor: `reachability:${reachability}`, effect: sevIndex(afterReach) - sevIndex(current), reason: adj.text });
  current = afterReach;
  if (scope === 'dev') {
    const next = lowerFloorLow(current, 1);
    riskFactors.push({ factor: 'devDependency', effect: sevIndex(next) - sevIndex(current), reason: 'Only a development dependency (not shipped to production)' });
    current = next;
  }
  return { severity: current, confidence: adj.confidence, riskFactors };
}

// --- advisories ------------------------------------------------------------------------------

function toSharedAdvisory(eco: Ecosystem, version: string, a: OsvAdvisory): Advisory {
  return {
    id: a.id, aliases: a.aliases, summary: truncate(a.summary || a.details.split('\n')[0] || a.id, MAX_SUMMARY),
    severity: a.severity, cvss: a.cvss, fixedIn: safeUpgradeVersion(eco, version, [a])?.version ?? null, url: a.url,
  };
}

/**
 * Smallest advisory fix version above `version` that is outside EVERY advisory's affected ranges
 * (not just the max of per-advisory fixes, which can land in a regression range); undefined if none.
 */
function coveringFix(eco: Ecosystem, version: string, advisories: readonly OsvAdvisory[]): string | undefined {
  return safeUpgradeVersion(eco, version, advisories)?.version;
}

const bySeverityDesc = (a: OsvAdvisory, b: OsvAdvisory): number =>
  sevIndex(b.severity) - sevIndex(a.severity) || (b.cvss ?? 0) - (a.cvss ?? 0) || a.id.localeCompare(b.id);

function vulnTitle(node: DepNode, advisories: readonly OsvAdvisory[]): string {
  const counts = new Map<Severity, number>();
  for (const a of advisories) counts.set(a.severity, (counts.get(a.severity) ?? 0) + 1);
  const parts = [...SEV_ORDER].reverse().filter((s) => counts.has(s)).map((s) => `${counts.get(s)} ${s}`);
  const n = advisories.length;
  return `${node.name}@${node.version} has ${n} known ${n === 1 ? 'vulnerability' : 'vulnerabilities'} (${parts.join(', ')})`;
}

/** Function names an advisory text mentions (`name()` or backticked identifiers). */
function mentionedFunctions(text: string): string[] {
  const names = new Set<string>();
  for (const m of text.matchAll(/([A-Za-z_$][\w$.]*)\s*\(\)/g)) if (m[1]) names.add(m[1]);
  for (const m of text.matchAll(/`([A-Za-z_$][\w$.]*)`/g)) if (m[1]) names.add(m[1]);
  return [...names];
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// --- analyzer --------------------------------------------------------------------------------

type GraphWork = {
  graph: DepGraph;
  vulnerable: Array<{ node: DepNode; advisories: OsvAdvisory[] }>;
  signals: SupplyChainSignal[];
  usages: PackageUsage[] | null;
  usageSource: UsageSource;
};

const evidenceOf = (v: ReachabilityVerdict) => v.evidence.slice(0, MAX_EVIDENCE).map((e) => ({ file: e.file, line: e.line }));

export function createDependenciesAnalyzer(deps: DependenciesAnalyzerDeps): Analyzer {
  return {
    id: 'dependencies',
    version: '1',
    category: 'dependency',

    async run(ctx: AnalyzerContext): Promise<Finding[]> {
      const { signal } = ctx;
      const { graphs } = await parseDependencyGraphs({ repoDir: ctx.repoDir, files: ctx.files, signal, touch: ctx.touch });
      if (graphs.length === 0) return [];
      ctx.touch();
      const read = createLineReader(ctx.repoDir);

      // 1. advisories (deduped by node key across graphs; concrete versions only)
      const inputs = new Map<string, { key: string; ecosystem: Ecosystem; name: string; version: string }>();
      for (const g of graphs) {
        for (const n of g.nodes.values()) {
          if (!inputs.has(n.key) && isValidVersion(n.ecosystem, n.version)) inputs.set(n.key, { key: n.key, ecosystem: n.ecosystem, name: n.name, version: n.version });
        }
      }
      let advisoriesByKey = new Map<string, OsvAdvisory[]>();
      let osvAvailable = true;
      if (inputs.size > 0) {
        let result: Awaited<ReturnType<OsvClient['advisoriesFor']>>;
        try {
          result = await deps.osv.advisoriesFor([...inputs.values()], signal);
        } catch (err) {
          if (isCancellation(err, signal)) throw toAppError(err);
          result = { byKey: new Map(), failedKeys: [...inputs.keys()], failedIds: [], errors: [`OSV query failed: ${toAppError(err).userMessage}`] };
        }
        // Every queried package failing its query means OSV was unreachable as a whole. Packages
        // whose advisory DETAILS failed still carry placeholder advisories (never silently clean).
        const failedKeys = new Set(result.failedKeys);
        if ([...inputs.keys()].every((k) => failedKeys.has(k))) {
          osvAvailable = false;
          ctx.warn('DEPENDENCY_ADVISORIES_UNAVAILABLE', 'Vulnerability advisories (OSV) could not be retrieved; only supply-chain signals are reported for dependencies');
        } else {
          advisoriesByKey = result.byKey;
          if (result.errors.length > 0 || failedKeys.size > 0 || result.failedIds.length > 0) {
            ctx.warn('DEPENDENCY_ADVISORIES_PARTIAL', `Advisories could not be retrieved for some dependencies (${result.errors.length} error(s)); results may be incomplete`);
          }
        }
      }
      ctx.touch();
      checkAborted(signal);

      // 2. per-graph vulnerable nodes + supply-chain signals
      const work: GraphWork[] = graphs.map((graph) => {
        const vulnerable: GraphWork['vulnerable'] = [];
        for (const node of [...graph.nodes.values()].sort((a, b) => a.key.localeCompare(b.key))) {
          const advisories = (advisoriesByKey.get(node.key) ?? []).filter((a) => !a.malicious);
          if (advisories.length > 0) vulnerable.push({ node, advisories });
        }
        return { graph, vulnerable, signals: supplyChainSignals(graph, advisoriesByKey), usages: null, usageSource: 'index' };
      });

      // 3. usage evidence: the import index everywhere; the sandbox (slow) only for graphs with a vulnerable package
      let edges: ReturnType<IndexRepo['imports']> | null;
      try {
        edges = deps.indexRepo.imports(ctx.scanId);
      } catch {
        edges = null;
      }
      for (const w of work) w.usages = edges === null ? null : indexUsages(edges, w.graph);

      const sandboxTargets = work.filter((w) => w.vulnerable.length > 0);
      if (deps.sandboxEnabled && deps.sandbox && sandboxTargets.length > 0) {
        const sandbox = deps.sandbox;
        try {
          const avail = await sandbox.availability(signal);
          if (!avail.ok) {
            ctx.warn('SANDBOX_UNAVAILABLE', `Docker sandbox unavailable (${truncate(avail.reason, 200)}); dependency usage taken from the import index`);
          } else {
            const failed: string[] = [];
            await forEachLimit(sandboxTargets, deps.maxSandboxConcurrency ?? 2, async (w) => {
              checkAborted(signal);
              try {
                const usages = await runSandbox(sandbox, ctx, w);
                if (usages === null) failed.push(w.graph.lockfile);
                else { w.usages = usages; w.usageSource = 'sandbox'; }
              } catch (err) {
                if (isCancellation(err, signal)) throw toAppError(err);
                failed.push(w.graph.lockfile);
              }
              ctx.touch();
            });
            if (failed.length > 0) {
              const code = failed.length === sandboxTargets.length ? 'SANDBOX_UNAVAILABLE' : 'SANDBOX_PARTIAL';
              ctx.warn(code, `Sandbox usage analysis failed for ${failed.sort().join(', ')}; used the import index there instead`);
            }
          }
        } finally {
          await sandbox.sweep(ctx.scanId).catch(() => undefined);
        }
      }
      checkAborted(signal);

      // 4. reachability (+ deep-tier judge for 'imported' packages with call-site evidence)
      const verdicts = new Map<string, ReachabilityVerdict>(); // `${lockfile}|${nodeKey}`
      const judgeItems: JudgeItem[] = [];
      for (const w of work) {
        const keys = new Set([...w.vulnerable.map((v) => v.node.key), ...w.signals.map((s) => s.key)]);
        for (const key of keys) {
          const node = w.graph.nodes.get(key);
          if (!node) continue;
          const advisories = advisoriesByKey.get(key) ?? [];
          const verdict = assessReachability({ graph: w.graph, node, advisories, usages: w.usages, usageSource: w.usageSource });
          const vk = `${w.graph.lockfile}|${key}`;
          verdicts.set(vk, verdict);
          const nonMal = advisories.filter((a) => !a.malicious);
          if (verdict.reachability === 'imported' && nonMal.length > 0) {
            const callSites = await callSitesFor(read, w.usageSource, verdict, nonMal);
            if (callSites.length > 0) {
              judgeItems.push({
                key: vk, package: node.name, version: node.version, callSites,
                advisories: nonMal.map((a) => ({ id: a.id, summary: a.summary, details: a.details, affectedSymbols: a.affectedSymbols, cvss: a.cvss })),
              });
            }
          }
        }
      }
      const judged = new Set<string>();
      if (judgeItems.length > 0) {
        const judgements = await judgeReachability(deps.llm, ctx.scanId, judgeItems, signal, {
          maxItems: deps.maxJudgeItems ?? 30, warn: ctx.warn, onActivity: ctx.touch,
        });
        for (const [vk, j] of judgements) {
          const before = verdicts.get(vk);
          if (!before) continue;
          const after = applyJudgement(before, j);
          if (after !== before) { verdicts.set(vk, after); judged.add(vk); }
        }
      }
      ctx.touch();
      checkAborted(signal);

      // 5. findings
      const findings: Finding[] = [];
      const vulnerablePackages: VulnerablePackage[] = [];
      const fixable = new Set<string>(); // finding ids that take part in the fix plan

      for (const w of work) {
        const { graph } = w;
        for (const { node, advisories } of w.vulnerable) {
          const vk = `${graph.lockfile}|${node.key}`;
          const verdict = verdicts.get(vk)!;
          const loc = await locate(read, graph, node);
          const ruleId = 'dependency/vulnerable-package';
          const fp = fingerprint(['dependency', ruleId, graph.ecosystem, node.name, node.version, graph.lockfile]);
          const id = fingerprint([ctx.scanId, fp]).slice(0, 32);
          const sorted = [...advisories].sort(bySeverityDesc);
          const worst = sorted[0]!;
          const baseSeverity = worst.severity;
          const { severity, confidence, riskFactors } = computeSeverity(baseSeverity, verdict.reachability, node.scope);
          const riskScore = provisionalScore(severity);
          const paths = pathsTo(graph, node.key, MAX_PATHS);
          const fixedIn = coveringFix(graph.ecosystem, node.version, advisories);

          findings.push({
            id, scanId: ctx.scanId, fingerprint: fp, category: 'dependency', ruleId,
            ...(worst.cwes[0] !== undefined ? { cwe: worst.cwes[0] } : {}),
            title: vulnTitle(node, advisories),
            baseSeverity, riskScore, severity, riskFactors, confidence,
            location: { file: loc.file, startLine: loc.line, endLine: loc.line, snippet: loc.snippet, permalink: githubPermalink(ctx.repo, ctx.commitSha, loc.file, loc.line, loc.line) },
            dependency: {
              ecosystem: graph.ecosystem, name: node.name, version: node.version, scope: node.scope, direct: node.direct, paths,
              advisories: sorted.map((a) => toSharedAdvisory(graph.ecosystem, node.version, a)),
              ...(fixedIn !== undefined ? { fixedIn } : {}),
              reachability: verdict.reachability,
              reachabilityEvidence: evidenceOf(verdict),
            },
            explanation: vulnExplanation(node, sorted, verdict, paths),
            impact: vulnImpact(worst),
            remediation: { summary: fixedIn !== undefined ? `Upgrade ${node.name} to ${fixedIn} or later` : 'No fixed version available — replace or remove' },
            scanStatus: 'new',
            producedBy: ['osv', w.usageSource, ...(judged.has(vk) ? ['llm'] : [])],
          });
          fixable.add(id);
          vulnerablePackages.push({ findingId: id, graph, node, advisories, riskScore });
        }

        for (const s of w.signals) {
          const node = graph.nodes.get(s.key);
          if (!node) continue;
          const verdict = verdicts.get(`${graph.lockfile}|${node.key}`);
          const loc = await locate(read, graph, node);
          const fp = fingerprint(['dependency', s.ruleId, graph.ecosystem, node.name, node.version, graph.lockfile]);
          const id = fingerprint([ctx.scanId, fp]).slice(0, 32);
          const isMal = s.ruleId === 'supply-chain/malicious-package';
          const mal = isMal ? (advisoriesByKey.get(node.key) ?? []).filter((a) => a.malicious || a.id.startsWith('MAL-')) : [];
          const severity: Severity = isMal ? 'critical' : s.severity;
          const paths = pathsTo(graph, node.key, MAX_PATHS);
          const via = paths[0] && !node.direct ? ` Pulled in via ${paths[0].join(' > ')}.` : '';
          findings.push({
            id, scanId: ctx.scanId, fingerprint: fp, category: 'dependency', ruleId: s.ruleId,
            ...(isMal ? { cwe: 'CWE-506' } : {}),
            title: s.title, baseSeverity: severity, riskScore: provisionalScore(severity), severity,
            riskFactors: isMal ? [{ factor: 'malicious', effect: 0, reason: 'Known malicious package: never lowered by reachability or scope' }] : [],
            confidence: s.ruleId === 'supply-chain/typosquat' ? 'medium' : 'high',
            location: { file: loc.file, startLine: loc.line, endLine: loc.line, snippet: loc.snippet, permalink: githubPermalink(ctx.repo, ctx.commitSha, loc.file, loc.line, loc.line) },
            dependency: {
              ecosystem: graph.ecosystem, name: node.name, version: node.version, scope: node.scope, direct: node.direct, paths,
              advisories: mal.map((a) => toSharedAdvisory(graph.ecosystem, node.version, a)),
              reachability: verdict?.reachability ?? 'unknown',
              ...(verdict ? { reachabilityEvidence: evidenceOf(verdict) } : {}),
            },
            explanation: `${s.reason}.${via}${verdict ? ` ${verdict.reason}.` : ''}`,
            impact: supplyChainImpact(s),
            remediation: { summary: supplyChainRemediation(s, node) },
            scanStatus: 'new',
            producedBy: isMal ? ['osv', 'lockfile'] : ['lockfile'],
          });
          if (mal.length > 0) {
            fixable.add(id);
            vulnerablePackages.push({ findingId: id, graph, node, advisories: mal, riskScore: provisionalScore(severity) });
          }
        }
      }
      checkAborted(signal);
      ctx.touch();

      // 6. fix plan
      let plan: FixPlan = { scanId: ctx.scanId, actions: [], unfixable: [] };
      try {
        const built = await buildFixPlan({ scanId: ctx.scanId, vulnerable: vulnerablePackages, registry: deps.registry, signal });
        plan = built.plan;
        if (built.warnings.length > 0) {
          ctx.warn('DEPENDENCY_FIX_PLAN_PARTIAL', truncate(`Fix plan is partial: ${built.warnings.join('; ')}`, 1000));
        }
      } catch (err) {
        if (isCancellation(err, signal)) throw toAppError(err);
        ctx.warn('DEPENDENCY_FIX_PLAN_PARTIAL', `Fix plan could not be built: ${toAppError(err).userMessage}`);
      }
      deps.fixPlans.save(plan);
      linkRemediation(findings, plan, fixable);

      return findings;
    },
  };
}

async function runSandbox(
  sandbox: Pick<DockerSandbox, 'install' | 'analyze'>, ctx: AnalyzerContext, w: GraphWork,
): Promise<PackageUsage[] | null> {
  const { graph } = w;
  const install = graph.ecosystem === 'npm'
    ? await sandbox.install({ scanId: ctx.scanId, signal: ctx.signal, ecosystem: 'npm', srcDir: ctx.repoDir, manifestDir: graph.manifestDir })
    : await sandbox.install({
      scanId: ctx.scanId, signal: ctx.signal, ecosystem: 'PyPI',
      requirements: [...graph.nodes.values()].filter((n) => isValidVersion('PyPI', n.version)).map((n) => `${n.name}==${n.version}`).sort(),
    });
  ctx.touch();
  if (!install.ok) return null;
  const keys = new Set([...w.vulnerable.map((v) => v.node.key), ...w.signals.map((s) => s.key)]);
  const analyzed = await sandbox.analyze({
    scanId: ctx.scanId, ecosystem: graph.ecosystem, srcDir: ctx.repoDir, depsDir: install.depsDir,
    packages: packagesOfInterest(graph, keys), signal: ctx.signal,
  });
  if (!analyzed.ok) return null;
  const usages = parseSandboxUsages(analyzed.usages, graph.ecosystem);
  return usages === null ? null : usages.filter((u) => underDir(u.file, graph.manifestDir));
}

/**
 * Call sites for the judge: sandbox usages carrying a symbol, plus (either evidence source) lines in
 * the importing files that call a function the advisories name (affectedSymbols, or `name()` /
 * backticked names in the summary). The import index has no symbol data, so this literal scan is
 * what lets the judge see `_.merge(...)` there. Each site carries its code line (≤ 300 chars, read
 * path-traversal safely).
 */
async function callSitesFor(
  read: (rel: string) => Promise<string[] | null>, usageSource: UsageSource, verdict: ReachabilityVerdict, advisories: readonly OsvAdvisory[],
): Promise<JudgeCallSite[]> {
  const out: JudgeCallSite[] = [];
  const seen = new Set<string>();
  const add = async (file: string, line: number): Promise<void> => {
    const k = `${file}:${line}`;
    if (seen.has(k) || out.length >= MAX_CALL_SITES) return;
    const code = (await read(file))?.[line - 1];
    if (code === undefined) return;
    seen.add(k);
    out.push({ file, line, code: truncate(code.trim(), MAX_SNIPPET) });
  };
  if (usageSource === 'sandbox') {
    for (const e of verdict.evidence) if (e.symbol !== null && e.symbol !== 'default') await add(e.file, e.line);
  }
  const symbols = new Set<string>();
  for (const a of advisories) {
    for (const s of [...a.affectedSymbols, ...mentionedFunctions(a.summary)]) {
      const last = s.slice(s.lastIndexOf('.') + 1);
      if (/^[A-Za-z_$][\w$]+$/.test(last)) symbols.add(last);
    }
  }
  if (symbols.size > 0) {
    const re = new RegExp(`(^|[^\\w$])(?:${[...symbols].map(escapeRe).join('|')})\\s*\\(`);
    const files = [...new Set(verdict.evidence.map((e) => e.file))].slice(0, MAX_SCAN_FILES);
    for (const f of files) {
      const lines = await read(f);
      if (!lines) continue;
      for (let i = 0; i < lines.length && out.length < MAX_CALL_SITES; i++) {
        if (re.test(lines[i]!)) await add(f, i + 1);
      }
    }
  }
  return out;
}

function vulnExplanation(node: DepNode, advisories: readonly OsvAdvisory[], verdict: ReachabilityVerdict, paths: string[][]): string {
  const top = advisories.slice(0, 3).map((a) => `${a.id} (${a.severity}): ${truncate(a.summary || a.id, 200)}`);
  const more = advisories.length > 3 ? ` …and ${advisories.length - 3} more.` : '';
  const dev = node.scope === 'dev' ? ' development' : '';
  const root = node.direct
    ? `${node.name} is a direct${dev} dependency declared in the manifest.`
    : `${node.name} is a transitive${dev} dependency${paths[0] ? `, pulled in via ${paths[0].join(' > ')}` : ''}; fixing it usually means upgrading the direct dependency that brings it in.`;
  const missing = advisories.filter((a) => a.detailsUnavailable).map((a) => a.id);
  const note = missing.length > 0
    ? ` Note: OSV lists ${missing.join(', ')} for this version but the advisory details are unavailable (fetch failed); severity defaults to medium — re-scan or check osv.dev.`
    : '';
  return `Known vulnerabilities in ${node.name}@${node.version}: ${top.join('; ')}.${more} Reachability (${verdict.reachability}): ${verdict.reason}. ${root}${note}`;
}

function vulnImpact(worst: OsvAdvisory): string {
  const cwe = worst.cwes[0] ? ` (${worst.cwes[0]})` : '';
  return `Worst advisory ${worst.id}${cwe}, ${worst.severity}${worst.cvss !== null ? `, CVSS ${worst.cvss}` : ''}: ${truncate(worst.summary || worst.details || worst.id, 300)}`;
}

function supplyChainImpact(s: SupplyChainSignal): string {
  switch (s.ruleId) {
    case 'supply-chain/malicious-package': return 'Malicious packages typically steal credentials, tokens or source code, or install backdoors, as soon as they are installed or imported.';
    case 'supply-chain/install-script': return 'Install scripts run arbitrary code with the developer\'s or CI runner\'s privileges on every install; a compromised release can exfiltrate credentials.';
    case 'supply-chain/typosquat': return 'Typosquatted packages imitate popular ones to get installed by mistake and usually carry malicious payloads.';
    case 'supply-chain/non-registry-source': return 'Packages from outside the registry skip its integrity and malware checks and can change without a version bump.';
  }
}

function supplyChainRemediation(s: SupplyChainSignal, node: DepNode): string {
  switch (s.ruleId) {
    case 'supply-chain/malicious-package': return `Remove ${node.name} immediately and rotate any credentials available where it was installed`;
    case 'supply-chain/install-script': return `Verify ${node.name} needs its install script; install with --ignore-scripts or allowlist it explicitly`;
    case 'supply-chain/typosquat': return `Confirm ${node.name} is intended${s.similarTo ? `; you probably meant ${s.similarTo}` : ''}`;
    case 'supply-chain/non-registry-source': return `Install ${node.name} from the public ${node.ecosystem} registry at a pinned version`;
  }
}

/** remediation.summary ← the fix-plan action resolving each finding (command + what else it fixes). */
function linkRemediation(findings: Finding[], plan: FixPlan, fixable: ReadonlySet<string>): void {
  const byFinding = new Map<string, FixAction>();
  for (const a of plan.actions) for (const r of a.resolves) if (!byFinding.has(r.findingId)) byFinding.set(r.findingId, a);
  for (const f of findings) {
    if (!fixable.has(f.id)) continue;
    const action = byFinding.get(f.id);
    if (!action) continue;
    const own = new Set(action.resolves.filter((r) => r.findingId === f.id).map((r) => r.advisoryId)).size;
    const others = action.resolvedCount - own;
    f.remediation = { summary: `${action.command}${others > 0 ? ` (also resolves ${others} other ${others === 1 ? 'advisory' : 'advisories'} in this action)` : ''}` };
  }
}
