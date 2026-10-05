// CycloneDX 1.6 SBOM+VEX export (P7 Task B).
//
// Scope note: this is NOT a full SBOM. We only persist dependency *findings* (one per vulnerable or
// supply-chain-flagged package@version — see analyzers/dependencies/dependenciesAnalyzer.ts), not the
// complete resolved dependency graph of every scanned repo. A full SBOM would require persisting every
// package the lockfile resolves, vulnerable or not, which is out of scope for P7 (see container.ts /
// FindingRepo — nothing else is stored). `components` below therefore lists only vulnerable/flagged
// packages; this is called out again in metadata.properties for anyone consuming the document.
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Finding, ScanDto, Severity } from '@vibesec/shared';

const CYCLONEDX_SPEC_VERSION = '1.6';

const RatingSchema = z.object({
  score: z.number().optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  method: z.literal('CVSSv31'),
});

const AnalysisStateSchema = z.enum(['not_affected', 'exploitable', 'in_triage']);

const ComponentSchema = z.object({
  'bom-ref': z.string(),
  type: z.literal('library'),
  name: z.string(),
  version: z.string(),
  purl: z.string(),
  scope: z.enum(['required', 'optional']),
});

const VulnerabilitySchema = z.object({
  id: z.string(),
  source: z.object({ name: z.literal('OSV'), url: z.string() }),
  ratings: z.array(RatingSchema),
  affects: z.array(z.object({ ref: z.string() })),
  analysis: z.object({
    state: AnalysisStateSchema,
    justification: z.literal('code_not_reachable').optional(),
  }),
});

export const CycloneDxBomSchema = z.object({
  bomFormat: z.literal('CycloneDX'),
  specVersion: z.literal(CYCLONEDX_SPEC_VERSION),
  serialNumber: z.string(),
  version: z.literal(1),
  metadata: z.object({
    timestamp: z.string(),
    component: z.object({ type: z.literal('application'), name: z.string(), version: z.string() }),
    properties: z.array(z.object({ name: z.string(), value: z.string() })),
  }),
  components: z.array(ComponentSchema),
  vulnerabilities: z.array(VulnerabilitySchema),
});

export type CycloneDxBom = z.infer<typeof CycloneDxBomSchema>;

/** npm: scoped names (`@scope/pkg`) keep their `/`; PyPI names are lower-cased with `_`/`.` folded to `-` (PEP 503). */
export function purlFor(ecosystem: 'npm' | 'PyPI', name: string, version: string): string {
  const v = encodeURIComponent(version);
  if (ecosystem === 'PyPI') {
    const normalized = name.toLowerCase().replace(/[._]+/g, '-');
    return `pkg:pypi/${encodeURIComponent(normalized)}@${v}`;
  }
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    const scope = name.slice(1, slash);
    const pkg = name.slice(slash + 1);
    return `pkg:npm/%40${encodeURIComponent(scope)}/${encodeURIComponent(pkg)}@${v}`;
  }
  return `pkg:npm/${encodeURIComponent(name)}@${v}`;
}

function analysisFor(reachability: NonNullable<Finding['dependency']>['reachability']): { state: z.infer<typeof AnalysisStateSchema>; justification?: 'code_not_reachable' } {
  if (reachability === 'unreachable') return { state: 'not_affected', justification: 'code_not_reachable' };
  if (reachability === 'reachable') return { state: 'exploitable' };
  return { state: 'in_triage' }; // 'imported' | 'unknown'
}

/** Builds and validates a CycloneDX 1.6 SBOM+VEX document limited to the vulnerable/flagged packages we persist. */
export function buildCycloneDx(scan: ScanDto, findings: readonly Finding[]): CycloneDxBom {
  const components = new Map<string, z.infer<typeof ComponentSchema>>();
  // One vulnerability entry per advisory id; if the same advisory shows up on more than one
  // component (rare — a monorepo with two lockfiles pinning the same vulnerable version) `affects`
  // grows to list every one of them, while `analysis` keeps the reachability of the first finding
  // seen for it (documented simplification: VEX does not carry a per-component state here).
  const vulns = new Map<string, z.infer<typeof VulnerabilitySchema>>();

  for (const f of findings) {
    if (f.category !== 'dependency' || !f.dependency) continue;
    const dep = f.dependency;
    const purl = purlFor(dep.ecosystem, dep.name, dep.version);
    if (!components.has(purl)) {
      components.set(purl, {
        'bom-ref': purl, type: 'library', name: dep.name, version: dep.version, purl,
        scope: dep.scope === 'dev' ? 'optional' : 'required',
      });
    }
    const analysis = analysisFor(dep.reachability);
    for (const a of dep.advisories) {
      const existing = vulns.get(a.id);
      if (existing) {
        if (!existing.affects.some((x) => x.ref === purl)) existing.affects.push({ ref: purl });
        continue;
      }
      const rating: z.infer<typeof RatingSchema> = { severity: a.severity as Severity, method: 'CVSSv31', ...(a.cvss !== null ? { score: a.cvss } : {}) };
      vulns.set(a.id, {
        id: a.id,
        source: { name: 'OSV', url: a.url ?? `https://osv.dev/vulnerability/${a.id}` },
        ratings: [rating],
        affects: [{ ref: purl }],
        analysis,
      });
    }
  }

  const bom: CycloneDxBom = {
    bomFormat: 'CycloneDX',
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: { type: 'application', name: `${scan.repo.owner}/${scan.repo.name}`, version: scan.commitSha ?? scan.ref ?? scan.id },
      properties: [{
        name: 'vibesec:scope',
        value: 'components are limited to vulnerable/flagged packages found by the dependency analyzer; this is not a full SBOM (the complete resolved dependency graph is not persisted)',
      }],
    },
    components: [...components.values()],
    vulnerabilities: [...vulns.values()],
  };
  return CycloneDxBomSchema.parse(bom);
}
