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
import { activeTriage, type Finding, type ScanDto, type Severity } from '@vibesec/shared';
import { VIBESEC_INFORMATION_URI } from './sarif';

const CYCLONEDX_SPEC_VERSION = '1.6';

/** A score + method only when the score really is CVSS v3.1 (its vector is known); else severity alone. */
const RatingSchema = z.object({
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  method: z.literal('CVSSv31').optional(),
  score: z.number().optional(),
  vector: z.string().optional(),
});

const AnalysisStateSchema = z.enum(['not_affected', 'exploitable', 'in_triage', 'false_positive']);

const ComponentSchema = z.object({
  'bom-ref': z.string(),
  type: z.literal('library'),
  name: z.string(),
  version: z.string(),
  purl: z.string(),
  scope: z.enum(['required', 'optional']),
});

const AnalysisSchema = z.object({
  state: AnalysisStateSchema,
  justification: z.literal('code_not_reachable').optional(),
  response: z.array(z.literal('will_not_fix')).optional(),
  detail: z.string().optional(),
});
type Analysis = z.infer<typeof AnalysisSchema>;

const VulnerabilitySchema = z.object({
  id: z.string(),
  source: z.object({ name: z.enum(['OSV', 'VibeSec']), url: z.string() }),
  description: z.string().optional(),
  ratings: z.array(RatingSchema),
  affects: z.array(z.object({ ref: z.string() })),
  analysis: AnalysisSchema,
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

function reachabilityAnalysis(reachability: NonNullable<Finding['dependency']>['reachability']): Analysis {
  if (reachability === 'unreachable') return { state: 'not_affected', justification: 'code_not_reachable' };
  if (reachability === 'reachable') return { state: 'exploitable' };
  return { state: 'in_triage' }; // 'imported' | 'unknown'
}

/**
 * VEX analysis: a triage decision in force wins — false_positive → state 'false_positive' (+ the reason
 * as detail); accepted_risk / wont_fix keep the reachability state and add response 'will_not_fix'.
 * Otherwise the reachability decides.
 */
function analysisFor(f: Finding, reachability: NonNullable<Finding['dependency']>['reachability'], now: string): Analysis {
  const triage = activeTriage(f, now);
  if (triage?.status === 'false_positive') return { state: 'false_positive', detail: triage.reason };
  const base = reachabilityAnalysis(reachability);
  return triage ? { ...base, response: ['will_not_fix'], detail: triage.reason } : base;
}

function ratingFor(a: { severity: Severity; cvss: number | null; cvssVector?: string | undefined }): z.infer<typeof RatingSchema> {
  if (a.cvss !== null && a.cvssVector?.startsWith('CVSS:3.1/')) {
    return { severity: a.severity, method: 'CVSSv31', score: a.cvss, vector: a.cvssVector };
  }
  return { severity: a.severity };
}

/** A VibeSec-defined vulnerability id for a finding with no public advisory: 'supply-chain/typosquat' → 'VIBESEC-SUPPLY-CHAIN-TYPOSQUAT'. */
export function vibesecVulnId(ruleId: string): string {
  return `VIBESEC-${ruleId.toUpperCase().replace(/[^A-Z0-9]+/g, '-').replace(/^-+|-+$/g, '')}`;
}

/** Builds and validates a CycloneDX 1.6 SBOM+VEX document limited to the vulnerable/flagged packages we persist. */
export function buildCycloneDx(scan: ScanDto, findings: readonly Finding[], now: string = new Date().toISOString()): CycloneDxBom {
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
    const analysis = analysisFor(f, dep.reachability, now);
    // A supply-chain signal (typosquat, install script, …) has no public advisory: it is reported as a
    // VibeSec-defined vulnerability (id from the rule, source VibeSec) so the package is not silently
    // listed as a component without any vulnerability.
    const advisories = dep.advisories.length > 0
      ? dep.advisories.map((a) => ({ ...a, source: { name: 'OSV' as const, url: a.url ?? `https://osv.dev/vulnerability/${a.id}` }, description: undefined }))
      : [{
        id: vibesecVulnId(f.ruleId), severity: f.severity, cvss: null, cvssVector: undefined,
        source: { name: 'VibeSec' as const, url: VIBESEC_INFORMATION_URI }, description: f.title,
      }];
    for (const a of advisories) {
      const existing = vulns.get(a.id);
      if (existing) {
        if (!existing.affects.some((x) => x.ref === purl)) existing.affects.push({ ref: purl });
        continue;
      }
      vulns.set(a.id, {
        id: a.id,
        source: a.source,
        ...(a.description ? { description: a.description } : {}),
        ratings: [ratingFor(a)],
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
