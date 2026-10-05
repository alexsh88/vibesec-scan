import type { Finding } from '@vibesec/shared';

/** cwe.mitre.org page for "CWE-89" / "89"; null when the id is not numeric. */
export function cweUrl(cwe: string): string | null {
  const n = cwe.match(/(\d+)/)?.[1];
  return n ? `https://cwe.mitre.org/data/definitions/${n}.html` : null;
}

/**
 * Permalink for another file/line of the same commit, derived from the finding's own permalink
 * (`https://github.com/o/r/blob/<sha>/<path>#L..`). Null when the base is not a GitHub blob URL.
 */
export function permalinkFor(base: string, file: string, line: number): string | null {
  const m = base.match(/^(https:\/\/github\.com\/[^/]+\/[^/]+\/blob\/[^/]+)\//);
  if (!m) return null;
  const path = file.split('/').map(encodeURIComponent).join('/');
  return `${m[1]}/${path}#L${line}`;
}

export function commitUrl(base: string, sha: string): string | null {
  const m = base.match(/^(https:\/\/github\.com\/[^/]+\/[^/]+)\//);
  return m ? `${m[1]}/commit/${encodeURIComponent(sha)}` : null;
}

export function advisoryUrl(a: { id: string; url: string | null }): string {
  return a.url ?? `https://osv.dev/vulnerability/${encodeURIComponent(a.id)}`;
}

export const CONFIDENCE_LABEL: Record<Finding['confidence'], string> = { high: 'High', medium: 'Medium', low: 'Low' };

const FACTOR_LABEL: Record<string, string> = {
  live_credential: 'Live credential',
  revoked_credential: 'Revoked credential',
  history_only: 'History only',
  client_exposed: 'Client-exposed',
  reachable: 'Reachable',
  transitive_unknown: 'Transitive',
  unreachable: 'Unreachable',
  dev_dependency: 'Dev dependency',
  devDependency: 'Dev dependency',
  public_route: 'Public route',
  entrypoint: 'Entrypoint',
  non_production_code: 'Non-production code',
  generated_code: 'Generated code',
  medium_confidence: 'Medium confidence',
  low_confidence: 'Low confidence',
  skeptic_weakened: 'Skeptic review',
  ai_unreviewed: 'AI unreviewed',
  ai_refuted: 'AI refuted',
  ai_false_positive: 'AI: false positive',
  malicious: 'Malicious package',
  'policy:malicious-floor': 'Policy: malicious floor',
  'policy:ai-refuted-ceiling': 'Policy: AI-refuted ceiling',
  'policy:live-credential-floor': 'Policy: live credential floor',
};

const human = (s: string) =>
  s.replace(/[_-]+/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^\w/, (c) => c.toUpperCase());

export function factorLabel(factor: string): string {
  const known = FACTOR_LABEL[factor];
  if (known) return known;
  const [head = factor, tail] = factor.split(':');
  return tail ? `${human(head)}: ${tail.replace(/[_-]+/g, ' ')}` : human(factor);
}

/** AI review / skeptic verdicts: their reasons are always shown, not just on hover. */
export function isReviewFactor(factor: string): boolean {
  return factor.startsWith('ai_') || factor.startsWith('skeptic') || factor === 'policy:ai-refuted-ceiling';
}

export function formatEffect(effect: number): string {
  if (effect > 0) return `+${effect}`;
  if (effect < 0) return `−${Math.abs(effect)}`;
  return '±0';
}
