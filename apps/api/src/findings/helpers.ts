import { createHash } from 'node:crypto';
import type { Severity } from '@vibesec/shared';

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Stable across scans (new/existing/fixed in P7). */
export function fingerprint(parts: readonly string[]): string {
  return createHash('sha256').update(parts.join('\u0000')).digest('hex');
}

/**
 * I7: `encodeURIComponent` does not escape '.', so a `..`/`.` path segment would pass through a
 * permalink unencoded and could alter which path the URL actually points at. Percent-encode the dots
 * in any segment that consists ENTIRELY of dots (`.`, `..`, `...`, …) so it can never be interpreted
 * as a path-traversal segment by GitHub or any other consumer of this URL; an ordinary filename that
 * merely contains a dot (`file.name.ts`) is untouched.
 */
function encodePathSegment(segment: string): string {
  const encoded = encodeURIComponent(segment);
  return /^\.+$/.test(segment) ? encoded.replace(/\./g, '%2E') : encoded;
}

export function githubPermalink(repo: { owner: string; name: string }, sha: string, file: string, start: number, end: number): string {
  const path = file.split('/').map(encodePathSegment).join('/');
  return `https://github.com/${repo.owner}/${repo.name}/blob/${sha}/${path}${end > start ? `#L${start}-L${end}` : `#L${start}`}`;
}

/** Placeholder until P7 risk scoring. */
export function provisionalScore(severity: Severity): number {
  return { critical: 90, high: 70, medium: 50, low: 25, info: 5 }[severity];
}

export function bumpSeverity(severity: Severity, steps: number): Severity {
  return ORDER[Math.min(Math.max(ORDER.indexOf(severity) + steps, 0), ORDER.length - 1)]!;
}
