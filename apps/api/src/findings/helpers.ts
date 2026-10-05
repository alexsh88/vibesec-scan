import { createHash } from 'node:crypto';
import type { Severity } from '@vibesec/shared';

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Stable across scans (new/existing/fixed in P7). */
export function fingerprint(parts: readonly string[]): string {
  return createHash('sha256').update(parts.join('\u0000')).digest('hex');
}

export function githubPermalink(repo: { owner: string; name: string }, sha: string, file: string, start: number, end: number): string {
  const path = file.split('/').map(encodeURIComponent).join('/');
  return `https://github.com/${repo.owner}/${repo.name}/blob/${sha}/${path}${end > start ? `#L${start}-L${end}` : `#L${start}`}`;
}

/** Placeholder until P7 risk scoring. */
export function provisionalScore(severity: Severity): number {
  return { critical: 90, high: 70, medium: 50, low: 25, info: 5 }[severity];
}

export function bumpSeverity(severity: Severity, steps: number): Severity {
  return ORDER[Math.min(Math.max(ORDER.indexOf(severity) + steps, 0), ORDER.length - 1)]!;
}
