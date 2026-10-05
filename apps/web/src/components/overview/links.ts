import type { Category, Finding, Severity } from '@vibesec/shared';

/**
 * Deep links into the findings list. Filters travel as URL search params named exactly like the
 * API's FindingFilters keys (`severity`, `category`, `scanStatus`), which is what FindingsPage reads.
 */
export function findingsHref(
  scanId: string,
  filters: { severity?: Severity; category?: Category; scanStatus?: Finding['scanStatus'] } = {},
): string {
  const qs = new URLSearchParams();
  if (filters.severity) qs.set('severity', filters.severity);
  if (filters.category) qs.set('category', filters.category);
  if (filters.scanStatus) qs.set('scanStatus', filters.scanStatus);
  const s = qs.toString();
  return `/scans/${encodeURIComponent(scanId)}/findings${s ? `?${s}` : ''}`;
}

/** The finding drawer route (rendered over the findings list). */
export const findingHref = (scanId: string, findingId: string): string =>
  `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`;
