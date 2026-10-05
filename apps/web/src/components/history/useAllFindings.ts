import type { Finding } from '@vibesec/shared';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

/** Hard stop for the compare view: enough for real repos, bounded memory for pathological ones. */
export const COMPARE_CAP = 5_000;
const PAGE = 200;

export type AllFindings = { items: Finding[]; truncated: boolean; total: number };

/**
 * Every current finding (new + existing, triaged included) of a scan, following cursors until the
 * end or COMPARE_CAP. Lives under ['scans', id, 'findings', …] so triage invalidation refreshes it.
 */
export function useAllFindings(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scans', scanId ?? '', 'findings', { compareAll: true }] as const,
    enabled: !!scanId,
    staleTime: 60_000,
    queryFn: async ({ signal }): Promise<AllFindings> => {
      const items: Finding[] = [];
      let cursor: string | undefined;
      let total = 0;
      do {
        const page = await api.listFindings(scanId!, { limit: PAGE }, cursor, signal);
        total = page.counts.total;
        items.push(...page.items);
        cursor = page.nextCursor ?? undefined;
      } while (cursor && items.length < COMPARE_CAP);
      const truncated = !!cursor || items.length > COMPARE_CAP;
      return { items: items.slice(0, COMPARE_CAP), truncated, total };
    },
  });
}
