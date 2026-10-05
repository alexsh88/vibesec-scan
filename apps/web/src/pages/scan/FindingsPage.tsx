import { Outlet } from 'react-router';
import { PagePlaceholder } from '@/components/layout/Page';

/**
 * TODO(FindingsPage): spec screen 4 — tabs Code / Credentials / Dependencies / Config / Quality
 * (lib/taxonomy FINDING_TABS), filterable table (severity, file, q, triage, new/existing/fixed),
 * infinite scroll, counts per tab. Row click navigates to `/scans/:id/findings/:findingId`.
 * Data: useFindings(id, filters) — pages[0].counts has totals; keep filters in the URL search params.
 *
 * Keep the <Outlet /> — the finding drawer route (FindingDrawer) renders into it, over the list.
 */
export default function FindingsPage() {
  return (
    <>
      <PagePlaceholder
        title="Findings"
        spec="Spec screen 4: tabbed, filterable findings table. Selecting a row opens the finding drawer (nested route)."
      />
      <Outlet />
    </>
  );
}
