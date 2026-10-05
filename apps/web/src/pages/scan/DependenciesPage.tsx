import { PagePlaceholder } from '@/components/layout/Page';

/**
 * TODO(DependenciesPage): Spec screen 6: CVEs grouped per library (reachability, paths, advisories) + fix plan actions ('upgrade X fixes N issues', command, breaking risk) + unfixable.
 * Data: useFixPlan, useFindings(id, { category: 'dependency' }), useScanIndex.
 */
export default function DependenciesPage() {
  return <PagePlaceholder title="Dependencies & fix plan" spec="Spec screen 6: CVEs grouped per library (reachability, paths, advisories) + fix plan actions ('upgrade X fixes N issues', command, breaking risk) + unfixable." />;
}
