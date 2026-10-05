import { PagePlaceholder } from '@/components/layout/Page';

/**
 * TODO(RepoHistoryPage): Spec screen 7: all scans of a repo (grade, state, cost, new/fixed deltas), compare two scans, rescan button.
 * Data: useRepoScans(repoId) (newest first), useRepos for repo name, useSummary per scan for grade.
 */
export default function RepoHistoryPage() {
  return <PagePlaceholder title="Scan history" spec="Spec screen 7: all scans of a repo (grade, state, cost, new/fixed deltas), compare two scans, rescan button." />;
}
