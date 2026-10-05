import { PagePlaceholder } from '@/components/layout/Page';

/**
 * TODO(LiveScanPage): Spec screen 2: pipeline stepper (lib/scanState PIPELINE_STAGES), analyzer progress, streaming findings, cost/cache ticker, warnings; on done link to overview.
 * Data: useScanContext().events (SSE state: progress, findings, cost, cache, warnings, summary, done) — never open a second EventSource.
 */
export default function LiveScanPage() {
  return <PagePlaceholder title="Live scan" spec="Spec screen 2: pipeline stepper (lib/scanState PIPELINE_STAGES), analyzer progress, streaming findings, cost/cache ticker, warnings; on done link to overview." />;
}
