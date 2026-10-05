import type { Finding, ScanSummary } from '@vibesec/shared';
import { ShieldCheck } from 'lucide-react';
import { EmptyState } from '@/components/feedback/EmptyState';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { SEVERITY_CLASSES } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';
import { FindingRefList } from './FindingRef';
import { Panel } from './Panel';

/** 3–5 most important risks, most important first, each linking to its findings. */
export function TopRisks({ summary, scanId, byId }: { summary: ScanSummary; scanId: string; byId: Map<string, Finding> }) {
  const risks = summary.topRisks;
  return (
    <Panel id="top-risks" title="Top risks" meta={risks.length > 0 ? `${risks.length} ranked` : undefined} bodyClassName="p-0">
      {risks.length === 0 ? (
        <EmptyState icon={ShieldCheck} title="No significant risks" description="Nothing in this scan rose to a top risk." className="m-4 border-none" />
      ) : (
        <ol className="divide-y">
          {risks.map((r, i) => (
            <li key={`${i}-${r.title}`} className="relative flex gap-3 px-4 py-4 sm:gap-4">
              <span aria-hidden className={cn('absolute inset-y-3 left-0 w-[3px] rounded-r', SEVERITY_CLASSES[r.severity].bg)} />
              <span className="font-mono text-xs leading-6 text-muted-foreground tabular">{String(i + 1).padStart(2, '0')}</span>
              <div className="min-w-0 flex-1 space-y-2">
                <div className="flex flex-wrap items-start gap-x-3 gap-y-1">
                  <h3 className="min-w-0 flex-1 text-sm leading-6 font-semibold text-balance">{r.title}</h3>
                  <SeverityBadge severity={r.severity} />
                </div>
                <p className="text-sm leading-relaxed text-muted-foreground text-pretty">{r.whyItMatters}</p>
                <FindingRefList scanId={scanId} ids={r.findingIds} byId={byId} />
              </div>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}
