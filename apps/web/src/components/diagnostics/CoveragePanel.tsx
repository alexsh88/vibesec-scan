import { ChevronDown, FileSearch } from 'lucide-react';
import { useState } from 'react';
import { Panel } from '@/components/common/Panel';
import { StackedBar, type Segment } from '@/components/common/StackedBar';
import type { CoverageStatus, Diagnostics } from '@/lib/api';
import { formatInt } from '@/lib/format';
import { cn } from '@/lib/utils';

export const COVERAGE_META: Record<CoverageStatus, { label: string; cls: string; hint: string }> = {
  reviewed: { label: 'Reviewed', cls: 'bg-signal', hint: 'Deep AI review of the file' },
  'reviewed-fast': { label: 'Reviewed (fast)', cls: 'bg-signal/50', hint: 'Reviewed by the fast model only' },
  cached: { label: 'Cached', cls: 'bg-status-triaged', hint: 'Result reused from an earlier scan (unchanged file)' },
  'not-relevant': { label: 'Not relevant', cls: 'bg-muted-foreground/35', hint: 'Pre-filter decided the analyzer has nothing to look at' },
  'budget-skipped': { label: 'Budget-skipped', cls: 'bg-sev-medium', hint: 'Not reviewed because the scan’s AI budget ran out' },
  failed: { label: 'Failed', cls: 'bg-sev-critical', hint: 'The model call failed after retries' },
};

const ORDER: CoverageStatus[] = ['reviewed', 'reviewed-fast', 'cached', 'not-relevant', 'budget-skipped', 'failed'];

const segs = (c: Record<CoverageStatus, number>): Segment[] =>
  ORDER.map((k) => ({ key: k, value: c[k] ?? 0, className: COVERAGE_META[k].cls, label: COVERAGE_META[k].label }));

const sum = (c: Record<CoverageStatus, number>): number => ORDER.reduce((s, k) => s + (c[k] ?? 0), 0);

export function CoveragePanel({ coverage }: { coverage: Diagnostics['coverage'] }) {
  const total = sum(coverage.totals);
  const covered = (coverage.totals.reviewed ?? 0) + (coverage.totals['reviewed-fast'] ?? 0) + (coverage.totals.cached ?? 0);
  const relevant = total - (coverage.totals['not-relevant'] ?? 0);
  const pct = relevant > 0 ? Math.round((covered / relevant) * 100) : 100;
  const analyzers = Object.entries(coverage.byAnalyzer).sort((a, b) => sum(b[1]) - sum(a[1]));

  return (
    <Panel id="coverage-h" icon={FileSearch} title="AI review coverage" meta={`${pct}% of relevant file-reviews done · ${formatInt(total)} total`}>
      <div className="space-y-4">
        <StackedBar segments={segs(coverage.totals)} height="h-3" />
        <ul className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3 lg:grid-cols-6">
          {ORDER.map((k) => (
            <li key={k} className="space-y-0.5" title={COVERAGE_META[k].hint}>
              <span className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                <span aria-hidden className={cn('size-2 rounded-[2px]', COVERAGE_META[k].cls)} />
                {COVERAGE_META[k].label}
              </span>
              <span
                className={cn(
                  'block font-mono text-lg font-semibold tabular',
                  k === 'failed' && coverage.totals[k] > 0 && 'text-sev-critical',
                  k === 'budget-skipped' && coverage.totals[k] > 0 && 'text-sev-medium',
                  (coverage.totals[k] ?? 0) === 0 && 'text-muted-foreground/50',
                )}
              >
                {formatInt(coverage.totals[k] ?? 0)}
              </span>
            </li>
          ))}
        </ul>

        {analyzers.length > 0 && (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[560px] text-sm">
              <caption className="sr-only">Coverage per analyzer</caption>
              <thead>
                <tr className="border-b text-left">
                  <th scope="col" className="eyebrow py-2 pr-3 text-[10px] font-medium">Analyzer</th>
                  <th scope="col" className="eyebrow w-[38%] py-2 pr-3 text-[10px] font-medium">Breakdown</th>
                  {ORDER.map((k) => (
                    <th key={k} scope="col" className="eyebrow py-2 pl-2 text-right text-[10px] font-medium" title={COVERAGE_META[k].label}>
                      <span aria-hidden className={cn('ml-auto block size-2 rounded-[2px]', COVERAGE_META[k].cls)} />
                      <span className="sr-only">{COVERAGE_META[k].label}</span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y">
                {analyzers.map(([name, c]) => (
                  <tr key={name}>
                    <th scope="row" className="py-2 pr-3 text-left font-mono text-xs font-medium">{name}</th>
                    <td className="py-2 pr-3">
                      <StackedBar segments={segs(c)} />
                    </td>
                    {ORDER.map((k) => (
                      <td key={k} className={cn('py-2 pl-2 text-right font-mono text-xs tabular', (c[k] ?? 0) === 0 && 'text-muted-foreground/40')}>
                        {c[k] ?? 0}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <BudgetSkipped items={coverage.budgetSkipped} />
      </div>
    </Panel>
  );
}

function BudgetSkipped({ items }: { items: Diagnostics['coverage']['budgetSkipped'] }) {
  const [open, setOpen] = useState(false);
  if (items.length === 0) {
    return <p className="font-mono text-[11px] text-muted-foreground">No files were skipped for budget.</p>;
  }
  return (
    <div className="rounded-md border border-sev-medium/35 bg-sev-medium/5">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <span aria-hidden className="size-2 rounded-[2px] bg-sev-medium" />
        <span className="font-medium">{items.length} file-review{items.length === 1 ? '' : 's'} skipped for budget</span>
        <span className="text-xs text-muted-foreground">— raise the scan budget to cover them</span>
        <ChevronDown aria-hidden className={cn('ml-auto size-4 text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <ul className="max-h-72 overflow-auto border-t px-3 py-2 font-mono text-[11px]">
          {items.map((it) => (
            <li key={`${it.analyzer}:${it.path}`} className="flex gap-3 py-0.5">
              <span className="w-28 shrink-0 truncate text-muted-foreground">{it.analyzer}</span>
              <span className="break-all">{it.path}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
