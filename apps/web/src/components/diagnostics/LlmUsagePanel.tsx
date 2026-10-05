import { Cpu } from 'lucide-react';
import type { Diagnostics, LlmTotals } from '@/lib/api';
import { formatCompact, formatInt, formatUsd } from '@/lib/format';
import { cn } from '@/lib/utils';
import { Meter, Panel } from './primitives';

/** LLM calls, tokens and $ per analyzer, with a cost-share bar and a token split bar per row. */
export function LlmUsagePanel({ llm }: { llm: Diagnostics['llm'] }) {
  const rows = [...llm.byAnalyzer].sort((a, b) => b.costUsd - a.costUsd);
  const maxCost = Math.max(1e-9, ...rows.map((r) => r.costUsd));
  const t = llm.totals;

  return (
    <Panel
      id="llm-h"
      icon={Cpu}
      title="LLM usage by analyzer"
      readout={
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className={cn('rounded border px-1.5 uppercase', llm.mode === 'live' ? 'border-signal/50 text-signal' : 'border-sev-medium/40 text-sev-medium')}>
            {llm.mode}
          </span>
          <span>prompt-cache hit {Math.round(llm.cacheHitRatio * 100)}%</span>
          {llm.breakerTrips > 0 && <span className="text-sev-high">breaker trips {llm.breakerTrips}</span>}
        </span>
      }
    >
      {llm.mode === 'mock' && (
        <p className="mb-3 text-xs text-muted-foreground">
          Mock mode: model responses are canned and costs are simulated from token counts — no API calls were billed.
        </p>
      )}
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No model calls were made for this scan.</p>
      ) : (
        <div className="relative overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <caption className="sr-only">LLM usage per analyzer</caption>
            <thead>
              <tr className="border-b text-right">
                <th scope="col" className="eyebrow py-2 pr-3 text-left text-[10px] font-medium">Analyzer</th>
                <th scope="col" className="eyebrow py-2 px-2 text-[10px] font-medium">Calls</th>
                <th scope="col" className="eyebrow py-2 px-2 text-[10px] font-medium">In</th>
                <th scope="col" className="eyebrow py-2 px-2 text-[10px] font-medium">Out</th>
                <th scope="col" className="eyebrow py-2 px-2 text-[10px] font-medium">Cache read</th>
                <th scope="col" className="eyebrow py-2 pl-2 text-[10px] font-medium">Cost</th>
                <th scope="col" className="eyebrow w-[22%] py-2 pl-4 text-left text-[10px] font-medium">Share</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {rows.map((r) => (
                <UsageRow key={r.analyzer} name={r.analyzer} r={r} share={r.costUsd / maxCost} total={t.costUsd} />
              ))}
            </tbody>
            <tfoot>
              <tr className="border-t-2 font-semibold">
                <th scope="row" className="py-2 pr-3 text-left font-mono text-xs">total</th>
                <Num v={t.calls} failed={t.failedCalls} />
                <Num v={t.inputTokens} compact />
                <Num v={t.outputTokens} compact />
                <Num v={t.cacheReadTokens} compact />
                <td className="py-2 pl-2 text-right font-mono text-xs tabular">{formatUsd(t.costUsd)}</td>
                <td />
              </tr>
            </tfoot>
          </table>
          <p className="mt-3 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10.5px] text-muted-foreground">
            <span className="flex items-center gap-1.5"><span aria-hidden className="h-1.5 w-3 rounded-full bg-signal" /> cost vs top analyzer</span>
            <span className="flex items-center gap-1.5"><span aria-hidden className="h-1 w-3 rounded-full bg-foreground/45" /> input tokens</span>
            <span className="flex items-center gap-1.5"><span aria-hidden className="h-1 w-3 rounded-full bg-sev-low" /> output</span>
            <span className="flex items-center gap-1.5"><span aria-hidden className="h-1 w-3 rounded-full bg-status-triaged" /> cache read</span>
          </p>
        </div>
      )}
    </Panel>
  );
}

function UsageRow({ name, r, share, total }: { name: string; r: LlmTotals; share: number; total: number }) {
  const tokens = r.inputTokens + r.outputTokens + r.cacheReadTokens;
  return (
    <tr>
      <th scope="row" className="py-2 pr-3 text-left font-mono text-xs font-medium">{name}</th>
      <Num v={r.calls} failed={r.failedCalls} />
      <Num v={r.inputTokens} compact />
      <Num v={r.outputTokens} compact />
      <Num v={r.cacheReadTokens} compact />
      <td className="py-2 pl-2 text-right font-mono text-xs tabular">{formatUsd(r.costUsd)}</td>
      <td className="py-2 pl-4">
        <div className="space-y-1">
          <Meter value={share} tone="signal" />
          {tokens > 0 && (
            <div className="flex h-1 overflow-hidden rounded-full bg-muted" title={`in ${r.inputTokens} · out ${r.outputTokens} · cache ${r.cacheReadTokens}`}>
              <span className="bg-foreground/45" style={{ width: `${(r.inputTokens / tokens) * 100}%` }} />
              <span className="bg-sev-low" style={{ width: `${(r.outputTokens / tokens) * 100}%` }} />
              <span className="bg-status-triaged" style={{ width: `${(r.cacheReadTokens / tokens) * 100}%` }} />
            </div>
          )}
          <span className="block font-mono text-[10px] text-muted-foreground tabular">
            {total > 0 ? `${Math.round((r.costUsd / total) * 100)}% of spend` : '—'}
          </span>
        </div>
      </td>
    </tr>
  );
}

function Num({ v, compact, failed }: { v: number; compact?: boolean; failed?: number }) {
  return (
    <td className={cn('px-2 py-2 text-right font-mono text-xs tabular', v === 0 && 'text-muted-foreground/40')} title={formatInt(v)}>
      {compact ? formatCompact(v) : formatInt(v)}
      {failed ? <span className="ml-1 text-sev-critical" title={`${failed} failed`}>({failed}✕)</span> : null}
    </td>
  );
}
