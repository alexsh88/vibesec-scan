import type { Finding, FixAction, NextAction, ScanSummary } from '@vibesec/shared';
import { Check, Copy, ListChecks, Wrench } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { EmptyState } from '@/components/feedback/EmptyState';
import { Checkbox } from '@/components/ui/checkbox';
import { cn } from '@/lib/utils';
import { FindingRefList } from './FindingRef';
import { Panel } from './Panel';

const EFFORT: Record<NextAction['effort'], { label: string; cls: string }> = {
  minutes: { label: 'minutes', cls: 'border-signal/40 bg-signal-soft text-foreground' },
  hours: { label: 'hours', cls: 'border-border bg-muted text-foreground' },
  days: { label: 'days', cls: 'border-sev-medium/35 bg-sev-medium/10 text-sev-medium' },
};

const storageKey = (scanId: string) => `vibesec:overview:done:${scanId}`;

function readDone(scanId: string): number[] {
  try {
    const raw = window.localStorage.getItem(storageKey(scanId));
    const v: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(v) ? v.filter((n): n is number => typeof n === 'number') : [];
  } catch {
    return [];
  }
}

/** Checklist state is per browser, per scan (localStorage; silently in-memory when storage is blocked). */
function useDoneSet(scanId: string) {
  const [done, setDone] = useState<Set<number>>(() => new Set(readDone(scanId)));
  useEffect(() => setDone(new Set(readDone(scanId))), [scanId]);
  const toggle = useCallback(
    (i: number, on: boolean) => {
      setDone((prev) => {
        const next = new Set(prev);
        if (on) next.add(i);
        else next.delete(i);
        try {
          window.localStorage.setItem(storageKey(scanId), JSON.stringify([...next]));
        } catch {
          /* storage unavailable — keep in memory */
        }
        return next;
      });
    },
    [scanId],
  );
  return { done, toggle };
}

function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1_500);
    } catch {
      /* clipboard blocked */
    }
  };
  return (
    <div className="flex min-w-0 items-center gap-1 rounded-md border border-l-2 border-l-signal bg-surface-raised pl-2.5">
      <code className="min-w-0 flex-1 overflow-x-auto py-1.5 font-mono text-xs whitespace-nowrap">{command}</code>
      <button
        type="button"
        onClick={copy}
        aria-label={copied ? 'Copied' : 'Copy command'}
        className="grid size-7 shrink-0 place-items-center rounded-r-md border-l text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        {copied ? <Check className="size-3.5 text-status-fixed" /> : <Copy className="size-3.5" />}
      </button>
    </div>
  );
}

/** Ordered "do this first" checklist; dependency actions carry their fix-plan command. */
export function NextActions({
  summary,
  scanId,
  byId,
  fixActions,
}: {
  summary: ScanSummary;
  scanId: string;
  byId: Map<string, Finding>;
  fixActions: Map<string, FixAction>;
}) {
  const { done, toggle } = useDoneSet(scanId);
  const actions = summary.nextActions;
  const doneCount = actions.reduce((n, _, i) => n + (done.has(i) ? 1 : 0), 0);

  return (
    <Panel
      id="next-actions"
      title="Next actions"
      meta={actions.length > 0 ? `${doneCount}/${actions.length} done` : undefined}
      bodyClassName="p-0"
    >
      {actions.length === 0 ? (
        <EmptyState icon={ListChecks} title="Nothing to do" description="No follow-up actions were suggested for this scan." className="m-4 border-none" />
      ) : (
        <>
          <div
            aria-hidden
            className="h-0.5 bg-signal transition-[width] duration-500"
            style={{ width: `${(doneCount / actions.length) * 100}%` }}
          />
          <ol className="divide-y">
            {actions.map((a, i) => {
              const checked = done.has(i);
              const fix = a.fixActionId ? fixActions.get(a.fixActionId) : undefined;
              const cbId = `next-action-${i}`;
              return (
                <li key={`${i}-${a.title}`} className="flex gap-3 px-4 py-4">
                  <Checkbox
                    id={cbId}
                    checked={checked}
                    onCheckedChange={(v) => toggle(i, v === true)}
                    className="mt-0.5"
                    aria-describedby={`${cbId}-detail`}
                  />
                  <div className={cn('min-w-0 flex-1 space-y-2 transition-opacity', checked && 'opacity-55')}>
                    <div className="flex flex-wrap items-start gap-x-3 gap-y-1">
                      <label htmlFor={cbId} className={cn('min-w-0 flex-1 cursor-pointer text-sm leading-5 font-medium', checked && 'line-through decoration-muted-foreground/60')}>
                        <span className="mr-2 font-mono text-xs text-muted-foreground tabular">{i + 1}.</span>
                        {a.title}
                      </label>
                      <span
                        className={cn('inline-flex h-5 items-center rounded-full border px-2 font-mono text-[10px] tracking-wide uppercase', EFFORT[a.effort].cls)}
                        title={`Estimated effort: ${EFFORT[a.effort].label}`}
                      >
                        ~{EFFORT[a.effort].label}
                      </span>
                    </div>
                    <p id={`${cbId}-detail`} className="text-sm leading-relaxed text-muted-foreground text-pretty">
                      {a.detail}
                    </p>
                    {fix && (
                      <div className="space-y-1.5">
                        <CopyCommand command={fix.command} />
                        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                          <Wrench aria-hidden className="size-3.5" />
                          <span>
                            Fixes <span className="font-medium text-foreground tabular">{fix.resolvedCount}</span>{' '}
                            {fix.resolvedCount === 1 ? 'issue' : 'issues'}
                          </span>
                          <span className="font-mono text-[11px]">
                            {fix.package} {fix.from} → {fix.to ?? 'remove'}
                          </span>
                          {fix.breakingRisk && (
                            <span className="rounded border border-sev-medium/35 bg-sev-medium/10 px-1.5 font-mono text-[10px] text-sev-medium uppercase">
                              {fix.semverJump ?? 'major'} · may break
                            </span>
                          )}
                        </p>
                      </div>
                    )}
                    <FindingRefList scanId={scanId} ids={a.findingIds} byId={byId} />
                  </div>
                </li>
              );
            })}
          </ol>
        </>
      )}
    </Panel>
  );
}
