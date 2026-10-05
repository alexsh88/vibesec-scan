import type { FixAction, FixPlan, Severity } from '@vibesec/shared';
import {
  ArrowRight,
  ArrowUpFromLine,
  ChevronDown,
  CircleOff,
  ExternalLink,
  GitFork,
  Layers,
  ListChecks,
  Trash2,
  TriangleAlert,
} from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { Button } from '@/components/ui/button';
import { formatInt } from '@/lib/format';
import { SEVERITY_CLASSES, SEVERITY_ORDER } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';
import { CommandLine } from './CopyButton';
import { actionAnchor, actionPackages, actionTally, libraryAnchor, osvUrl, splitCommand, type SeverityTally } from './depModel';

const KIND_META: Record<FixAction['kind'], { label: string; icon: typeof Layers; hint: string }> = {
  'upgrade-direct': { label: 'Upgrade', icon: ArrowUpFromLine, hint: 'Bump a dependency you declare directly.' },
  'upgrade-parent': { label: 'Upgrade parent', icon: GitFork, hint: 'Bump the direct dependency that pulls the vulnerable package in.' },
  override: { label: 'Override', icon: Layers, hint: 'Pin the nested package to a fixed version (overrides / resolutions).' },
  remove: { label: 'Remove', icon: Trash2, hint: 'No fixed version exists — remove or replace the package.' },
};

const JUMP_CLS: Record<NonNullable<FixAction['semverJump']>, string> = {
  patch: 'border-status-fixed/40 bg-status-fixed/10 text-status-fixed',
  minor: 'border-sev-medium/40 bg-sev-medium/10 text-sev-medium',
  major: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
};

const INITIAL = 5;

type Props = {
  scanId: string;
  plan: FixPlan;
  /** Action ids to show expanded (e.g. the one a library row jumped to). */
  expanded: ReadonlySet<string>;
  onToggle: (id: string) => void;
  flashId: string | null;
  showAll: boolean;
  onShowAll: () => void;
};

export function FixPlanPanel({ scanId, plan, expanded, onToggle, flashId, showAll, onShowAll }: Props) {
  const { actions, unfixable } = plan;
  const maxRisk = Math.max(1, ...actions.map((a) => a.riskReduced));
  const totalAdvisories = new Set(actions.flatMap((a) => a.resolves.map((r) => r.advisoryId))).size;
  const visible = showAll ? actions : actions.slice(0, INITIAL);

  return (
    <section aria-labelledby="fixplan-heading" className="space-y-3">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h2 id="fixplan-heading" className="eyebrow flex items-center gap-2">
          <ListChecks aria-hidden className="size-3.5 text-signal" /> Next actions · ranked by risk removed per effort
        </h2>
        {actions.length > 0 && (
          <p className="font-mono text-[11px] text-muted-foreground tabular">
            {actions.length} action{actions.length === 1 ? '' : 's'} clear {formatInt(totalAdvisories)} advisor{totalAdvisories === 1 ? 'y' : 'ies'}
          </p>
        )}
      </div>

      {actions.length === 0 ? (
        <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">
          No upgrade path to compute — nothing fixable was found.
        </p>
      ) : (
        <ol className="space-y-2">
          {visible.map((a, i) => (
            <ActionCard
              key={a.id}
              scanId={scanId}
              action={a}
              rank={i + 1}
              maxRisk={maxRisk}
              open={expanded.has(a.id)}
              onToggle={() => onToggle(a.id)}
              flash={flashId === a.id}
            />
          ))}
        </ol>
      )}
      {!showAll && actions.length > INITIAL && (
        <Button variant="ghost" size="sm" onClick={onShowAll} className="font-mono text-xs">
          <ChevronDown /> Show {actions.length - INITIAL} more action{actions.length - INITIAL === 1 ? '' : 's'}
        </Button>
      )}

      {unfixable.length > 0 && <UnfixableList items={unfixable} />}
    </section>
  );
}

function ActionCard({
  scanId, action: a, rank, maxRisk, open, onToggle, flash,
}: { scanId: string; action: FixAction; rank: number; maxRisk: number; open: boolean; onToggle: () => void; flash: boolean }) {
  const kind = KIND_META[a.kind];
  const tally = actionTally(a);
  const pkgs = actionPackages(a);
  const vulnerableNames = [...new Set(pkgs.map((p) => p.name))].filter((n) => n !== a.package);
  const pct = Math.max(4, Math.round((a.riskReduced / maxRisk) * 100));
  const detailsId = `${actionAnchor(a)}-details`;
  const topSeverity = SEVERITY_ORDER.find((s) => tally[s] > 0);

  return (
    <li
      id={actionAnchor(a)}
      className={cn(
        'scroll-mt-24 overflow-hidden rounded-lg border bg-card transition-shadow duration-500',
        flash && 'ring-2 ring-signal ring-offset-2 ring-offset-background',
      )}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={detailsId}
        className="group grid w-full grid-cols-[auto_1fr_auto] items-start gap-x-3 gap-y-2 px-3 py-3 text-left hover:bg-accent/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none sm:grid-cols-[auto_1fr_minmax(9rem,13rem)_auto] sm:px-4"
      >
        <span
          aria-hidden
          className={cn(
            'mt-0.5 grid size-7 place-items-center rounded-md border font-mono text-xs font-semibold tabular',
            rank === 1 ? 'border-signal/50 bg-signal-soft text-signal' : 'text-muted-foreground',
          )}
        >
          {String(rank).padStart(2, '0')}
        </span>

        <span className="min-w-0 space-y-1.5">
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10.5px] tracking-wide text-muted-foreground uppercase" title={kind.hint}>
              <kind.icon aria-hidden className="size-3" /> {kind.label}
            </span>
            <span className="font-mono text-sm font-medium break-all">{a.package}</span>
            <span className="inline-flex items-center gap-1 font-mono text-xs tabular">
              <span className="text-muted-foreground line-through decoration-muted-foreground/50">{a.from}</span>
              <ArrowRight aria-hidden className="size-3 text-muted-foreground" />
              {a.to ? <span className="font-semibold text-signal">{a.to}</span> : <span className="text-sev-critical">no fix</span>}
            </span>
            {a.semverJump && (
              <span className={cn('rounded-full border px-1.5 font-mono text-[10px] leading-4 uppercase', JUMP_CLS[a.semverJump])}>{a.semverJump}</span>
            )}
            {a.breakingRisk && (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-sev-high" title="A major version bump or API change — run your tests">
                <TriangleAlert aria-hidden className="size-3" /> may break
              </span>
            )}
          </span>
          <span className="block text-sm">
            Fixes <strong className="font-semibold tabular">{a.resolvedCount}</strong> advisor{a.resolvedCount === 1 ? 'y' : 'ies'}
            {pkgs.length > 1 ? (
              <span className="text-muted-foreground">
                {' '}in <strong className="font-semibold text-foreground tabular">{pkgs.length}</strong> vulnerable packages
              </span>
            ) : pkgs[0] && pkgs[0].name !== a.package ? (
              <span className="text-muted-foreground"> in {pkgs[0].name}@{pkgs[0].version}</span>
            ) : null}
            {a.kind === 'upgrade-parent' && pkgs.length > 1 && vulnerableNames.length > 0 && (
              <span className="text-muted-foreground">
                {' '}— pulls in fixed <span className="font-mono text-foreground">{vulnerableNames.slice(0, 3).join(', ')}</span>
                {vulnerableNames.length > 3 && ` +${vulnerableNames.length - 3}`}
              </span>
            )}
          </span>
          <SeverityTallyLine tally={tally} />
        </span>

        <span className="col-span-3 col-start-2 space-y-1 sm:col-span-1 sm:col-start-3">
          <span className="flex items-baseline justify-between font-mono text-[10.5px] text-muted-foreground uppercase">
            <span>risk removed</span>
            <span className="text-foreground tabular">{Math.round(a.riskReduced)}</span>
          </span>
          <span className="block h-1.5 overflow-hidden rounded-full bg-muted" role="presentation">
            <span className={cn('block h-full rounded-full', barClass(topSeverity))} style={{ width: `${pct}%` }} />
          </span>
        </span>

        <ChevronDown
          aria-hidden
          className={cn('col-start-3 row-start-1 mt-1.5 size-4 text-muted-foreground transition-transform sm:col-start-4', open && 'rotate-180')}
        />
      </button>

      {open && (
        <div id={detailsId} className="space-y-4 border-t bg-surface-raised/50 px-3 py-4 sm:px-4 sm:pl-14">
          <ActionCommand action={a} />

          <div className="space-y-2">
            <p className="eyebrow">What this resolves</p>
            <ul className="divide-y rounded-md border bg-card">
              {pkgs.map((p) => (
                <li key={`${p.name}@${p.version}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                  <a href={`#${libraryAnchor(p.findingId)}`} className="font-mono text-xs font-medium hover:underline">
                    {p.name}@{p.version}
                  </a>
                  <span className="flex flex-1 flex-wrap gap-1.5">
                    {p.advisories.map((r) => (
                      <a
                        key={r.advisoryId}
                        href={osvUrl(r.advisoryId)}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10.5px] hover:bg-accent"
                      >
                        <span aria-hidden className={cn('size-1.5 rounded-full', SEVERITY_CLASSES[r.severity].dot)} />
                        {r.advisoryId}
                      </a>
                    ))}
                  </span>
                  <Link to={`/scans/${scanId}/findings/${p.findingId}`} className="text-xs text-muted-foreground hover:text-foreground hover:underline">
                    Open finding
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {a.notes.length > 0 && (
            <ul className="space-y-1 text-xs text-muted-foreground">
              {a.notes.map((n) => (
                <li key={n} className="flex gap-2">
                  <span aria-hidden className="text-signal">›</span>
                  {n}
                </li>
              ))}
            </ul>
          )}
          <p className="font-mono text-[10.5px] text-muted-foreground">
            {a.ecosystem} · {a.lockfile}
            {a.manifestDir ? ` · ${a.manifestDir}` : ''} · effort {a.effort} · priority {a.priority.toFixed(1)}
          </p>
        </div>
      )}
    </li>
  );
}

function ActionCommand({ action }: { action: FixAction }) {
  const cmd = splitCommand(action.command);
  if (cmd.instruction) {
    return (
      <div className="space-y-1.5">
        <p className="eyebrow">{cmd.instruction}</p>
        <CommandLine text={cmd.snippet} prompt="{}" />
        {cmd.then && (
          <>
            <p className="eyebrow">then run</p>
            <CommandLine text={cmd.then} />
          </>
        )}
      </div>
    );
  }
  return (
    <div className="space-y-1.5">
      <p className="eyebrow">Command</p>
      <CommandLine text={cmd.snippet} />
    </div>
  );
}

function UnfixableList({ items }: { items: FixPlan['unfixable'] }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, 6);
  return (
    <div className="rounded-lg border border-dashed p-3 sm:p-4">
      <p className="eyebrow mb-2 flex items-center gap-2">
        <CircleOff aria-hidden className="size-3.5" /> No fix available · {items.length}
      </p>
      <ul className="space-y-2">
        {shown.map((u) => (
          <li key={`${u.package}@${u.version}`} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
            <span className="font-mono text-xs font-medium">
              {u.package}@{u.version}
            </span>
            <span className="flex flex-wrap gap-1.5">
              {u.advisoryIds.map((id) => (
                <a key={id} href={osvUrl(id)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 font-mono text-[10.5px] text-muted-foreground hover:text-foreground hover:underline">
                  {id} <ExternalLink aria-hidden className="size-2.5" />
                </a>
              ))}
            </span>
            <span className="w-full text-xs text-muted-foreground sm:w-auto sm:flex-1">{u.reason}</span>
          </li>
        ))}
      </ul>
      {!all && items.length > shown.length && (
        <Button variant="ghost" size="sm" onClick={() => setAll(true)} className="mt-2 font-mono text-xs">
          <ChevronDown /> Show {items.length - shown.length} more
        </Button>
      )}
    </div>
  );
}

function barClass(s: Severity | undefined): string {
  switch (s) {
    case 'critical': return 'bg-sev-critical';
    case 'high': return 'bg-sev-high';
    case 'medium': return 'bg-sev-medium';
    case 'low': return 'bg-sev-low';
    default: return 'bg-signal';
  }
}

/** "● 1 critical · ● 2 high" in severity colours (text, so meaning never depends on colour alone). */
export function SeverityTallyLine({ tally, className }: { tally: SeverityTally; className?: string }) {
  return (
    <span className={cn('flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] tabular', className)}>
      {SEVERITY_ORDER.filter((s) => tally[s] > 0).map((s) => (
        <span key={s} className={cn('inline-flex items-center gap-1', SEVERITY_CLASSES[s].text)}>
          <span aria-hidden className={cn('size-1.5 rounded-full', SEVERITY_CLASSES[s].dot)} />
          {tally[s]} {s}
        </span>
      ))}
    </span>
  );
}
