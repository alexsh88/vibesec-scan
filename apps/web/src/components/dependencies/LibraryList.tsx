import type { FixAction } from '@vibesec/shared';
import { ArrowRight, ChevronRight, ExternalLink, FileCode2, PanelRightOpen, Wrench } from 'lucide-react';
import { Link } from 'react-router';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { TriagePill } from '@/components/security/StatusPill';
import { cn } from '@/lib/utils';
import {
  advisoryTally,
  cveIds,
  libraryAnchor,
  maxCvss,
  osvUrl,
  type DepFinding,
} from './depModel';
import { SeverityTallyLine } from './FixPlanPanel';
import { ReachabilityBadge } from './ReachabilityBadge';

type Props = {
  scanId: string;
  items: DepFinding[];
  fixFor: ReadonlyMap<string, FixAction>;
  actionRank: ReadonlyMap<string, number>;
  expanded: ReadonlySet<string>;
  onToggle: (findingId: string) => void;
  onJumpToAction: (actionId: string) => void;
};

export function LibraryList({ scanId, items, fixFor, actionRank, expanded, onToggle, onJumpToAction }: Props) {
  return (
    <ul className="divide-y overflow-hidden rounded-lg border bg-card">
      {items.map((f) => (
        <LibraryRow
          key={f.id}
          scanId={scanId}
          f={f}
          fix={fixFor.get(f.id)}
          rank={fixFor.get(f.id) ? actionRank.get(fixFor.get(f.id)!.id) : undefined}
          open={expanded.has(f.id)}
          onToggle={() => onToggle(f.id)}
          onJumpToAction={onJumpToAction}
        />
      ))}
    </ul>
  );
}

export function EcosystemMark({ ecosystem }: { ecosystem: DepFinding['dependency']['ecosystem'] }) {
  return (
    <span
      className={cn(
        'inline-flex h-4.5 items-center rounded-[4px] px-1 font-mono text-[9.5px] font-semibold tracking-wide uppercase',
        ecosystem === 'npm' ? 'bg-sev-critical/12 text-sev-critical' : 'bg-sev-low/12 text-sev-low',
      )}
      title={ecosystem === 'npm' ? 'npm package' : 'PyPI package'}
    >
      {ecosystem === 'npm' ? 'npm' : 'py'}
    </span>
  );
}

function LibraryRow({
  scanId, f, fix, rank, open, onToggle, onJumpToAction,
}: {
  scanId: string; f: DepFinding; fix: FixAction | undefined; rank: number | undefined; open: boolean;
  onToggle: () => void; onJumpToAction: (actionId: string) => void;
}) {
  const d = f.dependency;
  const cvss = maxCvss(f);
  const detailsId = `${libraryAnchor(f.id)}-details`;
  const drawerTo = `/scans/${scanId}/findings/${f.id}`;

  return (
    <li id={libraryAnchor(f.id)} className="scroll-mt-24">
      <div className="grid grid-cols-[auto_1fr_auto] items-start gap-x-3 gap-y-2 px-3 py-3 sm:grid-cols-[auto_minmax(0,1.6fr)_minmax(0,1fr)_4.5rem_minmax(0,1fr)_auto] sm:items-center sm:px-4">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          aria-controls={detailsId}
          aria-label={`${open ? 'Collapse' : 'Expand'} ${d.name}@${d.version}`}
          className="col-start-1 row-start-1 mt-0.5 grid size-6 place-items-center rounded text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none sm:mt-0"
        >
          <ChevronRight aria-hidden className={cn('size-4 transition-transform', open && 'rotate-90')} />
        </button>

        {/* identity */}
        <div className="col-start-2 row-start-1 min-w-0 space-y-1">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            <EcosystemMark ecosystem={d.ecosystem} />
            <Link to={drawerTo} className="truncate font-mono text-sm font-medium hover:underline" title="Open finding">
              {d.name}
              <span className="text-muted-foreground">@{d.version}</span>
            </Link>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
            <span className={cn('rounded border px-1 font-mono', d.direct ? 'border-foreground/25 text-foreground' : '')}>
              {d.direct ? 'direct' : 'transitive'}
            </span>
            <span className="rounded border px-1 font-mono">{d.scope}</span>
            {!d.direct && d.paths[0] && d.paths[0].length > 1 && (
              <span className="truncate font-mono" title={d.paths[0].join(' › ')}>
                via {d.paths[0][0]}
              </span>
            )}
            {f.triage && <TriagePill triage={f.triage} />}
          </div>
        </div>

        {/* severity + advisories (mobile: right column) */}
        <div className="col-start-3 row-start-1 flex flex-col items-end gap-1 sm:items-start">
          <SeverityBadge severity={f.severity} score={f.riskScore} />
          <SeverityTallyLine tally={advisoryTally(f)} className="hidden sm:flex" />
        </div>

        <div className="col-span-2 col-start-2 row-start-2 flex flex-wrap items-center gap-2 sm:col-span-1 sm:col-start-4 sm:row-start-1 sm:block sm:text-right">
          <span className="font-mono text-xs tabular" title="Highest CVSS score among advisories">
            <span className="text-muted-foreground sm:hidden">CVSS </span>
            {cvss !== null ? cvss.toFixed(1) : '—'}
          </span>
          <SeverityTallyLine tally={advisoryTally(f)} className="sm:hidden" />
        </div>

        <div className="col-span-2 col-start-2 row-start-3 flex flex-wrap items-center gap-2 sm:col-span-1 sm:col-start-5 sm:row-start-1">
          <ReachabilityBadge reachability={d.reachability} />
          {fix ? (
            <button
              type="button"
              onClick={() => onJumpToAction(fix.id)}
              className="inline-flex items-center gap-1 rounded-md border border-signal/40 bg-signal-soft px-1.5 py-0.5 font-mono text-[11px] text-foreground hover:border-signal focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              title={`Fixed by action #${rank}: ${fix.package} → ${fix.to ?? 'remove'}`}
            >
              <Wrench aria-hidden className="size-3 text-signal" />#{rank ?? '?'}
              <span className="text-muted-foreground">{fix.to ? `→ ${fix.package === d.name ? '' : `${fix.package}@`}${fix.to}` : 'remove'}</span>
            </button>
          ) : d.fixedIn ? (
            <span className="font-mono text-[11px] text-muted-foreground">fixed in {d.fixedIn}</span>
          ) : (
            <span className="font-mono text-[11px] text-sev-critical">no fix</span>
          )}
        </div>

        <Link
          to={drawerTo}
          aria-label={`Open finding for ${d.name}`}
          className="hidden size-7 place-items-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground sm:col-start-6 sm:row-start-1 sm:grid"
        >
          <PanelRightOpen className="size-4" />
        </Link>
      </div>

      {open && <LibraryDetails id={detailsId} f={f} />}
    </li>
  );
}

/** github.com/o/r/blob/<sha>/package.json#L3 → same commit, another file + line. */
function permalinkFor(base: string, file: string, line: number): string | null {
  const m = base.match(/^(https:\/\/github\.com\/[^/]+\/[^/]+\/blob\/[^/]+)\//);
  return m ? `${m[1]}/${file.split('/').map(encodeURIComponent).join('/')}#L${line}` : null;
}

function LibraryDetails({ id, f }: { id: string; f: DepFinding }) {
  const d = f.dependency;
  const reach = f.riskFactors.find((r) => r.factor.startsWith('reachability'));
  return (
    <div id={id} className="space-y-4 border-t bg-surface-raised/50 px-3 py-4 sm:px-4 sm:pl-13">
      <div className="space-y-2">
        <p className="eyebrow">Advisories · {d.advisories.length}</p>
        <ul className="divide-y rounded-md border bg-card">
          {d.advisories.map((a) => (
            <li key={a.id} className="grid gap-1 px-3 py-2 sm:grid-cols-[minmax(0,13rem)_1fr_auto] sm:items-baseline sm:gap-3">
              <div className="min-w-0 space-y-0.5">
                <a href={osvUrl(a.id)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-mono text-xs font-medium hover:underline">
                  {a.id} <ExternalLink aria-hidden className="size-2.5 text-muted-foreground" />
                </a>
                {a.aliases.length > 0 && (
                  <div className="flex flex-wrap gap-x-2 font-mono text-[10.5px] text-muted-foreground">
                    {[...cveIds(a.aliases), ...a.aliases.filter((x) => !x.startsWith('CVE-'))].map((al) => (
                      <a key={al} href={osvUrl(al)} target="_blank" rel="noreferrer" className={cn('hover:underline', al.startsWith('CVE-') && 'text-foreground')}>
                        {al}
                      </a>
                    ))}
                  </div>
                )}
              </div>
              <p className="text-sm text-pretty">{a.summary}</p>
              <div className="flex items-center gap-2 sm:justify-end">
                <SeverityBadge severity={a.severity} />
                <span className="w-10 text-right font-mono text-xs tabular" title="CVSS">
                  {a.cvss !== null ? a.cvss.toFixed(1) : '—'}
                </span>
                <span className="inline-flex min-w-16 items-center gap-1 font-mono text-[11px] text-muted-foreground">
                  <ArrowRight aria-hidden className="size-3" />
                  {a.fixedIn ?? 'none'}
                </span>
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-2">
          <p className="eyebrow">Dependency paths · {d.paths.length}</p>
          <ul className="space-y-1">
            {d.paths.slice(0, 6).map((p, i) => (
              <li key={i} className="flex flex-wrap items-center gap-1 font-mono text-[11px]">
                <span className="text-muted-foreground">app</span>
                {p.map((node, j) => (
                  <span key={j} className="inline-flex items-center gap-1">
                    <ChevronRight aria-hidden className="size-3 text-muted-foreground/60" />
                    <span className={cn(j === p.length - 1 ? 'font-semibold text-sev-high' : '')}>{node}</span>
                  </span>
                ))}
              </li>
            ))}
            {d.paths.length > 6 && <li className="font-mono text-[11px] text-muted-foreground">+{d.paths.length - 6} more paths</li>}
          </ul>
        </div>

        <div className="space-y-2">
          <p className="eyebrow">Reachability evidence</p>
          {reach && <p className="text-xs text-muted-foreground">{reach.reason}</p>}
          {d.reachabilityEvidence && d.reachabilityEvidence.length > 0 ? (
            <ul className="space-y-1">
              {d.reachabilityEvidence.map((e) => {
                const href = permalinkFor(f.location.permalink, e.file, e.line);
                const label = `${e.file}:${e.line}`;
                return (
                  <li key={label} className="flex items-center gap-1.5 font-mono text-[11px]">
                    <FileCode2 aria-hidden className="size-3 text-muted-foreground" />
                    {href ? (
                      <a href={href} target="_blank" rel="noreferrer" className="break-all hover:underline">
                        {label}
                      </a>
                    ) : (
                      <span className="break-all">{label}</span>
                    )}
                  </li>
                );
              })}
            </ul>
          ) : (
            !reach && <p className="text-xs text-muted-foreground">No import sites recorded.</p>
          )}
        </div>
      </div>
    </div>
  );
}
