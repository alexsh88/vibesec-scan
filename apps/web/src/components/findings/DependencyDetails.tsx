import type { Finding } from '@vibesec/shared';
import { ChevronRight, ExternalLink, Package } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { SeverityBadge } from '@/components/security/SeverityBadge';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { cn } from '@/lib/utils';
import { advisoryUrl, permalinkFor } from './meta';

type Dep = NonNullable<Finding['dependency']>;

const REACH: Record<Dep['reachability'], { label: string; cls: string; hint: string }> = {
  reachable: { label: 'Reachable', cls: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical', hint: 'Vulnerable code is called from the application' },
  imported: { label: 'Imported', cls: 'border-sev-medium/40 bg-sev-medium/10 text-sev-medium', hint: 'The package is imported by application code' },
  unreachable: { label: 'Unreachable', cls: 'border-status-fixed/40 bg-status-fixed/10 text-status-fixed', hint: 'Never imported by application code' },
  unknown: { label: 'Reachability unknown', cls: 'border-border bg-muted text-muted-foreground', hint: 'Could not determine whether the package is used' },
};

export function ReachabilityBadge({ value }: { value: Dep['reachability'] }) {
  const m = REACH[value];
  return (
    <span className={cn('inline-flex h-5.5 items-center gap-1 rounded-full border px-2 text-[11px] font-medium', m.cls)} title={m.hint}>
      {m.label}
    </span>
  );
}

const PATHS_SHOWN = 4;

export function DependencyDetails({ dep, permalinkBase }: { dep: Dep; permalinkBase: string }) {
  const [allPaths, setAllPaths] = useState(false);
  const paths = allPaths ? dep.paths : dep.paths.slice(0, PATHS_SHOWN);
  const evidence = dep.reachabilityEvidence ?? [];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1.5 font-mono text-sm font-medium">
          <Package aria-hidden className="size-4 text-muted-foreground" />
          {dep.name}
          <span className="text-muted-foreground">@{dep.version}</span>
        </span>
        <Tag>{dep.ecosystem}</Tag>
        <Tag>{dep.direct ? 'direct' : 'transitive'}</Tag>
        <Tag className={dep.scope === 'dev' ? 'text-muted-foreground' : ''}>{dep.scope === 'dev' ? 'dev scope' : 'prod scope'}</Tag>
        <ReachabilityBadge value={dep.reachability} />
        {dep.fixedIn && (
          <span className="text-xs text-muted-foreground">
            fix: upgrade to <code className="code-ref">{dep.fixedIn}</code>
          </span>
        )}
      </div>

      {evidence.length > 0 && (
        <div>
          <p className="eyebrow mb-1.5">Reachability evidence</p>
          <ul className="space-y-1">
            {evidence.map((e) => {
              const href = permalinkFor(permalinkBase, e.file, e.line);
              const label = `${e.file}:${e.line}`;
              return (
                <li key={label} className="font-mono text-xs">
                  {href ? (
                    <a href={href} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:underline">
                      {label} <ExternalLink aria-hidden className="size-3 text-muted-foreground" />
                    </a>
                  ) : (
                    label
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {dep.advisories.length > 0 && (
        <div>
          <p className="eyebrow mb-1">Advisories ({dep.advisories.length})</p>
          <Accordion type="multiple" className="rounded-lg border bg-card px-3">
            {dep.advisories.map((a) => (
              <AccordionItem key={a.id} value={a.id}>
                <AccordionTrigger className="py-2.5 hover:no-underline">
                  <span className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
                    <SeverityBadge severity={a.severity} />
                    <span className="font-mono text-xs">{a.id}</span>
                    {a.cvss !== null && <span className="font-mono text-[11px] text-muted-foreground tabular">CVSS {a.cvss.toFixed(1)}</span>}
                    <span className="min-w-0 basis-full truncate text-xs font-normal text-muted-foreground sm:basis-auto sm:flex-1">{a.summary}</span>
                  </span>
                </AccordionTrigger>
                <AccordionContent className="space-y-2 pb-3 text-sm">
                  <p>{a.summary}</p>
                  <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
                    <dt className="text-muted-foreground">Aliases</dt>
                    <dd className="font-mono">{a.aliases.length ? a.aliases.join(', ') : '—'}</dd>
                    <dt className="text-muted-foreground">CVSS</dt>
                    <dd className="font-mono">{a.cvss !== null ? a.cvss.toFixed(1) : '—'}</dd>
                    <dt className="text-muted-foreground">Fixed in</dt>
                    <dd className="font-mono">{a.fixedIn ?? 'no fix released'}</dd>
                  </dl>
                  <a
                    href={advisoryUrl(a)}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-medium hover:underline"
                  >
                    {a.id} advisory <ExternalLink aria-hidden className="size-3" />
                  </a>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </div>
      )}

      {dep.paths.length > 0 && (
        <div>
          <p className="eyebrow mb-1.5">Dependency paths ({dep.paths.length})</p>
          <ul className="space-y-1.5">
            {paths.map((p, i) => (
              <li key={i} className="flex flex-wrap items-center gap-1 font-mono text-xs">
                {p.map((node, j) => (
                  <span key={j} className="inline-flex items-center gap-1">
                    {j > 0 && <ChevronRight aria-hidden className="size-3 text-muted-foreground/60" />}
                    <span className={cn('rounded px-1 py-0.5', j === p.length - 1 ? 'bg-sev-high/10 text-foreground' : 'bg-muted text-muted-foreground')}>
                      {node}
                    </span>
                  </span>
                ))}
              </li>
            ))}
          </ul>
          {dep.paths.length > PATHS_SHOWN && (
            <button type="button" onClick={() => setAllPaths((v) => !v)} className="mt-1.5 text-xs text-muted-foreground hover:text-foreground hover:underline">
              {allPaths ? 'Show fewer' : `Show all ${dep.paths.length} paths`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('inline-flex h-5.5 items-center rounded-[5px] border px-1.5 font-mono text-[11px]', className)}>{children}</span>;
}
