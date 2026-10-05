import type { Finding } from '@vibesec/shared';
import { ArrowDownToLine, ChevronsUpDown, ExternalLink, LogIn, ShieldCheck, Shuffle, type LucideIcon } from 'lucide-react';
import { Fragment, useState } from 'react';
import { CodeBlock } from '@/components/security/CodeBlock';
import { langFromPath } from '@/lib/highlighter';
import { cn } from '@/lib/utils';
import { permalinkFor } from './meta';

type Step = NonNullable<Finding['taintTrace']>[number];

const KIND: Record<Step['kind'], { label: string; icon: LucideIcon; node: string; badge: string }> = {
  source: {
    label: 'Source',
    icon: LogIn,
    node: 'border-sev-high bg-sev-high/15 text-sev-high',
    badge: 'border-sev-high/40 bg-sev-high/10 text-sev-high',
  },
  propagator: {
    label: 'Propagator',
    icon: Shuffle,
    node: 'border-muted-foreground/50 bg-card text-muted-foreground',
    badge: 'border-border bg-muted text-muted-foreground',
  },
  sanitizer: {
    label: 'Sanitizer',
    icon: ShieldCheck,
    node: 'border-status-fixed bg-status-fixed/15 text-status-fixed',
    badge: 'border-status-fixed/40 bg-status-fixed/10 text-status-fixed',
  },
  sink: {
    label: 'Sink',
    icon: ArrowDownToLine,
    node: 'border-sev-critical bg-sev-critical/15 text-sev-critical',
    badge: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
  },
};

/** Collapse the middle of traces longer than this. */
const COLLAPSE_OVER = 5;

/**
 * Source → propagators/sanitizers → sink, as a vertical rail. Each step links to the exact line on
 * GitHub and shows that line highlighted. Long traces collapse their middle steps.
 */
export function TaintFlow({ trace, permalinkBase }: { trace: Step[]; permalinkBase: string }) {
  const [expanded, setExpanded] = useState(false);
  const collapsible = trace.length > COLLAPSE_OVER;
  const hiddenFrom = 2;
  const hiddenTo = trace.length - 2; // exclusive
  const hiddenCount = hiddenTo - hiddenFrom;
  const sanitized = trace.some((s) => s.kind === 'sanitizer');

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span className="font-mono tabular">{trace.length} steps</span>
        <span aria-hidden>·</span>
        <span>{new Set(trace.map((s) => s.file)).size} file(s)</span>
        {sanitized && (
          <>
            <span aria-hidden>·</span>
            <span className="text-status-fixed">passes a sanitizer (may be insufficient for this sink)</span>
          </>
        )}
      </div>
      <ol className="relative" aria-label="Taint flow">
        {trace.map((step, i) => {
          if (collapsible && !expanded && i >= hiddenFrom && i < hiddenTo) {
            if (i !== hiddenFrom) return null;
            return (
              <li key="collapsed" className="relative flex gap-3 pb-4">
                <Rail last={false} dashed />
                <button
                  type="button"
                  onClick={() => setExpanded(true)}
                  className="ml-0.5 inline-flex items-center gap-1.5 rounded-md border border-dashed px-2.5 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
                >
                  <ChevronsUpDown className="size-3.5" /> Show {hiddenCount} intermediate step{hiddenCount === 1 ? '' : 's'}
                </button>
              </li>
            );
          }
          return (
            <Fragment key={`${step.file}:${step.line}:${i}`}>
              <TaintStep step={step} index={i} last={i === trace.length - 1} permalinkBase={permalinkBase} />
            </Fragment>
          );
        })}
      </ol>
      {collapsible && expanded && (
        <button type="button" onClick={() => setExpanded(false)} className="ml-9 text-xs text-muted-foreground hover:text-foreground hover:underline">
          Collapse intermediate steps
        </button>
      )}
    </div>
  );
}

function Rail({ last, dashed }: { last: boolean; dashed?: boolean }) {
  return (
    <span aria-hidden className="relative w-6 shrink-0">
      {!last && (
        <span className={cn('absolute top-0 bottom-0 left-1/2 -translate-x-1/2 border-l-2', dashed ? 'border-dashed border-border' : 'border-border')} />
      )}
    </span>
  );
}

function TaintStep({ step, index, last, permalinkBase }: { step: Step; index: number; last: boolean; permalinkBase: string }) {
  const k = KIND[step.kind];
  const href = permalinkFor(permalinkBase, step.file, step.line);
  const code = step.code.replace(/\s+$/, '');
  return (
    <li className="relative flex gap-3 pb-4 last:pb-0">
      {/* rail + node */}
      <span aria-hidden className="relative flex w-6 shrink-0 justify-center">
        {!last && <span className="absolute top-6 -bottom-0 left-1/2 -translate-x-1/2 border-l-2 border-border" />}
        <span className={cn('relative z-10 grid size-6 place-items-center rounded-full border-2', k.node, step.kind === 'sanitizer' && 'rounded-md')}>
          <k.icon className="size-3" strokeWidth={2.25} />
        </span>
      </span>
      <div className={cn('min-w-0 flex-1', step.kind === 'sanitizer' && 'rounded-lg border border-dashed border-status-fixed/40 bg-status-fixed/5 p-2')}>
        <div className="mb-1.5 flex flex-wrap items-center gap-2">
          <span className="font-mono text-[10px] text-muted-foreground tabular">{String(index + 1).padStart(2, '0')}</span>
          <span className={cn('inline-flex h-5 items-center rounded-[4px] border px-1.5 font-mono text-[10px] font-medium tracking-wide uppercase', k.badge)}>
            {k.label}
          </span>
          {step.note && <span className="min-w-0 text-xs text-muted-foreground">{step.note}</span>}
        </div>
        {code ? (
          <CodeBlock
            code={code}
            lang={langFromPath(step.file)}
            path={`${step.file}:${step.line}`}
            startLine={step.line}
            highlight={{ from: step.line, to: step.line }}
            actions={href ? <PermalinkIcon href={href} label={`${step.file}:${step.line} on GitHub`} /> : undefined}
            className="text-[12px]"
          />
        ) : (
          <span className="font-mono text-xs">
            {step.file}:{step.line}
          </span>
        )}
      </div>
    </li>
  );
}

export function PermalinkIcon({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      aria-label={label}
      title={label}
      className="inline-flex size-6 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
    >
      <ExternalLink className="size-3.5" />
    </a>
  );
}
