import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

/** Instrument-panel card: mono eyebrow header with an optional right-hand readout. */
export function Panel({
  icon: Icon, title, readout, children, className, id,
}: { icon?: LucideIcon; title: string; readout?: ReactNode; children: ReactNode; className?: string; id?: string }) {
  return (
    <section aria-labelledby={id} className={cn('min-w-0 overflow-hidden rounded-lg border bg-card', className)}>
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b bg-surface-raised px-4 py-2.5">
        <h2 id={id} className="eyebrow flex items-center gap-2">
          {Icon && <Icon aria-hidden className="size-3.5" />}
          {title}
        </h2>
        {readout && <div className="ml-auto font-mono text-[11px] text-muted-foreground tabular">{readout}</div>}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

export type Segment = { key: string; value: number; className: string; label: string };

/** Horizontal stacked bar; segments with value 0 are skipped. Accessible via a text summary. */
export function StackedBar({ segments, className, height = 'h-2' }: { segments: Segment[]; className?: string; height?: string }) {
  const total = segments.reduce((s, x) => s + x.value, 0);
  const text = segments.filter((s) => s.value > 0).map((s) => `${s.value} ${s.label}`).join(', ');
  return (
    <div role="img" aria-label={total === 0 ? 'No data' : text} className={cn('flex w-full gap-px overflow-hidden rounded-full bg-muted', height, className)}>
      {total > 0 &&
        segments
          .filter((s) => s.value > 0)
          .map((s) => (
            <span key={s.key} className={cn('h-full first:rounded-l-full last:rounded-r-full', s.className)} style={{ width: `${(s.value / total) * 100}%` }} title={`${s.label}: ${s.value}`} />
          ))}
    </div>
  );
}

/** Single-value meter (0..1). `tone` switches colour as it fills. */
export function Meter({ value, className, tone }: { value: number; className?: string; tone?: 'signal' | 'warn' | 'bad' }) {
  const v = Math.max(0, Math.min(1, value));
  const auto = tone ?? (v >= 0.9 ? 'bad' : v >= 0.7 ? 'warn' : 'signal');
  return (
    <div className={cn('h-1.5 w-full overflow-hidden rounded-full bg-muted', className)} role="presentation">
      <div
        className={cn('h-full rounded-full', auto === 'bad' ? 'bg-sev-critical' : auto === 'warn' ? 'bg-sev-medium' : 'bg-signal')}
        style={{ width: `${Math.max(v > 0 ? 1.5 : 0, v * 100)}%` }}
      />
    </div>
  );
}

/** Big readout tile used in the KPI strip. */
export function Readout({ label, value, sub, icon: Icon, children }: { label: string; value: ReactNode; sub?: ReactNode; icon?: LucideIcon; children?: ReactNode }) {
  return (
    <div className="min-w-0 space-y-1.5 bg-card px-4 py-3">
      <p className="eyebrow flex items-center gap-1.5 text-[10px]">
        {Icon && <Icon aria-hidden className="size-3" />}
        {label}
      </p>
      <p className="truncate font-mono text-2xl font-semibold tabular">{value}</p>
      {sub && <p className="truncate font-mono text-[11px] text-muted-foreground">{sub}</p>}
      {children}
    </div>
  );
}
