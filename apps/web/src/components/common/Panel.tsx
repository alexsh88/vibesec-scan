import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

/**
 * Hairline instrument panel: mono eyebrow heading (optional icon), optional right-hand meta, body.
 * Passing an `icon` switches on the slightly heavier "raised" header (bg-surface-raised, wraps on
 * small screens) used by diagnostics-style panels; without one it matches the plain overview style.
 */
export function Panel({
  id,
  title,
  icon: Icon,
  meta,
  children,
  className,
  bodyClassName,
}: {
  id?: string;
  title: ReactNode;
  icon?: LucideIcon;
  meta?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  const raised = !!Icon;
  return (
    <section aria-labelledby={id} className={cn('rounded-lg border bg-card', raised && 'min-w-0 overflow-hidden', className)}>
      <header
        className={
          raised
            ? 'flex flex-wrap items-center gap-x-3 gap-y-1 border-b bg-surface-raised px-4 py-2.5'
            : 'flex items-baseline gap-3 border-b px-4 py-2.5'
        }
      >
        <h2 id={id} className="eyebrow flex items-center gap-2">
          {Icon && <Icon aria-hidden className="size-3.5" />}
          {title}
        </h2>
        {meta && <div className="ml-auto font-mono text-[11px] text-muted-foreground tabular">{meta}</div>}
      </header>
      <div className={cn('p-4', bodyClassName)}>{children}</div>
    </section>
  );
}
