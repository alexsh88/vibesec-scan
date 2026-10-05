import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

/** Hairline instrument panel: mono eyebrow heading, optional meta on the right, body. */
export function Panel({
  id,
  title,
  meta,
  children,
  className,
  bodyClassName,
}: {
  id: string;
  title: ReactNode;
  meta?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section aria-labelledby={id} className={cn('rounded-lg border bg-card', className)}>
      <header className="flex items-baseline gap-3 border-b px-4 py-2.5">
        <h2 id={id} className="eyebrow">
          {title}
        </h2>
        {meta && <div className="ml-auto font-mono text-[11px] text-muted-foreground tabular">{meta}</div>}
      </header>
      <div className={cn('p-4', bodyClassName)}>{children}</div>
    </section>
  );
}
