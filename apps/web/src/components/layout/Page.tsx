import { Construction } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

/** Standard page container: consistent gutters + max width. Use for every routed page. */
export function Page({ children, className, wide }: { children: ReactNode; className?: string; wide?: boolean }) {
  return (
    <div className={cn('mx-auto w-full animate-rise px-4 py-6 sm:px-6', wide ? 'max-w-[1400px]' : 'max-w-6xl', className)}>
      {children}
    </div>
  );
}

/** Page title block: mono eyebrow, title, optional description and right-aligned actions. */
export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  className,
}: {
  eyebrow?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('mb-6 flex flex-wrap items-end gap-4', className)}>
      <div className="min-w-0 flex-1 space-y-1">
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1 className="text-xl font-semibold tracking-tight text-balance sm:text-2xl">{title}</h1>
        {description && <p className="max-w-2xl text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Temporary body for routes that another agent will build. Delete when the page is implemented. */
export function PagePlaceholder({ title, spec, children }: { title: string; spec: string; children?: ReactNode }) {
  return (
    <Page>
      <PageHeader eyebrow="Coming soon" title={title} />
      <div className="flex items-start gap-3 rounded-lg border border-dashed bg-muted/30 p-5 text-sm text-muted-foreground">
        <Construction aria-hidden className="mt-0.5 size-4 shrink-0" />
        <div className="space-y-2">
          <p>{spec}</p>
          {children}
        </div>
      </div>
    </Page>
  );
}
