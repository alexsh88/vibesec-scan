import type { Category } from '@vibesec/shared';
import { cn } from '@/lib/utils';
import { CATEGORY_META } from '@/lib/taxonomy';

export function CategoryIcon({ category, className }: { category: Category; className?: string }) {
  const Icon = CATEGORY_META[category].icon;
  return <Icon aria-hidden className={cn('size-4 text-muted-foreground', className)} strokeWidth={1.75} />;
}

/** Icon + label, e.g. in a finding row's category column. */
export function CategoryLabel({ category, className, short }: { category: Category; className?: string; short?: boolean }) {
  const meta = CATEGORY_META[category];
  return (
    <span className={cn('inline-flex items-center gap-1.5 text-xs text-muted-foreground', className)} title={meta.description}>
      <CategoryIcon category={category} className="size-3.5" />
      {short ? meta.short : meta.label}
    </span>
  );
}
