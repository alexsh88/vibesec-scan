import { cn } from '@/lib/utils';

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
