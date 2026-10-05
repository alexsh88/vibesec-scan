import { cn } from '@/lib/utils';

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
