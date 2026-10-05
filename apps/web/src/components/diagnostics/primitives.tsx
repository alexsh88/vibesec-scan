import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

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
