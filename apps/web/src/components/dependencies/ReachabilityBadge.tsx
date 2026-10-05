import { CircleDashed, CircleHelp, Crosshair, Import } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import type { Reachability } from './depModel';

export const REACHABILITY_META: Record<Reachability, { label: string; icon: typeof Crosshair; cls: string; explain: string }> = {
  reachable: {
    label: 'Reachable',
    icon: Crosshair,
    cls: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
    explain:
      'Your code imports this package and calls a function named in the advisory. The vulnerable code path is very likely exercised — fix first.',
  },
  imported: {
    label: 'Imported',
    icon: Import,
    cls: 'border-sev-high/40 bg-sev-high/10 text-sev-high',
    explain:
      'Your application code imports this package directly (a root library). The import is proven; whether the specific vulnerable function is called is not.',
  },
  unknown: {
    label: 'Unknown',
    icon: CircleHelp,
    cls: 'border-border bg-muted text-muted-foreground',
    explain:
      'Usage could not be proven either way. For an inner (transitive) library this usually means it is only reached through the internals of a root library you import.',
  },
  unreachable: {
    label: 'Unreachable',
    icon: CircleDashed,
    cls: 'border-status-fixed/35 bg-status-fixed/10 text-status-fixed',
    explain:
      'Nothing in your code imports it, nor any root library that pulls it in (or it is a dev-only dependency). Lower priority — but it still ships in the lockfile.',
  },
};

export function ReachabilityBadge({ reachability, className }: { reachability: Reachability; className?: string }) {
  const m = REACHABILITY_META[reachability];
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className={cn(
            'inline-flex h-5.5 cursor-help items-center gap-1 rounded-full border px-2 text-[11px] font-medium whitespace-nowrap focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
            m.cls,
            className,
          )}
        >
          <m.icon aria-hidden className="size-3" />
          {m.label}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-72 text-xs leading-relaxed">
        <span className="font-semibold">{m.label}.</span> {m.explain}
      </TooltipContent>
    </Tooltip>
  );
}
