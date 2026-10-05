import type { Finding, ScanState, Triage } from '@vibesec/shared';
import { CircleCheck, CircleDot, CircleSlash, Clock, LoaderCircle, ShieldCheck, TriangleAlert, CircleX } from 'lucide-react';
import { cn } from '@/lib/utils';
import { STATE_LABEL, stateTone, type StateTone } from '@/lib/scanState';
import { TRIAGE_LABEL } from '@/lib/taxonomy';

const pillBase = 'inline-flex h-5.5 items-center gap-1 rounded-full border px-2 text-[11px] font-medium whitespace-nowrap';

const FINDING_STATUS = {
  new: { label: 'New', icon: CircleDot, cls: 'border-status-new/35 bg-status-new/10 text-status-new' },
  existing: { label: 'Existing', icon: Clock, cls: 'border-border bg-transparent text-status-existing' },
  fixed: { label: 'Fixed', icon: CircleCheck, cls: 'border-status-fixed/35 bg-status-fixed/10 text-status-fixed' },
} as const;

/** new / existing / fixed relative to the previous scan of the same repo. */
export function FindingStatusPill({ status, className }: { status: Finding['scanStatus']; className?: string }) {
  const m = FINDING_STATUS[status];
  return (
    <span className={cn(pillBase, m.cls, className)}>
      <m.icon aria-hidden className="size-3" />
      {m.label}
    </span>
  );
}

export function TriagePill({ triage, className }: { triage: Triage; className?: string }) {
  return (
    <span className={cn(pillBase, 'border-status-triaged/35 bg-status-triaged/10 text-status-triaged', className)} title={triage.reason}>
      <ShieldCheck aria-hidden className="size-3" />
      {TRIAGE_LABEL[triage.status]}
    </span>
  );
}

const TONE: Record<StateTone, { cls: string; icon: typeof LoaderCircle }> = {
  running: { cls: 'border-state-running/35 bg-state-running/10 text-state-running', icon: LoaderCircle },
  success: { cls: 'border-status-fixed/35 bg-status-fixed/10 text-status-fixed', icon: CircleCheck },
  warning: { cls: 'border-sev-medium/35 bg-sev-medium/10 text-sev-medium', icon: TriangleAlert },
  danger: { cls: 'border-sev-critical/35 bg-sev-critical/10 text-sev-critical', icon: CircleX },
  neutral: { cls: 'border-border bg-muted text-muted-foreground', icon: CircleSlash },
};

export function ScanStatePill({ state, className }: { state: ScanState; className?: string }) {
  const tone = stateTone(state);
  const { cls, icon: Icon } = TONE[tone];
  return (
    <span className={cn(pillBase, cls, className)}>
      <Icon aria-hidden className={cn('size-3', tone === 'running' && 'animate-spin')} />
      {STATE_LABEL[state]}
    </span>
  );
}
