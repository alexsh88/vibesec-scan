import { activeTriage, type Finding, type TriageStatus } from '@vibesec/shared';
import { Ban, CircleSlash, RotateCcw, ShieldAlert, ShieldCheck, type LucideIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { useTriage } from '@/hooks/queries';
import { toApiError } from '@/lib/api';
import { formatDateTime, formatRelative } from '@/lib/format';
import { TRIAGE_LABEL } from '@/lib/taxonomy';

const ACTIONS: Array<{ status: TriageStatus; label: string; icon: LucideIcon; blurb: string }> = [
  { status: 'false_positive', label: 'Mark false positive', icon: Ban, blurb: 'The finding is wrong: the code is not vulnerable.' },
  { status: 'accepted_risk', label: 'Accept risk', icon: ShieldAlert, blurb: 'The issue is real, but the risk is acceptable for now.' },
  { status: 'wont_fix', label: "Won't fix", icon: CircleSlash, blurb: 'The issue is real and will not be fixed.' },
];

/**
 * Current triage decision + actions. A decision suppresses the finding from open lists, the summary
 * and the grade, and is re-applied to later scans by fingerprint; "Reopen" clears it.
 */
export function TriagePanel({ finding, scanId }: { finding: Finding; scanId: string }) {
  const triage = useTriage(scanId);
  const [dialog, setDialog] = useState<TriageStatus | null>(null);
  const current = activeTriage(finding);
  const lapsed = finding.triage && !current ? finding.triage : undefined;

  const reopen = () =>
    triage.mutate(
      { findingId: finding.id, clear: true },
      {
        onSuccess: () => toast.success('Finding reopened'),
        onError: (e) => toast.error(toApiError(e).userMessage),
      },
    );

  return (
    <div className="space-y-3">
      {current ? (
        <div className="rounded-lg border border-status-triaged/35 bg-status-triaged/8 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <ShieldCheck aria-hidden className="size-4 text-status-triaged" />
            <span className="text-sm font-medium">{TRIAGE_LABEL[current.status]}</span>
            <span className="text-xs text-muted-foreground" title={formatDateTime(current.at)}>
              {formatRelative(current.at)}
            </span>
            {current.expiresAt && (
              <span className="text-xs text-muted-foreground" title={formatDateTime(current.expiresAt)}>
                · expires {formatRelative(current.expiresAt)}
              </span>
            )}
            <div className="flex-1" />
            <Button size="sm" variant="outline" onClick={reopen} disabled={triage.isPending}>
              <RotateCcw /> Reopen
            </Button>
          </div>
          {current.reason && <p className="mt-2 text-sm whitespace-pre-wrap text-muted-foreground">“{current.reason}”</p>}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          Open. Triage decisions are audited and carried over to future scans of this repository.
          {lapsed && (
            <span className="mt-1 block text-xs">
              A previous “{TRIAGE_LABEL[lapsed.status]}” decision expired {formatRelative(lapsed.expiresAt)}.
            </span>
          )}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        {ACTIONS.filter((a) => a.status !== current?.status).map((a) => (
          <Button key={a.status} size="sm" variant="outline" onClick={() => setDialog(a.status)} disabled={triage.isPending}>
            <a.icon /> {a.label}
          </Button>
        ))}
      </div>
      <TriageDialog
        status={dialog}
        pending={triage.isPending}
        onClose={() => setDialog(null)}
        onSubmit={(reason, expiresAt) =>
          dialog &&
          triage.mutate(
            { findingId: finding.id, status: dialog, reason, expiresAt },
            {
              onSuccess: () => {
                toast.success(`Marked as ${TRIAGE_LABEL[dialog].toLowerCase()}`);
                setDialog(null);
              },
              onError: (e) => toast.error(toApiError(e).userMessage),
            },
          )
        }
      />
    </div>
  );
}

function TriageDialog({
  status,
  pending,
  onClose,
  onSubmit,
}: {
  status: TriageStatus | null;
  pending: boolean;
  onClose: () => void;
  onSubmit: (reason: string, expiresAt: string | undefined) => void;
}) {
  const [reason, setReason] = useState('');
  const [expiry, setExpiry] = useState('');
  const reasonId = useId();
  const expiryId = useId();
  const action = ACTIONS.find((a) => a.status === status);
  const tomorrow = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);
  const trimmed = reason.trim();

  return (
    <Dialog
      open={status !== null}
      onOpenChange={(o) => {
        if (!o) {
          onClose();
          setReason('');
          setExpiry('');
        }
      }}
    >
      <DialogContent className="sm:max-w-md">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!trimmed) return;
            // End of the chosen local day.
            onSubmit(trimmed, expiry ? new Date(`${expiry}T23:59:59`).toISOString() : undefined);
          }}
          className="space-y-4"
        >
          <DialogHeader>
            <DialogTitle>{action?.label}</DialogTitle>
            <DialogDescription>{action?.blurb} The finding is suppressed from open results and the grade.</DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor={reasonId}>Reason</Label>
            <textarea
              id={reasonId}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={1000}
              rows={4}
              required
              autoFocus
              placeholder="Why? This is recorded in the audit log."
              className="w-full resize-y rounded-md border bg-card px-3 py-2 text-sm outline-none placeholder:text-muted-foreground/70 focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30"
            />
            <p className="text-right font-mono text-[10px] text-muted-foreground tabular">{reason.length}/1000</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor={expiryId}>
              Expires <span className="font-normal text-muted-foreground">(optional)</span>
            </Label>
            <input
              id={expiryId}
              type="date"
              min={tomorrow}
              value={expiry}
              onChange={(e) => setExpiry(e.target.value)}
              className="h-9 w-full rounded-md border bg-card px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30"
            />
            <p className="text-xs text-muted-foreground">After this date the finding counts as open again.</p>
          </div>
          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="ghost">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={!trimmed || pending}>
              {pending ? 'Saving…' : action?.label}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
