import { Trash2 } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { useDeleteRepo } from '@/hooks/queries';
import { toApiError, type Repo } from '@/lib/api';
import { formatInt } from '@/lib/format';

/**
 * Confirms and deletes a repository's whole scan history (DELETE /api/repos/:id), so its next scan
 * starts fresh: no same-commit cache hit, no "existing" baseline, no triage decisions. Optionally also
 * clears the shared AI result caches so every file gets a fresh AI review. The audit log keeps its
 * entries and records the deletion.
 */
export function DeleteRepoDialog({
  repo,
  scanCount,
  running,
  trigger,
  onDeleted,
}: {
  repo: Pick<Repo, 'id' | 'owner' | 'name'>;
  scanCount: number | undefined;
  /** A scan of this repo is still running: the server refuses (409), so the action is disabled. */
  running: boolean;
  trigger: ReactNode;
  onDeleted?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [purge, setPurge] = useState(false);
  const purgeId = useId();
  const del = useDeleteRepo();
  const name = `${repo.owner}/${repo.name}`;

  const onConfirm = () => {
    del.mutate(
      { repoId: repo.id, purgeAiCache: purge },
      {
        onSuccess: (res) => {
          setOpen(false);
          toast.success(
            `Deleted ${formatInt(res.deletedScans)} ${res.deletedScans === 1 ? 'scan' : 'scans'} of ${name}`
              + (purge ? ` · cleared ${formatInt(res.purgedCacheEntries)} cached AI results` : ''),
          );
          onDeleted?.();
        },
        onError: (e) => toast.error(toApiError(e).userMessage),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) setPurge(false); }}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete scan history for {name}?</DialogTitle>
          <DialogDescription>
            Removes {scanCount === undefined ? 'every scan' : `${formatInt(scanCount)} ${scanCount === 1 ? 'scan' : 'scans'}`},
            together with findings, events, coverage and triage decisions. The next scan of this repository starts fresh: no cached
            result and nothing marked as existing. The audit log keeps its entries and records this deletion.
          </DialogDescription>
        </DialogHeader>
        <div className="flex items-start gap-3 rounded-md border px-3 py-3">
          <Checkbox id={purgeId} checked={purge} onCheckedChange={(v) => setPurge(v === true)} className="mt-0.5" />
          <div className="space-y-1">
            <Label htmlFor={purgeId}>Also clear the AI result cache</Label>
            <p className="text-xs text-muted-foreground">
              Shared by all repositories. Without it, unchanged files reuse earlier AI reviews, so the next scan is cheaper
              but shows them as cached.
            </p>
          </div>
        </div>
        {running && (
          <p role="alert" className="text-sm text-destructive">
            A scan of this repository is still running. Cancel it or wait for it to finish first.
          </p>
        )}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Keep history</Button>
          </DialogClose>
          <Button variant="destructive" onClick={onConfirm} disabled={running || del.isPending}>
            <Trash2 /> {del.isPending ? 'Deleting…' : 'Delete history'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
