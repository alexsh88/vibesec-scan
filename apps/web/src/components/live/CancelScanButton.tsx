import { Square } from 'lucide-react';
import { useState } from 'react';
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
import { useCancelScan } from '@/hooks/queries';
import { toApiError } from '@/lib/api';

/** Cancel with a confirmation step; disabled while the request is in flight. */
export function CancelScanButton({ scanId, findingsSoFar }: { scanId: string; findingsSoFar: number }) {
  const cancel = useCancelScan();
  const [open, setOpen] = useState(false);

  const onConfirm = () => {
    cancel.mutate(scanId, {
      onSuccess: () => {
        setOpen(false);
        toast.success('Scan cancelled');
      },
      onError: (e) => toast.error(toApiError(e).userMessage),
    });
  };

  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)} disabled={cancel.isPending}>
        <Square className="fill-current" /> {cancel.isPending ? 'Cancelling…' : 'Cancel scan'}
      </Button>
      <Dialog open={open} onOpenChange={(o) => !cancel.isPending && setOpen(o)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Stop this scan?</DialogTitle>
            <DialogDescription>
              Analysis stops at the next checkpoint.{' '}
              {findingsSoFar > 0
                ? `The ${findingsSoFar} finding${findingsSoFar === 1 ? '' : 's'} found so far are kept, but the result will be incomplete.`
                : 'Anything found so far is kept, but the result will be incomplete.'}{' '}
              AI spend already incurred is not refunded.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="ghost" disabled={cancel.isPending}>
                Keep scanning
              </Button>
            </DialogClose>
            <Button variant="destructive" onClick={onConfirm} disabled={cancel.isPending}>
              {cancel.isPending ? 'Cancelling…' : 'Stop scan'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
