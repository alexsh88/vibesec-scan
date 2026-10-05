import type { Finding } from '@vibesec/shared';
import { ChevronRight } from 'lucide-react';
import { Link } from 'react-router';
import { Skeleton } from '@/components/ui/skeleton';
import { useFinding } from '@/hooks/queries';
import { SEVERITY_CLASSES } from '@/lib/taxonomy';
import { cn } from '@/lib/utils';
import { findingHref } from './links';

/**
 * One linked finding (title + file:line) opening the finding drawer. Uses `known` when the finding
 * is already in a loaded list page; otherwise fetches it on its own (cached per id).
 */
export function FindingRef({ scanId, findingId, known }: { scanId: string; findingId: string; known?: Finding }) {
  const q = useFinding(scanId, known ? undefined : findingId);
  const f = known ?? q.data;

  if (!f) {
    if (q.isError) {
      return (
        <Link to={findingHref(scanId, findingId)} className="font-mono text-xs text-muted-foreground hover:text-foreground">
          finding {findingId.slice(0, 8)}
        </Link>
      );
    }
    return <Skeleton className="h-4 w-48" />;
  }

  return (
    <Link
      to={findingHref(scanId, f.id)}
      className="group/ref flex min-w-0 items-center gap-2 rounded-sm text-xs focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
    >
      <span aria-hidden className={cn('size-1.5 shrink-0 rounded-full', SEVERITY_CLASSES[f.severity].dot)} />
      <span className="min-w-0 truncate text-foreground/90 group-hover/ref:underline">{f.title}</span>
      <span className="hidden shrink-0 truncate font-mono text-[11px] text-muted-foreground sm:inline sm:max-w-[16rem]" title={f.location.file}>
        {f.location.file}:{f.location.startLine}
      </span>
      <ChevronRight aria-hidden className="ml-auto size-3 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover/ref:opacity-100" />
    </Link>
  );
}

/** Up to `max` linked findings, then a "+N more" note. */
export function FindingRefList({
  scanId,
  ids,
  byId,
  max = 3,
}: {
  scanId: string;
  ids: string[];
  byId: Map<string, Finding>;
  max?: number;
}) {
  if (ids.length === 0) return null;
  const shown = ids.slice(0, max);
  return (
    <ul className="space-y-1.5">
      {shown.map((id) => (
        <li key={id}>
          <FindingRef scanId={scanId} findingId={id} known={byId.get(id)} />
        </li>
      ))}
      {ids.length > max && (
        <li className="pl-3.5 font-mono text-[11px] text-muted-foreground">+{ids.length - max} more linked</li>
      )}
    </ul>
  );
}
